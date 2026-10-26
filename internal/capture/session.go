package capture

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// Options tune a capture session.
type Options struct {
	SnapLen int           // bytes per packet; 0 = 65535
	Promisc bool          // promiscuous mode (recommended)
	BPF     string        // optional BPF filter expression
	Timeout time.Duration // read timeout used to poll for cancellation; 0 = 250ms
}

// Session is an open live capture on one interface.
type Session struct {
	Iface    Interface
	handle   *pcap.Handle
	linkType layers.LinkType
	received atomic.Uint64
	dropped  atomic.Uint64
}

// Open starts a live capture. Errors are wrapped so PrivilegeHint can explain
// permission problems.
func Open(iface Interface, opts Options) (*Session, error) {
	if err := checkRuntime(); err != nil {
		return nil, err
	}
	if opts.SnapLen <= 0 {
		opts.SnapLen = 65535
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 250 * time.Millisecond
	}
	ih, err := pcap.NewInactiveHandle(iface.Name)
	if err != nil {
		return nil, fmt.Errorf("preparing capture on %s: %w", iface.Name, err)
	}
	defer ih.CleanUp()
	if err := ih.SetSnapLen(opts.SnapLen); err != nil {
		return nil, fmt.Errorf("snaplen: %w", err)
	}
	if err := ih.SetPromisc(opts.Promisc); err != nil {
		return nil, fmt.Errorf("promisc: %w", err)
	}
	if err := ih.SetTimeout(opts.Timeout); err != nil {
		return nil, fmt.Errorf("timeout: %w", err)
	}
	// Immediate mode delivers packets as they arrive instead of buffering.
	_ = ih.SetImmediateMode(true)
	h, err := ih.Activate()
	if err != nil {
		return nil, fmt.Errorf("opening capture on %s: %w", iface.Name, err)
	}
	if opts.BPF != "" {
		if err := h.SetBPFFilter(opts.BPF); err != nil {
			h.Close()
			return nil, fmt.Errorf("applying BPF filter %q: %w", opts.BPF, err)
		}
	}
	return &Session{Iface: iface, handle: h, linkType: h.LinkType()}, nil
}

// LinkType reports the data-link type pcap decodes for this interface.
func (s *Session) LinkType() layers.LinkType { return s.linkType }

// Packets reads frames until ctx is cancelled or the handle fails, decoding
// each lazily. The returned channel is closed on exit.
func (s *Session) Packets(ctx context.Context) <-chan gopacket.Packet {
	out := make(chan gopacket.Packet, 1024)
	go func() {
		defer close(out)
		for {
			if ctx.Err() != nil {
				return
			}
			data, ci, err := s.handle.ReadPacketData()
			switch {
			case err == nil:
			case errors.Is(err, pcap.NextErrorTimeoutExpired):
				continue
			default:
				// EOF (offline) or a fatal handle error.
				return
			}
			s.received.Add(1)
			pkt := gopacket.NewPacket(data, s.linkType, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			md := pkt.Metadata()
			md.CaptureInfo = ci
			md.Truncated = ci.CaptureLength < ci.Length
			select {
			case out <- pkt:
			case <-ctx.Done():
				return
			default:
				// Consumer is behind: drop rather than stall the capture.
				s.dropped.Add(1)
			}
		}
	}()
	return out
}

// Inject writes a raw frame to the interface (used by the ARP sweep).
func (s *Session) Inject(frame []byte) error {
	if err := s.handle.WritePacketData(frame); err != nil {
		return fmt.Errorf("injecting frame: %w", err)
	}
	return nil
}

// Stats summarises counters from pcap and from our own queue.
type Stats struct {
	Received, PcapDropped, IfDropped, QueueDropped uint64
}

// Stats returns live counters.
func (s *Session) Stats() Stats {
	st := Stats{Received: s.received.Load(), QueueDropped: s.dropped.Load()}
	if ps, err := s.handle.Stats(); err == nil && ps != nil {
		st.PcapDropped = uint64(ps.PacketsDropped)
		st.IfDropped = uint64(ps.PacketsIfDropped)
	}
	return st
}

// Close releases the pcap handle.
func (s *Session) Close() {
	if s.handle != nil {
		s.handle.Close()
	}
}
