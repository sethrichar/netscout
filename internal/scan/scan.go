// Package scan actively probes a subnet so quiet devices reveal themselves:
// an ARP sweep (every host answers ARP, even Dante gear that ignores ping)
// with an optional ICMP echo sweep as a fallback.
package scan

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/sethrichar/netscout/internal/capture"
	"github.com/sethrichar/netscout/internal/model"
	"github.com/sethrichar/netscout/internal/parse"
)

// Options tune a sweep.
type Options struct {
	Rate   int           // packets per second (default 250)
	Settle time.Duration // how long to keep listening after the last probe (default 2s)
	ICMP   bool          // also send ICMP echo requests
	Passes int           // how many times to sweep (default 1; 2 catches sleepy hosts)
}

func (o *Options) defaults() {
	if o.Rate <= 0 {
		o.Rate = 250
	}
	if o.Settle <= 0 {
		o.Settle = 2 * time.Second
	}
	if o.Passes <= 0 {
		o.Passes = 1
	}
}

// Hosts enumerates the usable host addresses in a CIDR (network and
// broadcast excluded for /30 and larger; /31 and /32 return every address).
// Sweeps larger than /16 are refused to avoid flooding.
func Hosts(cidr string) ([]net.IP, *net.IPNet, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing %q: %w", cidr, err)
	}
	if ip.To4() == nil {
		return nil, nil, fmt.Errorf("%q: only IPv4 subnets can be swept", cidr)
	}
	ones, bits := ipnet.Mask.Size()
	if bits-ones > 16 {
		return nil, nil, fmt.Errorf("%q is larger than /16 (%d addresses); sweep a smaller range", cidr, 1<<(bits-ones))
	}
	base := ipnet.IP.To4()
	n := 1 << (bits - ones)
	var hosts []net.IP
	for i := 0; i < n; i++ {
		if n > 2 && (i == 0 || i == n-1) {
			continue
		}
		h := make(net.IP, 4)
		copy(h, base)
		h[3] += byte(i)
		h[2] += byte(i >> 8)
		h[1] += byte(i >> 16)
		hosts = append(hosts, h)
	}
	return hosts, ipnet, nil
}

// ARPRequest builds a broadcast who-has frame from us for target.
func ARPRequest(srcMAC net.HardwareAddr, srcIP, target net.IP) ([]byte, error) {
	eth := &layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
		SourceHwAddress: srcMAC, SourceProtAddress: srcIP.To4(),
		DstHwAddress: net.HardwareAddr{0, 0, 0, 0, 0, 0}, DstProtAddress: target.To4(),
	}
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true}, eth, arp); err != nil {
		return nil, fmt.Errorf("building ARP request: %w", err)
	}
	return buf.Bytes(), nil
}

// ARPSweep injects one ARP request per host through an open capture session.
// Replies arrive on the session like any other traffic, so callers that are
// already sniffing need nothing more. Returns the number of requests sent.
func ARPSweep(ctx context.Context, sess *capture.Session, iface capture.Interface, cidr string, opts Options) (int, error) {
	opts.defaults()
	hosts, _, err := Hosts(cidr)
	if err != nil {
		return 0, err
	}
	srcMAC, err := net.ParseMAC(iface.MAC)
	if err != nil {
		return 0, fmt.Errorf("interface %s has no usable MAC (%q): %w", iface.Name, iface.MAC, err)
	}
	srcIP := iface.FirstIPv4()
	if srcIP == nil {
		return 0, fmt.Errorf("interface %s has no IPv4 address", iface.Name)
	}
	interval := time.Second / time.Duration(opts.Rate)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	sent := 0
	for pass := 0; pass < opts.Passes; pass++ {
		for _, h := range hosts {
			if h.Equal(srcIP) {
				continue
			}
			frame, err := ARPRequest(srcMAC, srcIP, h)
			if err != nil {
				return sent, err
			}
			if err := sess.Inject(frame); err != nil {
				return sent, err
			}
			sent++
			select {
			case <-ctx.Done():
				return sent, ctx.Err()
			case <-tick.C:
			}
		}
	}
	return sent, nil
}

// Result is one host that answered during a standalone scan.
type Result struct {
	IP, MAC string
	Source  string // "arp" or "icmp"
}

// Run performs a self-contained sweep: opens its own capture on the interface,
// sends ARP (and optionally ICMP) probes, listens until Settle elapses after
// the last probe and returns everything that answered. Observations for the
// replies are also passed to observe when non-nil, so a store can be updated.
func Run(ctx context.Context, iface capture.Interface, cidr string, opts Options, observe func(model.Observation)) ([]Result, error) {
	opts.defaults()
	sess, err := capture.Open(iface, capture.Options{Promisc: true, BPF: "arp or icmp"})
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	packets := sess.Packets(ctx)

	found := map[string]Result{}
	collect := func(pkt gopacket.Packet) {
		for _, o := range parse.Packet(pkt, iface.Name) {
			if o.Source != model.SourceARP || o.IP == "" || o.Extra["arp_op"] != "reply" {
				continue
			}
			if _, ok := found[o.MAC+"|"+o.IP]; !ok {
				found[o.MAC+"|"+o.IP] = Result{IP: o.IP, MAC: o.MAC, Source: "arp"}
			}
			if observe != nil {
				o.Source = model.SourceScan
				observe(o)
			}
		}
	}

	// Collector runs while we send.
	collectDone := make(chan struct{})
	go func() {
		defer close(collectDone)
		for pkt := range packets {
			collect(pkt)
		}
	}()

	sent, serr := ARPSweep(ctx, sess, iface, cidr, opts)
	var ierr error
	if opts.ICMP && serr == nil {
		_, ierr = ICMPSweep(ctx, cidr, opts)
	}
	// Give stragglers time to answer, then stop the collector.
	select {
	case <-time.After(opts.Settle):
	case <-ctx.Done():
	}
	cancel()
	<-collectDone

	out := make([]Result, 0, len(found))
	for _, r := range found {
		out = append(out, r)
	}
	sortResults(out)
	if serr != nil && serr != context.Canceled {
		return out, fmt.Errorf("after %d probes: %w", sent, serr)
	}
	if ierr != nil {
		return out, fmt.Errorf("icmp sweep: %w", ierr)
	}
	return out, nil
}

func sortResults(rs []Result) {
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0 && ipLess(rs[j].IP, rs[j-1].IP); j-- {
			rs[j], rs[j-1] = rs[j-1], rs[j]
		}
	}
}

func ipLess(a, b string) bool {
	pa, pb := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if pa == nil || pb == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}
