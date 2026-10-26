package scan

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ICMPSweep sends one echo request to every host in the CIDR. Replies are not
// read here: the kernel has to ARP for each target first, and those ARP
// exchanges (plus the echo replies) are seen by the capture session, which is
// what we are really after. Uses an unprivileged datagram ICMP socket where
// the OS allows it (macOS, Linux with ping_group_range) and a raw socket
// otherwise (Windows as Administrator).
func ICMPSweep(ctx context.Context, cidr string, opts Options) (int, error) {
	opts.defaults()
	hosts, _, err := Hosts(cidr)
	if err != nil {
		return 0, err
	}
	conn, dgram, err := openICMP()
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	// Drain replies so the socket buffer never fills.
	go func() {
		buf := make([]byte, 1500)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if _, _, err := conn.ReadFrom(buf); err != nil {
				if ctx.Err() != nil {
					return
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				return
			}
		}
	}()
	id := os.Getpid() & 0xffff
	interval := time.Second / time.Duration(opts.Rate)
	tick := time.NewTicker(interval)
	defer tick.Stop()
	sent := 0
	for seq, h := range hosts {
		msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &icmp.Echo{ID: id, Seq: seq & 0xffff, Data: []byte("netscout")}}
		b, err := msg.Marshal(nil)
		if err != nil {
			return sent, fmt.Errorf("marshal echo: %w", err)
		}
		var dst net.Addr = &net.IPAddr{IP: h}
		if dgram {
			dst = &net.UDPAddr{IP: h}
		}
		if _, err := conn.WriteTo(b, dst); err != nil {
			// Unreachable / no route for one host is not fatal.
			continue
		}
		sent++
		select {
		case <-ctx.Done():
			return sent, ctx.Err()
		case <-tick.C:
		}
	}
	return sent, nil
}

// openICMP returns a packet connection and whether it is a datagram socket
// (which needs UDPAddr destinations).
func openICMP() (*icmp.PacketConn, bool, error) {
	if runtime.GOOS != "windows" {
		if c, err := icmp.ListenPacket("udp4", "0.0.0.0"); err == nil {
			return c, true, nil
		}
	}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, false, fmt.Errorf("opening ICMP socket (needs root/Administrator for raw ICMP): %w", err)
	}
	return c, false, nil
}
