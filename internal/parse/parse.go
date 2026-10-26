// Package parse turns captured frames into Observations. Every function here is
// pure: packet in, zero or more observations out, no I/O.
package parse

import (
	"net"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/sethrichar/netscout/internal/model"
)

// Context carries per-packet facts the individual parsers need.
type Context struct {
	Iface  string
	VLAN   int
	Time   time.Time
	SrcMAC string
	DstMAC string
	SrcIP  net.IP // set when an IPv4 layer is present
	DstIP  net.IP
}

// Packet dispatches one frame to every applicable protocol parser.
func Packet(pkt gopacket.Packet, iface string) []model.Observation {
	ctx := Context{Iface: iface, Time: pkt.Metadata().Timestamp}
	if ctx.Time.IsZero() {
		ctx.Time = time.Now()
	}

	eth, _ := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	switch {
	case eth != nil:
		ctx.SrcMAC = model.MACString(eth.SrcMAC)
		ctx.DstMAC = model.MACString(eth.DstMAC)
	default:
		// Linux "any" pseudo-interface (SLL on older libpcap, SLL2 on >= 1.10):
		// only the source address is available.
		if sll, ok := pkt.Layer(layers.LayerTypeLinuxSLL).(*layers.LinuxSLL); ok {
			ctx.SrcMAC = model.MACString(sll.Addr)
		} else if sll2, ok := pkt.Layer(layers.LayerTypeLinuxSLL2).(*layers.LinuxSLL2); ok {
			ctx.SrcMAC = model.MACString(sll2.Addr)
		} else {
			return nil
		}
	}
	if !model.IsUsableMAC(ctx.SrcMAC) {
		return nil
	}

	// 802.1Q: take the innermost tag so QinQ (802.1ad) frames record the
	// customer VLAN the device actually lives on, not the provider S-VLAN.
	for _, l := range pkt.Layers() {
		if dq, ok := l.(*layers.Dot1Q); ok {
			ctx.VLAN = int(dq.VLANIdentifier)
		}
	}
	if ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		ctx.SrcIP, ctx.DstIP = ip4.SrcIP, ip4.DstIP
	}

	var obs []model.Observation
	if arp, ok := pkt.Layer(layers.LayerTypeARP).(*layers.ARP); ok {
		obs = append(obs, ARP(ctx, arp)...)
	}
	if d, ok := pkt.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4); ok {
		obs = append(obs, DHCP(ctx, d)...)
	}
	if udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); ok && (udp.SrcPort == 5353 || udp.DstPort == 5353) {
		if dns, ok := pkt.Layer(layers.LayerTypeDNS).(*layers.DNS); ok {
			obs = append(obs, MDNS(ctx, dns)...)
		} else if len(udp.Payload) > 12 {
			var dns layers.DNS
			if err := dns.DecodeFromBytes(udp.Payload, gopacket.NilDecodeFeedback); err == nil {
				obs = append(obs, MDNS(ctx, &dns)...)
			}
		}
	}
	if l, ok := pkt.Layer(layers.LayerTypeLinkLayerDiscovery).(*layers.LinkLayerDiscovery); ok {
		info, _ := pkt.Layer(layers.LayerTypeLinkLayerDiscoveryInfo).(*layers.LinkLayerDiscoveryInfo)
		obs = append(obs, LLDP(ctx, l, info)...)
	}
	if c, ok := pkt.Layer(layers.LayerTypeCiscoDiscoveryInfo).(*layers.CiscoDiscoveryInfo); ok {
		obs = append(obs, CDP(ctx, c)...)
	}
	// Generic liveness: any IPv4 frame proves the source MAC is up and using
	// that IP. Skipped when a richer parser already produced an observation
	// for this frame (avoids double-counting ARP/DHCP/mDNS).
	if len(obs) == 0 && ctx.SrcIP != nil {
		obs = append(obs, IPv4(ctx)...)
	}
	return obs
}

// IPv4 emits the baseline "MAC is alive with this IP" observation.
func IPv4(ctx Context) []model.Observation {
	ip := ctx.SrcIP.String()
	if !model.IsUsableIPv4(ip) {
		return nil
	}
	return []model.Observation{{
		MAC:       ctx.SrcMAC,
		IP:        ip,
		Source:    model.SourceIPv4,
		Timestamp: ctx.Time,
		Interface: ctx.Iface,
		VLAN:      ctx.VLAN,
	}}
}

func (c Context) obs(source string) model.Observation {
	return model.Observation{
		MAC:       c.SrcMAC,
		Source:    source,
		Timestamp: c.Time,
		Interface: c.Iface,
		VLAN:      c.VLAN,
	}
}
