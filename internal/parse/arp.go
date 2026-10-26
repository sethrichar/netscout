package parse

import (
	"net"

	"github.com/gopacket/gopacket/layers"

	"github.com/sethrichar/netscout/internal/model"
)

// ARP extracts IP↔MAC bindings from ARP requests and replies.
//
//   - The sender hardware/protocol pair is always a binding (except ARP probes,
//     whose sender IP is 0.0.0.0 — those still prove the MAC is alive).
//   - In a reply, the target pair is the original requester and is also a
//     valid binding.
//   - Gratuitous ARP (sender == target) is a normal binding announcement.
func ARP(ctx Context, arp *layers.ARP) []model.Observation {
	if arp.AddrType != layers.LinkTypeEthernet || arp.Protocol != layers.EthernetTypeIPv4 {
		return nil
	}
	if len(arp.SourceHwAddress) != 6 || len(arp.SourceProtAddress) != 4 {
		return nil
	}
	var out []model.Observation

	senderMAC := model.MACString(net.HardwareAddr(arp.SourceHwAddress))
	senderIP := net.IP(arp.SourceProtAddress).String()
	if model.IsUsableMAC(senderMAC) {
		o := model.Observation{
			MAC:       senderMAC,
			Source:    model.SourceARP,
			Timestamp: ctx.Time,
			Interface: ctx.Iface,
			VLAN:      ctx.VLAN,
			Extra:     map[string]string{"arp_op": arpOpName(arp.Operation)},
		}
		if model.IsUsableIPv4(senderIP) {
			o.IP = senderIP
		} else {
			o.Extra["arp_probe"] = "true"
		}
		if net.IP(arp.SourceProtAddress).Equal(net.IP(arp.DstProtAddress)) && o.IP != "" {
			o.Extra["arp_gratuitous"] = "true"
		}
		out = append(out, o)
	}

	if arp.Operation == layers.ARPReply && len(arp.DstHwAddress) == 6 && len(arp.DstProtAddress) == 4 {
		targetMAC := model.MACString(net.HardwareAddr(arp.DstHwAddress))
		targetIP := net.IP(arp.DstProtAddress).String()
		if model.IsUsableMAC(targetMAC) && model.IsUsableIPv4(targetIP) && targetMAC != senderMAC {
			out = append(out, model.Observation{
				MAC:       targetMAC,
				IP:        targetIP,
				Source:    model.SourceARP,
				Timestamp: ctx.Time,
				Interface: ctx.Iface,
				VLAN:      ctx.VLAN,
				Extra:     map[string]string{"arp_op": "reply-target"},
			})
		}
	}
	return out
}

func arpOpName(op uint16) string {
	switch op {
	case layers.ARPRequest:
		return "request"
	case layers.ARPReply:
		return "reply"
	default:
		return "other"
	}
}
