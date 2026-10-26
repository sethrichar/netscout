package parse

import (
	"fmt"
	"net"
	"strings"

	"github.com/gopacket/gopacket/layers"

	"github.com/sethrichar/netscout/internal/model"
)

// DHCP extracts hostnames, vendor classes and address assignments from DHCPv4.
//
//   - Client messages (Discover/Request/Inform/Release) identify the client by
//     ClientHWAddr and carry option 12 (hostname), 60 (vendor class) and 50
//     (requested IP).
//   - Server messages (Offer/ACK) bind YourClientIP to the client's MAC and
//     identify the DHCP server itself (frame source + option 54).
func DHCP(ctx Context, d *layers.DHCPv4) []model.Observation {
	if len(d.ClientHWAddr) != 6 {
		return nil
	}
	clientMAC := model.MACString(d.ClientHWAddr)
	if !model.IsUsableMAC(clientMAC) {
		return nil
	}

	var (
		msgType     layers.DHCPMsgType
		hostname    string
		vendorClass string
		requestedIP string
		serverID    string
		clientID    string
		paramReq    string
	)
	for _, o := range d.Options {
		switch o.Type {
		case layers.DHCPOptMessageType:
			if len(o.Data) == 1 {
				msgType = layers.DHCPMsgType(o.Data[0])
			}
		case layers.DHCPOptHostname:
			hostname = cleanString(o.Data)
		case layers.DHCPOptClassID:
			vendorClass = cleanString(o.Data)
		case layers.DHCPOptRequestIP:
			if len(o.Data) == 4 {
				requestedIP = net.IP(o.Data).String()
			}
		case layers.DHCPOptServerID:
			if len(o.Data) == 4 {
				serverID = net.IP(o.Data).String()
			}
		case layers.DHCPOptClientID:
			if len(o.Data) == 7 && o.Data[0] == 1 {
				clientID = model.MACString(net.HardwareAddr(o.Data[1:]))
			} else if len(o.Data) > 1 {
				clientID = fmt.Sprintf("%x", o.Data)
			}
		case layers.DHCPOptParamsRequest:
			paramReq = fmt.Sprintf("%d", o.Data)
		}
	}

	extra := map[string]string{"dhcp_msg_type": dhcpMsgName(msgType)}
	if vendorClass != "" {
		extra["dhcp_vendor_class"] = vendorClass
	}
	if requestedIP != "" {
		extra["dhcp_requested_ip"] = requestedIP
	}
	if clientID != "" && clientID != clientMAC {
		extra["dhcp_client_id"] = clientID
	}
	if paramReq != "" {
		extra["dhcp_param_request"] = paramReq
	}

	client := model.Observation{
		MAC:       clientMAC,
		Hostname:  hostname,
		Source:    model.SourceDHCP,
		Timestamp: ctx.Time,
		Interface: ctx.Iface,
		VLAN:      ctx.VLAN,
		Extra:     extra,
	}

	var out []model.Observation
	switch msgType {
	case layers.DHCPMsgTypeOffer, layers.DHCPMsgTypeAck:
		// Server → client. The assigned address is authoritative.
		if ip := d.YourClientIP.String(); model.IsUsableIPv4(ip) {
			client.IP = ip
		}
		if serverID == "" && ctx.SrcIP != nil {
			serverID = ctx.SrcIP.String()
		}
		if serverID != "" {
			client.Extra["dhcp_server"] = serverID
		}
		out = append(out, client)
		// The frame's source is the DHCP server (or relay) itself.
		if ctx.SrcMAC != "" && ctx.SrcMAC != clientMAC && ctx.SrcIP != nil && model.IsUsableIPv4(ctx.SrcIP.String()) {
			out = append(out, model.Observation{
				MAC:       ctx.SrcMAC,
				IP:        ctx.SrcIP.String(),
				Source:    model.SourceDHCP,
				Timestamp: ctx.Time,
				Interface: ctx.Iface,
				VLAN:      ctx.VLAN,
				Extra:     map[string]string{"dhcp_role": "server", "dhcp_msg_type": dhcpMsgName(msgType)},
			})
		}
	default:
		// Client → server. ClientIP is set on Request (renew) / Inform / Release;
		// Discover carries 0.0.0.0 and we fall back to the requested IP (not
		// authoritative, so it is recorded only as an attribute above).
		if ip := d.ClientIP.String(); model.IsUsableIPv4(ip) {
			client.IP = ip
		} else if ctx.SrcIP != nil && model.IsUsableIPv4(ctx.SrcIP.String()) && ctx.SrcMAC == clientMAC {
			client.IP = ctx.SrcIP.String()
		}
		out = append(out, client)
	}
	return out
}

func dhcpMsgName(t layers.DHCPMsgType) string {
	switch t {
	case layers.DHCPMsgTypeDiscover:
		return "discover"
	case layers.DHCPMsgTypeOffer:
		return "offer"
	case layers.DHCPMsgTypeRequest:
		return "request"
	case layers.DHCPMsgTypeDecline:
		return "decline"
	case layers.DHCPMsgTypeAck:
		return "ack"
	case layers.DHCPMsgTypeNak:
		return "nak"
	case layers.DHCPMsgTypeRelease:
		return "release"
	case layers.DHCPMsgTypeInform:
		return "inform"
	default:
		return "unknown"
	}
}

// cleanString trims NULs and whitespace and drops non-printable bytes.
func cleanString(b []byte) string {
	s := strings.TrimRight(string(b), "\x00")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}
