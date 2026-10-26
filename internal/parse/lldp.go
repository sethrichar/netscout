package parse

import (
	"fmt"
	"net"
	"strings"

	"github.com/gopacket/gopacket/layers"

	"github.com/sethrichar/netscout/internal/model"
)

// LLDP records what a neighbour (usually the switch we are plugged into)
// says about itself: chassis, port, system name/description and management
// address. The observation is attributed to the frame's source MAC.
func LLDP(ctx Context, l *layers.LinkLayerDiscovery, info *layers.LinkLayerDiscoveryInfo) []model.Observation {
	o := ctx.obs(model.SourceLLDP)
	o.Extra = map[string]string{}

	if chassis := lldpChassis(l.ChassisID); chassis != "" {
		o.Extra["lldp_chassis"] = chassis
	}
	if port := lldpPort(l.PortID); port != "" {
		o.Extra["lldp_port"] = port
	}
	if info != nil {
		if info.SysName != "" {
			o.Hostname = strings.TrimSpace(info.SysName)
		}
		if info.SysDescription != "" {
			o.Extra["lldp_sysdesc"] = firstLine(info.SysDescription)
		}
		if info.PortDescription != "" {
			o.Extra["lldp_portdesc"] = strings.TrimSpace(info.PortDescription)
		}
		if ip := mgmtIP(info.MgmtAddress); ip != "" {
			o.Extra["lldp_mgmt_ip"] = ip
			o.IP = ip
		}
		if caps := lldpCaps(info.SysCapabilities); caps != "" {
			o.Extra["lldp_caps"] = caps
		}
	}
	if o.Hostname == "" && len(o.Extra) == 0 {
		return nil
	}
	return []model.Observation{o}
}

// CDP is the Cisco equivalent of LLDP.
func CDP(ctx Context, c *layers.CiscoDiscoveryInfo) []model.Observation {
	o := ctx.obs(model.SourceCDP)
	o.Extra = map[string]string{}
	if c.DeviceID != "" {
		o.Hostname = strings.TrimSpace(c.DeviceID)
	}
	if c.SysName != "" && o.Hostname == "" {
		o.Hostname = strings.TrimSpace(c.SysName)
	}
	if c.PortID != "" {
		o.Extra["cdp_port"] = strings.TrimSpace(c.PortID)
	}
	if c.Platform != "" {
		o.Extra["cdp_platform"] = strings.TrimSpace(c.Platform)
	}
	if c.Version != "" {
		o.Extra["cdp_version"] = firstLine(c.Version)
	}
	if c.NativeVLAN != 0 {
		o.Extra["cdp_native_vlan"] = fmt.Sprint(c.NativeVLAN)
	}
	for _, ip := range append(c.Addresses, c.MgmtAddresses...) {
		if v4 := ip.To4(); v4 != nil && model.IsUsableIPv4(v4.String()) {
			o.IP = v4.String()
			o.Extra["cdp_mgmt_ip"] = v4.String()
			break
		}
	}
	if o.Hostname == "" && len(o.Extra) == 0 {
		return nil
	}
	return []model.Observation{o}
}

func lldpChassis(c layers.LLDPChassisID) string {
	switch c.Subtype {
	case layers.LLDPChassisIDSubTypeMACAddr:
		if len(c.ID) == 6 {
			return model.MACString(net.HardwareAddr(c.ID))
		}
	case layers.LLDPChassisIDSubTypeNetworkAddr:
		if len(c.ID) == 5 && c.ID[0] == 1 {
			return net.IP(c.ID[1:]).String()
		}
	}
	return cleanString(c.ID)
}

func lldpPort(p layers.LLDPPortID) string {
	switch p.Subtype {
	case layers.LLDPPortIDSubtypeMACAddr:
		if len(p.ID) == 6 {
			return model.MACString(net.HardwareAddr(p.ID))
		}
	case layers.LLDPPortIDSubtypeNetworkAddr:
		if len(p.ID) == 5 && p.ID[0] == 1 {
			return net.IP(p.ID[1:]).String()
		}
	}
	return cleanString(p.ID)
}

func mgmtIP(m layers.LLDPMgmtAddress) string {
	if m.Subtype == layers.IANAAddressFamilyIPV4 && len(m.Address) == 4 {
		ip := net.IP(m.Address).String()
		if model.IsUsableIPv4(ip) {
			return ip
		}
	}
	return ""
}

func lldpCaps(c layers.LLDPSysCapabilities) string {
	var caps []string
	e := c.EnabledCap
	if e.Bridge {
		caps = append(caps, "bridge")
	}
	if e.Router {
		caps = append(caps, "router")
	}
	if e.WLANAP {
		caps = append(caps, "wlan-ap")
	}
	if e.Phone {
		caps = append(caps, "phone")
	}
	if e.StationOnly {
		caps = append(caps, "station")
	}
	if e.Repeater {
		caps = append(caps, "repeater")
	}
	return strings.Join(caps, ",")
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	return s
}
