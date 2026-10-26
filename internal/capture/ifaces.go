// Package capture lists network interfaces and runs live packet capture
// sessions on top of libpcap / Npcap.
package capture

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/gopacket/gopacket/pcap"
)

// Interface describes a capturable network interface.
type Interface struct {
	// Name is the identifier pcap expects (e.g. "en0", "eth0", or on Windows
	// "\Device\NPF_{GUID}").
	Name string
	// Description is a friendly name when the platform provides one (Windows
	// adapter descriptions, "Wi-Fi", etc.).
	Description string
	// FriendlyName is the OS interface name from net.Interfaces when it
	// differs from Name (Windows: "Ethernet 2").
	FriendlyName string
	MAC          string
	IPv4         []string
	IPv6         []string
	Up           bool
	Loopback     bool
	// Default is true for the interface that carries the default route.
	Default bool
}

// Label returns the best human-readable name for the interface.
func (i Interface) Label() string {
	switch {
	case i.Description != "" && i.Description != i.Name:
		return i.Description
	case i.FriendlyName != "" && i.FriendlyName != i.Name:
		return i.FriendlyName
	default:
		return i.Name
	}
}

// ListInterfaces merges pcap's device list with the OS interface table so each
// entry has a pcap-usable name, a friendly description, MAC and addresses.
// Interfaces that pcap cannot open are omitted. The default-route interface is
// flagged.
func ListInterfaces() ([]Interface, error) {
	if err := checkRuntime(); err != nil {
		return nil, err
	}
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, fmt.Errorf("listing pcap devices: %w", err)
	}
	osIfaces, _ := net.Interfaces()

	defIP := defaultRouteIP()

	var out []Interface
	for _, d := range devs {
		ifc := Interface{Name: d.Name, Description: d.Description}
		for _, a := range d.Addresses {
			if a.IP == nil {
				continue
			}
			if v4 := a.IP.To4(); v4 != nil {
				ifc.IPv4 = append(ifc.IPv4, cidrString(v4, a.Netmask))
			} else if a.IP.To16() != nil {
				ifc.IPv6 = append(ifc.IPv6, a.IP.String())
			}
		}
		if m := matchOSInterface(d, osIfaces); m != nil {
			ifc.MAC = m.HardwareAddr.String()
			ifc.Up = m.Flags&net.FlagUp != 0
			ifc.Loopback = m.Flags&net.FlagLoopback != 0
			if m.Name != d.Name {
				ifc.FriendlyName = m.Name
			}
		} else {
			ifc.Up = d.Flags&pcapIfUp != 0
			ifc.Loopback = d.Flags&pcapIfLoopback != 0
		}
		// Only an Ethernet-like interface (one with a MAC) can be the capture
		// default: a VPN tunnel may carry the default route but sees no LAN.
		if defIP != nil && ifc.MAC != "" {
			for _, c := range ifc.IPv4 {
				if strings.HasPrefix(c, defIP.String()+"/") {
					ifc.Default = true
				}
			}
		}
		out = append(out, ifc)
	}
	sort.SliceStable(out, func(a, b int) bool {
		ra, rb := rank(out[a]), rank(out[b])
		if ra != rb {
			return ra < rb
		}
		return out[a].Name < out[b].Name
	})
	return out, nil
}

// rank orders interfaces by how likely they are to be the show LAN:
// default route first, then physical up+addressed, then virtual/bridges,
// then tunnels, then everything else.
func rank(i Interface) int {
	switch {
	case i.Loopback:
		return 9
	case i.Default:
		return 0
	case i.MAC == "":
		return 6 // tunnel / point-to-point
	case len(i.IPv4) == 0 || !i.Up:
		return 5
	case IsVirtualName(i.Name) || IsVirtualName(i.FriendlyName) || IsVirtualName(i.Description):
		return 3
	case hasLinkLocalOnly(i):
		return 2
	default:
		return 1
	}
}

// IsVirtualName flags bridges, VM and container adapters that are rarely the
// network an operator wants to watch.
func IsVirtualName(name string) bool {
	n := strings.ToLower(name)
	for _, p := range []string{"bridge", "vmnet", "vethernet", "vbox", "virtual", "docker", "utun", "tun", "tap", "awdl", "llw", "hyper-v", "wsl", "vmware", "parallels", "tailscale", "zerotier", "wireguard", "ap1", "anpi"} {
		if strings.HasPrefix(n, p) || strings.Contains(n, " "+p) || strings.Contains(n, "("+p) {
			return true
		}
	}
	return false
}

func hasLinkLocalOnly(i Interface) bool {
	if len(i.IPv4) == 0 {
		return false
	}
	for _, c := range i.IPv4 {
		if !strings.HasPrefix(c, "169.254.") {
			return false
		}
	}
	return true
}

// DefaultInterface returns the interface carrying the default route, or the
// best-ranked physical interface with an IPv4 address (isolated show LANs
// often have no default route at all).
func DefaultInterface() (Interface, error) {
	ifaces, err := ListInterfaces()
	if err != nil {
		return Interface{}, err
	}
	for _, i := range ifaces {
		if i.Default {
			return i, nil
		}
	}
	for _, i := range ifaces {
		if !i.Loopback && len(i.IPv4) > 0 && i.MAC != "" {
			return i, nil
		}
	}
	for _, i := range ifaces {
		if !i.Loopback && len(i.IPv4) > 0 {
			return i, nil
		}
	}
	return Interface{}, fmt.Errorf("no usable network interface found")
}

// Usable reports whether the interface can realistically see a LAN right now.
func (i Interface) Usable() bool {
	return !i.Loopback && i.Up && len(i.IPv4) > 0 && i.MAC != ""
}

// FindInterface resolves a user-supplied name against pcap names, OS names and
// descriptions (case-insensitive). An empty name picks the default interface.
func FindInterface(name string) (Interface, error) {
	if name == "" {
		return DefaultInterface()
	}
	ifaces, err := ListInterfaces()
	if err != nil {
		return Interface{}, err
	}
	for _, i := range ifaces {
		if strings.EqualFold(i.Name, name) || strings.EqualFold(i.FriendlyName, name) || strings.EqualFold(i.Description, name) {
			return i, nil
		}
	}
	// Windows: allow the bare GUID without the \Device\NPF_ prefix.
	for _, i := range ifaces {
		if strings.Contains(strings.ToLower(i.Name), strings.ToLower(name)) {
			return i, nil
		}
	}
	return Interface{}, fmt.Errorf("interface %q not found (run `netscout ifaces`)", name)
}

// LocalNets returns the IPv4 networks configured on the interface.
func (i Interface) LocalNets() []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range i.IPv4 {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

// FirstIPv4 returns the interface's primary IPv4 address, or nil.
func (i Interface) FirstIPv4() net.IP {
	for _, c := range i.IPv4 {
		if ip, _, err := net.ParseCIDR(c); err == nil {
			return ip
		}
	}
	return nil
}

// pcap interface flag bits (from pcap.h); the Go binding exposes Flags as a
// raw uint32.
const (
	pcapIfLoopback = 0x00000001
	pcapIfUp       = 0x00000002
)

func cidrString(ip net.IP, mask net.IPMask) string {
	if len(mask) == 16 {
		mask = mask[12:]
	}
	ones, bits := mask.Size()
	if bits == 0 {
		return ip.String() + "/32"
	}
	return fmt.Sprintf("%s/%d", ip, ones)
}

// matchOSInterface finds the net.Interface corresponding to a pcap device by
// exact name first, then by any shared IP address (Windows pcap names are
// GUIDs that never match the OS name).
func matchOSInterface(d pcap.Interface, osIfaces []net.Interface) *net.Interface {
	for idx := range osIfaces {
		if osIfaces[idx].Name == d.Name {
			return &osIfaces[idx]
		}
	}
	for idx := range osIfaces {
		addrs, err := osIfaces[idx].Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			for _, pa := range d.Addresses {
				if pa.IP != nil && pa.IP.Equal(ipn.IP) {
					return &osIfaces[idx]
				}
			}
		}
	}
	return nil
}

// defaultRouteIP returns the local IPv4 address the OS would use to reach the
// internet. No packets are sent: a UDP "dial" only consults the routing table.
func defaultRouteIP() net.IP {
	conn, err := net.Dial("udp4", "1.1.1.1:53")
	if err != nil {
		return nil
	}
	defer conn.Close()
	if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return ua.IP.To4()
	}
	return nil
}
