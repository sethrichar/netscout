// Package model defines the types shared by every netscout package.
package model

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Observation sources.
const (
	SourceARP      = "arp"
	SourceDHCP     = "dhcp"
	SourceMDNS     = "mdns"
	SourceLLDP     = "lldp"
	SourceCDP      = "cdp"
	SourceIPv4     = "ipv4"
	SourceScan     = "scan"
	SourceARPTable = "arptable"
)

// Event kinds.
const (
	EventNewDevice = "new_device"
	EventOnline    = "online"
	EventOffline   = "offline"
	EventIPChange  = "ip_change"
	EventHostname  = "hostname"
	EventConflict  = "conflict"
	EventScan      = "scan"
	EventInfo      = "info"
)

// Device is the merged view of everything known about one MAC address.
type Device struct {
	MAC         string            `json:"mac"`
	IPs         []string          `json:"ips"` // most recently seen first
	Vendor      string            `json:"vendor"`
	VendorShort string            `json:"vendor_short,omitempty"`
	Hostname    string            `json:"hostname"`
	FirstSeen   time.Time         `json:"first_seen"`
	LastSeen    time.Time         `json:"last_seen"`
	Online      bool              `json:"online"`
	Interface   string            `json:"interface"`
	Label       string            `json:"label"`
	Notes       string            `json:"notes"`
	Tags        []string          `json:"tags"`
	Randomized  bool              `json:"randomized"`
	Attrs       map[string]string `json:"attrs,omitempty"` // free-form protocol facts: services, dhcp_vendor_class, lldp_port…
}

// IP returns the most recently seen IPv4 address, or "".
func (d Device) IP() string {
	if len(d.IPs) == 0 {
		return ""
	}
	return d.IPs[0]
}

// DisplayName returns the label if set, else hostname, else vendor, else MAC.
func (d Device) DisplayName() string {
	switch {
	case d.Label != "":
		return d.Label
	case d.Hostname != "":
		return d.Hostname
	case d.Vendor != "":
		return d.Vendor
	default:
		return d.MAC
	}
}

// Observation is one fact gleaned from one packet (or scan reply).
type Observation struct {
	MAC       string            `json:"mac"`
	IP        string            `json:"ip,omitempty"`
	Hostname  string            `json:"hostname,omitempty"`
	Source    string            `json:"source"`
	Timestamp time.Time         `json:"timestamp"`
	Interface string            `json:"interface,omitempty"`
	VLAN      int               `json:"vlan,omitempty"` // 0 = untagged
	Extra     map[string]string `json:"extra,omitempty"`
}

// Subnet is a managed IPv4 network.
type Subnet struct {
	ID      int64  `json:"id"`
	CIDR    string `json:"cidr"`
	Name    string `json:"name"`
	VLAN    int    `json:"vlan"`
	Gateway string `json:"gateway"`
	Notes   string `json:"notes"`
}

// Reservation pins an IP to a MAC with a label, whether or not it is online.
type Reservation struct {
	ID       int64  `json:"id"`
	SubnetID int64  `json:"subnet_id"`
	IP       string `json:"ip"`
	MAC      string `json:"mac"`
	Label    string `json:"label"`
	Notes    string `json:"notes"`
}

// Event is something worth telling the operator about.
type Event struct {
	ID      int64             `json:"id"`
	Time    time.Time         `json:"time"`
	Kind    string            `json:"kind"`
	MAC     string            `json:"mac,omitempty"`
	IP      string            `json:"ip,omitempty"`
	Message string            `json:"message"`
	Details map[string]string `json:"details,omitempty"`
}

// NormalizeMAC canonicalises a MAC address to lowercase colon-separated form.
// It accepts aa:bb:cc:dd:ee:ff, AA-BB-CC-DD-EE-FF, aabb.ccdd.eeff, aabbccddeeff
// and the unpadded form macOS `arp` prints (0:1b:21:a:b:c).
func NormalizeMAC(s string) (string, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return "", fmt.Errorf("empty MAC")
	}
	var parts []string
	switch {
	case strings.Contains(s, ":"):
		parts = strings.Split(s, ":")
	case strings.Contains(s, "-"):
		parts = strings.Split(s, "-")
	case strings.Contains(s, "."):
		// Cisco aabb.ccdd.eeff
		hex := strings.ReplaceAll(s, ".", "")
		return splitHex(hex)
	default:
		return splitHex(s)
	}
	if len(parts) != 6 {
		return "", fmt.Errorf("invalid MAC %q", s)
	}
	for i, p := range parts {
		if len(p) == 1 {
			p = "0" + p
		}
		if len(p) != 2 || !isHex(p) {
			return "", fmt.Errorf("invalid MAC %q", s)
		}
		parts[i] = p
	}
	return strings.Join(parts, ":"), nil
}

func splitHex(hex string) (string, error) {
	if len(hex) != 12 || !isHex(hex) {
		return "", fmt.Errorf("invalid MAC %q", hex)
	}
	var b strings.Builder
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hex[i : i+2])
	}
	return b.String(), nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// MACString formats a hardware address canonically.
func MACString(hw net.HardwareAddr) string {
	if len(hw) == 0 {
		return ""
	}
	return strings.ToLower(hw.String())
}

// firstOctet returns the first byte of a canonical MAC, or 0 and false.
func firstOctet(mac string) (byte, bool) {
	if len(mac) < 2 {
		return 0, false
	}
	var v byte
	for _, c := range mac[:2] {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= byte(c - '0')
		case c >= 'a' && c <= 'f':
			v |= byte(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= byte(c-'A') + 10
		default:
			return 0, false
		}
	}
	return v, true
}

// IsRandomizedMAC reports whether the locally-administered bit is set (and the
// address is unicast) — the signature of iOS/Android/Windows private Wi-Fi
// addresses and most VM/container NICs.
func IsRandomizedMAC(mac string) bool {
	b, ok := firstOctet(mac)
	return ok && b&0x02 != 0 && b&0x01 == 0
}

// IsMulticastMAC reports whether the group bit is set (includes broadcast).
func IsMulticastMAC(mac string) bool {
	b, ok := firstOctet(mac)
	return ok && b&0x01 != 0
}

// IsUsableMAC filters out zero, broadcast and multicast addresses.
func IsUsableMAC(mac string) bool {
	if mac == "" || mac == "00:00:00:00:00:00" || mac == "ff:ff:ff:ff:ff:ff" {
		return false
	}
	return !IsMulticastMAC(mac)
}

// IsUsableIPv4 filters out empty, unspecified, multicast, broadcast and
// non-IPv4 addresses.
func IsUsableIPv4(ip string) bool {
	if ip == "" {
		return false
	}
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	v4 := p.To4()
	if v4 == nil {
		return false
	}
	if v4.IsUnspecified() || v4.IsMulticast() || v4.Equal(net.IPv4bcast) {
		return false
	}
	return true
}
