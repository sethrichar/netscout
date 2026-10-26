// Package ipam computes the status of every address in a subnet from the plan
// (reservations) and reality (observed IP↔MAC bindings). It is pure: no I/O.
package ipam

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/sethrichar/netscout/internal/model"
)

// Status of one address.
type Status string

// Address statuses, roughly in order of "how much should the operator care".
const (
	StatusFree     Status = "free"     // nothing planned, nothing seen
	StatusReserved Status = "reserved" // planned, not seen
	StatusInUse    Status = "in-use"   // seen, nothing planned
	StatusMatch    Status = "match"    // planned and the right MAC is using it
	StatusMismatch Status = "mismatch" // planned for one MAC, used by another (or reserved MAC is elsewhere)
	StatusConflict Status = "conflict" // two MACs using it right now
)

// Binding is an observed IP↔MAC pair. Current says whether it is believed to
// be live (recent) rather than history.
type Binding struct {
	IP       string
	MAC      string
	LastSeen time.Time
	Current  bool
}

// Address is the computed state of one IP.
type Address struct {
	IP          string             `json:"ip"`
	Status      Status             `json:"status"`
	Reservation *model.Reservation `json:"reservation,omitempty"`
	// MACs currently bound to this address (0, 1, or 2+ for a conflict).
	MACs []string `json:"macs,omitempty"`
	// Devices for those MACs, when known.
	Devices []model.Device `json:"devices,omitempty"`
	Online  bool           `json:"online"`
	// LastSeen is the newest observation of any current binding.
	LastSeen time.Time `json:"last_seen,omitempty"`
	// History lists MACs that used the address before (not current).
	History  []string `json:"history,omitempty"`
	Note     string   `json:"note,omitempty"`
	Gateway  bool     `json:"gateway,omitempty"`
	Network  bool     `json:"network,omitempty"`
	Bcast    bool     `json:"broadcast,omitempty"`
	Reserved bool     `json:"reserved"`
}

// Summary counts statuses across a subnet.
type Summary struct {
	Total    int `json:"total"` // usable host addresses
	Free     int `json:"free"`
	Reserved int `json:"reserved"`
	InUse    int `json:"in_use"`
	Match    int `json:"match"`
	Mismatch int `json:"mismatch"`
	Conflict int `json:"conflict"`
	Online   int `json:"online"`
}

// Options tune Compute.
type Options struct {
	// IncludeEdges keeps the network and broadcast addresses in the output.
	IncludeEdges bool
}

// MarkCurrent decides which bindings are live: anything seen within window, or
// the single most recent IP of each MAC (so a device that has been offline for
// a day still shows where it was). Returns the bindings with Current set.
func MarkCurrent(bindings []Binding, now time.Time, window time.Duration) []Binding {
	newest := map[string]time.Time{}
	for _, b := range bindings {
		if t, ok := newest[b.MAC]; !ok || b.LastSeen.After(t) {
			newest[b.MAC] = b.LastSeen
		}
	}
	out := make([]Binding, len(bindings))
	for i, b := range bindings {
		b.Current = now.Sub(b.LastSeen) <= window || b.LastSeen.Equal(newest[b.MAC])
		out[i] = b
	}
	return out
}

// Compute returns one Address per host in the subnet plus a summary.
func Compute(sn model.Subnet, reservations []model.Reservation, bindings []Binding, devices []model.Device, opts Options) ([]Address, Summary, error) {
	_, ipnet, err := net.ParseCIDR(sn.CIDR)
	if err != nil {
		return nil, Summary{}, fmt.Errorf("subnet %q: %w", sn.CIDR, err)
	}
	if ipnet.IP.To4() == nil {
		return nil, Summary{}, fmt.Errorf("subnet %q: only IPv4 is supported", sn.CIDR)
	}
	ones, bits := ipnet.Mask.Size()
	if bits-ones > 16 {
		return nil, Summary{}, fmt.Errorf("subnet %q is larger than /16; too many addresses to render", sn.CIDR)
	}

	devByMAC := map[string]model.Device{}
	for _, d := range devices {
		devByMAC[d.MAC] = d
	}
	resByIP := map[string]*model.Reservation{}
	resByMAC := map[string]*model.Reservation{}
	for i := range reservations {
		r := &reservations[i]
		resByIP[r.IP] = r
		if r.MAC != "" {
			resByMAC[r.MAC] = r
		}
	}
	// Bindings inside this subnet, grouped by IP; also where each MAC lives now.
	curByIP := map[string][]Binding{}
	histByIP := map[string][]string{}
	macAt := map[string][]string{} // mac → current IPs in this subnet
	for _, b := range bindings {
		ip := net.ParseIP(b.IP)
		if ip == nil || !ipnet.Contains(ip) {
			continue
		}
		if b.Current {
			curByIP[b.IP] = append(curByIP[b.IP], b)
			macAt[b.MAC] = append(macAt[b.MAC], b.IP)
		} else {
			histByIP[b.IP] = appendUnique(histByIP[b.IP], b.MAC)
		}
	}

	n := 1 << (bits - ones)
	base := ipnet.IP.To4()
	var out []Address
	var sum Summary
	for i := 0; i < n; i++ {
		ip := make(net.IP, 4)
		copy(ip, base)
		ip[3] += byte(i)
		ip[2] += byte(i >> 8)
		ip[1] += byte(i >> 16)
		s := ip.String()
		a := Address{IP: s}
		if n > 2 {
			a.Network = i == 0
			a.Bcast = i == n-1
		}
		a.Gateway = sn.Gateway != "" && s == sn.Gateway
		a.Reservation = resByIP[s]
		a.Reserved = a.Reservation != nil

		cur := curByIP[s]
		sort.Slice(cur, func(x, y int) bool { return cur[x].LastSeen.After(cur[y].LastSeen) })
		for _, b := range cur {
			a.MACs = appendUnique(a.MACs, b.MAC)
			if b.LastSeen.After(a.LastSeen) {
				a.LastSeen = b.LastSeen
			}
		}
		for _, m := range a.MACs {
			if d, ok := devByMAC[m]; ok {
				a.Devices = append(a.Devices, d)
				if d.Online {
					a.Online = true
				}
			}
		}
		for _, m := range histByIP[s] {
			if !contains(a.MACs, m) {
				a.History = append(a.History, m)
			}
		}

		a.Status, a.Note = classify(a, resByMAC, macAt)

		if a.Network || a.Bcast {
			if opts.IncludeEdges {
				out = append(out, a)
			}
			continue
		}
		sum.Total++
		switch a.Status {
		case StatusFree:
			sum.Free++
		case StatusReserved:
			sum.Reserved++
		case StatusInUse:
			sum.InUse++
		case StatusMatch:
			sum.Match++
		case StatusMismatch:
			sum.Mismatch++
		case StatusConflict:
			sum.Conflict++
		}
		if a.Online {
			sum.Online++
		}
		out = append(out, a)
	}
	return out, sum, nil
}

func classify(a Address, resByMAC map[string]*model.Reservation, macAt map[string][]string) (Status, string) {
	switch {
	case len(a.MACs) > 1:
		return StatusConflict, fmt.Sprintf("%d MACs claim this address: %s", len(a.MACs), strings.Join(a.MACs, ", "))
	case a.Reservation == nil && len(a.MACs) == 0:
		return StatusFree, ""
	case a.Reservation == nil:
		// Unplanned usage. Is this MAC supposed to be somewhere else?
		if r, ok := resByMAC[a.MACs[0]]; ok && r.IP != a.IP {
			return StatusMismatch, fmt.Sprintf("%s is reserved %s but is here", r.Label, r.IP)
		}
		return StatusInUse, ""
	case len(a.MACs) == 0:
		// Planned, nothing here. Is the reserved MAC squatting elsewhere?
		if a.Reservation.MAC != "" {
			if elsewhere := macAt[a.Reservation.MAC]; len(elsewhere) > 0 {
				return StatusMismatch, fmt.Sprintf("reserved MAC is using %s instead", strings.Join(elsewhere, ", "))
			}
		}
		return StatusReserved, ""
	default:
		// Planned and in use by exactly one MAC.
		if a.Reservation.MAC == "" {
			return StatusMatch, "reservation has no MAC; occupied as planned"
		}
		if a.MACs[0] == a.Reservation.MAC {
			return StatusMatch, ""
		}
		return StatusMismatch, fmt.Sprintf("reserved for %s, used by %s", a.Reservation.MAC, a.MACs[0])
	}
}

// Filter keeps addresses whose status is in the set (empty set = all).
func Filter(addrs []Address, statuses ...Status) []Address {
	if len(statuses) == 0 {
		return addrs
	}
	set := map[Status]bool{}
	for _, s := range statuses {
		set[s] = true
	}
	var out []Address
	for _, a := range addrs {
		if set[a.Status] {
			out = append(out, a)
		}
	}
	return out
}

// NextFree returns the first free address after start (or the first free
// address in the subnet when start is empty). "" when none.
func NextFree(addrs []Address, start string) string {
	seen := start == ""
	for _, a := range addrs {
		if a.IP == start {
			seen = true
			continue
		}
		if seen && a.Status == StatusFree && !a.Gateway {
			return a.IP
		}
	}
	return ""
}

func appendUnique(list []string, s string) []string {
	if contains(list, s) {
		return list
	}
	return append(list, s)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
