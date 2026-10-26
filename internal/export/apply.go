package export

import (
	"fmt"
	"net"
	"strings"

	"github.com/sethrichar/netscout/internal/model"
	"github.com/sethrichar/netscout/internal/store"
)

// ApplyOptions control how an Import is written to the store.
type ApplyOptions struct {
	// DefaultSubnet (CIDR or name) receives rows that name no subnet and fall
	// in no existing subnet.
	DefaultSubnet string
	// AutoSubnets creates a /24 for rows that cannot be placed otherwise.
	AutoSubnets bool
	// DryRun computes the report without writing.
	DryRun bool
}

// Report summarises what Apply did (or would do).
type Report struct {
	SubnetsCreated      []string
	ReservationsWritten int
	DevicesLabelled     int
	Skipped             []string // "line N: reason"
}

// Apply writes reservations, subnets and device labels from an Import.
func Apply(st *store.Store, imp *Import, opts ApplyOptions) (Report, error) {
	var rep Report
	subnets, err := st.ListSubnets()
	if err != nil {
		return rep, err
	}
	findSubnet := func(ref string) *model.Subnet {
		if _, n, err := net.ParseCIDR(ref); err == nil {
			ref = n.String()
		}
		for i := range subnets {
			if subnets[i].CIDR == ref || (subnets[i].Name != "" && strings.EqualFold(subnets[i].Name, ref)) || fmt.Sprint(subnets[i].ID) == ref {
				return &subnets[i]
			}
		}
		return nil
	}
	containing := func(ip string) *model.Subnet {
		p := net.ParseIP(ip)
		var best *model.Subnet
		bestOnes := -1
		for i := range subnets {
			_, n, err := net.ParseCIDR(subnets[i].CIDR)
			if err != nil || !n.Contains(p) {
				continue
			}
			if ones, _ := n.Mask.Size(); ones > bestOnes {
				best, bestOnes = &subnets[i], ones
			}
		}
		return best
	}
	create := func(sn model.Subnet) (*model.Subnet, error) {
		if _, n, err := net.ParseCIDR(sn.CIDR); err == nil {
			sn.CIDR = n.String()
		} else {
			return nil, fmt.Errorf("invalid subnet %q: %w", sn.CIDR, err)
		}
		if existing := findSubnet(sn.CIDR); existing != nil {
			return existing, nil
		}
		if !opts.DryRun {
			saved, err := st.AddSubnet(sn)
			if err != nil {
				return nil, err
			}
			sn = saved
		} else {
			sn.ID = -int64(len(subnets) + 1)
		}
		subnets = append(subnets, sn)
		rep.SubnetsCreated = append(rep.SubnetsCreated, sn.CIDR)
		return &subnets[len(subnets)-1], nil
	}

	// Subnets carried by a JSON snapshot come first.
	for _, sn := range imp.Subnets {
		if _, err := create(model.Subnet{CIDR: sn.CIDR, Name: sn.Name, VLAN: sn.VLAN, Gateway: sn.Gateway, Notes: sn.Notes}); err != nil {
			return rep, err
		}
	}
	if opts.DefaultSubnet != "" && findSubnet(opts.DefaultSubnet) == nil {
		if _, _, err := net.ParseCIDR(opts.DefaultSubnet); err != nil {
			return rep, fmt.Errorf("--subnet %q is neither an existing subnet nor a CIDR", opts.DefaultSubnet)
		}
		if _, err := create(model.Subnet{CIDR: opts.DefaultSubnet}); err != nil {
			return rep, err
		}
	}

	for _, row := range imp.Rows {
		if row.IP == "" {
			// Label-only row.
			if row.MAC == "" {
				continue
			}
			if !opts.DryRun {
				var label, notes *string
				if row.Label != "" {
					label = &row.Label
				}
				if row.Notes != "" {
					notes = &row.Notes
				}
				if err := st.SetUserFields(row.MAC, label, notes, row.Tags); err != nil {
					return rep, fmt.Errorf("line %d: %w", row.Line, err)
				}
			}
			rep.DevicesLabelled++
			continue
		}
		var sn *model.Subnet
		switch {
		case row.Subnet != "":
			sn = findSubnet(row.Subnet)
			if sn == nil {
				if _, _, err := net.ParseCIDR(row.Subnet); err != nil {
					rep.Skipped = append(rep.Skipped, fmt.Sprintf("line %d: unknown subnet %q", row.Line, row.Subnet))
					continue
				}
				if sn, err = create(model.Subnet{CIDR: row.Subnet, VLAN: row.VLAN}); err != nil {
					return rep, err
				}
			}
		default:
			sn = containing(row.IP)
			if sn == nil && opts.DefaultSubnet != "" {
				sn = findSubnet(opts.DefaultSubnet)
			}
			if sn == nil && opts.AutoSubnets {
				p := net.ParseIP(row.IP).To4()
				if sn, err = create(model.Subnet{CIDR: fmt.Sprintf("%d.%d.%d.0/24", p[0], p[1], p[2]), VLAN: row.VLAN}); err != nil {
					return rep, err
				}
			}
		}
		if sn == nil {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("line %d: %s is in no known subnet (use --subnet <cidr> or --auto-subnets)", row.Line, row.IP))
			continue
		}
		if _, n, _ := net.ParseCIDR(sn.CIDR); n != nil && !n.Contains(net.ParseIP(row.IP)) {
			rep.Skipped = append(rep.Skipped, fmt.Sprintf("line %d: %s is outside %s", row.Line, row.IP, sn.CIDR))
			continue
		}
		if !opts.DryRun {
			if _, err := st.UpsertReservation(model.Reservation{SubnetID: sn.ID, IP: row.IP, MAC: row.MAC, Label: row.Label, Notes: row.Notes}); err != nil {
				return rep, fmt.Errorf("line %d: %w", row.Line, err)
			}
			// Carry the plan's name onto the device itself if it has no label yet.
			if row.MAC != "" && row.Label != "" {
				if d, _ := st.GetDevice(row.MAC); d == nil || d.Label == "" {
					if err := st.SetUserFields(row.MAC, &row.Label, nil, row.Tags); err == nil {
						rep.DevicesLabelled++
					}
				}
			}
		}
		rep.ReservationsWritten++
	}
	return rep, nil
}
