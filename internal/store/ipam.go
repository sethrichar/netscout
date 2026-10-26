package store

import (
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/sethrichar/netscout/internal/model"
)

// --- subnets -----------------------------------------------------------------

// AddSubnet inserts a subnet and returns it with its ID. The CIDR is
// normalised to its network address.
func (s *Store) AddSubnet(sn model.Subnet) (model.Subnet, error) {
	n, err := ValidateSubnetCIDR(sn.CIDR)
	if err != nil {
		return sn, err
	}
	sn.CIDR = n.String()
	if sn.Gateway != "" {
		gw := net.ParseIP(sn.Gateway)
		if gw == nil || gw.To4() == nil || !n.Contains(gw) {
			return sn, fmt.Errorf("gateway %q is not an IPv4 address inside %s", sn.Gateway, n)
		}
	}
	res, err := s.db.Exec(`INSERT INTO subnets (cidr, name, vlan, gateway, notes) VALUES (?, ?, ?, ?, ?)`,
		sn.CIDR, sn.Name, sn.VLAN, sn.Gateway, sn.Notes)
	if err != nil {
		return sn, fmt.Errorf("adding subnet %s: %w", sn.CIDR, err)
	}
	sn.ID, _ = res.LastInsertId()
	return sn, nil
}

// ValidateSubnetCIDR accepts IPv4 networks no larger than /16 — the limit the
// address map and the sweeps can handle.
func ValidateSubnetCIDR(cidr string) (*net.IPNet, error) {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	if n.IP.To4() == nil {
		return nil, fmt.Errorf("%q: only IPv4 subnets are supported", cidr)
	}
	if ones, bits := n.Mask.Size(); bits-ones > model.MaxSubnetHostBits {
		return nil, fmt.Errorf("%q is larger than /%d; register smaller subnets", cidr, 32-model.MaxSubnetHostBits)
	}
	return n, nil
}

// UpdateSubnet rewrites name/vlan/gateway/notes for an existing subnet.
func (s *Store) UpdateSubnet(sn model.Subnet) error {
	res, err := s.db.Exec(`UPDATE subnets SET name = ?, vlan = ?, gateway = ?, notes = ? WHERE id = ?`,
		sn.Name, sn.VLAN, sn.Gateway, sn.Notes, sn.ID)
	if err != nil {
		return fmt.Errorf("updating subnet %d: %w", sn.ID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("subnet %d not found", sn.ID)
	}
	return nil
}

// DeleteSubnet removes a subnet and its reservations.
func (s *Store) DeleteSubnet(id int64) error {
	if _, err := s.db.Exec(`DELETE FROM subnets WHERE id = ?`, id); err != nil {
		return fmt.Errorf("deleting subnet %d: %w", id, err)
	}
	return nil
}

// ListSubnets returns every subnet ordered by CIDR.
func (s *Store) ListSubnets() ([]model.Subnet, error) {
	rows, err := s.db.Query(`SELECT id, cidr, name, vlan, gateway, notes FROM subnets ORDER BY cidr`)
	if err != nil {
		return nil, fmt.Errorf("listing subnets: %w", err)
	}
	defer rows.Close()
	var out []model.Subnet
	for rows.Next() {
		var sn model.Subnet
		if err := rows.Scan(&sn.ID, &sn.CIDR, &sn.Name, &sn.VLAN, &sn.Gateway, &sn.Notes); err != nil {
			return nil, err
		}
		out = append(out, sn)
	}
	return out, rows.Err()
}

// GetSubnet fetches by ID; nil when missing.
func (s *Store) GetSubnet(id int64) (*model.Subnet, error) {
	var sn model.Subnet
	err := s.db.QueryRow(`SELECT id, cidr, name, vlan, gateway, notes FROM subnets WHERE id = ?`, id).
		Scan(&sn.ID, &sn.CIDR, &sn.Name, &sn.VLAN, &sn.Gateway, &sn.Notes)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("getting subnet %d: %w", id, err)
	}
	return &sn, nil
}

// FindSubnet resolves a user reference: numeric ID, exact CIDR, or name.
func (s *Store) FindSubnet(ref string) (*model.Subnet, error) {
	subnets, err := s.ListSubnets()
	if err != nil {
		return nil, err
	}
	if _, n, err := net.ParseCIDR(ref); err == nil {
		ref = n.String()
	}
	for _, sn := range subnets {
		if sn.CIDR == ref || sn.Name == ref || fmt.Sprint(sn.ID) == ref {
			return &sn, nil
		}
	}
	return nil, nil
}

// SubnetContaining returns the most specific subnet holding ip, or nil.
func (s *Store) SubnetContaining(ip string) (*model.Subnet, error) {
	p := net.ParseIP(ip)
	if p == nil {
		return nil, fmt.Errorf("invalid IP %q", ip)
	}
	subnets, err := s.ListSubnets()
	if err != nil {
		return nil, err
	}
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
	return best, nil
}

// --- reservations ------------------------------------------------------------

// UpsertReservation creates or replaces the reservation for (subnet, ip).
func (s *Store) UpsertReservation(r model.Reservation) (model.Reservation, error) {
	if r.MAC != "" {
		mac, err := model.NormalizeMAC(r.MAC)
		if err != nil {
			return r, err
		}
		r.MAC = mac
	}
	ip := net.ParseIP(r.IP)
	if ip == nil || ip.To4() == nil {
		return r, fmt.Errorf("invalid IPv4 address %q", r.IP)
	}
	r.IP = ip.To4().String()
	sn, err := s.GetSubnet(r.SubnetID)
	if err != nil {
		return r, err
	}
	if sn == nil {
		return r, fmt.Errorf("subnet %d not found", r.SubnetID)
	}
	if _, n, err := net.ParseCIDR(sn.CIDR); err == nil && !n.Contains(ip) {
		return r, fmt.Errorf("%s is not inside %s", r.IP, sn.CIDR)
	}
	_, err = s.db.Exec(`
INSERT INTO reservations (subnet_id, ip, mac, label, notes) VALUES (?, ?, ?, ?, ?)
ON CONFLICT(subnet_id, ip) DO UPDATE SET mac = excluded.mac, label = excluded.label, notes = excluded.notes`,
		r.SubnetID, r.IP, r.MAC, r.Label, r.Notes)
	if err != nil {
		return r, fmt.Errorf("saving reservation %s: %w", r.IP, err)
	}
	if err := s.db.QueryRow(`SELECT id FROM reservations WHERE subnet_id = ? AND ip = ?`, r.SubnetID, r.IP).Scan(&r.ID); err != nil {
		return r, fmt.Errorf("reading reservation id: %w", err)
	}
	return r, nil
}

// DeleteReservation removes the reservation for (subnet, ip).
func (s *Store) DeleteReservation(subnetID int64, ip string) error {
	res, err := s.db.Exec(`DELETE FROM reservations WHERE subnet_id = ? AND ip = ?`, subnetID, ip)
	if err != nil {
		return fmt.Errorf("deleting reservation %s: %w", ip, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("no reservation for %s", ip)
	}
	return nil
}

// ListReservations returns reservations for one subnet (0 = all).
func (s *Store) ListReservations(subnetID int64) ([]model.Reservation, error) {
	q := `SELECT id, subnet_id, ip, mac, label, notes FROM reservations`
	var args []any
	if subnetID != 0 {
		q += ` WHERE subnet_id = ?`
		args = append(args, subnetID)
	}
	q += ` ORDER BY subnet_id, ip`
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("listing reservations: %w", err)
	}
	defer rows.Close()
	var out []model.Reservation
	for rows.Next() {
		var r model.Reservation
		if err := rows.Scan(&r.ID, &r.SubnetID, &r.IP, &r.MAC, &r.Label, &r.Notes); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- bindings ----------------------------------------------------------------

// IPBinding is one (MAC, IP) pair with its observation window.
type IPBinding struct {
	MAC       string
	IP        string
	FirstSeen time.Time
	LastSeen  time.Time
}

// ListBindings returns every IP ever seen for every device, newest first.
func (s *Store) ListBindings() ([]IPBinding, error) {
	rows, err := s.db.Query(`SELECT mac, ip, first_seen, last_seen FROM device_ips ORDER BY last_seen DESC`)
	if err != nil {
		return nil, fmt.Errorf("listing bindings: %w", err)
	}
	defer rows.Close()
	var out []IPBinding
	for rows.Next() {
		var b IPBinding
		var f, l string
		if err := rows.Scan(&b.MAC, &b.IP, &f, &l); err != nil {
			return nil, err
		}
		b.FirstSeen, b.LastSeen = parseTime(f), parseTime(l)
		out = append(out, b)
	}
	return out, rows.Err()
}
