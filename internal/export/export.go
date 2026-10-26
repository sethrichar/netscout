// Package export reads and writes netscout's inventory as CSV and JSON, both
// for show documentation (export) and for loading a client's IP plan (import).
package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/sethrichar/netscout/internal/model"
)

// Snapshot is the JSON export format. It is also accepted by Import.
type Snapshot struct {
	Format       string              `json:"format"` // "netscout"
	Version      string              `json:"version"`
	ExportedAt   time.Time           `json:"exported_at"`
	Subnets      []model.Subnet      `json:"subnets"`
	Reservations []model.Reservation `json:"reservations"`
	Devices      []model.Device      `json:"devices"`
}

// WriteJSON writes the snapshot indented.
func WriteJSON(w io.Writer, s Snapshot) error {
	if s.Format == "" {
		s.Format = "netscout"
	}
	if s.ExportedAt.IsZero() {
		s.ExportedAt = time.Now().UTC()
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("encoding JSON: %w", err)
	}
	return nil
}

// DeviceCSVHeader is the column order of WriteDevicesCSV.
var DeviceCSVHeader = []string{"ip", "mac", "vendor", "hostname", "label", "tags", "notes", "online", "first_seen", "last_seen", "other_ips", "services", "randomized"}

// WriteDevicesCSV writes one row per device (most recent IP first).
func WriteDevicesCSV(w io.Writer, devs []model.Device) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(DeviceCSVHeader); err != nil {
		return err
	}
	for _, d := range devs {
		other := ""
		if len(d.IPs) > 1 {
			other = strings.Join(d.IPs[1:], " ")
		}
		row := []string{
			d.IP(), d.MAC, safeCell(d.Vendor), safeCell(d.Hostname), safeCell(d.Label), safeCell(strings.Join(d.Tags, ";")), safeCell(d.Notes),
			boolStr(d.Online), fmtTime(d.FirstSeen), fmtTime(d.LastSeen), other, safeCell(d.Attrs["services"]), boolStr(d.Randomized),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// safeCell neutralises spreadsheet formula injection: hostnames and vendor
// strings come off the wire, and a cell starting with = + - @ would be
// evaluated by Excel/Sheets when the show doc is opened.
func safeCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

// ReservationCSVHeader is the column order of WriteReservationsCSV — and the
// simplest shape Import accepts.
var ReservationCSVHeader = []string{"subnet", "ip", "mac", "label", "notes"}

// WriteReservationsCSV writes the IP plan.
func WriteReservationsCSV(w io.Writer, subnets []model.Subnet, res []model.Reservation) error {
	byID := map[int64]string{}
	for _, s := range subnets {
		byID[s.ID] = s.CIDR
	}
	cw := csv.NewWriter(w)
	if err := cw.Write(ReservationCSVHeader); err != nil {
		return err
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].SubnetID != res[j].SubnetID {
			return res[i].SubnetID < res[j].SubnetID
		}
		return ipLess(res[i].IP, res[j].IP)
	})
	for _, r := range res {
		if err := cw.Write([]string{byID[r.SubnetID], r.IP, r.MAC, safeCell(r.Label), safeCell(r.Notes)}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// --- import ------------------------------------------------------------------

// Row is one planned address or device label from an import file.
type Row struct {
	Line   int
	Subnet string // CIDR or name, may be empty
	IP     string
	MAC    string
	Label  string
	Notes  string
	Tags   []string
	VLAN   int
}

// Import is the parsed, not-yet-applied content of an import file.
type Import struct {
	Subnets []model.Subnet // only from JSON snapshots
	Rows    []Row
	// Warnings are per-row problems that did not stop the import (an
	// unparseable IP cell, a duplicate address). Apply copies them into the
	// report so the operator sees them.
	Warnings []string
	// DevicesOnly is set when the file is netscout's own devices export: its
	// rows carry labels/notes/tags for devices and are not an IP plan, so no
	// reservations are created from them.
	DevicesOnly bool
}

// Parse detects JSON (netscout snapshot) or CSV and returns the rows.
func Parse(r io.Reader) (*Import, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading import: %w", err)
	}
	trim := strings.TrimLeft(strings.TrimPrefix(string(data), "\xef\xbb\xbf"), " \t\r\n")
	if strings.HasPrefix(trim, "{") {
		return parseJSON([]byte(trim))
	}
	return parseCSV(trim)
}

func parseJSON(data []byte) (*Import, error) {
	var s Snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("decoding JSON snapshot: %w", err)
	}
	imp := &Import{Subnets: s.Subnets}
	byID := map[int64]string{}
	for _, sn := range s.Subnets {
		byID[sn.ID] = sn.CIDR
	}
	for i, r := range s.Reservations {
		if p := net.ParseIP(r.IP); p == nil || p.To4() == nil {
			return nil, fmt.Errorf("reservation %d: %q is not an IPv4 address", i+1, r.IP)
		}
		if r.MAC != "" {
			m, err := model.NormalizeMAC(r.MAC)
			if err != nil {
				return nil, fmt.Errorf("reservation %d: %w", i+1, err)
			}
			r.MAC = m
		}
		imp.Rows = append(imp.Rows, Row{Line: i + 1, Subnet: byID[r.SubnetID], IP: r.IP, MAC: r.MAC, Label: r.Label, Notes: r.Notes})
	}
	for i, d := range s.Devices {
		if d.Label == "" && d.Notes == "" && len(d.Tags) == 0 {
			continue
		}
		m, err := model.NormalizeMAC(d.MAC)
		if err != nil {
			return nil, fmt.Errorf("device %d: %w", i+1, err)
		}
		imp.Rows = append(imp.Rows, Row{Line: len(s.Reservations) + i + 1, MAC: m, Label: d.Label, Notes: d.Notes, Tags: d.Tags})
	}
	return imp, nil
}

// Column aliases accepted in CSV headers (lower-cased, trimmed), with a rank:
// when two columns map to the same field the lower rank wins, so an explicit
// "label" beats "hostname" and "ip address" beats a stray "address".
type alias struct {
	canon string
	rank  int
}

var columnAliases = map[string]alias{
	"ip": {"ip", 0}, "ip address": {"ip", 0}, "ipaddress": {"ip", 0}, "ipv4": {"ip", 0}, "ipv4 address": {"ip", 0}, "ip addr": {"ip", 0}, "static ip": {"ip", 1}, "address": {"ip", 2},
	"mac": {"mac", 0}, "mac address": {"mac", 0}, "macaddress": {"mac", 0}, "mac addr": {"mac", 0}, "hardware address": {"mac", 1}, "hw address": {"mac", 1}, "hwaddr": {"mac", 1}, "ethernet": {"mac", 2},
	"label": {"label", 0}, "name": {"label", 1}, "device name": {"label", 1}, "device": {"label", 2}, "unit": {"label", 2}, "hostname": {"label", 3}, "host": {"label", 3}, "description": {"label", 4}, "desc": {"label", 4},
	"notes": {"notes", 0}, "note": {"notes", 0}, "comment": {"notes", 1}, "comments": {"notes", 1}, "location": {"notes", 2},
	"subnet": {"subnet", 0}, "cidr": {"subnet", 0}, "network": {"subnet", 1}, "net": {"subnet", 2},
	"tags": {"tags", 0}, "tag": {"tags", 0}, "group": {"tags", 1}, "category": {"tags", 1}, "type": {"tags", 2},
	"vlan": {"vlan", 0},
}

func parseCSV(text string) (*Import, error) {
	cr := csv.NewReader(strings.NewReader(text))
	cr.FieldsPerRecord = -1
	cr.TrimLeadingSpace = true
	cr.LazyQuotes = true
	// Sniff the delimiter from the first line.
	if first := strings.SplitN(text, "\n", 2)[0]; strings.Count(first, "\t") > strings.Count(first, ",") {
		cr.Comma = '\t'
	} else if strings.Count(first, ";") > strings.Count(first, ",") {
		cr.Comma = ';'
	}
	records, err := cr.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("parsing CSV: %w", err)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("empty file")
	}
	imp := &Import{}

	// Header detection: a header row has no IP/MAC-looking cells.
	cols := map[string]int{}
	rank := map[string]int{}
	start := 0
	if !looksLikeData(records[0]) {
		for i, h := range records[0] {
			key := strings.ToLower(strings.TrimSpace(h))
			if a, ok := columnAliases[key]; ok {
				if r, dup := rank[a.canon]; !dup || a.rank < r {
					cols[a.canon], rank[a.canon] = i, a.rank
				}
			}
		}
		start = 1
		// netscout's own devices export: labels for devices, not an IP plan.
		if _, hasVendor := indexOf(records[0], "vendor"); hasVendor {
			if _, hasFirst := indexOf(records[0], "first_seen"); hasFirst {
				imp.DevicesOnly = true
			}
		}
		// A header was found but no IP (or MAC) column was recognised: adopt
		// the column whose cells look like addresses instead of silently
		// importing everything as label-only rows.
		for _, want := range []string{"ip", "mac"} {
			if _, ok := cols[want]; !ok {
				if idx := guessColumn(records[1:], want); idx >= 0 {
					cols[want] = idx
				}
			}
		}
	}
	for i := start; i < len(records); i++ {
		rec := records[i]
		if len(rec) == 0 || allEmpty(rec) {
			continue
		}
		var row Row
		row.Line = i + 1
		if len(cols) > 0 {
			row.IP = cell(rec, cols, "ip")
			row.MAC = cell(rec, cols, "mac")
			row.Label = cell(rec, cols, "label")
			row.Notes = cell(rec, cols, "notes")
			row.Subnet = cell(rec, cols, "subnet")
			if t := cell(rec, cols, "tags"); t != "" {
				row.Tags = splitTags(t)
			}
			if v := cell(rec, cols, "vlan"); v != "" {
				fmt.Sscanf(v, "%d", &row.VLAN)
			}
			if imp.DevicesOnly {
				row.IP = "" // keep label/notes/tags only
			}
		} else {
			// Headerless: guess each cell by shape. ip, mac, then label, notes.
			var rest []string
			for _, c := range rec {
				c = strings.TrimSpace(c)
				switch {
				case row.IP == "" && net.ParseIP(c) != nil && net.ParseIP(c).To4() != nil:
					row.IP = c
				case row.MAC == "" && isMAC(c):
					row.MAC = c
				case c != "":
					rest = append(rest, c)
				}
			}
			if len(rest) > 0 {
				row.Label = rest[0]
			}
			if len(rest) > 1 {
				row.Notes = strings.Join(rest[1:], " / ")
			}
		}
		// A cell that is not an address ("DHCP", "TBD", a range) is a problem
		// for that row only: report it and keep going.
		row.IP = strings.TrimSpace(row.IP)
		if row.IP != "" {
			if p := net.ParseIP(row.IP); p == nil || p.To4() == nil {
				imp.Warnings = append(imp.Warnings, fmt.Sprintf("line %d: %q is not an IPv4 address; row skipped", row.Line, row.IP))
				continue
			}
		}
		if row.MAC != "" {
			m, err := model.NormalizeMAC(row.MAC)
			if err != nil {
				imp.Warnings = append(imp.Warnings, fmt.Sprintf("line %d: %q is not a MAC address; MAC ignored", row.Line, row.MAC))
				row.MAC = ""
			} else {
				row.MAC = m
			}
		}
		if row.IP == "" && row.MAC == "" {
			continue
		}
		imp.Rows = append(imp.Rows, row)
	}
	if len(imp.Rows) == 0 {
		msg := "no rows with an IP or MAC found (recognised columns: ip, mac, label/name, notes, subnet, tags)"
		if len(imp.Warnings) > 0 {
			msg += "; " + strings.Join(imp.Warnings, "; ")
		}
		return nil, fmt.Errorf("%s", msg)
	}
	return imp, nil
}

// indexOf finds a header cell by exact (case-insensitive) name.
func indexOf(header []string, name string) (int, bool) {
	for i, h := range header {
		if strings.EqualFold(strings.TrimSpace(h), name) {
			return i, true
		}
	}
	return -1, false
}

// guessColumn returns the index of the column whose non-empty cells are
// mostly IPv4 addresses (want="ip") or MACs (want="mac"), or -1.
func guessColumn(rows [][]string, want string) int {
	best, bestScore := -1, 0
	width := 0
	for _, r := range rows {
		if len(r) > width {
			width = len(r)
		}
	}
	for c := 0; c < width; c++ {
		hits, total := 0, 0
		for _, r := range rows {
			if c >= len(r) {
				continue
			}
			v := strings.TrimSpace(r[c])
			if v == "" {
				continue
			}
			total++
			switch want {
			case "ip":
				if p := net.ParseIP(v); p != nil && p.To4() != nil {
					hits++
				}
			case "mac":
				if isMAC(v) {
					hits++
				}
			}
		}
		if total > 0 && hits*2 > total && hits > bestScore {
			best, bestScore = c, hits
		}
	}
	return best
}

func cell(rec []string, cols map[string]int, key string) string {
	i, ok := cols[key]
	if !ok || i >= len(rec) {
		return ""
	}
	return strings.TrimSpace(rec[i])
}

func looksLikeData(rec []string) bool {
	for _, c := range rec {
		c = strings.TrimSpace(c)
		if p := net.ParseIP(c); p != nil && p.To4() != nil {
			return true
		}
		if isMAC(c) {
			return true
		}
	}
	return false
}

func isMAC(s string) bool {
	_, err := model.NormalizeMAC(s)
	return err == nil && len(s) >= 12
}

func allEmpty(rec []string) bool {
	for _, c := range rec {
		if strings.TrimSpace(c) != "" {
			return false
		}
	}
	return true
}

func splitTags(s string) []string {
	var out []string
	for _, t := range strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' || r == '|' }) {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func ipLess(a, b string) bool {
	pa, pb := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if pa == nil || pb == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}
