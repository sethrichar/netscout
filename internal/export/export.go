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
			d.IP(), d.MAC, d.Vendor, d.Hostname, d.Label, strings.Join(d.Tags, ";"), d.Notes,
			boolStr(d.Online), fmtTime(d.FirstSeen), fmtTime(d.LastSeen), other, d.Attrs["services"], boolStr(d.Randomized),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
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
		if err := cw.Write([]string{byID[r.SubnetID], r.IP, r.MAC, r.Label, r.Notes}); err != nil {
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
		imp.Rows = append(imp.Rows, Row{Line: i + 1, Subnet: byID[r.SubnetID], IP: r.IP, MAC: r.MAC, Label: r.Label, Notes: r.Notes})
	}
	for i, d := range s.Devices {
		if d.Label == "" && d.Notes == "" && len(d.Tags) == 0 {
			continue
		}
		imp.Rows = append(imp.Rows, Row{Line: len(s.Reservations) + i + 1, MAC: d.MAC, Label: d.Label, Notes: d.Notes, Tags: d.Tags})
	}
	return imp, nil
}

// Column aliases accepted in CSV headers (lower-cased, trimmed).
var columnAliases = map[string]string{
	"ip": "ip", "ip address": "ip", "ipaddress": "ip", "address": "ip", "ipv4": "ip", "ip addr": "ip",
	"mac": "mac", "mac address": "mac", "macaddress": "mac", "hw address": "mac", "hwaddr": "mac", "ethernet": "mac", "hardware address": "mac",
	"label": "label", "name": "label", "device": "label", "device name": "label", "hostname": "label", "host": "label", "description": "label", "desc": "label", "unit": "label",
	"notes": "notes", "note": "notes", "comment": "notes", "comments": "notes", "location": "notes",
	"subnet": "subnet", "cidr": "subnet", "network": "subnet", "net": "subnet",
	"tags": "tags", "tag": "tags", "group": "tags", "category": "tags", "type": "tags",
	"vlan": "vlan",
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
	start := 0
	if !looksLikeData(records[0]) {
		for i, h := range records[0] {
			key := strings.ToLower(strings.TrimSpace(h))
			if canon, ok := columnAliases[key]; ok {
				if _, dup := cols[canon]; !dup {
					cols[canon] = i
				}
			}
		}
		start = 1
	}
	if _, ok := cols["ip"]; !ok && start == 1 {
		// No recognised IP column — maybe there is no header and the first row was data.
		if looksLikeData(records[0]) {
			start = 0
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
		row.IP = strings.TrimSpace(row.IP)
		if row.IP != "" {
			if p := net.ParseIP(row.IP); p == nil || p.To4() == nil {
				return nil, fmt.Errorf("line %d: %q is not an IPv4 address", row.Line, row.IP)
			}
		}
		if row.MAC != "" {
			m, err := model.NormalizeMAC(row.MAC)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", row.Line, err)
			}
			row.MAC = m
		}
		if row.IP == "" && row.MAC == "" {
			continue
		}
		imp.Rows = append(imp.Rows, row)
	}
	if len(imp.Rows) == 0 {
		return nil, fmt.Errorf("no rows with an IP or MAC found (recognised columns: ip, mac, label/name, notes, subnet, tags)")
	}
	return imp, nil
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
