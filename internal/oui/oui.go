// Package oui resolves MAC addresses to vendors using the Wireshark `manuf`
// database (IEEE OUI 24-bit, MA-M 28-bit and MA-S 36-bit registries merged).
// A copy is embedded in the binary so lookups work offline; `update-oui`
// refreshes a copy in the data directory which takes precedence when present.
package oui

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/sethrichar/netscout/internal/model"
)

// Entry is one registry assignment.
type Entry struct {
	Prefix string `json:"prefix"` // canonical, e.g. "00:1b:c5:00:00:00/36" or "00:1d:c1/24"
	Bits   int    `json:"bits"`   // 24, 28 or 36
	Short  string `json:"short"`  // Wireshark's abbreviated name ("Audinate")
	Long   string `json:"long"`   // full registrant name ("Audinate Pty Ltd")
}

// DB is an in-memory, read-only vendor database.
type DB struct {
	m24 map[uint32]Entry
	m28 map[uint32]Entry
	m36 map[uint64]Entry
	// Source describes where the data came from ("embedded", a file path…).
	Source string
}

// Len returns the number of assignments loaded.
func (db *DB) Len() int { return len(db.m24) + len(db.m28) + len(db.m36) }

// Parse reads the Wireshark manuf text format:
//
//	00:00:0C<TAB>Cisco<TAB>Cisco Systems, Inc
//	00:55:DA:00:00:00/28<TAB>ShinkoTechno<TAB>Shinko Technos co.,ltd.
//	00:1B:C5:00:00:00/36<TAB>Converging<TAB>Converging Systems Inc.
//
// Lines starting with # and blank lines are ignored. Both the padded
// (six-octet) and truncated prefix spellings are accepted.
func Parse(r io.Reader) (*DB, error) {
	db := &DB{m24: map[uint32]Entry{}, m28: map[uint32]Entry{}, m36: map[uint64]Entry{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 2 {
			// Some older files use runs of spaces.
			fields = strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			if len(fields) > 3 {
				fields = []string{fields[0], fields[1], strings.Join(fields[2:], " ")}
			}
		}
		prefix, bits, err := parsePrefix(strings.TrimSpace(fields[0]))
		if err != nil {
			return nil, fmt.Errorf("manuf line %d: %w", lineNo, err)
		}
		e := Entry{Bits: bits, Short: strings.TrimSpace(fields[1])}
		if len(fields) >= 3 {
			e.Long = strings.TrimSpace(fields[2])
		}
		if e.Long == "" {
			e.Long = e.Short
		}
		db.add(prefix, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading manuf: %w", err)
	}
	return db, nil
}

// parsePrefix returns the first 5 bytes (zero padded) and the prefix length.
func parsePrefix(s string) ([5]byte, int, error) {
	var b [5]byte
	bits := 24
	if i := strings.IndexByte(s, '/'); i >= 0 {
		n, err := strconv.Atoi(s[i+1:])
		if err != nil {
			return b, 0, fmt.Errorf("bad prefix length in %q", s)
		}
		bits = n
		s = s[:i]
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ':' || r == '-' || r == '.' })
	if len(parts) < 3 || len(parts) > 6 {
		return b, 0, fmt.Errorf("bad prefix %q", s)
	}
	for i, p := range parts {
		if i >= 5 {
			break
		}
		if len(p) != 2 {
			return b, 0, fmt.Errorf("bad octet %q in %q", p, s)
		}
		v, err := hex.DecodeString(p)
		if err != nil {
			return b, 0, fmt.Errorf("bad octet %q in %q", p, s)
		}
		b[i] = v[0]
	}
	switch bits {
	case 24, 28, 36:
	default:
		return b, 0, fmt.Errorf("unsupported prefix length /%d in %q", bits, s)
	}
	return b, bits, nil
}

func (db *DB) add(b [5]byte, e Entry) {
	switch e.Bits {
	case 24:
		e.Prefix = fmt.Sprintf("%02x:%02x:%02x/24", b[0], b[1], b[2])
		db.m24[key24(b[0], b[1], b[2])] = e
	case 28:
		e.Prefix = fmt.Sprintf("%02x:%02x:%02x:%02x:00:00/28", b[0], b[1], b[2], b[3]&0xf0)
		db.m28[key28(b[0], b[1], b[2], b[3])] = e
	case 36:
		e.Prefix = fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:00/36", b[0], b[1], b[2], b[3], b[4]&0xf0)
		db.m36[key36(b[0], b[1], b[2], b[3], b[4])] = e
	}
}

func key24(a, b, c byte) uint32 { return uint32(a)<<16 | uint32(b)<<8 | uint32(c) }
func key28(a, b, c, d byte) uint32 {
	return uint32(a)<<20 | uint32(b)<<12 | uint32(c)<<4 | uint32(d)>>4
}
func key36(a, b, c, d, e byte) uint64 {
	return uint64(a)<<28 | uint64(b)<<20 | uint64(c)<<12 | uint64(d)<<4 | uint64(e)>>4
}

// Find returns the longest-prefix registry entry for a MAC address.
func (db *DB) Find(mac string) (Entry, bool) {
	if db == nil {
		return Entry{}, false
	}
	n, err := model.NormalizeMAC(mac)
	if err != nil {
		return Entry{}, false
	}
	raw, err := hex.DecodeString(strings.ReplaceAll(n, ":", ""))
	if err != nil || len(raw) != 6 {
		return Entry{}, false
	}
	if e, ok := db.m36[key36(raw[0], raw[1], raw[2], raw[3], raw[4])]; ok {
		return e, true
	}
	if e, ok := db.m28[key28(raw[0], raw[1], raw[2], raw[3])]; ok {
		return e, true
	}
	if e, ok := db.m24[key24(raw[0], raw[1], raw[2])]; ok {
		return e, true
	}
	return Entry{}, false
}

// Lookup satisfies engine.VendorLookup.
func (db *DB) Lookup(mac string) (short, long string, ok bool) {
	e, ok := db.Find(mac)
	if !ok {
		return "", "", false
	}
	return e.Short, e.Long, true
}

// Result is the full answer for one MAC, used by the lookup command and API.
type Result struct {
	MAC        string `json:"mac"`
	Vendor     string `json:"vendor"`
	Short      string `json:"vendor_short"`
	Prefix     string `json:"prefix,omitempty"`
	Bits       int    `json:"prefix_bits,omitempty"`
	Randomized bool   `json:"randomized"`
	Multicast  bool   `json:"multicast"`
	Found      bool   `json:"found"`
}

// Describe classifies a MAC and looks it up.
func (db *DB) Describe(mac string) (Result, error) {
	n, err := model.NormalizeMAC(mac)
	if err != nil {
		return Result{}, err
	}
	r := Result{MAC: n, Randomized: model.IsRandomizedMAC(n), Multicast: model.IsMulticastMAC(n)}
	if e, ok := db.Find(n); ok {
		r.Found, r.Vendor, r.Short, r.Prefix, r.Bits = true, e.Long, e.Short, e.Prefix, e.Bits
	}
	return r, nil
}

// Search returns entries whose short or long name contains q (case-insensitive),
// sorted by prefix. Handy for "what prefixes does Shure own?".
func (db *DB) Search(q string, limit int) []Entry {
	q = strings.ToLower(q)
	var out []Entry
	collect := func(e Entry) {
		if strings.Contains(strings.ToLower(e.Short), q) || strings.Contains(strings.ToLower(e.Long), q) {
			out = append(out, e)
		}
	}
	for _, e := range db.m24 {
		collect(e)
	}
	for _, e := range db.m28 {
		collect(e)
	}
	for _, e := range db.m36 {
		collect(e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Write serialises the database in manuf text format (used by the converter
// and by update-oui when it has to fall back to the C source).
func (db *DB) Write(w io.Writer, header string) error {
	bw := bufio.NewWriter(w)
	if header != "" {
		for _, line := range strings.Split(strings.TrimRight(header, "\n"), "\n") {
			fmt.Fprintf(bw, "# %s\n", line)
		}
		fmt.Fprintln(bw, "#")
	}
	write := func(entries []Entry) {
		sort.Slice(entries, func(i, j int) bool { return entries[i].Prefix < entries[j].Prefix })
		for _, e := range entries {
			p := strings.ToUpper(strings.TrimSuffix(e.Prefix, "/24"))
			fmt.Fprintf(bw, "%s\t%s\t%s\n", p, e.Short, e.Long)
		}
	}
	e24 := make([]Entry, 0, len(db.m24))
	for _, e := range db.m24 {
		e24 = append(e24, e)
	}
	e28 := make([]Entry, 0, len(db.m28))
	for _, e := range db.m28 {
		e28 = append(e28, e)
	}
	e36 := make([]Entry, 0, len(db.m36))
	for _, e := range db.m36 {
		e36 = append(e36, e)
	}
	write(e24)
	write(e28)
	write(e36)
	return bw.Flush()
}
