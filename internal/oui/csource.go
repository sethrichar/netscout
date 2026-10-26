package oui

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Wireshark ≥ 4.2 no longer ships `manuf` as a text file in its repository;
// the data lives in epan/manuf-data.c as C initialisers:
//
//	{ { 0x00, 0x1D, 0xC1 }, "AudinateL",    "Audinate Pty L" },
//	{ { 0x00, 0x55, 0xDA, 0x00 }, "ShinkoTechno", "Shinko Technos co.,ltd." },
//	{ { 0x00, 0x1B, 0xC5, 0x00, 0x00 }, "Converging",   "Converging Systems Inc." },
//
// ParseCSource reads that file. Three-, four- and five-byte prefixes map to
// 24-, 28- and 36-bit registrations respectively.
var cEntryRe = regexp.MustCompile(`^\s*\{\s*\{\s*((?:0x[0-9A-Fa-f]{2}\s*,\s*)*0x[0-9A-Fa-f]{2})\s*\}\s*,\s*"((?:[^"\\]|\\.)*)"\s*,\s*"((?:[^"\\]|\\.)*)"\s*\}`)

// ParseCSource converts Wireshark's epan/manuf-data.c into a DB.
func ParseCSource(r io.Reader) (*DB, error) {
	db := &DB{m24: map[uint32]Entry{}, m28: map[uint32]Entry{}, m36: map[uint64]Entry{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		m := cEntryRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		var b [5]byte
		parts := strings.Split(m[1], ",")
		if len(parts) < 3 || len(parts) > 5 {
			continue
		}
		for i, p := range parts {
			v, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(p), "0x"), 16, 8)
			if err != nil {
				return nil, fmt.Errorf("bad byte %q: %w", p, err)
			}
			b[i] = byte(v)
		}
		bits := map[int]int{3: 24, 4: 28, 5: 36}[len(parts)]
		e := Entry{Bits: bits, Short: cUnescape(m[2]), Long: cUnescape(m[3])}
		if e.Long == "" {
			e.Long = e.Short
		}
		db.add(b, e)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading C source: %w", err)
	}
	if db.Len() == 0 {
		return nil, fmt.Errorf("no entries found: not a manuf-data.c file?")
	}
	return db, nil
}

func cUnescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				b.WriteByte(' ')
			case 't':
				b.WriteByte(' ')
			default:
				b.WriteByte(s[i])
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
