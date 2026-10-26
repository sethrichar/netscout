package oui

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"context"
)

func embedded(t *testing.T) *DB {
	t.Helper()
	db, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestEmbeddedKnownVendors(t *testing.T) {
	db := embedded(t)
	if db.Len() < MinEntries {
		t.Fatalf("embedded db too small: %d", db.Len())
	}
	cases := map[string]string{
		"00:1d:c1:12:34:56": "Audinate", // Dante
		"AC-44-F2-00-00-01": "Yamaha",
		"00:0e:dd:aa:bb:cc": "Shure",
		"00:60:74:00:00:01": "Qsc",
		"f0:18:98:01:02:03": "Apple",
		"00:00:0c:00:00:01": "Cisco",
		"0000.0cab.cdef":    "Cisco",
	}
	for mac, want := range cases {
		e, ok := db.Find(mac)
		if !ok {
			t.Errorf("Find(%s): not found", mac)
			continue
		}
		if !strings.Contains(strings.ToLower(e.Long), strings.ToLower(want)) && !strings.Contains(strings.ToLower(e.Short), strings.ToLower(want)) {
			t.Errorf("Find(%s) = %q / %q, want %s", mac, e.Short, e.Long, want)
		}
		if e.Bits != 24 {
			t.Errorf("Find(%s) bits = %d", mac, e.Bits)
		}
	}
	// Allen & Heath registers as its parent company, Audiotonix (00:04:C4).
	if e, ok := db.Find("00:04:c4:00:00:01"); !ok || !strings.Contains(e.Long, "Audiotonix") {
		t.Errorf("Allen & Heath / Audiotonix lookup: %+v %v", e, ok)
	}
	if hits := db.Search("audiotonix", 50); len(hits) == 0 {
		t.Error("search for Audiotonix returned nothing")
	}
}

func TestLongestPrefixMatch(t *testing.T) {
	src := strings.Join([]string{
		"# comment",
		"",
		"00:1B:C5\tIEEERegi\tIEEE Registration Authority",
		"00:1B:C5:00:00:00/36\tConverging\tConverging Systems Inc.",
		"00:1B:C5:00:10:00/36\tOpenRBcomDir\tOpenRB.com, Direct SIA",
		"00:55:DA\tIEEERegi\tIEEE Registration Authority",
		"00:55:DA:10:00:00/28\tKoolPOS\tKoolPOS Inc.",
		"00:55:DA:20/28\tConnectedInf\tBeijing Connected Information Technology Co.,Ltd.",
		"AA:BB:CC  Spaced   Spaced Vendor Name", // space-separated legacy line
	}, "\n")
	db, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	if db.Len() != 7 {
		t.Fatalf("len = %d", db.Len())
	}
	check := func(mac, wantShort string, wantBits int) {
		e, ok := db.Find(mac)
		if !ok || e.Short != wantShort || e.Bits != wantBits {
			t.Errorf("Find(%s) = %+v ok=%v, want %s/%d", mac, e, ok, wantShort, wantBits)
		}
	}
	check("00:1b:c5:00:0f:ff", "Converging", 36)   // 36-bit block 00:1B:C5:00:0
	check("00:1b:c5:00:1a:bc", "OpenRBcomDir", 36) // 36-bit block 00:1B:C5:00:1
	check("00:1b:c5:ff:00:00", "IEEERegi", 24)     // falls back to the /24
	check("00:55:da:1f:00:01", "KoolPOS", 28)      // 28-bit block 00:55:DA:1
	check("00:55:da:2a:00:01", "ConnectedInf", 28) // truncated prefix spelling
	check("00:55:da:30:00:01", "IEEERegi", 24)
	check("aa:bb:cc:00:00:00", "Spaced", 24)
	if _, ok := db.Find("de:ad:be:ef:00:00"); ok {
		t.Error("unknown prefix should not match")
	}
	if _, ok := db.Find("not-a-mac"); ok {
		t.Error("garbage should not match")
	}
}

func TestDescribeRandomized(t *testing.T) {
	db := embedded(t)
	r, err := db.Describe("3a:5f:2c:00:11:22")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Randomized || r.Found {
		t.Errorf("private Wi-Fi address should be randomized and unknown: %+v", r)
	}
	// Android's fixed randomised prefix DA:A1:19 is actually registered to
	// Google: it is both randomized and found. Both flags must survive.
	r, _ = db.Describe("da:a1:19:00:11:22")
	if !r.Randomized || !r.Found {
		t.Errorf("DA:A1:19 should be randomized AND found: %+v", r)
	}
	r, _ = db.Describe("01:00:5e:00:00:fb")
	if !r.Multicast {
		t.Errorf("multicast flag missing: %+v", r)
	}
	r, _ = db.Describe("00:1d:c1:00:00:01")
	if r.Randomized || !r.Found || r.Prefix != "00:1d:c1/24" {
		t.Errorf("Audinate describe wrong: %+v", r)
	}
}

func TestParseCSourceAndRoundTrip(t *testing.T) {
	c := `
static const manuf_registry_t ieee_registry_table[] = {
    { { 0x00, 0x1B, 0xC5 }, MA_S },
};
static const manuf_oui24_t global_manuf_oui24_table[] = {
    { { 0x00, 0x1D, 0xC1 }, "AudinateL",    "Audinate Pty L" },
    { { 0x00, 0x17, 0x32 }, "ScienceTechn", "Science-Technical Center \"RISSA\"" },
};
static const manuf_oui28_t global_manuf_oui28_table[] = {
    { { 0x00, 0x55, 0xDA, 0x10 }, "KoolPOS",      "KoolPOS Inc." },
};
static const manuf_oui36_t global_manuf_oui36_table[] = {
    { { 0x00, 0x1B, 0xC5, 0x00, 0x10 }, "OpenRBcomDir", "OpenRB.com, Direct SIA" },
};
`
	db, err := ParseCSource(strings.NewReader(c))
	if err != nil {
		t.Fatal(err)
	}
	if db.Len() != 4 {
		t.Fatalf("len = %d", db.Len())
	}
	if e, _ := db.Find("00:17:32:00:00:00"); e.Long != `Science-Technical Center "RISSA"` {
		t.Errorf("escape handling: %q", e.Long)
	}
	var buf bytes.Buffer
	if err := db.Write(&buf, "test"); err != nil {
		t.Fatal(err)
	}
	db2, err := Parse(&buf)
	if err != nil {
		t.Fatalf("round trip parse: %v\n%s", err, buf.String())
	}
	if db2.Len() != 4 {
		t.Fatalf("round trip len = %d", db2.Len())
	}
	if e, ok := db2.Find("00:1b:c5:00:1f:ff"); !ok || e.Short != "OpenRBcomDir" || e.Bits != 36 {
		t.Errorf("round trip 36-bit: %+v %v", e, ok)
	}
	if e, ok := db2.Find("00:55:da:1a:00:00"); !ok || e.Bits != 28 {
		t.Errorf("round trip 28-bit: %+v %v", e, ok)
	}
}

func TestUpdateFallsBackToCSourceAndLoadPrefersIt(t *testing.T) {
	// Build a big enough C source by cloning the embedded DB.
	emb := embedded(t)
	var manufText bytes.Buffer
	_ = emb.Write(&manufText, "")
	var cSrc bytes.Buffer
	for _, line := range strings.Split(manufText.String(), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 3 || strings.HasPrefix(line, "#") {
			continue
		}
		p := f[0]
		bits := 24
		if i := strings.IndexByte(p, '/'); i >= 0 {
			if p[i+1:] == "28" {
				bits = 28
			} else {
				bits = 36
			}
			p = p[:i]
		}
		oct := strings.Split(p, ":")
		n := map[int]int{24: 3, 28: 4, 36: 5}[bits]
		var bs []string
		for i := 0; i < n; i++ {
			bs = append(bs, "0x"+oct[i])
		}
		cSrc.WriteString("    { { " + strings.Join(bs, ", ") + " }, \"" + f[1] + "\", \"" + strings.ReplaceAll(f[2], `"`, `\"`) + "\" },\n")
	}
	manufHits, cHits := 0, 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/manuf":
			manufHits++
			http.Error(w, "nope", http.StatusForbidden)
		case "/manuf-data.c":
			cHits++
			w.Write(cSrc.Bytes())
		}
	}))
	defer srv.Close()
	oldM, oldC := ManufURL, CSourceURL
	ManufURL, CSourceURL = srv.URL+"/manuf", srv.URL+"/manuf-data.c"
	defer func() { ManufURL, CSourceURL = oldM, oldC }()

	dir := t.TempDir()
	res, err := Update(context.Background(), dir, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if manufHits != 1 || cHits != 1 || res.Entries != emb.Len() || res.Source != CSourceURL {
		t.Errorf("update result: %+v (manuf=%d c=%d)", res, manufHits, cHits)
	}
	if _, err := os.Stat(filepath.Join(dir, "manuf")); err != nil {
		t.Fatal("manuf not written")
	}
	db, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if db.Source == "embedded" {
		t.Error("Load should prefer the updated copy")
	}
	if e, ok := db.Find("00:1d:c1:00:00:01"); !ok || !strings.Contains(e.Long, "Audinate") {
		t.Errorf("updated db lookup: %+v %v", e, ok)
	}
	// A corrupt updated copy is ignored.
	os.WriteFile(filepath.Join(dir, "manuf"), []byte("garbage\n"), 0o644)
	db, err = Load(dir)
	if err != nil || db.Source != "embedded" {
		t.Errorf("corrupt copy should fall back to embedded: %v %v", db.Source, err)
	}
}
