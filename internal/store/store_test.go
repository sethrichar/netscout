package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sethrichar/netscout/internal/model"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestDeviceRoundTrip(t *testing.T) {
	s := openTest(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	d := &model.Device{
		MAC: "00:1d:c1:00:00:01", Vendor: "Audinate Pty L", VendorShort: "Audinate", Hostname: "cl5-primary",
		FirstSeen: now, LastSeen: now.Add(time.Minute), Online: true, Interface: "en0",
		Attrs: map[string]string{"services": "_netaudio-arc._udp"},
	}
	ips := []IPSeen{{IP: "10.0.0.5", FirstSeen: now, LastSeen: now.Add(time.Minute)}}
	if err := s.SaveObserved(d, ips); err != nil {
		t.Fatal(err)
	}
	label := "Yamaha CL5 primary"
	if err := s.SetUserFields(d.MAC, &label, nil, []string{"dante", "foh"}); err != nil {
		t.Fatal(err)
	}
	// Second observed save must not clobber label/tags and must widen the window.
	d.LastSeen = now.Add(2 * time.Minute)
	d.FirstSeen = now.Add(time.Hour) // later first_seen must be ignored (MIN)
	if err := s.SaveObserved(d, []IPSeen{{IP: "10.0.0.6", FirstSeen: now.Add(2 * time.Minute), LastSeen: now.Add(2 * time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDevice(d.MAC)
	if err != nil || got == nil {
		t.Fatalf("get: %v %v", got, err)
	}
	if got.Label != label || len(got.Tags) != 2 || got.Tags[0] != "dante" {
		t.Errorf("user fields clobbered: %+v", got)
	}
	if !got.FirstSeen.Equal(now) || !got.LastSeen.Equal(now.Add(2*time.Minute)) {
		t.Errorf("time window wrong: %v..%v", got.FirstSeen, got.LastSeen)
	}
	if len(got.IPs) != 2 || got.IPs[0] != "10.0.0.6" {
		t.Errorf("ips wrong (want most recent first): %v", got.IPs)
	}
	if got.Attrs["services"] != "_netaudio-arc._udp" {
		t.Errorf("attrs missing: %v", got.Attrs)
	}
	list, err := s.ListDevices()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %v", list, err)
	}
	if err := s.DeleteDevice(d.MAC); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetDevice(d.MAC); got != nil {
		t.Error("device should be gone")
	}
	if ips, _ := s.ListDeviceIPs(d.MAC); len(ips) != 0 {
		t.Error("cascade delete of ips failed")
	}
}

func TestPlaceholderDeviceTimestamps(t *testing.T) {
	s := openTest(t)
	label := "Planned stagebox"
	if err := s.SetUserFields("00:1d:c1:00:00:77", &label, nil, nil); err != nil {
		t.Fatal(err)
	}
	d, _ := s.GetDevice("00:1d:c1:00:00:77")
	if d == nil || !d.FirstSeen.IsZero() || !d.LastSeen.IsZero() {
		t.Fatalf("placeholder should have zero timestamps: %+v", d)
	}
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := s.SaveObserved(&model.Device{MAC: d.MAC, FirstSeen: now, LastSeen: now}, nil); err != nil {
		t.Fatal(err)
	}
	d, _ = s.GetDevice(d.MAC)
	if !d.FirstSeen.Equal(now) || !d.LastSeen.Equal(now) || d.Label != label {
		t.Errorf("first observation should fill timestamps and keep label: %+v", d)
	}
}

func TestEventsAndObservations(t *testing.T) {
	s := openTest(t)
	for i := 0; i < 5; i++ {
		e := &model.Event{Kind: model.EventConflict, IP: "10.0.0.9", Message: "conflict", Details: map[string]string{"n": string(rune('0' + i))}}
		if err := s.AddEvent(e); err != nil {
			t.Fatal(err)
		}
		if e.ID == 0 {
			t.Fatal("event id not set")
		}
	}
	evs, err := s.ListEvents(EventFilter{Kind: model.EventConflict, Limit: 3})
	if err != nil || len(evs) != 3 || evs[0].ID != 5 {
		t.Fatalf("newest-first listing wrong: %v %v", evs, err)
	}
	tail, err := s.ListEvents(EventFilter{AfterID: 3})
	if err != nil || len(tail) != 2 || tail[0].ID != 4 {
		t.Fatalf("tail listing wrong: %v %v", tail, err)
	}
	o := model.Observation{MAC: "aa:bb:cc:dd:ee:ff", IP: "10.0.0.1", Source: model.SourceARP, Timestamp: time.Now(), Extra: map[string]string{"arp_op": "reply"}}
	if err := s.AddObservation(o); err != nil {
		t.Fatal(err)
	}
	obs, err := s.ListObservations(o.MAC, 10)
	if err != nil || len(obs) != 1 || obs[0].Extra["arp_op"] != "reply" {
		t.Fatalf("observations wrong: %v %v", obs, err)
	}
	n, err := s.PruneObservations(time.Now().Add(time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
}

func TestMeta(t *testing.T) {
	s := openTest(t)
	if v, _ := s.GetMeta("iface"); v != "" {
		t.Fatal("expected empty")
	}
	if err := s.SetMeta("iface", "en0"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetMeta("iface", "en1"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.GetMeta("iface"); v != "en1" {
		t.Fatalf("got %q", v)
	}
}

func TestOpenWithAwkwardPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "show #3 100%")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "net?scout.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.SetMeta("k", "v"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("database was not created at the requested path: %v", err)
	}
}

func TestTimestampLayoutIsFixedWidth(t *testing.T) {
	a := fmtTime(time.Date(2026, 1, 1, 0, 0, 0, 500000000, time.UTC))
	b := fmtTime(time.Date(2026, 1, 1, 0, 0, 0, 500000001, time.UTC))
	if len(a) != len(b) || !(a < b) {
		t.Errorf("layout must be fixed width and order lexically: %q %q", a, b)
	}
	if got := parseTime("2026-01-01T00:00:00.5Z"); got.Nanosecond() != 500000000 {
		t.Errorf("old RFC3339Nano rows must still parse: %v", got)
	}
}
