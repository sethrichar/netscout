package engine

import (
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/sethrichar/netscout/internal/model"
	"github.com/sethrichar/netscout/internal/store"
)

type fakeVendors struct{}

func (fakeVendors) Lookup(mac string) (string, string, bool) {
	if len(mac) >= 8 && mac[:8] == "00:1d:c1" {
		return "Audinate", "Audinate Pty Ltd", true
	}
	return "", "", false
}

func newTest(t *testing.T) (*Engine, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	_, lan, _ := net.ParseCIDR("10.0.0.0/24")
	e, err := New(st, Options{
		Interface: "en0", LocalNets: []*net.IPNet{lan}, Vendors: fakeVendors{},
		ConflictWindow: time.Minute, OnlineWindow: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e, st
}

func drain(ch <-chan model.Event) []model.Event {
	var out []model.Event
	for {
		select {
		case ev := <-ch:
			out = append(out, ev)
		default:
			return out
		}
	}
}

func kinds(evs []model.Event) map[string]int {
	m := map[string]int{}
	for _, e := range evs {
		m[e.Kind]++
	}
	return m
}

func TestObserveBuildsDevice(t *testing.T) {
	e, st := newTest(t)
	ch, cancel := e.Subscribe()
	defer cancel()
	t0 := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	e.Observe(model.Observation{MAC: "00:1D:C1:AA:BB:CC", IP: "10.0.0.20", Source: model.SourceARP, Timestamp: t0, Interface: "en0"})
	e.Observe(model.Observation{MAC: "00:1d:c1:aa:bb:cc", IP: "10.0.0.20", Hostname: "CL5-Primary", Source: model.SourceMDNS, Timestamp: t0.Add(time.Second),
		Extra: map[string]string{"services": "_netaudio-arc._udp"}})

	d, ok := e.Device("00:1d:c1:aa:bb:cc")
	if !ok {
		t.Fatal("device missing")
	}
	if d.Vendor != "Audinate Pty Ltd" || d.Hostname != "CL5-Primary" || d.IP() != "10.0.0.20" || !d.Online {
		t.Errorf("device wrong: %+v", d)
	}
	if d.Attrs["services"] != "_netaudio-arc._udp" {
		t.Errorf("attrs not merged: %v", d.Attrs)
	}
	k := kinds(drain(ch))
	if k[model.EventNewDevice] != 1 {
		t.Errorf("expected one new_device event, got %v", k)
	}

	e.Flush()
	saved, err := st.GetDevice(d.MAC)
	if err != nil || saved == nil || saved.Hostname != "CL5-Primary" || len(saved.IPs) != 1 {
		t.Fatalf("flush did not persist: %+v %v", saved, err)
	}
}

func TestForeignIPv4Ignored(t *testing.T) {
	e, _ := newTest(t)
	// Gateway MAC forwarding internet traffic: the source IP is off-LAN.
	e.Observe(model.Observation{MAC: "aa:aa:aa:aa:aa:01", IP: "142.250.72.14", Source: model.SourceIPv4, Timestamp: time.Now()})
	d, ok := e.Device("aa:aa:aa:aa:aa:01")
	if !ok {
		t.Fatal("device should still be recorded as alive")
	}
	if len(d.IPs) != 0 {
		t.Errorf("foreign IP must not be attached: %v", d.IPs)
	}
	// ARP is always trusted even outside the configured nets (someone misconfigured).
	e.Observe(model.Observation{MAC: "aa:aa:aa:aa:aa:02", IP: "192.168.99.5", Source: model.SourceARP, Timestamp: time.Now()})
	if d, _ := e.Device("aa:aa:aa:aa:aa:02"); d.IP() != "192.168.99.5" {
		t.Errorf("ARP IP should be accepted: %v", d.IPs)
	}
}

func TestConflictDetection(t *testing.T) {
	e, _ := newTest(t)
	ch, cancel := e.Subscribe()
	defer cancel()
	t0 := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	e.Observe(model.Observation{MAC: "00:1d:c1:00:00:01", IP: "10.0.0.50", Source: model.SourceARP, Timestamp: t0})
	e.Observe(model.Observation{MAC: "00:1d:c1:00:00:02", IP: "10.0.0.50", Source: model.SourceARP, Timestamp: t0.Add(10 * time.Second)})
	// Same pair flapping again inside the window must not spam.
	e.Observe(model.Observation{MAC: "00:1d:c1:00:00:01", IP: "10.0.0.50", Source: model.SourceARP, Timestamp: t0.Add(20 * time.Second)})
	k := kinds(drain(ch))
	if k[model.EventConflict] != 1 {
		t.Fatalf("expected exactly one conflict, got %v", k)
	}
	d, _ := e.Device("00:1d:c1:00:00:02")
	if d.Attrs["conflict_ip"] != "10.0.0.50" {
		t.Errorf("conflict attr missing: %v", d.Attrs)
	}

	// A lease change long after the previous owner went quiet is not a conflict.
	e.Observe(model.Observation{MAC: "00:1d:c1:00:00:03", IP: "10.0.0.60", Source: model.SourceDHCP, Timestamp: t0})
	e.Observe(model.Observation{MAC: "00:1d:c1:00:00:04", IP: "10.0.0.60", Source: model.SourceDHCP, Timestamp: t0.Add(time.Hour)})
	if k := kinds(drain(ch)); k[model.EventConflict] != 0 {
		t.Errorf("lease change flagged as conflict: %v", k)
	}

	e.ClearConflict("10.0.0.50")
	if d, _ := e.Device("00:1d:c1:00:00:02"); d.Attrs["conflict_ip"] != "" {
		t.Error("conflict not cleared")
	}
}

func TestOfflineSweepAndReload(t *testing.T) {
	e, st := newTest(t)
	ch, cancel := e.Subscribe()
	defer cancel()
	t0 := time.Now().Add(-10 * time.Minute)
	e.Observe(model.Observation{MAC: "00:1d:c1:00:00:09", IP: "10.0.0.9", Source: model.SourceARP, Timestamp: t0})
	e.sweepOffline(time.Now())
	d, _ := e.Device("00:1d:c1:00:00:09")
	if d.Online {
		t.Error("device should be offline after sweep")
	}
	if k := kinds(drain(ch)); k[model.EventOffline] != 1 {
		t.Errorf("expected offline event: %v", k)
	}
	// Coming back emits online.
	e.Observe(model.Observation{MAC: "00:1d:c1:00:00:09", IP: "10.0.0.9", Source: model.SourceARP, Timestamp: time.Now()})
	if k := kinds(drain(ch)); k[model.EventOnline] != 1 {
		t.Errorf("expected online event: %v", k)
	}
	label := "Stagebox A"
	if err := e.SetUserFields("00:1D:C1:00:00:09", &label, nil, []string{"stage"}); err != nil {
		t.Fatal(err)
	}
	e.Flush()

	// A fresh engine reloads the device with its label and IP history.
	e2, err := New(st, Options{})
	if err != nil {
		t.Fatal(err)
	}
	d2, ok := e2.Device("00:1d:c1:00:00:09")
	if !ok || d2.Label != "Stagebox A" || d2.IP() != "10.0.0.9" || d2.Online {
		t.Errorf("reload wrong: %+v", d2)
	}
}

func TestSortDevices(t *testing.T) {
	devs := []model.Device{
		{MAC: "c", IPs: []string{"10.0.0.20"}},
		{MAC: "a", IPs: []string{"10.0.0.3"}, Online: true},
		{MAC: "b", IPs: []string{}, Online: true},
		{MAC: "d", IPs: []string{"10.0.0.100"}, Online: true},
	}
	SortDevices(devs)
	want := []string{"a", "d", "b", "c"}
	for i, w := range want {
		if devs[i].MAC != w {
			t.Fatalf("order %d = %s, want %s", i, devs[i].MAC, w)
		}
	}
}
