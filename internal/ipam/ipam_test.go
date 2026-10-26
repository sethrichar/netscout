package ipam

import (
	"testing"
	"time"

	"github.com/sethrichar/netscout/internal/model"
)

var now = time.Date(2026, 6, 1, 20, 0, 0, 0, time.UTC)

func TestComputeStatuses(t *testing.T) {
	sn := model.Subnet{ID: 1, CIDR: "10.0.0.0/28", Gateway: "10.0.0.1"}
	res := []model.Reservation{
		{SubnetID: 1, IP: "10.0.0.2", MAC: "00:1d:c1:00:00:02", Label: "Dante CL5"},     // match
		{SubnetID: 1, IP: "10.0.0.3", MAC: "00:1d:c1:00:00:03", Label: "Dante Rio"},     // mismatch: squatter
		{SubnetID: 1, IP: "10.0.0.4", MAC: "00:1d:c1:00:00:04", Label: "Stagebox"},      // reserved, absent
		{SubnetID: 1, IP: "10.0.0.5", MAC: "00:1d:c1:00:00:05", Label: "Wireless rack"}, // mismatch: MAC elsewhere
		{SubnetID: 1, IP: "10.0.0.6", Label: "spare for lighting"},                      // no MAC, in use → match
	}
	bindings := []Binding{
		{IP: "10.0.0.1", MAC: "00:00:0c:00:00:01", LastSeen: now, Current: true},
		{IP: "10.0.0.2", MAC: "00:1d:c1:00:00:02", LastSeen: now, Current: true},
		{IP: "10.0.0.3", MAC: "f0:18:98:00:00:99", LastSeen: now, Current: true}, // laptop squatting on the Rio's IP
		{IP: "10.0.0.9", MAC: "00:1d:c1:00:00:05", LastSeen: now, Current: true}, // wireless rack on the wrong IP
		{IP: "10.0.0.6", MAC: "ac:44:f2:00:00:06", LastSeen: now, Current: true},
		{IP: "10.0.0.7", MAC: "aa:aa:aa:00:00:07", LastSeen: now, Current: true}, // conflict
		{IP: "10.0.0.7", MAC: "bb:bb:bb:00:00:07", LastSeen: now, Current: true},
		{IP: "10.0.0.8", MAC: "cc:cc:cc:00:00:08", LastSeen: now, Current: true},                        // plain in-use
		{IP: "10.0.0.10", MAC: "dd:dd:dd:00:00:10", LastSeen: now.Add(-48 * time.Hour), Current: false}, // history only
		{IP: "10.0.0.11", MAC: "ee:ee:ee:00:00:11", LastSeen: now.Add(-3 * time.Hour), LastKnown: true}, // offline device's last address: not in use
		// DHCP reuse: the old lease holder was last seen an hour ago, the new one now → in-use, not conflict
		{IP: "10.0.0.12", MAC: "01:01:01:00:00:12", LastSeen: now.Add(-time.Hour), Current: true},
		{IP: "10.0.0.12", MAC: "02:02:02:00:00:12", LastSeen: now, Current: true},
		{IP: "192.168.1.5", MAC: "ee:ee:ee:00:00:05", LastSeen: now, Current: true}, // other subnet, ignored
	}
	devs := []model.Device{
		{MAC: "00:1d:c1:00:00:02", Online: true, Hostname: "CL5"},
		{MAC: "f0:18:98:00:00:99", Online: true, Hostname: "seths-macbook"},
	}
	addrs, sum, err := Compute(sn, res, bindings, devs, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 14 { // /28 minus network and broadcast
		t.Fatalf("expected 14 host addresses, got %d", len(addrs))
	}
	byIP := map[string]Address{}
	for _, a := range addrs {
		byIP[a.IP] = a
	}
	want := map[string]Status{
		"10.0.0.1":  StatusInUse,
		"10.0.0.2":  StatusMatch,
		"10.0.0.3":  StatusMismatch,
		"10.0.0.4":  StatusReserved,
		"10.0.0.5":  StatusMismatch,
		"10.0.0.6":  StatusMatch,
		"10.0.0.7":  StatusConflict,
		"10.0.0.8":  StatusInUse,
		"10.0.0.9":  StatusMismatch, // the wireless rack's MAC is reserved for .5
		"10.0.0.10": StatusFree,
		"10.0.0.11": StatusFree,
		"10.0.0.12": StatusInUse,
		"10.0.0.14": StatusFree,
	}
	for ip, st := range want {
		if got := byIP[ip].Status; got != st {
			t.Errorf("%s: status %s, want %s (note %q)", ip, got, st, byIP[ip].Note)
		}
	}
	if !byIP["10.0.0.1"].Gateway {
		t.Error("gateway flag missing")
	}
	if !byIP["10.0.0.2"].Online || byIP["10.0.0.2"].Devices[0].Hostname != "CL5" {
		t.Errorf("device join failed: %+v", byIP["10.0.0.2"])
	}
	if byIP["10.0.0.3"].Note == "" || byIP["10.0.0.5"].Note == "" || byIP["10.0.0.7"].Note == "" {
		t.Error("mismatch/conflict notes should explain themselves")
	}
	if h := byIP["10.0.0.10"].History; len(h) != 1 || h[0] != "dd:dd:dd:00:00:10" {
		t.Errorf("history: %v", h)
	}
	if lk := byIP["10.0.0.11"].LastKnown; len(lk) != 1 || lk[0] != "ee:ee:ee:00:00:11" {
		t.Errorf("last known: %v", lk)
	}
	if a := byIP["10.0.0.12"]; len(a.MACs) != 1 || a.MACs[0] != "02:02:02:00:00:12" || len(a.History) != 1 {
		t.Errorf("lease change should keep only the newest claimant: %+v", a)
	}
	if sum.Total != 14 || sum.Match != 2 || sum.Mismatch != 3 || sum.Conflict != 1 || sum.InUse != 3 || sum.Reserved != 1 || sum.Free != 4 {
		t.Errorf("summary: %+v", sum)
	}
	if sum.Online != 2 {
		t.Errorf("online count: %d", sum.Online)
	}

	if got := NextFree(addrs, ""); got != "10.0.0.10" {
		t.Errorf("NextFree = %s", got)
	}
	if got := NextFree(addrs, "10.0.0.11"); got != "10.0.0.13" {
		t.Errorf("NextFree after .11 = %s", got)
	}
	if f := Filter(addrs, StatusMismatch, StatusConflict); len(f) != 4 {
		t.Errorf("filter: %d", len(f))
	}

	withEdges, _, _ := Compute(sn, nil, nil, nil, Options{IncludeEdges: true})
	if len(withEdges) != 16 || !withEdges[0].Network || !withEdges[15].Bcast {
		t.Errorf("edges: %d %v %v", len(withEdges), withEdges[0].Network, withEdges[len(withEdges)-1].Bcast)
	}
}

func TestMarkCurrent(t *testing.T) {
	b := MarkCurrent([]Binding{
		{IP: "10.0.0.5", MAC: "aa", LastSeen: now.Add(-3 * time.Hour)}, // old but most recent for aa → last known, not current
		{IP: "10.0.0.6", MAC: "aa", LastSeen: now.Add(-5 * time.Hour)}, // older → history
		{IP: "10.0.0.7", MAC: "bb", LastSeen: now.Add(-10 * time.Minute)},
		{IP: "10.0.0.8", MAC: "bb", LastSeen: now.Add(-20 * time.Minute)}, // inside window → still current
	}, now, time.Hour)
	wantCur := []bool{false, false, true, true}
	wantLK := []bool{true, false, false, false}
	for i := range wantCur {
		if b[i].Current != wantCur[i] || b[i].LastKnown != wantLK[i] {
			t.Errorf("binding %d current=%v lastKnown=%v, want %v/%v", i, b[i].Current, b[i].LastKnown, wantCur[i], wantLK[i])
		}
	}
}

func TestComputeRejectsHuge(t *testing.T) {
	if _, _, err := Compute(model.Subnet{CIDR: "10.0.0.0/8"}, nil, nil, nil, Options{}); err == nil {
		t.Error("/8 should be refused")
	}
	if _, _, err := Compute(model.Subnet{CIDR: "garbage"}, nil, nil, nil, Options{}); err == nil {
		t.Error("garbage should be refused")
	}
}
