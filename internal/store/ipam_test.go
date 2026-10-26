package store

import (
	"testing"
	"time"

	"github.com/sethrichar/netscout/internal/model"
)

func TestSubnetsAndReservations(t *testing.T) {
	s := openTest(t)
	sn, err := s.AddSubnet(model.Subnet{CIDR: "10.0.0.77/24", Name: "Dante Primary", VLAN: 10, Gateway: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if sn.ID == 0 || sn.CIDR != "10.0.0.0/24" {
		t.Fatalf("subnet not normalised: %+v", sn)
	}
	if _, err := s.AddSubnet(model.Subnet{CIDR: "10.0.0.0/24"}); err == nil {
		t.Error("duplicate CIDR should fail")
	}
	if _, err := s.AddSubnet(model.Subnet{CIDR: "nope"}); err == nil {
		t.Error("bad CIDR should fail")
	}
	sn2, _ := s.AddSubnet(model.Subnet{CIDR: "10.0.0.0/26", Name: "Console VLAN"})

	got, _ := s.FindSubnet("dante primary")
	if got != nil {
		t.Error("name match should be exact")
	}
	got, _ = s.FindSubnet("Dante Primary")
	if got == nil || got.ID != sn.ID {
		t.Errorf("find by name: %+v", got)
	}
	got, _ = s.FindSubnet("10.0.0.5/24")
	if got == nil || got.ID != sn.ID {
		t.Errorf("find by cidr: %+v", got)
	}
	got, _ = s.SubnetContaining("10.0.0.20")
	if got == nil || got.ID != sn2.ID {
		t.Errorf("most specific subnet should win: %+v", got)
	}
	got, _ = s.SubnetContaining("10.0.0.200")
	if got == nil || got.ID != sn.ID {
		t.Errorf("containing: %+v", got)
	}

	r, err := s.UpsertReservation(model.Reservation{SubnetID: sn.ID, IP: "10.0.0.20", MAC: "00-1D-C1-00-00-20", Label: "CL5"})
	if err != nil || r.ID == 0 || r.MAC != "00:1d:c1:00:00:20" {
		t.Fatalf("upsert: %+v %v", r, err)
	}
	r2, _ := s.UpsertReservation(model.Reservation{SubnetID: sn.ID, IP: "10.0.0.20", Label: "CL5 primary", Notes: "FOH"})
	if r2.ID != r.ID {
		t.Error("upsert should keep the same row")
	}
	list, _ := s.ListReservations(sn.ID)
	if len(list) != 1 || list[0].Label != "CL5 primary" || list[0].MAC != "" {
		t.Errorf("reservation list: %+v", list)
	}
	if _, err := s.UpsertReservation(model.Reservation{SubnetID: sn.ID, IP: "bad"}); err == nil {
		t.Error("bad IP should fail")
	}
	if err := s.DeleteReservation(sn.ID, "10.0.0.99"); err == nil {
		t.Error("deleting a missing reservation should fail")
	}
	sn.Name = "Dante A"
	if err := s.UpdateSubnet(sn); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSubnet(sn.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.ListReservations(0); len(list) != 0 {
		t.Error("reservations should cascade-delete with the subnet")
	}
}

func TestListBindings(t *testing.T) {
	s := openTest(t)
	now := time.Now()
	d := &model.Device{MAC: "aa:bb:cc:00:00:01", FirstSeen: now, LastSeen: now}
	_ = s.SaveObserved(d, []IPSeen{{IP: "10.0.0.5", FirstSeen: now.Add(-time.Hour), LastSeen: now.Add(-time.Hour)}, {IP: "10.0.0.6", FirstSeen: now, LastSeen: now}})
	b, err := s.ListBindings()
	if err != nil || len(b) != 2 || b[0].IP != "10.0.0.6" {
		t.Fatalf("bindings: %+v %v", b, err)
	}
}
