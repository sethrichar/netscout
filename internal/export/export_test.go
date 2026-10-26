package export

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sethrichar/netscout/internal/model"
	"github.com/sethrichar/netscout/internal/store"
)

func TestParseCSVWithHeaders(t *testing.T) {
	in := "Device Name,IP Address,MAC Address,Notes,VLAN\nCL5 Primary,10.0.0.20,00-1D-C1-00-00-20,FOH,10\nRio 3224,10.0.0.21,,stage left,10\n,,,,\nSpare,10.0.0.50,,,\n"
	imp, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.Rows) != 3 {
		t.Fatalf("rows: %+v", imp.Rows)
	}
	r := imp.Rows[0]
	if r.IP != "10.0.0.20" || r.MAC != "00:1d:c1:00:00:20" || r.Label != "CL5 Primary" || r.Notes != "FOH" || r.VLAN != 10 {
		t.Errorf("row 0: %+v", r)
	}
	if imp.Rows[1].MAC != "" || imp.Rows[1].Label != "Rio 3224" {
		t.Errorf("row 1: %+v", imp.Rows[1])
	}
}

func TestParseCSVHeaderlessAndTabs(t *testing.T) {
	in := "10.0.0.5\tac:44:f2:00:00:05\tQL1 monitors\tmon world\n10.0.0.6\t\tLighting console\n"
	imp, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(imp.Rows) != 2 || imp.Rows[0].Label != "QL1 monitors" || imp.Rows[0].Notes != "mon world" || imp.Rows[1].IP != "10.0.0.6" {
		t.Errorf("rows: %+v", imp.Rows)
	}
	if _, err := Parse(strings.NewReader("name,ip\nx,not-an-ip\n")); err == nil {
		t.Error("bad IP should error")
	}
	if _, err := Parse(strings.NewReader("just,text\nno,addresses\n")); err == nil {
		t.Error("no usable rows should error")
	}
}

func TestJSONRoundTripAndApply(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	sn, _ := st.AddSubnet(model.Subnet{CIDR: "10.0.0.0/24", Name: "Dante", VLAN: 10, Gateway: "10.0.0.1"})
	st.UpsertReservation(model.Reservation{SubnetID: sn.ID, IP: "10.0.0.20", MAC: "00:1d:c1:00:00:20", Label: "CL5"})
	st.SetUserFields("f0:18:98:00:00:01", strPtr("Seth's MacBook"), nil, []string{"crew"})
	devs, _ := st.ListDevices()
	subs, _ := st.ListSubnets()
	res, _ := st.ListReservations(0)

	var buf bytes.Buffer
	if err := WriteJSON(&buf, Snapshot{Version: "0.5", Subnets: subs, Reservations: res, Devices: devs}); err != nil {
		t.Fatal(err)
	}
	var csvBuf bytes.Buffer
	if err := WriteDevicesCSV(&csvBuf, devs); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(csvBuf.String(), "Seth's MacBook") {
		t.Error("devices csv missing label")
	}
	var planBuf bytes.Buffer
	if err := WriteReservationsCSV(&planBuf, subs, res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(planBuf.String(), "10.0.0.0/24,10.0.0.20,00:1d:c1:00:00:20,CL5,") {
		t.Errorf("plan csv: %s", planBuf.String())
	}

	// Import the snapshot into a fresh store: subnet, reservation and label come back.
	st2, _ := store.Open(filepath.Join(t.TempDir(), "y.db"))
	defer st2.Close()
	imp, err := Parse(&buf)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Apply(st2, imp, ApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.SubnetsCreated) != 1 || rep.ReservationsWritten != 1 || rep.DevicesLabelled != 2 || len(rep.Skipped) != 0 {
		t.Errorf("report: %+v", rep)
	}
	got, _ := st2.ListReservations(0)
	if len(got) != 1 || got[0].Label != "CL5" {
		t.Errorf("reservations after import: %+v", got)
	}
	d, _ := st2.GetDevice("f0:18:98:00:00:01")
	if d == nil || d.Label != "Seth's MacBook" || len(d.Tags) != 1 {
		t.Errorf("device label after import: %+v", d)
	}
	d, _ = st2.GetDevice("00:1d:c1:00:00:20")
	if d == nil || d.Label != "CL5" {
		t.Errorf("plan label should be carried to the device: %+v", d)
	}

	// The plan CSV re-imports too, and is idempotent.
	imp2, _ := Parse(&planBuf)
	rep2, err := Apply(st2, imp2, ApplyOptions{})
	if err != nil || rep2.ReservationsWritten != 1 || len(rep2.SubnetsCreated) != 0 {
		t.Errorf("re-import: %+v %v", rep2, err)
	}
}

func TestApplyPlacement(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "z.db"))
	defer st.Close()
	imp, _ := Parse(strings.NewReader("ip,name\n10.0.0.5,A\n192.168.50.9,B\n"))

	rep, err := Apply(st, imp, ApplyOptions{DryRun: true})
	if err != nil || rep.ReservationsWritten != 0 || len(rep.Skipped) != 2 {
		t.Errorf("dry run with no subnets: %+v %v", rep, err)
	}
	if subs, _ := st.ListSubnets(); len(subs) != 0 {
		t.Error("dry run must not write")
	}
	rep, err = Apply(st, imp, ApplyOptions{DefaultSubnet: "10.0.0.0/24"})
	if err != nil || rep.ReservationsWritten != 1 || len(rep.Skipped) != 1 || len(rep.SubnetsCreated) != 1 {
		t.Errorf("default subnet: %+v %v", rep, err)
	}
	rep, err = Apply(st, imp, ApplyOptions{AutoSubnets: true})
	if err != nil || rep.ReservationsWritten != 2 || len(rep.Skipped) != 0 || len(rep.SubnetsCreated) != 1 || rep.SubnetsCreated[0] != "192.168.50.0/24" {
		t.Errorf("auto subnets: %+v %v", rep, err)
	}
}

func strPtr(s string) *string { return &s }
