package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sethrichar/netscout/internal/capture"
	"github.com/sethrichar/netscout/internal/engine"
	"github.com/sethrichar/netscout/internal/model"
	"github.com/sethrichar/netscout/internal/oui"
	"github.com/sethrichar/netscout/internal/store"
)

type fakeCtl struct {
	scans []string
	db    *oui.DB
}

func (f *fakeCtl) Status() CaptureStatus {
	return CaptureStatus{Interface: capture.Interface{Name: "en0"}, OnlineAfter: 5 * time.Minute, OUISource: "embedded"}
}
func (f *fakeCtl) Interfaces() ([]capture.Interface, error) {
	return []capture.Interface{{Name: "en0", Default: true}}, nil
}
func (f *fakeCtl) SwitchInterface(name string) error { return nil }
func (f *fakeCtl) Scan(ctx context.Context, cidr string) error {
	f.scans = append(f.scans, cidr)
	return nil
}
func (f *fakeCtl) SetScanInterval(ctx context.Context, every time.Duration, cidr string) {}
func (f *fakeCtl) UpdateOUI(ctx context.Context) (oui.UpdateResult, error) {
	return oui.UpdateResult{}, nil
}
func (f *fakeCtl) OUI() *oui.DB { return f.db }

func newTestServer(t *testing.T) (*httptest.Server, *engine.Engine, *fakeCtl) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	db, _ := oui.Embedded()
	eng, err := engine.New(st, engine.Options{Vendors: db})
	if err != nil {
		t.Fatal(err)
	}
	ctl := &fakeCtl{db: db}
	srv := New(eng, st, ctl, nil)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, eng, ctl
}

func call(t *testing.T, ts *httptest.Server, method, path, body string, hostOverride string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if hostOverride != "" {
		req.Host = hostOverride
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var buf strings.Builder
	b := make([]byte, 4096)
	for {
		n, err := res.Body.Read(b)
		buf.Write(b[:n])
		if err != nil {
			break
		}
	}
	return res.StatusCode, []byte(buf.String())
}

func TestHostCheck(t *testing.T) {
	ts, _, _ := newTestServer(t)
	if code, _ := call(t, ts, "GET", "/api/status", "", "evil.example.com"); code != 403 {
		t.Errorf("foreign Host should be rejected, got %d", code)
	}
	if code, _ := call(t, ts, "GET", "/api/status", "", ""); code != 200 {
		t.Errorf("loopback Host should pass, got %d", code)
	}
	if code, _ := call(t, ts, "GET", "/", "", ""); code != 200 {
		t.Errorf("index should be served, got %d", code)
	}
}

func TestDevicesAndIPAMFlow(t *testing.T) {
	ts, eng, ctl := newTestServer(t)
	now := time.Now()
	eng.Observe(model.Observation{MAC: "00:1d:c1:00:00:20", IP: "10.0.0.20", Source: model.SourceARP, Timestamp: now})
	eng.Observe(model.Observation{MAC: "f0:18:98:00:00:99", IP: "10.0.0.21", Source: model.SourceARP, Timestamp: now})

	code, body := call(t, ts, "GET", "/api/devices", "", "")
	var devs []model.Device
	if err := json.Unmarshal(body, &devs); err != nil || code != 200 || len(devs) != 2 {
		t.Fatalf("devices: %d %s %v", code, body, err)
	}
	if devs[0].Vendor == "" {
		t.Errorf("vendor should be resolved: %+v", devs[0])
	}

	code, body = call(t, ts, "PATCH", "/api/devices/00:1D:C1:00:00:20", `{"label":"CL5","tags":["dante"]}`, "")
	if code != 200 || !strings.Contains(string(body), `"label":"CL5"`) {
		t.Fatalf("patch: %d %s", code, body)
	}

	code, body = call(t, ts, "POST", "/api/subnets", `{"cidr":"10.0.0.0/24","name":"Dante","gateway":"10.0.0.1"}`, "")
	if code != 201 {
		t.Fatalf("subnet create: %d %s", code, body)
	}
	var sn model.Subnet
	_ = json.Unmarshal(body, &sn)

	// Reserve .20 for the right MAC and .21 for a different one → match + mismatch.
	if code, body = call(t, ts, "POST", "/api/reservations", `{"ip":"10.0.0.20","mac":"00:1d:c1:00:00:20","label":"CL5"}`, ""); code != 200 {
		t.Fatalf("reserve: %d %s", code, body)
	}
	if code, body = call(t, ts, "POST", "/api/reservations", `{"ip":"10.0.0.21","mac":"ac:44:f2:00:00:21","label":"Rio"}`, ""); code != 200 {
		t.Fatalf("reserve: %d %s", code, body)
	}
	if code, body = call(t, ts, "POST", "/api/reservations", `{"ip":"192.168.9.9","label":"nowhere"}`, ""); code != 400 {
		t.Errorf("reservation outside any subnet should fail: %d %s", code, body)
	}

	code, body = call(t, ts, "GET", "/api/subnets/1/map", "", "")
	var m struct {
		Summary   map[string]int `json:"summary"`
		Addresses []struct {
			IP     string `json:"ip"`
			Status string `json:"status"`
		} `json:"addresses"`
	}
	if err := json.Unmarshal(body, &m); err != nil || code != 200 {
		t.Fatalf("map: %d %s %v", code, body, err)
	}
	if m.Summary["match"] != 1 || m.Summary["mismatch"] != 1 || len(m.Addresses) != 256 {
		t.Errorf("map summary: %v (addresses %d)", m.Summary, len(m.Addresses))
	}

	if code, _ = call(t, ts, "POST", "/api/scan", `{"cidr":"10.0.0.0/24"}`, ""); code != 202 || len(ctl.scans) != 1 {
		t.Errorf("scan: %d %v", code, ctl.scans)
	}

	code, body = call(t, ts, "GET", "/api/export?format=csv&what=reservations", "", "")
	if code != 200 || !strings.Contains(string(body), "10.0.0.0/24,10.0.0.20,00:1d:c1:00:00:20,CL5,") {
		t.Errorf("export: %d %s", code, body)
	}
	code, body = call(t, ts, "GET", "/api/lookup?mac=00:1d:c1:00:00:01", "", "")
	if code != 200 || !strings.Contains(string(body), "Audinate") {
		t.Errorf("lookup: %d %s", code, body)
	}
	code, body = call(t, ts, "GET", "/api/events?kind=new_device", "", "")
	if code != 200 || strings.Count(string(body), `"new_device"`) != 2 {
		t.Errorf("events: %d %s", code, body)
	}
	if code, _ = call(t, ts, "DELETE", "/api/devices/f0:18:98:00:00:99", "", ""); code != 204 {
		t.Errorf("delete: %d", code)
	}
}
