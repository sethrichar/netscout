package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sethrichar/netscout"
	"github.com/sethrichar/netscout/internal/export"
	"github.com/sethrichar/netscout/internal/ipam"
	"github.com/sethrichar/netscout/internal/model"
	"github.com/sethrichar/netscout/internal/store"
)

// --- status / capture ----------------------------------------------------------

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	st := s.ctl.Status()
	st.Version = netscout.Version()
	total, online := s.eng.Counts()
	writeJSON(w, 200, map[string]any{
		"capture": st,
		"devices": total,
		"online":  online,
		"packets": s.eng.Packets(),
		"now":     time.Now(),
	})
}

func (s *Server) handleIfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := s.ctl.Interfaces()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	writeJSON(w, 200, ifaces)
}

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Interface string `json:"interface"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, 400, err)
		return
	}
	if err := s.ctl.SwitchInterface(body.Interface); err != nil {
		writeError(w, 400, err)
		return
	}
	writeJSON(w, 200, s.ctl.Status())
}

// --- devices -------------------------------------------------------------------

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, s.eng.Devices())
}

func (s *Server) handleDevice(w http.ResponseWriter, r *http.Request) {
	mac, err := model.NormalizeMAC(r.PathValue("mac"))
	if err != nil {
		writeError(w, 400, err)
		return
	}
	d, ok := s.eng.Device(mac)
	if !ok {
		writeError(w, 404, fmt.Errorf("unknown device %s", mac))
		return
	}
	ips, _ := s.store.ListDeviceIPs(mac)
	obs, _ := s.store.ListObservations(mac, 50)
	evs, _ := s.store.ListEvents(store.EventFilter{MAC: mac, Limit: 50})
	var vendor any
	if db := s.ctl.OUI(); db != nil {
		if res, err := db.Describe(mac); err == nil {
			vendor = res
		}
	}
	writeJSON(w, 200, map[string]any{"device": d, "ips": ips, "observations": obs, "events": evs, "vendor": vendor})
}

func (s *Server) handleDevicePatch(w http.ResponseWriter, r *http.Request) {
	mac, err := model.NormalizeMAC(r.PathValue("mac"))
	if err != nil {
		writeError(w, 400, err)
		return
	}
	var body struct {
		Label *string  `json:"label"`
		Notes *string  `json:"notes"`
		Tags  []string `json:"tags"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, 400, err)
		return
	}
	if err := s.eng.SetUserFields(mac, body.Label, body.Notes, body.Tags); err != nil {
		writeError(w, 400, err)
		return
	}
	d, _ := s.eng.Device(mac)
	writeJSON(w, 200, d)
}

func (s *Server) handleDeviceDelete(w http.ResponseWriter, r *http.Request) {
	if err := s.eng.Forget(r.PathValue("mac")); err != nil {
		writeError(w, 400, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) handleLookup(w http.ResponseWriter, r *http.Request) {
	db := s.ctl.OUI()
	if db == nil {
		writeError(w, 503, fmt.Errorf("vendor database unavailable"))
		return
	}
	if q := r.URL.Query().Get("q"); q != "" {
		writeJSON(w, 200, db.Search(q, 100))
		return
	}
	res, err := db.Describe(r.URL.Query().Get("mac"))
	if err != nil {
		writeError(w, 400, err)
		return
	}
	writeJSON(w, 200, res)
}

// --- events --------------------------------------------------------------------

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.EventFilter{Kind: q.Get("kind"), MAC: q.Get("mac")}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.AfterID, _ = strconv.ParseInt(q.Get("after"), 10, 64)
	evs, err := s.store.ListEvents(f)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	if evs == nil {
		evs = []model.Event{}
	}
	writeJSON(w, 200, evs)
}

func (s *Server) handleClearConflict(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP string `json:"ip"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, 400, err)
		return
	}
	s.eng.ClearConflict(body.IP)
	w.WriteHeader(204)
}

// --- subnets / ipam -------------------------------------------------------------

type subnetView struct {
	model.Subnet
	Summary ipam.Summary `json:"summary"`
}

func (s *Server) bindings() []ipam.Binding {
	raw := s.eng.IPBindings()
	out := make([]ipam.Binding, len(raw))
	for i, b := range raw {
		out[i] = ipam.Binding{IP: b.IP, MAC: b.MAC, LastSeen: b.LastSeen}
	}
	window := s.ctl.Status().OnlineAfter
	if window <= 0 {
		window = time.Hour
	}
	// A binding is current if it is recent, or it is the device's latest.
	return ipam.MarkCurrent(out, time.Now(), window)
}

func (s *Server) handleSubnets(w http.ResponseWriter, r *http.Request) {
	subnets, err := s.store.ListSubnets()
	if err != nil {
		writeError(w, 500, err)
		return
	}
	bindings := s.bindings()
	devs := s.eng.Devices()
	views := []subnetView{}
	for _, sn := range subnets {
		res, _ := s.store.ListReservations(sn.ID)
		_, sum, err := ipam.Compute(sn, res, bindings, devs, ipam.Options{})
		if err != nil {
			writeError(w, 500, err)
			return
		}
		views = append(views, subnetView{sn, sum})
	}
	writeJSON(w, 200, views)
}

func (s *Server) handleSubnetCreate(w http.ResponseWriter, r *http.Request) {
	var sn model.Subnet
	if err := readJSON(r, &sn); err != nil {
		writeError(w, 400, err)
		return
	}
	created, err := s.store.AddSubnet(sn)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	writeJSON(w, 201, created)
}

func (s *Server) handleSubnetPatch(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	sn, err := s.store.GetSubnet(id)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	if sn == nil {
		writeError(w, 404, fmt.Errorf("subnet %d not found", id))
		return
	}
	var body struct {
		Name    *string `json:"name"`
		VLAN    *int    `json:"vlan"`
		Gateway *string `json:"gateway"`
		Notes   *string `json:"notes"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, 400, err)
		return
	}
	if body.Name != nil {
		sn.Name = *body.Name
	}
	if body.VLAN != nil {
		sn.VLAN = *body.VLAN
	}
	if body.Gateway != nil {
		sn.Gateway = *body.Gateway
	}
	if body.Notes != nil {
		sn.Notes = *body.Notes
	}
	if err := s.store.UpdateSubnet(*sn); err != nil {
		writeError(w, 400, err)
		return
	}
	writeJSON(w, 200, sn)
}

func (s *Server) handleSubnetDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.store.DeleteSubnet(id); err != nil {
		writeError(w, 500, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Server) handleSubnetMap(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	sn, err := s.store.GetSubnet(id)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	if sn == nil {
		writeError(w, 404, fmt.Errorf("subnet %d not found", id))
		return
	}
	res, err := s.store.ListReservations(sn.ID)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	addrs, sum, err := ipam.Compute(*sn, res, s.bindings(), s.eng.Devices(), ipam.Options{IncludeEdges: true})
	if err != nil {
		writeError(w, 400, err)
		return
	}
	if res == nil {
		res = []model.Reservation{}
	}
	writeJSON(w, 200, map[string]any{"subnet": sn, "summary": sum, "addresses": addrs, "reservations": res})
}

func (s *Server) handleReservationUpsert(w http.ResponseWriter, r *http.Request) {
	var body model.Reservation
	if err := readJSON(r, &body); err != nil {
		writeError(w, 400, err)
		return
	}
	if body.SubnetID == 0 {
		sn, err := s.store.SubnetContaining(body.IP)
		if err != nil {
			writeError(w, 400, err)
			return
		}
		if sn == nil {
			writeError(w, 400, fmt.Errorf("%s is in no registered subnet", body.IP))
			return
		}
		body.SubnetID = sn.ID
	} else if sn, _ := s.store.GetSubnet(body.SubnetID); sn != nil {
		if _, n, err := net.ParseCIDR(sn.CIDR); err == nil && !n.Contains(net.ParseIP(body.IP)) {
			writeError(w, 400, fmt.Errorf("%s is outside %s", body.IP, sn.CIDR))
			return
		}
	}
	saved, err := s.store.UpsertReservation(body)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	// Carry the label to the device when it has none.
	if saved.MAC != "" && saved.Label != "" {
		if d, ok := s.eng.Device(saved.MAC); !ok || d.Label == "" {
			_ = s.eng.SetUserFields(saved.MAC, &saved.Label, nil, nil)
		}
	}
	writeJSON(w, 200, saved)
}

func (s *Server) handleReservationDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	all, err := s.store.ListReservations(0)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	for _, res := range all {
		if res.ID == id {
			if err := s.store.DeleteReservation(res.SubnetID, res.IP); err != nil {
				writeError(w, 500, err)
				return
			}
			w.WriteHeader(204)
			return
		}
	}
	writeError(w, 404, fmt.Errorf("reservation %d not found", id))
}

// --- export / import ------------------------------------------------------------

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	what := r.URL.Query().Get("what")
	devs := s.eng.Devices()
	subnets, _ := s.store.ListSubnets()
	res, _ := s.store.ListReservations(0)
	var buf bytes.Buffer
	var name, ctype string
	stamp := time.Now().Format("20060102-1504")
	switch format {
	case "json", "":
		if err := export.WriteJSON(&buf, export.Snapshot{Version: netscout.Version(), Subnets: subnets, Reservations: res, Devices: devs}); err != nil {
			writeError(w, 500, err)
			return
		}
		name, ctype = "netscout-"+stamp+".json", "application/json"
	case "csv":
		var err error
		if what == "reservations" {
			err = export.WriteReservationsCSV(&buf, subnets, res)
			name = "netscout-plan-" + stamp + ".csv"
		} else {
			err = export.WriteDevicesCSV(&buf, devs)
			name = "netscout-devices-" + stamp + ".csv"
		}
		if err != nil {
			writeError(w, 500, err)
			return
		}
		ctype = "text/csv"
	default:
		writeError(w, 400, fmt.Errorf("format must be json or csv"))
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(16 << 20); err != nil {
		writeError(w, 400, fmt.Errorf("expected multipart form: %w", err))
		return
	}
	f, _, err := r.FormFile("file")
	if err != nil {
		writeError(w, 400, fmt.Errorf("missing file field: %w", err))
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 16<<20))
	if err != nil {
		writeError(w, 400, err)
		return
	}
	imp, err := export.Parse(bytes.NewReader(data))
	if err != nil {
		writeError(w, 400, err)
		return
	}
	opts := export.ApplyOptions{
		DefaultSubnet: r.FormValue("subnet"),
		AutoSubnets:   r.FormValue("auto_subnets") == "true",
		DryRun:        r.FormValue("dry_run") == "true",
	}
	rep, err := export.Apply(s.store, imp, opts)
	if err != nil {
		writeError(w, 400, err)
		return
	}
	// Labels written straight to the store need to reach the engine's memory.
	if !opts.DryRun {
		for _, row := range imp.Rows {
			if row.MAC != "" && row.Label != "" {
				if d, ok := s.eng.Device(row.MAC); ok && d.Label == "" {
					_ = s.eng.SetUserFields(row.MAC, &row.Label, nil, nil)
				}
			}
		}
	}
	if rep.Skipped == nil {
		rep.Skipped = []string{}
	}
	if rep.SubnetsCreated == nil {
		rep.SubnetsCreated = []string{}
	}
	writeJSON(w, 200, map[string]any{"rows": len(imp.Rows), "report": rep, "dry_run": opts.DryRun})
}

// --- scan / oui ----------------------------------------------------------------

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		CIDR string `json:"cidr"`
	}
	if r.ContentLength > 0 {
		if err := readJSON(r, &body); err != nil {
			writeError(w, 400, err)
			return
		}
	}
	if err := s.ctl.Scan(context.Background(), body.CIDR); err != nil {
		writeError(w, 409, err)
		return
	}
	w.WriteHeader(202)
}

func (s *Server) handleScanSchedule(w http.ResponseWriter, r *http.Request) {
	var body struct {
		EverySeconds int    `json:"every_seconds"`
		CIDR         string `json:"cidr"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, 400, err)
		return
	}
	if body.EverySeconds < 0 || (body.EverySeconds > 0 && body.EverySeconds < 30) {
		writeError(w, 400, fmt.Errorf("every_seconds must be 0 (off) or at least 30"))
		return
	}
	s.ctl.SetScanInterval(context.Background(), time.Duration(body.EverySeconds)*time.Second, body.CIDR)
	writeJSON(w, 200, s.ctl.Status())
}

func (s *Server) handleOUIUpdate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	res, err := s.ctl.UpdateOUI(ctx)
	if err != nil {
		writeError(w, 502, err)
		return
	}
	writeJSON(w, 200, res)
}

// --- SSE -------------------------------------------------------------------------

// handleStream pushes events and a status heartbeat as server-sent events.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, 500, fmt.Errorf("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(200)

	events, cancel := s.eng.Subscribe()
	defer cancel()
	send := func(kind string, v any) bool {
		b, err := json.Marshal(v)
		if err != nil {
			return true
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", kind, strings.ReplaceAll(string(b), "\n", " ")); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	send("hello", map[string]any{"now": time.Now()})
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			if !send("event", ev) {
				return
			}
		case <-tick.C:
			total, online := s.eng.Counts()
			st := s.ctl.Status()
			st.Version = netscout.Version()
			if !send("status", map[string]any{"devices": total, "online": online, "packets": s.eng.Packets(), "capture": st, "now": time.Now()}) {
				return
			}
		}
	}
}
