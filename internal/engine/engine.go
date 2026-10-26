// Package engine merges observations into a live device table, persists it,
// detects IP conflicts and fans events out to subscribers (TUI, web SSE).
package engine

import (
	"context"
	"fmt"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sethrichar/netscout/internal/model"
	"github.com/sethrichar/netscout/internal/store"
)

// VendorLookup resolves a MAC to vendor names. Implemented by oui.DB.
type VendorLookup interface {
	Lookup(mac string) (short, long string, ok bool)
}

// Options tune engine behaviour.
type Options struct {
	Interface      string
	LocalNets      []*net.IPNet  // IPv4 networks on the capture interface
	SelfMAC        string        // our own MAC; flagged with attr self=true
	OnlineWindow   time.Duration // device goes offline after this much silence (default 5m)
	ConflictWindow time.Duration // same IP, different MAC inside this window = conflict (default 2m)
	FlushInterval  time.Duration // how often dirty devices are written (default 2s)
	ObsLogInterval time.Duration // min gap between logged observations per (mac,source) (default 60s)
	Vendors        VendorLookup  // optional
	Logger         *log.Logger   // optional
}

func (o *Options) defaults() {
	if o.OnlineWindow <= 0 {
		o.OnlineWindow = 5 * time.Minute
	}
	if o.ConflictWindow <= 0 {
		o.ConflictWindow = 2 * time.Minute
	}
	if o.FlushInterval <= 0 {
		o.FlushInterval = 2 * time.Second
	}
	if o.ObsLogInterval <= 0 {
		o.ObsLogInterval = 60 * time.Second
	}
}

type devState struct {
	dev        model.Device
	ips        map[string]*store.IPSeen
	hostSource int // priority of the source that set the hostname
	dirty      bool
	wentOff    bool                 // went offline during this run (so a return is news)
	lastLogged map[string]time.Time // source → last observation row written
}

type ipOwner struct {
	mac string
	ts  time.Time
}

// Engine is safe for concurrent use.
type Engine struct {
	opts  Options
	store *store.Store

	mu        sync.RWMutex
	devices   map[string]*devState
	owners    map[string]ipOwner   // ip → current owner
	conflicts map[string]time.Time // ip → last conflict event time
	packets   uint64
	closed    bool

	subMu sync.Mutex
	subs  map[int]chan model.Event
	nextS int
}

// New loads the existing device table from the store.
func New(st *store.Store, opts Options) (*Engine, error) {
	opts.defaults()
	e := &Engine{
		opts:      opts,
		store:     st,
		devices:   map[string]*devState{},
		owners:    map[string]ipOwner{},
		conflicts: map[string]time.Time{},
		subs:      map[int]chan model.Event{},
	}
	devs, err := st.ListDevices()
	if err != nil {
		return nil, fmt.Errorf("loading devices: %w", err)
	}
	for _, d := range devs {
		ips, err := st.ListDeviceIPs(d.MAC)
		if err != nil {
			return nil, err
		}
		ds := &devState{dev: d, ips: map[string]*store.IPSeen{}, lastLogged: map[string]time.Time{}}
		if ds.dev.Attrs == nil {
			ds.dev.Attrs = map[string]string{}
		}
		for i := range ips {
			ip := ips[i]
			ds.ips[ip.IP] = &ip
			if cur, ok := e.owners[ip.IP]; !ok || ip.LastSeen.After(cur.ts) {
				e.owners[ip.IP] = ipOwner{mac: d.MAC, ts: ip.LastSeen}
			}
		}
		// Anything loaded from disk is offline until we see it again.
		ds.dev.Online = false
		if d.Hostname != "" {
			ds.hostSource = 1
		}
		e.classify(ds)
		e.devices[d.MAC] = ds
	}
	return e, nil
}

// classify fills vendor and the randomized flag for a device that lacks them
// (placeholders from an imported plan, or rows saved before vendor data was
// available). Cheap: two map lookups.
func (e *Engine) classify(ds *devState) {
	d := &ds.dev
	if d.Vendor != "" {
		return
	}
	if r := model.IsRandomizedMAC(d.MAC); r != d.Randomized {
		d.Randomized = r
		ds.dirty = true
	}
	if e.opts.Vendors != nil {
		if short, long, ok := e.opts.Vendors.Lookup(d.MAC); ok {
			d.Vendor, d.VendorShort = long, short
			ds.dirty = true
		}
	}
}

// Run flushes dirty devices and sweeps for offline devices until ctx ends.
// Call Close once the packet source has stopped to mark devices offline and
// write the final state.
func (e *Engine) Run(ctx context.Context) {
	flush := time.NewTicker(e.opts.FlushInterval)
	defer flush.Stop()
	sweep := time.NewTicker(5 * time.Second)
	defer sweep.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-flush.C:
			e.Flush()
		case <-sweep.C:
			e.sweepOffline(time.Now())
		}
	}
}

// CountPacket bumps the packet counter shown in the UI.
func (e *Engine) CountPacket() {
	e.mu.Lock()
	e.packets++
	e.mu.Unlock()
}

// Packets returns how many frames have been fed through the engine.
func (e *Engine) Packets() uint64 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.packets
}

// Observe merges one observation into the device table.
func (e *Engine) Observe(o model.Observation) {
	mac, err := model.NormalizeMAC(o.MAC)
	if err != nil || !model.IsUsableMAC(mac) {
		return
	}
	o.MAC = mac
	if o.Timestamp.IsZero() {
		o.Timestamp = time.Now()
	}

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	if o.IP != "" && !e.acceptIP(o) {
		o.IP = ""
	}
	ds, isNew := e.devices[mac], false
	if ds == nil {
		isNew = true
		ds = &devState{
			dev: model.Device{
				MAC:        mac,
				IPs:        []string{},
				FirstSeen:  o.Timestamp,
				Interface:  o.Interface,
				Tags:       []string{},
				Randomized: model.IsRandomizedMAC(mac),
				Attrs:      map[string]string{},
			},
			ips:        map[string]*store.IPSeen{},
			lastLogged: map[string]time.Time{},
		}
		if e.opts.Vendors != nil {
			if short, long, ok := e.opts.Vendors.Lookup(mac); ok {
				ds.dev.Vendor, ds.dev.VendorShort = long, short
			}
		}
		if e.opts.SelfMAC != "" && mac == e.opts.SelfMAC {
			ds.dev.Attrs["self"] = "true"
		}
		e.devices[mac] = ds
	}
	d := &ds.dev
	var events []model.Event

	e.classify(ds)

	if o.Timestamp.After(d.LastSeen) {
		d.LastSeen = o.Timestamp
	}
	if d.FirstSeen.IsZero() || o.Timestamp.Before(d.FirstSeen) {
		d.FirstSeen = o.Timestamp
	}
	if o.Interface != "" {
		d.Interface = o.Interface
	}
	if o.VLAN != 0 {
		d.Attrs["vlan"] = fmt.Sprint(o.VLAN)
	}
	wasOnline := d.Online
	d.Online = true

	logObs := isNew
	if o.IP != "" {
		if seen, ok := ds.ips[o.IP]; ok {
			if o.Timestamp.After(seen.LastSeen) {
				seen.LastSeen = o.Timestamp
			}
		} else {
			ds.ips[o.IP] = &store.IPSeen{IP: o.IP, FirstSeen: o.Timestamp, LastSeen: o.Timestamp}
			logObs = true
			if !isNew && len(ds.ips) > 1 {
				events = append(events, model.Event{
					Time: o.Timestamp, Kind: model.EventIPChange, MAC: mac, IP: o.IP,
					Message: fmt.Sprintf("%s now using %s (was %s)", d.DisplayName(), o.IP, d.IP()),
					Details: map[string]string{"previous": d.IP(), "source": o.Source},
				})
			}
		}
		d.IPs = ds.sortedIPs()
		if ev := e.checkConflictLocked(mac, o); ev != nil {
			events = append(events, *ev)
			logObs = true
		}
	}

	if o.Hostname != "" {
		prio := hostPriority(o.Source)
		if d.Hostname == "" || prio > ds.hostSource || (prio == ds.hostSource && o.Hostname != d.Hostname) {
			if d.Hostname != "" && d.Hostname != o.Hostname {
				events = append(events, model.Event{
					Time: o.Timestamp, Kind: model.EventHostname, MAC: mac, IP: o.IP,
					Message: fmt.Sprintf("%s hostname changed %q → %q (%s)", mac, d.Hostname, o.Hostname, o.Source),
				})
			}
			if d.Hostname != o.Hostname {
				logObs = true
			}
			d.Hostname = o.Hostname
			ds.hostSource = prio
		}
	}
	for k, v := range o.Extra {
		if v == "" || strings.HasPrefix(k, "arp_") {
			continue // ARP op details are noise at the device level
		}
		if d.Attrs[k] != v {
			d.Attrs[k] = v
			logObs = true
		}
	}
	if _, ok := d.Attrs["sources"]; !ok || !strings.Contains(d.Attrs["sources"], o.Source) {
		d.Attrs["sources"] = addToken(d.Attrs["sources"], o.Source)
	}

	if isNew {
		events = append([]model.Event{{
			Time: o.Timestamp, Kind: model.EventNewDevice, MAC: mac, IP: o.IP,
			Message: fmt.Sprintf("new device %s %s %s", mac, o.IP, vendorOrRandom(d)),
			Details: map[string]string{"vendor": d.Vendor, "source": o.Source, "hostname": d.Hostname},
		}}, events...)
	} else if !wasOnline && ds.wentOff {
		ds.wentOff = false
		events = append(events, model.Event{
			Time: o.Timestamp, Kind: model.EventOnline, MAC: mac, IP: d.IP(),
			Message: fmt.Sprintf("%s back online", d.DisplayName()),
		})
	}
	if last, ok := ds.lastLogged[o.Source]; !ok || o.Timestamp.Sub(last) >= e.opts.ObsLogInterval {
		logObs = true
	}
	if logObs {
		ds.lastLogged[o.Source] = o.Timestamp
	}
	ds.dirty = true
	e.mu.Unlock()

	if logObs {
		if err := e.store.AddObservation(o); err != nil {
			e.logf("observation: %v", err)
		}
	}
	for i := range events {
		e.emit(&events[i])
	}
}

// acceptIP decides whether an observation's IP is believable for this LAN. ARP,
// DHCP and discovery protocols are link-local by nature; generic IPv4 frames
// are only trusted when the source address is in one of our local networks
// (otherwise the gateway MAC would accumulate every internet address).
func (e *Engine) acceptIP(o model.Observation) bool {
	if !model.IsUsableIPv4(o.IP) {
		return false
	}
	if o.Source != model.SourceIPv4 {
		return true
	}
	ip := net.ParseIP(o.IP)
	if len(e.opts.LocalNets) == 0 {
		return ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	for _, n := range e.opts.LocalNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// checkConflictLocked updates the IP ownership table and returns a conflict
// event when a different MAC claims an IP that was in use moments ago.
func (e *Engine) checkConflictLocked(mac string, o model.Observation) *model.Event {
	cur, ok := e.owners[o.IP]
	defer func() { e.owners[o.IP] = ipOwner{mac: mac, ts: o.Timestamp} }()
	if !ok || cur.mac == mac {
		return nil
	}
	if o.Timestamp.Sub(cur.ts) > e.opts.ConflictWindow {
		return nil // stale ownership: a normal lease change
	}
	if o.Extra["arp_op"] == "reply-target" {
		return nil // the target side of an ARP reply is hearsay, not a claim
	}
	if last, ok := e.conflicts[o.IP]; ok && o.Timestamp.Sub(last) < e.opts.ConflictWindow {
		return nil // already reported inside this window
	}
	e.conflicts[o.IP] = o.Timestamp
	other := e.devices[cur.mac]
	otherName := cur.mac
	if other != nil {
		otherName = other.dev.DisplayName()
		other.dev.Attrs["conflict_ip"] = o.IP
		other.dirty = true
	}
	this := e.devices[mac]
	this.dev.Attrs["conflict_ip"] = o.IP
	return &model.Event{
		Time: o.Timestamp, Kind: model.EventConflict, MAC: mac, IP: o.IP,
		Message: fmt.Sprintf("IP CONFLICT %s: %s and %s (%s) both claim it", o.IP, otherName, this.dev.DisplayName(), mac),
		Details: map[string]string{"mac_a": cur.mac, "mac_b": mac, "source": o.Source},
	}
}

// ClearConflict removes conflict markers for an IP (after the operator fixes it).
func (e *Engine) ClearConflict(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.conflicts, ip)
	for _, ds := range e.devices {
		if ds.dev.Attrs["conflict_ip"] == ip {
			delete(ds.dev.Attrs, "conflict_ip")
			ds.dirty = true
		}
	}
}

func (e *Engine) sweepOffline(now time.Time) {
	e.mu.Lock()
	var events []model.Event
	for _, ds := range e.devices {
		if ds.dev.Online && now.Sub(ds.dev.LastSeen) > e.opts.OnlineWindow {
			ds.dev.Online = false
			ds.dirty = true
			ds.wentOff = true
			events = append(events, model.Event{
				Time: now, Kind: model.EventOffline, MAC: ds.dev.MAC, IP: ds.dev.IP(),
				Message: fmt.Sprintf("%s went offline (silent %s)", ds.dev.DisplayName(), now.Sub(ds.dev.LastSeen).Round(time.Second)),
			})
		}
	}
	e.mu.Unlock()
	for i := range events {
		e.emit(&events[i])
	}
}

// Close marks every device offline (nothing is watching any more) and flushes.
// Observations arriving after Close are ignored.
func (e *Engine) Close() {
	e.mu.Lock()
	e.closed = true
	for _, ds := range e.devices {
		if ds.dev.Online {
			ds.dev.Online = false
			ds.dirty = true
		}
	}
	e.mu.Unlock()
	e.Flush()
}

// Flush writes every dirty device to the store.
func (e *Engine) Flush() {
	e.mu.Lock()
	type pending struct {
		dev model.Device
		ips []store.IPSeen
	}
	var batch []pending
	for _, ds := range e.devices {
		if !ds.dirty {
			continue
		}
		ds.dirty = false
		p := pending{dev: cloneDevice(ds.dev)}
		for _, ip := range ds.ips {
			p.ips = append(p.ips, *ip)
		}
		batch = append(batch, p)
	}
	e.mu.Unlock()
	for _, p := range batch {
		if err := e.store.SaveObserved(&p.dev, p.ips); err != nil {
			e.logf("flush %s: %v", p.dev.MAC, err)
		}
	}
}

// Devices returns a snapshot sorted online-first, then by IP, then MAC.
func (e *Engine) Devices() []model.Device {
	e.mu.RLock()
	out := make([]model.Device, 0, len(e.devices))
	for _, ds := range e.devices {
		out = append(out, cloneDevice(ds.dev))
	}
	e.mu.RUnlock()
	SortDevices(out)
	return out
}

// Device returns one device snapshot.
func (e *Engine) Device(mac string) (model.Device, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ds, ok := e.devices[mac]
	if !ok {
		return model.Device{}, false
	}
	return cloneDevice(ds.dev), true
}

// Counts returns total and online device counts.
func (e *Engine) Counts() (total, online int) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, ds := range e.devices {
		total++
		if ds.dev.Online {
			online++
		}
	}
	return
}

// SetUserFields updates label/notes/tags in memory and on disk. nil leaves a
// field unchanged.
func (e *Engine) SetUserFields(mac string, label, notes *string, tags []string) error {
	mac, err := model.NormalizeMAC(mac)
	if err != nil {
		return err
	}
	if err := e.store.SetUserFields(mac, label, notes, tags); err != nil {
		return err
	}
	e.mu.Lock()
	ds, ok := e.devices[mac]
	if !ok {
		d, err := e.store.GetDevice(mac)
		if err == nil && d != nil {
			ds = &devState{dev: *d, ips: map[string]*store.IPSeen{}, lastLogged: map[string]time.Time{}}
			if ds.dev.Attrs == nil {
				ds.dev.Attrs = map[string]string{}
			}
			e.classify(ds)
			e.devices[mac] = ds
		}
	}
	if ds != nil {
		if label != nil {
			ds.dev.Label = *label
		}
		if notes != nil {
			ds.dev.Notes = *notes
		}
		if tags != nil {
			ds.dev.Tags = tags
		}
	}
	e.mu.Unlock()
	if ds != nil {
		e.emit(&model.Event{Kind: model.EventInfo, MAC: mac, Message: "device updated", Details: map[string]string{"silent": "true"}})
	}
	return nil
}

// Forget removes a device from memory and disk.
func (e *Engine) Forget(mac string) error {
	mac, err := model.NormalizeMAC(mac)
	if err != nil {
		return err
	}
	e.mu.Lock()
	delete(e.devices, mac)
	for ip, o := range e.owners {
		if o.mac == mac {
			delete(e.owners, ip)
		}
	}
	e.mu.Unlock()
	return e.store.DeleteDevice(mac)
}

// Emit publishes an externally generated event (scan started, etc.).
func (e *Engine) Emit(ev model.Event) { e.emit(&ev) }

func (e *Engine) emit(ev *model.Event) {
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	if ev.Details["silent"] != "true" {
		if err := e.store.AddEvent(ev); err != nil {
			e.logf("event: %v", err)
		}
	}
	e.subMu.Lock()
	defer e.subMu.Unlock()
	for _, ch := range e.subs {
		select {
		case ch <- *ev:
		default: // slow subscriber: drop rather than block capture
		}
	}
}

// Subscribe returns a channel of live events and a cancel func.
func (e *Engine) Subscribe() (<-chan model.Event, func()) {
	ch := make(chan model.Event, 256)
	e.subMu.Lock()
	id := e.nextS
	e.nextS++
	e.subs[id] = ch
	e.subMu.Unlock()
	return ch, func() {
		e.subMu.Lock()
		if c, ok := e.subs[id]; ok {
			delete(e.subs, id)
			close(c)
		}
		e.subMu.Unlock()
	}
}

// Store exposes the backing store for read-only API queries.
func (e *Engine) Store() *store.Store { return e.store }

// Options returns the engine configuration.
func (e *Engine) Options() Options {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.opts
}

// SetInterface updates the capture interface facts used for IP acceptance and
// self-detection (after the operator switches interfaces in the UI).
func (e *Engine) SetInterface(name string, nets []*net.IPNet, selfMAC string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.opts.Interface, e.opts.LocalNets, e.opts.SelfMAC = name, nets, selfMAC
	for mac, ds := range e.devices {
		if mac == selfMAC {
			ds.dev.Attrs["self"] = "true"
			ds.dirty = true
		} else if ds.dev.Attrs["self"] == "true" {
			delete(ds.dev.Attrs, "self")
			ds.dirty = true
		}
	}
}

// SetVendors swaps the vendor lookup (after update-oui) and re-resolves
// devices that have no vendor yet.
func (e *Engine) SetVendors(v VendorLookup) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.opts.Vendors = v
	if v == nil {
		return
	}
	for mac, ds := range e.devices {
		if ds.dev.Vendor == "" {
			if short, long, ok := v.Lookup(mac); ok {
				ds.dev.Vendor, ds.dev.VendorShort = long, short
				ds.dirty = true
			}
		}
	}
}

// IPBindings returns every (MAC, IP) pair known in memory with its window.
func (e *Engine) IPBindings() []store.IPBinding {
	e.mu.RLock()
	defer e.mu.RUnlock()
	var out []store.IPBinding
	for mac, ds := range e.devices {
		for _, ip := range ds.ips {
			out = append(out, store.IPBinding{MAC: mac, IP: ip.IP, FirstSeen: ip.FirstSeen, LastSeen: ip.LastSeen})
		}
	}
	return out
}

func (e *Engine) logf(format string, args ...any) {
	if e.opts.Logger != nil {
		e.opts.Logger.Printf(format, args...)
	}
}

// --- helpers -----------------------------------------------------------------

func (ds *devState) sortedIPs() []string {
	ips := make([]*store.IPSeen, 0, len(ds.ips))
	for _, s := range ds.ips {
		ips = append(ips, s)
	}
	sort.Slice(ips, func(a, b int) bool {
		if !ips[a].LastSeen.Equal(ips[b].LastSeen) {
			return ips[a].LastSeen.After(ips[b].LastSeen)
		}
		return ipLess(ips[a].IP, ips[b].IP)
	})
	out := make([]string, len(ips))
	for i, s := range ips {
		out[i] = s.IP
	}
	return out
}

func hostPriority(source string) int {
	switch source {
	case model.SourceDHCP, model.SourceMDNS:
		return 3
	case model.SourceLLDP, model.SourceCDP:
		return 2
	default:
		return 1
	}
}

func vendorOrRandom(d *model.Device) string {
	switch {
	case d.Vendor != "":
		return "[" + d.Vendor + "]"
	case d.Randomized:
		return "[randomized MAC]"
	default:
		return "[unknown vendor]"
	}
}

func addToken(list, tok string) string {
	if list == "" {
		return tok
	}
	for _, t := range strings.Split(list, ",") {
		if t == tok {
			return list
		}
	}
	return list + "," + tok
}

func cloneDevice(d model.Device) model.Device {
	c := d
	c.IPs = append([]string(nil), d.IPs...)
	c.Tags = append([]string(nil), d.Tags...)
	if c.IPs == nil {
		c.IPs = []string{}
	}
	if c.Tags == nil {
		c.Tags = []string{}
	}
	c.Attrs = make(map[string]string, len(d.Attrs))
	for k, v := range d.Attrs {
		c.Attrs[k] = v
	}
	return c
}

// SortDevices orders online devices first, then by IP (numeric), then MAC.
func SortDevices(devs []model.Device) {
	sort.SliceStable(devs, func(a, b int) bool {
		if devs[a].Online != devs[b].Online {
			return devs[a].Online
		}
		ia, ib := devs[a].IP(), devs[b].IP()
		if (ia == "") != (ib == "") {
			return ia != ""
		}
		if ia != ib {
			return ipLess(ia, ib)
		}
		return devs[a].MAC < devs[b].MAC
	})
}

func ipLess(a, b string) bool {
	pa, pb := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if pa == nil || pb == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return false
}
