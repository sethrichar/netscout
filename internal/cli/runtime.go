package cli

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/sethrichar/netscout/internal/arptable"
	"github.com/sethrichar/netscout/internal/capture"
	"github.com/sethrichar/netscout/internal/config"
	"github.com/sethrichar/netscout/internal/engine"
	"github.com/sethrichar/netscout/internal/model"
	"github.com/sethrichar/netscout/internal/oui"
	"github.com/sethrichar/netscout/internal/parse"
	"github.com/sethrichar/netscout/internal/scan"
	"github.com/sethrichar/netscout/internal/store"
	"github.com/sethrichar/netscout/internal/term"
)

// rtime bundles everything a long-running command (sniff, ui) needs: the
// store, the engine, the vendor DB and the current capture session. Capture
// can be stopped and restarted on another interface while the engine keeps
// running.
type rtime struct {
	dataDir string
	store   *store.Store
	engine  *engine.Engine
	logger  *log.Logger
	started time.Time
	bpf     string

	mu        sync.Mutex
	oui       *oui.DB
	iface     capture.Interface
	session   *capture.Session // nil when passive
	passive   bool
	hint      string // privilege hint shown when passive
	appCtx    context.Context
	capCancel context.CancelFunc
	capDone   chan struct{}

	scanMu       sync.Mutex
	scanning     bool
	lastScan     time.Time
	scanInterval time.Duration
	scanCIDR     string
	scanCancel   context.CancelFunc
	scanDone     chan struct{}
}

// openStore opens the SQLite DB in the data dir.
func openStore() (string, *store.Store, error) {
	dir, err := dataDir()
	if err != nil {
		return "", nil, err
	}
	st, err := store.Open(config.DBPath(dir))
	if err != nil {
		return "", nil, err
	}
	return dir, st, nil
}

// newRuntime resolves the interface, opens the DB and engine, and tries to
// start capture. On a permission failure it degrades to passive mode (OS ARP
// table polling) and records the hint to show the user.
func newRuntime(ifaceName string, onlineWindow, conflictWindow time.Duration, bpf string, logger *log.Logger) (*rtime, error) {
	dir, st, err := openStore()
	if err != nil {
		return nil, err
	}
	db, err := oui.Load(dir)
	if err != nil {
		logger.Printf("oui: %v (vendor lookup disabled)", err)
	}
	rt := &rtime{dataDir: dir, store: st, oui: db, logger: logger, bpf: bpf, started: time.Now()}

	if ifaceName == "" {
		// Reuse the last interface only if it can still see a LAN; otherwise
		// fall back to the default-route choice rather than a dead adapter.
		if last, _ := st.GetMeta("last_interface"); last != "" {
			if i, err := capture.FindInterface(last); err == nil && i.Usable() {
				ifaceName = last
			}
		}
	}
	if err := rt.openCapture(ifaceName); err != nil {
		st.Close()
		return nil, err
	}

	var vendors engine.VendorLookup
	if db != nil {
		vendors = db
	}
	rt.engine, err = engine.New(st, engine.Options{
		Interface:      rt.iface.Name,
		LocalNets:      rt.iface.LocalNets(),
		SelfMAC:        rt.iface.MAC,
		OnlineWindow:   onlineWindow,
		ConflictWindow: conflictWindow,
		Vendors:        vendors,
		Logger:         logger,
	})
	if err != nil {
		rt.close()
		return nil, err
	}
	return rt, nil
}

// openCapture resolves name and opens a session, or records passive mode.
// Caller holds no lock; this sets iface/session/passive/hint.
func (rt *rtime) openCapture(name string) error {
	iface, err := capture.FindInterface(name)
	if err != nil {
		// Only a missing driver / no permission degrades to passive mode;
		// "no such interface" is a plain error the operator must fix.
		if !capture.IsPermissionError(err) {
			return err
		}
		rt.iface, rt.session, rt.passive = capture.Interface{Name: name}, nil, true
		rt.hint = fmt.Sprintf("%v\n\n%s", err, capture.PrivilegeHint(err))
		return nil
	}
	sess, err := capture.Open(iface, capture.Options{Promisc: true, BPF: rt.bpf})
	if err != nil {
		if !capture.IsPermissionError(err) {
			return err
		}
		rt.iface, rt.session, rt.passive = iface, nil, true
		rt.hint = fmt.Sprintf("%v\n\n%s", err, capture.PrivilegeHint(err))
	} else {
		rt.iface, rt.session, rt.passive, rt.hint = iface, sess, false, ""
	}
	_ = rt.store.SetMeta("last_interface", rt.iface.Name)
	return nil
}

func (rt *rtime) close() {
	rt.mu.Lock()
	if rt.session != nil {
		rt.session.Close()
		rt.session = nil
	}
	rt.mu.Unlock()
	if rt.store != nil {
		rt.store.Close()
	}
}

// start launches the engine and the capture loop under ctx.
func (rt *rtime) start(ctx context.Context) {
	rt.appCtx = ctx
	go rt.engine.Run(ctx)
	rt.mu.Lock()
	rt.startCaptureLocked()
	rt.mu.Unlock()
}

// stop ends any sweep and the capture, then closes the engine (final flush,
// everything offline).
func (rt *rtime) stop() {
	rt.stopScan()
	rt.mu.Lock()
	cancel, done := rt.capCancel, rt.capDone
	rt.capCancel, rt.capDone = nil, nil
	rt.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	rt.mu.Lock()
	rt.session = nil
	rt.mu.Unlock()
	rt.engine.Close()
}

// stopScan cancels a running sweep and waits for it to finish injecting.
func (rt *rtime) stopScan() {
	rt.scanMu.Lock()
	cancel, done := rt.scanCancel, rt.scanDone
	rt.scanMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// run is the simple synchronous form used by sniff: start, wait, stop.
func (rt *rtime) run(ctx context.Context) {
	rt.start(ctx)
	<-ctx.Done()
	rt.stop()
}

// runAsync starts run in the background and returns a channel closed when it
// has fully stopped (engine flushed).
func (rt *rtime) runAsync(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		rt.run(ctx)
	}()
	return done
}

// waitStopped blocks until run has finished or the grace period elapses.
func waitStopped(done <-chan struct{}, grace time.Duration) {
	select {
	case <-done:
	case <-time.After(grace):
	}
}

// startCaptureLocked spawns the packet loop for the current session, or the
// OS ARP-table poller in passive mode. rt.mu must be held.
//
// The OS ARP cache is only consulted in passive mode: its entries can be
// many minutes stale, so in active mode they would only seed false
// ownership and phantom offline events.
func (rt *rtime) startCaptureLocked() {
	ctx, cancel := context.WithCancel(rt.appCtx)
	done := make(chan struct{})
	rt.capCancel, rt.capDone = cancel, done
	sess, iface, passive := rt.session, rt.iface, rt.passive
	go func() {
		defer close(done)
		if sess == nil {
			rt.pollARPTable(iface, passive)
			t := time.NewTicker(5 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					rt.pollARPTable(iface, passive)
				}
			}
		}
		for pkt := range sess.Packets(ctx) {
			rt.engine.CountPacket()
			for _, o := range parse.Packet(pkt, iface.Name) {
				rt.engine.Observe(o)
			}
		}
		sess.Close()
		if err := sess.Err(); err != nil && ctx.Err() == nil {
			// The capture died on its own (cable pulled, adapter removed,
			// driver reset). Say so loudly and fall back to passive mode so
			// the UI does not keep claiming "capturing".
			rt.logger.Printf("capture on %s stopped: %v", iface.Name, err)
			rt.mu.Lock()
			if rt.session == sess {
				rt.session = nil
				rt.passive = true
				rt.hint = fmt.Sprintf("capture on %s stopped: %v\n\nReconnect the interface and switch to it again in Settings (or restart netscout).", iface.Name, err)
			}
			rt.mu.Unlock()
			rt.engine.Emit(model.Event{Kind: model.EventInfo, Message: fmt.Sprintf("capture on %s stopped: %v — now passive", iface.Label(), err)})
		}
	}()
}

// switchInterface stops any sweep and the capture, reopens on another
// interface and restarts. The target is validated before the current capture
// is torn down so a typo never leaves the tool dead.
func (rt *rtime) switchInterface(name string) error {
	target, err := capture.FindInterface(name)
	if err != nil && !capture.IsPermissionError(err) {
		return err
	}
	rt.stopScan()
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.capCancel != nil {
		rt.capCancel()
		<-rt.capDone
	}
	rt.session = nil // closed by the loop
	if err := rt.openCapture(target.Name); err != nil {
		// Reopen the previous interface so we are never left dead.
		_ = rt.openCapture(rt.iface.Name)
		rt.startCaptureLocked()
		return err
	}
	rt.engine.SetInterface(rt.iface.Name, rt.iface.LocalNets(), rt.iface.MAC)
	rt.engine.Emit(model.Event{Kind: model.EventInfo, Message: "capturing on " + rt.iface.Label()})
	rt.startCaptureLocked()
	return nil
}

func (rt *rtime) pollARPTable(iface capture.Interface, passive bool) {
	entries, err := arptable.Read()
	if err != nil {
		rt.logger.Printf("arp table: %v", err)
		return
	}
	for _, o := range arptable.Observations(entries, iface.Name) {
		if !passive && !ifaceMatches(o.Interface, iface) {
			continue
		}
		rt.engine.Observe(o)
	}
}

func ifaceMatches(name string, iface capture.Interface) bool {
	return name == "" || name == iface.Name || name == iface.FriendlyName || (iface.FirstIPv4() != nil && name == iface.FirstIPv4().String())
}

// --- scanning ----------------------------------------------------------------

// startScan runs an ARP sweep through the live capture session; replies are
// picked up by the normal parse pipeline. Only one sweep runs at a time.
func (rt *rtime) startScan(ctx context.Context, cidr string) error {
	rt.mu.Lock()
	sess, iface := rt.session, rt.iface
	rt.mu.Unlock()
	if sess == nil {
		return fmt.Errorf("scan unavailable: capture is in passive mode")
	}
	if cidr == "" {
		cidr = scan.DefaultCIDR(iface)
	}
	if cidr == "" {
		return fmt.Errorf("interface has no IPv4 subnet; specify a CIDR")
	}
	if _, _, err := scan.Hosts(cidr); err != nil {
		return err
	}
	rt.scanMu.Lock()
	if rt.scanning {
		rt.scanMu.Unlock()
		return fmt.Errorf("a scan is already running")
	}
	rt.scanning = true
	sctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	rt.scanCancel, rt.scanDone = cancel, done
	rt.scanMu.Unlock()

	go func() {
		defer func() {
			cancel()
			rt.scanMu.Lock()
			rt.scanning = false
			rt.lastScan = time.Now()
			rt.scanCancel, rt.scanDone = nil, nil
			rt.scanMu.Unlock()
			close(done)
		}()
		rt.engine.Emit(model.Event{Kind: model.EventScan, Message: fmt.Sprintf("ARP sweep of %s started", cidr), Details: map[string]string{"cidr": cidr, "state": "started"}})
		start := time.Now()
		n, err := scan.ARPSweep(sctx, sess, iface, cidr, scan.Options{Passes: 2})
		msg := fmt.Sprintf("ARP sweep of %s sent %d requests in %s", cidr, n, time.Since(start).Round(time.Millisecond))
		if err != nil && sctx.Err() == nil {
			msg += " (" + err.Error() + ")"
		}
		rt.engine.Emit(model.Event{Kind: model.EventScan, Message: msg, Details: map[string]string{"cidr": cidr, "state": "done"}})
	}()
	return nil
}

// scanState reports whether a sweep is running and when the last one ended.
func (rt *rtime) scanState() (running bool, last time.Time, interval time.Duration, cidr string) {
	rt.scanMu.Lock()
	defer rt.scanMu.Unlock()
	return rt.scanning, rt.lastScan, rt.scanInterval, rt.scanCIDR
}

// setScanInterval enables (or disables with 0) periodic sweeps.
func (rt *rtime) setScanInterval(ctx context.Context, d time.Duration, cidr string) {
	rt.scanMu.Lock()
	rt.scanInterval, rt.scanCIDR = d, cidr
	rt.scanMu.Unlock()
}

// scanScheduler runs periodic sweeps when an interval is set.
func (rt *rtime) scanScheduler(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			running, last, interval, cidr := rt.scanState()
			if interval <= 0 || running || time.Since(last) < interval {
				continue
			}
			if err := rt.startScan(ctx, cidr); err != nil {
				rt.logger.Printf("scheduled scan: %v", err)
				rt.scanMu.Lock()
				rt.lastScan = time.Now() // back off until next interval
				rt.scanMu.Unlock()
			}
		}
	}
}

// --- oui ---------------------------------------------------------------------

// updateOUI downloads fresh vendor data and swaps it into the engine.
func (rt *rtime) updateOUI(ctx context.Context) (oui.UpdateResult, error) {
	res, err := oui.Update(ctx, rt.dataDir, nil)
	if err != nil {
		return res, err
	}
	db, err := oui.Load(rt.dataDir)
	if err != nil {
		return res, err
	}
	rt.mu.Lock()
	rt.oui = db
	rt.mu.Unlock()
	rt.engine.SetVendors(db)
	rt.engine.Emit(model.Event{Kind: model.EventInfo, Message: fmt.Sprintf("vendor database updated: %d entries", res.Entries)})
	return res, nil
}

// --- misc --------------------------------------------------------------------

// signalContext cancels on Ctrl-C / SIGTERM.
func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-ch:
			cancel()
		case <-ctx.Done():
		}
		signal.Stop(ch)
	}()
	return ctx, cancel
}

// eventLine formats an event for log-style output.
func eventLine(ev model.Event) string {
	ts := ev.Time.Local().Format("15:04:05")
	switch ev.Kind {
	case model.EventConflict:
		return fmt.Sprintf("%s %s %s", ts, term.Red("CONFLICT"), ev.Message)
	case model.EventNewDevice:
		return fmt.Sprintf("%s %s %s", ts, term.Green("NEW     "), ev.Message)
	case model.EventOffline:
		return fmt.Sprintf("%s %s %s", ts, term.Dim("OFFLINE "), ev.Message)
	case model.EventOnline:
		return fmt.Sprintf("%s %s %s", ts, term.Cyan("ONLINE  "), ev.Message)
	case model.EventIPChange:
		return fmt.Sprintf("%s %s %s", ts, term.Yellow("IP      "), ev.Message)
	default:
		return fmt.Sprintf("%s %-8s %s", ts, ev.Kind, ev.Message)
	}
}
