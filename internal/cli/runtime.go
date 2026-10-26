package cli

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sethrichar/netscout/internal/arptable"
	"github.com/sethrichar/netscout/internal/capture"
	"github.com/sethrichar/netscout/internal/config"
	"github.com/sethrichar/netscout/internal/engine"
	"github.com/sethrichar/netscout/internal/model"
	"github.com/sethrichar/netscout/internal/oui"
	"github.com/sethrichar/netscout/internal/parse"
	"github.com/sethrichar/netscout/internal/store"
	"github.com/sethrichar/netscout/internal/term"
)

// rtime bundles everything a long-running command (sniff, ui) needs.
type rtime struct {
	dataDir string
	store   *store.Store
	engine  *engine.Engine
	oui     *oui.DB
	iface   capture.Interface
	session *capture.Session // nil when running in passive fallback mode
	passive bool
	hint    string // privilege hint shown when passive
	logger  *log.Logger
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
	rt := &rtime{dataDir: dir, store: st, oui: db, logger: logger}

	rt.iface, err = capture.FindInterface(ifaceName)
	if err != nil {
		if hint := capture.PrivilegeHint(err); hint != "" {
			// Can't even enumerate interfaces (Windows without Npcap).
			rt.passive = true
			rt.hint = hint
			rt.iface = capture.Interface{Name: ifaceName}
		} else {
			st.Close()
			return nil, err
		}
	}
	if !rt.passive {
		sess, err := capture.Open(rt.iface, capture.Options{Promisc: true, BPF: bpf})
		if err != nil {
			hint := capture.PrivilegeHint(err)
			if hint == "" {
				st.Close()
				return nil, err
			}
			rt.passive = true
			rt.hint = fmt.Sprintf("%v\n\n%s", err, hint)
		} else {
			rt.session = sess
		}
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
	_ = st.SetMeta("last_interface", rt.iface.Name)
	return rt, nil
}

func (rt *rtime) close() {
	if rt.session != nil {
		rt.session.Close()
	}
	if rt.store != nil {
		rt.store.Close()
	}
}

// run drives capture (or passive polling) and the engine until ctx ends, then
// closes the engine so the final state (everything offline) is persisted.
func (rt *rtime) run(ctx context.Context) {
	defer rt.engine.Close()
	go rt.engine.Run(ctx)
	// Seed from the OS ARP cache regardless of mode: it's free information.
	rt.pollARPTable()
	if rt.session == nil {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				rt.pollARPTable()
			}
		}
	}
	for pkt := range rt.session.Packets(ctx) {
		rt.engine.CountPacket()
		for _, o := range parse.Packet(pkt, rt.iface.Name) {
			rt.engine.Observe(o)
		}
	}
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

func (rt *rtime) pollARPTable() {
	entries, err := arptable.Read()
	if err != nil {
		rt.logger.Printf("arp table: %v", err)
		return
	}
	for _, o := range arptable.Observations(entries, rt.iface.Name) {
		if !rt.passive && !ifaceMatches(o.Interface, rt.iface) {
			continue
		}
		rt.engine.Observe(o)
	}
}

func ifaceMatches(name string, iface capture.Interface) bool {
	return name == "" || name == iface.Name || name == iface.FriendlyName || (iface.FirstIPv4() != nil && name == iface.FirstIPv4().String())
}

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
