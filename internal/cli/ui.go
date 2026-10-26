package cli

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sethrichar/netscout/internal/capture"
	"github.com/sethrichar/netscout/internal/oui"
	"github.com/sethrichar/netscout/internal/term"
	"github.com/sethrichar/netscout/internal/web"
)

var (
	uiIface  string
	uiPort   int
	uiNoOpen bool
	uiScan   bool
	uiEvery  time.Duration
)

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Capture and open the live web UI in your browser (default command)",
	Long: `Start capturing on an interface and serve the netscout web UI on 127.0.0.1.
The browser opens automatically unless --no-open is given. Everything the CLI
can do — live table, subnets & reservations, conflicts, import/export, vendor
DB update — is available in the UI.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := log.New(os.Stderr, "", log.Ltime)
		rt, err := newRuntime(uiIface, sniffOnlineWindow, sniffConflictWindow, "", logger)
		if err != nil {
			return err
		}
		defer rt.close()

		ctx, cancel := signalContext()
		defer cancel()
		rt.start(ctx)
		go rt.scanScheduler(ctx)
		if uiEvery > 0 {
			rt.setScanInterval(ctx, uiEvery, "")
		}
		if uiScan {
			if err := rt.startScan(ctx, ""); err != nil {
				logger.Printf("scan: %v", err)
			}
		}

		srv := web.New(rt.engine, rt.store, &controller{rt: rt}, logger)
		url, err := srv.Listen(web.Options{Port: uiPort})
		if err != nil {
			return err
		}
		fmt.Printf("netscout UI → %s\n", term.Bold(url))
		if rt.passive {
			fmt.Fprintln(os.Stderr, term.Yellow("capture unavailable — running in passive mode"))
			fmt.Fprintln(os.Stderr, rt.hint)
		}
		fmt.Println(term.Dim("Ctrl-C to stop"))
		if !uiNoOpen {
			if err := web.OpenBrowser(url); err != nil {
				logger.Printf("%v (open %s manually)", err, url)
			}
		}
		err = srv.Serve(ctx)
		rt.stop()
		return err
	},
}

// controller adapts the runtime to what the web server needs.
type controller struct{ rt *rtime }

func (c *controller) Status() web.CaptureStatus {
	rt := c.rt
	rt.mu.Lock()
	st := web.CaptureStatus{
		Interface: rt.iface, Passive: rt.passive, Hint: rt.hint,
		DataDir: rt.dataDir, StartedAt: rt.started, OnlineAfter: rt.engine.Options().OnlineWindow,
	}
	if rt.session != nil {
		s := rt.session.Stats()
		st.Received, st.Dropped = s.Received, s.PcapDropped+s.QueueDropped
	}
	if rt.oui != nil {
		st.OUISource, st.OUIEntries = rt.oui.Source, rt.oui.Len()
		if rt.oui.Source != "embedded" {
			st.OUIUpdated = oui.UpdatedAt(rt.dataDir)
		}
	}
	rt.mu.Unlock()
	st.Scanning, st.LastScan, st.ScanEvery, st.ScanCIDR = rt.scanState()
	return st
}

func (c *controller) Interfaces() ([]capture.Interface, error) { return capture.ListInterfaces() }
func (c *controller) SwitchInterface(name string) error        { return c.rt.switchInterface(name) }
func (c *controller) Scan(ctx context.Context, cidr string) error {
	return c.rt.startScan(c.rt.appCtx, cidr)
}
func (c *controller) SetScanInterval(ctx context.Context, every time.Duration, cidr string) {
	c.rt.setScanInterval(c.rt.appCtx, every, cidr)
}
func (c *controller) UpdateOUI(ctx context.Context) (oui.UpdateResult, error) {
	return c.rt.updateOUI(ctx)
}
func (c *controller) OUI() *oui.DB {
	c.rt.mu.Lock()
	defer c.rt.mu.Unlock()
	return c.rt.oui
}

func init() {
	uiCmd.Flags().StringVarP(&uiIface, "iface", "i", "", "interface to capture on (default: last used, else default route)")
	uiCmd.Flags().IntVarP(&uiPort, "port", "p", 0, "port on 127.0.0.1 (default: random free port)")
	uiCmd.Flags().BoolVar(&uiNoOpen, "no-open", false, "don't open the browser")
	uiCmd.Flags().BoolVar(&uiScan, "scan", false, "ARP-sweep the local subnet on startup")
	uiCmd.Flags().DurationVar(&uiEvery, "scan-every", 0, "repeat the sweep at this interval (e.g. 5m); 0 = off")
	uiCmd.Flags().DurationVar(&sniffOnlineWindow, "online-window", 5*time.Minute, "mark devices offline after this much silence")
	uiCmd.Flags().DurationVar(&sniffConflictWindow, "conflict-window", 2*time.Minute, "same IP from two MACs within this window is a conflict")
	rootCmd.AddCommand(uiCmd)
	// Running the binary with no arguments (double-click) opens the UI.
	rootCmd.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fmt.Errorf("unknown command %q; see --help", args[0])
		}
		return uiCmd.RunE(uiCmd, nil)
	}
}
