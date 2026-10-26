package cli

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/sethrichar/netscout/internal/model"
	nterm "github.com/sethrichar/netscout/internal/term"
)

var (
	sniffIface          string
	sniffBPF            string
	sniffNoTUI          bool
	sniffOnlineWindow   time.Duration
	sniffConflictWindow time.Duration
	sniffScan           bool
	sniffScanCIDR       string
)

var sniffCmd = &cobra.Command{
	Use:   "sniff",
	Short: "Passively capture on an interface and show a live device table",
	Long: `Capture ARP, DHCP, mDNS/Bonjour, LLDP/CDP and IPv4 traffic on an interface and
maintain a live table of devices (IP, MAC, vendor, hostname, last seen).
Observations are saved to the database so later commands (devices, subnet
show, export) can use them.

If packet capture is not permitted, netscout falls back to polling the OS ARP
table and explains how to enable capture.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := log.New(os.Stderr, "", log.Ltime)
		rt, err := newRuntime(sniffIface, sniffOnlineWindow, sniffConflictWindow, sniffBPF, logger)
		if err != nil {
			return err
		}
		defer rt.close()
		if rt.passive {
			fmt.Fprintln(os.Stderr, nterm.Yellow("capture unavailable — running in passive mode"))
			fmt.Fprintln(os.Stderr, rt.hint)
		}

		ctx, cancel := signalContext()
		defer cancel()

		rt.start(ctx)
		if sniffScan {
			if err := rt.startScan(ctx, sniffScanCIDR); err != nil {
				logger.Printf("scan: %v", err)
			}
		}

		useTUI := !sniffNoTUI && nterm.IsTTY()
		if useTUI {
			nterm.EnableVT()
			err := runTUI(ctx, rt)
			cancel()
			rt.stop()
			return err
		}
		// Log mode: stream events as lines.
		events, unsub := rt.engine.Subscribe()
		defer unsub()
		go func() {
			for ev := range events {
				if ev.Details["silent"] == "true" {
					continue
				}
				fmt.Println(eventLine(ev))
			}
		}()
		<-ctx.Done()
		rt.stop()
		return nil
	},
}

func runTUI(ctx interface{ Done() <-chan struct{} }, rt *rtime) error {
	events, unsub := rt.engine.Subscribe()
	defer unsub()
	var recent []model.Event
	started := time.Now()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	draw := func() {
		width, _, err := term.GetSize(int(os.Stdout.Fd()))
		if err != nil || width <= 0 {
			width = 120
		}
		fmt.Print(nterm.ClearScreen)
		fmt.Print(renderTable(rt, started, recent, width))
	}
	draw()
	for {
		select {
		case <-ctx.Done():
			fmt.Print(nterm.ClearScreen)
			total, _ := rt.engine.Counts()
			fmt.Printf("stopped. %d devices saved to %s\n", total, rt.dataDir)
			return nil
		case ev := <-events:
			if ev.Details["silent"] == "true" {
				continue
			}
			recent = append(recent, ev)
			if len(recent) > 6 {
				recent = recent[len(recent)-6:]
			}
			if ev.Kind == model.EventConflict {
				draw()
			}
		case <-tick.C:
			draw()
		}
	}
}

func init() {
	sniffCmd.Flags().StringVarP(&sniffIface, "iface", "i", "", "interface to capture on (default: default-route interface)")
	sniffCmd.Flags().StringVar(&sniffBPF, "filter", "", "extra BPF filter expression")
	sniffCmd.Flags().BoolVar(&sniffNoTUI, "no-tui", false, "print events as log lines instead of a live table")
	sniffCmd.Flags().DurationVar(&sniffOnlineWindow, "online-window", 5*time.Minute, "mark devices offline after this much silence")
	sniffCmd.Flags().DurationVar(&sniffConflictWindow, "conflict-window", 2*time.Minute, "same IP from two MACs within this window is a conflict")
	sniffCmd.Flags().BoolVar(&sniffScan, "scan", false, "ARP-sweep the local subnet first (twice), then keep listening")
	sniffCmd.Flags().StringVar(&sniffScanCIDR, "scan-cidr", "", "CIDR to sweep with --scan (default: the interface's subnet)")
	rootCmd.AddCommand(sniffCmd)
}
