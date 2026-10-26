package cli

import (
	"fmt"
	"log"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/sethrichar/netscout/internal/capture"
	"github.com/sethrichar/netscout/internal/engine"
	"github.com/sethrichar/netscout/internal/model"
	"github.com/sethrichar/netscout/internal/oui"
	"github.com/sethrichar/netscout/internal/scan"
	"github.com/sethrichar/netscout/internal/term"
)

var (
	scanIface  string
	scanICMP   bool
	scanRate   int
	scanSettle time.Duration
	scanPasses int
	scanNoSave bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [cidr]",
	Short: "Actively sweep a subnet with ARP (and optionally ICMP) and list what answers",
	Long: `Send an ARP request to every address in the subnet (default: the interface's
own subnet) and report every host that answers, with vendor. ARP wakes up gear
that ignores ping — Dante, AES67, embedded controllers. Results are saved to
the device database unless --no-save is given.

Requires capture privileges (sudo on macOS, Npcap on Windows).`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := log.New(os.Stderr, "", log.Ltime)
		iface, err := capture.FindInterface(scanIface)
		if err != nil {
			return fmt.Errorf("%w\n%s", err, capture.PrivilegeHint(err))
		}
		cidr := ""
		if len(args) == 1 {
			cidr = args[0]
		} else if cidr = scan.DefaultCIDR(iface); cidr == "" {
			return fmt.Errorf("interface %s has no IPv4 subnet; pass a CIDR", iface.Name)
		}
		if hosts, _, err := scan.Hosts(cidr); err == nil && len(hosts) > 4096 {
			fmt.Fprintf(os.Stderr, "note: %s is %d addresses; at %d/s with %d passes this takes about %s\n",
				cidr, len(hosts), scanRate, scanPasses, (time.Duration(len(hosts)*scanPasses) * time.Second / time.Duration(scanRate)).Round(time.Second))
		}

		var observe func(model.Observation)
		var eng *engine.Engine
		var vendors engine.VendorLookup
		dir, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		db, err := oui.Load(dir)
		if err == nil {
			vendors = db
		}
		if !scanNoSave {
			eng, err = engine.New(st, engine.Options{Interface: iface.Name, LocalNets: iface.LocalNets(), SelfMAC: iface.MAC, Vendors: vendors, Logger: logger})
			if err != nil {
				return err
			}
			observe = eng.Observe
		}

		ctx, cancel := signalContext()
		defer cancel()
		fmt.Fprintf(os.Stderr, "sweeping %s on %s (%s)…\n", cidr, iface.Name, iface.Label())
		start := time.Now()
		results, err := scan.Run(ctx, iface, cidr, scan.Options{Rate: scanRate, Settle: scanSettle, ICMP: scanICMP, Passes: scanPasses}, observe)
		if err != nil {
			if hint := capture.PrivilegeHint(err); hint != "" {
				return fmt.Errorf("%w\n%s", err, hint)
			}
			if len(results) == 0 {
				return err
			}
			logger.Printf("warning: %v", err)
		}
		if eng != nil {
			eng.Emit(model.Event{Kind: model.EventScan, Message: fmt.Sprintf("scan of %s found %d hosts", cidr, len(results)), Details: map[string]string{"cidr": cidr}})
			eng.Close()
		}

		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "IP\tMAC\tVENDOR\tLABEL / HOST")
		for _, r := range results {
			vendor, label := "", ""
			if db != nil {
				if e, ok := db.Find(r.MAC); ok {
					vendor = e.Long
				} else if model.IsRandomizedMAC(r.MAC) {
					vendor = term.Dim("randomized")
				}
			}
			if eng != nil {
				if d, ok := eng.Device(r.MAC); ok {
					label = d.Label
					if label == "" {
						label = d.Hostname
					}
				}
			}
			if r.MAC == iface.MAC {
				label = "(this machine)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.IP, r.MAC, vendor, label)
		}
		tw.Flush()
		fmt.Fprintf(os.Stderr, "%d hosts answered in %s\n", len(results), time.Since(start).Round(time.Millisecond))
		return nil
	},
}

func init() {
	scanCmd.Flags().StringVarP(&scanIface, "iface", "i", "", "interface to scan from (default: default-route interface)")
	scanCmd.Flags().BoolVar(&scanICMP, "icmp", false, "also send ICMP echo requests")
	scanCmd.Flags().IntVar(&scanRate, "rate", 250, "probes per second")
	scanCmd.Flags().IntVar(&scanPasses, "passes", 2, "number of ARP sweeps (repeat catches sleepy hosts)")
	scanCmd.Flags().DurationVar(&scanSettle, "settle", 2*time.Second, "how long to listen after the last probe")
	scanCmd.Flags().BoolVar(&scanNoSave, "no-save", false, "don't record results in the device database")
	rootCmd.AddCommand(scanCmd)
}
