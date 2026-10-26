package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sethrichar/netscout"
	"github.com/sethrichar/netscout/internal/export"
)

var (
	exportFormat string
	exportWhat   string
	exportOut    string
	importSubnet string
	importAuto   bool
	importDry    bool
)

var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export devices and the IP plan as CSV or JSON",
	Long: `Write the inventory to stdout (or --out).

  --format json            everything: subnets, reservations, devices (re-importable)
  --format csv             devices (default) or --what reservations for the IP plan`,
	Example: `  netscout export --json > show.json
  netscout export --csv --what reservations > ip-plan.csv
  netscout export --csv --out devices.csv`,
	RunE: func(cmd *cobra.Command, args []string) error {
		_, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		var w io.Writer = os.Stdout
		if exportOut != "" {
			f, err := os.Create(exportOut)
			if err != nil {
				return fmt.Errorf("creating %s: %w", exportOut, err)
			}
			defer f.Close()
			w = f
		}
		devs, err := st.ListDevices()
		if err != nil {
			return err
		}
		subnets, err := st.ListSubnets()
		if err != nil {
			return err
		}
		res, err := st.ListReservations(0)
		if err != nil {
			return err
		}
		switch strings.ToLower(exportFormat) {
		case "json":
			return export.WriteJSON(w, export.Snapshot{Version: netscout.Version(), Subnets: subnets, Reservations: res, Devices: devs})
		case "csv":
			switch exportWhat {
			case "", "devices":
				return export.WriteDevicesCSV(w, devs)
			case "reservations", "plan":
				return export.WriteReservationsCSV(w, subnets, res)
			default:
				return fmt.Errorf("--what must be devices or reservations")
			}
		default:
			return fmt.Errorf("--format must be csv or json")
		}
	},
}

var importCmd = &cobra.Command{
	Use:   "import <file>",
	Short: "Import an IP plan (CSV) or a netscout JSON export",
	Long: `Load reservations (and device labels) from a file.

CSV: any column order; headers are matched loosely — ip/address, mac,
name/label/device/hostname, notes/comments, subnet/cidr, tags, vlan. Headerless
files are guessed column by column. Rows are placed into the registered subnet
containing their IP; use --subnet <cidr> for rows that fit none, or
--auto-subnets to create /24s as needed.

JSON: the output of "netscout export --json" (subnets, reservations, labels).`,
	Example: `  netscout import client-ip-sheet.csv --subnet 10.0.0.0/24
  netscout import show.json
  netscout import plan.csv --dry-run`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := os.Open(args[0])
		if err != nil {
			return err
		}
		defer f.Close()
		imp, err := export.Parse(f)
		if err != nil {
			return err
		}
		_, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		rep, err := export.Apply(st, imp, export.ApplyOptions{DefaultSubnet: importSubnet, AutoSubnets: importAuto, DryRun: importDry})
		if err != nil {
			return err
		}
		prefix := ""
		if importDry {
			prefix = "[dry run] "
		}
		if imp.DevicesOnly {
			fmt.Fprintln(os.Stderr, "note: this is a netscout devices export; importing labels/notes/tags only (no reservations)")
		}
		fmt.Printf("%s%d rows read: %d reservations written, %d devices labelled", prefix, len(imp.Rows), rep.ReservationsWritten, rep.DevicesLabelled)
		if len(rep.SubnetsCreated) > 0 {
			fmt.Printf(", subnets created: %s", strings.Join(rep.SubnetsCreated, " "))
		}
		fmt.Println()
		for _, s := range rep.Skipped {
			fmt.Fprintln(os.Stderr, "skipped", s)
		}
		if len(rep.Skipped) > 0 {
			return fmt.Errorf("%d rows skipped", len(rep.Skipped))
		}
		return nil
	},
}

func init() {
	exportCmd.Flags().StringVar(&exportFormat, "format", "csv", "csv or json")
	exportCmd.Flags().StringVar(&exportWhat, "what", "devices", "csv content: devices or reservations")
	exportCmd.Flags().StringVarP(&exportOut, "out", "o", "", "write to a file instead of stdout")
	exportCmd.Flags().Bool("json", false, "shorthand for --format json")
	exportCmd.Flags().Bool("csv", false, "shorthand for --format csv")
	exportCmd.PreRun = func(cmd *cobra.Command, args []string) {
		if j, _ := cmd.Flags().GetBool("json"); j {
			exportFormat = "json"
		}
		if c, _ := cmd.Flags().GetBool("csv"); c {
			exportFormat = "csv"
		}
	}
	importCmd.Flags().StringVar(&importSubnet, "subnet", "", "subnet (CIDR) for rows that fit no registered subnet")
	importCmd.Flags().BoolVar(&importAuto, "auto-subnets", false, "create a /24 for any row that fits no subnet")
	importCmd.Flags().BoolVar(&importDry, "dry-run", false, "report what would change without writing")
	rootCmd.AddCommand(exportCmd, importCmd)
}
