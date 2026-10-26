package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/sethrichar/netscout/internal/ipam"
	"github.com/sethrichar/netscout/internal/model"
	"github.com/sethrichar/netscout/internal/store"
	"github.com/sethrichar/netscout/internal/term"
)

var (
	subnetName    string
	subnetVLAN    int
	subnetGateway string
	subnetNotes   string
	subnetAll     bool
	subnetJSON    bool
	subnetOnly    []string
	subnetWindow  time.Duration
)

var subnetCmd = &cobra.Command{
	Use:   "subnet",
	Short: "Manage subnets (IPAM)",
}

var subnetAddCmd = &cobra.Command{
	Use:     "add <cidr>",
	Short:   "Register a subnet",
	Example: `  netscout subnet add 10.0.0.0/24 --name "Dante primary" --vlan 10 --gateway 10.0.0.1`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		sn, err := st.AddSubnet(model.Subnet{CIDR: args[0], Name: subnetName, VLAN: subnetVLAN, Gateway: subnetGateway, Notes: subnetNotes})
		if err != nil {
			return err
		}
		fmt.Printf("added subnet #%d %s %s\n", sn.ID, sn.CIDR, sn.Name)
		return nil
	},
}

var subnetSetCmd = &cobra.Command{
	Use:   "set <cidr|name|id>",
	Short: "Update a subnet's name, VLAN, gateway or notes",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		sn, err := mustSubnet(st, args[0])
		if err != nil {
			return err
		}
		if cmd.Flags().Changed("name") {
			sn.Name = subnetName
		}
		if cmd.Flags().Changed("vlan") {
			sn.VLAN = subnetVLAN
		}
		if cmd.Flags().Changed("gateway") {
			sn.Gateway = subnetGateway
		}
		if cmd.Flags().Changed("notes") {
			sn.Notes = subnetNotes
		}
		if err := st.UpdateSubnet(*sn); err != nil {
			return err
		}
		fmt.Printf("updated subnet #%d %s %s\n", sn.ID, sn.CIDR, sn.Name)
		return nil
	},
}

var subnetListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List subnets with usage summary",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		subnets, err := st.ListSubnets()
		if err != nil {
			return err
		}
		if len(subnets) == 0 {
			fmt.Println("no subnets yet — add one with `netscout subnet add <cidr>`")
			return nil
		}
		bindings, devs, err := loadBindings(st, subnetWindow)
		if err != nil {
			return err
		}
		type row struct {
			model.Subnet
			Summary ipam.Summary `json:"summary"`
		}
		var rows []row
		for _, sn := range subnets {
			res, _ := st.ListReservations(sn.ID)
			_, sum, err := ipam.Compute(sn, res, bindings, devs, ipam.Options{})
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: subnet #%d %s: %v\n", sn.ID, sn.CIDR, err)
			}
			rows = append(rows, row{sn, sum})
		}
		if subnetJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(rows)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tCIDR\tNAME\tVLAN\tGATEWAY\tUSED/TOTAL\tRESERVED\tMATCH\tMISMATCH\tCONFLICT\tONLINE")
		for _, r := range rows {
			vlan := ""
			if r.VLAN != 0 {
				vlan = fmt.Sprint(r.VLAN)
			}
			used := r.Summary.InUse + r.Summary.Match + r.Summary.Mismatch + r.Summary.Conflict
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%d/%d\t%d\t%d\t%s\t%s\t%d\n", r.ID, r.CIDR, r.Name, vlan, r.Gateway, used, r.Summary.Total,
				r.Summary.Reserved, r.Summary.Match, warnIf(r.Summary.Mismatch), warnIf(r.Summary.Conflict), r.Summary.Online)
		}
		tw.Flush()
		return nil
	},
}

var subnetShowCmd = &cobra.Command{
	Use:   "show <cidr|name|id>",
	Short: "Show every address in a subnet with its status",
	Long: `Show the plan (reservations) against reality (observed devices) for a subnet.

Statuses:
  free       nothing planned, nothing seen
  reserved   planned, not seen on the network
  in-use     seen, nothing planned
  match      reserved and the reserved MAC is using it
  mismatch   reserved for one MAC but another is using it, or the reserved
             MAC is sitting on a different address
  conflict   two MACs are using the address right now

Free addresses are hidden unless --all is given.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		sn, err := mustSubnet(st, args[0])
		if err != nil {
			return err
		}
		res, err := st.ListReservations(sn.ID)
		if err != nil {
			return err
		}
		bindings, devs, err := loadBindings(st, subnetWindow)
		if err != nil {
			return err
		}
		addrs, sum, err := ipam.Compute(*sn, res, bindings, devs, ipam.Options{})
		if err != nil {
			return err
		}
		if len(subnetOnly) > 0 {
			var sts []ipam.Status
			for _, s := range subnetOnly {
				sts = append(sts, ipam.Status(s))
			}
			addrs = ipam.Filter(addrs, sts...)
		} else if !subnetAll {
			addrs = ipam.Filter(addrs, ipam.StatusReserved, ipam.StatusInUse, ipam.StatusMatch, ipam.StatusMismatch, ipam.StatusConflict)
		}
		if subnetJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]any{"subnet": sn, "summary": sum, "addresses": addrs})
		}
		title := sn.CIDR
		if sn.Name != "" {
			title += "  " + sn.Name
		}
		if sn.VLAN != 0 {
			title += fmt.Sprintf("  vlan %d", sn.VLAN)
		}
		fmt.Println(term.Bold(title))
		fmt.Printf("%d addresses: %d free · %d reserved · %d in-use · %s match · %s mismatch · %s conflict · %d online\n\n",
			sum.Total, sum.Free, sum.Reserved, sum.InUse, term.Green(fmt.Sprint(sum.Match)), warnIf(sum.Mismatch), warnIf(sum.Conflict), sum.Online)

		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, " \tIP\tSTATUS\tPLANNED\tACTUAL\tVENDOR / HOST\tNOTE")
		for _, a := range addrs {
			planned := ""
			if a.Reservation != nil {
				planned = a.Reservation.Label
				if a.Reservation.MAC != "" {
					planned = strings.TrimSpace(planned + " " + term.Dim(a.Reservation.MAC))
				}
			}
			actual := strings.Join(a.MACs, " + ")
			who := ""
			for _, d := range a.Devices {
				name := d.Label
				if name == "" {
					name = d.Hostname
				}
				v := d.Vendor
				if v == "" && d.Randomized {
					v = "randomized"
				}
				if name != "" {
					who = strings.TrimSpace(who + " " + name)
				} else if v != "" {
					who = strings.TrimSpace(who + " " + v)
				}
			}
			mark := " "
			if a.Online {
				mark = "●"
			}
			if a.Gateway {
				mark = "G"
			}
			line := fmt.Sprintf("%s\t%s\t%s\t%s\t%s\t%s\t%s", mark, a.IP, statusColor(a.Status), planned, actual, term.Truncate(who, 30), a.Note)
			fmt.Fprintln(tw, line)
		}
		tw.Flush()
		if next := ipam.NextFree(addrs, ""); next != "" && subnetAll {
			fmt.Printf("\nnext free: %s\n", next)
		}
		return nil
	},
}

var subnetRmCmd = &cobra.Command{
	Use:   "rm <cidr|name|id>",
	Short: "Delete a subnet and its reservations",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		sn, err := mustSubnet(st, args[0])
		if err != nil {
			return err
		}
		if err := st.DeleteSubnet(sn.ID); err != nil {
			return err
		}
		fmt.Printf("deleted subnet #%d %s\n", sn.ID, sn.CIDR)
		return nil
	},
}

var subnetFreeCmd = &cobra.Command{
	Use:   "free <cidr|name|id> [count]",
	Short: "Print the next free address(es) in a subnet",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		sn, err := mustSubnet(st, args[0])
		if err != nil {
			return err
		}
		n := 1
		if len(args) == 2 {
			fmt.Sscanf(args[1], "%d", &n)
		}
		res, _ := st.ListReservations(sn.ID)
		bindings, devs, err := loadBindings(st, subnetWindow)
		if err != nil {
			return err
		}
		addrs, _, err := ipam.Compute(*sn, res, bindings, devs, ipam.Options{})
		if err != nil {
			return err
		}
		start := ""
		for i := 0; i < n; i++ {
			next := ipam.NextFree(addrs, start)
			if next == "" {
				break
			}
			fmt.Println(next)
			start = next
		}
		return nil
	},
}

func mustSubnet(st *store.Store, ref string) (*model.Subnet, error) {
	sn, err := st.FindSubnet(ref)
	if err != nil {
		return nil, err
	}
	if sn == nil {
		return nil, fmt.Errorf("subnet %q not found (see `netscout subnet list`)", ref)
	}
	return sn, nil
}

// loadBindings pulls every IP binding and device from the store and marks
// which bindings are current.
func loadBindings(st *store.Store, window time.Duration) ([]ipam.Binding, []model.Device, error) {
	raw, err := st.ListBindings()
	if err != nil {
		return nil, nil, err
	}
	devs, err := st.ListDevices()
	if err != nil {
		return nil, nil, err
	}
	bindings := make([]ipam.Binding, len(raw))
	for i, b := range raw {
		bindings[i] = ipam.Binding{IP: b.IP, MAC: b.MAC, LastSeen: b.LastSeen}
	}
	if window <= 0 {
		window = time.Hour
	}
	return ipam.MarkCurrent(bindings, time.Now(), window), devs, nil
}

func statusColor(s ipam.Status) string {
	switch s {
	case ipam.StatusMatch:
		return term.Green(string(s))
	case ipam.StatusMismatch:
		return term.Yellow(string(s))
	case ipam.StatusConflict:
		return term.Red(string(s))
	case ipam.StatusReserved:
		return term.Cyan(string(s))
	case ipam.StatusFree:
		return term.Dim(string(s))
	default:
		return string(s)
	}
}

func warnIf(n int) string {
	if n > 0 {
		return term.Red(fmt.Sprint(n))
	}
	return fmt.Sprint(n)
}

func init() {
	for _, c := range []*cobra.Command{subnetAddCmd, subnetSetCmd} {
		c.Flags().StringVar(&subnetName, "name", "", "friendly name")
		c.Flags().IntVar(&subnetVLAN, "vlan", 0, "VLAN tag")
		c.Flags().StringVar(&subnetGateway, "gateway", "", "gateway address")
		c.Flags().StringVar(&subnetNotes, "notes", "", "notes")
	}
	for _, c := range []*cobra.Command{subnetListCmd, subnetShowCmd, subnetFreeCmd} {
		c.Flags().DurationVar(&subnetWindow, "window", time.Hour, "bindings seen within this window count as current")
	}
	subnetListCmd.Flags().BoolVar(&subnetJSON, "json", false, "output JSON")
	subnetShowCmd.Flags().BoolVarP(&subnetAll, "all", "a", false, "include free addresses")
	subnetShowCmd.Flags().BoolVar(&subnetJSON, "json", false, "output JSON")
	subnetShowCmd.Flags().StringSliceVar(&subnetOnly, "status", nil, "only these statuses (free,reserved,in-use,match,mismatch,conflict)")
	subnetCmd.AddCommand(subnetAddCmd, subnetSetCmd, subnetListCmd, subnetShowCmd, subnetRmCmd, subnetFreeCmd)
	rootCmd.AddCommand(subnetCmd)
}
