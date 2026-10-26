package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/sethrichar/netscout/internal/model"
)

var (
	reserveLabel  string
	reserveNotes  string
	reserveSubnet string
)

var reserveCmd = &cobra.Command{
	Use:   "reserve <ip> [mac]",
	Short: "Reserve an IP for a MAC (or just label it) in its subnet",
	Long: `Record that an address is assigned to a device. The subnet is found
automatically from the registered subnets; pass --subnet to disambiguate or
to create one on the fly (CIDR). The MAC is optional: a reservation without one
is a labelled placeholder ("spare for lighting").`,
	Example: `  netscout reserve 10.0.0.20 00:1d:c1:12:34:56 --label "Dante — Yamaha CL5 primary"
  netscout reserve 10.0.0.50 --label "spare for lighting"
  netscout reserve 192.168.7.5 --subnet 192.168.7.0/24 --label "Projector L"`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		ip := args[0]
		mac := ""
		if len(args) == 2 {
			mac, err = model.NormalizeMAC(args[1])
			if err != nil {
				return err
			}
		}
		var sn *model.Subnet
		if reserveSubnet != "" {
			sn, err = st.FindSubnet(reserveSubnet)
			if err != nil {
				return err
			}
			if sn == nil {
				created, err := st.AddSubnet(model.Subnet{CIDR: reserveSubnet})
				if err != nil {
					return fmt.Errorf("--subnet %q is not a known subnet and not a valid CIDR: %w", reserveSubnet, err)
				}
				sn = &created
				fmt.Fprintf(os.Stderr, "created subnet %s\n", sn.CIDR)
			}
		} else {
			sn, err = st.SubnetContaining(ip)
			if err != nil {
				return err
			}
			if sn == nil {
				return fmt.Errorf("%s is in no registered subnet; run `netscout subnet add <cidr>` or pass --subnet <cidr>", ip)
			}
		}
		// Keep an existing label when only the MAC is being added.
		label, notes := reserveLabel, reserveNotes
		if existing, _ := st.ListReservations(sn.ID); existing != nil {
			for _, r := range existing {
				if r.IP == ip {
					if !cmd.Flags().Changed("label") {
						label = r.Label
					}
					if !cmd.Flags().Changed("notes") {
						notes = r.Notes
					}
					if mac == "" {
						mac = r.MAC
					}
				}
			}
		}
		r, err := st.UpsertReservation(model.Reservation{SubnetID: sn.ID, IP: ip, MAC: mac, Label: label, Notes: notes})
		if err != nil {
			return err
		}
		fmt.Printf("reserved %s → %s %q in %s\n", r.IP, orDash(r.MAC), r.Label, sn.CIDR)
		return nil
	},
}

var unreserveCmd = &cobra.Command{
	Use:   "unreserve <ip>",
	Short: "Remove a reservation",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		sn, err := st.SubnetContaining(args[0])
		if err != nil {
			return err
		}
		if sn == nil {
			return fmt.Errorf("%s is in no registered subnet", args[0])
		}
		if err := st.DeleteReservation(sn.ID, args[0]); err != nil {
			return err
		}
		fmt.Printf("removed reservation for %s\n", args[0])
		return nil
	},
}

var reservationsCmd = &cobra.Command{
	Use:   "reservations [subnet]",
	Short: "List reservations",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		var id int64
		if len(args) == 1 {
			sn, err := mustSubnet(st, args[0])
			if err != nil {
				return err
			}
			id = sn.ID
		}
		res, err := st.ListReservations(id)
		if err != nil {
			return err
		}
		subnets, _ := st.ListSubnets()
		cidr := map[int64]string{}
		for _, s := range subnets {
			cidr[s.ID] = s.CIDR
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "SUBNET\tIP\tMAC\tLABEL\tNOTES")
		for _, r := range res {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", cidr[r.SubnetID], r.IP, orDash(r.MAC), r.Label, r.Notes)
		}
		tw.Flush()
		return nil
	},
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func init() {
	reserveCmd.Flags().StringVar(&reserveLabel, "label", "", "what this address is for")
	reserveCmd.Flags().StringVar(&reserveNotes, "notes", "", "notes")
	reserveCmd.Flags().StringVar(&reserveSubnet, "subnet", "", "subnet (CIDR, name or id); created if it is a new CIDR")
	rootCmd.AddCommand(reserveCmd, unreserveCmd, reservationsCmd)
}
