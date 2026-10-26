package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/sethrichar/netscout/internal/capture"
)

var ifacesAll bool

var ifacesCmd = &cobra.Command{
	Use:     "ifaces",
	Aliases: []string{"interfaces", "if"},
	Short:   "List network interfaces (default route marked with *)",
	RunE: func(cmd *cobra.Command, args []string) error {
		ifaces, err := capture.ListInterfaces()
		if err != nil {
			return fmt.Errorf("%w\n%s", err, capture.PrivilegeHint(err))
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, " \tNAME\tDESCRIPTION\tIPV4\tMAC\tSTATE")
		shown := 0
		for _, i := range ifaces {
			if !ifacesAll && (i.Loopback || len(i.IPv4) == 0) {
				continue
			}
			mark := " "
			if i.Default {
				mark = "*"
			}
			state := "down"
			if i.Up {
				state = "up"
			}
			if i.Loopback {
				state += ",loopback"
			}
			desc := i.Description
			if desc == "" {
				desc = i.FriendlyName
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", mark, i.Name, desc, strings.Join(i.IPv4, ","), i.MAC, state)
			shown++
		}
		tw.Flush()
		if shown == 0 {
			fmt.Println("(no interfaces with addresses; use --all to show everything)")
		}
		return nil
	},
}

func init() {
	ifacesCmd.Flags().BoolVarP(&ifacesAll, "all", "a", false, "include loopback and down interfaces")
	rootCmd.AddCommand(ifacesCmd)
}
