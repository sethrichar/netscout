package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/sethrichar/netscout/internal/oui"
	"github.com/sethrichar/netscout/internal/term"
)

var (
	lookupJSON   bool
	lookupSearch bool
)

var lookupCmd = &cobra.Command{
	Use:   "lookup <mac|vendor> [...]",
	Short: "Look up the vendor for a MAC address (offline)",
	Long: `Resolve MAC addresses to vendors using the bundled Wireshark OUI database
(24-bit OUI, 28-bit MA-M and 36-bit MA-S blocks). Randomised / locally
administered addresses are flagged.

With --search the arguments are vendor names and every matching prefix is listed.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := dataDir()
		if err != nil {
			return err
		}
		db, err := oui.Load(dir)
		if err != nil {
			return err
		}
		if lookupSearch {
			for _, q := range args {
				hits := db.Search(q, 200)
				if lookupJSON {
					json.NewEncoder(os.Stdout).Encode(hits)
					continue
				}
				if len(hits) == 0 {
					fmt.Printf("%s: no vendors match\n", q)
					continue
				}
				tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
				for _, h := range hits {
					fmt.Fprintf(tw, "%s\t%s\t%s\n", h.Prefix, h.Short, h.Long)
				}
				tw.Flush()
			}
			return nil
		}
		var results []oui.Result
		for _, a := range args {
			r, err := db.Describe(a)
			if err != nil {
				return err
			}
			results = append(results, r)
		}
		if lookupJSON {
			return json.NewEncoder(os.Stdout).Encode(results)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		for _, r := range results {
			switch {
			case r.Found:
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.MAC, r.Vendor, term.Dim("("+r.Short+")"), term.Dim(r.Prefix))
			case r.Multicast:
				fmt.Fprintf(tw, "%s\t%s\n", r.MAC, term.Dim("multicast / broadcast address"))
			case r.Randomized:
				fmt.Fprintf(tw, "%s\t%s\n", r.MAC, term.Yellow("randomized / locally administered (phone private address, VM, container)"))
			default:
				fmt.Fprintf(tw, "%s\t%s\n", r.MAC, term.Dim("unknown vendor"))
			}
		}
		tw.Flush()
		if db.Source != "embedded" {
			fmt.Fprintln(os.Stderr, term.Dim("vendor data: "+db.Source))
		}
		return nil
	},
}

var updateOUICmd = &cobra.Command{
	Use:   "update-oui",
	Short: "Download the latest Wireshark vendor database into the data dir",
	Long: `Fetch the current Wireshark manuf file and store it in the data directory.
The bundled copy inside the binary stays as a fallback. Tries wireshark.org
first, then the GitHub mirror of the Wireshark source.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := dataDir()
		if err != nil {
			return err
		}
		before, _ := oui.Load(dir)
		fmt.Fprintf(os.Stderr, "current: %d entries (%s)\n", before.Len(), before.Source)
		res, err := oui.Update(cmd.Context(), dir, nil)
		if err != nil {
			return err
		}
		fmt.Printf("updated: %d entries from %s\n→ %s\n", res.Entries, res.Source, res.Path)
		return nil
	},
}

func init() {
	lookupCmd.Flags().BoolVar(&lookupJSON, "json", false, "output JSON")
	lookupCmd.Flags().BoolVarP(&lookupSearch, "search", "s", false, "search vendor names instead of looking up MACs")
	rootCmd.AddCommand(lookupCmd, updateOUICmd)
}
