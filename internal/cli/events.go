package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sethrichar/netscout/internal/store"
)

var (
	eventsKind  string
	eventsLimit int
	eventsJSON  bool
)

var eventsCmd = &cobra.Command{
	Use:   "events",
	Short: "Show recorded events (conflicts, new devices, offline/online)",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		evs, err := st.ListEvents(store.EventFilter{Kind: eventsKind, Limit: eventsLimit})
		if err != nil {
			return err
		}
		if eventsJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(evs)
		}
		// Oldest first reads naturally in a terminal.
		for i := len(evs) - 1; i >= 0; i-- {
			e := evs[i]
			fmt.Printf("%s  %s\n", e.Time.Local().Format("2006-01-02"), eventLine(e))
		}
		return nil
	},
}

func init() {
	eventsCmd.Flags().StringVar(&eventsKind, "kind", "", "filter by kind (conflict, new_device, online, offline, ip_change, hostname, scan)")
	eventsCmd.Flags().IntVarP(&eventsLimit, "limit", "n", 50, "maximum events")
	eventsCmd.Flags().BoolVar(&eventsJSON, "json", false, "output JSON")
	rootCmd.AddCommand(eventsCmd)
}
