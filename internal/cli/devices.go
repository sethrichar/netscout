package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/sethrichar/netscout/internal/engine"
	"github.com/sethrichar/netscout/internal/model"
	"github.com/sethrichar/netscout/internal/term"
)

var (
	devicesJSON   bool
	devicesOnline bool
	devicesFilter string
)

var devicesCmd = &cobra.Command{
	Use:   "devices [filter]",
	Short: "List devices recorded in the database",
	Long: `List every device netscout has seen, most recent first. An optional filter
matches IP, MAC, vendor, hostname, label or tag (case-insensitive).`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		devs, err := st.ListDevices()
		if err != nil {
			return err
		}
		filter := strings.ToLower(devicesFilter)
		if len(args) == 1 {
			filter = strings.ToLower(args[0])
		}
		var out []model.Device
		for _, d := range devs {
			if devicesOnline && !d.Online {
				continue
			}
			if filter != "" && !deviceMatches(d, filter) {
				continue
			}
			out = append(out, d)
		}
		engine.SortDevices(out)
		if devicesJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, " \tIP\tMAC\tVENDOR\tHOSTNAME\tLABEL\tTAGS\tLAST SEEN")
		for _, d := range out {
			state := " "
			if d.Online {
				state = "●"
			}
			if d.Attrs["conflict_ip"] != "" {
				state = "!"
			}
			vendor := d.Vendor
			if vendor == "" && d.Randomized {
				vendor = "(randomized)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", state, d.IP(), d.MAC, term.Truncate(vendor, 28), term.Truncate(d.Hostname, 24), term.Truncate(d.Label, 28), strings.Join(d.Tags, ","), lastSeen(d.LastSeen))
		}
		tw.Flush()
		fmt.Fprintf(os.Stderr, "%d devices\n", len(out))
		return nil
	},
}

func deviceMatches(d model.Device, q string) bool {
	hay := []string{d.MAC, d.Vendor, d.Hostname, d.Label, d.Notes, strings.Join(d.IPs, " "), strings.Join(d.Tags, " ")}
	for _, h := range hay {
		if strings.Contains(strings.ToLower(h), q) {
			return true
		}
	}
	return false
}

func lastSeen(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	if time.Since(t) < 24*time.Hour {
		return t.Local().Format("15:04:05") + " (" + ago(t) + ")"
	}
	return t.Local().Format("2006-01-02 15:04")
}

// --- device set / show / rm ---------------------------------------------------

var (
	devLabel     string
	devNotes     string
	devTags      []string
	devClearTags bool
	devAddTags   []string
	devRmTags    []string
)

var deviceCmd = &cobra.Command{
	Use:   "device",
	Short: "Inspect or annotate a single device",
}

var deviceShowCmd = &cobra.Command{
	Use:   "show <mac|ip>",
	Short: "Show everything known about a device, including recent observations",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		d, err := resolveDevice(st, args[0])
		if err != nil {
			return err
		}
		if devicesJSON {
			obs, _ := st.ListObservations(d.MAC, 50)
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]any{"device": d, "observations": obs})
		}
		fmt.Printf("%s  %s\n", term.Bold(d.MAC), vendorLine(*d))
		if d.Label != "" {
			fmt.Printf("  label:     %s\n", d.Label)
		}
		if d.Hostname != "" {
			fmt.Printf("  hostname:  %s\n", d.Hostname)
		}
		fmt.Printf("  ips:       %s\n", strings.Join(d.IPs, ", "))
		state := "offline"
		if d.Online {
			state = term.Green("online")
		}
		fmt.Printf("  state:     %s   first seen %s   last seen %s\n", state, d.FirstSeen.Local().Format("2006-01-02 15:04"), lastSeen(d.LastSeen))
		if len(d.Tags) > 0 {
			fmt.Printf("  tags:      %s\n", strings.Join(d.Tags, ", "))
		}
		if d.Notes != "" {
			fmt.Printf("  notes:     %s\n", d.Notes)
		}
		if d.Interface != "" {
			fmt.Printf("  interface: %s\n", d.Interface)
		}
		if len(d.Attrs) > 0 {
			fmt.Println("  facts:")
			keys := make([]string, 0, len(d.Attrs))
			for k := range d.Attrs {
				keys = append(keys, k)
			}
			sortStrings(keys)
			for _, k := range keys {
				fmt.Printf("    %-20s %s\n", k, d.Attrs[k])
			}
		}
		ips, _ := st.ListDeviceIPs(d.MAC)
		if len(ips) > 1 {
			fmt.Println("  ip history:")
			for _, ip := range ips {
				fmt.Printf("    %-15s %s → %s\n", ip.IP, ip.FirstSeen.Local().Format("01-02 15:04"), ip.LastSeen.Local().Format("01-02 15:04"))
			}
		}
		obs, _ := st.ListObservations(d.MAC, 15)
		if len(obs) > 0 {
			fmt.Println("  recent observations:")
			for _, o := range obs {
				extra := ""
				if len(o.Extra) > 0 {
					var parts []string
					for k, v := range o.Extra {
						parts = append(parts, k+"="+v)
					}
					sortStrings(parts)
					extra = term.Dim(strings.Join(parts, " "))
				}
				fmt.Printf("    %s %-8s %-15s %s %s\n", o.Timestamp.Local().Format("15:04:05"), o.Source, o.IP, o.Hostname, extra)
			}
		}
		return nil
	},
}

var deviceSetCmd = &cobra.Command{
	Use:   "set <mac|ip>",
	Short: "Set label, notes or tags on a device",
	Example: `  netscout device set 00:1d:c1:12:34:56 --label "CL5 FOH primary" --tag dante --tag foh
  netscout device set 10.0.0.20 --notes "rack 3, port 12"
  netscout device set 10.0.0.20 --clear-tags`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		mac := args[0]
		if _, err := model.NormalizeMAC(mac); err != nil {
			d, err := resolveDevice(st, mac)
			if err != nil {
				return err
			}
			mac = d.MAC
		}
		mac, _ = model.NormalizeMAC(mac)
		var label, notes *string
		if cmd.Flags().Changed("label") {
			label = &devLabel
		}
		if cmd.Flags().Changed("notes") {
			notes = &devNotes
		}
		var tags []string
		switch {
		case devClearTags:
			tags = []string{}
		case cmd.Flags().Changed("tag"):
			tags = devTags
		case len(devAddTags) > 0 || len(devRmTags) > 0:
			existing := []string{}
			if d, _ := st.GetDevice(mac); d != nil {
				existing = d.Tags
			}
			tags = editTags(existing, devAddTags, devRmTags)
		}
		if label == nil && notes == nil && tags == nil {
			return fmt.Errorf("nothing to change: pass --label, --notes, --tag, --add-tag, --rm-tag or --clear-tags")
		}
		if err := st.SetUserFields(mac, label, notes, tags); err != nil {
			return err
		}
		d, _ := st.GetDevice(mac)
		fmt.Printf("%s  label=%q tags=%v\n", d.MAC, d.Label, d.Tags)
		return nil
	},
}

var deviceRmCmd = &cobra.Command{
	Use:   "rm <mac|ip>",
	Short: "Forget a device (it will reappear if seen again)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		_, st, err := openStore()
		if err != nil {
			return err
		}
		defer st.Close()
		d, err := resolveDevice(st, args[0])
		if err != nil {
			return err
		}
		if err := st.DeleteDevice(d.MAC); err != nil {
			return err
		}
		fmt.Printf("forgot %s\n", d.MAC)
		return nil
	},
}

func vendorLine(d model.Device) string {
	switch {
	case d.Vendor != "":
		return d.Vendor
	case d.Randomized:
		return term.Yellow("randomized / locally administered")
	default:
		return term.Dim("unknown vendor")
	}
}

func editTags(existing, add, rm []string) []string {
	set := map[string]bool{}
	var out []string
	for _, t := range existing {
		if !set[t] {
			set[t] = true
			out = append(out, t)
		}
	}
	for _, t := range add {
		if !set[t] {
			set[t] = true
			out = append(out, t)
		}
	}
	if len(rm) > 0 {
		drop := map[string]bool{}
		for _, t := range rm {
			drop[t] = true
		}
		kept := out[:0]
		for _, t := range out {
			if !drop[t] {
				kept = append(kept, t)
			}
		}
		out = kept
	}
	if out == nil {
		out = []string{}
	}
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func init() {
	devicesCmd.Flags().BoolVar(&devicesJSON, "json", false, "output JSON")
	devicesCmd.Flags().BoolVar(&devicesOnline, "online", false, "only devices currently online")
	devicesCmd.Flags().StringVar(&devicesFilter, "filter", "", "substring filter (same as the positional argument)")
	deviceShowCmd.Flags().BoolVar(&devicesJSON, "json", false, "output JSON")
	deviceSetCmd.Flags().StringVar(&devLabel, "label", "", "friendly name")
	deviceSetCmd.Flags().StringVar(&devNotes, "notes", "", "free-text notes")
	deviceSetCmd.Flags().StringArrayVar(&devTags, "tag", nil, "replace tags (repeatable)")
	deviceSetCmd.Flags().StringArrayVar(&devAddTags, "add-tag", nil, "add a tag (repeatable)")
	deviceSetCmd.Flags().StringArrayVar(&devRmTags, "rm-tag", nil, "remove a tag (repeatable)")
	deviceSetCmd.Flags().BoolVar(&devClearTags, "clear-tags", false, "remove all tags")
	deviceCmd.AddCommand(deviceShowCmd, deviceSetCmd, deviceRmCmd)
	rootCmd.AddCommand(devicesCmd, deviceCmd)
}
