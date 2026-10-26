package cli

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sethrichar/netscout"
	"github.com/sethrichar/netscout/internal/capture"
	"github.com/sethrichar/netscout/internal/config"
	"github.com/sethrichar/netscout/internal/oui"
	"github.com/sethrichar/netscout/internal/term"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "First-run checklist: capture permissions, Npcap, interface, data dir, vendor DB",
	RunE: func(cmd *cobra.Command, args []string) error {
		ok := runDoctor(os.Stdout)
		if !ok {
			return fmt.Errorf("some checks failed (see above)")
		}
		return nil
	},
}

// runDoctor prints the checklist and reports whether everything passed.
func runDoctor(w *os.File) bool {
	pass := func(msg string) { fmt.Fprintf(w, "  %s %s\n", term.Green("✔"), msg) }
	warn := func(msg string) { fmt.Fprintf(w, "  %s %s\n", term.Yellow("!"), msg) }
	fail := func(msg string) { fmt.Fprintf(w, "  %s %s\n", term.Red("✘"), msg) }
	allOK := true

	fmt.Fprintf(w, "%s v%s on %s/%s\n\n", term.Bold("netscout"), netscout.Version(), runtime.GOOS, runtime.GOARCH)

	// Data dir
	dir, err := config.DataDir(flagDataDir)
	if err != nil {
		fail("data directory: " + err.Error())
		allOK = false
	} else {
		pass("data directory " + dir)
	}

	// Vendor DB
	if db, err := oui.Load(dir); err != nil {
		fail("vendor database: " + err.Error())
		allOK = false
	} else {
		src := "bundled"
		if db.Source != "embedded" {
			src = "updated copy at " + db.Source
		}
		pass(fmt.Sprintf("vendor database: %d prefixes (%s)", db.Len(), src))
	}

	// Capture runtime / interfaces
	ifaces, err := capture.ListInterfaces()
	if err != nil {
		fail("interfaces: " + err.Error())
		if hint := capture.PrivilegeHint(err); hint != "" {
			fmt.Fprintln(w, indent(hint))
		}
		return false
	}
	var usable []capture.Interface
	for _, i := range ifaces {
		if !i.Loopback && len(i.IPv4) > 0 {
			usable = append(usable, i)
		}
	}
	if len(usable) == 0 {
		warn("no interface with an IPv4 address is up — connect to a network first")
		allOK = false
	} else {
		def, _ := capture.DefaultInterface()
		pass(fmt.Sprintf("%d usable interface(s); default: %s %s", len(usable), def.Name, strings.Join(def.IPv4, ",")))
	}

	// Try to open a capture on the default interface.
	if len(usable) > 0 {
		def, _ := capture.DefaultInterface()
		sess, err := capture.Open(def, capture.Options{Promisc: true})
		if err != nil {
			fail("packet capture on " + def.Name + ": " + err.Error())
			if hint := capture.PrivilegeHint(err); hint != "" {
				fmt.Fprintln(w, indent(hint))
			} else {
				fmt.Fprintln(w, indent("netscout will run in passive mode (ARP table only) until this works."))
			}
			allOK = false
		} else {
			sess.Close()
			pass("packet capture works on " + def.Name)
		}
	}

	fmt.Fprintln(w)
	if allOK {
		fmt.Fprintln(w, "all good — run `netscout` to open the UI or `netscout sniff` for the terminal view")
	}
	return allOK
}

func indent(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	for i := range lines {
		lines[i] = "      " + lines[i]
	}
	return strings.Join(lines, "\n")
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
