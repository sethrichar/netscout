// Package cli wires the cobra command tree for the netscout binary.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/sethrichar/netscout/internal/config"
	"github.com/sethrichar/netscout/internal/term"
)

var (
	flagDataDir string
)

var rootCmd = &cobra.Command{
	Use:   "netscout",
	Short: "LAN sniffer + IPAM with offline MAC vendor lookup",
	Long: `netscout discovers what's on a network, tracks IP/MAC assignments and
identifies devices by MAC vendor. Built for show-site / AV / Dante networks.`,
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Make ANSI output safe everywhere: enable VT processing on Windows
		// consoles, and drop colours when output is not a terminal.
		term.EnableVT()
		if !term.IsTTY() || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
			term.DisableColor()
		}
	},
}

// Execute runs the CLI and prints any error to stderr.
func Execute() error {
	err := rootCmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
	}
	return err
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagDataDir, "data-dir", "", "override the data directory (default: per-OS app data location)")
}

// dataDir resolves the data directory honouring --data-dir.
func dataDir() (string, error) {
	return config.DataDir(flagDataDir)
}
