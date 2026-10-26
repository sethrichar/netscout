package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/sethrichar/netscout"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the netscout version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("netscout v%s (%s/%s, %s)\n", netscout.Version(), runtime.GOOS, runtime.GOARCH, runtime.Version())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
