// Command netscout is a LAN sniffer and IPAM tool with offline MAC vendor
// lookup, built for show-site / AV / Dante networks.
package main

import (
	"os"

	"github.com/sethrichar/netscout/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
