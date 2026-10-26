// Command manufconv converts Wireshark's epan/manuf-data.c (stdin or a path)
// into the classic tab-separated `manuf` text format on stdout. It is used to
// refresh assets/oui/manuf:
//
//	curl -sSL https://raw.githubusercontent.com/wireshark/wireshark/master/epan/manuf-data.c \
//	  | go run ./tools/manufconv > assets/oui/manuf
package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sethrichar/netscout/internal/oui"
)

func main() {
	var in io.Reader = os.Stdin
	if len(os.Args) > 1 {
		f, err := os.Open(os.Args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer f.Close()
		in = f
	}
	db, err := oui.ParseCSource(in)
	if err != nil {
		fmt.Fprintln(os.Stderr, "convert:", err)
		os.Exit(1)
	}
	header := fmt.Sprintf(`Wireshark manuf — Ethernet vendor codes (IEEE OUI / MA-M / MA-S).
Converted from epan/manuf-data.c by netscout tools/manufconv on %s.
Source: https://gitlab.com/wireshark/wireshark (SPDX-License-Identifier: GPL-2.0-or-later)
Format: PREFIX<TAB>SHORT<TAB>LONG  — prefix is 24-bit unless suffixed /28 or /36.`, time.Now().UTC().Format("2006-01-02"))
	if err := db.Write(os.Stdout, header); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %d entries\n", db.Len())
}
