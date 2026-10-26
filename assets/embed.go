// Package assets bundles data files into the binary.
package assets

import _ "embed"

// Manuf is the Wireshark vendor database (see oui/manuf for provenance).
//
//go:embed oui/manuf
var Manuf []byte
