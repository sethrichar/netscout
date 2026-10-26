// Package netscout holds project-wide metadata shared by every binary and
// package in the module.
package netscout

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var rawVersion string

// Version returns the working revision recorded in the VERSION file at the
// repository root (for example "0.3"). Published releases use whole numbers.
func Version() string {
	return strings.TrimSpace(rawVersion)
}
