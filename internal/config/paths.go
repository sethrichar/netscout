// Package config resolves per-OS locations for netscout's data and settings.
package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// AppName is the directory name used under the per-OS config root.
const AppName = "netscout"

// DataDir returns the directory where netscout stores its database and
// downloaded vendor data, creating it if needed.
//
//	macOS:   ~/Library/Application Support/netscout/
//	Windows: %APPDATA%\netscout\
//	Linux:   $XDG_CONFIG_HOME/netscout/ (default ~/.config/netscout/)
//
// If override is non-empty it is used verbatim instead.
func DataDir(override string) (string, error) {
	dir := override
	if dir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("locating user config dir: %w", err)
		}
		dir = filepath.Join(base, AppName)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("creating data dir %q: %w", dir, err)
	}
	return dir, nil
}

// DBPath returns the SQLite database path inside dataDir.
func DBPath(dataDir string) string {
	return filepath.Join(dataDir, "netscout.db")
}

// ManufPath returns the location of a user-updated Wireshark manuf file.
func ManufPath(dataDir string) string {
	return filepath.Join(dataDir, "manuf")
}
