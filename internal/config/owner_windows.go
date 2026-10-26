//go:build windows

package config

// FixOwnership is a no-op on Windows (no sudo semantics).
func FixOwnership(path string) {}
