//go:build !windows

package term

// EnableVT is a no-op outside Windows.
func EnableVT() {}
