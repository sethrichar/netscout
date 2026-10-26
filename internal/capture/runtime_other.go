//go:build !windows

package capture

// checkRuntime is a no-op where libpcap is linked at build time.
func checkRuntime() error { return nil }
