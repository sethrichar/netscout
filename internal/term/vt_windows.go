//go:build windows

package term

import "golang.org/x/sys/windows"

// EnableVT turns on ANSI escape processing in the Windows console so the live
// table and colours render. Harmless if it fails (older consoles).
func EnableVT() {
	for _, h := range []windows.Handle{windows.Stdout, windows.Stderr} {
		var mode uint32
		std, err := windows.GetStdHandle(h)
		if err != nil {
			continue
		}
		if windows.GetConsoleMode(std, &mode) == nil {
			_ = windows.SetConsoleMode(std, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
		}
	}
}
