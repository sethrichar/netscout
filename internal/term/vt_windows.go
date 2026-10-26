//go:build windows

package term

import "golang.org/x/sys/windows"

// EnableVT turns on ANSI escape processing in the Windows console so the live
// table and colours render. Harmless if it fails (older consoles).
func EnableVT() {
	for _, id := range []uint32{windows.STD_OUTPUT_HANDLE, windows.STD_ERROR_HANDLE} {
		h, err := windows.GetStdHandle(id)
		if err != nil {
			continue
		}
		var mode uint32
		if windows.GetConsoleMode(h, &mode) == nil {
			_ = windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
		}
	}
}
