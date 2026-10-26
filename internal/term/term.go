// Package term holds small terminal helpers shared by the CLI views.
package term

import (
	"os"

	"github.com/mattn/go-isatty"
)

// IsTTY reports whether stdout is an interactive terminal.
func IsTTY() bool {
	return isatty.IsTerminal(os.Stdout.Fd()) || isatty.IsCygwinTerminal(os.Stdout.Fd())
}

// ANSI escape helpers. They are no-ops when colour is disabled.
var colorEnabled = true

// DisableColor turns every colour helper into identity.
func DisableColor() { colorEnabled = false }

func wrap(code, s string) string {
	if !colorEnabled {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// Bold, Dim, Red, Green, Yellow, Cyan, Magenta colourise text.
func Bold(s string) string    { return wrap("1", s) }
func Dim(s string) string     { return wrap("2", s) }
func Red(s string) string     { return wrap("31;1", s) }
func Green(s string) string   { return wrap("32", s) }
func Yellow(s string) string  { return wrap("33", s) }
func Cyan(s string) string    { return wrap("36", s) }
func Magenta(s string) string { return wrap("35", s) }

// ClearScreen homes the cursor and clears the display.
const ClearScreen = "\x1b[H\x1b[2J"

// Truncate shortens s to max runes, adding an ellipsis.
func Truncate(s string, max int) string {
	if max <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max == 1 {
		return "…"
	}
	return string(r[:max-1]) + "…"
}
