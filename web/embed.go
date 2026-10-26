// Package web holds the browser UI (vanilla HTML/CSS/JS, no build step),
// embedded into the binary and served by internal/web.
package web

import "embed"

// Static contains the files under static/.
//
//go:embed static
var Static embed.FS
