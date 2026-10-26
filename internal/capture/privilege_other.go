//go:build !windows

package capture

import "errors"

var errNoNpcap = errors.New("npcap not applicable")

func errNpcapMissing() error { return errNoNpcap }
