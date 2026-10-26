//go:build windows

package capture

import (
	"errors"

	"github.com/gopacket/gopacket/pcap"
)

// ErrNpcapMissing is returned when wpcap.dll (Npcap) cannot be loaded.
var ErrNpcapMissing = errors.New("Npcap is not installed (wpcap.dll not found)")

// checkRuntime makes sure the Npcap DLL is loadable before any pcap call.
// Calling pcap functions with the DLL missing would crash the process.
func checkRuntime() error {
	if err := pcap.LoadWinPCAP(); err != nil {
		return ErrNpcapMissing
	}
	return nil
}
