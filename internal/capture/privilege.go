package capture

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"strings"
)

// PrivilegeHint turns a capture error into actionable guidance for the current
// OS. It returns "" when the error does not look permission-related.
func PrivilegeHint(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	permission := strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "operation not permitted") ||
		strings.Contains(msg, "don't have permission") ||
		strings.Contains(msg, "/dev/bpf") ||
		strings.Contains(msg, "access is denied") ||
		strings.Contains(msg, "npcap")

	switch runtime.GOOS {
	case "darwin":
		if !permission && !bpfBlocked() {
			return ""
		}
		return strings.TrimSpace(`
Packet capture needs access to /dev/bpf* on macOS. Fix one of two ways:
  1. Run with sudo:            sudo netscout sniff
  2. Install Wireshark's ChmodBPF helper (grants your user BPF access
     permanently, no sudo): https://www.wireshark.org/download.html
     -> install Wireshark, accept the "ChmodBPF" component, then log out/in.
Passive mode (ARP table only) is used until capture works.`)
	case "windows":
		if errors.Is(err, errNpcapMissing()) || strings.Contains(msg, "wpcap") || strings.Contains(msg, "npcap") {
			return strings.TrimSpace(`
Npcap is required for packet capture on Windows and was not found.
  Download: https://npcap.com/#download and run the installer with its defaults.
  Then re-run netscout. Running as Administrator is not required once Npcap is installed,
  as long as you leave "Restrict Npcap driver's access to Administrators only" unchecked.`)
		}
		if permission {
			return "Capture was denied. Re-run netscout from an Administrator terminal, or reinstall Npcap with\n\"Restrict Npcap driver's access to Administrators only\" unchecked."
		}
		return ""
	default:
		if !permission {
			return ""
		}
		return fmt.Sprintf("Packet capture needs CAP_NET_RAW. Run with sudo, or grant it once:\n  sudo setcap cap_net_raw,cap_net_admin=eip %s", os.Args[0])
	}
}

// bpfBlocked reports whether the current user lacks read access to the BPF
// devices on macOS. A device that is merely busy (Wireshark or another
// netscout holds it) counts as accessible. Always false elsewhere.
func bpfBlocked() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	for n := 0; n < 4; n++ {
		f, err := os.OpenFile(fmt.Sprintf("/dev/bpf%d", n), os.O_RDONLY, 0)
		if err == nil {
			f.Close()
			return false
		}
		if errors.Is(err, fs.ErrPermission) {
			return true
		}
		// EBUSY / ENOENT etc.: try the next device.
	}
	return false
}

// IsPermissionError reports whether err looks like a capture-permission or
// missing-driver problem, i.e. one PrivilegeHint can explain.
func IsPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errNpcapMissing()) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, needle := range []string{"permission denied", "operation not permitted", "don't have permission", "/dev/bpf", "access is denied", "npcap", "wpcap", "cap_net_raw"} {
		if strings.Contains(msg, needle) {
			return true
		}
	}
	return false
}
