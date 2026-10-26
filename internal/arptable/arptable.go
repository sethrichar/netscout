// Package arptable reads the operating system's ARP/neighbour cache. It is the
// passive fallback when packet capture is unavailable, and a cheap seed for
// the device table at startup.
package arptable

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/sethrichar/netscout/internal/model"
)

// Entry is one IP→MAC binding from the OS cache.
type Entry struct {
	IP, MAC, Iface string
}

// Read returns the current ARP cache for the whole host.
func Read() ([]Entry, error) {
	switch runtime.GOOS {
	case "linux":
		if f, err := os.Open("/proc/net/arp"); err == nil {
			defer f.Close()
			return parseProcNetARP(f), nil
		}
		return runAndParse([]string{"ip", "neigh"}, parseIPNeigh)
	case "darwin":
		return runAndParse([]string{"arp", "-an"}, parseBSDARP)
	case "windows":
		return runAndParse([]string{"arp", "-a"}, parseWindowsARP)
	default:
		return runAndParse([]string{"arp", "-an"}, parseBSDARP)
	}
}

// Observations converts the cache into observations tagged with the given
// interface name (entries from other interfaces are kept but labelled).
func Observations(entries []Entry, iface string) []model.Observation {
	now := time.Now()
	var out []model.Observation
	for _, e := range entries {
		mac, err := model.NormalizeMAC(e.MAC)
		if err != nil || !model.IsUsableMAC(mac) || !model.IsUsableIPv4(e.IP) {
			continue
		}
		o := model.Observation{MAC: mac, IP: e.IP, Source: model.SourceARPTable, Timestamp: now, Interface: e.Iface}
		if o.Interface == "" {
			o.Interface = iface
		}
		out = append(out, o)
	}
	return out
}

func runAndParse(argv []string, parse func(string) []Entry) ([]Entry, error) {
	out, err := exec.Command(argv[0], argv[1:]...).Output()
	if err != nil {
		return nil, fmt.Errorf("running %s: %w", strings.Join(argv, " "), err)
	}
	return parse(string(out)), nil
}

// /proc/net/arp:
// IP address       HW type     Flags       HW address            Mask     Device
// 192.168.1.1      0x1         0x2         00:11:22:33:44:55     *        eth0
func parseProcNetARP(r *os.File) []Entry {
	var out []Entry
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 6 || f[2] == "0x0" { // flags 0x0 = incomplete
			continue
		}
		out = append(out, Entry{IP: f[0], MAC: f[3], Iface: f[5]})
	}
	return out
}

// ip neigh: 192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
func parseIPNeigh(s string) []Entry {
	var out []Entry
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		e := Entry{IP: f[0]}
		for i := 1; i+1 < len(f); i++ {
			switch f[i] {
			case "dev":
				e.Iface = f[i+1]
			case "lladdr":
				e.MAC = f[i+1]
			}
		}
		if e.MAC != "" && !strings.Contains(line, "FAILED") {
			out = append(out, e)
		}
	}
	return out
}

// macOS / BSD: ? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
var bsdRe = regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+) on (\S+)`)

func parseBSDARP(s string) []Entry {
	var out []Entry
	for _, m := range bsdRe.FindAllStringSubmatch(s, -1) {
		if strings.Contains(m[2], "incomplete") {
			continue
		}
		out = append(out, Entry{IP: m[1], MAC: m[2], Iface: m[3]})
	}
	return out
}

// Windows:
// Interface: 192.168.1.10 --- 0xb
//
//	Internet Address      Physical Address      Type
//	192.168.1.1           00-11-22-33-44-55     dynamic
//
// The adapter header is matched by shape ("<ip> --- 0x<index>") rather than
// by the word "Interface:" so localized Windows builds parse the same way.
var (
	winRe       = regexp.MustCompile(`^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(\S+)`)
	winHeaderRe = regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+---\s+0x[0-9a-fA-F]+`)
)

func parseWindowsARP(s string) []Entry {
	var out []Entry
	iface := ""
	for _, line := range strings.Split(s, "\n") {
		if m := winHeaderRe.FindStringSubmatch(line); m != nil {
			iface = m[1]
			continue
		}
		if m := winRe.FindStringSubmatch(line); m != nil {
			out = append(out, Entry{IP: m[1], MAC: m[2], Iface: iface})
		}
	}
	return out
}
