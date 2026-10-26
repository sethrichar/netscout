package cli

import (
	"fmt"
	"strings"
	"time"

	"github.com/sethrichar/netscout/internal/model"
	"github.com/sethrichar/netscout/internal/term"
)

// renderTable draws the live device table for the terminal.
func renderTable(rt *rtime, started time.Time, recent []model.Event, width int) string {
	var b strings.Builder
	devs := rt.engine.Devices()
	total, online := rt.engine.Counts()

	rt.mu.Lock()
	iface, session, passive, hint := rt.iface, rt.session, rt.passive, rt.hint
	rt.mu.Unlock()
	mode := term.Green("capturing")
	if passive {
		mode = term.Yellow("PASSIVE (ARP table only)")
	}
	label := iface.Label()
	if label != iface.Name {
		label = fmt.Sprintf("%s (%s)", iface.Name, label)
	}
	fmt.Fprintf(&b, "%s  %s on %s  %s\n", term.Bold("netscout"), mode, term.Cyan(label), strings.Join(iface.IPv4, ","))
	stats := ""
	if session != nil {
		s := session.Stats()
		stats = fmt.Sprintf("pkts %d", s.Received)
		if s.PcapDropped+s.QueueDropped > 0 {
			stats += fmt.Sprintf(" (dropped %d)", s.PcapDropped+s.QueueDropped)
		}
	}
	fmt.Fprintf(&b, "%s  devices %d (%s online)  %s  up %s  %s\n\n",
		time.Now().Format("15:04:05"), total, term.Green(fmt.Sprint(online)), stats,
		time.Since(started).Round(time.Second), term.Dim("Ctrl-C to stop"))

	if passive && hint != "" {
		fmt.Fprintln(&b, term.Yellow(hint))
		fmt.Fprintln(&b)
	}

	if width <= 0 {
		width = 120
	}
	// Column plan: state(2) ip(15) mac(17) vendor(v) host(h) last(7) info(rest)
	fixed := 2 + 1 + 15 + 1 + 17 + 1 + 7 + 2
	rest := width - fixed
	if rest < 30 {
		rest = 30
	}
	vw := rest * 30 / 100
	hw := rest * 30 / 100
	iw := rest - vw - hw - 2
	if vw < 10 {
		vw = 10
	}
	if hw < 10 {
		hw = 10
	}
	if iw < 10 {
		iw = 10
	}

	fmt.Fprintf(&b, "%s\n", term.Bold(fmt.Sprintf("%-2s %-15s %-17s %-*s %-*s %-7s %s", "", "IP", "MAC", vw, "VENDOR", hw, "HOST / LABEL", "LAST", "INFO")))
	for _, d := range devs {
		state := term.Dim("·")
		if d.Online {
			state = term.Green("●")
		}
		if d.Attrs["conflict_ip"] != "" {
			state = term.Red("!")
		}
		vendor := d.Vendor
		if vendor == "" {
			if d.Randomized {
				vendor = term.Dim("randomized")
			} else {
				vendor = term.Dim("unknown")
			}
		}
		host := d.Label
		if host == "" {
			host = d.Hostname
		}
		if d.Attrs["self"] == "true" {
			host = strings.TrimSpace(host + " (this machine)")
		}
		ip := d.IP()
		if len(d.IPs) > 1 {
			ip += term.Dim(fmt.Sprintf("+%d", len(d.IPs)-1))
		}
		info := deviceInfo(d)
		line := fmt.Sprintf("%-2s %-15s %-17s %s %s %-7s %s",
			state, padANSI(ip, 15), d.MAC,
			padANSI(term.Truncate(vendor, vw), vw),
			padANSI(term.Truncate(host, hw), hw),
			ago(d.LastSeen), term.Truncate(info, iw))
		if d.Attrs["conflict_ip"] != "" {
			line = term.Red(stripANSI(line))
		} else if !d.Online {
			line = term.Dim(stripANSI(line))
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if len(devs) == 0 {
		fmt.Fprintln(&b, term.Dim("  waiting for traffic… (try `netscout scan` or generate some ARP by pinging the broadcast)"))
	}

	if len(recent) > 0 {
		fmt.Fprintf(&b, "\n%s\n", term.Bold("recent events"))
		for _, ev := range recent {
			fmt.Fprintln(&b, "  "+term.Truncate(eventLine(ev), width-2))
		}
	}
	return b.String()
}

// deviceInfo summarises the most useful attributes in one short string.
func deviceInfo(d model.Device) string {
	var parts []string
	if v := d.Attrs["dhcp_vendor_class"]; v != "" {
		parts = append(parts, v)
	}
	if v := d.Attrs["services"]; v != "" {
		parts = append(parts, prettyServices(v))
	}
	if v := d.Attrs["lldp_sysdesc"]; v != "" {
		parts = append(parts, v)
	} else if v := d.Attrs["cdp_platform"]; v != "" {
		parts = append(parts, v)
	}
	if v := d.Attrs["lldp_port"]; v != "" {
		parts = append(parts, "port "+v)
	}
	if v := d.Attrs["vlan"]; v != "" {
		parts = append(parts, "vlan "+v)
	}
	if len(parts) == 0 {
		parts = append(parts, d.Attrs["sources"])
	}
	return strings.Join(parts, " · ")
}

// prettyServices maps well-known DNS-SD types to friendly names.
func prettyServices(list string) string {
	known := map[string]string{
		"_netaudio-arc._udp":    "Dante",
		"_netaudio-chan._udp":   "Dante",
		"_netaudio-cmc._udp":    "Dante",
		"_netaudio-dbc._udp":    "Dante",
		"_airplay._tcp":         "AirPlay",
		"_raop._tcp":            "AirPlay",
		"_ipp._tcp":             "Printer",
		"_printer._tcp":         "Printer",
		"_pdl-datastream._tcp":  "Printer",
		"_http._tcp":            "HTTP",
		"_https._tcp":           "HTTPS",
		"_ssh._tcp":             "SSH",
		"_sftp-ssh._tcp":        "SSH",
		"_smb._tcp":             "SMB",
		"_afpovertcp._tcp":      "AFP",
		"_googlecast._tcp":      "Chromecast",
		"_spotify-connect._tcp": "Spotify",
		"_companion-link._tcp":  "Apple",
		"_rdlink._tcp":          "Apple",
		"_homekit._tcp":         "HomeKit",
		"_hap._tcp":             "HomeKit",
		"_sonos._tcp":           "Sonos",
		"_qsc-qsys._tcp":        "Q-SYS",
		"_qsys._tcp":            "Q-SYS",
		"_shure._tcp":           "Shure",
		"_osc._udp":             "OSC",
		"_artnet._udp":          "Art-Net",
		"_sacn._udp":            "sACN",
		"_ndi._tcp":             "NDI",
		"_rtsp._tcp":            "RTSP",
		"_pulse._tcp":           "PulseAudio",
		"_workstation._tcp":     "Workstation",
		"_device-info._tcp":     "",
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range strings.Split(list, ",") {
		name, ok := known[s]
		if !ok {
			name = strings.TrimPrefix(strings.SplitN(s, ".", 2)[0], "_")
		}
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return strings.Join(out, ",")
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	d := time.Since(t)
	switch {
	case d < time.Second:
		return "now"
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// padANSI pads s to width visible characters, ignoring escape codes.
func padANSI(s string, width int) string {
	vis := len([]rune(stripANSI(s)))
	if vis >= width {
		return s
	}
	return s + strings.Repeat(" ", width-vis)
}

func stripANSI(s string) string {
	var b strings.Builder
	inEsc := false
	for _, r := range s {
		switch {
		case inEsc:
			if r == 'm' {
				inEsc = false
			}
		case r == '\x1b':
			inEsc = true
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
