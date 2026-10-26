package parse

import (
	"sort"
	"strings"

	"github.com/gopacket/gopacket/layers"

	"github.com/sethrichar/netscout/internal/model"
)

// MDNS extracts hostnames and advertised services from multicast DNS.
//
//   - A records whose address matches the frame's source IP bind hostname →
//     (MAC, IP). A records for other addresses are ignored: they may be a
//     sleep proxy or a multi-homed host's other interface.
//   - PTR records under a service type (e.g. _netaudio-arc._udp.local for
//     Dante) and SRV records name the services the host offers.
//   - A response that carries A records for other hosts but none for the
//     sender is hearsay (Bonjour reflector/gateway, sleep proxy): nothing in
//     it is attributed to the frame source.
//   - Queries carry no facts about the sender beyond liveness; the generic
//     IPv4 observation covers that, so queries return nothing here.
func MDNS(ctx Context, dns *layers.DNS) []model.Observation {
	if !dns.QR {
		return nil
	}
	o := ctx.obs(model.SourceMDNS)
	o.Extra = map[string]string{}
	services := map[string]bool{}
	instances := map[string]bool{}
	var hostname string
	aRecords, aMatching := 0, 0
	ownNames := map[string]bool{} // names whose A record matches the sender

	for _, rr := range append(append([]layers.DNSResourceRecord{}, dns.Answers...), dns.Additionals...) {
		if rr.Type == layers.DNSTypeA && rr.IP != nil {
			aRecords++
			if ctx.SrcIP != nil && rr.IP.Equal(ctx.SrcIP) {
				aMatching++
				ownNames[strings.ToLower(strings.TrimSuffix(string(rr.Name), "."))] = true
			}
		}
	}
	if aRecords > 0 && aMatching == 0 {
		return nil // speaking for someone else
	}

	consider := func(rr layers.DNSResourceRecord) {
		name := strings.TrimSuffix(string(rr.Name), ".")
		switch rr.Type {
		case layers.DNSTypeA:
			if rr.IP == nil || ctx.SrcIP == nil {
				return
			}
			if rr.IP.Equal(ctx.SrcIP) {
				if h := hostFromName(name); h != "" && (hostname == "" || len(h) < len(hostname)) {
					hostname = h
				}
			}
		case layers.DNSTypePTR:
			target := strings.TrimSuffix(string(rr.PTR), ".")
			if svc := serviceType(name); svc != "" {
				services[svc] = true
				if inst := instanceName(target, svc); inst != "" {
					instances[inst] = true
				}
			} else if strings.HasSuffix(name, ".in-addr.arpa") {
				// Reverse lookup answer: 4.3.2.1.in-addr.arpa → hostname
				if h := hostFromName(target); h != "" && hostname == "" && reverseMatches(name, ctx) {
					hostname = h
				}
			}
		case layers.DNSTypeSRV:
			if svc := serviceType(name); svc != "" {
				services[svc] = true
				if inst := instanceName(name, svc); inst != "" {
					instances[inst] = true
				}
			}
			// The SRV target names the host only when this packet proves the
			// target is the sender (an A record for it matching the source IP).
			target := strings.TrimSuffix(string(rr.SRV.Name), ".")
			if t := hostFromName(target); t != "" && hostname == "" && ownNames[strings.ToLower(target)] {
				hostname = t
			}
		case layers.DNSTypeTXT:
			// Dante and AirPlay publish useful bits in TXT; keep a short sample.
			if svc := serviceType(name); svc != "" {
				services[svc] = true
			}
		}
	}
	for _, rr := range dns.Answers {
		consider(rr)
	}
	for _, rr := range dns.Additionals {
		consider(rr)
	}

	if hostname == "" && len(services) == 0 {
		return nil
	}
	o.Hostname = hostname
	if ctx.SrcIP != nil && model.IsUsableIPv4(ctx.SrcIP.String()) {
		o.IP = ctx.SrcIP.String()
	}
	if len(services) > 0 {
		o.Extra["services"] = joinSorted(services)
	}
	if len(instances) > 0 {
		o.Extra["service_names"] = joinSorted(instances)
	}
	if len(o.Extra) == 0 {
		o.Extra = nil
	}
	return []model.Observation{o}
}

// hostFromName strips the .local suffix and returns "" for service names.
func hostFromName(name string) string {
	name = strings.TrimSuffix(name, ".")
	if name == "" || strings.Contains(name, "._") || strings.HasPrefix(name, "_") {
		return ""
	}
	name = strings.TrimSuffix(name, ".local")
	if strings.HasSuffix(name, ".arpa") {
		return ""
	}
	return name
}

// serviceType returns the "_svc._proto" portion of a DNS-SD name, or "".
//
//	_netaudio-arc._udp.local                 → _netaudio-arc._udp
//	CL5 Primary._netaudio-arc._udp.local     → _netaudio-arc._udp
//	_services._dns-sd._udp.local             → "" (meta query)
//	_printer._sub._http._tcp.local           → _http._tcp (subtypes collapse to the base service)
func serviceType(name string) string {
	name = strings.TrimSuffix(strings.TrimSuffix(name, "."), ".local")
	if strings.HasSuffix(name, "._dns-sd._udp") {
		return ""
	}
	labels := strings.Split(name, ".")
	for i := 0; i+1 < len(labels); i++ {
		if strings.HasPrefix(labels[i], "_") && labels[i] != "_sub" && (labels[i+1] == "_tcp" || labels[i+1] == "_udp") {
			return labels[i] + "." + labels[i+1]
		}
	}
	return ""
}

// instanceName returns the human instance portion of "Instance._svc._proto.local".
func instanceName(full, svc string) string {
	full = strings.TrimSuffix(strings.TrimSuffix(full, "."), ".local")
	idx := strings.LastIndex(full, "."+svc)
	if idx <= 0 {
		return ""
	}
	return strings.ReplaceAll(full[:idx], "\\032", " ")
}

// reverseMatches checks that a reverse-lookup name describes the frame's source IP.
func reverseMatches(name string, ctx Context) bool {
	if ctx.SrcIP == nil {
		return false
	}
	v4 := ctx.SrcIP.To4()
	if v4 == nil {
		return false
	}
	want := strings.Join([]string{itoa(v4[3]), itoa(v4[2]), itoa(v4[1]), itoa(v4[0])}, ".") + ".in-addr.arpa"
	return name == want
}

func itoa(b byte) string {
	const digits = "0123456789"
	if b == 0 {
		return "0"
	}
	var buf [3]byte
	i := 3
	for b > 0 {
		i--
		buf[i] = digits[b%10]
		b /= 10
	}
	return string(buf[i:])
}

func joinSorted(set map[string]bool) string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}
