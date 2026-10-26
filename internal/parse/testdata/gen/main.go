// Command gen writes the pcap fixtures used by the parse tests. Run it from the
// repo root with `go run ./internal/parse/testdata/gen` after changing frames.
//
// The frames are byte-accurate reconstructions of what a show-site LAN
// produces: ARP request/reply/probe, a DHCP Discover/ACK exchange, an mDNS
// announcement from a Dante device, an LLDP advert from a switch and a CDP
// frame, plus a VLAN-tagged ARP and a plain IPv4/UDP packet.
package main

import (
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func mac(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func ip(s string) net.IP { return net.ParseIP(s).To4() }

func serialize(ls ...gopacket.SerializableLayer) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	// UDP checksums need their IPv4 layer.
	var ip4 *layers.IPv4
	for _, l := range ls {
		switch v := l.(type) {
		case *layers.IPv4:
			ip4 = v
		case *layers.UDP:
			if ip4 != nil {
				_ = v.SetNetworkLayerForChecksum(ip4)
			}
		}
	}
	if err := gopacket.SerializeLayers(buf, opts, ls...); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func write(path string, frames [][]byte) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		log.Fatal(err)
	}
	ts := time.Date(2026, 3, 14, 15, 9, 26, 0, time.UTC)
	for i, fr := range frames {
		ci := gopacket.CaptureInfo{Timestamp: ts.Add(time.Duration(i) * 100 * time.Millisecond), CaptureLength: len(fr), Length: len(fr)}
		if err := w.WritePacket(ci, fr); err != nil {
			log.Fatal(err)
		}
	}
}

var (
	danteMAC  = mac("00:1d:c1:12:34:56") // Audinate
	yamahaMAC = mac("ac:44:f2:ab:cd:ef") // Yamaha
	appleMAC  = mac("f0:18:98:01:02:03") // Apple
	ciscoMAC  = mac("00:1b:0d:aa:bb:cc") // Cisco
	phoneMAC  = mac("da:a1:19:00:11:22") // randomized
	bcast     = mac("ff:ff:ff:ff:ff:ff")
)

func arpFrame(op uint16, srcMAC net.HardwareAddr, srcIP string, dstMAC net.HardwareAddr, dstIP string, ethDst net.HardwareAddr) []byte {
	return serialize(
		&layers.Ethernet{SrcMAC: srcMAC, DstMAC: ethDst, EthernetType: layers.EthernetTypeARP},
		&layers.ARP{
			AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
			HwAddressSize: 6, ProtAddressSize: 4, Operation: op,
			SourceHwAddress: srcMAC, SourceProtAddress: ip(srcIP),
			DstHwAddress: dstMAC, DstProtAddress: ip(dstIP),
		})
}

func main() {
	dir := "internal/parse/testdata"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	// --- arp.pcap -----------------------------------------------------------
	write(filepath.Join(dir, "arp.pcap"), [][]byte{
		// 0: who-has 10.0.0.1 tell 10.0.0.20 (Dante device asking for the gateway)
		arpFrame(layers.ARPRequest, danteMAC, "10.0.0.20", mac("00:00:00:00:00:00"), "10.0.0.1", bcast),
		// 1: reply 10.0.0.1 is-at cisco → dante (both sides learnable)
		arpFrame(layers.ARPReply, ciscoMAC, "10.0.0.1", danteMAC, "10.0.0.20", danteMAC),
		// 2: ARP probe from a phone (sender IP 0.0.0.0) — MAC alive, no IP
		arpFrame(layers.ARPRequest, phoneMAC, "0.0.0.0", mac("00:00:00:00:00:00"), "10.0.0.77", bcast),
		// 3: gratuitous ARP from the Yamaha console
		arpFrame(layers.ARPRequest, yamahaMAC, "10.0.0.30", mac("00:00:00:00:00:00"), "10.0.0.30", bcast),
		// 4: VLAN 10 tagged request from apple
		serialize(
			&layers.Ethernet{SrcMAC: appleMAC, DstMAC: bcast, EthernetType: layers.EthernetTypeDot1Q},
			&layers.Dot1Q{VLANIdentifier: 10, Type: layers.EthernetTypeARP},
			&layers.ARP{
				AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
				HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
				SourceHwAddress: appleMAC, SourceProtAddress: ip("10.0.10.5"),
				DstHwAddress: mac("00:00:00:00:00:00"), DstProtAddress: ip("10.0.10.1"),
			}),
	})

	// --- dhcp.pcap ----------------------------------------------------------
	discover := serialize(
		&layers.Ethernet{SrcMAC: yamahaMAC, DstMAC: bcast, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: ip("0.0.0.0"), DstIP: ip("255.255.255.255")},
		&layers.UDP{SrcPort: 68, DstPort: 67},
		&layers.DHCPv4{
			Operation: layers.DHCPOpRequest, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6, Xid: 0x1234,
			ClientIP: ip("0.0.0.0"), YourClientIP: ip("0.0.0.0"), NextServerIP: ip("0.0.0.0"), RelayAgentIP: ip("0.0.0.0"),
			ClientHWAddr: yamahaMAC,
			Options: layers.DHCPOptions{
				layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeDiscover)}),
				layers.NewDHCPOption(layers.DHCPOptHostname, []byte("CL5-FOH")),
				layers.NewDHCPOption(layers.DHCPOptClassID, []byte("Yamaha CL5")),
				layers.NewDHCPOption(layers.DHCPOptRequestIP, ip("10.0.0.30")),
				layers.NewDHCPOption(layers.DHCPOptParamsRequest, []byte{1, 3, 6, 15}),
			},
		})
	ack := serialize(
		&layers.Ethernet{SrcMAC: ciscoMAC, DstMAC: yamahaMAC, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: ip("10.0.0.1"), DstIP: ip("10.0.0.30")},
		&layers.UDP{SrcPort: 67, DstPort: 68},
		&layers.DHCPv4{
			Operation: layers.DHCPOpReply, HardwareType: layers.LinkTypeEthernet, HardwareLen: 6, Xid: 0x1234,
			ClientIP: ip("0.0.0.0"), YourClientIP: ip("10.0.0.30"), NextServerIP: ip("0.0.0.0"), RelayAgentIP: ip("0.0.0.0"),
			ClientHWAddr: yamahaMAC,
			Options: layers.DHCPOptions{
				layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(layers.DHCPMsgTypeAck)}),
				layers.NewDHCPOption(layers.DHCPOptServerID, ip("10.0.0.1")),
				layers.NewDHCPOption(layers.DHCPOptLeaseTime, []byte{0, 1, 0x51, 0x80}),
			},
		})
	write(filepath.Join(dir, "dhcp.pcap"), [][]byte{discover, ack})

	// --- mdns.pcap ----------------------------------------------------------
	name := func(s string) []byte { return []byte(s) }
	mdns := serialize(
		&layers.Ethernet{SrcMAC: danteMAC, DstMAC: mac("01:00:5e:00:00:fb"), EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, TTL: 255, Protocol: layers.IPProtocolUDP, SrcIP: ip("10.0.0.20"), DstIP: ip("224.0.0.251")},
		&layers.UDP{SrcPort: 5353, DstPort: 5353},
		&layers.DNS{QR: true, AA: true, OpCode: layers.DNSOpCodeQuery,
			Answers: []layers.DNSResourceRecord{
				{Name: name("_netaudio-arc._udp.local"), Type: layers.DNSTypePTR, Class: layers.DNSClassIN, TTL: 4500, PTR: name("CL5-FOH-Primary._netaudio-arc._udp.local")},
				{Name: name("CL5-FOH-Primary._netaudio-arc._udp.local"), Type: layers.DNSTypeSRV, Class: layers.DNSClassIN, TTL: 120,
					SRV: layers.DNSSRV{Port: 4440, Name: name("CL5-FOH-Primary.local")}},
				{Name: name("CL5-FOH-Primary.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 120, IP: ip("10.0.0.20")},
				// an A record for a different address (sleep-proxy style) must be ignored
				{Name: name("Other-Host.local"), Type: layers.DNSTypeA, Class: layers.DNSClassIN, TTL: 120, IP: ip("10.0.0.99")},
			},
			Additionals: []layers.DNSResourceRecord{
				{Name: name("_netaudio-chan._udp.local"), Type: layers.DNSTypePTR, Class: layers.DNSClassIN, TTL: 4500, PTR: name("CL5-FOH-Primary._netaudio-chan._udp.local")},
			},
		})
	query := serialize(
		&layers.Ethernet{SrcMAC: appleMAC, DstMAC: mac("01:00:5e:00:00:fb"), EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, TTL: 255, Protocol: layers.IPProtocolUDP, SrcIP: ip("10.0.0.40"), DstIP: ip("224.0.0.251")},
		&layers.UDP{SrcPort: 5353, DstPort: 5353},
		&layers.DNS{QR: false, OpCode: layers.DNSOpCodeQuery,
			Questions: []layers.DNSQuestion{{Name: name("_airplay._tcp.local"), Type: layers.DNSTypePTR, Class: layers.DNSClassIN}}})
	write(filepath.Join(dir, "mdns.pcap"), [][]byte{mdns, query})

	// --- lldp.pcap ----------------------------------------------------------
	lldp := serialize(
		&layers.Ethernet{SrcMAC: ciscoMAC, DstMAC: mac("01:80:c2:00:00:0e"), EthernetType: layers.EthernetTypeLinkLayerDiscovery},
		gopacket.Payload(lldpPayload()),
	)
	write(filepath.Join(dir, "lldp.pcap"), [][]byte{lldp})

	// --- ipv4.pcap ----------------------------------------------------------
	udp := serialize(
		&layers.Ethernet{SrcMAC: phoneMAC, DstMAC: ciscoMAC, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: ip("10.0.0.77"), DstIP: ip("8.8.8.8")},
		&layers.UDP{SrcPort: 50000, DstPort: 53},
		gopacket.Payload([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}),
	)
	// Return traffic from the internet: eth src is the gateway, IP src is foreign.
	ret := serialize(
		&layers.Ethernet{SrcMAC: ciscoMAC, DstMAC: phoneMAC, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, TTL: 55, Protocol: layers.IPProtocolUDP, SrcIP: ip("8.8.8.8"), DstIP: ip("10.0.0.77")},
		&layers.UDP{SrcPort: 53, DstPort: 50000},
		gopacket.Payload([]byte{0, 1, 0x81, 0x80, 0, 0, 0, 0, 0, 0, 0, 0}),
	)
	write(filepath.Join(dir, "ipv4.pcap"), [][]byte{udp, ret})
}

// lldpPayload hand-assembles LLDP TLVs (gopacket has no LLDP serializer).
func lldpPayload() []byte {
	tlv := func(t byte, v []byte) []byte {
		l := len(v)
		return append([]byte{t<<1 | byte(l>>8&1), byte(l)}, v...)
	}
	var p []byte
	p = append(p, tlv(1, append([]byte{4}, ciscoMAC...))...)                    // chassis id: MAC
	p = append(p, tlv(2, append([]byte{5}, []byte("Gi1/0/12")...))...)          // port id: ifname
	p = append(p, tlv(3, []byte{0, 120})...)                                    // ttl
	p = append(p, tlv(4, []byte("to FOH stagebox"))...)                         // port description
	p = append(p, tlv(5, []byte("sw-stage-01"))...)                             // sys name
	p = append(p, tlv(6, []byte("Cisco IOS Software, C2960X\nCompiled..."))...) // sys desc
	p = append(p, tlv(7, []byte{0x00, 0x04, 0x00, 0x04})...)                    // capabilities: bridge / bridge enabled
	mgmt := []byte{5, 1, 10, 0, 0, 1, 2, 0, 0, 0, 0, 0}                         // len=5, IPv4, 10.0.0.1, ifsubtype unknown, ifnum 0, oid len 0
	p = append(p, tlv(8, mgmt)...)
	p = append(p, tlv(0, nil)...) // end
	return p
}
