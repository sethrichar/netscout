package parse

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/sethrichar/netscout/internal/model"
)

// readFixture decodes every frame of a testdata pcap through the dispatcher.
func readFixture(t *testing.T, name string) [][]model.Observation {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()
	r, err := pcapgo.NewReader(f)
	if err != nil {
		t.Fatalf("pcap reader: %v", err)
	}
	var out [][]model.Observation
	for {
		data, ci, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read packet: %v", err)
		}
		pkt := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)
		pkt.Metadata().CaptureInfo = ci
		out = append(out, Packet(pkt, "en0"))
	}
	return out
}

func find(obs []model.Observation, mac string) *model.Observation {
	for i := range obs {
		if obs[i].MAC == mac {
			return &obs[i]
		}
	}
	return nil
}

func TestARPFixture(t *testing.T) {
	frames := readFixture(t, "arp.pcap")
	if len(frames) != 5 {
		t.Fatalf("expected 5 frames, got %d", len(frames))
	}
	// 0: request → sender binding only
	if o := frames[0]; len(o) != 1 || o[0].MAC != "00:1d:c1:12:34:56" || o[0].IP != "10.0.0.20" || o[0].Source != model.SourceARP {
		t.Errorf("request: %+v", o)
	}
	// 1: reply → sender (cisco) and target (dante)
	o := frames[1]
	if len(o) != 2 {
		t.Fatalf("reply should yield 2 observations: %+v", o)
	}
	if c := find(o, "00:1b:0d:aa:bb:cc"); c == nil || c.IP != "10.0.0.1" || c.Extra["arp_op"] != "reply" {
		t.Errorf("reply sender: %+v", c)
	}
	if d := find(o, "00:1d:c1:12:34:56"); d == nil || d.IP != "10.0.0.20" || d.Extra["arp_op"] != "reply-target" {
		t.Errorf("reply target: %+v", d)
	}
	// 2: probe → MAC alive, no IP
	if o := frames[2]; len(o) != 1 || o[0].IP != "" || o[0].Extra["arp_probe"] != "true" {
		t.Errorf("probe: %+v", o)
	}
	// 3: gratuitous
	if o := frames[3]; len(o) != 1 || o[0].IP != "10.0.0.30" || o[0].Extra["arp_gratuitous"] != "true" {
		t.Errorf("gratuitous: %+v", o)
	}
	// 4: VLAN tagged
	if o := frames[4]; len(o) != 1 || o[0].VLAN != 10 || o[0].IP != "10.0.10.5" || o[0].MAC != "f0:18:98:01:02:03" {
		t.Errorf("vlan: %+v", o)
	}
	for _, fr := range frames {
		for _, ob := range fr {
			if ob.Interface != "en0" || ob.Timestamp.IsZero() {
				t.Errorf("iface/timestamp not set: %+v", ob)
			}
		}
	}
}

func TestDHCPFixture(t *testing.T) {
	frames := readFixture(t, "dhcp.pcap")
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	disc := frames[0]
	if len(disc) != 1 {
		t.Fatalf("discover: %+v", disc)
	}
	d := disc[0]
	if d.Source != model.SourceDHCP || d.MAC != "ac:44:f2:ab:cd:ef" || d.Hostname != "CL5-FOH" || d.IP != "" {
		t.Errorf("discover fields: %+v", d)
	}
	if d.Extra["dhcp_vendor_class"] != "Yamaha CL5" || d.Extra["dhcp_requested_ip"] != "10.0.0.30" || d.Extra["dhcp_msg_type"] != "discover" {
		t.Errorf("discover extra: %+v", d.Extra)
	}
	ack := frames[1]
	if len(ack) != 2 {
		t.Fatalf("ack should yield client + server: %+v", ack)
	}
	if c := find(ack, "ac:44:f2:ab:cd:ef"); c == nil || c.IP != "10.0.0.30" || c.Extra["dhcp_server"] != "10.0.0.1" || c.Extra["dhcp_msg_type"] != "ack" {
		t.Errorf("ack client: %+v", c)
	}
	if s := find(ack, "00:1b:0d:aa:bb:cc"); s == nil || s.IP != "10.0.0.1" || s.Extra["dhcp_role"] != "server" {
		t.Errorf("ack server: %+v", s)
	}
}

func TestMDNSFixture(t *testing.T) {
	frames := readFixture(t, "mdns.pcap")
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	ann := frames[0]
	if len(ann) != 1 {
		t.Fatalf("announcement: %+v", ann)
	}
	o := ann[0]
	if o.Source != model.SourceMDNS || o.MAC != "00:1d:c1:12:34:56" || o.IP != "10.0.0.20" {
		t.Errorf("mdns fields: %+v", o)
	}
	if o.Hostname != "CL5-FOH-Primary" {
		t.Errorf("hostname = %q", o.Hostname)
	}
	if o.Extra["services"] != "_netaudio-arc._udp,_netaudio-chan._udp" {
		t.Errorf("services = %q", o.Extra["services"])
	}
	if o.Extra["service_names"] != "CL5-FOH-Primary" {
		t.Errorf("service_names = %q", o.Extra["service_names"])
	}
	// A query carries nothing but liveness → generic ipv4 observation.
	q := frames[1]
	if len(q) != 1 || q[0].Source != model.SourceIPv4 || q[0].IP != "10.0.0.40" {
		t.Errorf("query: %+v", q)
	}
}

func TestLLDPFixture(t *testing.T) {
	frames := readFixture(t, "lldp.pcap")
	if len(frames) != 1 || len(frames[0]) != 1 {
		t.Fatalf("expected one observation: %+v", frames)
	}
	o := frames[0][0]
	if o.Source != model.SourceLLDP || o.MAC != "00:1b:0d:aa:bb:cc" {
		t.Errorf("lldp fields: %+v", o)
	}
	if o.Hostname != "sw-stage-01" || o.Extra["lldp_port"] != "Gi1/0/12" || o.Extra["lldp_chassis"] != "00:1b:0d:aa:bb:cc" {
		t.Errorf("lldp extra: host=%q %+v", o.Hostname, o.Extra)
	}
	if o.Extra["lldp_sysdesc"] != "Cisco IOS Software, C2960X" {
		t.Errorf("sysdesc should be first line: %q", o.Extra["lldp_sysdesc"])
	}
	// The management IP is an attribute only: the port MAC sending LLDP is
	// not the MAC that answers ARP for it, so binding it would fake conflicts.
	if o.IP != "" || o.Extra["lldp_mgmt_ip"] != "10.0.0.1" {
		t.Errorf("mgmt ip: %q %+v", o.IP, o.Extra)
	}
	if o.Extra["lldp_caps"] != "bridge" {
		t.Errorf("caps: %q", o.Extra["lldp_caps"])
	}
}

func TestIPv4Fixture(t *testing.T) {
	frames := readFixture(t, "ipv4.pcap")
	if len(frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(frames))
	}
	if o := frames[0]; len(o) != 1 || o[0].Source != model.SourceIPv4 || o[0].MAC != "da:a1:19:00:11:22" || o[0].IP != "10.0.0.77" {
		t.Errorf("outbound: %+v", o)
	}
	// The parser reports what it sees; the engine decides the 8.8.8.8 is foreign.
	if o := frames[1]; len(o) != 1 || o[0].MAC != "00:1b:0d:aa:bb:cc" || o[0].IP != "8.8.8.8" {
		t.Errorf("return: %+v", o)
	}
}

func TestServiceTypeHelpers(t *testing.T) {
	cases := map[string]string{
		"_netaudio-arc._udp.local":             "_netaudio-arc._udp",
		"CL5 Primary._netaudio-arc._udp.local": "_netaudio-arc._udp",
		"_services._dns-sd._udp.local":         "",
		"_printer._sub._http._tcp.local":       "_http._tcp",
		"MacBook.local":                        "",
	}
	for in, want := range cases {
		if got := serviceType(in); got != want {
			t.Errorf("serviceType(%q) = %q, want %q", in, got, want)
		}
	}
	if got := hostFromName("CL5-FOH-Primary.local."); got != "CL5-FOH-Primary" {
		t.Errorf("hostFromName = %q", got)
	}
	if got := hostFromName("_airplay._tcp.local"); got != "" {
		t.Errorf("service name must not be a hostname: %q", got)
	}
	if got := instanceName("Living\\032Room._airplay._tcp.local", "_airplay._tcp"); got != "Living Room" {
		t.Errorf("instanceName = %q", got)
	}
}

func TestMulticastSourceIgnored(t *testing.T) {
	// A frame whose source MAC is multicast/broadcast is garbage; nothing learned.
	buf := gopacket.NewSerializeBuffer()
	_ = gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true},
		&layers.Ethernet{SrcMAC: []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, DstMAC: []byte{1, 2, 3, 4, 5, 6}, EthernetType: layers.EthernetTypeIPv4},
		&layers.IPv4{Version: 4, Protocol: layers.IPProtocolUDP, SrcIP: []byte{10, 0, 0, 1}, DstIP: []byte{10, 0, 0, 2}},
	)
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LinkTypeEthernet, gopacket.Default)
	if obs := Packet(pkt, "en0"); len(obs) != 0 {
		t.Errorf("expected nothing, got %+v", obs)
	}
}
