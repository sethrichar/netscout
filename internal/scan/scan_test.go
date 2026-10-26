package scan

import (
	"net"
	"testing"

	"github.com/sethrichar/netscout/internal/capture"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestHosts(t *testing.T) {
	hosts, _, err := Hosts("10.0.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 254 || hosts[0].String() != "10.0.0.1" || hosts[253].String() != "10.0.0.254" {
		t.Errorf("/24: %d hosts, first %s last %s", len(hosts), hosts[0], hosts[len(hosts)-1])
	}
	hosts, _, err = Hosts("192.168.1.77/30")
	if err != nil || len(hosts) != 2 || hosts[0].String() != "192.168.1.77" || hosts[1].String() != "192.168.1.78" {
		t.Errorf("/30: %v %v", hosts, err)
	}
	hosts, _, _ = Hosts("10.1.2.3/32")
	if len(hosts) != 1 || hosts[0].String() != "10.1.2.3" {
		t.Errorf("/32: %v", hosts)
	}
	hosts, _, _ = Hosts("10.0.0.0/22")
	if len(hosts) != 1022 || hosts[1021].String() != "10.0.3.254" {
		t.Errorf("/22 carry: %d %s", len(hosts), hosts[len(hosts)-1])
	}
	if _, _, err := Hosts("10.0.0.0/8"); err == nil {
		t.Error("/8 should be refused")
	}
	if _, _, err := Hosts("fe80::/64"); err == nil {
		t.Error("IPv6 should be refused")
	}
	if _, _, err := Hosts("nope"); err == nil {
		t.Error("garbage should be refused")
	}
}

func TestARPRequestFrame(t *testing.T) {
	src, _ := net.ParseMAC("00:11:22:33:44:55")
	frame, err := ARPRequest(src, net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.9"))
	if err != nil {
		t.Fatal(err)
	}
	pkt := gopacket.NewPacket(frame, layers.LinkTypeEthernet, gopacket.Default)
	eth, _ := pkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
	arp, _ := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	if eth == nil || arp == nil {
		t.Fatal("frame did not decode")
	}
	if eth.DstMAC.String() != "ff:ff:ff:ff:ff:ff" || eth.SrcMAC.String() != "00:11:22:33:44:55" {
		t.Errorf("ethernet: %v → %v", eth.SrcMAC, eth.DstMAC)
	}
	if arp.Operation != layers.ARPRequest || net.IP(arp.DstProtAddress).String() != "10.0.0.9" || net.IP(arp.SourceProtAddress).String() != "10.0.0.2" {
		t.Errorf("arp: %+v", arp)
	}
	// gopacket pads to the 60-byte Ethernet minimum (42 bytes of real frame).
	if len(frame) != 60 {
		t.Errorf("frame length %d, want 60 (padded minimum frame)", len(frame))
	}
}

func TestDefaultCIDR(t *testing.T) {
	cases := map[string]string{
		"10.0.0.20/24":   "10.0.0.0/24",
		"10.0.4.20/22":   "10.0.4.0/22",
		"10.1.2.3/16":    "10.1.2.0/24", // too wide: narrow to our /24
		"169.254.7.9/16": "169.254.7.0/24",
		"192.168.1.5/25": "192.168.1.0/25",
		"172.16.9.9/8":   "172.16.9.0/24",
	}
	for cidr, want := range cases {
		got := DefaultCIDR(capture.Interface{IPv4: []string{cidr}})
		if got != want {
			t.Errorf("DefaultCIDR(%s) = %s, want %s", cidr, got, want)
		}
	}
	if got := DefaultCIDR(capture.Interface{}); got != "" {
		t.Errorf("no address should give empty, got %s", got)
	}
}

func TestSortResults(t *testing.T) {
	rs := []Result{{IP: "10.0.0.20"}, {IP: "10.0.0.3"}, {IP: "10.0.0.100"}}
	sortResults(rs)
	if rs[0].IP != "10.0.0.3" || rs[1].IP != "10.0.0.20" || rs[2].IP != "10.0.0.100" {
		t.Errorf("order: %v", rs)
	}
}
