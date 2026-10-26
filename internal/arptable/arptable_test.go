package arptable

import "testing"

func TestParseBSD(t *testing.T) {
	in := `? (192.168.1.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]
? (192.168.1.44) at (incomplete) on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (10.20.30.5) at ac:44:f2:12:34:56 on en7 ifscope [ethernet]`
	got := parseBSDARP(in)
	if len(got) != 3 || got[0].MAC != "0:11:22:33:44:55" || got[2].Iface != "en7" {
		t.Fatalf("bad parse: %+v", got)
	}
	obs := Observations(got, "en0")
	if len(obs) != 2 { // multicast dropped
		t.Fatalf("expected 2 observations, got %d: %+v", len(obs), obs)
	}
	if obs[0].MAC != "00:11:22:33:44:55" {
		t.Errorf("unpadded MAC not normalised: %s", obs[0].MAC)
	}
}

func TestParseWindows(t *testing.T) {
	in := "\r\nInterface: 192.168.1.10 --- 0xb\r\n  Internet Address      Physical Address      Type\r\n  192.168.1.1           00-11-22-33-44-55     dynamic\r\n  192.168.1.255         ff-ff-ff-ff-ff-ff     static\r\n  224.0.0.22            01-00-5e-00-00-16     static\r\n"
	got := parseWindowsARP(in)
	if len(got) != 3 || got[0].Iface != "192.168.1.10" {
		t.Fatalf("bad parse: %+v", got)
	}
	if obs := Observations(got, "x"); len(obs) != 1 || obs[0].MAC != "00:11:22:33:44:55" {
		t.Fatalf("expected only the unicast entry: %+v", obs)
	}
}

func TestParseIPNeigh(t *testing.T) {
	in := `192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
192.168.1.7 dev eth0  FAILED
fe80::1 dev eth0 lladdr 00:11:22:33:44:66 router STALE`
	got := parseIPNeigh(in)
	if len(got) != 2 || got[0].MAC != "00:11:22:33:44:55" {
		t.Fatalf("bad parse: %+v", got)
	}
	if obs := Observations(got, ""); len(obs) != 1 || obs[0].Interface != "eth0" {
		t.Fatalf("ipv6 should be dropped: %+v", obs)
	}
}
