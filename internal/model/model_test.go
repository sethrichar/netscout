package model

import "testing"

func TestNormalizeMAC(t *testing.T) {
	cases := map[string]string{
		"AA:BB:CC:DD:EE:FF":  "aa:bb:cc:dd:ee:ff",
		"aa-bb-cc-dd-ee-ff":  "aa:bb:cc:dd:ee:ff",
		"aabb.ccdd.eeff":     "aa:bb:cc:dd:ee:ff",
		"AABBCCDDEEFF":       "aa:bb:cc:dd:ee:ff",
		"0:1b:21:a:b:c":      "00:1b:21:0a:0b:0c",
		" 00:1D:C1:00:00:01": "00:1d:c1:00:00:01",
	}
	for in, want := range cases {
		got, err := NormalizeMAC(in)
		if err != nil {
			t.Errorf("NormalizeMAC(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "zz:zz:zz:zz:zz:zz", "00:11:22:33:44", "001122334455667"} {
		if _, err := NormalizeMAC(bad); err == nil {
			t.Errorf("NormalizeMAC(%q) expected error", bad)
		}
	}
}

func TestMACClassification(t *testing.T) {
	if !IsRandomizedMAC("02:fc:00:00:00:01") {
		t.Error("02:... should be randomized/locally administered")
	}
	if !IsRandomizedMAC("da:a1:19:00:00:01") {
		t.Error("da:... (iOS private) should be randomized")
	}
	if IsRandomizedMAC("00:1d:c1:00:00:01") {
		t.Error("Audinate OUI should not be randomized")
	}
	if IsRandomizedMAC("01:00:5e:00:00:fb") {
		t.Error("multicast must not count as randomized")
	}
	if !IsMulticastMAC("ff:ff:ff:ff:ff:ff") || !IsMulticastMAC("01:00:5e:00:00:fb") {
		t.Error("multicast detection failed")
	}
	if IsUsableMAC("00:00:00:00:00:00") || IsUsableMAC("ff:ff:ff:ff:ff:ff") || IsUsableMAC("33:33:00:00:00:01") {
		t.Error("unusable MACs reported usable")
	}
	if !IsUsableMAC("00:1d:c1:00:00:01") {
		t.Error("unicast MAC should be usable")
	}
}

func TestIsUsableIPv4(t *testing.T) {
	for _, ok := range []string{"192.168.1.1", "10.0.0.5", "169.254.3.4"} {
		if !IsUsableIPv4(ok) {
			t.Errorf("%s should be usable", ok)
		}
	}
	for _, bad := range []string{"", "0.0.0.0", "255.255.255.255", "224.0.0.251", "fe80::1", "garbage"} {
		if IsUsableIPv4(bad) {
			t.Errorf("%s should not be usable", bad)
		}
	}
}
