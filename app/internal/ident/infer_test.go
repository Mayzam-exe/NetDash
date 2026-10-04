package ident

import "testing"

func TestInfer(t *testing.T) {
	cases := []struct {
		name, vendor, mac, ip, gw, want string
	}{
		// gateway position wins
		{"", "zte corporation", "", "192.168.1.1", "192.168.1.1", "router"},
		{"_gateway", "zte corporation", "", "192.168.1.1", "192.168.1.1", "router"},
		{"_gateway", "", "", "10.0.0.1", "192.168.1.1", "router"},
		// hostname beats vendor
		{"Max's iPhone", "Apple, Inc.", "f0:2f:74:8a:1c:03", "192.168.1.12", "192.168.1.1", "phone"},
		{"Max's MacBook Pro", "Apple, Inc.", "f0:2f:74:8a:1c:03", "192.168.1.10", "192.168.1.1", "laptop"},
		{"Living Room TV", "Samsung", "", "192.168.1.42", "192.168.1.1", "tv"},
		{"living-room-tv", "Unknown", "", "192.168.1.60", "192.168.1.1", "tv"},
		{"joes-iphone-2", "Apple, Inc.", "", "192.168.1.12", "192.168.1.1", "phone"},
		{"ESP32-Living", "Espressif Inc", "", "192.168.1.50", "192.168.1.1", "hub"},
		{"Office Printer", "Hewlett Packard", "", "192.168.1.70", "192.168.1.1", "printer"},
		{"PS5", "Sony", "", "192.168.1.30", "192.168.1.1", "console"},
		{"DESKTOP-ABC123", "Intel", "", "192.168.1.33", "192.168.1.1", "desktop"},
		// model-number hostnames (randomized MACs hide the vendor)
		{"SM-G991B", "", "", "192.168.1.44", "192.168.1.1", "phone"},
		{"GT-I9300", "", "", "192.168.1.45", "192.168.1.1", "phone"},
		{"RMX3687", "", "", "192.168.1.46", "192.168.1.1", "phone"},
		{"cph2579", "", "", "192.168.1.47", "192.168.1.1", "phone"},
		{"living-pc", "", "", "192.168.1.48", "192.168.1.1", "desktop"},
		{"johns-mac", "", "", "192.168.1.49", "192.168.1.1", "laptop"},
		{"mac-pro-edit", "", "", "192.168.1.52", "192.168.1.1", "desktop"}, // mac pro beats token "mac"
		{"dsm-admin", "", "", "192.168.1.53", "192.168.1.1", ""},           // "sm-" must not match mid-word
		{"surface-pro-9", "", "", "192.168.1.54", "192.168.1.1", "laptop"},
		// Samsung alone proves nothing (phone, TV, monitor, washer…)
		{"", "Samsung", "ac:de:48:00:11:22", "192.168.1.55", "192.168.1.1", ""},
		// vendor fallbacks
		{"", "Apple, Inc.", "ac:de:48:00:11:22", "192.168.1.12", "192.168.1.1", "laptop"}, // burned-in MAC
		{"", "Apple, Inc.", "ee:de:48:00:11:22", "192.168.1.12", "192.168.1.1", "phone"},  // locally administered
		{"", "Xiaomi Communications", "", "192.168.1.20", "192.168.1.1", "phone"},
		{"", "Raspberry Pi Foundation", "", "192.168.1.50", "192.168.1.1", "desktop"},
		{"", "Espressif Inc", "", "192.168.1.51", "192.168.1.1", "hub"},
		// unknowns stay unknown
		{"Device 192.168.1.77", "", "", "192.168.1.77", "192.168.1.1", ""},
		{"", "PCS Systemtechnik GmbH", "", "192.168.1.60", "192.168.1.1", ""},
		{"", "zte corporation", "", "192.168.1.99", "192.168.1.1", ""},
		// no gateway configured: still infers the rest
		{"iPhone", "", "", "192.168.1.5", "", "phone"},
	}
	for _, c := range cases {
		got := Infer(c.name, c.vendor, c.mac, c.ip, c.gw)
		if got != c.want {
			t.Errorf("Infer(%q,%q,%q,%q,%q) = %q, want %q",
				c.name, c.vendor, c.mac, c.ip, c.gw, got, c.want)
		}
	}
}

func TestValidKind(t *testing.T) {
	for _, k := range Kinds {
		if !ValidKind(k) {
			t.Errorf("ValidKind(%q) = false", k)
		}
	}
	if !ValidKind("") {
		t.Error(`ValidKind("") = false, want true`)
	}
	if ValidKind("toaster") {
		t.Error(`ValidKind("toaster") = true, want false`)
	}
}
