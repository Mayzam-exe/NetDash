package netinfo

import "testing"

func TestParseIwLink(t *testing.T) {
	out := "Connected to 14:ca:56:9e:4d:4a (on wlp3s0)\n" +
		"\tSSID: Al Mustafa II 2nd Floor 5G\n" +
		"\tfreq: 5785.0\n" +
		"\tsignal: -58 dBm\n"
	freq, sig, ok := parseIwLink(out)
	if !ok || freq != 5785.0 || sig != -58 {
		t.Errorf("parseIwLink(5G) = %v,%v,%v; want 5785,-58,true", freq, sig, ok)
	}

	freq, sig, ok = parseIwLink("freq: 2412.0\nsignal: -70 dBm\n")
	if !ok || freq != 2412.0 || sig != -70 {
		t.Errorf("parseIwLink(2.4G) = %v,%v,%v; want 2412,-70,true", freq, sig, ok)
	}

	if _, _, ok = parseIwLink("Not connected."); ok {
		t.Error("parseIwLink(no link) ok = true; want false")
	}
}

func TestNameFromHostname(t *testing.T) {
	cases := map[string]string{
		"maxim-laptop": "maxim-laptop",
		"192.168.1.48": "This machine",
		"":             "This machine",
		"localhost":    "This machine",
		"host.lan.":    "host.lan",
	}
	for in, want := range cases {
		if got := nameFromHostname(in); got != want {
			t.Errorf("nameFromHostname(%q) = %q; want %q", in, got, want)
		}
	}
}
