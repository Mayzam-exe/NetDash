package netinfo

import (
	"reflect"
	"testing"
)

// Fixture: real `iw dev wlp3s0 link` output from a 2.4 GHz association.
const iwLinkConnected = `Connected to 44:59:43:4e:26:b8 (on wlp3s0)
	SSID: PTCL-BB
	freq: 2422.0
	RX: 60604382 bytes (201465 packets)
	TX: 73291564 bytes (207021 packets)
	signal: -54 dBm
	tx bitrate: 72.2 MBit/s
	channel 3 (2422 MHz), width: 40 MHz, center1: 2432 MHz
`

func TestParseLinkDetailConnected(t *testing.T) {
	ssid, freq, signal, ch, bw, ok := parseLinkDetail(iwLinkConnected)
	if !ok {
		t.Fatal("expected ok for a connected link")
	}
	if ssid != "PTCL-BB" || freq != 2422 || signal != -54 || ch != "3" || bw != "40 MHz" {
		t.Errorf("got ssid=%q freq=%v signal=%d ch=%q bw=%q", ssid, freq, signal, ch, bw)
	}
	// The legacy WifiSignal view must keep its exact contract.
	f, s, ok := parseIwLink(iwLinkConnected)
	if !ok || f != 2422 || s != -54 {
		t.Errorf("parseIwLink = %v,%d,%v — delegation changed behavior", f, s, ok)
	}
}

func TestParseLinkDetailDisconnected(t *testing.T) {
	ssid, freq, _, _, _, ok := parseLinkDetail("Not connected.\n")
	if ssid != "" || freq != 0 || ok {
		t.Errorf("disconnected: got ssid=%q freq=%v ok=%v", ssid, freq, ok)
	}
}

func TestBandOfFreq(t *testing.T) {
	cases := map[float64]string{
		2412: "24", 2422: "24", 2484: "24",
		5180: "5", 5745: "5",
		5955: "", // 6 GHz is not labelled as 5
		0:    "", 2399: "",
	}
	for freq, want := range cases {
		if got := bandOfFreq(freq); got != want {
			t.Errorf("bandOfFreq(%v) = %q, want %q", freq, got, want)
		}
	}
}

func TestSplitEscaped(t *testing.T) {
	got := splitEscaped(`PTCL-BB:3:2422 MHz:62`, ':')
	want := []string{"PTCL-BB", "3", "2422 MHz", "62"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("basic row = %#v", got)
	}
	// An SSID carrying an escaped colon must not split into an extra field.
	got = splitEscaped(`My\:Net:6:2437 MHz:40`, ':')
	want = []string{"My:Net", "6", "2437 MHz", "40"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("escaped colon row = %#v", got)
	}
	got = splitEscaped(`a\\b:1:2`, ':')
	want = []string{`a\b`, "1", "2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("escaped backslash row = %#v", got)
	}
}

func TestWanTypeOf(t *testing.T) {
	cases := []struct {
		typ, method, want string
	}{
		{"802-11-wireless", "auto", "DHCP"},
		{"802-3-ethernet", "auto", "DHCP"},
		{"802-3-ethernet", "manual", "Static"},
		{"ppp", "", "PPPoE"},
		{"802-11-wireless", "link-local", ""}, // unknown stays unknown
		{"", "", ""},
	}
	for _, c := range cases {
		if got := wanTypeOf(c.typ, c.method); got != c.want {
			t.Errorf("wanTypeOf(%q,%q) = %q, want %q", c.typ, c.method, got, c.want)
		}
	}
}

func TestSecOf(t *testing.T) {
	for in, want := range map[string]string{
		"sae": "WPA3", "SAE": "WPA3", " wpa-psk ": "WPA2",
		"wpa-eap": "", "none": "", "": "",
	} {
		if got := secOf(in); got != want {
			t.Errorf("secOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPropValue(t *testing.T) {
	if got := propValue("ipv4.method:auto"); got != "auto" {
		t.Errorf("propValue = %q", got)
	}
	if got := propValue("802-11-wireless-security.key-mgmt:wpa-psk"); got != "wpa-psk" {
		t.Errorf("propValue = %q", got)
	}
	// IPv6 DNS values contain colons — the property name still ends at the first.
	if got := propValue("IP4.DNS[1]:fd00::1"); got != "fd00::1" {
		t.Errorf("propValue = %q", got)
	}
	if got := propValue("novalue"); got != "" {
		t.Errorf("propValue = %q", got)
	}
}

func TestParseDNSLines(t *testing.T) {
	got := parseDNSLines("IP4.DNS[1]:192.168.1.1\nIP4.DNS[2]:1.1.1.1\nIP4.DNS[3]:9.9.9.9\n")
	if !reflect.DeepEqual(got, []string{"192.168.1.1", "1.1.1.1"}) {
		t.Errorf("got %#v — want two entries capped", got)
	}
	if got := parseDNSLines("garbage\nnot-an-ip:hello\n"); got != nil {
		t.Errorf("garbage = %#v, want nil", got)
	}
}

func TestParseTrace(t *testing.T) {
	body := "fl=xx\nip=182.185.132.194\nloc=PK\nts=1\n"
	if got := parseTrace(body); got != "182.185.132.194" {
		t.Errorf("parseTrace = %q", got)
	}
	if got := parseTrace("fl=xx\nloc=PK\n"); got != "" {
		t.Errorf("missing ip line = %q, want empty", got)
	}
	if got := parseTrace("ip=not-an-ip\n"); got != "" {
		t.Errorf("invalid ip = %q, want empty", got)
	}
}

func TestFillFromCache(t *testing.T) {
	cache := []wifiNet{
		{ssid: "Imamia 1st Floor 4G", chn: "9", freq: 2452}, // neighbour, stronger
		{ssid: "PTCL-BB", chn: "3", freq: 2422},             // our 2.4 GHz row
		{ssid: "PTCL-BB", chn: "36", freq: 5180},            // identical-name 5 GHz
		{ssid: "", chn: "1", freq: 2412},                    // hidden network
	}

	// Connected on 2.4 GHz where iw gave the SSID but no channel line:
	// the channel must come from OUR row, never the neighbour's.
	d := Detected{SSID24: "PTCL-BB"}
	fillFromCache(&d, "PTCL-BB", cache)
	if d.Ch24 != "3" {
		t.Errorf("Ch24 = %q, want PTCL-BB's channel 3 (not the neighbour's 9)", d.Ch24)
	}
	if d.SSID5 != "PTCL-BB" || d.Ch5 != "36" {
		t.Errorf("SSID5/Ch5 = %q/%q — identical-name dual band not paired", d.SSID5, d.Ch5)
	}

	// Not associated: no claims at all.
	d = Detected{}
	fillFromCache(&d, "", cache)
	if d.SSID24 != "" || d.SSID5 != "" || d.Ch24 != "" {
		t.Errorf("unassociated host claimed networks: %+v", d)
	}

	// A different connected network must not adopt our cache rows.
	d = Detected{SSID24: "OtherNet"}
	fillFromCache(&d, "OtherNet", cache)
	if d.SSID5 != "" || d.Ch5 != "" {
		t.Errorf("connected to OtherNet but claimed: %+v", d)
	}
}
