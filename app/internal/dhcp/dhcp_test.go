package dhcp

import "testing"

// buildFrame assembles an Ethernet/IPv4/UDP/DHCP DISCOVER·REQUEST·ACK frame.
// Checksums are left zero — Parse never validates them.
func buildFrame(msgType byte, mac [6]byte, ciaddr, yiaddr, reqIP [4]byte, hostname string, taggedVLAN bool) []byte {
	dhcp := make([]byte, 240)
	dhcp[0] = 1                    // op = BOOTREQUEST (2 for ACK is not required by Parse)
	dhcp[1] = 1                    // htype ethernet
	dhcp[2] = 6                    // hlen
	copy(dhcp[28:34], mac[:])      // chaddr
	copy(dhcp[12:16], ciaddr[:])   // ciaddr
	copy(dhcp[16:20], yiaddr[:])   // yiaddr
	copy(dhcp[236:240], []byte{99, 130, 83, 99})
	opts := []byte{53, 1, msgType}
	if hostname != "" {
		opts = append(opts, 12, byte(len(hostname)))
		opts = append(opts, []byte(hostname)...)
	}
	if reqIP != [4]byte{} {
		opts = append(opts, 50, 4, reqIP[0], reqIP[1], reqIP[2], reqIP[3])
	}
	opts = append(opts, 255)
	dhcp = append(dhcp, opts...)

	udpLen := 8 + len(dhcp)
	udp := make([]byte, 8+udpLen-8)
	udp[0], udp[1] = 0, 68 // client → server
	udp[2], udp[3] = 0, 67
	udp[4] = byte(udpLen >> 8)
	udp[5] = byte(udpLen)
	copy(udp[8:], dhcp)

	ipTotal := 20 + len(udp)
	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[2] = byte(ipTotal >> 8)
	ip[3] = byte(ipTotal)
	ip[8] = 64
	ip[9] = 17 // UDP
	ip[12], ip[13], ip[14], ip[15] = 0, 0, 0, 0 // 0.0.0.0
	ip[16], ip[17], ip[18], ip[19] = 255, 255, 255, 255

	eth := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]}
	if taggedVLAN {
		eth = append(eth, 0x81, 0x00, 0x00, 0x01) // VLAN 1 tag
	}
	eth = append(eth, 0x08, 0x00)
	eth = append(eth, ip...)
	eth = append(eth, udp...)
	return eth
}

func TestParseDiscoverWithHostname(t *testing.T) {
	mac := [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	frame := buildFrame(TypeDiscover, mac, [4]byte{}, [4]byte{}, [4]byte{}, "Kids Tablet", false)
	ev, ok := Parse(frame)
	if !ok {
		t.Fatal("discover not parsed")
	}
	if ev.MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("mac=%q want aa:bb:cc:dd:ee:01", ev.MAC)
	}
	if ev.Hostname != "Kids Tablet" {
		t.Errorf("hostname=%q want %q", ev.Hostname, "Kids Tablet")
	}
	if ev.Type != TypeDiscover {
		t.Errorf("type=%d want discover", ev.Type)
	}
	if ev.IP != "" {
		t.Errorf("discover must carry no IP, got %q", ev.IP)
	}
}

func TestParseACKCarriesYiaddr(t *testing.T) {
	mac := [6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	frame := buildFrame(TypeACK, mac, [4]byte{}, [4]byte{192, 168, 1, 77}, [4]byte{}, "pixel-7", false)
	ev, ok := Parse(frame)
	if !ok {
		t.Fatal("ack not parsed")
	}
	if ev.IP != "192.168.1.77" {
		t.Errorf("ip=%q want 192.168.1.77", ev.IP)
	}
	if ev.Hostname != "pixel-7" {
		t.Errorf("hostname=%q want pixel-7", ev.Hostname)
	}
}

func TestParseRequestPrefersCiaddrThenRequested(t *testing.T) {
	mac := [6]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	frame := buildFrame(TypeRequest, mac, [4]byte{10, 0, 0, 9}, [4]byte{}, [4]byte{}, "", false)
	ev, ok := Parse(frame)
	if !ok || ev.IP != "10.0.0.9" {
		t.Fatalf("request ciaddr: ok=%v ip=%q", ok, ev.IP)
	}
	frame = buildFrame(TypeRequest, mac, [4]byte{}, [4]byte{}, [4]byte{10, 0, 0, 8}, "", false)
	ev, ok = Parse(frame)
	if !ok || ev.IP != "10.0.0.8" {
		t.Fatalf("request option50: ok=%v ip=%q", ok, ev.IP)
	}
}

func TestParseVLANTagged(t *testing.T) {
	mac := [6]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}
	frame := buildFrame(TypeDiscover, mac, [4]byte{}, [4]byte{}, [4]byte{}, "vlan-host", true)
	ev, ok := Parse(frame)
	if !ok || ev.Hostname != "vlan-host" || ev.MAC != "de:ad:be:ef:00:01" {
		t.Fatalf("vlan frame: ok=%v ev=%+v", ok, ev)
	}
}

func TestParseRejectsNonDHCP(t *testing.T) {
	cases := map[string][]byte{
		"empty":   {},
		"short":   make([]byte, 40),
		"arp":     append(append(make([]byte, 12), 0x08, 0x06), make([]byte, 28)...),
		"no-cookie": func() []byte {
			f := buildFrame(TypeDiscover, [6]byte{1, 2, 3, 4, 5, 6}, [4]byte{}, [4]byte{}, [4]byte{}, "x", false)
			f[14+20+8+236] = 0 // break magic cookie
			return f
		}(),
		"wrong-udp": func() []byte {
			f := buildFrame(TypeDiscover, [6]byte{1, 2, 3, 4, 5, 6}, [4]byte{}, [4]byte{}, [4]byte{}, "x", false)
			// zero both UDP ports so neither is 67/68
			copy(f[14+20:14+20+8], make([]byte, 8))
			return f
		}(),
	}
	for name, frame := range cases {
		if _, ok := Parse(frame); ok {
			t.Errorf("%s: parsed as DHCP, want reject", name)
		}
	}
}

func TestParseOfferAndNAKIgnored(t *testing.T) {
	// Build with DISCOVER type then patch option 53 to OFFER (2) / NAK (6).
	mac := [6]byte{9, 9, 9, 9, 9, 9}
	base := buildFrame(TypeDiscover, mac, [4]byte{}, [4]byte{}, [4]byte{}, "x", false)
	// option 53 sits right after the fixed header: 240 → [53,1,<type>]
	off := 14 + 20 + 8 + 240
	for _, offerType := range []byte{2, 6} {
		f := append([]byte{}, base...)
		f[off+2] = offerType
		if _, ok := Parse(f); ok {
			t.Errorf("type %d parsed, want ignore", offerType)
		}
	}
}

func TestSanitizeName(t *testing.T) {
	if got := sanitizeName([]byte("  tv\x00\x01 lounge ")); got != "tv lounge" {
		t.Errorf("sanitize=%q", got)
	}
	long := make([]byte, 200)
	for i := range long {
		long[i] = 'a'
	}
	if got := sanitizeName(long); len(got) != 63 {
		t.Errorf("cap len=%d want 63", len(got))
	}
}
