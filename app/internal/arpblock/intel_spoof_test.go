package arpblock

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// makeDNSQuery builds eth+IPv4+UDP dport:53 query from victim to server.
func makeDNSQuery(victimMAC, dstMAC net.HardwareAddr, victimIP, serverIP net.IP, qname string, sport, txid uint16) []byte {
	var q []byte
	for _, lab := range strings.Split(qname, ".") {
		q = append(q, byte(len(lab)))
		q = append(q, lab...)
	}
	q = append(q, 0)
	q = append(q, 0x00, 0x01, 0x00, 0x01)
	dns := []byte{byte(txid >> 8), byte(txid), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	dns = append(dns, q...)

	f := make([]byte, 14+20+8+len(dns))
	copy(f[0:6], dstMAC)
	copy(f[6:12], victimMAC)
	binary.BigEndian.PutUint16(f[12:14], etherTypeIPv4)
	f[14] = 0x45
	binary.BigEndian.PutUint16(f[16:18], uint16(20+8+len(dns)))
	f[22] = 64
	f[23] = 17
	copy(f[26:30], victimIP.To4())
	copy(f[30:34], serverIP.To4())
	binary.BigEndian.PutUint16(f[10:12], 0)
	l4 := 34
	binary.BigEndian.PutUint16(f[l4:l4+2], sport)
	binary.BigEndian.PutUint16(f[l4+2:l4+4], 53)
	binary.BigEndian.PutUint16(f[l4+4:l4+6], uint16(8+len(dns)))
	copy(f[l4+8:], dns)
	return f
}

type tapEvent struct {
	ip string
	up bool
}

func TestTapObservesRelayedFrames(t *testing.T) {
	fn := &fakeNet{}
	b := testBlocker(fn)
	our := append(net.HardwareAddr(nil), b.ourMAC...)
	victimMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01}
	victimIP := net.IPv4(192, 168, 1, 40)
	serverIP := net.IPv4(93, 184, 216, 34)

	var taps []tapEvent
	b.SetTap(func(ip string, up bool, frame []byte) {
		if len(frame) == 0 {
			t.Error("tap got empty frame")
		}
		taps = append(taps, tapEvent{ip, up})
	})

	// unknown device: no tap
	if f := makeIPv4Frame(victimMAC, our, victimIP, serverIP, 60); b.handleFrame(f) != nil {
		t.Fatal("unlisted device relayed")
	}
	if len(taps) != 0 {
		t.Fatalf("taps = %v, want none", taps)
	}

	if err := b.SetState(nil, map[string]Limit{"192.168.1.40": {MAC: victimMAC.String()}}); err != nil {
		t.Fatal(err)
	}
	up := makeIPv4Frame(victimMAC, our, victimIP, serverIP, 60)
	if b.handleFrame(up) == nil {
		t.Fatal("up frame dropped")
	}
	down := makeIPv4Frame(b.gwMAC, our, serverIP, victimIP, 60)
	if b.handleFrame(down) == nil {
		t.Fatal("down frame dropped")
	}
	if len(taps) != 2 || taps[0] != (tapEvent{"192.168.1.40", true}) || taps[1] != (tapEvent{"192.168.1.40", false}) {
		t.Errorf("taps = %v, want [192.168.1.40 up, 192.168.1.40 down]", taps)
	}

	// blocked traffic is never relayed, so the tap must not fire
	blockedMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02}
	if err := b.SetState(map[string]string{"192.168.1.41": blockedMAC.String()}, nil); err != nil {
		t.Fatal(err)
	}
	if f := makeIPv4Frame(blockedMAC, our, net.IPv4(192, 168, 1, 41), serverIP, 60); b.handleFrame(f) != nil {
		t.Fatal("blocked frame relayed")
	}
	if len(taps) != 2 {
		t.Errorf("tap fired for blocked frame: %v", taps)
	}
}

func TestSpoofDNSForgesARecord(t *testing.T) {
	fn := &fakeNet{}
	b := testBlocker(fn)
	our := append(net.HardwareAddr(nil), b.ourMAC...)
	gw := append(net.HardwareAddr(nil), b.gwMAC...)
	victimMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03}
	victimIP := net.IPv4(192, 168, 1, 50)
	resolver := net.IPv4(8, 8, 8, 8)

	if err := b.SetState(nil, map[string]Limit{"192.168.1.50": {MAC: victimMAC.String()}}); err != nil {
		t.Fatal(err)
	}
	b.SetSpoof(func(domain string) string {
		if domain == "evil.example.com" {
			return "10.9.9.9"
		}
		return ""
	})

	// matching query is swallowed and answered
	q := makeDNSQuery(victimMAC, our, victimIP, resolver, "evil.example.com", 40000, 0xbeef)
	got := b.handleFrame(q)
	if got == nil {
		t.Fatal("spoofed query produced no response")
	}
	if !bytes.Equal(got[0:6], victimMAC) {
		t.Errorf("resp dst = %x, want victim %x", got[0:6], victimMAC)
	}
	if !bytes.Equal(got[6:12], our) {
		t.Errorf("resp src = %x, want our mac", got[6:12])
	}
	// IP: from the queried server to the victim
	if !bytes.Equal(got[26:30], resolver.To4()) || !bytes.Equal(got[30:34], victimIP.To4()) {
		t.Errorf("resp ip %x->%x, want %x->%x", got[26:30], got[30:34], resolver.To4(), victimIP.To4())
	}
	if got[23] != 17 {
		t.Errorf("resp proto = %d, want UDP", got[23])
	}
	l4 := 34
	if binary.BigEndian.Uint16(got[l4:l4+2]) != 53 {
		t.Errorf("resp sport = %d, want 53", binary.BigEndian.Uint16(got[l4:l4+2]))
	}
	if binary.BigEndian.Uint16(got[l4+2:l4+4]) != 40000 {
		t.Errorf("resp dport = %d, want 40000", binary.BigEndian.Uint16(got[l4+2:l4+4]))
	}
	dns := got[l4+8:]
	if dns[0] != 0xbe || dns[1] != 0xef {
		t.Errorf("resp txid = %x%x, want beef", dns[0], dns[1])
	}
	if dns[2]&0x80 == 0 {
		t.Error("resp QR bit not set")
	}
	// answer must carry 10.9.9.9
	if !bytes.Contains(dns, []byte{10, 9, 9, 9}) {
		t.Errorf("answer IP missing from dns payload: %x", dns)
	}
	if b.stSpoof.Load() != 1 {
		t.Errorf("stSpoof = %d, want 1", b.stSpoof.Load())
	}

	// non-matching query relays normally
	q2 := makeDNSQuery(victimMAC, our, victimIP, resolver, "other.test", 40001, 0x1111)
	got2 := b.handleFrame(q2)
	if got2 == nil {
		t.Fatal("non-matching query dropped")
	}
	if !bytes.Equal(got2[0:6], gw) {
		t.Errorf("non-matching dst = %x, want gateway (relayed)", got2[0:6])
	}
	if b.stSpoof.Load() != 1 {
		t.Errorf("stSpoof = %d, want 1 (no double count)", b.stSpoof.Load())
	}
}
