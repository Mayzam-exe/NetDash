package engine

import (
	"errors"
	"strings"
	"testing"
	"time"

	"netdash/internal/model"
)

func boolp(v bool) *bool { return &v }

func TestWatchedValidation(t *testing.T) {
	e := newTestEngine(t)

	e.applyNeighbor("192.168.1.60", "aa:bb:cc:dd:ee:60", "", time.Now().UnixMilli())
	d := deviceByIP(t, e, "192.168.1.60")

	// intercept requires arp (laptop) mode; sandbox has no raw-socket cap
	if _, err := e.UpdateDevice(d.ID, DevicePatch{Watched: boolp(true)}); !errors.Is(err, ErrInvalid) ||
		!strings.Contains(err.Error(), "intercept unavailable") {
		t.Errorf("watch without arp mode: err=%v, want ErrInvalid intercept unavailable", err)
	}

	// this machine can never be intercepted
	e.mu.Lock()
	selfID := int64(-1)
	e.devices[selfID] = model.Device{ID: selfID, IP: "10.9.9.9", Self: true, Name: "This machine"}
	e.mu.Unlock()
	if _, err := e.UpdateDevice(selfID, DevicePatch{Watched: boolp(true)}); !errors.Is(err, ErrInvalid) ||
		!strings.Contains(err.Error(), "cannot intercept this machine") {
		t.Errorf("self intercept: err=%v, want cannot intercept this machine", err)
	}
	e.mu.Lock()
	delete(e.devices, selfID)
	e.mu.Unlock()

	// the gateway can never be intercepted
	e.mu.Lock()
	gwID := int64(-2)
	e.devices[gwID] = model.Device{ID: gwID, IP: e.settings.GatewayIP, Name: "Gateway"}
	e.mu.Unlock()
	if _, err := e.UpdateDevice(gwID, DevicePatch{Watched: boolp(true)}); !errors.Is(err, ErrInvalid) ||
		!strings.Contains(err.Error(), "cannot intercept the gateway") {
		t.Errorf("gw intercept: err=%v, want cannot intercept the gateway", err)
	}
	e.mu.Lock()
	delete(e.devices, gwID)
	e.mu.Unlock()

	// turning intercept off must always be accepted
	e.mu.Lock()
	cur := e.devices[d.ID]
	cur.Watched = true
	e.devices[d.ID] = cur
	e.mu.Unlock()
	if _, err := e.UpdateDevice(d.ID, DevicePatch{Watched: boolp(false)}); err != nil {
		t.Errorf("clearing intercept while unavailable: err=%v, want nil", err)
	}
	if got := deviceByIP(t, e, "192.168.1.60").Watched; got {
		t.Error("watched still true after clear")
	}
}

func TestBlockSetWatchedIntercept(t *testing.T) {
	e := newTestEngine(t)
	e.applyNeighbor("192.168.1.61", "aa:bb:cc:dd:ee:61", "", time.Now().UnixMilli())
	d := deviceByIP(t, e, "192.168.1.61")

	// watched alone: unlimited relay (Down=Up=0) with the device MAC
	e.mu.Lock()
	cur := e.devices[d.ID]
	cur.Watched = true
	e.devices[d.ID] = cur
	_, limited, _ := e.blockSetLocked(0, nil)
	e.mu.Unlock()
	lim, ok := limited["192.168.1.61"]
	if !ok || lim.Down != 0 || lim.Up != 0 || lim.MAC == "" {
		t.Errorf("limited = %v, want {MAC, Down:0, Up:0}", limited)
	}

	// a speed limit wins over watched (same entry, real rates)
	e.mu.Lock()
	cur = e.devices[d.ID]
	cur.SpeedDown, cur.SpeedUp = 3000, 750
	e.devices[d.ID] = cur
	_, limited, _ = e.blockSetLocked(0, nil)
	e.mu.Unlock()
	if lim := limited["192.168.1.61"]; lim.Down != 3000 || lim.Up != 750 {
		t.Errorf("limited = %v, want speed rates to win", limited)
	}

	// blocked wins over everything
	e.mu.Lock()
	cur = e.devices[d.ID]
	cur.Blocked = true
	e.devices[d.ID] = cur
	desired, limited, _ := e.blockSetLocked(0, nil)
	e.mu.Unlock()
	if _, blocked := desired["192.168.1.61"]; !blocked {
		t.Error("blocked device missing from block set")
	}
	if _, still := limited["192.168.1.61"]; still {
		t.Error("blocked device must not also be relayed for intel")
	}
}

func TestSpoofRuleCRUDAndMatch(t *testing.T) {
	e := newTestEngine(t)

	r, err := e.PutSpoofRule("Evil.Example.com", "10.9.9.9")
	if err != nil {
		t.Fatalf("PutSpoofRule: %v", err)
	}
	if r.Domain != "evil.example.com" || r.IP != "10.9.9.9" {
		t.Errorf("rule = %+v, want normalized domain + ip", r)
	}

	if _, err := e.PutSpoofRule("bad domain", "10.9.9.9"); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad domain: err=%v, want ErrInvalid", err)
	}
	if _, err := e.PutSpoofRule("ok.example.com", "not-an-ip"); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad ip: err=%v, want ErrInvalid", err)
	}
	if _, err := e.PutSpoofRule("ok.example.com", "2001:db8::1"); !errors.Is(err, ErrInvalid) {
		t.Errorf("ipv6: err=%v, want ErrInvalid", err)
	}

	// exact + subdomain match
	if got := e.spoofMatch("evil.example.com"); got != "10.9.9.9" {
		t.Errorf("exact match = %q, want 10.9.9.9", got)
	}
	if got := e.spoofMatch("a.b.evil.example.com"); got != "10.9.9.9" {
		t.Errorf("suffix match = %q, want 10.9.9.9", got)
	}
	if got := e.spoofMatch("example.org"); got != "" {
		t.Errorf("unrelated = %q, want \"\"", got)
	}

	rules, err := e.SpoofRules()
	if err != nil || len(rules) != 1 {
		t.Fatalf("SpoofRules = %v, %v; want 1 rule", rules, err)
	}
	if err := e.DelSpoofRule(r.ID); err != nil {
		t.Fatalf("DelSpoofRule: %v", err)
	}
	if got := e.spoofMatch("evil.example.com"); got != "" {
		t.Errorf("after delete match = %q, want \"\"", got)
	}
}

func TestIntelPipeline(t *testing.T) {
	e := newTestEngine(t)
	e.applyNeighbor("192.168.1.62", "aa:bb:cc:dd:ee:62", "", time.Now().UnixMilli())
	d := deviceByIP(t, e, "192.168.1.62")

	// hand a DNS-query frame to the tap
	frame := testDNSFrame()
	e.tapRelay("192.168.1.62", true, frame)

	deadline := time.Now().Add(2 * time.Second)
	for {
		items, err := e.IntelFor(d.ID, 50)
		if err != nil {
			t.Fatalf("IntelFor: %v", err)
		}
		if len(items) > 0 {
			if items[0].Kind != "dns" || items[0].Value != "tracker.example.net" {
				t.Errorf("intel[0] = %+v, want dns tracker.example.net", items[0])
			}
			// duplicate frame within the dedup window must not add a row
			e.tapRelay("192.168.1.62", true, frame)
			time.Sleep(150 * time.Millisecond)
			items2, _ := e.IntelFor(d.ID, 50)
			if len(items2) != 1 {
				t.Errorf("dedup: rows = %d, want 1", len(items2))
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("intel row never appeared")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// testDNSFrame mirrors the layout the arp-blocker tap forwards.
func testDNSFrame() []byte {
	name := "tracker.example.net"
	var q []byte
	for _, lab := range strings.Split(name, ".") {
		q = append(q, byte(len(lab)))
		q = append(q, lab...)
	}
	q = append(q, 0, 0x00, 0x01, 0x00, 0x01)
	dns := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	dns = append(dns, q...)

	f := make([]byte, 14+20+8+len(dns))
	f[12], f[13] = 0x08, 0x00
	f[14] = 0x45
	f[22] = 64
	f[23] = 17
	l4 := 34
	f[l4+2], f[l4+3] = 0, 53 // dport 53
	copy(f[l4+8:], dns)
	return f
}

// TestIntelTLSFingerprints feeds a real TLS ClientHello through the tap and
// asserts all three findings (sni + ja3 + ja4) reach the store — the
// encrypted-traffic intel path end to end.
func TestIntelTLSFingerprints(t *testing.T) {
	e := newTestEngine(t)
	e.applyNeighbor("192.168.1.63", "aa:bb:cc:dd:ee:63", "", time.Now().UnixMilli())
	d := deviceByIP(t, e, "192.168.1.63")

	e.tapRelay("192.168.1.63", true, testClientHelloFrame())

	kinds := map[string]string{}
	deadline := time.Now().Add(2 * time.Second)
	for len(kinds) < 3 {
		items, err := e.IntelFor(d.ID, 50)
		if err != nil {
			t.Fatalf("IntelFor: %v", err)
		}
		for _, it := range items {
			kinds[it.Kind] = it.Value
		}
		if time.Now().After(deadline) {
			t.Fatalf("missing TLS findings, have: %v", kinds)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if kinds["sni"] != "example.com" {
		t.Errorf("sni = %q, want example.com", kinds["sni"])
	}
	if len(kinds["ja3"]) != 32 {
		t.Errorf("ja3 = %q, want 32 hex chars", kinds["ja3"])
	}
	if ja4 := kinds["ja4"]; !strings.HasPrefix(ja4, "t13d0203h2_") || len(ja4) != 36 {
		t.Errorf("ja4 = %q, want t13d0203h2_<12>_<12>", ja4)
	}
}

// testClientHelloFrame builds eth+IPv4+TCP carrying a TLS1.3 ClientHello
// (SNI example.com, ciphers 1301/1302, ALPN h2, supported_versions 0304).
func testClientHelloFrame() []byte {
	sniName := []byte("example.com")
	sniEntry := []byte{0x00, byte(len(sniName) >> 8), byte(len(sniName))}
	sniEntry = append(sniEntry, sniName...)
	sniBody := []byte{byte(len(sniEntry) >> 8), byte(len(sniEntry))}
	sniBody = append(sniBody, sniEntry...)

	alpnBody := []byte{0x00, 0x03, 0x02, 'h', '2'} // listlen=3, entry: len=2 "h2"
	verBody := []byte{0x02, 0x03, 0x04}            // u8 bytelen=2, version 0304

	ext := func(typ uint16, body []byte) []byte {
		e := []byte{byte(typ >> 8), byte(typ), byte(len(body) >> 8), byte(len(body))}
		return append(e, body...)
	}
	var exts []byte
	exts = append(exts, ext(0x0000, sniBody)...)
	exts = append(exts, ext(0x0010, alpnBody)...)
	exts = append(exts, ext(0x002b, verBody)...)

	ch := []byte{0x03, 0x03} // client version
	ch = append(ch, make([]byte, 32)...)
	ch = append(ch, 0x00)                               // session id
	ch = append(ch, 0x00, 0x04, 0x13, 0x01, 0x13, 0x02) // ciphers
	ch = append(ch, 0x01, 0x00)                         // compression
	ch = append(ch, byte(len(exts)>>8), byte(len(exts)))
	ch = append(ch, exts...)

	hs := []byte{0x01, byte(len(ch) >> 16), byte(len(ch) >> 8), byte(len(ch))}
	hs = append(hs, ch...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	rec = append(rec, hs...)

	f := make([]byte, 14+20+20+len(rec))
	f[12], f[13] = 0x08, 0x00
	f[14] = 0x45
	f[22] = 64
	f[23] = 6
	l4 := 34
	f[l4], f[l4+1] = 0xC3, 0x50   // sport 50000
	f[l4+2], f[l4+3] = 0x01, 0xBB // dport 443
	f[l4+12] = 0x50               // data offset 5
	f[l4+13] = 0x18               // PSH+ACK
	copy(f[l4+20:], rec)
	return f
}
