package arpblock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func parseReply(f []byte) (dst, src, sha net.HardwareAddr, spa net.IP, tha net.HardwareAddr, tpa net.IP, op uint16, ok bool) {
	if len(f) != 42 || binary.BigEndian.Uint16(f[12:14]) != etherTypeARP {
		return nil, nil, nil, nil, nil, nil, 0, false
	}
	dst = append(net.HardwareAddr(nil), f[0:6]...)
	src = append(net.HardwareAddr(nil), f[6:12]...)
	op = binary.BigEndian.Uint16(f[20:22])
	sha = append(net.HardwareAddr(nil), f[22:28]...)
	spa = net.IP(append([]byte(nil), f[28:32]...))
	tha = append(net.HardwareAddr(nil), f[32:38]...)
	tpa = net.IP(append([]byte(nil), f[38:42]...))
	return dst, src, sha, spa, tha, tpa, op, true
}

type fakeNet struct {
	mu     sync.Mutex
	frames [][]byte
}

func (f *fakeNet) send(b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.frames = append(f.frames, append([]byte(nil), b...))
	return nil
}

func (f *fakeNet) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.frames)
}

func testBlocker(fn *fakeNet) *Blocker {
	return New(
		net.HardwareAddr{0x14, 0xca, 0x56, 0x9e, 0x4d, 0x49},
		net.IPv4(192, 168, 1, 1),
		net.HardwareAddr{0x14, 0xca, 0x56, 0x9e, 0x4d, 0x01},
		fn.send,
		50*time.Millisecond,
	)
}

func (f *fakeNet) frameAt(i int) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.frames[i]
}

func TestSetStatePoisonsBothDirections(t *testing.T) {
	fn := &fakeNet{}
	b := testBlocker(fn)
	if err := b.SetState(map[string]string{"192.168.1.23": "aa:bb:cc:dd:ee:ff"}, nil); err != nil {
		t.Fatal(err)
	}
	// burst=3 rounds × 2 directions
	if fn.count() != 6 {
		t.Fatalf("frames = %d, want 6", fn.count())
	}
	victim, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	gw, _ := net.ParseMAC("14:ca:56:9e:4d:01")
	ours := net.HardwareAddr{0x14, 0xca, 0x56, 0x9e, 0x4d, 0x49}

	// Round 1: victim told "gateway is me"; gateway told "victim is me".
	dst, _, sha, spa, tha, tpa, op, ok := parseReply(fn.frames[0])
	if !ok || op != arpOpReply {
		t.Fatalf("frame 0 not an arp reply")
	}
	if !bytes.Equal(dst, victim) || !bytes.Equal(sha, ours) || !spa.Equal(net.IPv4(192, 168, 1, 1)) || !bytes.Equal(tha, victim) || !tpa.Equal(net.IPv4(192, 168, 1, 23)) {
		t.Errorf("poison-to-victim wrong: dst=%v sha=%v spa=%v tha=%v tpa=%v", dst, sha, spa, tha, tpa)
	}
	dst, _, sha, spa, tha, tpa, _, _ = parseReply(fn.frames[1])
	if !bytes.Equal(dst, gw) || !bytes.Equal(sha, ours) || !spa.Equal(net.IPv4(192, 168, 1, 23)) || !tpa.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Errorf("poison-to-gateway wrong: dst=%v sha=%v spa=%v tpa=%v", dst, sha, spa, tpa)
	}
	if _, ok := b.Active()["192.168.1.23"]; !ok {
		t.Errorf("active not recorded")
	}
}

func TestReconcileIdempotentAndRepairs(t *testing.T) {
	fn := &fakeNet{}
	b := testBlocker(fn)
	desired := map[string]string{"192.168.1.23": "aa:bb:cc:dd:ee:ff"}
	_ = b.SetState(desired, nil)
	n := fn.count()
	_ = b.SetState(desired, nil)
	if fn.count() != n {
		t.Errorf("second identical SetState sent %d extra frames", fn.count()-n)
	}

	// Unblock: repairs must carry the REAL gateway MAC as sender.
	_ = b.SetState(map[string]string{}, nil)
	if fn.count() != n+6 {
		t.Fatalf("repair frames = %d, want 6", fn.count()-n)
	}
	victim, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	gw, _ := net.ParseMAC("14:ca:56:9e:4d:01")
	dst, _, sha, spa, _, _, _, _ := parseReply(fn.frameAt(n))
	if !bytes.Equal(dst, victim) || !bytes.Equal(sha, gw) || !spa.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Errorf("repair-to-victim should come from real gw: dst=%v sha=%v spa=%v", dst, sha, spa)
	}
	dst, _, sha, spa, _, _, _, _ = parseReply(fn.frameAt(n + 1))
	if !bytes.Equal(dst, gw) || !bytes.Equal(sha, victim) || !spa.Equal(net.IPv4(192, 168, 1, 23)) {
		t.Errorf("repair-to-gateway should come from real victim: dst=%v sha=%v spa=%v", dst, sha, spa)
	}
	if len(b.Active()) != 0 {
		t.Errorf("active not cleared")
	}
}

func TestTickerRefreshesPoison(t *testing.T) {
	fn := &fakeNet{}
	b := testBlocker(fn)
	_ = b.SetState(map[string]string{"192.168.1.23": "aa:bb:cc:dd:ee:ff"}, nil)
	b.Start()
	defer b.Stop()
	time.Sleep(130 * time.Millisecond) // interval 50ms → ≥2 ticks × 2 frames
	if fn.count() < 6+4 {
		t.Errorf("ticker sent too few frames: %d", fn.count())
	}
}

func TestStopRepairsAndRefuses(t *testing.T) {
	fn := &fakeNet{}
	b := testBlocker(fn)
	_ = b.SetState(map[string]string{"192.168.1.23": "aa:bb:cc:dd:ee:ff"}, nil)
	b.Start()
	b.Stop()
	if len(b.Active()) != 0 {
		t.Errorf("active not cleared on stop")
	}
	if err := b.SetState(map[string]string{"192.168.1.24": "aa:bb:cc:dd:ee:00"}, nil); err == nil {
		t.Errorf("SetState after Stop should fail")
	}
	b.Stop() // idempotent
}

func TestRepairSkipsStillBlocked(t *testing.T) {
	fn := &fakeNet{}
	b := testBlocker(fn)
	desired := map[string]string{"192.168.1.23": "aa:bb:cc:dd:ee:ff"}
	_ = b.SetState(desired, nil)
	n := fn.count()
	stale := map[string]string{
		"192.168.1.23": "aa:bb:cc:dd:ee:ff", // still blocked → no repair
		"192.168.1.44": "aa:bb:cc:dd:ee:44", // crashed leftover → repair
	}
	if err := b.Repair(stale); err != nil {
		t.Fatal(err)
	}
	if fn.count() != n+6 {
		t.Errorf("stale repair frames = %d, want 6", fn.count()-n)
	}
}

func TestReplyFrameBytes(t *testing.T) {
	f := replyFrame(
		net.HardwareAddr{1, 2, 3, 4, 5, 6},
		net.HardwareAddr{6, 5, 4, 3, 2, 1},
		net.HardwareAddr{6, 5, 4, 3, 2, 1},
		net.IPv4(10, 0, 0, 1),
		net.HardwareAddr{1, 2, 3, 4, 5, 6},
		net.IPv4(10, 0, 0, 2),
	)
	want := []byte{
		1, 2, 3, 4, 5, 6, // dst
		6, 5, 4, 3, 2, 1, // src
		0x08, 0x06, // ethertype ARP
		0x00, 0x01, // htype ethernet
		0x08, 0x00, // ptype IPv4
		6, 4, // hlen plen
		0x00, 0x02, // op reply
		6, 5, 4, 3, 2, 1, // sender mac
		10, 0, 0, 1, // sender ip
		1, 2, 3, 4, 5, 6, // target mac
		10, 0, 0, 2, // target ip
	}
	if len(f) != len(want) {
		t.Fatalf("len %d want %d", len(f), len(want))
	}
	for i := range want {
		if f[i] != want[i] {
			t.Fatalf("byte %d = %#x want %#x", i, f[i], want[i])
		}
	}
}

/* ---------- speed limiting (arp bridge shaper) ---------- */

func TestSetStateLimitedPoisonsAndSeparatesFromBlocked(t *testing.T) {
	fn := &fakeNet{}
	b := testBlocker(fn)
	lim := map[string]Limit{"192.168.1.30": {MAC: "aa:bb:cc:dd:ee:ff", Down: 5000, Up: 1000}}

	if err := b.SetState(nil, lim); err != nil {
		t.Fatal(err)
	}
	if fn.count() == 0 {
		t.Error("limited victim was not poisoned")
	}
	if got := b.ActiveBlocked(); len(got) != 0 {
		t.Errorf("limited victim reported as blocked: %v", got)
	}
	if got := b.Active(); len(got) != 1 {
		t.Errorf("Active() = %v, want the limited victim", got)
	}

	// blocked wins over the limit for the same IP
	if err := b.SetState(map[string]string{"192.168.1.30": "aa:bb:cc:dd:ee:ff"}, lim); err != nil {
		t.Fatal(err)
	}
	if got := b.ActiveBlocked(); len(got) != 1 {
		t.Errorf("blocked should win: ActiveBlocked() = %v", got)
	}

	// rate-only change on a still-poisoned victim sends no ARP frames
	fn.frames = nil
	if err := b.SetState(nil, map[string]Limit{"192.168.1.30": {MAC: "aa:bb:cc:dd:ee:ff", Down: 100, Up: 100}}); err != nil {
		t.Fatal(err)
	}
	if n := fn.count(); n != 0 {
		t.Errorf("rate change resent %d arp frames, want 0", n)
	}

	// clearing everything repairs the caches
	fn.frames = nil
	if err := b.SetState(nil, nil); err != nil {
		t.Fatal(err)
	}
	if fn.count() == 0 {
		t.Error("clearing limits did not send repair frames")
	}
	if got := b.Active(); len(got) != 0 {
		t.Errorf("Active() after clear = %v", got)
	}
}

func makeIPv4Frame(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, payload int) []byte {
	f := make([]byte, 14+20+payload)
	copy(f[0:6], dstMAC)
	copy(f[6:12], srcMAC)
	binary.BigEndian.PutUint16(f[12:14], etherTypeIPv4)
	copy(f[26:30], srcIP.To4())
	copy(f[30:34], dstIP.To4())
	return f
}

func TestHandleFrameRelay(t *testing.T) {
	fn := &fakeNet{}
	b := testBlocker(fn)
	our := append(net.HardwareAddr(nil), b.ourMAC...)
	gw := append(net.HardwareAddr(nil), b.gwMAC...)
	victimMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	victimIP := net.IPv4(192, 168, 1, 30)
	serverIP := net.IPv4(93, 184, 216, 34)

	if err := b.SetState(nil, map[string]Limit{"192.168.1.30": {MAC: victimMAC.String(), Down: 5000, Up: 1000}}); err != nil {
		t.Fatal(err)
	}

	// up: victim -> server, arrives at our MAC, must leave toward the gateway
	up := makeIPv4Frame(victimMAC, our, victimIP, serverIP, 100)
	got := b.handleFrame(up)
	if got == nil {
		t.Fatal("up frame dropped")
	}
	if !bytes.Equal(got[0:6], gw) {
		t.Errorf("up dst mac = %x, want gateway %x", got[0:6], gw)
	}
	if !bytes.Equal(got[6:12], our) {
		t.Errorf("up src mac = %x, want our mac %x (spoofed sources trip APs)", got[6:12], our)
	}

	// down: server -> victim, must leave toward the victim
	down := makeIPv4Frame(gw, our, serverIP, victimIP, 100)
	got = b.handleFrame(down)
	if got == nil {
		t.Fatal("down frame dropped")
	}
	if !bytes.Equal(got[0:6], victimMAC) {
		t.Errorf("down dst mac = %x, want victim %x", got[0:6], victimMAC)
	}
	if !bytes.Equal(got[6:12], our) {
		t.Errorf("down src mac = %x, want our mac %x", got[6:12], our)
	}

	// frames not addressed to us are ignored
	if f := makeIPv4Frame(victimMAC, net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}, victimIP, serverIP, 50); b.handleFrame(f) != nil {
		t.Error("frame for another host was relayed")
	}

	// non-IPv4 frames are ignored
	arpFrame := make([]byte, 42)
	copy(arpFrame[0:6], our)
	binary.BigEndian.PutUint16(arpFrame[12:14], etherTypeARP)
	if b.handleFrame(arpFrame) != nil {
		t.Error("ARP frame was relayed")
	}
}

func TestHandleFrameBlockedDrops(t *testing.T) {
	fn := &fakeNet{}
	b := testBlocker(fn)
	our := append(net.HardwareAddr(nil), b.ourMAC...)
	victimMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	victimIP := net.IPv4(192, 168, 1, 31)

	if err := b.SetState(map[string]string{"192.168.1.31": victimMAC.String()}, nil); err != nil {
		t.Fatal(err)
	}
	up := makeIPv4Frame(victimMAC, our, victimIP, net.IPv4(1, 2, 3, 4), 100)
	if b.handleFrame(up) != nil {
		t.Error("blocked up frame was relayed")
	}
	down := makeIPv4Frame(b.gwMAC, our, net.IPv4(1, 2, 3, 4), victimIP, 100)
	if b.handleFrame(down) != nil {
		t.Error("blocked down frame was relayed")
	}
	// unknown IPs are dropped too
	stranger := makeIPv4Frame(victimMAC, our, net.IPv4(192, 168, 1, 99), net.IPv4(1, 2, 3, 4), 100)
	if b.handleFrame(stranger) != nil {
		t.Error("unknown source frame was relayed")
	}
}

func TestBucketRateLimit(t *testing.T) {
	var bkt bucket
	now := time.Now()
	// 1000 kbit/s = 125000 B/s; bucket starts full (cap = 1s of rate)
	if !bkt.take(now, 1000, 120_000) {
		t.Fatal("first burst should pass from a full bucket")
	}
	if bkt.take(now, 1000, 120_000) {
		t.Error("second burst should be starved (only ~5 KB left)")
	}
	if bkt.take(now.Add(100*time.Millisecond), 1000, 120_000) {
		t.Error("100ms of refill must not cover a 120 KB frame burst")
	}
	if !bkt.take(now.Add(2*time.Second), 1000, 125_000) {
		t.Error("full refill after idle should cover one second of traffic")
	}
	var unlimited bucket
	if !unlimited.take(now, 0, 1<<30) {
		t.Error("unlimited direction must always pass")
	}
}

func makeARPRequest(srcMAC net.HardwareAddr, srcIP, tpa net.IP) []byte {
	f := make([]byte, 42)
	for i := 0; i < 6; i++ {
		f[i] = 0xff // broadcast
	}
	copy(f[6:12], srcMAC)
	binary.BigEndian.PutUint16(f[12:14], etherTypeARP)
	binary.BigEndian.PutUint16(f[14:16], 1)
	binary.BigEndian.PutUint16(f[16:18], 0x0800)
	f[18] = 6
	f[19] = 4
	binary.BigEndian.PutUint16(f[20:22], arpOpRequest)
	copy(f[22:28], srcMAC)
	copy(f[28:32], srcIP.To4())
	copy(f[38:42], tpa.To4())
	return f
}

func TestHandleARPPoisonAnswers(t *testing.T) {
	fn := &fakeNet{}
	b := testBlocker(fn)
	b.ourIP = net.IPv4(192, 168, 1, 48)
	our := append(net.HardwareAddr(nil), b.ourMAC...)
	victimMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	victimIP := net.IPv4(192, 168, 1, 30)

	if err := b.SetState(nil, map[string]Limit{"192.168.1.30": {MAC: victimMAC.String(), Down: 5000, Up: 1000}}); err != nil {
		t.Fatal(err)
	}

	// gateway asks for the victim -> "victim is at my MAC" (solicited)
	got := b.handleARP(makeARPRequest(b.gwMAC, net.IPv4(192, 168, 1, 1), victimIP))
	if got == nil {
		t.Fatal("gateway's request for a poisoned victim was not answered")
	}
	if !bytes.Equal(got[0:6], b.gwMAC) || !bytes.Equal(got[6:12], our) {
		t.Errorf("reply dst/src = %x/%x", got[0:6], got[6:12])
	}
	if !bytes.Equal(got[22:28], our) || net.IP(got[28:32]).String() != "192.168.1.30" {
		t.Errorf("reply sha/spa = %x / %s", got[22:28], net.IP(got[28:32]))
	}
	if net.IP(got[38:42]).String() != "192.168.1.1" {
		t.Errorf("reply tpa = %s", net.IP(got[38:42]))
	}

	// poisoned victim asks for the gateway -> "gateway is at my MAC"
	got = b.handleARP(makeARPRequest(victimMAC, victimIP, net.IPv4(192, 168, 1, 1)))
	if got == nil {
		t.Fatal("victim's request for the gateway was not answered")
	}
	if net.IP(got[28:32]).String() != "192.168.1.1" {
		t.Errorf("reply spa = %s, want gateway", net.IP(got[28:32]))
	}

	// a stranger asking about the victim is not answered
	if b.handleARP(makeARPRequest(victimMAC, net.IPv4(192, 168, 1, 99), victimIP)) != nil {
		t.Error("stranger's request was answered")
	}
	// our own probes are never answered (would poison ourselves)
	self := net.HardwareAddr{0x14, 0xca, 0x56, 0x9e, 0x4d, 0x49}
	if b.handleARP(makeARPRequest(self, net.IPv4(192, 168, 1, 48), victimIP)) != nil {
		t.Error("our own request was answered")
	}
	// gateway asking for a non-poisoned host is not answered
	if b.handleARP(makeARPRequest(b.gwMAC, net.IPv4(192, 168, 1, 1), net.IPv4(192, 168, 1, 77))) != nil {
		t.Error("gateway's request for a normal host was answered")
	}
}

// TestAliveFalseWhenRefreshDies: a socket send error kills the refresh
// ticker permanently; Alive must notice so supervision can reopen.
func TestAliveFalseWhenRefreshDies(t *testing.T) {
	var mu sync.Mutex
	fail := false
	b := New(
		net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		net.IPv4(192, 168, 1, 1),
		net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		func([]byte) error {
			mu.Lock()
			defer mu.Unlock()
			if fail {
				return errors.New("network is down")
			}
			return nil
		},
		10*time.Millisecond,
	)
	if err := b.SetState(map[string]string{"192.168.1.50": "aa:bb:cc:dd:ee:50"}, nil); err != nil {
		t.Fatalf("SetState: %v", err)
	}
	b.Start()
	if !b.Alive() {
		t.Fatal("not alive after Start")
	}
	mu.Lock()
	fail = true
	mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for b.Alive() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if b.Alive() {
		t.Fatal("refresh death not detected")
	}
	b.Stop() // must not hang on already-dead loops
}

// TestAliveFalseAfterStop: Stop marks the bridge not alive.
func TestAliveFalseAfterStop(t *testing.T) {
	b := testBlocker(&fakeNet{})
	b.Start()
	if !b.Alive() {
		t.Fatal("not alive after Start")
	}
	b.Stop()
	if b.Alive() {
		t.Fatal("alive after Stop")
	}
}
