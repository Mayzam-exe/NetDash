package engine

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"netdash/internal/arpblock"
)

func hasDeviceIP(e *Engine, ip string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, d := range e.devices {
		if d.IP == ip {
			return true
		}
	}
	return false
}

func TestGatewayAdoptNeedsTwoConfirmations(t *testing.T) {
	e := newTestEngine(t)
	base := e.Settings().GatewayIP
	det := ""
	e.gwDetect = func() string { return det }

	e.checkGateway() // no route detected → nothing happens
	if got := e.Settings().GatewayIP; got != base {
		t.Fatalf("empty detection changed gateway: %s", got)
	}

	det = "10.99.88.1"
	e.checkGateway() // first sighting → candidate only
	if got := e.Settings().GatewayIP; got != base {
		t.Fatalf("adopted before confirmation: %s", got)
	}

	det = "" // roaming blip resets the candidate
	e.checkGateway()
	det = "10.99.88.1"
	e.checkGateway() // first sighting again (not a resumed candidate)
	if got := e.Settings().GatewayIP; got != base {
		t.Fatalf("candidate survived an empty-route blip: %s", got)
	}

	e.checkGateway() // second confirmation → adopt
	if got := e.Settings().GatewayIP; got != "10.99.88.1" {
		t.Fatalf("gateway = %s, want 10.99.88.1", got)
	}
	persisted, err := e.st.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if persisted.GatewayIP != "10.99.88.1" {
		t.Errorf("persisted gateway = %s, want 10.99.88.1", persisted.GatewayIP)
	}

	e.checkGateway() // stable detection → no churn
	if got := e.Settings().GatewayIP; got != "10.99.88.1" {
		t.Errorf("stable detection changed gateway: %s", got)
	}

	e.mu.RLock()
	defer e.mu.RUnlock()
	found := false
	for _, a := range e.alerts {
		if strings.Contains(a.Msg, "adopted gateway 10.99.88.1") {
			found = true
		}
	}
	if !found {
		t.Error("no adoption alert recorded")
	}
}

func TestExpireOfflineDropsIdleUnconfiguredDevices(t *testing.T) {
	e := newTestEngine(t)
	now := time.Now().UnixMilli()
	gw := e.Settings().GatewayIP

	seed := func(ip, mac string) {
		e.applyNeighbor(ip, mac, "", now)
	}
	seed("192.168.1.70", "aa:bb:cc:dd:ee:70") // plain idle → expires
	seed("192.168.1.71", "aa:bb:cc:dd:ee:71") // fresh → kept
	seed("192.168.1.72", "aa:bb:cc:dd:ee:72") // blocked → kept
	seed("192.168.1.73", "aa:bb:cc:dd:ee:73") // watched → kept
	seed("192.168.1.74", "aa:bb:cc:dd:ee:74") // speed-limited → kept
	seed("192.168.1.75", "aa:bb:cc:dd:ee:75") // reserved → kept
	seed("192.168.1.76", "aa:bb:cc:dd:ee:76") // scheduled → kept
	seed("192.168.1.77", "aa:bb:cc:dd:ee:77") // priority set → kept
	seed(gw, "aa:bb:cc:dd:dd:01")             // gateway → kept
	seed("192.168.1.78", "aa:bb:cc:dd:ee:78") // this machine → kept
	seed("192.168.1.79", "aa:bb:cc:dd:ee:79") // manual kind → kept

	age := func(ip string) {
		d := deviceByIP(t, e, ip)
		old := time.Now().Add(-offlineExpireAfter - time.Minute)
		d.LastSeen = &old
		d.State = "offline"
		e.mu.Lock()
		e.devices[d.ID] = d
		e.mu.Unlock()
	}
	for _, ip := range []string{
		"192.168.1.70", "192.168.1.72", "192.168.1.73", "192.168.1.74",
		"192.168.1.75", "192.168.1.76", "192.168.1.77", gw,
		"192.168.1.78", "192.168.1.79",
	} {
		age(ip)
	}

	// Configure the exempt devices (directly: expiry reads the runtime map).
	d := deviceByIP(t, e, "192.168.1.72")
	d.Blocked = true
	e.devices[d.ID] = d
	d = deviceByIP(t, e, "192.168.1.73")
	d.Watched = true
	e.devices[d.ID] = d
	d = deviceByIP(t, e, "192.168.1.74")
	d.SpeedDown = 1000
	e.devices[d.ID] = d
	d = deviceByIP(t, e, "192.168.1.75")
	d.Reserved = true
	e.devices[d.ID] = d
	d = deviceByIP(t, e, "192.168.1.76")
	d.Schedule = "08:00-09:00"
	e.devices[d.ID] = d
	d = deviceByIP(t, e, "192.168.1.77")
	d.Priority = "high"
	e.devices[d.ID] = d
	d = deviceByIP(t, e, "192.168.1.78")
	d.Self = true
	e.devices[d.ID] = d
	e.manualKind[deviceByIP(t, e, "192.168.1.79").ID] = true

	// A never-seen record (nil LastSeen) must not be touched either.
	{
		d := deviceByIP(t, e, "192.168.1.71")
		d.ID = 9999
		d.IP = "192.168.1.80"
		d.LastSeen = nil
		e.mu.Lock()
		e.devices[9999] = d
		e.mu.Unlock()
	}

	e.expireOffline()

	kept := []string{
		"192.168.1.71", "192.168.1.72", "192.168.1.73", "192.168.1.74",
		"192.168.1.75", "192.168.1.76", "192.168.1.77", gw,
		"192.168.1.78", "192.168.1.79", "192.168.1.80",
	}
	for _, ip := range kept {
		if !hasDeviceIP(e, ip) {
			t.Errorf("device %s should be kept", ip)
		}
	}
	if hasDeviceIP(e, "192.168.1.70") {
		t.Error("idle unconfigured device should be removed")
	}

	// The record must be gone from the store too, not just the map.
	devs, err := e.st.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	for _, d := range devs {
		if d.IP == "192.168.1.70" {
			t.Error("expired device still in store")
		}
	}
}

// TestCheckBridgeReopensDeadBridge: the poison ticker and relay loop exit
// permanently on socket errors (wifi bounce, carrier loss) with no cleanup,
// so supervision must detect the dead bridge and reopen it — otherwise
// limits/intel/spoof stay dead until a daemon restart.
func TestCheckBridgeReopensDeadBridge(t *testing.T) {
	e := newTestEngine(t)

	// A bridge whose sender always fails: the refresh ticker dies on its
	// first send (SetState still converges, so a victim exists to send for).
	b := arpblock.New(
		net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		net.ParseIP("192.168.1.1"),
		net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		func([]byte) error { return errors.New("network is down") },
		10*time.Millisecond,
	)
	_ = b.SetState(map[string]string{"192.168.1.50": "aa:bb:cc:dd:ee:50"}, nil)
	b.Start()
	e.mu.Lock()
	e.arp = b
	e.blockMode = "arp"
	e.mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for b.Alive() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if b.Alive() {
		t.Fatal("refresh ticker did not die on send errors")
	}

	e.checkBridge()

	if b.Alive() {
		t.Error("dead bridge was not torn down")
	}
	e.mu.RLock()
	cur := e.arp
	e.mu.RUnlock()
	if cur == b {
		t.Fatal("bridge was not reopened")
	}
	// Tests run unprivileged: reopening normally fails the raw-socket open
	// and the engine records the reason instead of a live bridge.
	if cur != nil && !cur.Alive() {
		t.Error("replacement bridge is not alive")
	}
}

// TestCheckBridgeLeavesHealthyBridgeAlone: no teardown churn while loops run.
func TestCheckBridgeLeavesHealthyBridgeAlone(t *testing.T) {
	e := newTestEngine(t)
	b := arpblock.New(
		net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		net.ParseIP("192.168.1.1"),
		net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		func([]byte) error { return nil },
		10*time.Millisecond,
	)
	b.Start()
	e.mu.Lock()
	e.arp = b
	e.blockMode = "arp"
	e.mu.Unlock()
	defer b.Stop()

	e.checkBridge()

	e.mu.RLock()
	cur := e.arp
	e.mu.RUnlock()
	if cur != b {
		t.Fatal("healthy bridge was replaced")
	}
	if !b.Alive() {
		t.Fatal("healthy bridge stopped")
	}
}
