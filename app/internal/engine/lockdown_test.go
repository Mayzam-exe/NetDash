package engine

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"netdash/internal/arpblock"
	"netdash/internal/model"
)

// withArmEnforcement gives the engine a working ARP bridge so lockdown can be
// enforced. PutSettings refuses to engage a lockdown when nothing here can
// apply it, which is exactly what TestPutSettingsRejectsLockdown checks.
func withArmEnforcement(t *testing.T, e *Engine) {
	t.Helper()
	b := arpblock.New(
		net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
		net.ParseIP(e.Settings().GatewayIP),
		net.HardwareAddr{0x02, 0, 0, 0, 0, 2},
		func([]byte) error { return nil },
		10*time.Millisecond,
	)
	b.Start()
	t.Cleanup(b.Stop)
	e.mu.Lock()
	e.arp = b
	e.blockMode = "arp"
	e.arpReason = ""
	e.mu.Unlock()
}

func addTestDevice(e *Engine, id int64, ip string, mut ...func(*model.Device)) model.Device {
	d := model.Device{
		ID:       id,
		IP:       ip,
		MAC:      "aa:bb:cc:dd:ee:05",
		Name:     "device-" + ip,
		Priority: "normal",
	}
	if len(mut) > 0 && mut[0] != nil {
		mut[0](&d)
	}
	e.mu.Lock()
	e.devices[id] = d
	e.mu.Unlock()
	return d
}

// blockedIPs returns the block set the engine would apply right now.
func blockedIPs(e *Engine) map[string]bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	desired, _, _ := e.blockSetLocked(0, nil)
	out := map[string]bool{}
	for ip := range desired {
		out[ip] = true
	}
	return out
}

func TestEffectiveBlockedLockdown(t *testing.T) {
	now := time.Now()
	plain := model.Device{IP: "192.168.1.20"}
	trusted := model.Device{IP: "192.168.1.21", Trusted: true}
	manuallyBlocked := model.Device{IP: "192.168.1.22", Blocked: true}
	trustedButBlocked := model.Device{IP: "192.168.1.23", Trusted: true, Blocked: true}

	cases := []struct {
		name     string
		d        model.Device
		lockdown bool
		want     bool
	}{
		{"off: free device allowed", plain, false, false},
		{"on: free device cut off", plain, true, true},
		{"on: trusted survives", trusted, true, false},
		{"off: manual block still applies", manuallyBlocked, false, true},
		{"on: trusted does not override a manual block", trustedButBlocked, true, true},
	}
	for _, c := range cases {
		if got := effectiveBlocked(c.d, now, c.lockdown); got != c.want {
			t.Errorf("%s: effectiveBlocked = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestLockdownBlockSetExemptsSelfRouterAndTrusted is the core promise: with
// lockdown on, everyone except this machine, the router and the trusted
// devices is in the block set — and nothing else changes.
func TestLockdownBlockSetExemptsSelfRouterAndTrusted(t *testing.T) {
	e := newTestEngine(t)
	gw := e.Settings().GatewayIP

	addTestDevice(e, 1, "192.168.1.2", func(d *model.Device) { d.Self = true })
	addTestDevice(e, 2, gw) // the router
	addTestDevice(e, 3, "192.168.1.3", func(d *model.Device) { d.Trusted = true })
	addTestDevice(e, 4, "192.168.1.4")
	addTestDevice(e, 5, "192.168.1.5")

	s := e.Settings()
	s.Lockdown = true
	withArmEnforcement(t, e)
	if err := e.PutSettings(s); err != nil {
		t.Fatalf("engage lockdown: %v", err)
	}

	got := blockedIPs(e)
	for _, ip := range []string{"192.168.1.4", "192.168.1.5"} {
		if !got[ip] {
			t.Errorf("untrusted %s not blocked under lockdown", ip)
		}
	}
	for _, ip := range []string{"192.168.1.2", "192.168.1.3", gw} {
		if got[ip] {
			t.Errorf("%s must be exempt under lockdown", ip)
		}
	}
	if len(got) != 2 {
		t.Errorf("blocked %d devices, want exactly the 2 untrusted ones: %v", len(got), got)
	}
}

// TestPutSettingsRejectsLockdownWhenNothingCanEnforce keeps the switch honest:
// a lockdown the host cannot apply must be refused, not silently accepted.
func TestPutSettingsRejectsLockdownWhenNothingCanEnforce(t *testing.T) {
	e := newTestEngine(t) // no bridge, no firewall: enforcement is unavailable

	s := e.Settings()
	s.Lockdown = true
	err := e.PutSettings(s)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("PutSettings = %v, want ErrInvalid", err)
	}
	if e.Settings().Lockdown {
		t.Fatal("lockdown was committed despite being unenforceable")
	}
	// Turning it off is always allowed, enforceable or not.
	s.Lockdown = false
	if err := e.PutSettings(s); err != nil {
		t.Fatalf("release lockdown: %v", err)
	}
}

func TestPutSettingsLockdownEngagesAndReleases(t *testing.T) {
	e := newTestEngine(t)
	addTestDevice(e, 1, "192.168.1.4")
	withArmEnforcement(t, e)

	s := e.Settings()
	s.Lockdown = true
	if err := e.PutSettings(s); err != nil {
		t.Fatalf("engage: %v", err)
	}

	snap := e.Snapshot()
	if !snap.Status.Lockdown {
		t.Error("status does not report lockdown as engaged")
	}
	if len(snap.Devices) != 1 || !snap.Devices[0].Lockdown {
		t.Fatalf("snapshot device flags: %+v", snap.Devices)
	}
	if !hasAlert(snap.Alerts, "Lockdown engaged") {
		t.Error("no alert recorded when lockdown engaged")
	}

	s.Lockdown = false
	if err := e.PutSettings(s); err != nil {
		t.Fatalf("release: %v", err)
	}
	snap = e.Snapshot()
	if snap.Status.Lockdown {
		t.Error("status still reports lockdown after release")
	}
	if snap.Devices[0].Lockdown {
		t.Error("device still flagged as lockdown-cut after release")
	}
	if !hasAlert(snap.Alerts, "Lockdown released") {
		t.Error("no alert recorded when lockdown released")
	}
	if blockedIPs(e)["192.168.1.4"] {
		t.Error("device is still blocked after lockdown was released")
	}
}

// TestLockdownReleaseKeepsManualBlocks: disengaging must restore exactly the
// previous state rather than unblocking devices the admin had blocked.
func TestLockdownReleaseKeepsManualBlocks(t *testing.T) {
	e := newTestEngine(t)
	addTestDevice(e, 1, "192.168.1.4", func(d *model.Device) { d.Blocked = true })
	addTestDevice(e, 2, "192.168.1.5")
	withArmEnforcement(t, e)

	s := e.Settings()
	s.Lockdown = true
	if err := e.PutSettings(s); err != nil {
		t.Fatalf("engage: %v", err)
	}
	if len(blockedIPs(e)) != 2 {
		t.Fatalf("lockdown should block both devices: %v", blockedIPs(e))
	}

	s.Lockdown = false
	if err := e.PutSettings(s); err != nil {
		t.Fatalf("release: %v", err)
	}
	got := blockedIPs(e)
	if !got["192.168.1.4"] {
		t.Error("manual block was lost when lockdown was released")
	}
	if got["192.168.1.5"] {
		t.Error("device stayed blocked after lockdown was released")
	}
}

// TestTrustedPatchPersists: marking a device trusted is a real setting, so it
// has to survive a restart.
func TestTrustedPatchPersists(t *testing.T) {
	e := newTestEngine(t)
	// Discover the device the normal way so there is a real row to update.
	e.applyNeighbor("192.168.1.4", "aa:bb:cc:dd:ee:05", "Acme", time.Now().UnixMilli())
	var id int64
	for _, d := range e.Snapshot().Devices {
		if d.IP == "192.168.1.4" {
			id = d.ID
		}
	}
	if id == 0 {
		t.Fatal("device was not registered")
	}

	upd, err := e.UpdateDevice(id, DevicePatch{Trusted: boolPtr(true)})
	if err != nil {
		t.Fatalf("UpdateDevice: %v", err)
	}
	if !upd.Trusted {
		t.Fatal("trusted not applied to the returned device")
	}

	devs, err := e.st.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	found := false
	for _, d := range devs {
		if d.IP == "192.168.1.4" && d.Trusted {
			found = true
		}
	}
	if !found {
		t.Fatal("trusted flag was not persisted")
	}
}

// TestSnapshotMarksLockdownOnlyForUntrusted: a device that is blocked for its
// own reasons must not be reported as a lockdown casualty.
func TestSnapshotMarksLockdownOnlyForUntrusted(t *testing.T) {
	e := newTestEngine(t)
	gw := e.Settings().GatewayIP
	addTestDevice(e, 1, "192.168.1.2", func(d *model.Device) { d.Self = true })
	addTestDevice(e, 2, gw)
	addTestDevice(e, 3, "192.168.1.3", func(d *model.Device) { d.Trusted = true })
	addTestDevice(e, 4, "192.168.1.4")
	addTestDevice(e, 5, "192.168.1.5", func(d *model.Device) { d.Blocked = true })
	withArmEnforcement(t, e)

	s := e.Settings()
	s.Lockdown = true
	if err := e.PutSettings(s); err != nil {
		t.Fatalf("engage: %v", err)
	}

	want := map[int64]bool{1: false, 2: false, 3: false, 4: true, 5: false}
	for _, d := range e.Snapshot().Devices {
		if got, ok := want[d.ID]; ok && got != d.Lockdown {
			t.Errorf("device %d (%s): lockdown flag = %v, want %v", d.ID, d.IP, d.Lockdown, got)
		}
	}
}

// TestLockdownSurvivesRestart: the switch is persisted settings, so a restart
// must come back up still enforcing.
func TestLockdownSurvivesRestart(t *testing.T) {
	e := newTestEngine(t)
	addTestDevice(e, 1, "192.168.1.4")
	withArmEnforcement(t, e)

	s := e.Settings()
	s.Lockdown = true
	if err := e.PutSettings(s); err != nil {
		t.Fatalf("engage: %v", err)
	}

	got, err := e.st.GetSettings()
	if err != nil {
		t.Fatalf("GetSettings: %v", err)
	}
	if !got.Lockdown {
		t.Fatal("lockdown was not persisted")
	}
	if !blockedIPs(e)["192.168.1.4"] {
		t.Error("device not blocked while lockdown is engaged")
	}
}

func boolPtr(b bool) *bool { return &b }

func hasAlert(alerts []model.Alert, substr string) bool {
	for _, a := range alerts {
		if strings.Contains(a.Msg, substr) {
			return true
		}
	}
	return false
}
