package engine

import (
	"testing"
	"time"

	"netdash/internal/model"
	"netdash/internal/netinfo"
)

// storedDevice writes a row the way discovery would and mirrors it into the
// engine's map, so persistence assertions have something to read back.
func storedDevice(t *testing.T, e *Engine, ip, name string, self bool) model.Device {
	t.Helper()
	d, _, err := e.st.UpsertDevice(ip, "02:00:00:00:00:01", "", time.Now().UnixMilli())
	if err != nil {
		t.Fatalf("UpsertDevice(%s): %v", ip, err)
	}
	d.Name = name
	d.Self = self
	if err := e.st.SaveDevice(d); err != nil {
		t.Fatalf("SaveDevice(%s): %v", ip, err)
	}
	e.mu.Lock()
	e.devices[d.ID] = d
	e.mu.Unlock()
	return d
}

// namesByIP reads the engine's in-memory device names under lock.
func namesByIP(e *Engine) map[string]string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := map[string]string{}
	for _, d := range e.devices {
		out[d.IP] = d.Name
	}
	return out
}

// A row reloaded from the store this session carries no state — the column
// does not exist — and nothing touches it while it stays away. It has to
// resolve to offline like any other stale row: rendered as an empty status dot
// it matched no filter, and the state sort had no rank for it.
func TestTickResolvesUnseenRowToOffline(t *testing.T) {
	e := newTestEngine(t)

	stale := time.Now().Add(-time.Hour)
	fresh := time.Now()

	e.mu.Lock()
	e.devices[1] = model.Device{ID: 1, IP: "192.0.2.10", Name: "unseen", State: "", LastSeen: &stale}
	e.devices[2] = model.Device{ID: 2, IP: "192.0.2.11", Name: "live", State: "online", LastSeen: &fresh}
	e.devices[3] = model.Device{ID: 3, IP: "192.0.2.12", Name: "stale", State: "online", LastSeen: &stale}
	e.mu.Unlock()

	e.tick()

	e.mu.RLock()
	unseen, live, known := e.devices[1].State, e.devices[2].State, e.devices[3].State
	e.mu.RUnlock()

	if unseen != "offline" {
		t.Errorf("row never seen this session: state %q, want offline", unseen)
	}
	if live != "online" {
		t.Errorf("recently seen row: state %q, want online", live)
	}
	if known != "offline" {
		t.Errorf("online row past the deadline: state %q, want offline", known)
	}

	alerts := e.Snapshot().Alerts
	// The user never saw the first row online, so there is no transition to
	// report. The third still reports one.
	if hasAlert(alerts, "unseen went offline") {
		t.Error("unknown → offline raised an alert; want silence")
	}
	if !hasAlert(alerts, "stale went offline") {
		t.Error("online → offline should still raise its alert")
	}
}

// Roaming between networks leaves the machine's previous address behind as an
// ordinary row — but still wearing the name self-registration gave it, which
// is persisted even though the self flag is not. Without this the inventory
// accumulates rows that read as "This machine" while another row is. A name the
// user typed is never produced by that path, so it is preserved.
func TestRevertStaleSelfNames(t *testing.T) {
	e := newTestEngine(t)
	selfName := netinfo.SelfName()

	// Us, right now.
	live := storedDevice(t, e, "192.0.2.20", selfName, true)
	// Leftovers from a previous address: the fallback answer, and the answer
	// once a hostname was usable.
	fallback := storedDevice(t, e, "192.0.2.21", netinfo.FallbackSelfName, false)
	hostname := storedDevice(t, e, "192.0.2.22", selfName, false)
	// A name the user chose, and an ordinary device already on the placeholder.
	userNamed := storedDevice(t, e, "192.0.2.23", "Kids tablet", false)
	ordinary := storedDevice(t, e, "192.0.2.24", "Device 192.0.2.24", false)

	e.mu.Lock()
	e.revertStaleSelfNames()
	e.mu.Unlock()

	got := namesByIP(e)
	want := map[string]string{
		live.IP:      selfName,
		fallback.IP:  "Device " + fallback.IP,
		hostname.IP:  "Device " + hostname.IP,
		userNamed.IP: "Kids tablet",
		ordinary.IP:  "Device " + ordinary.IP,
	}
	for ip, w := range want {
		if got[ip] != w {
			t.Errorf("%s: name %q, want %q", ip, got[ip], w)
		}
	}

	// The name lives in a column, unlike the self flag: a rename that stays in
	// memory returns the next time the process restarts.
	stored, err := e.st.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	for _, d := range stored {
		if want[d.IP] != "" && d.Name != want[d.IP] {
			t.Errorf("%s not persisted: name %q, want %q", d.IP, d.Name, want[d.IP])
		}
	}
}

// The sweep has to be wired into ensureSelf, not merely exist — an unwired
// helper passes every test while roamed-to rows keep their stale name forever.
func TestEnsureSelfRevertsPreviousAddress(t *testing.T) {
	if ip, _, _ := netinfo.LocalSelf(); ip == "" {
		t.Skip("no usable local address, so ensureSelf cannot identify this machine")
	}
	e := newTestEngine(t)
	stale := storedDevice(t, e, "192.0.2.30", netinfo.FallbackSelfName, false)

	e.ensureSelf()

	if got := namesByIP(e)[stale.IP]; got != "Device "+stale.IP {
		t.Errorf("previous-address row: name %q, want %q", got, "Device "+stale.IP)
	}
}
