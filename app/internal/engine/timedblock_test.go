package engine

import (
	"testing"
	"time"

	"netdash/internal/model"
)

// TestReapTimedBlocks: an expired timed block is released (map + store) and
// raises an alert; future timed blocks and permanent blocks are untouched.
func TestReapTimedBlocks(t *testing.T) {
	e := newTestEngine(t)

	// Persist a row first so the reaper's SaveDevice (an UPDATE) lands.
	row, isNew, err := e.st.UpsertDevice("192.168.1.40", "aa:bb:cc:dd:ee:40", "", time.Now().UnixMilli())
	if err != nil || !isNew {
		t.Fatalf("upsert: isNew=%v err=%v", isNew, err)
	}
	expiredUntil := time.Now().Add(-time.Minute).UnixMilli()
	expired := addTestDevice(e, row.ID, "192.168.1.40", func(d *model.Device) {
		d.Blocked = true
		d.BlockUntil = expiredUntil
	})
	future := addTestDevice(e, 41, "192.168.1.41", func(d *model.Device) {
		d.Blocked = true
		d.BlockUntil = time.Now().Add(time.Hour).UnixMilli()
	})
	perm := addTestDevice(e, 42, "192.168.1.42", func(d *model.Device) {
		d.Blocked = true
	})

	e.reapTimedBlocks()

	snap := e.Snapshot()
	byID := map[int64]model.Device{}
	for _, d := range snap.Devices {
		byID[d.ID] = d
	}
	if d := byID[expired.ID]; d.Blocked || d.BlockUntil != 0 {
		t.Errorf("expired block not released: blocked=%v blockUntil=%d", d.Blocked, d.BlockUntil)
	}
	if d := byID[future.ID]; !d.Blocked || d.BlockUntil == 0 {
		t.Errorf("future timed block must stay: blocked=%v blockUntil=%d", d.Blocked, d.BlockUntil)
	}
	if d := byID[perm.ID]; !d.Blocked || d.BlockUntil != 0 {
		t.Errorf("permanent block must stay: blocked=%v blockUntil=%d", d.Blocked, d.BlockUntil)
	}
	if !hasAlert(snap.Alerts, "Timed block expired") {
		t.Errorf("no release alert raised: %+v", snap.Alerts)
	}

	// The release must be persisted, not just in memory.
	devs, err := e.st.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	for _, d := range devs {
		if d.ID == expired.ID && (d.Blocked || d.BlockUntil != 0) {
			t.Errorf("release not persisted: blocked=%v blockUntil=%d", d.Blocked, d.BlockUntil)
		}
	}
}

// TestReapLeavesUnblockedAlone: a stale expiry on a device that is not
// blocked (a cleared patch) is normalized to zero without an alert.
func TestReapLeavesUnblockedAlone(t *testing.T) {
	e := newTestEngine(t)
	addTestDevice(e, 50, "192.168.1.50", func(d *model.Device) {
		d.Blocked = false
		d.BlockUntil = time.Now().Add(-time.Hour).UnixMilli()
	})

	e.reapTimedBlocks()

	for _, d := range e.Snapshot().Devices {
		if d.ID == 50 && d.BlockUntil != 0 {
			t.Errorf("stale expiry not normalized: blockUntil=%d", d.BlockUntil)
		}
	}
	if hasAlert(e.Snapshot().Alerts, "Timed block expired") {
		t.Errorf("alert raised for a device that was not blocked")
	}
}
