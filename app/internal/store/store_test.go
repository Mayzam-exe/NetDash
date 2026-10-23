package store

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"netdash/internal/model"
)

func TestUpsertAndListDevice(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	_, isNew, err := s.UpsertDevice("192.168.1.5", "aa:bb:cc:dd:ee:05", "Acme", time.Now().UnixMilli())
	if err != nil || !isNew {
		t.Fatalf("upsert new: isNew=%v err=%v", isNew, err)
	}
	// A second upsert of the same IP updates rather than inserts.
	if _, isNew, err = s.UpsertDevice("192.168.1.5", "", "", time.Now().UnixMilli()); err != nil || isNew {
		t.Fatalf("upsert existing: isNew=%v err=%v", isNew, err)
	}

	devs, err := s.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devs) != 1 {
		t.Fatalf("ListDevices len=%d want 1", len(devs))
	}
	// The empty second upsert must not wipe the stored vendor.
	if devs[0].Vendor != "Acme" {
		t.Fatalf("vendor=%q want Acme", devs[0].Vendor)
	}
}

// TestAlertsRetention verifies the new bounded retention: an old alert is
// pruned on the next insert while a fresh one survives.
func TestAlertsRetention(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	now := time.Now().UnixMilli()
	if _, err := s.AddAlert("info", "old", nil, now-alertRetention-1000); err != nil {
		t.Fatalf("add old: %v", err)
	}
	if _, err := s.AddAlert("info", "fresh", nil, now); err != nil {
		t.Fatalf("add fresh: %v", err)
	}

	alerts, err := s.ListAlerts(100)
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	seenFresh := false
	for _, a := range alerts {
		if a.Msg == "old" {
			t.Fatalf("old alert survived retention prune: %+v", alerts)
		}
		if a.Msg == "fresh" {
			seenFresh = true
		}
	}
	if !seenFresh {
		t.Fatalf("fresh alert missing: %+v", alerts)
	}
}

// TestClearAlerts: the Clear-all button wipes every row, read or not, so a
// restart can't resurrect a log the user already cleared.
func TestClearAlerts(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	for _, m := range []string{"one", "two", "three"} {
		if _, err := s.AddAlert("info", m, nil, time.Now().UnixMilli()); err != nil {
			t.Fatalf("add %s: %v", m, err)
		}
	}
	if err := s.ClearAlerts(); err != nil {
		t.Fatalf("ClearAlerts: %v", err)
	}
	alerts, err := s.ListAlerts(100)
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if len(alerts) != 0 {
		t.Fatalf("log not cleared: %+v", alerts)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	st := model.DefaultSettings()
	st.SSID24 = "TestNet"
	if err := s.PutSettings(st); err != nil {
		t.Fatalf("PutSettings: %v", err)
	}
	got, err := s.GetSettings()
	if err != nil || got.SSID24 != "TestNet" {
		t.Fatalf("GetSettings=%+v err=%v", got, err)
	}

	// Lockdown rides along in the same JSON blob.
	st.Lockdown = true
	if err := s.PutSettings(st); err != nil {
		t.Fatalf("PutSettings(lockdown): %v", err)
	}
	got, err = s.GetSettings()
	if err != nil || !got.Lockdown {
		t.Fatalf("lockdown not persisted: %+v err=%v", got, err)
	}
}

// TestTrustedColumnMigratesFromOldSchema: a database written before lockdown
// existed gets the column added, and existing devices come back untrusted
// rather than silently exempt.
func TestTrustedColumnMigratesFromOldSchema(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "netdash.db")

	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	const oldSchema = `CREATE TABLE devices(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL UNIQUE,
  mac TEXT NOT NULL DEFAULT '',
  name TEXT NOT NULL DEFAULT '',
  vendor TEXT NOT NULL DEFAULT '',
  conn TEXT NOT NULL DEFAULT 'unknown',
  blocked INTEGER NOT NULL DEFAULT 0,
  reserved INTEGER NOT NULL DEFAULT 0,
  priority TEXT NOT NULL DEFAULT 'normal',
  schedule TEXT NOT NULL DEFAULT '',
  speed_down INTEGER NOT NULL DEFAULT 0,
  speed_up INTEGER NOT NULL DEFAULT 0,
  watched INTEGER NOT NULL DEFAULT 0,
  kind TEXT NOT NULL DEFAULT '',
  first_seen INTEGER NOT NULL DEFAULT 0,
  last_seen INTEGER NOT NULL DEFAULT 0
);`
	if _, err := db.Exec(oldSchema); err != nil {
		t.Fatalf("create old schema: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO devices(ip, mac, name) VALUES('192.168.1.7','aa:bb:cc:dd:ee:07','old phone')`); err != nil {
		t.Fatalf("seed old device: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close old db: %v", err)
	}

	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open on pre-lockdown schema: %v", err)
	}
	defer s.Close()

	devs, err := s.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices after migration: %v", err)
	}
	if len(devs) != 1 || devs[0].IP != "192.168.1.7" {
		t.Fatalf("devices after migration: %+v", devs)
	}
	if devs[0].Trusted {
		t.Error("pre-existing device migrated as trusted")
	}

	devs[0].Trusted = true
	if err := s.SaveDevice(devs[0]); err != nil {
		t.Fatalf("SaveDevice after migration: %v", err)
	}
	again, err := s.ListDevices()
	if err != nil || !again[0].Trusted {
		t.Fatalf("trusted did not round-trip after migration: %+v err=%v", again, err)
	}
}
