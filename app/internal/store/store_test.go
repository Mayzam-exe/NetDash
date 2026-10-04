package store

import (
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
}
