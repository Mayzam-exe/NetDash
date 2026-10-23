package store

import (
	"testing"
	"time"
)

// TestBlockUntilRoundTrip: a timed block's expiry survives save → load, and
// saving with BlockUntil=0 clears it (permanent-block semantics).
func TestBlockUntilRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()

	d, isNew, err := s.UpsertDevice("192.168.1.60", "aa:bb:cc:dd:ee:60", "Acme", time.Now().UnixMilli())
	if err != nil || !isNew {
		t.Fatalf("upsert: isNew=%v err=%v", isNew, err)
	}

	until := time.Now().Add(time.Hour).UnixMilli()
	d.Blocked = true
	d.BlockUntil = until
	if err := s.SaveDevice(d); err != nil {
		t.Fatalf("SaveDevice(timed): %v", err)
	}

	devs, err := s.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	var found bool
	for _, got := range devs {
		if got.ID != d.ID {
			continue
		}
		found = true
		if !got.Blocked || got.BlockUntil != until {
			t.Fatalf("timed block lost: blocked=%v blockUntil=%d want %d", got.Blocked, got.BlockUntil, until)
		}
	}
	if !found {
		t.Fatalf("device %d missing after save", d.ID)
	}

	// A permanent re-block clears the expiry.
	d.BlockUntil = 0
	if err := s.SaveDevice(d); err != nil {
		t.Fatalf("SaveDevice(permanent): %v", err)
	}
	devs, err = s.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices(2): %v", err)
	}
	for _, got := range devs {
		if got.ID == d.ID && got.BlockUntil != 0 {
			t.Fatalf("expiry not cleared: blockUntil=%d", got.BlockUntil)
		}
	}
}
