package engine

import (
	"testing"

	"netdash/internal/model"
	"netdash/internal/store"
)

func newTestEngine(t *testing.T) *Engine {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e, err := New(st, NewHub())
	if err != nil {
		t.Fatalf("engine.New: %v", err)
	}
	return e
}

func TestInferKindTTLFallback(t *testing.T) {
	e := newTestEngine(t)

	dev := model.Device{IP: "192.168.1.50", Name: "Device 192.168.1.50"}

	// No reply captured: stay unknown rather than guess.
	if got := e.inferKindLocked(dev); got != "" {
		t.Errorf("no ttl: got %q, want \"\"", got)
	}

	// Windows answers LAN pings with TTL 128 → PC-class fallback.
	e.recordTTL(dev.IP, 128)
	if got := e.inferKindLocked(dev); got != "desktop" {
		t.Errorf("ttl=128: got %q, want \"desktop\"", got)
	}

	// Android/iOS/macOS/Linux keep TTL 64 → not a Windows PC, stay unknown.
	e.recordTTL(dev.IP, 64)
	if got := e.inferKindLocked(dev); got != "" {
		t.Errorf("ttl=64: got %q, want \"\"", got)
	}

	// Hostname always beats the TTL fingerprint, even a Windows-looking one.
	e.recordTTL(dev.IP, 128)
	dev.Name = "joes-iphone"
	if got := e.inferKindLocked(dev); got != "phone" {
		t.Errorf("hostname vs ttl: got %q, want \"phone\"", got)
	}

	// Unparsed replies (ttl=-1) must not poison the map.
	e.recordTTL("192.168.1.51", -1)
	if _, ok := e.ttlByIP["192.168.1.51"]; ok {
		t.Errorf("ttl=-1 was recorded")
	}
}
