package engine

import (
	"errors"
	"strings"
	"testing"
	"time"

	"netdash/internal/model"
)

func iptr(v int) *int { return &v }

func deviceByIP(t *testing.T, e *Engine, ip string) model.Device {
	t.Helper()
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, d := range e.devices {
		if d.IP == ip {
			return d
		}
	}
	t.Fatalf("device %s not found", ip)
	return model.Device{}
}

func TestSpeedPatchValidation(t *testing.T) {
	e := newTestEngine(t)

	e.applyNeighbor("192.168.1.60", "aa:bb:cc:dd:ee:60", "", time.Now().UnixMilli())
	d := deviceByIP(t, e, "192.168.1.60")

	if _, err := e.UpdateDevice(d.ID, DevicePatch{SpeedDown: iptr(-1)}); !errors.Is(err, ErrInvalid) {
		t.Errorf("negative speedDown: err=%v, want ErrInvalid", err)
	}
	if _, err := e.UpdateDevice(d.ID, DevicePatch{SpeedUp: iptr(10_000_001)}); !errors.Is(err, ErrInvalid) {
		t.Errorf("oversized speedUp: err=%v, want ErrInvalid", err)
	}

	// this machine can never be limited
	e.mu.Lock()
	selfID := int64(-1)
	e.devices[selfID] = model.Device{ID: selfID, IP: "10.9.9.9", Self: true, Name: "This machine"}
	e.mu.Unlock()
	if _, err := e.UpdateDevice(selfID, DevicePatch{SpeedDown: iptr(100)}); !errors.Is(err, ErrInvalid) ||
		!strings.Contains(err.Error(), "cannot limit this machine") {
		t.Errorf("self limit: err=%v, want ErrInvalid cannot limit this machine", err)
	}
	e.mu.Lock()
	delete(e.devices, selfID)
	e.mu.Unlock()

	// rate limits require arp mode; the sandbox has no raw-socket capability
	if _, err := e.UpdateDevice(d.ID, DevicePatch{SpeedDown: iptr(5000)}); !errors.Is(err, ErrInvalid) ||
		!strings.Contains(err.Error(), "speed control unavailable") {
		t.Errorf("speed without arp mode: err=%v, want ErrInvalid speed control unavailable", err)
	}

	// clearing a limit must work even while enforcement is unavailable
	e.mu.Lock()
	cur := e.devices[d.ID]
	cur.SpeedDown = 5000
	e.devices[d.ID] = cur
	e.mu.Unlock()
	if _, err := e.UpdateDevice(d.ID, DevicePatch{SpeedDown: iptr(0)}); err != nil {
		t.Errorf("clearing speed while unavailable: err=%v, want nil", err)
	}
	if got := deviceByIP(t, e, "192.168.1.60").SpeedDown; got != 0 {
		t.Errorf("speedDown after clear = %d, want 0", got)
	}
}

func TestBlockSetComputesLimited(t *testing.T) {
	e := newTestEngine(t)
	e.applyNeighbor("192.168.1.61", "aa:bb:cc:dd:ee:61", "", time.Now().UnixMilli())
	d := deviceByIP(t, e, "192.168.1.61")

	e.mu.Lock()
	cur := e.devices[d.ID]
	cur.SpeedDown, cur.SpeedUp = 2000, 500
	e.devices[d.ID] = cur
	desired, limited, _ := e.blockSetLocked(0, nil)
	e.mu.Unlock()

	if len(desired) != 0 {
		t.Errorf("blocked set = %v, want empty", desired)
	}
	lim, ok := limited["192.168.1.61"]
	if !ok || lim.Down != 2000 || lim.Up != 500 || lim.MAC == "" {
		t.Errorf("limited = %v, want {MAC, Down:2000, Up:500}", limited)
	}

	// a blocked device must not also appear as limited
	e.mu.Lock()
	cur = e.devices[d.ID]
	cur.Blocked = true
	e.devices[d.ID] = cur
	desired, limited, _ = e.blockSetLocked(0, nil)
	e.mu.Unlock()
	if _, blocked := desired["192.168.1.61"]; !blocked {
		t.Error("blocked device missing from block set")
	}
	if _, still := limited["192.168.1.61"]; still {
		t.Error("blocked device must not also be rate-limited")
	}
}
