package engine

import (
	"testing"
	"time"

	"netdash/internal/model"
)

func findIP(e *Engine, ip string) model.Device {
	for _, d := range e.devices {
		if d.IP == ip {
			return d
		}
	}
	return model.Device{}
}

func TestMDNSNameAdoption(t *testing.T) {
	e := newTestEngine(t)

	// Hint recorded before the device is ever seen.
	e.mdnsName("192.168.1.77", "maxs-iPhone")
	e.applyNeighbor("192.168.1.77", "aa:bb:cc:dd:ee:01", "", time.Now().UnixMilli())
	e.mu.RLock()
	d1 := findIP(e, "192.168.1.77")
	e.mu.RUnlock()
	if d1.Name != "maxs-iPhone" {
		t.Errorf("hint not adopted: name=%q", d1.Name)
	}
	if d1.Kind != "phone" {
		t.Errorf("kind not inferred from mDNS name: %q", d1.Kind)
	}

	// Existing placeholder device adopts directly.
	e.applyNeighbor("192.168.1.88", "aa:bb:cc:dd:ee:02", "", time.Now().UnixMilli())
	e.mdnsName("192.168.1.88", "living-room-chromecast")
	e.mu.RLock()
	d2 := findIP(e, "192.168.1.88")
	e.mu.RUnlock()
	if d2.Name != "living-room-chromecast" || d2.Kind != "tv" {
		t.Errorf("direct adopt: name=%q kind=%q", d2.Name, d2.Kind)
	}

	// A real name is never overwritten by a later mDNS hit.
	e.mdnsName("192.168.1.88", "something-else")
	e.mu.RLock()
	d3 := findIP(e, "192.168.1.88")
	e.mu.RUnlock()
	if d3.Name != "living-room-chromecast" {
		t.Errorf("placeholder was overwritten: %q", d3.Name)
	}
}
