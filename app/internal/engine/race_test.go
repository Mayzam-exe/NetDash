package engine

import (
	"sync"
	"testing"

	"netdash/internal/model"
)

// TestPublishSnapshotNoRace drives publishNow (which recomputes status while
// holding the engine lock) concurrently with Snapshot. Run under -race; before
// the fix publishNow took only a read lock while writing e.status, so two
// "readers" raced. This test must simply not trip the detector.
func TestPublishSnapshotNoRace(t *testing.T) {
	e := newTestEngine(t)
	e.mu.Lock()
	e.devices[1] = model.Device{ID: 1, IP: "192.168.1.9", Name: "d1", State: "online"}
	e.mu.Unlock()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				e.publishNow()
			}
		}
	}()
	for i := 0; i < 300; i++ {
		_ = e.Snapshot()
	}
	close(stop)
	wg.Wait()
}

// TestTickConcurrentSnapshot covers the tick path (which now fires offline
// alerts after releasing the lock) racing with Snapshot readers.
func TestTickConcurrentSnapshot(t *testing.T) {
	e := newTestEngine(t)
	e.mu.Lock()
	e.devices[1] = model.Device{ID: 1, IP: "192.168.1.9", Name: "d1", State: "online"}
	e.mu.Unlock()

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				e.tick()
			}
		}
	}()
	for i := 0; i < 300; i++ {
		_ = e.Snapshot()
	}
	close(stop)
	wg.Wait()
}
