package model

import "testing"

func TestHistoryPushCaps(t *testing.T) {
	h := NewHistory()
	for i := 0; i < HistLen+10; i++ {
		h.Push(float64(i), float64(i), float64(i))
	}
	if len(h.Down) != HistLen || len(h.Up) != HistLen || len(h.Lat) != HistLen {
		t.Fatalf("len down/up/lat = %d/%d/%d want %d", len(h.Down), len(h.Up), len(h.Lat), HistLen)
	}
	if h.Points != HistLen {
		t.Fatalf("Points=%d want %d", h.Points, HistLen)
	}
	if h.Down[len(h.Down)-1] != float64(HistLen+9) {
		t.Fatalf("last down=%v want %d", h.Down[len(h.Down)-1], HistLen+9)
	}
}
