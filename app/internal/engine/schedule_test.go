package engine

import (
	"testing"
	"time"
)

func TestParseSchedule(t *testing.T) {
	cases := []struct {
		in   string
		ok   bool
		from int
		to   int
	}{
		{"07:00-23:00", true, 420, 1380},
		{"07:00–23:00", true, 420, 1380}, // en-dash from the UI
		{"7:05—23:00", true, 425, 1380},
		{"22:00-06:00", true, 1320, 360}, // wraps midnight
		{"", false, 0, 0},
		{"bogus", false, 0, 0},
		{"25:00-10:00", false, 0, 0},
	}
	for _, c := range cases {
		from, to, ok := parseSchedule(c.in)
		if ok != c.ok || (ok && (from != c.from || to != c.to)) {
			t.Errorf("parseSchedule(%q) = %d,%d,%v want ok=%v %d,%d", c.in, from, to, ok, c.ok, c.from, c.to)
		}
	}
}

func TestScheduleAllows(t *testing.T) {
	at := func(h, m int) time.Time {
		return time.Date(2026, 9, 27, h, m, 0, 0, time.UTC)
	}
	must := func(s string, h, m int, want bool) {
		if got := scheduleAllows(s, at(h, m)); got != want {
			t.Errorf("scheduleAllows(%q, %02d:%02d) = %v want %v", s, h, m, got, want)
		}
	}
	must("07:00-23:00", 8, 0, true)
	must("07:00-23:00", 6, 59, false)
	must("07:00-23:00", 23, 0, false)
	must("07:00-23:00", 7, 0, true)
	must("22:00-06:00", 23, 0, true)
	must("22:00-06:00", 3, 0, true)
	must("22:00-06:00", 12, 0, false)
	must("", 3, 0, true)            // no schedule -> always allowed
	must("garbage", 3, 0, true)     // invalid -> fail open
	must("07:00-07:00", 3, 0, true) // degenerate
}
