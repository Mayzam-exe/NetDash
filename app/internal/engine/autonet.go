package engine

import (
	"log"

	"netdash/internal/model"
	"netdash/internal/netinfo"
)

// DetectNetwork asks the OS which network this host is on and auto-applies
// the settings that are genuinely network-derived: both SSIDs (the
// dashboard's band labels) and the public egress address. Everything else it
// learns rides back to the UI to fill the reference form fields with. "" from
// detection means "unknown" and never clears a stored value, and the WAN
// health probe target is deliberately left alone — a ping to one's own
// public IP is usually answered by the local router's NAT, which would keep
// the WAN check green with the internet dead.
func (e *Engine) DetectNetwork() (netinfo.Detected, model.Settings) {
	det := netinfo.Detect()

	e.mu.RLock()
	s := e.settings
	e.mu.RUnlock()

	changed := false
	if det.SSID24 != "" && det.SSID24 != s.SSID24 {
		s.SSID24 = det.SSID24
		changed = true
	}
	if det.SSID5 != "" && det.SSID5 != s.SSID5 {
		s.SSID5 = det.SSID5
		changed = true
	}
	if det.PublicIP != "" && det.PublicIP != s.WanEgress {
		s.WanEgress = det.PublicIP
		changed = true
	}
	if changed {
		// PutSettings persists and publishes; the snapshot carries settings,
		// so every open UI picks the new values up on the next SSE frame.
		if err := e.PutSettings(s); err != nil {
			log.Printf("autonet: apply: %v", err)
		}
	}
	return det, e.Settings()
}

// autoDetect runs DetectNetwork off the caller's path: boot, gateway
// adoption and the periodic tick all trigger detection without blocking on
// its command execution and internet fetch.
func (e *Engine) autoDetect() {
	_, _ = e.DetectNetwork()
}
