package engine

import (
	"log"
	"strings"
	"time"

	"netdash/internal/model"
	"netdash/internal/netinfo"
)

// offlineExpireAfter is how long a device may stay unseen before it is
// dropped from the inventory. Its "shadow" (offline entry) lives this long;
// it reappears automatically the moment it is seen again.
const offlineExpireAfter = 5 * time.Minute

// checkGateway adopts a new default gateway when the OS default route
// changes (the host joined a different network). Detection must agree on
// two consecutive checks so roaming blips and transient empty routes do not
// rebind anything. Callers: the Run loop.
func (e *Engine) checkGateway() {
	det := e.gwDetect()
	e.mu.RLock()
	cur := e.settings.GatewayIP
	e.mu.RUnlock()
	if det == "" || det == cur {
		e.gwCandidate = ""
		return
	}
	if det != e.gwCandidate {
		e.gwCandidate = det // first sighting — wait for confirmation
		return
	}
	e.gwCandidate = ""
	log.Printf("network change: default gateway %s (configured %s) — adopting", det, cur)
	s := e.Settings()
	s.GatewayIP = det
	if err := e.PutSettings(s); err != nil {
		log.Printf("gateway adopt: %v", err)
		return
	}
	e.fireAlert("gwadopt", "info", "Network changed — adopted gateway "+det, nil, time.Minute)
}

// rebindBridge tears down enforcement bound to the previous gateway and
// brings it back up against the current settings. The old ARP bridge stops
// first so its active poisons are repaired instead of leaking toward a
// network we no longer own. Called when GatewayIP changes.
func (e *Engine) rebindBridge() {
	e.mu.Lock()
	old := e.arp
	e.arp = nil
	e.blockMode = ""
	e.arpReason = ""
	e.mu.Unlock()
	if old != nil {
		old.Stop() // repairs active poisons toward the old gateway
	}
	// applyRules re-opens the bridge (refreshBlockMode) and pushes the
	// desired block/limit/watch sets to whichever mode now applies.
	e.applyRules(false)
	log.Printf("blocking: rebound to gateway %s", e.Settings().GatewayIP)
}

// checkBridge reopens the ARP bridge after a carrier outage (wifi bounce,
// cable pull, suspend). The poison ticker and relay loop exit permanently on
// socket errors and nothing else restarts them, which would silently kill
// speed limits, intercept and DNS spoofing until the daemon restarts while
// status still claims the bridge is active. Callers: the Run loop.
func (e *Engine) checkBridge() {
	e.mu.RLock()
	b := e.arp
	e.mu.RUnlock()
	if b == nil || b.Alive() {
		return
	}
	if ip, _, _ := netinfo.LocalSelf(); ip == "" {
		return // still no address — wait for rejoin, retry next tick
	}
	log.Printf("arp bridge: loops died during a link outage — reopening")
	e.rebindBridge()
	e.fireAlert("bridgedown", "info", "ARP bridge reopened after a link outage", nil, time.Minute)
}

// expireOffline drops unconfigured devices that have not been seen for
// offlineExpireAfter, shrinking the inventory and the map back to devices
// that are actually on this network. Configured devices (blocked, limited,
// intercepted, scheduled, reserved, this machine, the gateway) are kept:
// their records carry state the user would silently lose.
func (e *Engine) expireOffline() {
	now := time.Now()
	type gone struct {
		id   int64
		name string
	}
	var rm []gone
	e.mu.Lock()
	for id, d := range e.devices {
		if d.Self || d.IP == e.settings.GatewayIP || e.hasUserConfig(d) {
			continue
		}
		if d.LastSeen == nil || now.Sub(*d.LastSeen) < offlineExpireAfter {
			continue
		}
		delete(e.devices, id)
		delete(e.offlineTag, d.IP)
		delete(e.ttlByIP, d.IP)
		rm = append(rm, gone{id, d.Name})
	}
	e.mu.Unlock()
	if len(rm) == 0 {
		return
	}
	names := make([]string, 0, len(rm))
	for _, g := range rm {
		if err := e.st.DeleteDevice(g.id); err != nil {
			log.Printf("expiry: delete device %d: %v", g.id, err)
		}
		names = append(names, g.name)
	}
	// No rediscovery grace: unlike a manual forget, an expired device
	// reappears immediately (fresh record) when it next joins the network.
	log.Printf("expiry: removed %d idle device(s): %s", len(rm), strings.Join(names, ", "))
	e.publishNow()
}

// hasUserConfig reports whether the device carries configuration the user
// would lose if the record were dropped. Callers hold e.mu.
func (e *Engine) hasUserConfig(d model.Device) bool {
	if d.Blocked || d.Reserved || d.Watched {
		return true
	}
	if d.SpeedDown > 0 || d.SpeedUp > 0 {
		return true
	}
	if d.Schedule != "" || (d.Priority != "" && d.Priority != "normal") {
		return true
	}
	return e.manualKind[d.ID]
}
