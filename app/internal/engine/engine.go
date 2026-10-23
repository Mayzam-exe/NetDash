package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"netdash/internal/arpblock"
	"netdash/internal/discover"
	"netdash/internal/firewall"
	"netdash/internal/ident"
	"netdash/internal/mdns"
	"netdash/internal/model"
	"netdash/internal/netinfo"
	"netdash/internal/probe"
	"netdash/internal/snmp"
	"netdash/internal/store"
	"netdash/internal/vendor"
)

// Version is reported by /api/status and `netdash -version`.
const Version = "0.1.0"

// exeHint is this binary's real path, used to fill in capability advice
// ("sudo setcap … <netdash binary>"). Resolved once; symlinks are followed so
// the answer matches what setcap should be pointed at. Tests resolve to the
// test binary, which is harmless — the string only appears in status text.
var exeHint = func() string {
	p, err := os.Executable()
	if err != nil {
		return "<netdash binary>"
	}
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return real
	}
	return p
}()

// rawPacketAdvice says what will actually put CAP_NET_RAW in this process's
// hands: bin is the binary to change, nosuidMount the mount that would grant it
// ("" when nothing there blocks it).
//
// The bare hint — "run setcap" — was handed out in a form that cannot work, and
// led straight into a dead end. Two properties of file capabilities cause it:
// the kernel ignores them entirely on a nosuid mount, where setcap still exits
// 0 and getcap still reports them; and they are read only when a process
// starts, so a grant made while NetDash runs reaches nothing until a restart.
// Both send someone into a loop of running a command that changes nothing, so
// this names the precondition instead of repeating the command.
func rawPacketAdvice(bin, nosuidMount string) string {
	if nosuidMount != "" {
		return "raw packet access denied — " + bin + " sits on " + nosuidMount +
			", mounted nosuid: the kernel ignores file capabilities there, so setcap on it grants nothing. " +
			"Install the binary on a mount without nosuid (grantcaps.sh puts it in /usr/local/lib/netdash), then restart the service"
	}
	return "raw packet access denied — need CAP_NET_RAW: run `sudo setcap cap_net_raw,cap_net_admin+ep " + bin +
		"`, then restart the service (a process only receives file capabilities when it starts)"
}

const (
	offlineAfter     = 120 * time.Second
	discoverEvery    = 10 * time.Second
	probeEvery       = 3 * time.Second
	sweepEvery       = 30 * time.Second
	scheduleEvery    = 30 * time.Second
	alertKeep        = 30
	gwDownAfter      = 3                // consecutive failed gateway pings before critical
	wanDegradedAfter = 3                // failed WAN pings before the degraded warning
	wanDownAfter     = 8                // failed WAN pings before critical
	latWarnMs        = 60.0             // WAN latency warning threshold
	latCriticalMs    = 150.0            // WAN latency critical threshold
	forgetFor        = 10 * time.Minute // how long "forget" suppresses re-discovery
)

// Hub fans snapshot bytes out to SSE subscribers.
type Hub struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

func NewHub() *Hub { return &Hub{subs: make(map[chan []byte]struct{})} }

func (h *Hub) Subscribe() chan []byte {
	ch := make(chan []byte, 8)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) Unsubscribe(ch chan []byte) {
	h.mu.Lock()
	delete(h.subs, ch)
	h.mu.Unlock()
	close(ch)
}

func (h *Hub) Publish(b []byte) {
	h.mu.Lock()
	for ch := range h.subs {
		select {
		case ch <- b:
		default: // slow subscriber: drop frame, stream stays live
		}
	}
	h.mu.Unlock()
}

type Engine struct {
	st       *store.Store
	hub      *Hub
	started  time.Time
	settings model.Settings

	mu         sync.RWMutex
	devices    map[int64]model.Device
	alerts     []model.Alert
	hist       model.History
	status     model.Status
	lastLat    float64
	gwLatency  float64 // ms, -1 = unknown/unreachable
	wanLatency float64
	offlineTag map[string]bool // ip -> offline alert pending

	// default-gateway adoption (network switch): detect reads the OS default
	// route (injectable for tests); gwCandidate must agree twice before the
	// configured gateway is rebound.
	gwDetect    func() string
	gwCandidate string

	// alert dedupe: key -> last fired, for cooldown-aware fireAlert
	alertMu    sync.Mutex
	alertFired map[string]time.Time

	// probe alert state (phase 3)
	gwFails    int
	wanFails   int
	gwWasDown  bool
	wanWasDown bool
	latLevel   int // 0 normal, 1 >= latWarnMs, 2 >= latCriticalMs

	// firewall enforcement (phase 4)
	fwOK       bool
	fwReason   string
	fwApplied  map[string]bool // ip -> currently enforced by the firewall
	path       string          // "gateway" (traffic crosses us) | "behind"
	manualKind map[int64]bool  // device ids whose kind was set by the user
	ttlByIP    map[string]int  // ping reply TTL per IP (128 = Windows, 64 = Unix/mobile)

	// blocking enforcement: "nft" (traffic crosses us), "arp" (poison the
	// gateway toward blocked devices), or "" (unavailable — see arpReason).
	blockMode string
	arp       *arpblock.Blocker
	arpReason string

	// intercept intel: relayed-frame tap -> DNS/SNI/HTTP hostnames, and
	// in-memory DNS spoof rules applied to relayed queries.
	intelCh   chan intelSample
	intelMemo map[string]time.Time
	spoofMu   sync.RWMutex
	spoof     map[string]string // domain suffix -> answer IP

	// mDNS-captured hostnames waiting for their device to appear
	mdnsHints map[string]string

	// devices recently forgotten (suppress rediscovery briefly)
	forgotten map[string]time.Time

	// SNMP-sourced metrics (phase 2)
	metricsSource  string  // host | snmp
	snmpDown       float64 // Mb/s, from router IF-MIB
	snmpUp         float64
	snmpFreshUntil time.Time // snmp rates valid until
	snmpAlerted    bool      // SNMP-unreachable alert dedupe

	// async name resolution
	nameMu    sync.Mutex
	resolving map[string]bool
}

func New(st *store.Store, hub *Hub) (*Engine, error) {
	e := &Engine{
		st:            st,
		hub:           hub,
		started:       time.Now(),
		devices:       map[int64]model.Device{},
		hist:          model.NewHistory(),
		gwLatency:     -1,
		wanLatency:    -1,
		offlineTag:    map[string]bool{},
		alertFired:    map[string]time.Time{},
		fwApplied:     map[string]bool{},
		forgotten:     map[string]time.Time{},
		manualKind:    map[int64]bool{},
		ttlByIP:       map[string]int{},
		mdnsHints:     map[string]string{},
		metricsSource: "host",
		resolving:     map[string]bool{},
		intelCh:       make(chan intelSample, 256),
		intelMemo:     map[string]time.Time{},
		spoof:         map[string]string{},
		gwDetect:      netinfo.DetectGateway,
	}
	e.fwOK, e.fwReason = firewall.Capable()
	if e.fwOK {
		log.Printf("firewall: ready (%s)", e.fwReason)
	} else {
		log.Printf("firewall: unavailable (%s) — device blocking disabled", e.fwReason)
	}
	set, err := st.GetSettings()
	if err != nil {
		return nil, err
	}
	// First boot: adopt the detected default gateway when settings are untouched.
	if _, seen, _ := st.MetaGet("gw_provisioned"); !seen {
		if gw := netinfo.DetectGateway(); gw != "" {
			if set.GatewayIP == "192.168.1.1" {
				set.GatewayIP = gw
			}
			_ = st.PutSettings(set)
			_ = st.MetaSet("gw_provisioned", "1")
		}
	}
	e.settings = set
	e.refreshPath()
	if raw, ok, _ := st.MetaGet("kind_manual"); ok {
		for _, s := range strings.Split(raw, ",") {
			if id, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64); err == nil {
				e.manualKind[id] = true
			}
		}
	}

	devs, err := st.ListDevices()
	if err != nil {
		return nil, err
	}
	for _, d := range devs {
		// Backfill kinds for rows stored before type inference existed.
		if d.Kind == "" && !e.manualKind[d.ID] {
			if k := e.inferKindLocked(d); k != "" {
				d.Kind = k
				_ = st.SaveDevice(d)
			}
		}
		e.devices[d.ID] = d
	}
	alerts, err := st.ListAlerts(alertKeep)
	if err != nil {
		return nil, err
	}
	e.alerts = alerts
	e.recomputeStatus()
	if err := e.ReloadSpoof(); err != nil {
		log.Printf("spoof rules: %v", err)
	}
	go e.intelLoop()
	return e, nil
}

func (e *Engine) Hub() *Hub { return e.hub }

// Run starts the background loops and blocks until ctx is cancelled.
func (e *Engine) Run(ctx context.Context) {
	e.applyRules(true)
	e.discover()
	e.publish()

	tick := time.NewTicker(time.Second)
	disc := time.NewTicker(discoverEvery)
	sweep := time.NewTicker(sweepEvery)
	probeT := time.NewTicker(probeEvery)
	gwT := time.NewTicker(20 * time.Second)
	expT := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	defer disc.Stop()
	defer sweep.Stop()
	defer probeT.Stop()
	defer gwT.Stop()
	defer expT.Stop()

	// Seed gateway adoption immediately: booting on a different network
	// then binds after the second confirmation (~20 s) instead of waiting.
	e.checkGateway()

	go e.probeLoop(ctx)
	go e.snmpLoop(ctx)
	go e.scheduleLoop(ctx)
	go e.meterLoop(ctx)
	go func() {
		if err := mdns.Start(ctx, e.mdnsName); err != nil && ctx.Err() == nil {
			log.Printf("mdns: %v", err)
		}
	}()
	go func() {
		// Seed the ARP table promptly instead of waiting one full sweep
		// interval: quiet LAN devices are otherwise invisible at startup.
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
		e.sweep(ctx)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			e.tick()
		case <-disc.C:
			e.discover()
		case <-sweep.C:
			e.sweep(ctx)
		case <-gwT.C:
			e.checkGateway()
			e.checkBridge()
		case <-expT.C:
			e.expireOffline()
		}
	}
}

func (e *Engine) tick() {
	hostDown, hostUp := netinfo.Sample()

	e.mu.Lock()
	// This machine's own speed always comes from local interface counters,
	// even when the global metrics source is SNMP or metering is unavailable.
	for id, d := range e.devices {
		if d.Self {
			d.Down, d.Up = hostDown, hostUp
			e.devices[id] = d
		}
	}
	lat := e.gwLatency
	if lat >= 0 {
		e.lastLat = lat
	}
	down, up := hostDown, hostUp
	e.metricsSource = "host"
	if time.Now().Before(e.snmpFreshUntil) {
		down, up = e.snmpDown, e.snmpUp
		e.metricsSource = "snmp"
	}
	// stale detection. Offline transitions are collected and their alerts are
	// fired only after e.mu is released: fireAlert → AddAlert takes e.mu itself,
	// and unlocking mid-iteration let concurrent writers mutate e.devices under
	// us (lost updates / devices skipped for the tick).
	now := time.Now()
	var wentOffline []model.Device
	for id, d := range e.devices {
		// State is not a column, so a row reloaded from the store this session
		// starts as "" and stays that way while nothing touches it: it renders
		// an empty status dot, the offline filter never matches it, and the
		// state sort has no rank for it (comparisons come back NaN). Resolve
		// "" on the same rule as any other age — but unknown → offline is not
		// a transition the user watched happen, so it raises no alert.
		if d.LastSeen == nil || d.State == "offline" || now.Sub(*d.LastSeen) <= offlineAfter {
			continue
		}
		wasOnline := d.State == "online"
		d.State = "offline"
		e.devices[id] = d
		if wasOnline && !e.offlineTag[d.IP] {
			e.offlineTag[d.IP] = true
			wentOffline = append(wentOffline, d)
		}
	}
	if down > e.status.HostPeakDown {
		e.status.HostPeakDown = down
	}
	e.hist.Push(down, up, e.lastLat)
	e.status.HostDown, e.status.HostUp = down, up
	e.status.LatencyGateway, e.status.LatencyWAN = e.gwLatency, e.wanLatency
	e.status.GatewayIP, e.status.WANIP = e.settings.GatewayIP, e.settings.WANIP
	e.status.OK = e.gwLatency >= 0
	e.refreshBlockModeLocked()
	e.recomputeStatusLocked()
	snap := e.snapshotLocked()
	e.mu.Unlock()

	for _, d := range wentOffline {
		id := d.ID
		e.fireAlert("offline:"+d.IP, "warning", d.Name+" went offline", &id, 10*time.Minute)
	}

	e.publishBytes(snap)
}

func (e *Engine) discover() {
	neighbors, err := discover.Neighbors()
	if err != nil {
		log.Printf("discover: %v", err)
	}
	now := time.Now().UnixMilli()
	for _, n := range neighbors {
		if !n.Valid {
			continue
		}
		e.applyNeighbor(n.IP, n.MAC, vendor.Lookup(n.MAC), now)
	}
	e.ensureSelf()
	e.recomputeStatus()
}

// inferKindLocked classifies a device: hostname and OUI vendor first (via
// ident.Infer), then a TTL fingerprint fallback — on a single LAN hop Windows
// replies keep TTL 128 while Android/iOS/macOS/Linux keep 64, which at least
// separates Windows PCs from phones when the MAC address is randomized.
// Returns "" when nothing matches confidently.
func (e *Engine) inferKindLocked(d model.Device) string {
	if k := ident.Infer(d.Name, d.Vendor, d.MAC, d.IP, e.settings.GatewayIP); k != "" {
		return k
	}
	if e.ttlByIP[d.IP] == 128 {
		return "desktop"
	}
	return ""
}

// recordTTL stores a ping reply's TTL as an OS fingerprint hint for kind
// inference. ttl < 0 (unparsed / no reply) is ignored.
func (e *Engine) recordTTL(ip string, ttl int) {
	if ttl < 0 || ip == "" {
		return
	}
	e.mu.Lock()
	e.ttlByIP[ip] = ttl
	e.mu.Unlock()
}

// ensureSelf registers the machine running NetDash as a device, so the host
// itself appears in its own inventory with its real link info (MAC vendor,
// Wi-Fi band and signal) instead of being invisible.
func (e *Engine) ensureSelf() {
	ip, mac, ifName := netinfo.LocalSelf()

	// The self flag is runtime-only: clear it everywhere first so a changed
	// local IP cannot leave a stale "this machine" marker behind. The name
	// that row was given is persisted, so it is handed back separately, once
	// this pass knows which row really is this machine — see
	// revertStaleSelfNames.
	e.mu.Lock()
	for id, d := range e.devices {
		if d.Self && d.IP != ip {
			d.Self = false
			e.devices[id] = d
		}
	}
	e.mu.Unlock()
	if ip == "" {
		return
	}

	now := time.Now().UnixMilli()
	vend := vendor.Lookup(mac)
	e.mu.Lock()
	defer e.mu.Unlock()
	existing, isNew, err := e.st.UpsertDevice(ip, mac, vend, now)
	if err != nil {
		log.Printf("self upsert: %v", err)
		return
	}
	d, known := e.devices[existing.ID]
	if !known {
		d = existing
	}
	before := d.Name + "\x00" + d.Vendor + "\x00" + d.Kind + "\x00" + d.Conn + "\x00" + d.MAC
	d.MAC, d.LastSeen, d.State = existing.MAC, existing.LastSeen, "online"
	d.Self = true
	if vend != "" {
		d.Vendor = vend
	}
	if d.Name == "" || d.Name == "Device "+ip {
		d.Name = netinfo.SelfName()
	}
	conn := netinfo.InterfaceConn(ifName)
	if conn != "unknown" {
		d.Conn = conn
	}
	if sig, ok := netinfo.WifiSignal(ifName); ok {
		d.Signal = &sig
	} else if d.Conn == "wifi2" || d.Conn == "wifi5" {
		d.Signal = nil
	}
	if d.Kind == "" && !e.manualKind[d.ID] {
		d.Kind = e.inferKindLocked(d)
		if d.Kind == "" {
			d.Kind = netinfo.FormFactor() // battery = laptop; this host is PC-class
		}
	}
	e.devices[d.ID] = d
	// With the flag landed on this row, any other row still carrying a self
	// name is a leftover from an address we no longer have.
	e.revertStaleSelfNames()
	after := d.Name + "\x00" + d.Vendor + "\x00" + d.Kind + "\x00" + d.Conn + "\x00" + d.MAC
	if isNew || before != after {
		_ = e.st.SaveDevice(d) // Self itself is runtime-only and not persisted.
	}
}

// revertStaleSelfNames puts the generic placeholder back on rows whose name
// came from self-registration. That path is the only writer of a self name, so
// a row still holding one while a different row carries the self flag is a
// record from an address the machine no longer has — which is exactly what a
// restart leaves behind, because the runtime flag does not survive one while
// the name column does. Without this, roaming between networks (home Wi-Fi,
// phone hotspot) piles up rows that read as "This machine" but are not.
//
// A name the user typed is never produced by that path, so it is preserved.
// Renaming back to the placeholder also returns the row to the normal naming
// pipeline: the next DHCP lease or mDNS answer takes over, as it would for any
// other unknown device.
//
// The rename is written to the store here because, unlike the self flag, it
// lives in a persisted column. Callers hold e.mu.
func (e *Engine) revertStaleSelfNames() {
	selfName := netinfo.SelfName()
	for id, d := range e.devices {
		if d.Self || (d.Name != selfName && d.Name != netinfo.FallbackSelfName) {
			continue
		}
		d.Name = "Device " + d.IP
		e.devices[id] = d
		if err := e.st.SaveDevice(d); err != nil {
			log.Printf("revert stale self name %s: %v", d.IP, err)
		}
	}
}

// applyNeighbor upserts a device seen at the network level (ARP or SNMP), refreshes
// its live state, and kicks off async human-name resolution for default names.
func (e *Engine) applyNeighbor(ip, mac, vend string, now int64) {
	e.mu.Lock()
	// Recently-forgotten devices stay suppressed until the grace period ends.
	if until, ok := e.forgotten[ip]; ok {
		if time.Now().Before(until) {
			e.mu.Unlock()
			return
		}
		delete(e.forgotten, ip)
	}
	existing, isNew, err := e.st.UpsertDevice(ip, mac, vend, now)
	if err != nil {
		e.mu.Unlock()
		log.Printf("discover upsert %s: %v", ip, err)
		return
	}
	d, known := e.devices[existing.ID]
	if !known {
		d = existing
	}
	d.MAC, d.LastSeen, d.State = existing.MAC, existing.LastSeen, "online"
	if vend != "" && d.Vendor == "" {
		d.Vendor = vend
	}
	if d.Name == "" {
		d.Name = "Device " + d.IP
	}
	// Adopt a hostname captured via mDNS while we still hold the placeholder.
	if d.Name == "Device "+d.IP {
		if h := e.mdnsHints[d.IP]; h != "" {
			d.Name = h
		}
	}
	kindChanged := false
	if d.Kind == "" && !e.manualKind[d.ID] {
		if k := e.inferKindLocked(d); k != "" {
			d.Kind = k
			kindChanged = true
		}
	}
	e.devices[d.ID] = d
	e.offlineTag[d.IP] = false
	e.mu.Unlock()

	if isNew {
		e.AddAlert("info", "New device seen: "+d.IP+" ("+shortMAC(d.MAC)+")", &d.ID)
	}
	if kindChanged {
		_ = e.st.SaveDevice(d)
	}
	e.resolveNameAsync(d)
}

// mdnsName adopts a hostname captured from an mDNS A record: it fills the
// placeholder on the matching device (re-running kind inference when the
// type is still unknown) and remembers hints for IPs not seen yet.
func (e *Engine) mdnsName(ip, name string) {
	if ip == "" || name == "" || name == "localhost" {
		return
	}
	e.mu.Lock()
	if _, known := e.mdnsHints[ip]; known || len(e.mdnsHints) < 512 {
		e.mdnsHints[ip] = name // bounded: unknown IPs beyond the cap are dropped
	}
	var save []model.Device
	for id, d := range e.devices {
		if d.IP != ip || (d.Name != "" && d.Name != "Device "+d.IP) {
			continue // only ever replace the placeholder
		}
		d.Name = name
		if d.Kind == "" && !e.manualKind[id] {
			d.Kind = e.inferKindLocked(d)
		}
		e.devices[id] = d
		save = append(save, d)
	}
	e.mu.Unlock()
	for _, d := range save {
		_ = e.st.SaveDevice(d)
	}
	if len(save) > 0 {
		e.publishNow()
	}
}

// resolveNameAsync fills a placeholder name from DHCP leases / reverse DNS, once per IP.
func (e *Engine) resolveNameAsync(d model.Device) {
	if d.Name != "" && d.Name != "Device "+d.IP {
		return
	}
	e.nameMu.Lock()
	if e.resolving[d.IP] {
		e.nameMu.Unlock()
		return
	}
	e.resolving[d.IP] = true
	e.nameMu.Unlock()

	go func() {
		defer func() {
			e.nameMu.Lock()
			delete(e.resolving, d.IP)
			e.nameMu.Unlock()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		name := ident.BestName(ctx, d.IP)
		if name == "" {
			return
		}
		e.mu.Lock()
		cur, ok := e.devices[d.ID]
		if !ok || (cur.Name != "" && cur.Name != "Device "+cur.IP) {
			e.mu.Unlock()
			return
		}
		cur.Name = name
		// A real hostname is the strongest type signal: re-infer unless the
		// user pinned this device's kind manually.
		if !e.manualKind[cur.ID] {
			if k := e.inferKindLocked(cur); k != "" {
				cur.Kind = k
			}
		}
		e.devices[d.ID] = cur
		e.mu.Unlock()
		_ = e.st.SaveDevice(cur)
		e.publishNow()
	}()
}

// applyLinks applies SNMP bridge-FDB interface classification to devices by MAC.
func (e *Engine) applyLinks(links map[string]snmp.Link) {
	var changed []model.Device
	e.mu.Lock()
	for id, d := range e.devices {
		l, ok := links[d.MAC]
		if !ok || d.MAC == "" || l.Conn == "unknown" || l.Conn == d.Conn {
			continue
		}
		d.Conn = l.Conn
		e.devices[id] = d
		changed = append(changed, d)
	}
	e.mu.Unlock()
	for _, d := range changed {
		_ = e.st.SaveDevice(d)
	}
	if len(changed) > 0 {
		e.publishNow()
	}
}

// snmpLoop polls the router (when enabled): neighbors, FDB conn types, WAN counters.
func (e *Engine) snmpLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	var meter snmp.WANMeter
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		cfg := e.Settings()
		if !cfg.SnmpEnabled || strings.TrimSpace(cfg.SnmpHost) == "" {
			if meter.HasLast {
				meter = snmp.WANMeter{}
			}
			e.mu.Lock()
			if time.Now().After(e.snmpFreshUntil) {
				e.snmpDown, e.snmpUp = 0, 0
				e.metricsSource = "host"
			}
			e.snmpAlerted = false
			e.mu.Unlock()
			continue
		}
		scfg := snmp.Config{Host: cfg.SnmpHost, Community: cfg.SnmpCommunity}

		nbs, err := snmp.Neighbors(scfg)
		if err != nil {
			e.mu.Lock()
			wasAlerted := e.snmpAlerted
			e.snmpAlerted = true
			e.mu.Unlock()
			if !wasAlerted {
				e.AddAlert("warning", "SNMP unreachable on "+cfg.SnmpHost, nil)
			}
			continue
		}
		e.mu.Lock()
		wasAlerted := e.snmpAlerted
		e.snmpAlerted = false
		e.mu.Unlock()
		if wasAlerted {
			e.AddAlert("info", "SNMP reachable again on "+cfg.SnmpHost, nil)
		}

		now := time.Now().UnixMilli()
		for _, n := range nbs {
			e.applyNeighbor(n.IP, n.MAC, vendor.Lookup(n.MAC), now)
		}
		if links, err := snmp.Links(scfg); err == nil {
			e.applyLinks(links)
		}
		if down, up, ifName, ok, err := meter.Update(scfg, cfg.SnmpWanIf); err == nil && ok {
			e.mu.Lock()
			e.snmpDown, e.snmpUp = down, up
			e.snmpFreshUntil = time.Now().Add(15 * time.Second)
			e.metricsSource = "snmp"
			e.mu.Unlock()
			_ = ifName
			e.publishNow()
		}
	}
}

// sweep pings devices that are currently stale/offline to refresh presence.
func (e *Engine) sweep(ctx context.Context) {
	e.pingSweep(ctx)
	var targets []struct {
		id  int64
		ip  string
		dID int64
	}
	e.mu.RLock()
	for _, d := range e.devices {
		stale := d.LastSeen == nil || time.Since(*d.LastSeen) > offlineAfter
		if stale || d.State == "offline" {
			targets = append(targets, struct {
				id  int64
				ip  string
				dID int64
			}{d.ID, d.IP, d.ID})
		}
	}
	e.mu.RUnlock()

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(id int64, ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			pctx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
			defer cancel()
			if _, ttl, ok := probe.PingTTL(pctx, ip, time.Second); ok {
				e.recordTTL(ip, ttl)
				now := time.Now().UTC()
				e.mu.Lock()
				if d, found := e.devices[id]; found {
					d.LastSeen = &now
					d.State = "online"
					e.devices[id] = d
					e.offlineTag[d.IP] = false
					e.mu.Unlock()
					_ = e.st.TouchSeen(id, now.UnixMilli())
				} else {
					e.mu.Unlock()
				}
			}
		}(t.id, t.ip)
	}
	wg.Wait()
	e.discover() // pick up neighbors the subnet sweep just resolved
	e.recomputeStatus()
}

// pingSweep probes every host on the local subnet so that devices which
// never talk to this machine (TVs, phones, IoT) still get resolved into the
// ARP table and show up in discovery. Replies to ARP are enough — the ICMP
// echo itself may be ignored.
func (e *Engine) pingSweep(ctx context.Context) {
	targets := netinfo.SubnetHosts()
	if len(targets) == 0 {
		return
	}
	sem := make(chan struct{}, 48)
	var wg sync.WaitGroup
	for _, ip := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			pctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer cancel()
			// ARP resolves even when the echo itself is ignored; a reply
			// also contributes an OS fingerprint (TTL) for kind inference.
			if _, ttl, ok := probe.PingTTL(pctx, ip, time.Second); ok {
				e.recordTTL(ip, ttl)
			}
		}(ip)
	}
	wg.Wait()
}

// probeLoop measures gateway and WAN latency every probeEvery.
func (e *Engine) probeLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		e.refreshPath() // picks up gateway-IP and interface changes
		cfg := e.Settings()
		var wg sync.WaitGroup
		var gwOK, wanOK bool
		var gwD, wanD time.Duration
		wg.Add(2)
		go func() {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			defer cancel()
			gwD, gwOK = probe.Ping(pctx, cfg.GatewayIP, time.Second)
		}()
		go func() {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, 2000*time.Millisecond)
			defer cancel()
			wanD, wanOK = probe.Ping(pctx, cfg.WANIP, time.Second)
		}()
		wg.Wait()

		e.mu.Lock()
		if gwOK {
			e.gwLatency = float64(gwD.Microseconds()) / 1000
		} else {
			e.gwLatency = -1
		}
		if wanOK {
			e.wanLatency = float64(wanD.Microseconds()) / 1000
		} else {
			e.wanLatency = -1
		}
		if gwOK {
			e.gwFails = 0
		} else {
			e.gwFails++
		}
		if wanOK {
			e.wanFails = 0
		} else {
			e.wanFails++
		}
		gwFails, wanFails := e.gwFails, e.wanFails
		gwWas, wanWas := e.gwWasDown, e.wanWasDown
		e.gwWasDown = gwFails >= gwDownAfter
		e.wanWasDown = wanFails >= wanDownAfter
		level := 0
		if wanOK {
			switch {
			case e.wanLatency >= latCriticalMs:
				level = 2
			case e.wanLatency >= latWarnMs:
				level = 1
			}
		}
		prevLevel := e.latLevel
		e.latLevel = level
		wanMs := e.wanLatency
		e.mu.Unlock()

		// Thresholds instead of single-packet flaps: gateway critical after
		// gwDownAfter fails, WAN warns when degraded and goes critical when down.
		if gwFails == gwDownAfter {
			e.fireAlert("gw-down", "critical",
				"Gateway unreachable ("+cfg.GatewayIP+")", nil, 10*time.Minute)
		}
		if gwFails == 0 && gwWas {
			e.fireAlert("gw-up", "info", "Gateway reachable again", nil, time.Minute)
		}
		if wanFails == wanDegradedAfter {
			e.fireAlert("wan-degraded", "warning",
				fmt.Sprintf("WAN degraded — %d consecutive ping failures to %s", wanFails, cfg.WANIP),
				nil, 10*time.Minute)
		}
		if wanFails == wanDownAfter {
			e.fireAlert("wan-down", "critical",
				"WAN unreachable — "+cfg.WANIP+" not replying", nil, 10*time.Minute)
		}
		if wanFails == 0 && wanWas {
			e.fireAlert("wan-up", "info", "WAN restored", nil, time.Minute)
		}
		if level > prevLevel {
			if level == 2 {
				e.fireAlert("wan-lat2", "critical",
					fmt.Sprintf("Very high WAN latency — %.0f ms (threshold %.0f ms)", wanMs, latCriticalMs),
					nil, 10*time.Minute)
			} else {
				e.fireAlert("wan-lat1", "warning",
					fmt.Sprintf("High WAN latency — %.0f ms (threshold %.0f ms)", wanMs, latWarnMs),
					nil, 10*time.Minute)
			}
		} else if level < prevLevel && level == 0 {
			e.fireAlert("wan-lat0", "info", "WAN latency back to normal", nil, time.Minute)
		}
		time.Sleep(probeEvery)
	}
}

/* ---------- snapshot / publish ---------- */

func (e *Engine) recomputeStatus() {
	e.mu.Lock()
	e.refreshBlockModeLocked()
	e.recomputeStatusLocked()
	e.mu.Unlock()
}

func (e *Engine) recomputeStatusLocked() {
	var t model.Totals
	lockdown := e.settings.Lockdown
	for _, d := range e.devices {
		t.Devices++
		switch {
		case d.Blocked || (lockdown && !lockdownExempt(d, e.settings.GatewayIP)):
			t.Blocked++
		case d.State == "warning":
			t.Warning++
		case d.State == "online":
			t.Online++
		default:
			t.Offline++
		}
	}
	e.status.Totals = t
	e.status.Lockdown = lockdown
	e.status.MetricsSource = e.metricsSource
	e.status.Version = Version
	e.status.Path = e.path
	behind := "behind gateway " + e.settings.GatewayIP + " — traffic does not cross this host"
	switch {
	case e.path == "behind":
		e.status.Firewall = "unavailable: " + behind
	case !e.fwOK:
		e.status.Firewall = "unavailable: " + e.fwReason
	default:
		e.status.Firewall = "ready"
	}
	switch e.blockMode {
	case "nft":
		e.status.Blocking = "active (nftables)"
	case "arp":
		e.status.Blocking = "active (arp poisoning)"
	default:
		e.status.Blocking = "unavailable: " + e.blockReasonLocked()
	}
	switch e.blockMode {
	case "arp":
		e.status.Speed = "active (arp bridge)"
	case "nft":
		e.status.Speed = "unavailable: rate limits not implemented for gateway (nftables) mode"
	default:
		e.status.Speed = "unavailable: " + e.blockReasonLocked()
	}
	switch {
	case e.blockMode == "arp":
		e.status.Metering = "unavailable: arp mode drops blocked traffic without carrying device flows"
	case runtime.GOOS != "linux":
		e.status.Metering = "unavailable: per-device metering requires a Linux gateway"
	case e.path == "behind":
		e.status.Metering = "unavailable: " + behind
	case !e.fwOK:
		e.status.Metering = "unavailable: " + e.fwReason
	default:
		e.status.Metering = "active"
	}
	e.status.StartedAt = e.started.UTC().Format(time.RFC3339)
}

func (e *Engine) snapshotLocked() model.Snapshot {
	devs := make([]model.Device, 0, len(e.devices))
	lockdown := e.settings.Lockdown
	gwIP := e.settings.GatewayIP
	for _, d := range e.devices {
		// Report *why* a device is offline so the UI can distinguish "the
		// admin blocked this one" from "lockdown mode caught it".
		if lockdown && !d.Blocked && !lockdownExempt(d, gwIP) {
			d.Lockdown = true
		}
		devs = append(devs, d)
	}
	sort.Slice(devs, func(i, j int) bool { return devs[i].Name < devs[j].Name })
	alerts := make([]model.Alert, len(e.alerts))
	copy(alerts, e.alerts)
	return model.Snapshot{Status: e.status, Devices: devs, Alerts: alerts, History: e.hist}
}

// Snapshot returns the current consistent snapshot.
func (e *Engine) Snapshot() model.Snapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.snapshotLocked()
}

func (e *Engine) publish() {
	e.mu.RLock()
	b, err := json.Marshal(e.snapshotLocked())
	e.mu.RUnlock()
	if err == nil {
		e.hub.Publish(b)
	}
}

func (e *Engine) publishBytes(snap model.Snapshot) {
	if b, err := json.Marshal(snap); err == nil {
		e.hub.Publish(b)
	}
}

func (e *Engine) publishNow() {
	// recomputeStatusLocked writes e.status, and Snapshot() reads it under
	// RLock, so this must take the write lock. (It previously used RLock,
	// which made two "readers" race with each other on e.status.)
	e.mu.Lock()
	e.recomputeStatusLocked()
	b, err := json.Marshal(e.snapshotLocked())
	e.mu.Unlock()
	if err == nil {
		e.hub.Publish(b)
	}
}

/* ---------- mutations ---------- */

type DevicePatch struct {
	Blocked   *bool   `json:"blocked,omitempty"`
	Name      *string `json:"name,omitempty"`
	Priority  *string `json:"priority,omitempty"`
	Reserved  *bool   `json:"reserved,omitempty"`
	Schedule  *string `json:"schedule,omitempty"`
	Kind      *string `json:"kind,omitempty"`      // one of ident.Kinds, or "" = auto
	SpeedDown *int    `json:"speedDown,omitempty"` // kbit/s, 0 = unlimited
	SpeedUp   *int    `json:"speedUp,omitempty"`   // kbit/s, 0 = unlimited
	Watched   *bool   `json:"watched,omitempty"`   // intercept for intel
	Trusted   *bool   `json:"trusted,omitempty"`   // exempt from lockdown mode
}

// reSchedule accepts "HH:MM-HH:MM" with -, – or — as separator.
var reSchedule = regexp.MustCompile(`^\s*(\d{1,2}):(\d{2})\s*[-–—]\s*(\d{1,2}):(\d{2})\s*$`)

func (e *Engine) UpdateDevice(id int64, p DevicePatch) (model.Device, error) {
	e.mu.Lock()
	d, ok := e.devices[id]
	if !ok {
		e.mu.Unlock()
		return model.Device{}, ErrNotFound
	}
	// "" (no window) means always allowed; otherwise "HH:MM-HH:MM".
	if p.Schedule != nil && *p.Schedule != "" && !reSchedule.MatchString(*p.Schedule) {
		e.mu.Unlock()
		return model.Device{}, ErrInvalid
	}
	if p.SpeedDown != nil && (*p.SpeedDown < 0 || *p.SpeedDown > 10_000_000) {
		e.mu.Unlock()
		return model.Device{}, fmt.Errorf("%w: speedDown must be 0..10000000 kbit/s", ErrInvalid)
	}
	if p.SpeedUp != nil && (*p.SpeedUp < 0 || *p.SpeedUp > 10_000_000) {
		e.mu.Unlock()
		return model.Device{}, fmt.Errorf("%w: speedUp must be 0..10000000 kbit/s", ErrInvalid)
	}
	if p.Blocked != nil && *p.Blocked && d.Self {
		e.mu.Unlock()
		return model.Device{}, fmt.Errorf("%w: cannot block this machine", ErrInvalid)
	}
	if p.Watched != nil && *p.Watched && d.Self {
		e.mu.Unlock()
		return model.Device{}, fmt.Errorf("%w: cannot intercept this machine", ErrInvalid)
	}
	if p.Watched != nil && *p.Watched && d.IP == e.settings.GatewayIP {
		e.mu.Unlock()
		return model.Device{}, fmt.Errorf("%w: cannot intercept the gateway", ErrInvalid)
	}
	cand := d
	if p.Kind != nil {
		if !ident.ValidKind(*p.Kind) {
			e.mu.Unlock()
			return model.Device{}, ErrInvalid
		}
		if *p.Kind == "" {
			// "auto": clear the pin and infer from current name/vendor/ttl.
			cand.Kind = e.inferKindLocked(cand)
		} else {
			cand.Kind = *p.Kind
		}
	}
	if p.Blocked != nil {
		cand.Blocked = *p.Blocked
	}
	if p.Reserved != nil {
		cand.Reserved = *p.Reserved
	}
	if p.Name != nil && *p.Name != "" {
		cand.Name = *p.Name
	}
	if p.Priority != nil && (*p.Priority == "normal" || *p.Priority == "high" || *p.Priority == "low") {
		cand.Priority = *p.Priority
	}
	if p.Schedule != nil {
		cand.Schedule = *p.Schedule
	}
	if p.SpeedDown != nil {
		cand.SpeedDown = *p.SpeedDown
	}
	if p.SpeedUp != nil {
		cand.SpeedUp = *p.SpeedUp
	}
	if p.Watched != nil {
		cand.Watched = *p.Watched
	}
	if p.Trusted != nil {
		cand.Trusted = *p.Trusted
	}
	blockChanged := p.Blocked != nil && cand.Blocked != d.Blocked
	speedChanged := (p.SpeedDown != nil && *p.SpeedDown != d.SpeedDown) ||
		(p.SpeedUp != nil && *p.SpeedUp != d.SpeedUp)
	speedSet := cand.SpeedDown > 0 || cand.SpeedUp > 0
	speedWas := d.SpeedDown > 0 || d.SpeedUp > 0
	watchChanged := p.Watched != nil && cand.Watched != d.Watched
	// Trust only matters while lockdown is engaged, but the block set has to
	// be rebuilt whenever it flips so the change takes effect immediately.
	trustChanged := p.Trusted != nil && cand.Trusted != d.Trusted

	if speedChanged && speedSet {
		if cand.Self {
			e.mu.Unlock()
			return model.Device{}, fmt.Errorf("%w: cannot limit this machine", ErrInvalid)
		}
		if cand.IP == e.settings.GatewayIP {
			e.mu.Unlock()
			return model.Device{}, fmt.Errorf("%w: cannot limit the gateway", ErrInvalid)
		}
	}

	if blockChanged || speedChanged || watchChanged || trustChanged {
		if blockChanged && cand.Blocked && d.IP == e.settings.GatewayIP {
			e.mu.Unlock()
			return model.Device{}, fmt.Errorf("%w: cannot block the gateway", ErrInvalid)
		}
		e.refreshBlockModeLocked()
		reason := e.blockReasonLocked()
		if blockChanged && reason != "" {
			e.mu.Unlock()
			return model.Device{}, fmt.Errorf("%w: blocking unavailable: %s", ErrInvalid, reason)
		}
		if watchChanged && cand.Watched {
			if reason != "" {
				e.mu.Unlock()
				return model.Device{}, fmt.Errorf("%w: intercept unavailable: %s", ErrInvalid, reason)
			}
			if e.blockMode != "arp" {
				e.mu.Unlock()
				return model.Device{}, fmt.Errorf("%w: intercept unavailable: needs laptop (arp bridge) mode", ErrInvalid)
			}
		}
		if speedChanged && speedSet && e.blockMode != "arp" {
			msg := reason
			if msg == "" {
				msg = "rate limits need laptop (arp bridge) mode — not implemented for gateway (nftables) mode"
			}
			e.mu.Unlock()
			return model.Device{}, fmt.Errorf("%w: speed control unavailable: %s", ErrInvalid, msg)
		}
		// Enforce at the firewall/ARP layer before committing the state, so
		// the UI never shows a block or limit the host cannot actually apply.
		// (When enforcement is down entirely, clearing a limit still commits —
		// there is nothing to tear down and the status already says why.)
		if reason == "" {
			desired, limited, meter := e.blockSetLocked(id, &cand)
			if err := e.enforceLocked(desired, limited, meter, false); err != nil {
				e.mu.Unlock()
				return model.Device{}, err
			}
		}
	}
	e.devices[id] = cand
	e.mu.Unlock()

	if err := e.st.SaveDevice(cand); err != nil {
		return cand, err
	}
	if p.Kind != nil {
		e.mu.Lock()
		if *p.Kind == "" {
			delete(e.manualKind, id)
		} else {
			e.manualKind[id] = true
		}
		ids := make([]string, 0, len(e.manualKind))
		for k := range e.manualKind {
			ids = append(ids, strconv.FormatInt(k, 10))
		}
		sort.Strings(ids)
		_ = e.st.MetaSet("kind_manual", strings.Join(ids, ","))
		e.mu.Unlock()
	}
	if blockChanged {
		if cand.Blocked {
			e.AddAlert("warning", "Internet access blocked for "+cand.Name, &cand.ID)
		} else {
			e.AddAlert("info", "Internet access restored for "+cand.Name, &cand.ID)
		}
	}
	if speedChanged {
		switch {
		case speedSet:
			e.AddAlert("info", fmt.Sprintf("Speed limit for %s: %d kbit/s down, %d kbit/s up",
				cand.Name, cand.SpeedDown, cand.SpeedUp), &cand.ID)
		case speedWas:
			e.AddAlert("info", "Speed limit removed for "+cand.Name, &cand.ID)
		}
	}
	if trustChanged {
		if cand.Trusted {
			e.AddAlert("warning", cand.Name+" exempted from lockdown mode", &cand.ID)
		} else {
			e.AddAlert("info", cand.Name+" will be cut off when lockdown mode is on", &cand.ID)
		}
	}
	e.publishNow()
	return cand, nil
}

func (e *Engine) PutSettings(s model.Settings) error {
	e.mu.Lock()
	gwChanged := s.GatewayIP != e.settings.GatewayIP
	lockdownChanged := s.Lockdown != e.settings.Lockdown
	if lockdownChanged && s.Lockdown {
		// A lockdown the host cannot enforce is worse than an error: the UI
		// would show the whole network as protected while nothing is cut off.
		if reason := e.blockReasonLocked(); reason != "" {
			e.mu.Unlock()
			return fmt.Errorf("%w: lockdown mode unavailable: %s", ErrInvalid, reason)
		}
	}
	e.settings = s
	e.mu.Unlock()
	if err := e.st.PutSettings(s); err != nil {
		return err
	}
	e.refreshPath()
	if gwChanged {
		// Enforcement is bound to a specific gateway: close the old ARP
		// bridge (repairing its poisons) and reopen against the new one.
		e.rebindBridge()
	}
	if lockdownChanged {
		// Rebuild the block set immediately — waiting for the next poll would
		// leave newly-engaged lockdown half-applied for seconds.
		e.applyRules(false)
		cut, exempt := e.lockdownVictims()
		if s.Lockdown {
			e.AddAlert("critical", fmt.Sprintf(
				"Lockdown engaged — %d device(s) cut off, %d exempt (this machine, router and trusted devices)",
				cut, exempt), nil)
		} else {
			e.AddAlert("info", "Lockdown released — internet restored wherever no other block applies", nil)
		}
	}
	e.publishNow()
	return nil
}

// lockdownVictims counts how many devices lockdown mode currently cuts off and
// how many it leaves alone, so the toggle can report real numbers.
func (e *Engine) lockdownVictims() (cut, exempt int) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	gw := e.settings.GatewayIP
	for _, d := range e.devices {
		if lockdownExempt(d, gw) {
			exempt++
		} else {
			cut++
		}
	}
	return cut, exempt
}

func (e *Engine) Settings() model.Settings {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.settings
}

func (e *Engine) AddAlert(sev, msg string, devID *int64) {
	id, err := e.st.AddAlert(sev, msg, devID, time.Now().UnixMilli())
	if err != nil {
		log.Printf("alert: %v", err)
		return
	}
	e.mu.Lock()
	e.alerts = append([]model.Alert{{ID: id, Sev: sev, Msg: msg, DevID: devID, TS: time.Now().UnixMilli()}}, e.alerts...)
	if len(e.alerts) > alertKeep {
		e.alerts = e.alerts[:alertKeep]
	}
	e.mu.Unlock()
	e.publishNow()
}

func (e *Engine) AckAlert(id int64) error {
	if err := e.st.AckAlert(id); err != nil {
		return err
	}
	e.mu.Lock()
	for i := range e.alerts {
		if e.alerts[i].ID == id {
			e.alerts[i].Read = true
		}
	}
	e.mu.Unlock()
	e.publishNow()
	return nil
}

// ClearAlerts wipes the log everywhere: SQLite (so a restart stays clear) and
// the in-memory snapshot. The fireAlert dedupe map is deliberately untouched —
// a cleared alert stays suppressed until its cooldown lapses, so clearing can't
// be used to make stale conditions spam the log again.
func (e *Engine) ClearAlerts() error {
	if err := e.st.ClearAlerts(); err != nil {
		return err
	}
	e.mu.Lock()
	e.alerts = nil
	e.mu.Unlock()
	e.publishNow()
	return nil
}

// fireAlert logs an alert unless the same key fired within the cooldown.
func (e *Engine) fireAlert(key, sev, msg string, devID *int64, cooldown time.Duration) {
	e.alertMu.Lock()
	last, seen := e.alertFired[key]
	if seen && time.Since(last) < cooldown {
		e.alertMu.Unlock()
		return
	}
	e.alertFired[key] = time.Now()
	e.alertMu.Unlock()
	e.AddAlert(sev, msg, devID)
}

/* ---------- schedule enforcement ---------- */

// parseSchedule splits "HH:MM-HH:MM" (any dash variant) into minute-of-day pairs.
func parseSchedule(s string) (from, to int, ok bool) {
	m := reSchedule.FindStringSubmatch(s)
	if m == nil {
		return 0, 0, false
	}
	h1, e1 := strconv.Atoi(m[1])
	m1, e2 := strconv.Atoi(m[2])
	h2, e3 := strconv.Atoi(m[3])
	m2, e4 := strconv.Atoi(m[4])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil ||
		h1 > 23 || h2 > 23 || m1 > 59 || m2 > 59 {
		return 0, 0, false
	}
	return h1*60 + m1, h2*60 + m2, true
}

// scheduleAllows reports whether internet is allowed inside the active-hours
// window. Empty/invalid windows and degenerate ranges allow always.
func scheduleAllows(schedule string, now time.Time) bool {
	from, to, ok := parseSchedule(schedule)
	if !ok || from == to {
		return true
	}
	cur := now.Hour()*60 + now.Minute()
	if from < to {
		return cur >= from && cur < to
	}
	return cur >= from || cur < to // wraps midnight
}

// effectiveBlocked is the enforced state: manual block, lockdown mode for
// anything not explicitly exempt, or outside active hours. Lockdown is applied
// here rather than by mutating every device, so disengaging it restores
// exactly the previous state (per-device blocks and schedules still stand).
func effectiveBlocked(d model.Device, now time.Time, lockdown bool) bool {
	if d.Blocked {
		return true
	}
	if lockdown && !d.Trusted {
		return true
	}
	return !scheduleAllows(d.Schedule, now)
}

// lockdownExempt reports whether lockdown mode leaves the device alone: the
// host running NetDash, the router, and anything the user marked Trusted. This
// mirrors the exemptions blockSetLocked applies when it builds the block set.
func lockdownExempt(d model.Device, gwIP string) bool {
	return d.Self || d.IP == gwIP || d.Trusted
}

// refreshPath classifies this host as being on the gateway path (traffic of
// other devices crosses us) or behind someone else's router. We are the
// gateway when our own IP is the configured gateway address, or — on Linux —
// when we forward packets across two or more networks (LAN + WAN).
func (e *Engine) refreshPath() {
	gw := e.Settings().GatewayIP
	path := "behind"
	for _, ip := range netinfo.LocalIPs() {
		if ip == gw {
			path = "gateway"
			break
		}
	}
	if path == "behind" && runtime.GOOS == "linux" &&
		netinfo.IPForward() && netinfo.LocalSubnets() >= 2 {
		path = "gateway"
	}
	e.mu.Lock()
	e.path = path
	e.mu.Unlock()
}

// refreshBlockModeLocked picks (once) the enforcement mode: nftables when
// this host is the gateway, ARP poisoning otherwise when raw sockets and a
// usable neighbor table allow it. Callers hold e.mu.
func (e *Engine) refreshBlockModeLocked() {
	if e.blockMode != "" {
		return
	}
	if e.path == "gateway" && e.fwOK {
		e.blockMode = "nft"
		return
	}
	b, err := arpblock.Open(e.settings.GatewayIP)
	if err != nil {
		if ce, ok := err.(*arpblock.ErrNotCapable); ok {
			// The placeholder marks the raw-packet reason — the one whose fix
			// can silently not work, so it gets advice that fits this machine
			// instead of a bare "run setcap".
			if strings.Contains(ce.Reason, "<netdash binary>") {
				e.arpReason = rawPacketAdvice(exeHint, netinfo.FileCapsBlocked(exeHint))
			} else {
				e.arpReason = ce.Reason
			}
		} else {
			e.arpReason = err.Error()
		}
		return
	}
	e.arp = b
	e.blockMode = "arp"
	e.arpReason = ""
	b.SetTap(e.tapRelay)
	b.SetSpoof(e.spoofMatch)
	b.Start()
	log.Printf("blocking: arp poisoning ready (laptop mode)")
}

// refreshBlockMode is the unlocked variant for call sites outside e.mu.
func (e *Engine) refreshBlockMode() {
	e.mu.Lock()
	e.refreshBlockModeLocked()
	e.mu.Unlock()
}

// blockReasonLocked returns "" when blocking/metering can be enforced right
// now, otherwise the human-readable reason it cannot. Callers hold e.mu.
func (e *Engine) blockReasonLocked() string {
	if e.blockMode != "" {
		return ""
	}
	if e.path == "behind" {
		r := "behind gateway " + e.settings.GatewayIP + " — traffic does not cross this host"
		if e.arpReason != "" {
			r += " (arp: " + e.arpReason + ")"
		}
		return r
	}
	if !e.fwOK {
		return e.fwReason
	}
	if e.arpReason != "" {
		return e.arpReason
	}
	return "enforcement unavailable"
}

// blockSetLocked computes the effective block set (ip -> mac), the rate-limit
// set for the ARP bridge (ip -> kbit caps) plus the nft meter list.
// pendingID/pending substitute a device whose patch has not been committed
// yet. Callers hold e.mu.
func (e *Engine) blockSetLocked(pendingID int64, pending *model.Device) (map[string]string, map[string]arpblock.Limit, []firewall.Entry) {
	desired := map[string]string{}
	limited := map[string]arpblock.Limit{}
	var meter []firewall.Entry
	now := time.Now()
	lockdown := e.settings.Lockdown
	for _, x := range e.devices {
		if x.Self || x.IP == e.settings.GatewayIP {
			continue // never meter, block or throttle the host or the router itself
		}
		c := x
		if pending != nil && x.ID == pendingID {
			c = *pending
		}
		if e.blockMode == "nft" {
			meter = append(meter, firewall.Entry{IP: x.IP, MAC: x.MAC})
		}
		blocked := effectiveBlocked(c, now, lockdown)
		if blocked {
			desired[c.IP] = c.MAC
			continue
		}
		if c.MAC != "" && (c.SpeedDown > 0 || c.SpeedUp > 0) {
			limited[c.IP] = arpblock.Limit{MAC: c.MAC, Down: c.SpeedDown, Up: c.SpeedUp}
			continue
		}
		if c.MAC != "" && c.Watched {
			limited[c.IP] = arpblock.Limit{MAC: c.MAC} // intercept: unlimited relay
		}
	}
	return desired, limited, meter
}

// enforcedIPsLocked returns the set currently enforced, mode-agnostic.
// Callers hold e.mu.
func (e *Engine) enforcedIPsLocked() map[string]bool {
	out := map[string]bool{}
	switch e.blockMode {
	case "nft":
		for ip := range e.fwApplied {
			out[ip] = true
		}
	case "arp":
		if e.arp != nil {
			for ip := range e.arp.ActiveBlocked() {
				out[ip] = true
			}
		}
	}
	return out
}

// enforceLocked applies the desired block + rate-limit sets through the
// active mode and persists the enforced state for cross-run cleanup.
// Callers hold e.mu.
func (e *Engine) enforceLocked(desired map[string]string, limited map[string]arpblock.Limit, meter []firewall.Entry, startup bool) error {
	switch e.blockMode {
	case "nft":
		var stale []string
		if startup {
			if raw, ok, _ := e.st.MetaGet("fw_applied"); ok && raw != "" {
				_ = json.Unmarshal([]byte(raw), &stale)
			}
		}
		entries := make([]firewall.Entry, 0, len(desired))
		for ip, mac := range desired {
			entries = append(entries, firewall.Entry{IP: ip, MAC: mac})
		}
		if err := firewall.Apply(entries, meter, stale); err != nil {
			return err
		}
		e.fwApplied = map[string]bool{}
		for ip := range desired {
			e.fwApplied[ip] = true
		}
		e.persistFwAppliedLocked()
	case "arp":
		if e.arp == nil {
			return fmt.Errorf("arp blocker not ready")
		}
		if startup {
			if raw, ok, _ := e.st.MetaGet("arp_poisoned"); ok && raw != "" {
				stale := map[string]string{}
				if json.Unmarshal([]byte(raw), &stale) == nil {
					_ = e.arp.Repair(stale)
				}
			}
		}
		clean := make(map[string]string, len(desired))
		for ip, mac := range desired {
			if mac != "" {
				clean[ip] = mac // ARP needs a MAC; offline/unknown ones are skipped
			}
		}
		cleanLim := make(map[string]arpblock.Limit, len(limited))
		for ip, lim := range limited {
			if lim.MAC != "" {
				cleanLim[ip] = lim
			}
		}
		if err := e.arp.SetState(clean, cleanLim); err != nil {
			return err
		}
		if raw, err := json.Marshal(e.arp.Active()); err == nil {
			_ = e.st.MetaSet("arp_poisoned", string(raw))
		}
	default:
		return fmt.Errorf("%w: blocking unavailable", ErrInvalid)
	}
	return nil
}

// Shutdown releases enforcement: poisoned ARP caches are repaired so
// previously blocked devices reconnect immediately.
func (e *Engine) Shutdown() {
	e.mu.Lock()
	b := e.arp
	e.mu.Unlock()
	if b != nil {
		b.Stop()
	}
}

// persistFwAppliedLocked saves the enforced IP list for cross-run cleanup.
// Callers must hold e.mu.
func (e *Engine) persistFwAppliedLocked() {
	ips := make([]string, 0, len(e.fwApplied))
	for ip := range e.fwApplied {
		ips = append(ips, ip)
	}
	if b, err := json.Marshal(ips); err == nil {
		_ = e.st.MetaSet("fw_applied", string(b))
	}
}

// applyRules reconciles the firewall table: byte counters for every device
// plus drop rules for the enforced blocks. On startup it also cleans up block
// rules left by a previous run. A rebuild resets all counters — the meter
// loop detects that and re-baselines. No-op when this host cannot enforce.
func (e *Engine) applyRules(startup bool) {
	e.refreshBlockMode()
	e.mu.RLock()
	reason := e.blockReasonLocked()
	desired, limited, meter := e.blockSetLocked(0, nil)
	e.mu.RUnlock()
	if reason != "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.enforceLocked(desired, limited, meter, startup); err != nil {
		log.Printf("enforce: %v", err)
	}
}

// deviceFingerprint identifies the current IP set so the meter loop can tell
// when rules must be rebuilt (new/removed devices).
func (e *Engine) deviceFingerprint() string {
	e.mu.RLock()
	ips := make([]string, 0, len(e.devices))
	for _, d := range e.devices {
		ips = append(ips, d.IP)
	}
	e.mu.RUnlock()
	sort.Strings(ips)
	return strings.Join(ips, ",")
}

// meterLoop samples per-device nft byte counters (5 s) and publishes live
// Down/Up rates on each device. Only runs where applyRules actually installs
// counters: Linux + gateway path + firewall capability.
func (e *Engine) meterLoop(ctx context.Context) {
	if runtime.GOOS != "linux" {
		return
	}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	var prev map[string]uint64
	var prevAt time.Time
	fp := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		e.refreshBlockMode()
		e.mu.RLock()
		mode := e.blockMode
		reason := e.blockReasonLocked()
		e.mu.RUnlock()
		if reason != "" {
			prev = nil
			continue
		}
		if mode == "arp" {
			// No nft counters here; keep the poison set reconciled with the
			// device table (new blocks, schedule changes, late capability).
			e.applyRules(false)
			prev = nil
			continue
		}
		if cur := e.deviceFingerprint(); cur != fp {
			e.applyRules(false) // device set changed: rebuild to add counters
			fp = cur
			prev = nil // rebuild resets counters
		}
		counters, err := firewall.ReadCounters()
		now := time.Now()
		if err != nil {
			prev = nil
			continue
		}
		if prev == nil {
			prev, prevAt = counters, now
			continue
		}
		dt := now.Sub(prevAt).Seconds()
		if dt < 1 {
			prev, prevAt = counters, now
			continue
		}
		rate := func(key string) float64 {
			cur, ok := counters[key]
			if !ok {
				return 0
			}
			old := prev[key]
			if cur < old {
				return 0 // table was rebuilt between samples
			}
			return float64(cur-old) * 8 / dt / 1e6
		}
		e.mu.Lock()
		for id, d := range e.devices {
			if d.Self {
				continue // host counters in tick() are authoritative for self
			}
			d.Down = rate("down:" + d.IP)
			d.Up = rate("up:" + d.IP)
			e.devices[id] = d
		}
		e.mu.Unlock()
		prev, prevAt = counters, now
	}
}

// scheduleLoop enforces active-hours windows: outside the window a device's
// internet is cut (and restored when the window opens again).
func (e *Engine) scheduleLoop(ctx context.Context) {
	t := time.NewTicker(scheduleEvery)
	defer t.Stop()
	var prevWant map[string]bool // last tick's per-device schedule state
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		e.refreshBlockMode()
		e.mu.RLock()
		reason := e.blockReasonLocked()
		e.mu.RUnlock()
		if reason != "" {
			continue
		}
		now := time.Now()
		type devRef struct {
			id   int64
			name string
			sch  string
		}
		var entered, left []devRef
		e.mu.RLock()
		devs := make([]model.Device, 0, len(e.devices))
		for _, d := range e.devices {
			devs = append(devs, d)
		}
		// Snapshot everything the loop needs under the lock: PutSettings
		// writes e.settings under e.mu.Lock (was a post-unlock read).
		gwIP := e.settings.GatewayIP
		lockdown := e.settings.Lockdown
		enforced := e.enforcedIPsLocked()
		desired, limited, meter := e.blockSetLocked(0, nil)
		e.mu.RUnlock()

		want := map[string]bool{}
		first := prevWant == nil
		for _, d := range devs {
			w := effectiveBlocked(d, now, lockdown)
			if d.IP != gwIP && !d.Self {
				want[d.IP] = w
			}
			if first {
				continue
			}
			was, known := prevWant[d.IP]
			switch {
			case w && (!known || !was):
				entered = append(entered, devRef{d.ID, d.Name, d.Schedule})
			case !w && known && was:
				left = append(left, devRef{d.ID, d.Name, d.Schedule})
			}
		}
		prevWant = want

		changed := len(enforced) != len(desired)
		if !changed {
			for ip := range desired {
				if !enforced[ip] {
					changed = true
					break
				}
			}
		}
		if !changed {
			continue
		}
		e.mu.Lock()
		err := e.enforceLocked(desired, limited, meter, false)
		e.mu.Unlock()
		if err != nil {
			log.Printf("schedule enforce: %v", err)
			continue
		}
		for _, r := range entered {
			id := r.id
			e.AddAlert("warning",
				r.name+" blocked — outside active hours ("+r.sch+")", &id)
		}
		for _, r := range left {
			id := r.id
			e.AddAlert("info",
				r.name+" internet allowed — inside active hours ("+r.sch+")", &id)
		}
		if len(entered) > 0 || len(left) > 0 {
			e.publishNow()
		}
	}
}

/* ---------- device actions ---------- */

// PingResult is the JSON shape for POST /api/devices/{id}/ping.
type PingResult struct {
	IP        string    `json:"ip"`
	Sent      int       `json:"sent"`
	Recv      int       `json:"recv"`
	Loss      float64   `json:"loss"` // percent
	AvgMs     float64   `json:"avgMs"`
	MinMs     float64   `json:"minMs"`
	MaxMs     float64   `json:"maxMs"`
	Rtts      []float64 `json:"rtts"`
	Reachable bool      `json:"reachable"`
}

// PingDevice runs four pings against a device and returns real statistics.
func (e *Engine) PingDevice(id int64) (PingResult, error) {
	e.mu.RLock()
	d, ok := e.devices[id]
	e.mu.RUnlock()
	if !ok {
		return PingResult{}, ErrNotFound
	}
	res := PingResult{IP: d.IP, Sent: 4, Rtts: []float64{}}
	for i := 0; i < res.Sent; i++ {
		pctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
		rtt, ok := probe.Ping(pctx, d.IP, 800*time.Millisecond)
		cancel()
		if ok {
			ms := float64(rtt.Microseconds()) / 1000
			res.Recv++
			res.Rtts = append(res.Rtts, ms)
			if res.MinMs == 0 || ms < res.MinMs {
				res.MinMs = ms
			}
			if ms > res.MaxMs {
				res.MaxMs = ms
			}
		}
		if i < res.Sent-1 {
			time.Sleep(250 * time.Millisecond)
		}
	}
	if res.Recv > 0 {
		sum := 0.0
		for _, v := range res.Rtts {
			sum += v
		}
		res.AvgMs = sum / float64(res.Recv)
		res.Reachable = true
	}
	res.Loss = float64(res.Sent-res.Recv) / float64(res.Sent) * 100
	return res, nil
}

// ForgetDevice removes a device and suppresses its rediscovery for a grace
// period so it does not immediately reappear on the next ARP/SNMP sweep.
func (e *Engine) ForgetDevice(id int64) error {
	e.mu.Lock()
	d, ok := e.devices[id]
	if !ok {
		e.mu.Unlock()
		return ErrNotFound
	}
	if d.Self {
		e.mu.Unlock()
		return fmt.Errorf("%w: cannot forget this machine", ErrInvalid)
	}
	delete(e.devices, id)
	delete(e.offlineTag, d.IP)
	e.forgotten[d.IP] = time.Now().Add(forgetFor)
	fwSync := e.fwApplied[d.IP]
	e.mu.Unlock()

	if err := e.st.DeleteDevice(id); err != nil {
		return err
	}
	if fwSync {
		e.applyRules(false)
	}
	e.publishNow()
	return nil
}

// ErrNotFound is returned when a device id does not exist.
var ErrNotFound = errors.New("device not found")

// ErrInvalid is returned when a patch fails validation (e.g. bad schedule).
var ErrInvalid = errors.New("invalid value")

func shortMAC(m string) string {
	if len(m) > 8 {
		return m[:8] + "…"
	}
	return m
}
