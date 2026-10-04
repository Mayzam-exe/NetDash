package engine

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"netdash/internal/intel"
	"netdash/internal/model"
)

// intelSample is one relayed frame handed off by the arp-blocker tap.
type intelSample struct {
	ip    string
	up    bool
	frame []byte
}

// tapRelay is installed on the blocker; it copies the original frame into
// the intel channel without ever blocking the relay path.
func (e *Engine) tapRelay(ip string, up bool, f []byte) {
	select {
	case e.intelCh <- intelSample{ip: ip, up: up, frame: append([]byte(nil), f...)}:
	default: // drop rather than stall the relay
	}
}

// intelLoop parses tapped frames, maps them to devices and stores findings
// (deduped per device+value for one minute).
func (e *Engine) intelLoop() {
	const dedupWindow = time.Minute
	pruned := 0
	for s := range e.intelCh {
		dv := e.deviceByIP(s.ip)
		if dv.ID == 0 {
			continue
		}
		for _, fi := range intel.Parse(s.up, s.frame) {
			key := fmt.Sprintf("%d|%s|%s", dv.ID, fi.Kind, fi.Value)
			if t, ok := e.intelMemo[key]; ok && time.Since(t) < dedupWindow {
				continue
			}
			e.intelMemo[key] = time.Now()
			if err := e.st.SaveIntel(dv.ID, fi.Kind, fi.Value, time.Now().UnixMilli()); err != nil {
				log.Printf("intel: save: %v", err)
			}
		}
		// Keep the dedup map bounded: an entry older than the window can never
		// suppress another write, so drop stale keys periodically. Without this
		// the map grows forever (one entry per distinct finding ever seen).
		if pruned++; pruned >= 256 {
			pruned = 0
			now := time.Now()
			for k, t := range e.intelMemo {
				if now.Sub(t) >= dedupWindow {
					delete(e.intelMemo, k)
				}
			}
		}
	}
}

func (e *Engine) deviceByIP(ip string) model.Device {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, d := range e.devices {
		if d.IP == ip && !d.Self {
			return d
		}
	}
	return model.Device{}
}

// spoofMatch answers a DNS name from the loaded rules: exact match first,
// then suffix match (rule "example.com" covers "a.b.example.com").
func (e *Engine) spoofMatch(name string) string {
	e.spoofMu.RLock()
	defer e.spoofMu.RUnlock()
	if ip := e.spoof[name]; ip != "" {
		return ip
	}
	for {
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return ""
		}
		name = name[i+1:]
		if ip := e.spoof[name]; ip != "" {
			return ip
		}
	}
}

// ReloadSpoof rebuilds the in-memory matcher from the store.
func (e *Engine) ReloadSpoof() error {
	rules, err := e.st.ListSpoofRules()
	if err != nil {
		return err
	}
	m := make(map[string]string, len(rules))
	for _, r := range rules {
		m[strings.ToLower(strings.TrimSpace(r.Domain))] = r.IP
	}
	e.spoofMu.Lock()
	e.spoof = m
	e.spoofMu.Unlock()
	return nil
}

// IntelFor returns the latest findings for a device, newest first.
func (e *Engine) IntelFor(devID int64, limit int) ([]model.Intel, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	items, err := e.st.ListIntel(devID, limit)
	if items == nil {
		items = []model.Intel{}
	}
	return items, err
}

// SpoofRules lists the DNS spoof table.
func (e *Engine) SpoofRules() ([]model.SpoofRule, error) {
	rules, err := e.st.ListSpoofRules()
	if rules == nil {
		rules = []model.SpoofRule{}
	}
	return rules, err
}

// PutSpoofRule validates and upserts a rule, then reloads the matcher.
func (e *Engine) PutSpoofRule(domain, ip string) (model.SpoofRule, error) {
	domain = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(domain), "*"))
	domain = strings.TrimPrefix(domain, ".")
	if domain == "" || strings.ContainsAny(domain, " \t/:@") {
		return model.SpoofRule{}, fmt.Errorf("%w: bad domain", ErrInvalid)
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return model.SpoofRule{}, fmt.Errorf("%w: bad ip (IPv4 required)", ErrInvalid)
	}
	r, err := e.st.AddSpoofRule(domain, parsed.String())
	if err != nil {
		return model.SpoofRule{}, err
	}
	if err := e.ReloadSpoof(); err != nil {
		return model.SpoofRule{}, err
	}
	return r, nil
}

// DelSpoofRule removes a rule and reloads the matcher.
func (e *Engine) DelSpoofRule(id int64) error {
	if err := e.st.DeleteSpoofRule(id); err != nil {
		return err
	}
	return e.ReloadSpoof()
}
