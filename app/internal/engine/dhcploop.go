package engine

import (
	"context"
	"log"
	"strings"
	"time"

	"netdash/internal/dhcp"
)

// dhcpSniffLoop passively watches DHCP broadcasts for client hostnames. The
// socket is receive-only and needs CAP_NET_RAW; without it the loop exits
// quietly and the rest of the engine is unaffected.
func (e *Engine) dhcpSniffLoop(ctx context.Context) {
	s, err := dhcp.Open(e.Settings().GatewayIP)
	if err != nil {
		log.Printf("dhcp: sniffer disabled: %v", err)
		return
	}
	defer s.Close()
	log.Printf("dhcp: sniffer listening for lease broadcasts")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		frame, ok := s.Next()
		if !ok {
			continue
		}
		if ev, hit := dhcp.Parse(frame); hit {
			e.observeDHCP(ev)
		}
	}
}

// observeDHCP folds a sniffed DHCP exchange into the matching device (by MAC).
// A hostname fills a placeholder name and is saved to intel — the same intel
// an intercept would collect, learned without touching traffic. A user-set
// name always wins; kind re-inference follows the resolveNameAsync policy.
func (e *Engine) observeDHCP(ev dhcp.Ev) {
	if ev.MAC == "" || ev.Hostname == "" {
		return
	}
	var ids []int64
	changed := false
	now := time.Now().UnixMilli()
	e.mu.Lock()
	for id, d := range e.devices {
		if !strings.EqualFold(d.MAC, ev.MAC) {
			continue
		}
		ids = append(ids, id)
		if d.Name == "" || d.Name == "Device "+d.IP {
			d.Name = ev.Hostname
			if !e.manualKind[id] {
				if k := e.inferKindLocked(d); k != "" {
					d.Kind = k
				}
			}
			e.devices[id] = d
			if err := e.st.SaveDevice(d); err != nil {
				log.Printf("dhcp: save %s: %v", d.IP, err)
			}
			changed = true
		}
	}
	e.mu.Unlock()
	if len(ids) == 0 {
		return
	}
	for _, id := range ids {
		if err := e.st.SaveIntel(id, "dhcp", ev.Hostname, now); err != nil {
			log.Printf("dhcp: intel: %v", err)
		}
	}
	if changed {
		e.publishNow()
	}
	log.Printf("dhcp: %s → %s", ev.MAC, ev.Hostname)
}
