package engine

import (
	"errors"
	"testing"

	"netdash/internal/model"
)

func TestParsePingTTLProbe(t *testing.T) {
	cases := []struct {
		name, out, target string
		wantIP, wantKind  string
		wantMs            float64
	}{
		{
			name: "linux time exceeded", target: "8.8.8.8",
			out:      "From 192.168.1.1 icmp_seq=1 Time-to-live exceeded\n",
			wantIP:   "192.168.1.1",
			wantKind: "hop",
			wantMs:   -1,
		},
		{
			name: "linux echo reply", target: "192.168.1.54",
			out:      "64 bytes from 192.168.1.54: icmp_seq=1 ttl=64 time=0.512 ms\n",
			wantIP:   "192.168.1.54",
			wantKind: "target",
			wantMs:   0.512,
		},
		{
			name: "linux echo from unexpected ip", target: "192.168.1.54",
			out:      "64 bytes from 10.0.0.5: icmp_seq=1 ttl=64 time=2.0 ms\n",
			wantIP:   "10.0.0.5",
			wantKind: "hop",
			wantMs:   2.0,
		},
		{
			name: "windows ttl expired", target: "8.8.8.8",
			out:      "Reply from 192.168.1.1: TTL expired in transit.\r\n",
			wantIP:   "192.168.1.1",
			wantKind: "hop",
			wantMs:   -1,
		},
		{
			name: "windows echo reply", target: "192.168.1.54",
			out:      "Reply from 192.168.1.54: bytes=32 time=12ms TTL=64\r\n",
			wantIP:   "192.168.1.54",
			wantKind: "target",
			wantMs:   12,
		},
		{
			name: "linux destination unreachable", target: "192.168.1.99",
			out:      "From 192.168.1.1 icmp_seq=1 Destination Host Unreachable\n",
			wantIP:   "192.168.1.1",
			wantKind: "hop",
			wantMs:   -1,
		},
		{
			name: "silence", target: "192.168.1.54",
			out:      "PING 192.168.1.54 56(84) bytes of data.\n\n--- 192.168.1.54 ping statistics ---\n",
			wantIP:   "",
			wantKind: "none",
			wantMs:   -1,
		},
		{
			name: "windows timeout", target: "192.168.1.54",
			out:      "Request timed out.\r\n",
			wantIP:   "",
			wantKind: "none",
			wantMs:   -1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ip, ms, kind := parsePingTTLProbe(c.out, c.target, "192.168.1.48")
			if ip != c.wantIP || kind != c.wantKind || ms != c.wantMs {
				t.Errorf("got (%q, %v, %q), want (%q, %v, %q)", ip, ms, kind, c.wantIP, c.wantMs, c.wantKind)
			}
		})
	}

	// Our own kernel's "host unreachable" is not a hop: the responder is us.
	ip, _, kind := parsePingTTLProbe(
		"From 192.168.1.48 icmp_seq=1 Destination Host Unreachable\n", "192.168.1.35", "192.168.1.48")
	if kind != "none" || ip != "" {
		t.Errorf("self-unreachable classified as (%q, %q), want none", ip, kind)
	}
}

func TestTroubleshootNotFound(t *testing.T) {
	e := newTestEngine(t)
	if _, err := e.TracerouteDevice(9999); !errors.Is(err, ErrNotFound) {
		t.Errorf("traceroute: err=%v, want ErrNotFound", err)
	}
	if _, err := e.DNSLookup(9999); !errors.Is(err, ErrNotFound) {
		t.Errorf("dns: err=%v, want ErrNotFound", err)
	}
	if _, err := e.RenewDHCP(9999); !errors.Is(err, ErrNotFound) {
		t.Errorf("renew: err=%v, want ErrNotFound", err)
	}
	if _, err := e.RestartRadio(9999); !errors.Is(err, ErrNotFound) {
		t.Errorf("restart: err=%v, want ErrNotFound", err)
	}
}

// Renew/radio restart are physically impossible on remote clients (no
// agent) — they must reject non-self devices instead of faking success.
func TestTroubleshootSelfOnly(t *testing.T) {
	e := newTestEngine(t)
	e.mu.Lock()
	e.devices[7] = model.Device{ID: 7, IP: "192.168.1.77", Name: "Device 192.168.1.77"}
	e.mu.Unlock()

	if _, err := e.RenewDHCP(7); !errors.Is(err, ErrInvalid) {
		t.Errorf("renew on client: err=%v, want ErrInvalid", err)
	}
	if _, err := e.RestartRadio(7); !errors.Is(err, ErrInvalid) {
		t.Errorf("restart on client: err=%v, want ErrInvalid", err)
	}
}

func TestDNSLookupRealResolvers(t *testing.T) {
	e := newTestEngine(t)
	e.mu.Lock()
	e.devices[9] = model.Device{ID: 9, IP: "127.0.0.1", Name: "localhost"}
	e.mu.Unlock()

	res, err := e.DNSLookup(9)
	if err != nil {
		t.Fatalf("DNSLookup: %v", err)
	}
	if len(res.PTR) == 0 || res.PTR[0] != "localhost" {
		t.Errorf("PTR = %v, want [localhost]", res.PTR)
	}
	found := false
	for _, a := range res.Fwd {
		if a == "127.0.0.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("fwd = %v, want 127.0.0.1", res.Fwd)
	}
}
