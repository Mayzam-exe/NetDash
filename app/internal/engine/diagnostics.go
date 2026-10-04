package engine

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"netdash/internal/netinfo"
)

/* ---------- Troubleshoot diagnostics ---------- */

// TraceHop is one TTL step of a traceroute: the answering router (or the
// target itself) and the probe RTTs. Empty IP = no reply ("*").
type TraceHop struct {
	IP      string    `json:"ip"`
	Rtts    []float64 `json:"rtts"`
	Reached bool      `json:"reached"`
}

type TracerouteResult struct {
	Hops    []TraceHop `json:"hops"`
	Reached bool       `json:"reached"`
	Probes  int        `json:"probes"`
}

type DNSResult struct {
	PTR  []string `json:"ptr"`
	Fwd  []string `json:"fwd"`
	MS   float64  `json:"ms"`
	Note string   `json:"note"`
}

type CmdResult struct {
	Lines []string `json:"lines"`
	OK    bool     `json:"ok"`
}

const traceMaxHops = 5

// TracerouteDevice walks TTLs toward the device's IP using the system ping
// binary: routers answer ICMP time-exceeded, the destination answers the
// echo itself. Unprivileged, works everywhere ping exists — no traceroute
// binary or raw sockets required.
func (e *Engine) TracerouteDevice(id int64) (TracerouteResult, error) {
	e.mu.RLock()
	d, ok := e.devices[id]
	e.mu.RUnlock()
	if !ok {
		return TracerouteResult{}, ErrNotFound
	}
	res := TracerouteResult{Hops: []TraceHop{}}
	if d.IP == "" {
		return res, nil
	}
	selfIP, _, _ := netinfo.LocalSelf()
	dead := 0
	for ttl := 1; ttl <= traceMaxHops; ttl++ {
		hop := TraceHop{Rtts: []float64{}}
		for i := 0; i < 2; i++ {
			ip, ms, kind := pingTTLProbe(d.IP, ttl, selfIP)
			switch kind {
			case "target":
				hop.IP, hop.Reached = ip, true
				if ms >= 0 {
					hop.Rtts = append(hop.Rtts, ms)
				}
				res.Probes++
			case "hop":
				if hop.IP == "" {
					hop.IP = ip
				}
				if ms >= 0 {
					hop.Rtts = append(hop.Rtts, ms)
				}
				res.Probes++
			}
			time.Sleep(150 * time.Millisecond)
		}
		res.Hops = append(res.Hops, hop)
		if hop.Reached {
			res.Reached = true
			return res, nil
		}
		if hop.IP == "" {
			dead++
			if dead >= 2 {
				return res, nil // two silent hops: target is not answering
			}
		} else {
			dead = 0
		}
	}
	return res, nil
}

// pingTTLProbe sends one echo with the given TTL and classifies the answer.
// kind: "target" (echo reply from the destination), "hop" (a router spoke
// for us), or "none" (silence / parse failure / our own kernel's unreachable
// message, which is not a hop).
func pingTTLProbe(target string, ttl int, selfIP string) (ip string, ms float64, kind string) {
	// Guard against argument injection: only a literal IP reaches the argv.
	if net.ParseIP(target) == nil {
		return "", -1, "none"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1400*time.Millisecond)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", "1000", "-i", strconv.Itoa(ttl), target)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", "-t", strconv.Itoa(ttl), target)
	}
	out, _ := cmd.CombinedOutput()
	return parsePingTTLProbe(string(out), target, selfIP)
}

var (
	reTraceFrom     = regexp.MustCompile(`(?i)(?:reply )?from\s+([0-9.]+)`)
	reTraceBytes    = regexp.MustCompile(`(?i)bytes from\s+([0-9.]+)`)
	reTraceWinReply = regexp.MustCompile(`(?i)reply from\s+([0-9.]+):`)
	reTraceTime     = regexp.MustCompile(`time[=<]([0-9.]+)\s*ms`)
	reTraceExceeded = regexp.MustCompile(`(?i)(time[- ]to[- ]live exceeded|ttl expired)`)
	reTraceUnreach  = regexp.MustCompile(`(?i)destination.*unreachable`)
)

// parsePingTTLProbe classifies one ping -t/-i output block. ms is -1 when
// the reply carried no parseable time. Answers sourced from our own IP are
// the local kernel's "host unreachable" — not a hop on the path.
func parsePingTTLProbe(out, target, selfIP string) (string, float64, string) {
	ms := -1.0
	if m := reTraceTime.FindStringSubmatch(out); m != nil {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil {
			ms = v
		}
	}
	if reTraceExceeded.MatchString(out) || reTraceUnreach.MatchString(out) {
		if m := reTraceFrom.FindStringSubmatch(out); m != nil && m[1] != selfIP {
			return m[1], ms, "hop"
		}
		return "", -1, "none"
	}
	// Echo reply: Linux "64 bytes from <ip>: …" / Windows "Reply from <ip>: …".
	ip := ""
	if m := reTraceBytes.FindStringSubmatch(out); m != nil {
		ip = m[1]
	} else if m := reTraceWinReply.FindStringSubmatch(out); m != nil {
		ip = m[1]
	}
	if ip != "" {
		if ip == target {
			return ip, ms, "target"
		}
		return ip, ms, "hop"
	}
	return "", -1, "none"
}

// DNSLookup performs a real reverse (PTR) lookup for the device's IP and,
// when the device has a real hostname, a forward lookup through the system
// resolver with an mDNS (avahi-resolve) fallback for bare/.local names.
func (e *Engine) DNSLookup(id int64) (DNSResult, error) {
	e.mu.RLock()
	d, ok := e.devices[id]
	e.mu.RUnlock()
	if !ok {
		return DNSResult{}, ErrNotFound
	}
	start := time.Now()
	res := DNSResult{PTR: []string{}, Fwd: []string{}}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	if names, err := net.DefaultResolver.LookupAddr(ctx, d.IP); err == nil {
		for _, n := range names {
			res.PTR = append(res.PTR, strings.TrimSuffix(n, "."))
		}
	}

	name := strings.TrimSpace(d.Name)
	placeholder := name == "" || name == "Device "+d.IP || name == "_gateway"
	if placeholder {
		res.Note = "no hostname on this device — reverse lookup only"
	} else if ips, err := net.DefaultResolver.LookupHost(ctx, name); err == nil {
		res.Fwd = ips
	} else {
		// Bare hostnames rarely resolve via unicast DNS on home networks —
		// try mDNS form through avahi when present.
		mdnsName := name
		if !strings.HasSuffix(mdnsName, ".local") {
			mdnsName += ".local"
		}
		// Never hand a hyphen-leading or whitespace-bearing name to argv.
		if strings.HasPrefix(mdnsName, "-") || strings.ContainsAny(mdnsName, " \t\r\n") {
			res.Note = "forward lookup skipped — hostname " + name + " is not safe to resolve"
			return res, nil
		}
		out, aerr := runCmd(2*time.Second, "avahi-resolve", "-n", mdnsName)
		if aerr == nil {
			for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
				f := strings.Fields(line)
				if len(f) == 2 && net.ParseIP(f[1]) != nil {
					res.Fwd = append(res.Fwd, f[1])
				}
			}
		}
		switch {
		case len(res.Fwd) > 0:
			res.Note = "forward record found via mDNS (" + mdnsName + ")"
		case aerr == nil:
			res.Note = "no forward record for " + name
		default:
			res.Note = "forward lookup failed for " + name + "; mDNS: " + cmdDetail(out, aerr)
		}
	}
	res.MS = float64(time.Since(start).Microseconds()) / 1000
	return res, nil
}

// RenewDHCP cycles this machine's link so NetworkManager performs a real
// DHCP release/discover cycle. Client devices cannot be renewed from here —
// they have no agent — so only the self device is accepted.
func (e *Engine) RenewDHCP(id int64) (CmdResult, error) {
	e.mu.RLock()
	d, ok := e.devices[id]
	e.mu.RUnlock()
	if !ok {
		return CmdResult{}, ErrNotFound
	}
	if !d.Self {
		return CmdResult{}, fmt.Errorf("%w: renew is only available for this machine", ErrInvalid)
	}
	_, _, ifName := netinfo.LocalSelf()
	if ifName == "" {
		return CmdResult{}, fmt.Errorf("%w: no local interface found", ErrInvalid)
	}
	before, _, _ := netinfo.LocalSelf()
	start := time.Now()
	res := CmdResult{Lines: []string{}}
	add := func(s string) { res.Lines = append(res.Lines, s) }

	add("$ nmcli connection up ifname " + ifName + "  (fresh DHCP cycle)")
	out, err := runCmd(25*time.Second, "nmcli", "-w", "20", "connection", "up", "ifname", ifName)
	if err == nil {
		add("nmcli: connection up on " + ifName + " — lease renew requested")
	} else {
		add("nmcli: " + cmdDetail(out, err))
		add("falling back to in-process link bounce (CAP_NET_ADMIN)…")
		if berr := netinfo.LinkBounce(ifName); berr != nil {
			add("✗ link bounce failed: " + berr.Error())
			return res, nil
		}
		add("carrier bounced on " + ifName + " — DHCP re-acquiring")
	}

	after := ""
	for i := 0; i < 30; i++ {
		time.Sleep(500 * time.Millisecond)
		ip, _, _ := netinfo.LocalSelf()
		if ip != "" {
			after = ip
			break
		}
	}
	sec := time.Since(start).Seconds()
	if after != "" {
		if after == before {
			add(fmt.Sprintf("✓ online: %s (address unchanged) in %.1fs", after, sec))
		} else {
			add(fmt.Sprintf("✓ back online: %s (was %s) in %.1fs", after, before, sec))
		}
		res.OK = true
	} else {
		add("✗ interface did not come back with an address in 15s")
	}
	return res, nil
}

// RestartRadio powers this machine's Wi-Fi radio off and back on (real
// rfkill/NM radio toggle), then waits for it to rejoin. Client devices are
// rejected: NetDash has no agent on them.
func (e *Engine) RestartRadio(id int64) (CmdResult, error) {
	e.mu.RLock()
	d, ok := e.devices[id]
	e.mu.RUnlock()
	if !ok {
		return CmdResult{}, ErrNotFound
	}
	if !d.Self {
		return CmdResult{}, fmt.Errorf("%w: radio restart is only available for this machine", ErrInvalid)
	}
	start := time.Now()
	res := CmdResult{Lines: []string{}}
	add := func(s string) { res.Lines = append(res.Lines, s) }

	add("$ nmcli radio wifi off")
	out, err := runCmd(6*time.Second, "nmcli", "radio", "wifi", "off")
	if err != nil {
		add("✗ nmcli radio wifi off: " + cmdDetail(out, err))
		return res, nil
	}
	add("radio off — link down")
	time.Sleep(1500 * time.Millisecond)

	add("$ nmcli radio wifi on")
	out, err = runCmd(6*time.Second, "nmcli", "radio", "wifi", "on")
	if err != nil {
		add("✗ nmcli radio wifi on: " + cmdDetail(out, err))
		return res, nil
	}
	add("radio on — rejoining network…")

	after := ""
	for i := 0; i < 40; i++ {
		time.Sleep(500 * time.Millisecond)
		ip, _, _ := netinfo.LocalSelf()
		if ip != "" {
			after = ip
			break
		}
	}
	sec := time.Since(start).Seconds()
	if after != "" {
		add(fmt.Sprintf("✓ connected again: %s after %.1fs", after, sec))
		res.OK = true
	} else {
		add("✗ radio did not rejoin within 20s — check Wi-Fi settings")
	}
	return res, nil
}

func runCmd(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// cmdDetail prefers the command's own (first non-empty) output line over a
// bare exit-status error, so terminals show the real reason for a failure.
func cmdDetail(out string, err error) string {
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); s != "" {
			return s
		}
	}
	if err != nil {
		return err.Error()
	}
	return "command failed"
}
