// Package firewall enforces internet-block decisions on the local machine.
//
// NetDash can only cut a device's internet if it runs where the traffic
// crosses: on the router/Linux gateway (nftables) or on a Windows host
// (firewall service). Elsewhere, Capable reports why blocking is unavailable
// and Apply is never called — the API surfaces the reason instead of faking a
// block.
package firewall

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	"netdash/internal/helper"
)

// Entry is one host that must not reach the internet.
type Entry struct {
	IP  string
	MAC string
}

// Capable reports whether device blocking can be enforced on this host and a
// human-readable reason when it cannot.
func Capable() (bool, string) {
	switch runtime.GOOS {
	case "linux":
		// Authority first: the live probe below would also refuse, but only
		// with the kernel's bare "Operation not permitted", which names no
		// fix. This names it.
		if ok, why := helper.Capable("nft"); !ok {
			return false, why
		}
		if out, err := exec.Command(helper.Path("nft"), "list", "tables").CombinedOutput(); err != nil {
			msg := strings.TrimSpace(string(out))
			if msg == "" {
				msg = err.Error()
			}
			return false, "nft: " + firstLine(msg)
		}
		return true, "nftables"
	case "windows":
		if _, err := exec.LookPath("netsh"); err != nil {
			return false, "netsh not found"
		}
		return true, "windows firewall"
	default:
		return false, "unsupported platform (" + runtime.GOOS + ")"
	}
}

// Apply reconciles the host firewall to the given state. blocked lists hosts
// whose traffic must be dropped; meter lists every known host that should get
// a byte counter (Linux only; Windows has no cheap per-IP counters). stale
// lists IPs that a previous run may have rules for (Windows needs explicit
// cleanup; nftables rebuilds its table from scratch and ignores it).
func Apply(blocked, meter []Entry, stale []string) error {
	switch runtime.GOOS {
	case "linux":
		return applyNft(blocked, meter)
	case "windows":
		return applyNetsh(blocked, stale)
	default:
		return fmt.Errorf("unsupported platform (%s)", runtime.GOOS)
	}
}

// applyNft rebuilds an isolated `inet netdash` table: one pair of counter
// rules per metered host (before the drops, so blocked traffic is still
// counted), then a drop rule per blocked host. Full rebuild keeps the
// operation idempotent and self-healing after crashes or manual edits —
// callers must know it resets counters.
func applyNft(blocked, meter []Entry) error {
	// Drop the previous table (ignore: it may not exist).
	_ = exec.Command(helper.Path("nft"), "delete", "table", "inet", "netdash").Run()
	if len(blocked) == 0 && len(meter) == 0 {
		return nil
	}
	sortedMeter := append([]Entry(nil), meter...)
	sort.Slice(sortedMeter, func(i, j int) bool { return sortedMeter[i].IP < sortedMeter[j].IP })
	sortedBlocked := append([]Entry(nil), blocked...)
	sort.Slice(sortedBlocked, func(i, j int) bool { return sortedBlocked[i].IP < sortedBlocked[j].IP })

	var b strings.Builder
	b.WriteString("table inet netdash {\n")
	b.WriteString("\tchain forward {\n")
	b.WriteString("\t\ttype filter hook forward priority 0; policy accept;\n")
	for _, e := range sortedMeter {
		if net.ParseIP(e.IP) == nil {
			continue
		}
		fmt.Fprintf(&b, "\t\tip saddr %s counter comment \"nd:up:%s\"\n", e.IP, e.IP)
		fmt.Fprintf(&b, "\t\tip daddr %s counter comment \"nd:down:%s\"\n", e.IP, e.IP)
	}
	for _, e := range sortedBlocked {
		if ip := net.ParseIP(e.IP); ip != nil && ip.To4() != nil {
			fmt.Fprintf(&b, "\t\tip saddr %s drop\n", e.IP)
		}
		if mac, err := net.ParseMAC(e.MAC); err == nil && mac != nil {
			fmt.Fprintf(&b, "\t\tether saddr %s drop\n", strings.ToLower(e.MAC))
		}
	}
	b.WriteString("\t}\n}\n")
	cmd := exec.Command(helper.Path("nft"), "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("nft apply: %s", firstLine(msg))
	}
	return nil
}

// ReadCounters returns cumulative byte counters from the NetDash nft table,
// keyed "up:<ip>" (traffic from the device) and "down:<ip>" (traffic to it).
func ReadCounters() (map[string]uint64, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("counter reading requires Linux nftables")
	}
	cmd := exec.Command(helper.Path("nft"), "--json", "list", "table", "inet", "netdash")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nft list: %v", err)
	}
	return parseCounters(out)
}

// parseCounters extracts nd:<dir>:<ip>-tagged counter rules from `nft --json`
// output. Exported behaviour is covered by tests via this helper.
func parseCounters(data []byte) (map[string]uint64, error) {
	var doc struct {
		Nftables []json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("nft json: %v", err)
	}
	out := map[string]uint64{}
	for _, raw := range doc.Nftables {
		var wrapper map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wrapper); err != nil {
			continue
		}
		ruleRaw, ok := wrapper["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Expr []map[string]json.RawMessage `json:"expr"`
		}
		if err := json.Unmarshal(ruleRaw, &rule); err != nil {
			continue
		}
		var comment string
		var bytes uint64
		hasCounter := false
		for _, expr := range rule.Expr {
			if c, ok := expr["comment"]; ok {
				_ = json.Unmarshal(c, &comment)
			}
			if c, ok := expr["counter"]; ok {
				var ctr struct {
					Bytes uint64 `json:"bytes"`
				}
				if err := json.Unmarshal(c, &ctr); err == nil {
					bytes = ctr.Bytes
					hasCounter = true
				}
			}
		}
		if !hasCounter || !strings.HasPrefix(comment, "nd:") {
			continue
		}
		// comment format: nd:<up|down>:<ip>
		parts := strings.SplitN(comment, ":", 3)
		if len(parts) != 3 || (parts[1] != "up" && parts[1] != "down") || parts[2] == "" {
			continue
		}
		out[parts[1]+":"+parts[2]] = bytes
	}
	return out, nil
}

// applyNetsh maintains one inbound + one outbound block rule per IP. Rules are
// deleted before being (re)created so repeated calls stay idempotent, and IPs
// from stale (previous runs) that are no longer wanted get removed.
func applyNetsh(entries []Entry, stale []string) error {
	want := make(map[string]bool, len(entries))
	for _, e := range entries {
		want[e.IP] = true
	}
	for _, ip := range stale {
		if ip != "" && !want[ip] {
			delNetshRule(ip)
		}
	}
	for _, e := range entries {
		// Reject anything that is not a literal IP: the value is interpolated
		// into netsh rule names and remoteip= arguments.
		if net.ParseIP(e.IP) == nil {
			continue
		}
		delNetshRule(e.IP)
		if err := addNetshRule(e.IP, "in"); err != nil {
			return err
		}
		if err := addNetshRule(e.IP, "out"); err != nil {
			return err
		}
	}
	return nil
}

func delNetshRule(ip string) {
	_ = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule",
		"name="+ruleName(ip)).Run()
}

func addNetshRule(ip, dir string) error {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+ruleName(ip), "dir="+dir, "action=block", "remoteip="+ip)
	if out, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("netsh add rule: %s", firstLine(msg))
	}
	return nil
}

func ruleName(ip string) string { return "netdash-block-" + ip }

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return strings.TrimSpace(s)
}
