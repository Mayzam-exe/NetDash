package probe

import (
	"context"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"time"
)

var (
	reLinux = regexp.MustCompile(`time[=<]([0-9.]+)\s*ms`)
	reWin   = regexp.MustCompile(`time[=<]?([0-9.]+)\s*ms`)
	reTTL   = regexp.MustCompile(`(?i)ttl=([0-9]+)`)
)

// Ping measures RTT to ip using the system ping utility (no raw-socket privileges required).
// Returns the RTT and true on success, or (-1, false) on failure/timeout.
func Ping(ctx context.Context, ip string, timeout time.Duration) (time.Duration, bool) {
	rtt, _, ok := PingTTL(ctx, ip, timeout)
	return rtt, ok
}

// PingTTL is Ping plus the reply's TTL header. The TTL is an OS fingerprint
// hint: Windows replies start at 128, Linux/Android/iOS/macOS at 64, network
// gear at 255 — on a single LAN hop the received value is still the original.
// ttl is -1 when the reply could not be parsed.
func PingTTL(ctx context.Context, ip string, timeout time.Duration) (time.Duration, int, bool) {
	if ip == "" {
		return -1, -1, false
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		ms := timeout.Milliseconds()
		if ms < 1000 {
			ms = 1000
		}
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", strconv.FormatInt(ms, 10), ip)
	} else {
		secs := int(timeout.Seconds())
		if secs < 1 {
			secs = 1
		}
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(secs), ip)
	}
	b, err := cmd.CombinedOutput()
	if err != nil {
		return -1, -1, false
	}
	s := string(b)
	ttl := -1
	if m := reTTL.FindStringSubmatch(s); m != nil {
		if v, err := strconv.Atoi(m[1]); err == nil {
			ttl = v
		}
	}
	re := reLinux
	if runtime.GOOS == "windows" {
		re = reWin
	}
	if m := re.FindStringSubmatch(s); m != nil {
		if v, err := strconv.ParseFloat(m[1], 64); err == nil {
			return time.Duration(v * float64(time.Millisecond)), ttl, true
		}
	}
	// Exit code success but no parsed sample (locale differences): treat as reachable.
	return time.Millisecond, ttl, true
}
