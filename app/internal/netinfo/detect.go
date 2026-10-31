package netinfo

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Detected is everything this host's own OS stack reports about the network
// it is currently on. Every field degrades to its zero value when the tool
// or the answer is unavailable — callers must read "" as "unknown", never as
// a value to clear anything with. Nothing here reaches into the router: it
// is exactly what `nmcli`, `iw`, resolv.conf and one internet echo service
// are willing to say.
type Detected struct {
	WanType  string   `json:"wanType"` // DHCP | Static | PPPoE
	DNS      []string `json:"dns"`     // OS resolvers, up to two
	SSID24   string   `json:"ssid24"`
	SSID5    string   `json:"ssid5"`
	Ch24     string   `json:"ch24"`
	Ch5      string   `json:"ch5"`
	Bw24     string   `json:"bw24"`
	Bw5      string   `json:"bw5"`
	Sec      string   `json:"sec"`      // WPA3 | WPA2
	PublicIP string   `json:"publicIp"` // egress address seen by the internet
}

// Detect gathers the current network's settings from the local OS. It never
// fails as a whole: each probe is best-effort with a tight timeout, so a
// missing tool (no NetworkManager, wired-only host) simply leaves the
// matching fields empty.
func Detect() Detected {
	var d Detected

	_, _, iface := LocalSelf()

	// The connected radio is authoritative for its own band: SSID, channel
	// and width come straight from `iw` while associated.
	connected := ""
	if iface != "" && !strings.HasPrefix(iface, "lo") {
		if out, err := sh(2*time.Second, "iw", "dev", iface, "link"); err == nil {
			if ssid, freq, _, ch, bw, _ := parseLinkDetail(string(out)); ssid != "" && freq > 0 {
				connected = ssid
				switch bandOfFreq(freq) {
				case "24":
					d.SSID24, d.Ch24, d.Bw24 = ssid, ch, bw
				case "5":
					d.SSID5, d.Ch5, d.Bw5 = ssid, ch, bw
				}
			}
		}
		// NetworkManager: which connection carries this interface, and how
		// it gets its address.
		name, typ := activeConn(iface)
		d.WanType = wanTypeOf(typ, ipv4Method(name))
		if typ == "802-11-wireless" {
			d.Sec = secOf(keyMgmt(name))
		}
		d.DNS = deviceDNS(iface)
	}

	// The scan cache may complete what iw could not — the connected band's
	// channel when iw omitted it, or the other band of an identical-name
	// dual-band AP. Strict pairing: only rows bearing the connected SSID are
	// ever claimed (a neighbour's stronger AP must never be labelled as
	// this router's second band), and nothing is claimed while this host is
	// not on a wireless network at all. --rescan no keeps the read instant.
	fillFromCache(&d, connected, wifiCache())

	if len(d.DNS) == 0 {
		d.DNS = resolvDNS()
	}
	d.PublicIP = publicIP()
	return d
}

// sh runs a read-only query command with a tight timeout.
func sh(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

// splitEscaped splits an nmcli terse field line on sep, honoring nmcli's
// backslash escapes ("My\:Net" carries a literal colon inside the SSID).
func splitEscaped(s string, sep byte) []string {
	var out []string
	var cur strings.Builder
	esc := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case esc:
			cur.WriteByte(c)
			esc = false
		case c == '\\':
			esc = true
		case c == sep:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	out = append(out, cur.String())
	return out
}

// parseLinkDetail reads the SSID, frequency, signal, channel and channel
// width from `iw dev <if> link` output. ok reports the frequency-or-signal
// presence parseIwLink has always accepted.
func parseLinkDetail(out string) (ssid string, freq float64, signal int, ch, bw string, ok bool) {
	var hasFreq, hasSig bool
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "SSID:"):
			ssid = strings.TrimSpace(strings.TrimPrefix(t, "SSID:"))
		case strings.HasPrefix(t, "freq:"):
			f, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimPrefix(t, "freq:")), 64)
			if err == nil {
				freq, hasFreq = f, true
			}
		case strings.HasPrefix(t, "signal:"):
			v := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(t, "signal:")), "dBm"))
			s, err := strconv.Atoi(v)
			if err == nil {
				signal, hasSig = s, true
			}
		case strings.HasPrefix(t, "channel "):
			// "channel 3 (2422 MHz), width: 40 MHz, center1: 2432 MHz"
			fields := strings.Fields(t)
			if len(fields) >= 2 {
				ch = fields[1]
			}
			if i := strings.Index(t, "width:"); i >= 0 {
				w := strings.TrimSpace(t[i+len("width:"):])
				if j := strings.IndexAny(w, " ,"); j >= 0 {
					w = w[:j]
				}
				if n, err := strconv.Atoi(w); err == nil && n > 0 {
					bw = strconv.Itoa(n) + " MHz"
				}
			}
		}
	}
	return ssid, freq, signal, ch, bw, hasFreq || hasSig
}

// bandOfFreq labels a frequency the way the settings form thinks of bands:
// sub-3 GHz is 2.4, up to 5925 is 5, and 6 GHz is skipped rather than
// mislabelled as 5.
func bandOfFreq(freq float64) string {
	switch {
	case freq >= 2400 && freq < 3000:
		return "24"
	case freq >= 4900 && freq < 5925:
		return "5"
	default:
		return ""
	}
}

// activeConn finds the NetworkManager connection whose DEVICE is iface.
func activeConn(iface string) (name, typ string) {
	if iface == "" {
		return "", ""
	}
	out, err := sh(2*time.Second, "nmcli", "-t", "-f", "NAME,TYPE,DEVICE", "connection", "show", "--active")
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(out, "\n") {
		if f := splitEscaped(line, ':'); len(f) == 3 && f[2] == iface {
			return f[0], f[1]
		}
	}
	return "", ""
}

// propValue extracts the value from an nmcli terse property line
// ("ipv4.method:auto" → "auto"). The property name is dot-separated, so the
// first colon is the separator even for values like IPv6 addresses.
func propValue(line string) string {
	if i := strings.IndexByte(line, ':'); i >= 0 {
		return line[i+1:]
	}
	return ""
}

func ipv4Method(conn string) string {
	if conn == "" {
		return ""
	}
	out, err := sh(2*time.Second, "nmcli", "-t", "-f", "ipv4.method", "connection", "show", conn)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(propValue(strings.TrimSpace(out)))
}

func keyMgmt(conn string) string {
	if conn == "" {
		return ""
	}
	out, err := sh(2*time.Second, "nmcli", "-t", "-f", "802-11-wireless-security.key-mgmt", "connection", "show", conn)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(propValue(strings.TrimSpace(out)))
}

// wanTypeOf maps the connection type + ipv4.method pair onto the form's
// options. Anything else (link-local, shared, unknown) stays "" rather than
// being guessed.
func wanTypeOf(typ, method string) string {
	if typ == "ppp" {
		return "PPPoE"
	}
	switch method {
	case "auto":
		return "DHCP"
	case "manual":
		return "Static"
	default:
		return ""
	}
}

// secOf maps key management onto the form's security options. A mixed or
// enterprise mode cannot be told apart from the outside here, so only the
// two that are genuinely knowable are reported.
func secOf(km string) string {
	switch strings.ToLower(strings.TrimSpace(km)) {
	case "sae":
		return "WPA3"
	case "wpa-psk":
		return "WPA2"
	default:
		return ""
	}
}

// deviceDNS reads the resolvers NetworkManager handed this interface.
func deviceDNS(iface string) []string {
	if iface == "" {
		return nil
	}
	out, err := sh(2*time.Second, "nmcli", "-t", "-f", "IP4.DNS", "device", "show", iface)
	if err != nil {
		return nil
	}
	return parseDNSLines(out)
}

func parseDNSLines(out string) []string {
	var dns []string
	seen := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.IndexByte(line, ':'); i >= 0 {
			v := strings.TrimSpace(line[i+1:])
			if ip := net.ParseIP(v); ip != nil && !seen[v] {
				seen[v] = true
				dns = append(dns, v)
				if len(dns) == 2 {
					return dns
				}
			}
		}
	}
	return dns
}

// resolvDNS falls back to resolv.conf, skipping the systemd stub loopback —
// a 127.0.0.53 answer tells the user nothing about their real resolvers.
func resolvDNS() []string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var dns []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if ip := net.ParseIP(f[1]); ip != nil && !ip.IsLoopback() {
				dns = append(dns, f[1])
				if len(dns) == 2 {
					return dns
				}
			}
		}
	}
	return nil
}

type wifiNet struct {
	ssid string
	chn  string
	freq float64
}

// fillFromCache completes d from NetworkManager's scan cache under strict
// pairing rules: only rows whose SSID equals the connected network's are
// ever used — the connected band's channel when iw omitted it, or the other
// band of an identical-name dual-band AP. No connection means no claims: an
// unassociated host cannot honestly say which visible network is "theirs".
func fillFromCache(d *Detected, connected string, cache []wifiNet) {
	if d == nil || connected == "" {
		return
	}
	for _, n := range cache {
		if n.ssid == "" || n.ssid != connected {
			continue // hidden, or another network entirely
		}
		switch bandOfFreq(n.freq) {
		case "24":
			if d.SSID24 == "" {
				d.SSID24, d.Ch24 = n.ssid, n.chn
			} else if d.Ch24 == "" {
				d.Ch24 = n.chn
			}
		case "5":
			if d.SSID5 == "" {
				d.SSID5, d.Ch5 = n.ssid, n.chn
			} else if d.Ch5 == "" {
				d.Ch5 = n.chn
			}
		}
	}
}

// wifiCache reads NetworkManager's last scan — no rescan is triggered, so
// this is instant and works without scan permissions.
func wifiCache() []wifiNet {
	out, err := sh(3*time.Second, "nmcli", "-t", "-f", "SSID,CHAN,FREQ,SIGNAL", "device", "wifi", "list", "--rescan", "no")
	if err != nil {
		return nil
	}
	var nets []wifiNet
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := splitEscaped(line, ':')
		if len(f) < 3 {
			continue
		}
		freq, _ := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(f[2], "MHz")), 64)
		nets = append(nets, wifiNet{ssid: f[0], chn: f[1], freq: freq})
	}
	return nets
}

// publicIP asks the internet what address this host egresses through. This
// is display information — the WAN health probe deliberately does not use
// it, because a reply to one's own public IP usually comes from the local
// router's NAT and would keep the WAN check green with the internet down.
func publicIP() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://1.1.1.1/cdn-cgi/trace", nil)
	if err != nil {
		return ""
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return ""
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return ""
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 16<<10))
	if err != nil {
		return ""
	}
	return parseTrace(string(b))
}

// parseTrace pulls the ip= line out of Cloudflare's trace body.
func parseTrace(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "ip="); ok {
			if ip := net.ParseIP(v); ip != nil {
				return ip.String()
			}
		}
	}
	return ""
}
