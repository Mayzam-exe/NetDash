package netinfo

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	mu       sync.Mutex
	lastTick time.Time
	lastRx   uint64
	lastTx   uint64
)

// Sample returns host-wide throughput in Mb/s since the previous call (0 on the first call or on error).
func Sample() (down, up float64) {
	mu.Lock()
	defer mu.Unlock()
	rx, tx, err := counters()
	now := time.Now()
	if err != nil || lastTick.IsZero() {
		lastTick = now
		lastRx, lastTx = rx, tx
		return 0, 0
	}
	dt := now.Sub(lastTick).Seconds()
	if dt < 0.2 {
		return 0, 0
	}
	var dRx, dTx float64
	if rx >= lastRx {
		dRx = float64(rx - lastRx)
	} else { // counter reset (interface bounce)
		dRx = float64(rx)
	}
	if tx >= lastTx {
		dTx = float64(tx - lastTx)
	} else {
		dTx = float64(tx)
	}
	lastTick = now
	lastRx, lastTx = rx, tx
	return dRx * 8 / dt / 1e6, dTx * 8 / dt / 1e6
}

func counters() (rx, tx uint64, err error) {
	if runtime.GOOS == "windows" {
		return countersWindows()
	}
	return countersLinux()
}

func countersLinux() (uint64, uint64, error) {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	var totRx, totTx uint64
	for sc.Scan() {
		line := sc.Text()
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		if name == "lo" {
			continue
		}
		fields := strings.Fields(line[idx+1:])
		if len(fields) < 9 {
			continue
		}
		r, _ := strconv.ParseUint(fields[0], 10, 64)
		t, _ := strconv.ParseUint(fields[8], 10, 64)
		totRx += r
		totTx += t
	}
	return totRx, totTx, nil
}

func countersWindows() (uint64, uint64, error) {
	// Locale-independent: sum adapter statistics via PowerShell.
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-NetAdapterStatistics | Measure-Object -Property ReceivedBytes -Sum).Sum.ToString() + ' ' + (Get-NetAdapterStatistics | Measure-Object -Property SentBytes -Sum).Sum.ToString()")
	b, err := cmd.Output()
	if err != nil {
		return 0, 0, err
	}
	parts := strings.Fields(string(b))
	if len(parts) < 2 {
		return 0, 0, strconv.ErrSyntax
	}
	rx, err1 := strconv.ParseUint(parts[0], 10, 64)
	tx, err2 := strconv.ParseUint(parts[1], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, strconv.ErrSyntax
	}
	return rx, tx, nil
}

// DetectGateway returns the default-route gateway IP, or "" if it cannot be determined.
func DetectGateway() string {
	if runtime.GOOS == "windows" {
		return detectGatewayWindows()
	}
	return detectGatewayLinux()
}

func detectGatewayLinux() string {
	f, err := os.Open(filepath.Join("/proc", "net", "route"))
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f2 := strings.Fields(sc.Text())
		if len(f2) < 3 || f2[1] != "00000000" {
			continue
		}
		gwHex := f2[2]
		if len(gwHex) != 8 {
			continue
		}
		// little-endian hex IPv4
		var b [4]byte
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(gwHex[i*2:i*2+2], 16, 8)
			if err != nil {
				return ""
			}
			b[3-i] = byte(v)
		}
		return strconv.Itoa(int(b[0])) + "." + strconv.Itoa(int(b[1])) + "." +
			strconv.Itoa(int(b[2])) + "." + strconv.Itoa(int(b[3]))
	}
	return ""
}

func detectGatewayWindows() string {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop")
	b, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// LocalIPs returns this machine's up, non-loopback IPv4 addresses.
func LocalIPs() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := ipnet.IP.To4(); v4 != nil {
				out = append(out, v4.String())
			}
		}
	}
	return out
}

// LocalSubnets returns the number of distinct IPv4 network prefixes this
// host has addresses in (a router typically has ≥2: LAN + WAN).
func LocalSubnets() int {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	seen := map[string]bool{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			seen[ipnet.String()] = true
		}
	}
	return len(seen)
}

// IPForward reports whether the kernel is forwarding IPv4 packets. Always
// false on non-Linux platforms (their forwarding knobs live in the registry).
func IPForward() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == "1"
}

// LocalSelf returns this machine's primary outbound IPv4 address, the MAC of
// the interface it uses, and that interface's name. Values are empty when the
// address cannot be determined (no route, no interfaces).
func LocalSelf() (ip, mac, ifName string) {
	// A UDP dial performs no packets; the kernel just picks the source address.
	if conn, err := net.Dial("udp4", "1.1.1.1:53"); err == nil {
		defer conn.Close()
		if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil && ua.IP.To4() != nil {
			ip = ua.IP.String()
		}
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return ip, "", ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() || ipnet.IP.To4() == nil {
				continue
			}
			if ip == "" {
				ip = ipnet.IP.String()
			}
			if ipnet.IP.String() == ip {
				return ip, iface.HardwareAddr.String(), iface.Name
			}
		}
	}
	return ip, "", ""
}

// SelfName is the display name for the machine running NetDash: the system
// hostname unless it is missing or just an IP (some DHCP setups do that).
func SelfName() string {
	h, err := os.Hostname()
	if err != nil {
		return "This machine"
	}
	return nameFromHostname(h)
}

func nameFromHostname(h string) string {
	h = strings.TrimSuffix(strings.TrimSpace(h), ".")
	if h == "" || h == "localhost" || net.ParseIP(h) != nil {
		return "This machine"
	}
	return h
}

// InterfaceConn classifies the interface for the device inventory:
// eth | wifi5 | wifi2 | unknown.
func InterfaceConn(ifName string) string {
	if ifName == "" {
		return "unknown"
	}
	if runtime.GOOS != "linux" {
		return "unknown"
	}
	if _, err := os.Stat("/sys/class/net/" + ifName + "/wireless"); err != nil {
		return "eth"
	}
	freq, _, ok := readWireless(ifName)
	if !ok || freq == 0 {
		return "unknown"
	}
	if freq >= 5000 {
		return "wifi5"
	}
	return "wifi2"
}

// WifiSignal returns the current Wi-Fi signal (dBm) for an associated
// interface. ok is false when unavailable (wired, disconnected, no iw).
func WifiSignal(ifName string) (int, bool) {
	_, sig, ok := readWireless(ifName)
	return sig, ok
}

// readWireless runs `iw dev <if> link` and parses frequency and signal.
func readWireless(ifName string) (freq float64, signal int, ok bool) {
	if runtime.GOOS == "windows" || ifName == "" {
		return 0, 0, false
	}
	out, err := exec.Command("iw", "dev", ifName, "link").Output()
	if err != nil {
		return 0, 0, false
	}
	return parseIwLink(string(out))
}

// parseIwLink extracts "freq: 5785.0" and "signal: -58 dBm" lines from the
// output of `iw dev <if> link`.
func parseIwLink(out string) (freq float64, signal int, ok bool) {
	var hasFreq, hasSig bool
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		switch {
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
		}
	}
	return freq, signal, hasFreq || hasSig
}

// SubnetHosts lists candidate IPv4 hosts on this machine's local subnets —
// every address between network and broadcast, minus this machine. Used by
// the discovery ping sweep: a host's ARP table only learns devices it has
// talked to, so quiet LAN devices are invisible without active probing.
// Subnets larger than /22 are skipped as a safety cap.
func SubnetHosts() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	self := map[string]bool{}
	if ip, _, _ := LocalSelf(); ip != "" {
		self[ip] = true
	}
	const maxHosts = 1022 // /22 minus network and broadcast
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			mask := ipn.Mask
			if len(mask) == net.IPv6len {
				mask = mask[12:]
			}
			ones, bits := mask.Size()
			if bits != 32 || ones > 30 {
				continue
			}
			n := 1 << uint(bits-ones)
			if n-2 > maxHosts {
				continue
			}
			base := binary.BigEndian.Uint32(ipn.IP.To4().Mask(mask))
			for host := 1; host < n-1; host++ {
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], base+uint32(host))
				ip := net.IP(b[:]).String()
				if !self[ip] {
					out = append(out, ip)
				}
			}
		}
	}
	return out
}

// FormFactor classifies the local machine: "laptop" when a battery is
// present, "" when unknown (desktop, VM, or non-Linux) — the host running
// NetDash is PC-class by definition, never a phone.
func FormFactor() string {
	ents, err := os.ReadDir("/sys/class/power_supply")
	if err != nil {
		return ""
	}
	for _, e := range ents {
		b, err := os.ReadFile("/sys/class/power_supply/" + e.Name() + "/type")
		if err == nil && strings.TrimSpace(string(b)) == "Battery" {
			return "laptop"
		}
	}
	return ""
}
