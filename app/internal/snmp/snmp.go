package snmp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

type Config struct {
	Host      string
	Community string
	Timeout   time.Duration // per-request timeout (default 1.5s)
}

type Neighbor struct {
	IP  string
	MAC string
}

// Link describes a bridge FDB entry's egress interface classification.
type Link struct {
	Conn   string // eth | wifi5 | wifi2 | unknown
	IfName string
}

func connect(cfg Config) (*gosnmp.GoSNMP, error) {
	to := cfg.Timeout
	if to == 0 {
		to = 1500 * time.Millisecond
	}
	comm := cfg.Community
	if comm == "" {
		comm = "public"
	}
	target := cfg.Host
	port := uint16(161)
	if h, p, ok := splitHostPort(cfg.Host); ok {
		if v, err := parsePort(p); err == nil {
			target, port = h, v
		}
	}
	g := &gosnmp.GoSNMP{
		Target:    target,
		Port:      port,
		Community: comm,
		Version:   gosnmp.Version2c,
		Timeout:   to,
		Retries:   1,
		MaxOids:   60,
	}
	if err := g.Connect(); err != nil {
		return nil, err
	}
	return g, nil
}

// splitHostPort accepts "host" or "host:port" (IPv4-oriented).
func splitHostPort(s string) (host, port string, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return s, "", false
	}
	// no port if this looks like a bare IPv6 literal
	if strings.Count(s, ":") > 1 {
		return s, "", false
	}
	return s[:i], s[i+1:], true
}

func parsePort(s string) (uint16, error) {
	v, err := strconv.ParseUint(s, 10, 16)
	return uint16(v), err
}

func macString(v interface{}) string {
	b, ok := v.([]byte)
	if !ok || len(b) != 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

// Neighbors walks the classic atTable and IP-MIB ipNetToPhysicalTable.
func Neighbors(cfg Config) ([]Neighbor, error) {
	g, err := connect(cfg)
	if err != nil {
		return nil, err
	}
	defer g.Conn.Close()

	seen := map[string]bool{}
	var out []Neighbor

	add := func(ip, mac string) {
		if ip == "" || mac == "" || seen[ip] {
			return
		}
		seen[ip] = true
		out = append(out, Neighbor{IP: ip, MAC: mac})
	}

	// RFC1213 atTable: .1.3.6.1.2.1.4.22.1.2 (atPhysAddress),
	// instance = ifIndex . ip-octets
	err = g.Walk("1.3.6.1.2.1.4.22.1.2", func(pdu gosnmp.SnmpPDU) error {
		suffix := strings.TrimPrefix(normName(pdu.Name), "1.3.6.1.2.1.4.22.1.2.")
		parts := strings.Split(suffix, ".")
		if len(parts) != 5 {
			return nil
		}
		ip := strings.Join(parts[1:], ".")
		add(ip, macString(pdu.Value))
		return nil
	})

	// IP-MIB ipNetToPhysicalPhysAddress: .1.3.6.1.2.1.4.35.1.3,
	// instance = ifIndex . length . ip-octets
	err2 := g.Walk("1.3.6.1.2.1.4.35.1.3", func(pdu gosnmp.SnmpPDU) error {
		suffix := strings.TrimPrefix(normName(pdu.Name), "1.3.6.1.2.1.4.35.1.3.")
		parts := strings.Split(suffix, ".")
		if len(parts) < 3 {
			return nil
		}
		n := int(parseUint(parts[1]))
		if n != 4 || len(parts) != 2+n {
			return nil
		}
		ip := strings.Join(parts[2:], ".")
		add(ip, macString(pdu.Value))
		return nil
	})

	if err != nil && err2 != nil {
		return nil, fmt.Errorf("atTable: %v; ipNetToPhysical: %v", err, err2)
	}
	return out, nil
}

// Links walks BRIDGE-MIB dot1dTpFdbTable + ifTable and classifies each MAC's port.
func Links(cfg Config) (map[string]Link, error) {
	g, err := connect(cfg)
	if err != nil {
		return nil, err
	}
	defer g.Conn.Close()

	// FDB: MAC -> port number
	fdb := map[string]uint64{}
	prefix := "1.3.6.1.2.1.17.4.3.1.2."
	if err := g.Walk(strings.TrimSuffix(prefix, "."), func(pdu gosnmp.SnmpPDU) error {
		suffix := strings.TrimPrefix(normName(pdu.Name), prefix)
		parts := strings.Split(suffix, ".")
		macParts := parts
		if len(parts) == 7 && parts[0] == "6" {
			macParts = parts[1:] // explicit length prefix
		} else if len(parts) != 6 {
			return nil // unexpected encoding
		}
		var mac []byte
		for _, p := range macParts {
			mac = append(mac, byte(parseUint(p)))
		}
		if len(mac) != 6 {
			return nil
		}
		fdb[fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])] = uint64(toInt(pdu.Value))
		return nil
	}); err != nil && len(fdb) == 0 {
		return nil, err
	}
	if len(fdb) == 0 {
		return map[string]Link{}, nil
	}

	// port -> ifIndex
	portIf := map[uint64]uint64{}
	_ = g.Walk("1.3.6.1.2.1.17.1.4.1.2", func(pdu gosnmp.SnmpPDU) error {
		port := parseUint(suffixLast(pdu.Name, "1.3.6.1.2.1.17.1.4.1.2."))
		portIf[port] = uint64(toInt(pdu.Value))
		return nil
	})

	// ifIndex -> ifType / ifDescr / ifName
	ifType := map[uint64]int{}
	ifDescr := map[uint64]string{}
	ifName := map[uint64]string{}
	_ = g.Walk("1.3.6.1.2.1.2.2.1.3", func(pdu gosnmp.SnmpPDU) error {
		idx := parseUint(suffixLast(pdu.Name, "1.3.6.1.2.1.2.2.1.3."))
		ifType[idx] = toInt(pdu.Value)
		return nil
	})
	_ = g.Walk("1.3.6.1.2.1.2.2.1.2", func(pdu gosnmp.SnmpPDU) error {
		idx := parseUint(suffixLast(pdu.Name, "1.3.6.1.2.1.2.2.1.2."))
		ifDescr[idx] = pduString(pdu.Value)
		return nil
	})
	_ = g.Walk("1.3.6.1.2.1.31.1.1.1.1", func(pdu gosnmp.SnmpPDU) error {
		idx := parseUint(suffixLast(pdu.Name, "1.3.6.1.2.1.31.1.1.1.1."))
		ifName[idx] = pduString(pdu.Value)
		return nil
	})

	out := make(map[string]Link, len(fdb))
	for mac, port := range fdb {
		ifi, ok := portIf[port]
		if !ok {
			continue
		}
		desc := ifDescr[ifi]
		name := ifName[ifi]
		out[mac] = Link{Conn: classify(ifType[ifi], desc, name), IfName: firstNonEmpty(name, desc)}
	}
	return out, nil
}

// WANMeter keeps last counters to compute rates between polls.
type WANMeter struct {
	HasLast bool
	LastIn  uint64
	LastOut uint64
	LastAt  time.Time
}

func (m *WANMeter) Update(cfg Config, wanHint string) (down, up float64, ifName string, ok bool, err error) {
	g, err := connect(cfg)
	if err != nil {
		return 0, 0, "", false, err
	}
	defer g.Conn.Close()

	in := map[uint64]uint64{}
	out := map[uint64]uint64{}
	descr := map[uint64]string{}

	_ = g.Walk("1.3.6.1.2.1.2.2.1.10", func(pdu gosnmp.SnmpPDU) error {
		in[parseUint(suffixLast(pdu.Name, "1.3.6.1.2.1.2.2.1.10."))] = counterValue(pdu.Value)
		return nil
	})
	_ = g.Walk("1.3.6.1.2.1.2.2.1.11", func(pdu gosnmp.SnmpPDU) error {
		out[parseUint(suffixLast(pdu.Name, "1.3.6.1.2.1.2.2.1.11."))] = counterValue(pdu.Value)
		return nil
	})
	_ = g.Walk("1.3.6.1.2.1.2.2.1.2", func(pdu gosnmp.SnmpPDU) error {
		descr[parseUint(suffixLast(pdu.Name, "1.3.6.1.2.1.2.2.1.2."))] = pduString(pdu.Value)
		return nil
	})

	hint := strings.ToLower(strings.TrimSpace(wanHint))
	var target uint64
	var targetName string
	for idx, d := range descr {
		ld := strings.ToLower(d)
		if hint == "" {
			if strings.Contains(ld, "wan") || strings.Contains(ld, "ppp") {
				target, targetName = idx, d
				break
			}
		} else if strings.Contains(ld, hint) {
			target, targetName = idx, d
			break
		}
	}
	if target == 0 {
		return 0, 0, "", false, fmt.Errorf("no WAN interface matched (hint %q)", wanHint)
	}
	curIn, haveIn := in[target]
	curOut, haveOut := out[target]
	if !haveIn || !haveOut {
		return 0, 0, targetName, false, fmt.Errorf("no counters for ifIndex %d", target)
	}
	now := time.Now()
	if !m.HasLast {
		m.HasLast, m.LastIn, m.LastOut, m.LastAt = true, curIn, curOut, now
		return 0, 0, targetName, false, nil
	}
	dt := now.Sub(m.LastAt).Seconds()
	if dt < 1 {
		return 0, 0, targetName, false, nil
	}
	dIn := delta(m.LastIn, curIn)
	dOut := delta(m.LastOut, curOut)
	m.LastIn, m.LastOut, m.LastAt = curIn, curOut, now
	return float64(dIn) * 8 / dt / 1e6, float64(dOut) * 8 / dt / 1e6, targetName, true, nil
}

func delta(prev, cur uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return cur // counter reset / wrap
}

// classify maps ifType + interface naming to the dashboard's conn vocabulary.
func classify(ifType int, descr, name string) string {
	if ifType == 6 { // ethernet
		return "eth"
	}
	if ifType != 71 && ifType != 113 { // ieee80211 / ltw
		return "unknown"
	}
	d := strings.ToLower(descr + " " + name)
	switch {
	case strings.Contains(d, "2.4"), strings.Contains(d, "24"), strings.Contains(d, "bgn"), strings.Contains(d, "bg "):
		return "wifi2"
	case strings.Contains(d, "5"), strings.Contains(d, "ac"), strings.Contains(d, "ax"), strings.Contains(d, "6g"), strings.Contains(d, "a "):
		return "wifi5"
	}
	return "unknown" // Wi-Fi, band not determinable from naming
}

func suffixLast(name, prefix string) string { return strings.TrimPrefix(normName(name), prefix) }

// normName strips gosnmp's canonical leading dot so callers can use plain OID prefixes.
func normName(name string) string { return strings.TrimPrefix(name, ".") }

func parseUint(s string) uint64 {
	var v uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return v
		}
		v = v*10 + uint64(c-'0')
	}
	return v
}

func toInt(v interface{}) int {
	switch t := v.(type) {
	case uint32:
		return int(t)
	case int:
		return t
	case int32:
		return int(t)
	case uint:
		return int(t)
	case int64:
		return int(t)
	case uint64:
		return int(t)
	case []byte:
		var n int
		for _, b := range t {
			n = n<<8 | int(b)
		}
		return n
	}
	return 0
}

func counterValue(v interface{}) uint64 {
	switch t := v.(type) {
	case uint:
		return uint64(t)
	case uint32:
		return uint64(t)
	case uint64:
		return t
	case int:
		if t > 0 {
			return uint64(t)
		}
	case int32:
		if t > 0 {
			return uint64(t)
		}
	case int64:
		if t > 0 {
			return uint64(t)
		}
	}
	return 0
}

func pduString(v interface{}) string {
	if b, ok := v.([]byte); ok {
		return strings.TrimRight(string(b), "\x00")
	}
	return fmt.Sprintf("%v", v)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ProbeReport describes what a router answers over SNMP. It is the honest
// capability check behind the Signal column: per-station Wi-Fi signal is only
// reportable when the router exposes a station-signal MIB, and most consumer
// gear does not.
type ProbeReport struct {
	Reachable bool     `json:"reachable"`
	SysName   string   `json:"sysName"`
	SysDescr  string   `json:"sysDescr"`
	Ifaces    []string `json:"ifaces"`
	RSSIMib   string   `json:"rssiMib"` // label of the station-signal tree that answered; "" = not exposed
	Error     string   `json:"error"`
}

// errStop ends a presence walk after the first answered instance.
var errStop = errors.New("presence confirmed")

// rssiCandidates are vendor station-signal subtrees worth probing. Each costs
// at most one request; an absent tree simply reports "not exposed".
var rssiCandidates = []struct{ OID, Label string }{
	{"1.3.6.1.4.1.14988.1.1.1.2.1.1", "MikroTik wireless station table"},
	{"1.3.6.1.4.1.41112.2.1", "UniFi station table"},
	{"1.3.6.1.4.1.2011.6.130.1", "Huawei AC station table"},
	{"1.3.6.1.2.1.105.1.1", "IEEE 802.11 station table"},
}

// Probe checks what the router exposes: identity, interfaces, and any
// per-station Wi-Fi signal tree. Reachable reflects an actual agent answer —
// a silent host or wrong community reports an error instead.
func Probe(cfg Config) (ProbeReport, error) {
	g, err := connect(cfg)
	if err != nil {
		return ProbeReport{}, err
	}
	defer g.Conn.Close()

	rep := ProbeReport{}
	if res, err := g.Get([]string{"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.5.0"}); err == nil {
		for _, v := range res.Variables {
			switch normName(v.Name) {
			case "1.3.6.1.2.1.1.1.0":
				rep.SysDescr = pduString(v.Value)
			case "1.3.6.1.2.1.1.5.0":
				rep.SysName = pduString(v.Value)
			}
		}
	}
	_ = g.Walk("1.3.6.1.2.1.2.2.1.2", func(pdu gosnmp.SnmpPDU) error {
		rep.Ifaces = append(rep.Ifaces, pduString(pdu.Value))
		return nil
	})
	if rep.SysDescr == "" && rep.SysName == "" && len(rep.Ifaces) == 0 {
		return ProbeReport{Error: "no SNMP response — wrong community, wrong host, or agent disabled"}, nil
	}
	rep.Reachable = true
	for _, c := range rssiCandidates {
		found := false
		_ = g.Walk(c.OID, func(gosnmp.SnmpPDU) error {
			found = true
			return errStop
		})
		if found {
			rep.RSSIMib = c.Label
			break
		}
	}
	return rep, nil
}
