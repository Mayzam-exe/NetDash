package model

import "time"

// Device is the JSON shape consumed by the web client.
type Device struct {
	ID        int64      `json:"id"`
	IP        string     `json:"ip"`
	MAC       string     `json:"mac"`
	Name      string     `json:"name"`
	Vendor    string     `json:"vendor"`
	Kind      string     `json:"kind"` // phone|laptop|desktop|tablet|tv|camera|speaker|thermostat|printer|hub|console|router|"" (auto/unknown)
	Conn      string     `json:"conn"` // eth | wifi5 | wifi2 | unknown
	Signal    *int       `json:"signal"`
	State     string     `json:"state"` // online | offline | warning
	Blocked   bool       `json:"blocked"`
	Reserved  bool       `json:"reserved"`
	Priority  string     `json:"priority"`
	Schedule  string     `json:"schedule"`
	SpeedDown int        `json:"speedDown"` // kbit/s cap toward the device, 0 = unlimited
	SpeedUp   int        `json:"speedUp"`   // kbit/s cap from the device, 0 = unlimited
	Down      float64    `json:"down"`
	Watched   bool       `json:"watched"` // intercept: poison + unlimited relay for intel (runtime+persisted)
	Up        float64    `json:"up"`
	Self      bool       `json:"self"` // this machine (computed at runtime, not persisted)
	LastSeen  *time.Time `json:"lastSeen"`
	FirstSeen *time.Time `json:"firstSeen"`
}

// Intel is one observed hostname from a device's intercepted traffic.
type Intel struct {
	ID    int64  `json:"id"`
	DevID int64  `json:"devId"`
	TS    int64  `json:"ts"`   // unix ms
	Kind  string `json:"kind"` // dns | sni | http
	Value string `json:"value"`
}

// SpoofRule maps a domain suffix to an IP answered by the interceptor.
type SpoofRule struct {
	ID     int64  `json:"id"`
	Domain string `json:"domain"`
	IP     string `json:"ip"`
}

type Alert struct {
	ID    int64  `json:"id"`
	Sev   string `json:"sev"` // info | warning | critical
	Msg   string `json:"msg"`
	DevID *int64 `json:"devId"`
	TS    int64  `json:"ts"` // unix ms
	Read  bool   `json:"read"`
}

type Totals struct {
	Devices int `json:"devices"`
	Online  int `json:"online"`
	Warning int `json:"warning"`
	Offline int `json:"offline"`
	Blocked int `json:"blocked"`
}

type Status struct {
	OK             bool    `json:"ok"`
	Version        string  `json:"version"`
	StartedAt      string  `json:"startedAt"`
	GatewayIP      string  `json:"gatewayIp"`
	WANIP          string  `json:"wanIp"`
	LatencyGateway float64 `json:"latencyGateway"` // ms, -1 unknown/unreachable
	LatencyWAN     float64 `json:"latencyWan"`
	HostDown       float64 `json:"hostDown"` // Mb/s
	HostUp         float64 `json:"hostUp"`   // Mb/s
	HostPeakDown   float64 `json:"hostPeakDown"`
	MetricsSource  string  `json:"metricsSource"` // host | snmp
	Firewall       string  `json:"firewall"`      // ready | unavailable: reason
	Blocking       string  `json:"blocking"`      // active (nftables|arp poisoning) | unavailable: reason
	Speed          string  `json:"speed"`         // active (arp bridge) | unavailable: reason
	Path           string  `json:"path"`          // gateway | behind
	Metering       string  `json:"metering"`      // active | unavailable: reason
	Totals         Totals  `json:"totals"`
}

type History struct {
	Down   []float64 `json:"down"`
	Up     []float64 `json:"up"`
	Lat    []float64 `json:"lat"`
	Points int       `json:"points"`
}

type Settings struct {
	SSID24        string `json:"ssid24"`
	SSID5         string `json:"ssid5"`
	GatewayIP     string `json:"gatewayIp"`
	WANIP         string `json:"wanIp"`
	SnmpEnabled   bool   `json:"snmpEnabled"`
	SnmpHost      string `json:"snmpHost"`
	SnmpCommunity string `json:"snmpCommunity"`
	SnmpWanIf     string `json:"snmpWanIf"`
}

func DefaultSettings() Settings {
	return Settings{SSID24: "HomeNet", SSID5: "HomeNet-5G", GatewayIP: "192.168.1.1", WANIP: "1.1.1.1"}
}

type Snapshot struct {
	Status  Status   `json:"status"`
	Devices []Device `json:"devices"`
	Alerts  []Alert  `json:"alerts"`
	History History  `json:"history"`
}

const HistLen = 60

func NewHistory() History {
	return History{
		Down:   make([]float64, 0, HistLen),
		Up:     make([]float64, 0, HistLen),
		Lat:    make([]float64, 0, HistLen),
		Points: 0,
	}
}

func (h *History) Push(down, up, lat float64) {
	push := func(s *[]float64, v float64) {
		*s = append(*s, v)
		if len(*s) > HistLen {
			*s = (*s)[len(*s)-HistLen:]
		}
	}
	push(&h.Down, down)
	push(&h.Up, up)
	push(&h.Lat, lat)
	h.Points = len(h.Down)
}
