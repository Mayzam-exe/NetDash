// Package scan probes TCP ports and grabs service banners. On Linux it
// sends crafted half-open SYNs over a raw socket (CAP_NET_RAW) and reads
// SYN-ACK/RST off the wire; elsewhere it falls back to connect-scan.
package scan

import (
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Probe timings: LAN-scale, bounded so one request never hangs the API.
const (
	probeTimeout  = 700 * time.Millisecond
	bannerTimeout = 1500 * time.Millisecond
	maxBannerPort = 30
	bannerWorkers = 8
)

// PortResult is one open port with what it said.
type PortResult struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner,omitempty"`
}

// Result is a finished scan.
type Result struct {
	ScannedAt int64        `json:"scannedAt"`
	Ms        float64      `json:"ms"`
	Method    string       `json:"method"` // syn | connect
	Probed    int          `json:"probed"`
	Open      int          `json:"open"`
	Filtered  int          `json:"filtered"`
	Ports     []PortResult `json:"ports"` // open only, ascending
}

// TopPorts is the default curated sweep: network gear, remote access,
// web stacks, databases, dev/monitoring services and common IoT/cam gear.
func TopPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 137, 139, 143, 161,
		389, 443, 445, 465, 514, 515, 543, 548, 587, 631, 636, 873, 902,
		990, 993, 995, 1080, 1194, 1433, 1434, 1521, 1723, 1883, 2049,
		2082, 2083, 2086, 2087, 2095, 2096, 2181, 2222, 2375, 2376, 3000,
		3128, 3306, 3389, 4369, 4444, 5000, 5432, 5555, 5601, 5672, 5900,
		5901, 5985, 5986, 6379, 6443, 6666, 7001, 8000, 8008, 8010, 8080,
		8081, 8086, 8088, 8090, 8443, 8888, 9000, 9042, 9090, 9091, 9100,
		9200, 9300, 9418, 9443, 9999, 10000, 10250, 11211, 15672, 27017,
		27018, 50000,
	}
}

// services maps well-known ports to service names for display.
var services = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
	81: "http-alt", 88: "kerberos", 110: "pop3", 111: "rpcbind",
	135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn", 143: "imap",
	161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
	514: "syslog", 515: "lpd", 543: "postgresql", 548: "afp",
	587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync",
	990: "ftps", 993: "imaps", 995: "pop3s", 1080: "socks",
	1194: "openvpn", 1433: "mssql", 1434: "mssql-monitor", 1521: "oracle",
	1723: "pptp", 1883: "mqtt", 2049: "nfs", 2082: "cpanel",
	2083: "cpanel-ssl", 2086: "cpanel", 2087: "cpanel-ssl", 2095: "webmail",
	2096: "webmail-ssl", 2181: "zookeeper", 2222: "ssh-alt", 2375: "docker",
	2376: "docker-tls", 3000: "dev-http", 3128: "squid", 3306: "mysql",
	3389: "rdp", 4369: "epmd", 4444: "meterpreter", 5000: "http-alt",
	5432: "postgres", 5555: "adb", 5601: "kibana", 5672: "rabbitmq",
	5900: "vnc", 5901: "vnc-1", 5985: "winrm", 5986: "winrm-ssl",
	6379: "redis", 6443: "k8s-api", 6666: "irc", 7001: "weblogic",
	8000: "http-alt", 8008: "http-alt", 8010: "http-alt", 8080: "http-proxy",
	8081: "http-alt", 8086: "influxdb", 8088: "http-alt", 8090: "http-alt",
	8443: "https-alt", 8888: "http-alt", 9000: "minio", 9042: "cassandra",
	9090: "prometheus", 9091: "prometheus", 9100: "node-exporter",
	9200: "elasticsearch", 9300: "elasticsearch-tr", 9418: "git",
	9443: "https-alt", 9999: "http-alt", 10000: "webmin", 10250: "kubelet",
	11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb",
	27018: "mongodb", 50000: "db-alt",
}

func serviceOf(port int) string {
	if s, ok := services[port]; ok {
		return s
	}
	return ""
}

// Scan probes ports on ip and grabs banners from the open ones.
func Scan(ip string, ports []int) Result {
	start := time.Now()
	states, method := probe(ip, ports, probeTimeout)

	res := Result{Method: method, Probed: len(ports)}
	var open []int
	for p, st := range states {
		switch st {
		case "open":
			open = append(open, p)
		case "filtered":
			res.Filtered++
		}
	}
	sort.Ints(open)
	res.Open = len(open)

	banners := grabBanners(ip, open)
	res.Ports = make([]PortResult, 0, len(open))
	for _, p := range open {
		res.Ports = append(res.Ports, PortResult{
			Port:    p,
			Service: serviceOf(p),
			Banner:  banners[p],
		})
	}
	res.Ms = float64(time.Since(start).Microseconds()) / 1000
	return res
}

// connectScan is the portable fallback (and Windows path): parallel TCP
// connects classified open / closed (refused) / filtered (timeout).
func connectScan(ip string, ports []int, timeout time.Duration) map[int]string {
	states := make(map[int]string, len(ports))
	var mu sync.Mutex
	sem := make(chan struct{}, 256)
	var wg sync.WaitGroup
	for _, p := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			st := "filtered"
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(p)), timeout)
			if err == nil {
				st = "open"
				_ = conn.Close()
			} else if errors.Is(err, syscall.ECONNREFUSED) ||
				strings.Contains(err.Error(), "refused") {
				st = "closed"
			}
			mu.Lock()
			states[p] = st
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	return states
}
