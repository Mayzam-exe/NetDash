//go:build !linux

package scan

import "time"

// probe: raw sockets for half-open scans are Linux-only; elsewhere we do
// a parallel connect-scan (needs no privileges).
func probe(ip string, ports []int, timeout time.Duration) (map[int]string, string) {
	return connectScan(ip, ports, timeout), "connect"
}
