package ident

import (
	"context"
	"net"
	"os"
	"strings"
	"time"
)

// leaseFiles are dnsmasq lease locations across common distros / OpenWrt.
var leaseFiles = []string{
	"/var/lib/misc/dnsmasq.leases",
	"/var/lib/dnsmasq/dnsmasq.leases",
	"/tmp/dnsmasq.leases",
}

// leaseName returns the DHCP hostname for ip from any readable dnsmasq lease file, or "".
// Format per line: <expiry> <mac> <ip> <hostname> <client-id>
func leaseName(ip string) string {
	for _, f := range leaseFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 4 || fields[2] != ip {
				continue
			}
			if h := fields[3]; h != "" && h != "*" {
				return h
			}
		}
	}
	return ""
}

// ptrName resolves reverse DNS for ip with a short timeout, or "".
func ptrName(ctx context.Context, ip string) string {
	cctx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(cctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	n := strings.TrimSuffix(names[0], ".")
	// skip purely numeric answers (raw IP returned)
	if n == ip {
		return ""
	}
	return n
}

// BestName returns the most specific human name for ip (DHCP lease → PTR), or "".
func BestName(ctx context.Context, ip string) string {
	if h := leaseName(ip); h != "" {
		return h
	}
	return ptrName(ctx, ip)
}
