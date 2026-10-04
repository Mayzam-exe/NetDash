// Package mdns passively captures mDNS/Bonjour announcements on the LAN and
// elicits them with periodic PTR queries, turning device hostnames
// ("maxs-iPhone.local", "living-room-chromecast.local") into name/kind
// enrichment for the inventory. No privileges required (UDP multicast).
package mdns

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"time"
)

// serviceTypes are queried so quiet devices answer even without announcing.
var serviceTypes = []string{
	"_googlecast._tcp.local", // Chromecast / Android TV
	"_airplay._tcp.local",    // Apple TV / HomePod
	"_companion-link._tcp.local",
	"_raop._tcp.local",
	"_ipp._tcp.local", // printers
	"_pdl-datastream._tcp.local",
	"_smb._tcp.local", // Windows/macOS shares
	"_workstation._tcp.local",
	"_device-info._tcp.local",
	"_hap._tcp.local", // HomeKit accessories
	"_sonos._tcp.local",
	"_spotify._tcp.local",
	"_miio._udp.local", // Xiaomi
	"_googlecast._udp.local",
}

const (
	queryEvery = 60 * time.Second
	groupAddr  = "224.0.0.251:5353"
)

// Start joins the mDNS group and runs listen+query loops until ctx is done.
// onName is called as (ip, hostname-without-.local) for every A record seen.
// Returns an error only if the socket cannot be opened.
func Start(ctx context.Context, onName func(ip, name string)) error {
	addr, err := net.ResolveUDPAddr("udp4", groupAddr)
	if err != nil {
		return err
	}
	// nil interface: join on every up IPv4 interface; SO_REUSEADDR lets us
	// coexist with other responders on :5353 (multicast is fanned out).
	conn, err := net.ListenMulticastUDP("udp4", nil, addr)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	go func() { // query burst at start and on interval
		sendQueries(conn)
		t := time.NewTicker(queryEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sendQueries(conn)
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		for ip, name := range parseResponses(buf[:n]) {
			if name != "" && ip != "" {
				onName(ip, name)
			}
		}
	}
}

func sendQueries(conn *net.UDPConn) {
	for _, svc := range serviceTypes {
		q := buildQuery(svc)
		_, _ = conn.WriteToUDP(q, &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353})
	}
}

// buildQuery encodes a single PTR question for the service type.
func buildQuery(name string) []byte {
	m := make([]byte, 12)
	binary.BigEndian.PutUint16(m[0:2], 0) // id
	binary.BigEndian.PutUint16(m[4:6], 1) // qdcount
	m = appendLabels(m, name)
	m = append(m, 0x00, 0x0c) // type PTR
	m = append(m, 0x00, 0x01) // class IN
	return m
}

// appendLabels writes a dotted name as length-prefixed labels.
func appendLabels(b []byte, name string) []byte {
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if l == "" {
			continue
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

// parseResponses extracts ip -> hostname pairs from every A record in the
// message (answers + authority + additional).
func parseResponses(msg []byte) map[string]string {
	out := map[string]string{}
	if len(msg) < 12 {
		return out
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8])) +
		int(binary.BigEndian.Uint16(msg[8:10])) +
		int(binary.BigEndian.Uint16(msg[10:12]))
	off := 12
	for i := 0; i < qd; i++ {
		var err error
		off, err = skipName(msg, off)
		if err != nil {
			return out
		}
		off += 4 // qtype qclass
		if off > len(msg) {
			return out
		}
	}
	for i := 0; i < an; i++ {
		name, next, err := readName(msg, off)
		if err != nil || next+10 > len(msg) {
			return out
		}
		off = next
		typ := binary.BigEndian.Uint16(msg[off : off+2])
		// class := binary.BigEndian.Uint16(msg[off+2 : off+4]) — IN assumed
		rdlen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdlen > len(msg) {
			return out
		}
		if typ == 1 && rdlen == 4 { // A
			ip := net.IP(msg[off : off+4]).String()
			hostname := strings.TrimSuffix(strings.TrimSuffix(name, ".local"), ".")
			if hostname != "" && ip != "" {
				out[ip] = hostname
			}
		}
		off += rdlen
	}
	return out
}

// readName decodes a possibly-compressed domain name starting at off,
// returning the name and the offset just past the ORIGINAL field.
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	next := -1
	jumps := 0
	for {
		if off >= len(msg) {
			return "", 0, errDNS
		}
		l := int(msg[off])
		switch {
		case l == 0:
			off++
			if next == -1 {
				next = off
			}
			return strings.Join(labels, "."), next, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errDNS
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3FFF)
			if next == -1 {
				next = off + 2
			}
			off = ptr
			jumps++
			if jumps > 32 || off >= len(msg) {
				return "", 0, errDNS
			}
		case l&0xC0 != 0:
			return "", 0, errDNS
		default:
			off++
			if off+l > len(msg) {
				return "", 0, errDNS
			}
			labels = append(labels, string(msg[off:off+l]))
			off += l
		}
	}
}

// skipName advances past a (possibly-compressed) name field.
func skipName(msg []byte, off int) (int, error) {
	_, next, err := readName(msg, off)
	return next, err
}

type dnsError struct{}

func (dnsError) Error() string { return "dns: malformed message" }

var errDNS = dnsError{}
