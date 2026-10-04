//go:build linux

package scan

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// probe: crafted half-open SYN scan over a raw socket (CAP_NET_RAW);
// falls back to the connect-scan when raw sockets are unavailable.
func probe(ip string, ports []int, timeout time.Duration) (map[int]string, string) {
	if st, ok := synScan(ip, ports, timeout); ok {
		return st, "syn"
	}
	return connectScan(ip, ports, timeout), "connect"
}

// synScan sends one SYN per port with a unique source port and classifies
// each probe from the SYN-ACK / RST that comes back. Unanswered probes
// stay "filtered". ok=false → use connect-scan instead.
func synScan(ip string, ports []int, timeout time.Duration) (map[int]string, bool) {
	dst := net.ParseIP(ip)
	if dst == nil || dst.To4() == nil || len(ports) == 0 || len(ports) > 20000 {
		return nil, false
	}
	dst = dst.To4()
	src := udpSrcIP(ip)
	if src == nil {
		return nil, false
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return nil, false // no CAP_NET_RAW
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return nil, false
	}
	tv := unix.NsecToTimeval((250 * time.Millisecond).Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, false
	}

	results := make(map[int]string, len(ports))
	byOurPort := make(map[uint16]int, len(ports))
	for i, p := range ports {
		results[p] = "filtered"
		byOurPort[uint16(40000+i)] = p
	}

	var ipid uint16 = 1
	sent, sendErr := 0, 0
	for i, p := range ports {
		pkt := buildSYN(src, dst, uint16(40000+i), uint16(p), ipid, uint32(0x6d000000+i))
		ipid++
		sa := &unix.SockaddrInet4{}
		copy(sa.Addr[:], dst)
		if err := unix.Sendto(fd, pkt, 0, sa); err != nil {
			sendErr++
			break // link problems: collect whatever already came back
		}
		sent++
	}

	var recv, synAck, rst, unkeyed int
	var sample []string
	remaining := len(ports)
	deadline := time.Now().Add(timeout + 250*time.Millisecond)
	buf := make([]byte, 65536)
	for remaining > 0 && time.Now().Before(deadline) {
		n, err := unix.Read(fd, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK || err == unix.EINTR {
				continue // recv timeout — re-check the deadline
			}
			break
		}
		recv++
		state, ourPort, ok := parseTCPReply(buf[:n], dst)
		if !ok {
			// keep samples only for packets actually sourced by the target
			if len(sample) < 6 && n >= 20 && buf[0]>>4 == 4 &&
				net.IP(buf[12:16]).Equal(dst) {
				sample = append(sample, "skip:"+describeTCP(buf[:n], dst))
			}
			continue
		}
		if state == "open" {
			synAck++
		} else {
			rst++
		}
		probed, known := byOurPort[ourPort]
		if !known {
			unkeyed++
			if len(sample) < 6 {
				sample = append(sample, "unkeyed:"+describeTCP(buf[:n], dst)+" state="+state)
			}
			continue
		}
		if results[probed] == "filtered" {
			results[probed] = state
			remaining--
		}
	}
	var closedList, filteredList []string
	open, closed, filteredN := 0, 0, 0
	for _, p := range ports {
		switch results[p] {
		case "open":
			open++
		case "closed":
			closed++
			if len(closedList) < 25 {
				closedList = append(closedList, strconv.Itoa(p))
			}
		default:
			filteredN++
			if len(filteredList) < 25 {
				filteredList = append(filteredList, strconv.Itoa(p))
			}
		}
	}
	log.Printf("scan %s: sent=%d sendErr=%d recv=%d synack=%d rst=%d unkeyed=%d → open=%d closed=%d filtered=%d closedPorts=%v filteredPorts=%v samples=%v",
		ip, sent, sendErr, recv, synAck, rst, unkeyed, open, closed, filteredN,
		closedList, filteredList, sample)
	return results, true
}

// describeTCP pretty-prints a raw packet for scan debugging.
func describeTCP(b []byte, wantSrc net.IP) string {
	if len(b) < 40 || b[0]>>4 != 4 {
		return "non-ipv4 len=" + strconv.Itoa(len(b))
	}
	ihl := int(b[0]&0x0f) * 4
	if len(b) < ihl+20 {
		return "short"
	}
	tcp := b[ihl:]
	return fmt.Sprintf("src=%s dst=%s proto=%d sport=%d dport=%d flags=0x%02x wantSrc=%s",
		net.IP(b[12:16]), net.IP(b[16:20]), b[9],
		binary.BigEndian.Uint16(tcp[0:2]), binary.BigEndian.Uint16(tcp[2:4]),
		tcp[13], wantSrc)
}

// parseTCPReply extracts (state, our source port) from an incoming IPv4
// TCP segment addressed to us.
func parseTCPReply(b []byte, wantSrc net.IP) (string, uint16, bool) {
	if len(b) < 40 || b[0]>>4 != 4 {
		return "", 0, false
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || b[9] != 6 || len(b) < ihl+20 {
		return "", 0, false
	}
	if !net.IP(b[12:16]).Equal(wantSrc) {
		return "", 0, false
	}
	tcp := b[ihl:]
	dport := binary.BigEndian.Uint16(tcp[2:4])
	flags := tcp[13]
	switch {
	case flags&0x12 == 0x12: // SYN+ACK
		return "open", dport, true
	case flags&0x04 != 0: // RST
		return "closed", dport, true
	}
	return "", dport, false
}

// buildSYN crafts one IPv4+TCP SYN packet (correct IP and TCP checksums).
func buildSYN(src, dst net.IP, sport, dport uint16, id uint16, seq uint32) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	binary.BigEndian.PutUint16(pkt[4:6], id)
	pkt[8] = 64 // TTL
	pkt[9] = 6  // TCP
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	binary.BigEndian.PutUint16(pkt[10:12], ipCsum(pkt[:20]))

	t := pkt[20:]
	binary.BigEndian.PutUint16(t[0:2], sport)
	binary.BigEndian.PutUint16(t[2:4], dport)
	binary.BigEndian.PutUint32(t[4:8], seq)
	t[12] = 5 << 4 // data offset
	t[13] = 0x02   // SYN
	binary.BigEndian.PutUint16(t[14:16], 65535)
	binary.BigEndian.PutUint16(t[16:18], tcpCsum(src, dst, t))
	return pkt
}

func ipCsum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for s > 0xffff {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}

func tcpCsum(src, dst net.IP, tcp []byte) uint16 {
	p := make([]byte, 12+len(tcp))
	copy(p[0:4], src)
	copy(p[4:8], dst)
	p[9] = 6
	binary.BigEndian.PutUint16(p[10:12], uint16(len(tcp)))
	copy(p[12:], tcp)
	return ipCsum(p)
}

// udpSrcIP picks the source address the kernel would use toward dst
// (a UDP dial sends no packets — it only resolves the route).
func udpSrcIP(dst string) net.IP {
	c, err := net.Dial("udp4", net.JoinHostPort(dst, strconv.Itoa(1)))
	if err != nil {
		return nil
	}
	defer c.Close()
	if a, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return a.IP.To4()
	}
	return nil
}
