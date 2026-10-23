// Package dhcp passively observes DHCP broadcasts on the LAN to learn client
// hostnames. Any RFC-compliant DHCP exchange carries option 12 (host name),
// so this works against any router without integration — broadcasts are
// flooded to every port even on a switch, so joins are always visible.
package dhcp

import "fmt"

// Message kinds (DHCP option 53 values NetDash cares about).
const (
	TypeDiscover = 1
	TypeRequest  = 3
	TypeACK      = 5
)

// Ev is one observed DHCP exchange worth folding into device intel.
type Ev struct {
	MAC      string // chaddr, lowercase colon form
	IP       string // client IP when the message carries one ("" on discover)
	Hostname string // option 12, sanitized; "" when absent
	Type     byte   // TypeDiscover | TypeRequest | TypeACK
}

func be16(b []byte) int { return int(b[0])<<8 | int(b[1]) }

// Parse extracts client identity from an Ethernet frame carrying DHCP.
// Structural parse only: IPv4 checksums were validated by the NIC and UDP's
// is not checked (a router would have dropped a broken one before we saw it).
func Parse(frame []byte) (Ev, bool) {
	// Ethernet, tolerating a single 802.1Q VLAN tag.
	if len(frame) < 34 {
		return Ev{}, false
	}
	off := 14
	etype := be16(frame[12:14])
	if etype == 0x8100 {
		if len(frame) < 38 {
			return Ev{}, false
		}
		etype = be16(frame[16:18])
		off = 18
	}
	if etype != 0x0800 || len(frame) < off+20 {
		return Ev{}, false
	}

	ip := frame[off:]
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl+8 || ip[9] != 17 { // 17 = UDP
		return Ev{}, false
	}
	udp := ip[ihl:]
	sp, dp := be16(udp[0:2]), be16(udp[2:4])
	if sp != 67 && sp != 68 && dp != 67 && dp != 68 {
		return Ev{}, false
	}

	// BOOTP/DHCP payload: header is 240 bytes including the magic cookie.
	p := udp[8:]
	if len(p) < 241 {
		return Ev{}, false
	}
	if p[236] != 99 || p[237] != 130 || p[238] != 83 || p[239] != 99 {
		return Ev{}, false // not DHCP (plain BOOTP or garbage)
	}
	if p[1] != 1 || p[2] != 6 { // htype Ethernet, hlen 6
		return Ev{}, false
	}

	var typ byte
	var hostname string
	var reqIP string
	for i := 240; i < len(p); {
		code := p[i]
		switch code {
		case 0: // pad
			i++
			continue
		case 255: // end
			i = len(p)
			continue
		}
		if i+1 >= len(p) {
			return Ev{}, false
		}
		l := int(p[i+1])
		if i+2+l > len(p) {
			return Ev{}, false
		}
		v := p[i+2 : i+2+l]
		switch code {
		case 53:
			if l >= 1 {
				typ = v[0]
			}
		case 12:
			hostname = sanitizeName(v)
		case 50:
			if l == 4 {
				reqIP = fmt.Sprintf("%d.%d.%d.%d", v[0], v[1], v[2], v[3])
			}
		}
		i += 2 + l
	}
	if typ != TypeDiscover && typ != TypeRequest && typ != TypeACK {
		return Ev{}, false
	}

	mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", p[28], p[29], p[30], p[31], p[32], p[33])
	ev := Ev{MAC: mac, Hostname: hostname, Type: typ}
	switch typ {
	case TypeACK:
		if y := ipString(p[16:20]); y != "" {
			ev.IP = y
		}
	case TypeRequest:
		if c := ipString(p[12:16]); c != "" {
			ev.IP = c
		} else {
			ev.IP = reqIP
		}
	}
	return ev, true
}

func ipString(b []byte) string {
	if b[0]|b[1]|b[2]|b[3] == 0 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// sanitizeName keeps the hostname printable and device-name sized.
func sanitizeName(v []byte) string {
	out := make([]byte, 0, len(v))
	for _, c := range v {
		if c < 0x20 || c > 0x7e {
			continue // control/non-ASCII bytes dropped
		}
		out = append(out, c)
	}
	for len(out) > 0 && out[0] == ' ' {
		out = out[1:]
	}
	for len(out) > 0 && out[len(out)-1] == ' ' {
		out = out[:len(out)-1]
	}
	if len(out) > 63 {
		out = out[:63]
	}
	return string(out)
}
