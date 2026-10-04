package mdns

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestBuildQuery(t *testing.T) {
	q := buildQuery("_googlecast._tcp.local")
	if len(q) < 12 {
		t.Fatal("short query")
	}
	if binary.BigEndian.Uint16(q[4:6]) != 1 {
		t.Errorf("qdcount != 1")
	}
	// labels: _googlecast(11) _tcp(4) local(5) 0 + type + class
	want := []byte{11, '_'}
	if q[12] != want[0] || q[13] != want[1] {
		t.Errorf("label start wrong: %v", q[12:14])
	}
	if q[len(q)-4] != 0 || q[len(q)-3] != 12 || q[len(q)-2] != 0 || q[len(q)-1] != 1 {
		t.Errorf("trailer should be PTR/IN, got %v", q[len(q)-4:])
	}
}

// buildAResponse assembles a DNS response: one A answer, optional extra RRs.
func buildAResponse(owner string, ip net.IP, withNoise bool) []byte {
	m := make([]byte, 12)
	binary.BigEndian.PutUint16(m[2:4], 0x8400) // response
	anc := 1
	if withNoise {
		anc = 3 // A + TXT + PTR
	}
	binary.BigEndian.PutUint16(m[6:8], uint16(anc))
	m = appendLabels(m, owner)
	m = append(m, 0x00, 0x01)   // type A
	m = append(m, 0x80, 0x01)   // class IN + cache-flush
	m = append(m, 0, 0, 0, 120) // ttl
	m = append(m, 0x00, 0x04)   // rdlen
	m = append(m, ip.To4()...)
	if withNoise {
		// TXT record with junk rdata
		m = appendLabels(m, "noise.local")
		m = append(m, 0x00, 0x10) // TXT
		m = append(m, 0x00, 0x01)
		m = append(m, 0, 0, 0, 120)
		txt := []byte{5, 'm', 'o', 'd', 'e', 'l'}
		m = append(m, byte(len(txt)))
		m = append(m, txt...)
		// PTR record
		m = appendLabels(m, "_ipp._tcp.local")
		m = append(m, 0x00, 0x0c)
		m = append(m, 0x00, 0x01)
		m = append(m, 0, 0, 0, 120)
		ptr := appendLabels(nil, "hp-printer._ipp._tcp.local")
		m = append(m, byte(len(ptr)))
		m = append(m, ptr...)
	}
	return m
}

func TestParseAResponse(t *testing.T) {
	msg := buildAResponse("maxs-iPhone.local", net.IPv4(192, 168, 1, 23), true)
	got := parseResponses(msg)
	if got["192.168.1.23"] != "maxs-iPhone" {
		t.Errorf("got %v", got)
	}
}

func TestParseCompressedName(t *testing.T) {
	// header + owner labels; second RR's name is a pointer to offset 12
	m := make([]byte, 12)
	binary.BigEndian.PutUint16(m[2:4], 0x8400)
	binary.BigEndian.PutUint16(m[6:8], 2) // two answers
	m = appendLabels(m, "tv-box.local")
	// answer 1: A of tv-box.local
	m = append(m, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 120, 0x00, 0x04, 192, 168, 1, 42)
	// answer 2: name = pointer to offset 12, type A again (other ip)
	m = append(m, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 120, 0x00, 0x04, 192, 168, 1, 43)
	got := parseResponses(m)
	if got["192.168.1.42"] != "tv-box" || got["192.168.1.43"] != "tv-box" {
		t.Errorf("got %v", got)
	}
}

func TestParseMalformed(t *testing.T) {
	if got := parseResponses(nil); len(got) != 0 {
		t.Errorf("nil msg: %v", got)
	}
	// truncated rdlen claims more bytes than exist
	m := make([]byte, 12)
	binary.BigEndian.PutUint16(m[6:8], 1)
	m = appendLabels(m, "x.local")
	m = append(m, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 120, 0x00, 0x04, 192, 168) // rdlen 4 but only 2
	if got := parseResponses(m); len(got) != 0 {
		t.Errorf("truncated: %v", got)
	}
	// pointer loop must not hang
	m2 := make([]byte, 12)
	binary.BigEndian.PutUint16(m2[6:8], 1)
	m2 = append(m2, 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 1, 0x00, 0x04, 1, 2, 3, 4)
	done := make(chan map[string]string, 1)
	go func() { done <- parseResponses(m2) }()
	got := <-done
	if len(got) != 0 {
		t.Errorf("pointer loop: %v", got)
	}
}
