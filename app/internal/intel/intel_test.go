package intel

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// dnsQuery builds a minimal DNS query message for name.
func dnsQuery(name string, txid uint16) []byte {
	var q []byte
	for _, lab := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		q = append(q, byte(len(lab)))
		q = append(q, lab...)
	}
	q = append(q, 0)
	q = append(q, 0x00, 0x01, 0x00, 0x01) // A IN
	msg := make([]byte, 0, 12+len(q))
	msg = append(msg, byte(txid>>8), byte(txid))
	msg = append(msg, 0x01, 0x00) // RD
	msg = append(msg, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	return append(msg, q...)
}

// ethUDP builds an ethernet+IPv4+UDP frame; ip[0]=0x45 is implied by layout.
func ethUDP(dport uint16, payload []byte) []byte {
	f := make([]byte, 14+20+8+len(payload))
	f[12], f[13] = 0x08, 0x00
	f[14] = 0x45
	binary.BigEndian.PutUint16(f[16:18], uint16(20+8+len(payload)))
	f[22] = 64
	f[23] = 17                              // UDP
	binary.BigEndian.PutUint16(f[20:22], 0) // checksum left 0
	copy(f[30:34], []byte{8, 8, 8, 8})
	copy(f[34:38], []byte{192, 168, 1, 9})
	l4 := 34
	binary.BigEndian.PutUint16(f[l4:l4+2], 40000) // sport
	binary.BigEndian.PutUint16(f[l4+2:l4+4], dport)
	binary.BigEndian.PutUint16(f[l4+4:l4+6], uint16(8+len(payload)))
	copy(f[l4+8:], payload)
	return f
}

// ethTCP builds an ethernet+IPv4+TCP(segment payload) frame with a
// 20-byte data offset.
func ethTCP(dport uint16, payload []byte) []byte {
	f := make([]byte, 14+20+20+len(payload))
	f[12], f[13] = 0x08, 0x00
	f[14] = 0x45
	binary.BigEndian.PutUint16(f[16:18], uint16(20+20+len(payload)))
	f[22] = 64
	f[23] = 6 // TCP
	copy(f[30:34], []byte{8, 8, 8, 8})
	copy(f[34:38], []byte{192, 168, 1, 9})
	l4 := 34
	binary.BigEndian.PutUint16(f[l4:l4+2], 40000)
	binary.BigEndian.PutUint16(f[l4+2:l4+4], dport)
	f[l4+12] = 5 << 4 // data offset 20 bytes
	copy(f[l4+20:], payload)
	return f
}

func TestParseDNSQuery(t *testing.T) {
	f := ethUDP(53, dnsQuery("API.Example.COM", 0x1234))
	got := Parse(true, f)
	if len(got) != 1 || got[0].Kind != "dns" || got[0].Value != "api.example.com" {
		t.Errorf("Parse = %+v, want [{dns api.example.com}]", got)
	}
}

func TestParseHTTPHost(t *testing.T) {
	payload := []byte("GET /index.html HTTP/1.1\r\nHost: Shop.Example.com\r\nUser-Agent: x\r\n\r\n")
	f := ethTCP(80, payload)
	got := Parse(true, f)
	if len(got) != 1 || got[0].Kind != "http" || got[0].Value != "shop.example.com" {
		t.Errorf("Parse = %+v, want [{http shop.example.com}]", got)
	}
}

// clientHello builds a minimal TLS record with one SNI extension.
func clientHello(sni string) []byte {
	srvName := make([]byte, 0, 5+len(sni))
	listLen := 3 + len(sni)
	srvName = append(srvName, byte(listLen>>8), byte(listLen))
	srvName = append(srvName, 0x00) // name type host_name
	srvName = append(srvName, byte(len(sni)>>8), byte(len(sni)))
	srvName = append(srvName, sni...)

	ext := make([]byte, 0, 4+len(srvName))
	ext = append(ext, 0x00, 0x00) // extension type server_name
	ext = append(ext, byte(len(srvName)>>8), byte(len(srvName)))
	ext = append(ext, srvName...)

	body := make([]byte, 0, 64+2+1+2+len(ext))
	body = append(body, 0x03, 0x03) // client version TLS1.2
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)                   // session id len
	body = append(body, 0x00, 0x02, 0x00, 0x2f) // cipher suites
	body = append(body, 0x01, 0x00)             // compression methods
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	hs := make([]byte, 0, 4+len(body))
	hs = append(hs, 0x01) // ClientHello
	hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	hs = append(hs, body...)

	rec := make([]byte, 0, 5+len(hs))
	rec = append(rec, 0x16, 0x03, 0x01)
	rec = append(rec, byte(len(hs)>>8), byte(len(hs)))
	return append(rec, hs...)
}

func TestParseTLSSNI(t *testing.T) {
	f := ethTCP(443, clientHello("secure.example.org"))
	got := Parse(true, f)
	if len(got) != 3 || got[0].Kind != "sni" || got[0].Value != "secure.example.org" {
		t.Fatalf("Parse = %+v, want [sni ja3 ja4] with sni secure.example.org", got)
	}
	if got[1].Kind != "ja3" || len(got[1].Value) != 32 {
		t.Errorf("ja3 finding = %+v, want 32-char md5", got[1])
	}
	if got[2].Kind != "ja4" || !strings.HasPrefix(got[2].Value, "t") ||
		strings.Count(got[2].Value, "_") != 2 {
		t.Errorf("ja4 finding = %+v, want t..._..._...", got[2])
	}
}

func TestParseTruncatedNeverPanics(t *testing.T) {
	full := ethUDP(53, dnsQuery("a.example.com", 1))
	full = append(full, ethTCP(443, clientHello("b.example.com"))...)
	for i := 0; i < len(full); i++ {
		_ = Parse(true, full[:i])
		_ = Parse(false, full[i:])
	}
	if got := Parse(true, []byte("garbage")); got != nil {
		t.Errorf("garbage = %+v, want nil", got)
	}
}

func TestDNSQueryNameEdgeCases(t *testing.T) {
	if n := DNSQueryName(dnsQuery("x.example.com", 1)[:13]); n != "" {
		t.Errorf("truncated label: %q, want \"\"", n)
	}
	// compression pointer inside a query is rejected
	msg := dnsQuery("a.b", 1)
	msg[12] = 0xc0
	if n := DNSQueryName(msg); n != "" {
		t.Errorf("pointer label: %q, want \"\"", n)
	}
	if n := DNSQueryName(nil); n != "" {
		t.Errorf("nil = %q, want \"\"", n)
	}
}

// ---- ClientHello builder for fingerprint vectors ----

type chExt struct {
	typ  uint16
	body []byte
}

type chBuilder struct {
	legacy  uint16
	ciphers []uint16
	exts    []chExt
}

func (b *chBuilder) add(typ uint16, body []byte) *chBuilder {
	b.exts = append(b.exts, chExt{typ, body})
	return b
}

func vecU16(vals ...uint16) []byte {
	out := make([]byte, 2+2*len(vals))
	binary.BigEndian.PutUint16(out[0:2], uint16(2*len(vals)))
	for i, v := range vals {
		binary.BigEndian.PutUint16(out[2+2*i:], v)
	}
	return out
}

func vecU8(vals ...uint8) []byte {
	return append([]byte{byte(len(vals))}, vals...)
}

// vecSupVer builds a ClientHello supported_versions body: u8 byte-length
// then versions (RFC 8446 — NOT a u16-prefixed vector).
func vecSupVer(vals ...uint16) []byte {
	out := []byte{byte(2 * len(vals))}
	for _, v := range vals {
		out = append(out, byte(v>>8), byte(v))
	}
	return out
}

func vecName(name string) []byte { // ALPN: u16 list length + one name entry
	inner := append([]byte{byte(len(name))}, name...)
	out := make([]byte, 2, 2+len(inner))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(inner)))
	return append(out, inner...)
}

func sniExtBody(name string) []byte {
	inner := []byte{0x00} // host_name
	inner = append(inner, byte(len(name)>>8), byte(len(name)))
	inner = append(inner, name...)
	out := make([]byte, 2, 2+len(inner))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(inner)))
	return append(out, inner...)
}

func (b *chBuilder) record() []byte {
	body := make([]byte, 0, 512)
	body = append(body, byte(b.legacy>>8), byte(b.legacy))
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00)
	cs := make([]byte, 2+2*len(b.ciphers))
	binary.BigEndian.PutUint16(cs[0:2], uint16(2*len(b.ciphers)))
	for i, c := range b.ciphers {
		binary.BigEndian.PutUint16(cs[2+2*i:], c)
	}
	body = append(body, cs...)
	body = append(body, 0x01, 0x00) // one compression method
	var extBytes []byte
	for _, e := range b.exts {
		extBytes = append(extBytes, byte(e.typ>>8), byte(e.typ))
		extBytes = append(extBytes, byte(len(e.body)>>8), byte(len(e.body)))
		extBytes = append(extBytes, e.body...)
	}
	body = append(body, byte(len(extBytes)>>8), byte(len(extBytes)))
	body = append(body, extBytes...)

	hs := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}
	return append(rec, hs...)
}

// TestJA3OfficialVector verifies against the published Salesforce example:
// 769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
// → ada70206e40642a3e4461f35503241d5
func TestJA3OfficialVector(t *testing.T) {
	b := &chBuilder{legacy: 0x0301, ciphers: []uint16{47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4}}
	b.add(0x0000, sniExtBody("x.example.com"))
	b.add(0x000a, vecU16(23, 24, 25))
	b.add(0x000b, vecU8(0))
	h := parseClientHello(b.record())
	if h == nil {
		t.Fatal("parse failed")
	}
	const want = "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
	sum := md5.Sum([]byte(want))
	if got := h.ja3(); got != hex.EncodeToString(sum[:]) {
		t.Errorf("ja3 = %s, want %s", got, hex.EncodeToString(sum[:]))
	}
}

// TestJA4OfficialVector verifies against the FoxIO spec example:
// t13d1516h2_8daaf6152771_e5627efa2ab1
func TestJA4OfficialVector(t *testing.T) {
	b := &chBuilder{legacy: 0x0303, ciphers: []uint16{
		0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9,
		0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
	}}
	b.add(0x001b, nil)
	b.add(0x0000, sniExtBody("example.com"))
	b.add(0x0033, nil)
	b.add(0x0010, vecName("h2"))
	b.add(0x4469, nil)
	b.add(0x0017, nil)
	b.add(0x002d, nil)
	b.add(0x000d, vecU16(0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601))
	b.add(0x0005, nil)
	b.add(0x0023, nil)
	b.add(0x0012, nil)
	b.add(0x002b, vecSupVer(0x0304, 0x0303))
	b.add(0xff01, nil)
	b.add(0x000b, vecU8(0))
	b.add(0x000a, vecU16(0x001d, 0x0017))
	b.add(0x0015, nil)
	h := parseClientHello(b.record())
	if h == nil {
		t.Fatal("parse failed")
	}
	if got := h.ja4(); got != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Errorf("ja4 = %s, want t13d1516h2_8daaf6152771_e5627efa2ab1", got)
	}
}

// TestGREASEExcluded: both specs drop GREASE anywhere it appears, and a
// GREASE value inside supported_versions must not win the version choice.
func TestGREASEExcluded(t *testing.T) {
	b := &chBuilder{legacy: 0x0303, ciphers: []uint16{0x0a0a, 0x1301, 0x1a1a}}
	b.add(0x2a2a, nil) // GREASE extension
	b.add(0x0000, sniExtBody("g.example.com"))
	b.add(0x002b, vecSupVer(0x2a2a, 0x0304))
	h := parseClientHello(b.record())
	if h == nil {
		t.Fatal("parse failed")
	}
	if len(h.ciphers) != 1 || h.ciphers[0] != 0x1301 {
		t.Errorf("ciphers = %v, want [4865] (GREASE dropped)", h.ciphers)
	}
	if len(h.exts) != 2 {
		t.Errorf("exts = %v, want GREASE extension dropped", h.exts)
	}
	if h.supVer != 0x0304 {
		t.Errorf("supVer = %#x, want 0x0304 (GREASE must not win)", h.supVer)
	}
	want := md5.Sum([]byte("771,4865,0-43,,"))
	if got := h.ja3(); got != hex.EncodeToString(want[:]) {
		t.Errorf("ja3 = %s, want %s", got, hex.EncodeToString(want[:]))
	}
	if ja4 := h.ja4(); !strings.HasPrefix(ja4, "t13d010200_") {
		t.Errorf("ja4 = %s, want prefix t13d010200_", ja4)
	}
}

// TestJA4ALPNRules covers the spec's first/last character rules.
func TestJA4ALPNRules(t *testing.T) {
	cases := map[string]string{
		"":         "00",
		"h2":       "h2",
		"http/1.1": "h1",
		"x":        "xx",
	}
	for in, want := range cases {
		if got := ja4ALPN(in); got != want {
			t.Errorf("ja4ALPN(%q) = %q, want %q", in, got, want)
		}
	}
	// non-alphanumeric ends fall back to the value's hex form
	if got := ja4ALPN("\xab"); got != "ab" {
		t.Errorf(`ja4ALPN("\xab") = %q, want "ab"`, got)
	}
	if got := ja4ALPN("\x20\x61"); got != "21" {
		t.Errorf(`ja4ALPN(0x20 0x61) = %q, want "21"`, got)
	}
}
