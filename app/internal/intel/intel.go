// Package intel extracts cleartext metadata from relayed IPv4 frames:
// DNS queries, TLS ClientHello SNI + JA3/JA4 fingerprints and HTTP Host
// headers. No TLS breaking — ClientHello fields are plaintext by design.
package intel

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
)

// Finding is one piece of cleartext metadata observed in a frame.
type Finding struct {
	Kind  string // dns | sni | http | ja3 | ja4
	Value string
}

// Parse inspects one ethernet+IPv4 frame and returns every hostname visible
// in its payload. Safe on truncated frames (best effort, never panics).
func Parse(up bool, f []byte) []Finding {
	if len(f) < 54 || binary.BigEndian.Uint16(f[12:14]) != 0x0800 {
		return nil
	}
	ihl := int(f[14]&0x0f) * 4
	if ihl < 20 || 14+ihl+8 > len(f) {
		return nil
	}
	l4 := 14 + ihl
	switch f[23] {
	case 17: // UDP
		if l4+8 > len(f) {
			return nil
		}
		dport := binary.BigEndian.Uint16(f[l4+2 : l4+4])
		if dport != 53 {
			return nil
		}
		payload := f[l4+8:]
		if name := DNSQueryName(payload); name != "" {
			return []Finding{{Kind: "dns", Value: name}}
		}
	case 6: // TCP
		if l4+14 > len(f) {
			return nil
		}
		doff := int(f[l4+12]>>4) * 4
		if doff < 20 || l4+doff > len(f) {
			return nil
		}
		dport := binary.BigEndian.Uint16(f[l4+2 : l4+4])
		payload := f[l4+doff:]
		if dport == 80 {
			if host := httpHost(payload); host != "" {
				return []Finding{{Kind: "http", Value: host}}
			}
		}
		if h := parseClientHello(payload); h != nil {
			out := make([]Finding, 0, 3)
			if h.sni != "" {
				out = append(out, Finding{Kind: "sni", Value: h.sni})
			}
			out = append(out,
				Finding{Kind: "ja3", Value: h.ja3()},
				Finding{Kind: "ja4", Value: h.ja4()})
			return out
		}
	}
	return nil
}

// DNSQueryName returns the first question name of a DNS message (lowercased,
// no trailing dot), or "" when the message is not a resolvable query.
func DNSQueryName(p []byte) string {
	if len(p) < 13 {
		return ""
	}
	if binary.BigEndian.Uint16(p[4:6]) == 0 { // qdcount
		return ""
	}
	off := 12
	var parts []string
	total := 0
	for {
		if off >= len(p) {
			return ""
		}
		l := int(p[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || off+l > len(p) || l > 63 {
			return "" // compression pointer or overrun: queries normally none
		}
		parts = append(parts, string(p[off:off+l]))
		total += l + 1
		off += l
		if total > 253 {
			return ""
		}
	}
	if off+4 > len(p) || len(parts) == 0 {
		return ""
	}
	return strings.ToLower(strings.Join(parts, "."))
}

// QuestionEnd returns the offset just past the first DNS question
// (start of answers), or -1.
func QuestionEnd(p []byte) int {
	if len(p) < 13 {
		return -1
	}
	off := 12
	for {
		if off >= len(p) {
			return -1
		}
		l := int(p[off])
		off++
		if l == 0 {
			break
		}
		if l&0xc0 != 0 || off+l > len(p) {
			return -1
		}
		off += l
	}
	if off+4 > len(p) {
		return -1
	}
	return off + 4
}

func httpHost(p []byte) string {
	if len(p) < 8 {
		return ""
	}
	head := p
	if len(head) > 1024 {
		head = head[:1024]
	}
	low := strings.ToLower(string(head))
	i := strings.Index(low, "\r\nhost: ")
	if i < 0 {
		if !strings.HasPrefix(low, "host: ") {
			return ""
		}
		i = -2
	}
	var rest string
	if i == -2 {
		rest = string(head)[6:]
	} else {
		rest = string(head)[i+8:]
	}
	if j := strings.IndexAny(rest, "\r\n"); j >= 0 {
		rest = rest[:j]
	}
	return strings.ToLower(strings.TrimSpace(rest))
}

// hello is a parsed TLS ClientHello: everything JA3/JA4 need plus SNI/ALPN.
// GREASE values are dropped at parse time — both specs ignore them.
type hello struct {
	legacy  uint16   // ClientHello legacy version (JA3 "SSLVersion")
	ciphers []uint16 // cipher suites, original order, GREASE removed
	exts    []uint16 // extension types, original order, GREASE removed
	groups  []uint16 // supported_groups
	pts     []uint8  // ec_point_formats
	sigalgs []uint16 // signature_algorithms, original order
	supVer  uint16   // highest supported_versions entry (GREASE excluded), 0 if none
	sni     string
	hasSNI  bool
	alpn    string // first ALPN value
}

// isGREASE reports whether v is one of the GREASE values (RFC 8701).
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// parseClientHello parses one TLS record holding a ClientHello, or returns
// nil when the record is not a parseable ClientHello. Never panics.
func parseClientHello(p []byte) *hello {
	if len(p) < 45 || p[0] != 0x16 || p[1] != 0x03 || p[5] != 1 {
		return nil
	}
	off := 9
	h := &hello{legacy: binary.BigEndian.Uint16(p[off : off+2])}
	off += 2 + 32 // legacy version + random
	if off >= len(p) {
		return nil
	}
	sidLen := int(p[off])
	off += 1 + sidLen
	if off+2 > len(p) {
		return nil
	}
	csLen := int(binary.BigEndian.Uint16(p[off : off+2]))
	off += 2
	if csLen%2 != 0 || off+csLen > len(p) {
		return nil
	}
	for i := 0; i < csLen; i += 2 {
		v := binary.BigEndian.Uint16(p[off+i : off+i+2])
		if !isGREASE(v) {
			h.ciphers = append(h.ciphers, v)
		}
	}
	off += csLen
	if off+1 > len(p) {
		return nil
	}
	compLen := int(p[off])
	off += 1 + compLen
	if off == len(p) {
		return h // valid ClientHello without extensions
	}
	if off+2 > len(p) {
		return nil
	}
	extEnd := off + 2 + int(binary.BigEndian.Uint16(p[off:off+2]))
	off += 2
	if extEnd > len(p) {
		extEnd = len(p) // truncated tail: parse what arrived
	}
	for off+4 <= extEnd {
		typ := binary.BigEndian.Uint16(p[off : off+2])
		size := int(binary.BigEndian.Uint16(p[off+2 : off+4]))
		off += 4
		if off+size > extEnd {
			break
		}
		body := p[off : off+size]
		off += size
		if isGREASE(typ) {
			continue
		}
		h.exts = append(h.exts, typ)
		switch typ {
		case 0x0000:
			h.hasSNI = true
			h.sni = sniName(body)
		case 0x000a:
			h.groups = u16List(body)
		case 0x000b:
			h.pts = u8List(body)
		case 0x000d:
			h.sigalgs = u16List(body)
		case 0x0010:
			h.alpn = alpnFirst(body)
		case 0x002b:
			// client supported_versions: u8 byte-length prefix (RFC 8446),
			// unlike the u16 vectors used by other extensions
			for _, v := range u16List8(body) {
				if !isGREASE(v) && v > h.supVer {
					h.supVer = v
				}
			}
		}
	}
	return h
}

// sniName extracts the host_name from a server_name extension body.
func sniName(d []byte) string {
	if len(d) < 5 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(d[0:2]))
	if 2+listLen > len(d) || d[2] != 0 {
		return ""
	}
	nameLen := int(binary.BigEndian.Uint16(d[3:5]))
	if 5+nameLen > len(d) || nameLen == 0 {
		return ""
	}
	return strings.ToLower(string(d[5 : 5+nameLen]))
}

// u16List reads a length-prefixed u16 list (supported_groups, sigalgs, ...).
func u16List(d []byte) []uint16 {
	if len(d) < 2 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(d[0:2]))
	if n%2 != 0 || 2+n > len(d) {
		return nil
	}
	out := make([]uint16, 0, n/2)
	for i := 0; i < n; i += 2 {
		out = append(out, binary.BigEndian.Uint16(d[2+i:4+i]))
	}
	return out
}

// u16List8 reads a u8-byte-length-prefixed u16 vector (client
// supported_versions in a ClientHello).
func u16List8(d []byte) []uint16 {
	if len(d) < 1 {
		return nil
	}
	n := int(d[0])
	if n%2 != 0 || 1+n > len(d) {
		return nil
	}
	out := make([]uint16, 0, n/2)
	for i := 0; i < n; i += 2 {
		out = append(out, binary.BigEndian.Uint16(d[1+i:3+i]))
	}
	return out
}

// u8List reads a length-prefixed byte list (ec_point_formats).
func u8List(d []byte) []uint8 {
	if len(d) < 1 {
		return nil
	}
	n := int(d[0])
	if 1+n > len(d) {
		return nil
	}
	return append([]uint8(nil), d[1:1+n]...)
}

// alpnFirst returns the first ALPN protocol name.
func alpnFirst(d []byte) string {
	if len(d) < 3 {
		return ""
	}
	total := int(binary.BigEndian.Uint16(d[0:2]))
	if 2+total > len(d) || total == 0 {
		return ""
	}
	off := 2
	l := int(d[off])
	off++
	if l == 0 || off+l > 2+total {
		return ""
	}
	return string(d[off : off+l])
}

// ja3 is the classic JA3 client fingerprint: MD5 of
// "Version,Ciphers,Extensions,Groups,PointFormats" — fields comma-joined,
// values within a field dash-joined, decimal, GREASE excluded.
func (h *hello) ja3() string {
	s := strings.Join([]string{
		strconv.Itoa(int(h.legacy)),
		dashDec16(h.ciphers),
		dashDec16(h.exts),
		dashDec16(h.groups),
		dashDec8(h.pts),
	}, ",")
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// ja4 is the JA4 fingerprint (FoxIO): t + version + sni-flag + counts +
// alpn, then truncated sha256 of the sorted cipher list and of the sorted
// extension list (SNI/ALPN omitted) plus the signature algorithms.
func (h *hello) ja4() string {
	ver := h.supVer
	if ver == 0 {
		ver = h.legacy
	}
	sniC := byte('i')
	if h.hasSNI {
		sniC = 'd'
	}
	nc, ne := len(h.ciphers), len(h.exts)
	if nc > 99 {
		nc = 99
	}
	if ne > 99 {
		ne = 99
	}
	a := "t" + ja4Version(ver) + string(sniC) +
		strconv.Itoa(nc/10) + strconv.Itoa(nc%10) +
		strconv.Itoa(ne/10) + strconv.Itoa(ne%10) +
		ja4ALPN(h.alpn)

	b := "000000000000"
	if len(h.ciphers) > 0 {
		cs := append([]uint16(nil), h.ciphers...)
		sort.Slice(cs, func(i, j int) bool { return cs[i] < cs[j] })
		b = hash12(hexJoin(cs))
	}

	c := "000000000000"
	exts := make([]uint16, 0, len(h.exts))
	for _, t := range h.exts {
		if t != 0x0000 && t != 0x0010 { // SNI and ALPN live in section a
			exts = append(exts, t)
		}
	}
	if len(exts) > 0 {
		sort.Slice(exts, func(i, j int) bool { return exts[i] < exts[j] })
		s := hexJoin(exts)
		if len(h.sigalgs) > 0 {
			s += "_" + hexJoin(h.sigalgs) // original order, not sorted
		}
		c = hash12(s)
	}
	return a + "_" + b + "_" + c
}

// ja4Version maps a TLS version to the JA4 two-character code.
func ja4Version(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	}
	return "00"
}

// ja4ALPN is first+last alphanumeric of the first ALPN value; when either
// end is not alphanumeric, first/last characters of the value's hex form.
func ja4ALPN(v string) string {
	if v == "" {
		return "00"
	}
	alnum := func(b byte) bool {
		return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
	}
	if alnum(v[0]) && alnum(v[len(v)-1]) {
		return string(v[0]) + string(v[len(v)-1])
	}
	hx := hex.EncodeToString([]byte(v))
	return string(hx[0]) + string(hx[len(hx)-1])
}

// hash12 is sha256 as lowercase hex, truncated to 12 characters.
func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// hexJoin renders u16 values as 4-char lowercase hex, comma-delimited.
func hexJoin(v []uint16) string {
	var b strings.Builder
	for i, x := range v {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(hexU16(x))
	}
	return b.String()
}

func hexU16(v uint16) string {
	const digits = "0123456789abcdef"
	return string([]byte{digits[v>>12], digits[(v>>8)&0xf], digits[(v>>4)&0xf], digits[v&0xf]})
}

// dashDec16 renders u16 values as decimal joined with '-'.
func dashDec16(v []uint16) string {
	if len(v) == 0 {
		return ""
	}
	var b strings.Builder
	for i, x := range v {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.Itoa(int(x)))
	}
	return b.String()
}

// dashDec8 renders bytes as decimal joined with '-'.
func dashDec8(v []uint8) string {
	if len(v) == 0 {
		return ""
	}
	var b strings.Builder
	for i, x := range v {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(strconv.Itoa(int(x)))
	}
	return b.String()
}
