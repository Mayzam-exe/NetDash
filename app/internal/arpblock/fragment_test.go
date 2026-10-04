package arpblock

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// foldRaw ones-complement folds a buffer WITHOUT the final complement
// (RFC 1071). A checksum field is valid iff folding the buffer INCLUDING
// the field yields 0xffff.
func foldRaw(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return uint16(sum)
}

// makeTCPFrame builds an ethernet+IPv4+TCP frame like a GRO-merged segment:
// valid layout, DF set, deliberately stale (first-segment) checksum.
func makeTCPFrame(payloadLen int, df bool) []byte {
	f := make([]byte, 14+20+20+payloadLen)
	f[12], f[13] = 0x08, 0x00
	ip := f[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20+payloadLen))
	binary.BigEndian.PutUint16(ip[4:6], 0x51c3) // id
	if df {
		binary.BigEndian.PutUint16(ip[6:8], 0x4000)
	}
	ip[8] = 49 // ttl
	ip[9] = 6  // TCP
	copy(ip[12:16], []byte{104, 14, 156, 121})
	copy(ip[16:20], []byte{192, 168, 1, 56})

	tcp := ip[20:]
	binary.BigEndian.PutUint16(tcp[0:2], 443)
	binary.BigEndian.PutUint16(tcp[2:4], 51052)
	binary.BigEndian.PutUint32(tcp[4:8], 0x38d48fb7)
	binary.BigEndian.PutUint32(tcp[8:12], 1)
	tcp[12] = 5 << 4 // 20-byte header
	binary.BigEndian.PutUint16(tcp[14:16], 65535)
	// stale checksum — as GRO leaves it (first segment's value)
	binary.BigEndian.PutUint16(tcp[16:18], 0xd1c6)
	for i := 0; i < payloadLen; i++ {
		tcp[20+i] = byte(i * 7)
	}
	binary.BigEndian.PutUint16(ip[10:12], 0)
	binary.BigEndian.PutUint16(ip[10:12], ^foldRaw(ip[:20]))
	return f
}

// tcpCsumBuffer builds pseudo-header + TCP segment for verification.
func tcpCsumBuffer(p []byte) []byte {
	ihl := int(p[0]&0x0f) * 4
	seg := p[ihl:]
	out := make([]byte, 0, 12+len(seg))
	out = append(out, p[12:20]...) // src + dst
	out = append(out, 0, p[9])
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(seg)))
	out = append(out, l[0], l[1])
	return append(out, seg...)
}

func TestFixL4ChecksumRepairsStaleGROValue(t *testing.T) {
	f := makeTCPFrame(100, true)
	ip := f[14:]
	// pre-condition: stored checksum is wrong
	if foldRaw(tcpCsumBuffer(ip)) == 0xffff {
		t.Fatal("frame should start with a stale checksum")
	}
	fixL4Checksum(ip)
	if got := foldRaw(tcpCsumBuffer(ip)); got != 0xffff {
		t.Errorf("repaired tcp checksum: fold=%04x, want ffff", got)
	}
	// idempotent
	before := append([]byte(nil), ip...)
	fixL4Checksum(ip)
	if !bytes.Equal(before, ip) {
		t.Error("second fix changed a correct checksum")
	}
}

func TestFixL4ChecksumKeepsDisabledUDP(t *testing.T) {
	f := make([]byte, 14+20+8+10)
	f[12], f[13] = 0x08, 0x00
	ip := f[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 20+8+10)
	ip[9] = 17
	copy(ip[12:16], []byte{192, 168, 1, 2})
	copy(ip[16:20], []byte{192, 168, 1, 56})
	// udp[6:8] already zero
	fixL4Checksum(ip)
	udp := ip[20:]
	if udp[6] != 0 || udp[7] != 0 {
		t.Errorf("udp checksum = %02x%02x, want kept disabled", udp[6], udp[7])
	}
}

func TestFragmentOversizeReassembles(t *testing.T) {
	const maxFrame = 600
	f := makeTCPFrame(1300, true)
	origID := binary.BigEndian.Uint16(f[18:20])
	origSrc := append([]byte(nil), f[26:30]...)
	origDst := append([]byte(nil), f[30:34]...)

	frags, err := fragmentIPv4(f, maxFrame)
	if err != nil {
		t.Fatalf("fragmentIPv4: %v", err)
	}
	// fragmentIPv4 repairs the L4 checksum in place — reference payload after
	origPayload := append([]byte(nil), f[34:]...)
	if len(frags) < 3 {
		t.Fatalf("fragments = %d, want >= 3", len(frags))
	}

	var reassembled []byte
	expectedOff := 0
	for i, fr := range frags {
		if len(fr) > maxFrame {
			t.Errorf("frag %d len = %d > maxFrame %d", i, len(fr), maxFrame)
		}
		if !bytes.Equal(fr[0:6], f[0:6]) || !bytes.Equal(fr[6:12], f[6:12]) {
			t.Errorf("frag %d ethernet addresses rewritten", i)
		}
		ip := fr[14:]
		if binary.BigEndian.Uint16(ip[4:6]) != origID {
			t.Errorf("frag %d ip id mismatch", i)
		}
		flags := binary.BigEndian.Uint16(ip[6:8])
		if flags&0x4000 != 0 {
			t.Errorf("frag %d still has DF set", i)
		}
		mf := flags&0x2000 != 0
		last := i == len(frags)-1
		if mf == last {
			t.Errorf("frag %d MF=%v, want %v", i, mf, !last)
		}
		off := int(flags&0x1fff) * 8
		if off != expectedOff {
			t.Errorf("frag %d offset = %d, want %d", i, off, expectedOff)
		}
		if foldRaw(ip[:20]) != 0xffff {
			t.Errorf("frag %d bad ip checksum: fold=%04x", i, foldRaw(ip[:20]))
		}
		tot := int(binary.BigEndian.Uint16(ip[2:4]))
		if tot != len(ip) {
			t.Errorf("frag %d tot_len=%d, frame ip len=%d", i, tot, len(ip))
		}
		expectedOff += len(ip[20:])
		reassembled = append(reassembled, ip[20:]...)
	}
	if !bytes.Equal(reassembled, origPayload) {
		t.Errorf("reassembled payload mismatch (%d vs %d bytes)", len(reassembled), len(origPayload))
	}
	// the reassembled segment must carry a checksum that validates
	seg := reassembled
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(origSrc[0:2]))
	sum += uint32(binary.BigEndian.Uint16(origSrc[2:4]))
	sum += uint32(binary.BigEndian.Uint16(origDst[0:2]))
	sum += uint32(binary.BigEndian.Uint16(origDst[2:4]))
	sum += 6
	sum += uint32(len(seg))
	for i := 0; i+1 < len(seg); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(seg[i : i+2]))
	}
	if len(seg)%2 == 1 {
		sum += uint32(seg[len(seg)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	if uint16(sum) != 0xffff {
		t.Errorf("reassembled tcp checksum invalid: fold=%04x, want ffff", uint16(sum))
	}
}

func TestFragmentSmallFrameSinglePassthrough(t *testing.T) {
	f := makeTCPFrame(100, false)
	frags, err := fragmentIPv4(f, 1514)
	if err != nil {
		t.Fatalf("fragmentIPv4: %v", err)
	}
	if len(frags) != 1 || !bytes.Equal(frags[0], f) {
		t.Errorf("small frame should pass through as one piece")
	}
}

func TestFragmentRejectsMalformed(t *testing.T) {
	f := makeTCPFrame(100, false)
	bad := append([]byte(nil), f...)
	binary.BigEndian.PutUint16(bad[16:18], 9000) // tot_len beyond frame
	if _, err := fragmentIPv4(bad, 600); err == nil {
		t.Error("bad tot_len accepted")
	}
	opts := append([]byte(nil), f...)
	opts[14] = 0x46 // ihl 24 — IP options
	if _, err := fragmentIPv4(opts, 600); err == nil {
		t.Error("ip options accepted")
	}
	if _, err := fragmentIPv4(f[:20], 600); err == nil {
		t.Error("short frame accepted")
	}
}
