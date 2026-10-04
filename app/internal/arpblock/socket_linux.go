//go:build linux

package arpblock

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	ethPARP     = 0x0806
	pktOutgoing = 4 // PACKET_OUTGOING: our own frames looped back by the kernel
)

func htons(v uint16) uint16 {
	return v<<8 | v>>8
}

// openSocket binds two raw AF_PACKET sockets to iface: one for sending the
// ARP poison/repair (bound like the original, proven path) and one for
// receiving the traffic the poison attracts, with a short timeout so the
// relay loop can check its stop flag. Requires CAP_NET_RAW.
func openSocket(iface *net.Interface) (send func([]byte) error, recv func([]byte) (int, bool, error), release func(), err error) {
	sfd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("af_packet socket: %w", err)
	}
	ll := &syscall.SockaddrLinklayer{
		Protocol: htons(ethPARP),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(sfd, ll); err != nil {
		_ = syscall.Close(sfd)
		return nil, nil, nil, fmt.Errorf("af_packet bind: %w", err)
	}

	rfd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		_ = syscall.Close(sfd)
		return nil, nil, nil, fmt.Errorf("af_packet recv socket: %w", err)
	}
	rll := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(rfd, rll); err != nil {
		_ = syscall.Close(sfd)
		_ = syscall.Close(rfd)
		return nil, nil, nil, fmt.Errorf("af_packet recv bind: %w", err)
	}
	tv := &syscall.Timeval{Usec: 200000}
	if err := syscall.SetsockoptTimeval(rfd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, tv); err != nil {
		_ = syscall.Close(sfd)
		_ = syscall.Close(rfd)
		return nil, nil, nil, fmt.Errorf("af_packet recv timeout: %w", err)
	}

	// Pick the TX protocol from the frame's own ethertype: relayed IPv4
	// frames must not carry sll_protocol=0x0806 (ARP) metadata, or drivers
	// may treat them differently on the way out.
	llIP := &syscall.SockaddrLinklayer{
		Protocol: htons(0x0800),
		Ifindex:  iface.Index,
	}
	send = func(b []byte) error {
		if len(b) >= 14 && binary.BigEndian.Uint16(b[12:14]) == 0x0800 {
			return syscall.Sendto(sfd, b, 0, llIP)
		}
		return syscall.Sendto(sfd, b, 0, ll)
	}
	recv = func(b []byte) (int, bool, error) {
		n, from, err := syscall.Recvfrom(rfd, b, 0)
		if err != nil {
			return 0, false, err
		}
		outgoing := false
		if ssl, ok := from.(*syscall.SockaddrLinklayer); ok {
			outgoing = ssl.Pkttype == pktOutgoing
		}
		return n, outgoing, nil
	}
	release = func() {
		_ = syscall.Close(rfd)
		_ = syscall.Close(sfd)
	}
	return send, recv, release, nil
}

// setMTU reads the interface MTU and raises it to mtu if smaller. Needs
// CAP_NET_ADMIN. Returns the previous MTU — the current one when it is
// already big enough (0 only on error).
func setMTU(name string, mtu int) (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	var ifr struct {
		Name [16]byte
		MTU  int32
		_    [12]byte
	}
	copy(ifr.Name[:], name)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(syscall.SIOCGIFMTU), uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		return 0, errno
	}
	old := int(ifr.MTU)
	if old >= mtu {
		return old, nil
	}
	ifr.MTU = int32(mtu)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(syscall.SIOCSIFMTU), uintptr(unsafe.Pointer(&ifr))); errno != 0 {
		return 0, errno
	}
	return old, nil
}
