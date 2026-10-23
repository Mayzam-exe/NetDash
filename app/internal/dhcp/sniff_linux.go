//go:build linux

package dhcp

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Sniffer receives LAN frames on a dedicated, receive-only AF_PACKET socket.
// Broadcast DHCP is flooded to every switch port, so no promiscuous mode is
// needed to see joins. Requires CAP_NET_RAW.
type Sniffer struct {
	fd  int
	buf []byte
}

// Open resolves the interface that reaches gwIP and binds the socket to it.
// A short receive timeout keeps the engine's context checks responsive.
func Open(gwIPStr string) (*Sniffer, error) {
	gw := net.ParseIP(gwIPStr).To4()
	if gw == nil {
		return nil, fmt.Errorf("gateway ip unknown")
	}
	iface, err := pickIface(gw)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("af_packet socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: iface.Index}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind %s: %w", iface.Name, err)
	}
	tv := syscall.NsecToTimeval((500 * time.Millisecond).Nanoseconds())
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("recv timeout: %w", err)
	}
	return &Sniffer{fd: fd, buf: make([]byte, 2048)}, nil
}

// Next returns the next frame received on the interface. ok=false on receive
// timeout (normal — it is how the caller re-checks its stop flag) or error.
func (s *Sniffer) Next() (frame []byte, ok bool) {
	n, _, err := syscall.Recvfrom(s.fd, s.buf, 0)
	if err != nil || n <= 0 {
		return nil, false
	}
	out := make([]byte, n)
	copy(out, s.buf[:n])
	return out, true
}

// Close releases the socket.
func (s *Sniffer) Close() {
	if s.fd > 0 {
		syscall.Close(s.fd)
		s.fd = -1
	}
}

// pickIface finds the up, non-loopback interface whose IPv4 subnet contains
// the gateway (same proven approach as the ARP blocker).
func pickIface(gw net.IP) (net.Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return net.Interface{}, err
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
			if ipn.Contains(gw) {
				return ifc, nil
			}
		}
	}
	return net.Interface{}, fmt.Errorf("no interface reaches the gateway")
}
