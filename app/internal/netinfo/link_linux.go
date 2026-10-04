//go:build linux

package netinfo

import (
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LinkBounce briefly takes ifName down and back up, forcing the link layer
// (and NetworkManager's DHCP client) to renegotiate from scratch. It runs
// in-process so the daemon's CAP_NET_ADMIN applies directly — no privileged
// helper binary is needed. Used as the fallback when nmcli is unavailable.
func LinkBounce(ifName string) error {
	if ifName == "" {
		return fmt.Errorf("no interface name")
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq(ifName)
	if err != nil {
		return fmt.Errorf("interface %q: %w", ifName, err)
	}
	// SIOCGIFFLAGS into the request, then flip IFF_UP off/on.
	if err := ioctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("get flags %s: %w", ifName, err)
	}
	orig := ifr.Uint16()

	ifr.SetUint16(orig &^ unix.IFF_UP)
	if err := ioctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("down %s: %w", ifName, err)
	}
	time.Sleep(400 * time.Millisecond)

	ifr.SetUint16(orig | unix.IFF_UP)
	if err := ioctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("up %s: %w", ifName, err)
	}
	return nil
}

// ioctlIfreq issues req with *Ifreq; the wrapper struct's single unexported
// field has identical layout to the raw ifreq, so the kernel sees the same
// memory layout (same technique x/sys itself uses internally).
func ioctlIfreq(fd int, req uint, ifr *unix.Ifreq) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(unsafe.Pointer(ifr)))
	if errno != 0 {
		return errno
	}
	return nil
}
