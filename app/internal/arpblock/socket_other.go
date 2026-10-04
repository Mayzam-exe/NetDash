//go:build !linux

package arpblock

import (
	"fmt"
	"net"
	"runtime"
)

// openSocket: raw ARP spoofing is only implemented on Linux.
func openSocket(iface *net.Interface) (func([]byte) error, func([]byte) (int, bool, error), func(), error) {
	return nil, nil, nil, fmt.Errorf("arp blocking unsupported on %s", runtime.GOOS)
}

// setMTU is Linux-only; other platforms never reach it (openSocket fails).
func setMTU(name string, mtu int) (int, error) {
	return 0, fmt.Errorf("mtu change unsupported on %s", runtime.GOOS)
}
