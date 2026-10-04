//go:build !linux

package netinfo

import "fmt"

// LinkBounce is only implemented on Linux (in-process ioctl with
// CAP_NET_ADMIN). Other platforms report honestly instead of faking it.
func LinkBounce(ifName string) error {
	return fmt.Errorf("link bounce is not supported on this platform")
}
