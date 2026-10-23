//go:build linux

package helper

import "golang.org/x/sys/unix"

// capXattr is the extended attribute carrying a file capability set.
const capXattr = "security.capability"

// fileCap reports whether the file at path grants cap in its permitted set.
//
// Read from the attribute itself rather than inferred by running the helper:
// the only observable difference between "no capability" and "no such device"
// is an equally bare "Operation not permitted", so an attempted run would prove
// nothing either way.
func fileCap(path string, cap uint) bool {
	buf := make([]byte, 64)
	n, err := unix.Getxattr(path, capXattr, buf)
	if err != nil || n == 0 {
		return false
	}
	return grantsCap(buf[:n], cap)
}
