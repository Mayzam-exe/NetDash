//go:build !linux

package helper

// fileCap is never true off Linux: grantcaps.sh installs no capability-bearing
// copies there, and the Windows path expects to be run as an administrator
// instead, which Capable's euid test already accepts.
func fileCap(path string, cap uint) bool {
	return false
}
