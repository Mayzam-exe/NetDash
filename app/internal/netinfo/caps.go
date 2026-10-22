package netinfo

import (
	"os"
	"path/filepath"
	"strings"
)

// FileCapsBlocked names the mount that stops file capabilities from applying to
// path, or "" when none does.
//
// The kernel skips the security.capability xattr entirely on a mount carrying
// nosuid. The failure is completely silent: setcap exits 0, getcap reports the
// capabilities, and the process still receives none. Anything that advises
// running setcap therefore has to check this first, or it hands out an
// instruction that cannot work.
//
// /proc/self/mountinfo is Linux; elsewhere the read fails and this reports "",
// which is correct — the capability model being described is Linux's.
func FileCapsBlocked(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return ""
	}
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return ""
	}
	return nosuidMountFor(abs, string(b))
}

// nosuidMountFor returns the deepest mount covering path whose mount options
// include nosuid, or "". Mountpoints are matched as path prefixes with the
// longest match winning, because bind mounts overlap one another. Exposed as a
// pure function so the match rules can be tested without a real mount table.
//
// mountinfo line layout (see proc(5)):
//
//	id parent maj:min root mountpoint options [optional...] - fstype source superopts
//
// Field 5 is the VFS mount options — nosuid lives there, not in the
// filesystem-specific super options after the "-".
func nosuidMountFor(path, mountinfo string) string {
	best, bestOpts := "", ""
	for _, line := range strings.Split(mountinfo, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		mp, opts := f[4], f[5]
		if !underMount(path, mp) || len(mp) < len(best) {
			continue
		}
		best, bestOpts = mp, opts
	}
	if !mountOpt(bestOpts, "nosuid") {
		return ""
	}
	return best
}

// underMount reports whether path sits at or below mountpoint.
func underMount(path, mountpoint string) bool {
	if mountpoint == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == mountpoint || strings.HasPrefix(path, strings.TrimRight(mountpoint, "/")+"/")
}

// mountOpt matches one comma-separated mount option exactly, so "nosuid" does
// not match a hypothetical "nosuidfoo".
func mountOpt(options, want string) bool {
	for _, o := range strings.Split(options, ",") {
		if o == want {
			return true
		}
	}
	return false
}
