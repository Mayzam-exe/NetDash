// Package helper resolves the privileged helper binary — nft — to an
// executable that actually carries the authority to run it.
//
// Why a copy, and why grantcaps.sh installs one
// ---------------------------------------------
// File capabilities are applied by execve to the file being executed, and they
// are not inherited. The grant netdash holds gives netdash CAP_NET_ADMIN and
// gives every child it spawns none: running /usr/bin/nft starts nft with an
// empty capability set, so each firewall call fails with the kernel's bare
// "Operation not permitted" — while in-process raw sockets keep working, which
// is what hides the cause.
//
// Two escapes exist and only one is usable here. Raising the ambient set needs
// CAP_SETPCAP in the caller, which this kernel refuses even for a process
// holding every capability, and systemd --user holds no privilege to do it on
// the service's behalf either (the unit exits 218/CAPABILITIES). Giving the
// helper its own grant needs no privilege at run time: a file capability applies
// to whatever file is executed, so an unprivileged parent can spawn a privileged
// helper. grantcaps.sh installs such copies under Dir, and Path prefers them.
//
// ip(8) and tc(8) are deliberately absent from that list. ip(8) was installed
// the same way, with a byte-identical security.capability xattr, and it still
// exec'd with CapPrm reading zero — while nft(8) and python3 retained theirs
// under the same directory and the same mount. The difference follows the
// file's content rather than its path: nft's content keeps the grant under any
// name. So delegation to ip(8) cannot be made to work, and nothing in netdash
// shells out to ip(8) or tc(8) for anything privileged.
//
// Without those copies the code still resolves the system tool and fails with
// the kernel's own message rather than claiming a success it cannot deliver.
package helper

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
)

// Dir is where grantcaps.sh installs the capability-bearing copies of the
// privileged helpers (on the same root-owned volume as the binary itself,
// because file capabilities are ignored on a nosuid mount). It is a variable so
// a test can point it at an empty directory and exercise the PATH fallback.
var Dir = "/usr/local/lib/netdash/helpers"

// CapNetAdmin is what nft(8) needs in order to change state through netlink,
// and what this process needs for its own in-process link work (setting the
// MTU, bouncing the radio). The helper never needs anything else: reads are
// unprivileged, and raw sockets are used in-process rather than by exec.
const CapNetAdmin uint = 12

// Revisions of the security.capability value. The attribute's name is shared
// with meanings that are not capabilities, so a value whose revision bits match
// neither is rejected rather than parsed as if it were one.
const (
	vfsCapRevMask = 0xff000000
	vfsCapRev2    = 0x02000000
	vfsCapRev3    = 0x03000000
)

// grantsCap reports whether a security.capability value grants cap in its
// permitted set.
//
// Layout (little endian throughout): four bytes of magic carrying the revision,
// then a permitted/inheritable pair of four-byte words per 32 capabilities —
// two words, so 20 bytes before any revision-three rootid tail. Capabilities
// above 63 address the second word, which is why the offset is derived rather
// than assumed.
func grantsCap(b []byte, cap uint) bool {
	le := binary.LittleEndian.Uint32
	if len(b) < 20 || cap >= 64 {
		return false
	}
	switch le(b[0:4]) & vfsCapRevMask {
	case vfsCapRev2, vfsCapRev3:
	default:
		return false
	}
	off := 4 + int(cap/32)*8
	if off+4 > len(b) {
		return false
	}
	return le(b[off:off+4])&(1<<(cap%32)) != 0
}

// Capable reports whether name can be run with the authority privileged netlink
// operations need, and the reason when it cannot.
//
// Root needs no help — a process running as root keeps its capabilities across
// execve even when the executed file carries none of its own — so the euid test
// comes first and covers "run it under sudo by hand".
func Capable(name string) (bool, string) {
	if !Available(name) {
		return false, name + " not found"
	}
	if os.Geteuid() == 0 || fileCap(Path(name), CapNetAdmin) {
		return true, ""
	}
	return false, "no CAP_NET_ADMIN on " + name + " — run ./grantcaps.sh, then restart netdash"
}

// Available reports whether the named helper resolves to something runnable.
func Available(name string) bool {
	return installed(name) != "" || lookPath(name) != ""
}

// Path resolves name to the executable to run: the copy grantcaps.sh installed
// with a capability of its own when there is one, otherwise whatever PATH has,
// otherwise the bare name so exec reports its usual "not found in $PATH".
func Path(name string) string {
	if p := installed(name); p != "" {
		return p
	}
	if p := lookPath(name); p != "" {
		return p
	}
	return name
}

// installed returns the copy grantcaps.sh installs, when there is one. The
// capability itself is checked separately by Capable, so a copy whose grant was
// lost fails with the message that names the fix instead of with a bare
// permission error from deep inside tc.
func installed(name string) string {
	p := filepath.Join(Dir, name)
	st, err := os.Stat(p)
	if err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
		return ""
	}
	return p
}

// lookPath is exec.LookPath, kept in one place so both callers agree on
// "found".
func lookPath(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}
