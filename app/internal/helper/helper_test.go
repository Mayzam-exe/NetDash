package helper

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pointDir redirects the installation root at an empty directory for the
// duration of a test, so results do not depend on whether grantcaps.sh has run
// on this machine.
func pointDir(t *testing.T) {
	t.Helper()
	restore := Dir
	Dir = t.TempDir()
	t.Cleanup(func() { Dir = restore })
}

// putTool drops an executable named name into dir and returns its path.
func putTool(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPathPrefersTheInstalledCopy(t *testing.T) {
	pointDir(t)
	installed := putTool(t, Dir, "tc")
	onPath := putTool(t, t.TempDir(), "tc")
	t.Setenv("PATH", filepath.Dir(onPath))

	// Both exist: the copy carries the capability, so it is the one to run.
	if got := Path("tc"); got != installed {
		t.Errorf("Path = %q, want the installed copy %q", got, installed)
	}

	// No copy yet (grantcaps.sh not run): fall back to the system tool rather
	// than refuse to run at all.
	Dir = t.TempDir()
	if got := Path("tc"); got != onPath {
		t.Errorf("Path = %q, want the PATH tool %q", got, onPath)
	}

	// Neither: hand exec the bare name, which produces its own honest
	// "not found in $PATH" instead of a fabricated one.
	Dir = t.TempDir()
	t.Setenv("PATH", t.TempDir())
	if got := Path("tc"); got != "tc" {
		t.Errorf("Path = %q, want the bare name %q", got, "tc")
	}
}

func TestAvailableReportsWhatItChecked(t *testing.T) {
	pointDir(t)
	t.Setenv("PATH", t.TempDir())

	if Available("tc") {
		t.Error("available with neither a copy nor a PATH entry")
	}
	putTool(t, t.TempDir(), "tc") // still not on PATH
	if Available("tc") {
		t.Error("available without the tool being reachable")
	}
	installed := putTool(t, Dir, "tc")
	if !Available("tc") {
		t.Errorf("not available with a copy at %q", installed)
	}
}

func TestCapableNamesTheFixRatherThanTheSymptom(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which needs no helper grant")
	}
	pointDir(t)
	putTool(t, Dir, "tc") // present, but without a capability of its own

	ok, why := Capable("tc")
	if ok {
		t.Fatal("Capable succeeded for a helper holding no CAP_NET_ADMIN")
	}
	if !strings.Contains(why, "grantcaps.sh") {
		t.Errorf("reason %q does not name the command that fixes it", why)
	}
	if !strings.Contains(why, "CAP_NET_ADMIN") {
		t.Errorf("reason %q does not say which capability is missing", why)
	}
}

func TestCapableWhenTheToolIsMissing(t *testing.T) {
	pointDir(t)
	t.Setenv("PATH", t.TempDir())

	ok, why := Capable("ip")
	if ok {
		t.Fatal("Capable succeeded with no ip anywhere")
	}
	if !strings.Contains(why, "not found") {
		t.Errorf("reason %q should say the tool is missing", why)
	}
}

// capValue builds a security.capability value of the given revision with the
// two permitted words set, leaving inheritable zero.
func capValue(rev uint32, perm0, perm1 uint32) []byte {
	b := make([]byte, 24) // room for a revision-three rootid tail
	binary.LittleEndian.PutUint32(b[0:4], rev)
	binary.LittleEndian.PutUint32(b[4:8], perm0)
	binary.LittleEndian.PutUint32(b[12:16], perm1)
	return b
}

func TestGrantsCapReadsTheRightBit(t *testing.T) {
	v2 := capValue(vfsCapRev2, 1<<12, 0)
	if !grantsCap(v2, 12) {
		t.Error("bit 12 of word 0 should be granted")
	}
	if grantsCap(v2, 13) {
		t.Error("bit 13 was never set")
	}

	// A revision-three value carries a trailing rootid; parsing must not care.
	v3 := capValue(vfsCapRev3, 1<<12, 0)
	if !grantsCap(v3, 12) {
		t.Error("revision three should parse like revision two")
	}

	// Second word: capabilities 32-63 live there, and the offset must follow
	// the index rather than assume a fixed layout.
	hi := capValue(vfsCapRev2, 0, 1<<8)
	if !grantsCap(hi, 40) {
		t.Error("bit 8 of word 1 (capability 40) should be granted")
	}
	if grantsCap(hi, 39) {
		t.Error("capability 39 was never set")
	}
}

func TestGrantsCapRejectsValuesThatAreNotCapabilities(t *testing.T) {
	cases := map[string][]byte{
		"no attribute": {},
		"truncated":    capValue(vfsCapRev2, 1<<12, 0)[:19],
		"unknown rev":  capValue(0x01000000, 1<<12, 0),
		"acl or other": []byte("user.hello\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
	}
	for name, b := range cases {
		if grantsCap(b, 12) {
			t.Errorf("%s: parsed as a grant of cap_net_admin", name)
		}
	}
	if grantsCap(capValue(vfsCapRev2, 1<<12, 0), 64) {
		t.Error("capability 64 does not exist")
	}
}
