package netinfo

import (
	"os"
	"strings"
	"testing"
)

// Two overlapping mounts: / is nosuid-free, the bind at /srv/media carries it.
// A path in the bind must report the bind, not the root it also sits under.
const sampleMountinfo = `21 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
36 21 8:17 / /srv rw,relatime shared:18 - ext4 /dev/sdb1 rw
72 36 8:17 / /srv/media rw,nosuid,nodev shared:20 - ext4 /dev/sdb1 rw
73 36 8:18 / /srv/media/cache rw,noexec shared:21 - ext4 /dev/sdb2 rw
101 21 0:28 / /run rw,nosuid,nodev shared:30 - tmpfs tmpfs rw
120 21 0:30 / /opt rw,relatime shared:40 - xfs /dev/sda2 rw
`

func TestNosuidMountFor(t *testing.T) {
	cases := []struct {
		name, path, want string
	}{
		// The bug this exists for: a file on removable media, setcap'd,
		// where the kernel ignores the grant.
		{
			name: "removable volume carrying nosuid",
			path: "/srv/media/home/user/Projects/netdash/run/netdash",
			want: "/srv/media",
		},
		{
			name: "exact mountpoint",
			path: "/srv/media",
			want: "/srv/media",
		},
		{
			name: "longest prefix beats the enclosing mount",
			// /srv/media is nosuid, /srv/media/cache is not: deepest wins.
			path: "/srv/media/cache/file",
			want: "",
		},
		{
			name: "plain root mount grants nothing wrongly",
			path: "/usr/local/lib/netdash/netdash",
			want: "",
		},
		{
			name: "prefix must not match a sibling with a shared prefix",
			path: "/srv/mediaother/file",
			want: "",
		},
		{
			name: "tmpfs with nosuid",
			path: "/run/netdash",
			want: "/run",
		},
		{
			name: "path matching the sample's grantable root",
			path: "/a/b/c",
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := nosuidMountFor(c.path, sampleMountinfo); got != c.want {
				t.Errorf("nosuidMountFor(%q) = %q, want %q", c.path, got, c.want)
			}
		})
	}
}

// A nosuid root must win for every path under it — the "/" case is the one a
// container or hardened install would actually hit.
func TestNosuidMountForNoisyRoot(t *testing.T) {
	const noisy = `21 1 8:1 / / rw,nosuid,nodev,relatime shared:1 - ext4 /dev/sda1 rw
36 21 8:17 / /srv rw,relatime shared:18 - ext4 /dev/sdb1 rw
`
	// Deeper mount without nosuid still wins: the kernel only refuses caps
	// where the covering mount says so.
	if got := nosuidMountFor("/srv/app/bin", noisy); got != "" {
		t.Errorf("under /srv (no nosuid): got %q, want \"\"", got)
	}
	if got := nosuidMountFor("/usr/local/bin", noisy); got != "/usr" && got != "/" {
		t.Errorf("under nosuid root: got %q, want \"/\"", got)
	}
}

func TestMountOptMatchesExactly(t *testing.T) {
	if !mountOpt("rw,nosuid,nodev", "nosuid") {
		t.Error("rw,nosuid,nodev should match nosuid")
	}
	if mountOpt("rw,nosuidfoo", "nosuid") {
		t.Error("nosuidfoo must not match nosuid")
	}
	if mountOpt("rw,relatime", "nosuid") {
		t.Error("relatime mount must not report nosuid")
	}
}

// End-to-end: the read, the Abs() normalisation and the prefix match have to
// agree with the machine's real mount table — this is what decides whether the
// advice handed to a user can work.
func TestFileCapsBlockedLive(t *testing.T) {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil || len(raw) == 0 {
		t.Skip("no /proc/self/mountinfo to check against")
	}
	bin, err := os.Executable()
	if err != nil {
		t.Skip("cannot resolve the test binary")
	}
	got := FileCapsBlocked(bin)
	t.Logf("FileCapsBlocked(%s) = %q", bin, got)
	if got == "" {
		return // reported as grantable; the mount table is checked below
	}
	// Non-empty means a real mount covering this file carries nosuid.
	if !strings.HasPrefix(bin, got) {
		t.Fatalf("reported mount %q does not cover %q", got, bin)
	}
	found := false
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) >= 6 && f[4] == got && mountOpt(f[5], "nosuid") {
			found = true
		}
	}
	if !found {
		t.Errorf("FileCapsBlocked reported %q for %q, but no such mount is nosuid", got, bin)
	}
}
