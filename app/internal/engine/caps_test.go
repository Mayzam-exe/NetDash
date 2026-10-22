package engine

import (
	"strings"
	"testing"
)

// The advice has to name the exact command, and has to carry the step that the
// bare "run setcap" left out — a grant made while the process runs reaches
// nothing until it restarts.
func TestRawPacketAdviceNamesCommandAndRestart(t *testing.T) {
	bin := "/usr/local/lib/netdash/netdash"
	got := rawPacketAdvice(bin, "")

	if !strings.Contains(got, "sudo setcap cap_net_raw,cap_net_admin+ep "+bin) {
		t.Errorf("must hand over the exact command for %s, got %q", bin, got)
	}
	if !strings.Contains(got, "restart") {
		t.Errorf("must say the service has to restart, got %q", got)
	}
}

// The trap that motivated this: on a nosuid mount setcap succeeds, getcap shows
// the capabilities, and the process still receives none. Telling the user to
// run the command that just failed for them is the one thing advice must not do.
func TestRawPacketAdviceRefusesFutileSetcap(t *testing.T) {
	bin := "/mnt/usb/Projects/netdash/run/netdash"
	got := rawPacketAdvice(bin, "/mnt/usb")

	for _, want := range []string{"/mnt/usb", "nosuid", "grants nothing", "/usr/local/lib/netdash"} {
		if !strings.Contains(got, want) {
			t.Errorf("advice missing %q: %q", want, got)
		}
	}
	if strings.Contains(got, "sudo setcap") {
		t.Errorf("must not offer setcap on a mount that ignores it: %q", got)
	}
	if !strings.Contains(got, bin) {
		t.Errorf("must name the binary it is talking about: %q", got)
	}
}
