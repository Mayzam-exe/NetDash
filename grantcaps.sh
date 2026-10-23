#!/bin/sh
# Root helper: install NetDash where file capabilities actually apply, grant
# them, install the user unit, and restart the service so the new process
# receives the grant.
#
# Run: sudo ./grantcaps.sh   (or: sudo -n ./grantcaps.sh)
#
# Why this installs somewhere else instead of just running setcap
# ---------------------------------------------------------------
# Two silent properties of file capabilities turned "run setcap" into a dead
# end — a command that changes nothing when you run it:
#
#   * the kernel ignores the grant entirely on a nosuid mount — setcap still
#     exits 0 and getcap still reports the capabilities, and the process still
#     receives none. The project lives on removable media, which is mounted
#     nosuid;
#   * capabilities are read only when a process starts, so a service already
#     running keeps its old (empty) set until it is restarted.
#
# So: install a root-owned copy under /usr/local (on /, which is not nosuid),
# grant there, refresh the unit, restart. The copy is root-owned on purpose —
# a user-writable binary carrying file capabilities hands cap_net_raw and
# cap_net_admin to anything running as that user, with no password check.
#
# Paths come from this script's own location rather than being hardcoded, so
# moving the project does not silently break capability granting.
#
# NOTE: on first root run this file is chown'd to root (self-protect, because
# it is passwordlessly root-running). To change it later: sudo install -m 755.
set -e
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
SRC="$HERE/app/bin/netdash"
DESTDIR=/usr/local/lib/netdash
DEST="$DESTDIR/netdash"
UNIT_SRC="$HERE/netdash.service"
SUDOERS=/etc/sudoers.d/netdash
U=${SUDO_USER:-$(id -un)}
USER_HOME=$(getent passwd "$U" | cut -d: -f6)
RUNDIR=/run/user/$(id -u "$U")

[ -x "$SRC" ] || { echo "no build at $SRC — run app/build.sh first" >&2; exit 1; }

install -d -o root -g root -m 0755 "$DESTDIR"
install -o root -g root -m 0755 "$SRC" "$DEST"
# netdash's own grant. The ARP bridge opens raw sockets in-process (raw), and
# the link work -- setting the MTU, bouncing the radio -- changes interface
# state in-process (admin). Both run as ordinary syscalls, where the
# capability this process holds applies directly.
/usr/sbin/setcap cap_net_raw,cap_net_admin+ep "$DEST" || exit 1
/usr/sbin/setcap cap_net_raw+ep /usr/sbin/tcpdump || exit 1

# The helper gets a grant of its own, because netdash's does not reach it.
# File capabilities are applied by execve to the file being executed and are
# not inherited: running /usr/bin/nft starts nft with an empty set, so every
# firewall call from the service fails with the kernel's
# bare "Operation not permitted" -- while in-process raw sockets keep working,
# which is what hides the cause. Two escapes exist and neither is available
# here: raising the ambient set needs CAP_SETPCAP, which this kernel refuses
# even for a process holding every capability, and systemd --user holds no
# privilege to do it on the service's behalf (the unit exits 218/CAPABILITIES).
# A file capability, by contrast, needs no privilege at run time: it applies to
# whatever file is executed, so an unprivileged parent can spawn a helper that
# carries its own cap_net_admin. So install that copy here.
HELPERS="$DESTDIR/helpers"
install -d -o root -g root -m 0755 "$HELPERS"
#
# ip(8) is deliberately not installed here: it does not retain a file
# capability on exec (CapPrm reads zero after exec even with a correct xattr,
# while nft keeps its grant), so a capped copy would be a grant that does
# nothing. tc(8) is no longer installed: the traffic-shaping feature that
# needed it was removed. Drop anything a previous install put here that this
# set no longer includes, so a helper cannot linger as an executable that
# looks authoritative.
rm -f "$HELPERS/ip" "$HELPERS/tc"
for TOOL in nft; do
  if ! SRC_TOOL=$(command -v "$TOOL"); then
    # Not installed: leave no copy of a helper that is gone.
    rm -f "$HELPERS/$TOOL"
    continue
  fi
  install -o root -g root -m 0755 "$SRC_TOOL" "$HELPERS/$TOOL" || exit 1
  /usr/sbin/setcap cap_net_admin=ep "$HELPERS/$TOOL" || exit 1
done

# The project copy must not keep a grant: it sits on a nosuid mount where the
# capabilities do nothing, and it is user-writable, so a stale grant there would
# go live the moment that file reached a filesystem with suid — a preserving
# copy, or the volume remounted. Clear it rather than leave that trap.
/usr/sbin/setcap -r "$HERE/run/netdash" 2>/dev/null || true

# Passwordless root for *this* script only, at its resolved path. Because the
# rule is path-based, keep this file on trusted storage — anyone able to write
# here can make you run code as root without a password.
printf '%s\n' "$U ALL=(root) NOPASSWD: $HERE/grantcaps.sh" > "$SUDOERS"
chmod 0440 "$SUDOERS"

if [ "$(id -u)" = "0" ] && [ "$(stat -c %u "$0")" != "0" ]; then
  chown root:root "$0" && chmod 0755 "$0"
  echo "grantcaps.sh is now root-owned"
fi
if [ -x /usr/sbin/getcap ]; then
  /usr/sbin/getcap "$DEST"
else
  echo "installed $DEST"
fi

# Point the service at the installed copy, then restart it: the grant is only
# read when a process starts, so the running service still has none.
UNIT_OK=1
if [ -f "$UNIT_SRC" ] && [ -n "$USER_HOME" ] && [ -d "$USER_HOME" ]; then
  sudo -u "$U" install -d -m 0755 "$USER_HOME/.config/systemd/user" &&
    sudo -u "$U" install -m 644 "$UNIT_SRC" "$USER_HOME/.config/systemd/user/netdash.service" ||
    UNIT_OK=0
else
  UNIT_OK=0
fi

if [ "$UNIT_OK" != 1 ]; then
  echo "warning: could not install the unit from $UNIT_SRC; service left as-is" >&2
  exit 0
fi
if [ ! -S "$RUNDIR/systemd/private" ]; then
  echo "no user manager for $U; run this as $U:" >&2
  echo "  systemctl --user daemon-reload && systemctl --user restart netdash.service" >&2
  exit 0
fi
if sudo -u "$U" XDG_RUNTIME_DIR="$RUNDIR" systemctl --user daemon-reload &&
  sudo -u "$U" XDG_RUNTIME_DIR="$RUNDIR" systemctl --user restart netdash.service; then
  echo "service restarted as $U — running $DEST"
else
  echo "warning: could not restart the service; run this as $U:" >&2
  echo "  systemctl --user daemon-reload && systemctl --user restart netdash.service" >&2
fi
