#!/bin/sh
# Root helper: grant NetDash its packet capabilities, cap tcpdump for
# diagnostics, and install the passwordless sudoers rule for future deploys.
# Run: sudo ./grantcaps.sh   (or: sudo -n ./grantcaps.sh)
# NOTE: on first root run this file is chown'd to root (self-protect, because
# it is passwordlessly root-runnable). To change it later: sudo install -m 755.
/usr/sbin/setcap cap_net_raw,cap_net_admin+ep /home/maxim/Projects/netdash/run/netdash || exit 1
/usr/sbin/setcap cap_net_raw+ep /usr/sbin/tcpdump || exit 1
printf '%s\n' 'maxim ALL=(root) NOPASSWD: /home/maxim/Projects/netdash/grantcaps.sh' > /etc/sudoers.d/netdash
chmod 0440 /etc/sudoers.d/netdash
if [ "$(id -u)" = "0" ] && [ "$(stat -c %u "$0")" != "0" ]; then
  chown root:root "$0" && chmod 0755 "$0"
  echo "grantcaps.sh is now root-owned"
fi
echo "caps granted, sudoers rule installed"
