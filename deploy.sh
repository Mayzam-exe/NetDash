#!/bin/sh
# NetDash deploy: build → stop → copy → re-grant caps → start.
# Uses the sudoers rule from grantcaps.sh (passwordless); falls back to a
# prompt if it is missing.
set -e
cd "$(dirname "$0")"
export PATH="$HOME/.local/bin:$PATH"

./app/build.sh linux

have_svc=0
if systemctl --user cat netdash.service >/dev/null 2>&1; then
  have_svc=1
  systemctl --user stop netdash.service
else
  pkill -x netdash || true
  sleep 1
fi

# Dev copy for running the binary by hand. It cannot hold capabilities — the
# project volume is mounted nosuid, where the kernel ignores them — so the
# grant goes to the /usr/local copy that grantcaps.sh installs below.
cp app/bin/netdash run/netdash

if ! sudo -n ./grantcaps.sh; then
  echo "Password needed to grant capabilities:"
  sudo ./grantcaps.sh
fi

mkdir -p data /tmp/opencode
if [ "$have_svc" = 1 ]; then
  systemctl --user start netdash.service
else
  # No service: prefer the granted copy, which is the only one that can block.
  RUNBIN=/usr/local/lib/netdash/netdash
  [ -x "$RUNBIN" ] || RUNBIN="$PWD/run/netdash"
  setsid -f "$RUNBIN" -addr 127.0.0.1:7420 -data "$PWD/data" \
    > /tmp/opencode/netdash.log 2>&1 < /dev/null
fi
sleep 6
curl -s -m5 http://127.0.0.1:7420/api/status | grep -o '"blocking":"[^"]*"'
