#!/usr/bin/env bash
# NetDash build: frontend (Vite) -> embed -> Go binary.
#   ./build.sh                 # build for this OS/arch -> bin/netdash
set -euo pipefail
cd "$(dirname "$0")"

command -v npm >/dev/null || { echo "npm not found"; exit 1; }
GO="${GO:-go}"
command -v "$GO" >/dev/null || GO="$HOME/.local/bin/go"

echo "==> frontend"
(cd web && npm install --silent && npm run build)
# The embedded UI is internal/api/dist (see //go:embed in internal/api/api.go).
# This copy is the single source of truth for keeping it in sync with web/dist,
# so never ship a frontend build without running this step (a stale copy here
# silently serves an old UI).
rm -rf internal/api/dist
mkdir -p internal/api/dist
cp -r web/dist/* internal/api/dist/

echo "==> backend"
"$GO" vet ./...
# Linux-only by design: the raw-socket packages (arpblock, dhcp, netinfo,
# scan) have no non-Linux implementation, so cross-compiling elsewhere cannot
# succeed — build for this OS only.
mkdir -p bin
out="bin/netdash"
echo "==> $("$GO" env GOOS) -> $out"
"$GO" build -trimpath -ldflags "-s -w" -o "$out" ./cmd/netdash
echo "done."
