#!/usr/bin/env bash
# NetDash build: frontend (Vite) -> embed -> Go binary.
#   ./build.sh                 # build for this OS/arch -> bin/netdash
#   ./build.sh linux windows   # cross-compile listed targets -> bin/netdash-<os>
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
targets=("$@")
if [ ${#targets[@]} -eq 0 ]; then
  targets=("$(go env GOOS)")
fi
mkdir -p bin
for t in "${targets[@]}"; do
  out="bin/netdash"
  if [ "$t" != "$(go env GOOS)" ] || [ ${#targets[@]} -gt 1 ]; then out="bin/netdash-$t"; fi
  if [ "$t" = "windows" ]; then out="$out.exe"; fi
  echo "==> $t -> $out"
  GOOS="$t" GOARCH=amd64 "$GO" build -trimpath -ldflags "-s -w" -o "$out" ./cmd/netdash
done
echo "done."
