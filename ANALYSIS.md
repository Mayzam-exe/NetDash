# NetDash — Deep Analysis

*Static analysis of the NetDash source tree, `go vet`, `go test`, `go test -race`,
`tsc --noEmit`, and one targeted race-detector probe (removed after use).*

> **Status — all findings addressed.** The fixes are grouped into 14 parts:
>
> 1. `publishNow` now takes the **write** lock (fixes the proven `e.status` race).
> 2. `scheduleLoop` snapshots `settings.GatewayIP` under the lock.
> 3. `tick()` collects offline transitions and fires alerts *after* unlocking
>    (no more mid-iteration unlock).
> 4. Settings page marks client-only controls **reference only** with an honest
>    banner + save toast.
> 5. Fabricated device facts (`LAN 3 · 1 Gbps`, `Cat6`, `Full`, `Living Room AP`,
>    `18h left`) removed.
> 6. README false claims corrected (per-client signal, QoS, reservations,
>    peak-since-start).
> 7. QoS/Reservation UI copy now states they are stored, not enforced.
> 8. Optional bearer auth (`-auth-token` / `NETDASH_AUTH_TOKEN`) with an exposure
>    warning; the SNMP community is no longer reachable without the token.
> 9. `withCORS` → `withSecurityHeaders` (CSP, X-Frame-Options, Referrer-Policy).
> 10. HTTP server read/write/idle timeouts (the SSE stream clears its own write
>     deadline so it is not cut off).
> 11. Argument-injection guards + `net.ParseIP` validation on settings and
>     `applyNetsh`.
> 12. `intelMemo` is pruned; the `alerts` table has 30-day retention.
> 13. Git repo initialised with `.gitignore`; legacy HTML moved to `legacy/`;
>     `HostPeakDown` labelled "since start"; dist-sync documented.
> 14. Residual `ip`/`mac` interpolations escaped; tests added for `api`, `store`
>     and `model`, plus an engine race-regression test (verified to trip `-race`
>     before the fix and pass after).
>
> Corrections to this document itself: the untested-package list was wrong
> (`mdns` and `netinfo` **do** have tests — 8 of 16 packages were untested, not
> 9 of 17), and a `.git` directory **did** exist (empty, with no commits).

---

## 1. Architecture

Single Go 1.27 binary + embedded Vite SPA. ~14.4k LOC total.

| Layer | Files | Notes |
|---|---|---|
| Entry | `cmd/netdash/main.go` | flags, `127.0.0.1:7420` default, embedded `dist` |
| HTTP | `internal/api/api.go` | one `HandleFunc` file, all routes, `esc()`-based escaping |
| State | `internal/engine/engine.go` (1784 L) | single `Engine` object behind one mutex; loops for probe/scrape/schedule/gw/intel/alert |
| Enforcement | `internal/arpblock/arpblock.go` (1002 L), `internal/firewall` | ARP `is-at` poisoning + token-bucket shaper + DNS spoof; nftables/netsh |
| Capture | `internal/discover`, `mdns`, `snmp`, `scan` | L2 neighbor ingest, mDNS, SNMPv2c bridge-mib/FDB, port scan |
| Persistence | `internal/store` | modernc SQLite, WAL, `MaxOpenConns(1)` |
| UI | `web/src` | hand-rolled string templates + `esc()`, SSE stream, no framework |

**Strengths.** Clear layering, no shell interpolation anywhere (`exec.Command` always argv),
nftables inputs guarded by `net.ParseIP`/`net.ParseMAC`, fail-open by design (a broken
firewall never takes the LAN down), no dependency bloat, all tests green,
`tsc --noEmit` green.

---

## 2. Correctness — the one *proven* bug

### Data race in `publishNow` / `Snapshot` (`engine.go:892-893` vs `943`)

`publishNow()` calls `recomputeStatusLocked()` while holding only `e.mu.RLock()`, but that
function writes `e.status`. `Snapshot()` reads it under the same `RLock`. Two readers, one
writer — the `Locked` suffix is a lie.

`go test -race` with a 2-iteration probe reproduced it immediately. The shipped test suite
never hits it because nothing exercises `publishNow` concurrently with `Snapshot`.

**Fix:** take `e.mu.Lock()` in `publishNow`, or split `status` into an `atomic.Pointer`.

### Second race — unsynchronized settings read (`engine.go:1638`)

`scheduleLoop` reads `e.settings.GatewayIP` at line 1638, *after* `e.mu.RUnlock()` at
line 1632, while `PutSettings` writes `e.settings` under `Lock` at line 1167.

The window is microseconds, so `-race` with 33 s of churn did not trip it — but it is a
genuine unsynchronized read.

### Third — mid-iteration unlock in `tick()` (~328-331)

Mutex-protected, so no detector finding, but `d` is a pointer held across the unlock:
stale write-back / lost update, and devices added during the gap are skipped for that tick.

### Fourth

`e.status.GatewayIP` is also written at `engine.go:341`.

---

## 3. The real problem: features that don't exist

The project's stated ethos (README) is *"says so instead of faking it."* Several places
do the opposite.

### 3a. The Settings page lies

`collectGlobalSettings()` (`settings.ts:171`) reads ~13 controls into `state.prefs`,
which is **client-only**. `saveSettings()` then calls `putSettings(state.settings)` —
prefs are never sent to the API and never reach the backend.

Controls that are **pure decoration** (edit → "Settings saved" → nothing happens):

- Connection type (DHCP / PPPoE / Static)
- DNS servers (Auto / Custom, both resolvers)
- 2.4 GHz & 5 GHz **channel and bandwidth**
- Security (WPA3 / WPA2)
- **Wi-Fi password** (default literal `hunter2secret`, `state.ts:96`)
- Guest network on/off
- DHCP range start/end
- Lease time

Hints are written as if live: *"Channel 1, 6 or 11 to avoid overlap"*,
*"WPA3 recommended"*.

Actually persisted / polled: WAN IP, both SSIDs, Router IP, the SNMP block.

These prefs survive only via `exportConfig()` → a local JSON file. The backend
`model.Settings` has no fields for any of them.

### 3b. Device overview prints fabricated facts

`web/src/views/device.ts:122-141`, rendered for every device, all hardcoded:

```
Interface      LAN 3 · 1 Gbps
Duplex         Full
Cable          Cat6
Access point   Living Room AP
DHCP           Dynamic · 18h left
```

Also `device.ts:77` `Link 1 Gbps full duplex` and `device.ts:102` `· 1 Gbps` in the
device sublines. No link speed, duplex, cable category or lease data is ever read from
anywhere.

### 3c. Two README claims are false

1. **"signal from SNMP neighbors"** (README:15) — `internal/snmp` contains no
   `dot11` / `rssi` / `signal` code at all. `d.Signal` is assigned in exactly one place,
   `engine.go:440`, inside `ensureSelf`. Every other device's `signal` is `null`, so the
   UI permanently shows *"the router does not report client Wi-Fi signal."*
2. **QoS priority** — `device.ts:395` promises *"High-priority devices get bandwidth first
   when the link is saturated."* `d.Priority` is written (`engine.go:1050`), read for
   display (`device.ts:161`), and read in `reprovision.go:136` to retain config across
   expiry. It is **never consumed by `arpblock` or `firewall`** — the token bucket has no
   priority notion, no nft rule references it.

   Same story for `Reserved`: it only prevents expiry, it does not create a DHCP
   reservation on the router despite the *"Reservations keep this address across
   reboots"* hint.

### 3d. Milder

- `factory-reset` shows a *"cannot be undone / Erase everything"* confirm modal, then
  toasts *"not available yet"* (`main.ts:590-597`). Honest outcome, alarming dialog.
- `fw-check` / `reboot` correctly report unavailability. Good.

---

## 4. Security

### No authentication whatsoever

No `Authorization`, no token, no middleware — grep across `internal/` and `cmd/` returns
nothing.

Mitigated by the `127.0.0.1` default, but `grantcaps.sh` + `netdash.service` +
`deploy.sh` exist precisely to run it *with* `cap_net_raw,cap_net_admin`.
`-addr 0.0.0.0` (the documented LAN-dashboard use case) then exposes block / schedule /
DHCP / radio / intel control to anyone on the LAN — **including `GET /api/settings`,
which serializes `model.Settings.SnmpCommunity`**, the read-only SNMPv2c community
string, i.e. the router's full neighbor/bridge table and WAN counters.

### `withCORS` is not CORS

`api.go` sets only `X-Content-Type-Options: nosniff`. No CORS, no CSP, no
`X-Frame-Options`, no HSTS.

CSRF is prevented only *accidentally* — mutating endpoints require JSON bodies, which
force a preflight that no CORS headers will approve. Rename the helper; it is not
setting CORS.

### HTTP server timeouts

Only `ReadHeaderTimeout` is set — no `ReadTimeout`, `WriteTimeout`, `IdleTimeout`.

### Argument injection (no shell)

- nftables paths are `ParseIP` / `ParseMAC` guarded.
- `applyNetsh` does **not** validate `e.IP`.
- `d.IP` / `d.Name` are passed as leading-`-`-capable argv to `ping`, `avahi-resolve`,
  `iw`.

**Fix:** `--` separator, or reject arguments matching `^-`.

### Input validation

- `Settings.GatewayIP` / `WANIP` are only checked non-empty (`api.go` PUT) — no
  `net.ParseIP`.
- Length caps on names/messages are present and sane.

### Privilege surface

`grantcaps.sh` installs a passwordless sudoers entry for itself and `chown root`s
itself. Expected for the design, but it is a standing privilege-escalation surface —
worth documenting explicitly.

### XSS

Escaping is consistently careful: `esc()` on device names, intel values, alert messages,
atlas tooltip, rail foot.

Residual raw interpolation of `d.ip` / `d.mac` into attributes (`device.ts:73-74`,
`ui.ts` cmdk, `openMenu`) — kernel/SNMP-derived, low risk, but should be `esc()`'d for
consistency.

---

## 5. Resource lifecycle

- **`e.intelMemo` unbounded** (`engine/intel.go:40-43`) — dedup map with no prune, one
  entry per unseen intel item, grows forever.
- **`alerts` table never deleted** — `store.go` has `DELETE FROM intel` (7-day
  retention) and `DELETE FROM devices`, but no `DELETE FROM alerts`. 2737 rows since
  Sep 27 (~100/day, ~36k/year). `alertKeep=30` is memory-only.
- **`e.mu` held across I/O** — `SetState` / burst writes (~40 ms per victim) and all
  SQLite writes run under the engine lock; `store` also serializes to a single
  connection.
- `status.HostPeakDown` never resets (peak-since-start). Probably intended; not
  labelled as such in the UI.

---

## 6. Ops / hygiene

- **No git repository** in the project directory at all.
- Legacy root `index.html` (1861 L) and `map.html` (1068 L) are stale prototype
  duplicates of the shipped UI — unused by the build, confusing to have in-tree.
- `app/bin/netdash-linux` (Sep 27) is stale vs `app/bin/netdash` / `run/netdash`
  (Oct 1).
- `app/internal/api/dist/index.html` correctly mirrors `app/web/dist/index.html`
  (both Oct 1) — but nothing enforces that; a frontend build without a backend rebuild
  silently ships stale UI.
- Live instance at time of analysis: PID 468,
  `run/netdash -addr 127.0.0.1:7420 -data ./data`,
  13 devices / 2008 intel rows / 2737 alerts, 4.1 MB `-wal` (right at SQLite's default
  1000-page checkpoint threshold).
- Tests: `go vet` clean, `go test ./...` clean, `go test -race ./...` clean,
  `tsc --noEmit` clean. **9 of 17 Go packages have no test files** — `api`, `store`,
  `snmp`, `discover`, `mdns`, `vendor`, `netinfo`, `probe`, `model` — including every
  HTTP handler and all SQL.

---

## Top 5, ranked

1. **Settings page silently discards 13 controls** (incl. Wi-Fi password) —
   user-facing deception against the project's own stated principle.
2. **No authentication** while shipping LAN-exposure tooling; `SnmpCommunity` readable
   unauthenticated.
3. **Proven data race** in `publishNow` / `recomputeStatusLocked` — fix by taking the
   write lock (plus the `scheduleLoop` unsynchronized read).
4. **Hardcoded fake facts** in device overview (`Living Room AP`, `Cat6`, `18h left`,
   `1 Gbps`).
5. **False README claims**: per-client signal from SNMP; QoS priority that is stored
   and displayed but never enforced.
