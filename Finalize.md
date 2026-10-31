# NetDash — Project Finalization

Everything this project is, every change made to it end to end, everything that
was fixed, and everything that is still open. Read this first to know the state
of the build.

- **Branch:** `master` · **Commits:** 14 · **Last:** `1d221ce feat: Clear all alerts button`
- **Runtime:** `127.0.0.1:7420` · service `/usr/local/lib/netdash/netdash` · data `./data`
- **Host:** gateway `192.168.1.1`, this machine sits *behind* the gateway
- **Size:** ~12.2k lines Go (32 files + 25 test files) · ~5.9k lines web (TS/TSX/CSS)
- **Bundles:** CSS 44.7 kB · JS 109.9 kB · **zero webfonts, zero external assets**
- **Tests:** 12 of 17 Go packages carry tests, all green

---

## 1. What NetDash is

A self-hosted home-network dashboard in **one Go binary**: it discovers every
device on the LAN (ARP sweep, ICMP, mDNS, SNMP, vendor OUI), identifies them,
charts host throughput, keeps an alert log, and can actively **block a device's
internet** — plus per-device controls (block, watch, priority, speed caps,
schedules, spoof rules), a device dossier with diagnostics/terminal, an
interactive network map, and command palette (cmdk).

The UI is themed as a **2D cyber deck** — a game-HUD layered over the NEON GRID
cyber-indigo theme, entirely from a single `tokens.css` override layer.

---

## 2. Architecture

### Backend (Go)

| Package | Responsibility |
|---|---|
| `cmd/netdash` | entrypoint, wiring, service lifecycle |
| `internal/engine` | core loop: discovery, state machine, alerts, lockdown, schedules, bandwidth metrics, SSE publishing |
| `internal/store` | SQLite persistence: devices, alerts (30-day retention), intel, spoof rules, scans, settings + schema migrations |
| `internal/api` | REST endpoints + `/api/stream` SSE (bearer-token protected) |
| `internal/arpblock` | ARP-poisoning enforcement — how lockdown/block actually work behind a gateway |
| `internal/firewall` | nftables path via a **capped helper** (full nft only ships in gateway mode) |
| `internal/discover`, `scan`, `probe`, `ident`, `intel`, `mdns`, `snmp`, `netinfo`, `vendor`, `model`, `helper` | sweeps, probes, fingerprints, vendor OUI, mDNS names, SNMP, data model |

Engine state flows one way: engine → `Snapshot()` → SSE → frontend. Alerts are
born in `AddAlert` (SQLite insert + in-memory prepend, capped at 30,
`publishNow()` pushes every subscriber fresh state).

### Frontend (TypeScript + Preact/signals, Vite)

- `main.ts` — routing, full `render()` vs `updateLiveDom()` (SSE `render(true)`
  preserves scroll and never replays entrance animation), one click-delegation
  switch (`data-action=…`) shared by string views and the Preact alerts app.
- `state.ts` — single source of truth (`displayState`, `counts()`,
  `unreadAlerts()`, client-side `readIds`).
- `views/` — `dashboard`, `devices`, `device` (dossier), `deck` (Agent Deck,
  operative sprite `FIG`), `settings`, `alerts.app.tsx` (Preact pilot),
  `alerts.ts` (legacy string view — now orphaned, tree-shakes to nothing).
- `signals.ts` — `alertsSig`, `alertFilterSig`, `snapshotTick`, `uiTick` let the
  Preact view re-render itself without innerHTML replacement.
- `lib/ui.ts` — toasts, modals, body-appended context menu (immune to card
  clip-paths), `ICONS`, `sigHtml`.
- `lib/atlas.ts` — canvas network map.

### Theme layering (the key frontend rule)

1. `style.css` — **legacy component kit, intentionally untouched.** Old
   colors/radii live here and are *overridden*, not edited.
2. `tokens.css` — NEON GRID tokens → cyber-deck component pass → DECKIFIED
   pass (~973 lines). Loaded **after** `style.css`, same specificity → wins.
3. Light theme via `:root[data-theme="light"]` overrides.

### Build → deploy → verify

```
app/web:  npx tsc --noEmit && npm run build   # vite → dist
./deploy.sh                                   # dist → app/internal/api/dist (git-tracked),
                                              # go build, install with
                                              # cap_net_admin,cap_net_raw=ep, restart service
```

- `grantcaps.sh` installs **only the capped `nft` helper** — no full-cap grants.
- **No browser in this environment.** Verification is `curl` + `grep` against
  `127.0.0.1:7420`; the human checks visually with **Ctrl+Shift+R** and sends
  screenshots.
- The CSS minifier merges identical rules and does **not** touch custom-property
  values (spaces survive) — greps must expect merged selector lists and
  `rgba(r, g, b, .a)` spacing. (A `--grid: 0` scare earlier was exactly this
  grep artifact, not a bug.)
- Setcap work: `/tmp` is **nosuid** — use `/var/tmp`. Sudo password (machine-local, kept out of record),
  re-prime per shell (`printf '%s\n' '<local-sudo-password>' | sudo -S -p '' -v`).

---

## 3. The story, commit by commit

| # | Commit | What landed |
|---|---|---|
| 1 | `4ac8d18` **Initial commit** | NetDash core: dashboard, device roster + dossier, charts, alerts, block/watch/priority/schedule controls, spoof rules, map, cmdk — plus the analysis-driven fixes recorded in ANALYSIS.md. |
| 2 | `6a2ea83` docs | README security section + ANALYSIS resolution log (kept as the historical record of findings → resolutions). |
| 3 | `e3d232f` redesign Phase 0 | Design tokens + Preact/signals foundation; **Alerts pilot view** (the first Preact view, proving the hybrid render model). |
| 4 | `76e791f` redesign Phase 4 a11y | Mobile bottom-nav tier, skip link, touch targets, `aria-current`, contextual live badge. |
| 5 | `d654043` redesign Phase 4 semantics | `tablist/tabpanel`, cmdk combobox pattern, skip-link focus target. |
| 6 | `54a8b77` **Lockdown** | The headline feature (deep-dive below): block internet for every device except this machine, the router, and Trusted devices — **refusing the toggle when it cannot be enforced**. Honest capability reporting, stale self-row fix, capped nft helper, binary caps. |
| 7 | `c213ce0` lock UI | Lockdown becomes a **slide switch**, not a tick box. |
| 8 | `6aedf24` QoS removal | **QoS removed permanently** — never reappear (product decision, honored since). |
| 9 | `ca637a9` **NEON GRID** | Brass & Ember replaced by the cyber-indigo HUD theme: one `tokens.css` override layer, blueprint grid, crimson = blocked everywhere (deck sprite, table legend dot, dossier pill). |
| 10 | `2d43ca6` **Agent Deck** | `views/deck.ts`: the dashboard crew strip — every device as a mini operative (sprite `FIG`, HP bar, rank) — button-native, opens the dossier through the same delegation. `.view.enter` entrance animation gated to navigation only. |
| 11 | `ba71df0` deck everywhere | The 2D deck reaches every screen: roster status dot → mini operative sprite, dossier header → state-colored operative badge with antenna blink, HUD buttons/chips/inputs, ~260-line component pass (mono uppercase nav, overlays, alert rails, toasts, readouts). |
| 12 | `8e91d51` **deckified + slim dashboard** | The loud pass (deep-dive below) **and** dashboard surgery: the Devices and Alerts docks removed. |
| 13 | `4c7246a` chore | Tracked UI bundle re-synced (dist is committed alongside source). |
| 14 | `1d221ce` **Clear all alerts** | End-to-end alert wipe (deep-dive below). |
| 15 | `c9ecbdf` **Timed block** | Block with expiry: `block_until` column, `{blocked:true, blockUntil:N}` patch semantics, 30 s reaper inside the schedule loop, dossier `1h/4h/12h` chips and a `releases HH:MM` chip. |
| 16 | `ffa3551` **DHCP hostnames + gateway probe** | Passive DHCP sniffer (any router, live hostnames → name fill + Intel) and the honest SNMP capability probe that decides whether a per-client Signal column can ever be shown (deep-dive below). |
| 17 | `2d6246f` `89b027a` `5791636` **Ponytail audit** | Whole-repo dead-code removal (report in the audit): legacy alerts view,4 dead components, ~150 lines orphan CSS, `SetBlocked`/`parseARPLine`/`Store.Dir`/`Link.IfName`, over-exported helpers, `legacy/` prototypes, broken windows build target, ~59 MB regenerable binaries. One hunter false-positive rejected (write-only signals are the live `snapshotTick` change-detector). |

---

## 4. Feature deep-dives

### 4.1 Lockdown (the security feature)

**Goal:** block internet for *every* device on the LAN **except** this machine,
the router, and devices marked **Trusted** — and **refuse the toggle when it
can't actually be enforced**.

- This host sits *behind* `192.168.1.1`, so gateway traffic never crosses it and
  nftables has nothing to intercept. Enforcement therefore rides **ARP poisoning**
  (`internal/arpblock`): non-trusted devices get the WAN blackholed while the
  router and this machine keep working.
- The UI is honest about capability: status reports
  `firewall: unavailable: behind gateway 192.168.1.1 — traffic does not cross
  this host` (designed state, not an error) and
  `blocking: active (arp poisoning)` when engaged.
- **Refusal path:** if no enforcement path exists, the API refuses and the
  settings slide-switch **snaps back** with a toast — the toggle never lies.
- Persistence rides the same settings JSON blob; devices carry a `trusted`
  column added by **schema migration** (pre-existing rows come back untrusted,
  never silently exempt).
- Engaging/releasing raises alerts (covered by `lockdown_test.go`, including
  refusal and trusted-device behavior).
- Binary runs with `cap_net_admin,cap_net_raw=ep`; `grantcaps.sh` installs only
  the capped nft helper.

### 4.2 Alerts lifecycle

- **Birth:** engine conditions call `fireAlert(key, …, cooldown)` — dedupe map
  prevents the same condition spamming; `AddAlert` inserts to SQLite (30-day
  retention prune) and prepends to the 30-row in-memory snapshot.
- **Read:** Dismiss/Open-device → `POST /api/alerts/{id}/ack` + client
  `readIds`; filters (All/Critical/Warning/Info) live in `alertFilterSig`.
- **Clear all (new in `1d221ce`):** one button in the Alerts toolbar —

  ```
  click → data-action=clear-alerts
        → state.readIds.clear()          (store may reuse ids once rows are gone)
        → POST /api/alerts/clear
        → store: DELETE FROM alerts      (survives restart)
        → engine.ClearAlerts() under e.mu → publishNow()
        → SSE repaints every view (list, KPI badge, nav badge) → toast
  ```

  The `fireAlert` dedupe map deliberately **survives** the wipe, so clearing
  can't be used to replay stale conditions on cooldown. `TestClearAlerts`
  covers the store wipe; the route coexists with `{id}/ack` (3 vs 4 path
  segments — no ServeMux conflict).

### 4.3 The 2D Cyber Deck design system

**Lineage:** cyber game dashboard → data-dense instrument output → **NEON GRID**
cyber-indigo HUD → the full **deckified** game-deck layer the user asked for
("each and everything like a 2D Cyber deck system" — across the *entire* app,
not just the dashboard).

What it consists of:

- **Plates:** every card/panel is an angular cut-corner plate — `radius: 0`
  plus a shared **16 px top-right notch** (same geometry the hero KPI
  pioneered), glowing frames with accent-tinted borders and faint halos.
- **Scanlines:** one global CRT veil (`body::after`, z-999, theme-aware via
  `--text`) — deliberately *the only* scanline layer (per-card copies removed).
- **Grid:** blueprint grid punched to `rgba(103,178,255,.09)` @ 40 px (dark) /
  `rgba(37,99,235,.09)` (light) — visible on both themes.
- **KPI gutters:** blue circuit gutters through the KPI strip; accent rules on
  table cells/heads; uppercase **silkscreen** legends (mono, tracked) on
  tbl-foot, sum labels, map legend, chart chrome.
- **Square HUD controls:** buttons, chips, inputs, badges, tabs — square,
  glowing focus/caret, overlay auras — never rounded, never glass
  (`backdrop-filter: none` on the map HUD; depth = fill + border + glow).
- **Sprites:** `FIG` operative figure reused as roster `.op-mini` (per-state
  color) and dossier `.op-badge` (antenna blink), HP bars, ranks, status dots —
  crimson is blocked-state everywhere (sprite, legend dot, pill).
- **Motion:** entrance choreography runs only on route change
  (`.view.enter`, delays 0→440 ms); the ~5 s SSE snapshot rebuilds data without
  ever replaying it.

### 4.4 Dashboard slimming (the `8e91d51` surgery)

The dashboard originally stacked: KPIs → Agent Deck → Bandwidth → **Devices
dock + Alerts dock**. The deck's height crushed `.dash-body` (flex, min-height
0) until `.tbl-scroll` collapsed to **zero rows** — the toolbar and legend were
glued together with no table between (visible in a user screenshot).

Fix = removal: the Agent Deck *is* the dashboard's roster (click → dossier), the
full table lives on `/devices`, the log on `/alerts`. Dashboard now reads
**KPI strip → Agent Deck → Bandwidth scope**. Dead code left with it:
`dash-body` entrance rule, `.alert-item` rails, and the legacy `alerts.ts`
module lost its last importer (tree-shaken to zero bytes).

### 4.5 DHCP hostnames + the honest gateway probe

The user picked **Wi-Fi signal / DHCP** next, under the project's honesty
rule (never render a metric the engine can't truly know) — so it shipped
probe-first.

**Passive DHCP sniffer** (`internal/dhcp`): a receive-only AF_PACKET socket
on the LAN interface (same proven pattern as the ARP blocker's
`socket_linux.go`, 500 ms recv timeout so the loop keeps checking its stop
flag) parses every DHCP DISCOVER/REQUEST/ACK broadcast — Ethernet (+ one
802.1Q tag) → IPv4 → UDP 67/68 → BOOTP + options (53 message type, 12 host
name, 50 requested IP). Broadcasts are flooded to every switch port, so
client *joins* are always visible without promiscuous mode; unicast renewals
are simply missed (PTR/mDNS still cover those). `observeDHCP` matches the
frame's `chaddr` to a device **by MAC**: a hostname fills a placeholder name
(`""` or `"Device <ip>"`) under the same policy as `resolveNameAsync`,
re-infers kind unless manually pinned, and lands in the Intel tab as kind
`dhcp` — a user-set name always wins. Proven live end-to-end: a crafted
DISCOVER (MAC `f2:f5:b7:63:31:91`, hostname `sniff-test-handset`) renamed
offline device 3065 and wrote the intel row within one poll tick; the name
was then restored.

**SNMP gateway probe** (`snmp.Probe` → `engine.ProbeRouter` →
`POST /api/gateway/probe`, "Probe router" button in Settings → Monitoring):
one click reports what the router actually exposes — sysName/sysDescr, the
interface list, and a best-effort walk over vendor station-signal MIB
candidates (MikroTik, UniFi, Huawei AC, IEEE 802.11 presence checks).
`reachable` is true only when an agent genuinely answered; a silent host or
wrong community reports `no SNMP response — wrong community, wrong host, or
agent disabled` (UDP "connect" alone proves nothing — first cut got that
wrong and was fixed before ship). The probe's answer is the gate for a
per-client Signal column: until a router exposes station RSSI, Signal stays
unset.

---

## 5. Everything that was fixed

1. **Stale self-row** — the host's own row could persist stale; fixed in
   `54a8b77`.
2. **Offline-alert noise** — unknown→offline stays silent, online→offline still
   alerts (`self_test.go`).
3. **Alerts were never deleted** — added 30-day retention prune
   (`TestAlertsRetention`).
4. **Lockdown honesty** — no silent "protected" state: refusal + snap-back when
   unenforceable; `unavailable` is an explained, designed status.
5. **Trusted migration** — old databases gain `trusted` via migration;
   pre-existing devices come back *untrusted* (`TestTrustedColumnMigrates…`).
6. **QoS** — removed permanently per product decision (`6aedf24`).
7. **Entrance animation replaying every SSE tick** — gated to navigation
   (`.view.enter` only when `!preserveScroll`).
8. **Alerts inline `border-radius:12px`** beating the theme's radius-0 — inline
   style trimmed; Preact rows use themed `.btn`/`.chip`.
9. **Redundant scanline/clip rules** — `.term`'s own scanlines and the
   standalone `.deck` clip removed (global veil / merged `.card` clip cover
   them).
10. **Crushed dashboard table** — root-caused and removed with the docks
    (§4.4).
11. **`--grid` "disappearing" scare** — proven to be a grep artifact (minifier
    preserves custom-property whitespace); cascade verified: tokens load after
    style.css → ours win in both themes.
12. **Alert-id reuse poisoning** — `readIds.clear()` on wipe so a reused SQLite
    id can't render a fresh alert as already-dismissed.
13. **Last `ICONS` consumer removed** — dossier badge uses the sprite; icons
    tree-shake out.
14. **Map HUD glass** — `backdrop-filter` dropped (deck rule: no glass; map HUD
    goes solid plate).

---

## 6. Quality gates (all currently green)

- `npx tsc --noEmit` — clean.
- `go build ./... && go test ./...` — **12/12 test packages ok** (api, arpblock,
  engine, firewall, helper, ident, intel, mdns, model, netinfo, scan, store).
- Live: `/api/status` → `ok:true`, `blocking: active (arp poisoning)`,
  `/api/alerts` → `[]`, connectivity probe → 204.
- Bundle verified for every feature: presence greps for new endpoints/labels,
  absence greps for removed code.

---

## 7. Known issues / open flags (honest ledger)

1. **World-executable raw-cap binaries** — `/usr/bin/tcpdump` and
   `/usr/sbin/tcpdump` carry `cap_net_raw=ep` for *any* local user. Pre-existing
   hardening gap; not touched yet.
2. **`Reserved` is UI-only** — the flag persists but no router reservation is
   actually created (needs router-side integration or removal).
3. **Factory reset** — reports "not available yet".
4. **Gateway-mode speed caps** (`engine.go` ~1212) — per-device speed caps only
   bite in gateway mode; behind-gateway ARP mode can't shape traffic.
5. **Tick boxes vs switches** — `gSnmp` and `dnTrusted`/`dnWatched` are still
   plain tick boxes while lockdown became a slide switch; consistency decision
   pending.
6. **Map canvas not deckified** — atlas nodes/packets are drawn in JS; the map
   HUD frame is themed but the canvas dots aren't (last deckification
   frontier).
7. **No UI login** — the backend stream is bearer-token protected but there is
   no login flow in the UI yet.
8. **Station RSSI is detectable, not consumed** — the gateway probe reports
   whether the router exposes a station-signal MIB, but nothing maps its
   values to per-device `Signal` yet; that plumbing lands when a router in
   the wild actually answers (`snmp.rssiCandidates` holds the best-effort
   candidate list).

## 8. Next up (feature queue, in the user's order)

1. ~~Per-client Wi-Fi signal~~ — shipped probe-first (`ffa3551`): the gateway
   probe reports whether the router exposes a station-signal MIB; Signal
   stays honest (unset) until one does, then map values → `Device.Signal`.
2. ~~Real DHCP lease data~~ — shipped (`ffa3551`): passive DHCP sniffer —
   live hostnames from broadcasts, no lease-file dependency, any router.
3. **Real link speed/duplex** — currently not read from the NIC.
4. **UI login flow** — wire the existing backend bearer auth to a login screen.
5. Optional polish: stretch the bandwidth scope into the dashboard's bottom
   floor (chart canvas is fixed-height — needs a deliberate resize), uppercase
   chart legend to match silkscreen.

## 9. Conduct rules that held (for future sessions)

> "Don't make anything too much over which slows the project. Build clean,
> don't get confused, build like it's routine. **Don't break the already-made
> NetDash system logic.**"

- **Layers, not rewrites:** theming lives in `tokens.css`; `style.css` stays
  untouched; every feature is additive.
- **One concept per commit**; the tracked `dist/` is re-synced with its source.
- **Zero external assets** — system font stacks only, offline single binary.
- **QoS never reappears.**
- **Don't trust a grep** until you know how the minifier wrote it; verify live
  with curl before claiming done.
