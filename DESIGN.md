# NetDash — Design Specification

A real-time network monitoring and device management dashboard for home / prosumer networks (single router + access points, 10–50 devices).

**Companion prototype:** `index.html` — single-file, dependency-free, runs in any modern browser on Linux or Windows.

---

## 1. Dashboard Layout & Information Hierarchy

### Design principle

Three depth levels, each answering one question:

| Level | Question it answers | Where it lives |
|---|---|---|
| **L0 — Health band** | "Is my network okay?" (3-second read) | Top of dashboard, always visible without scrolling |
| **L1 — Dashboard body** | "What's using it / what's wrong?" | Dashboard, below the fold if needed |
| **L2 — Device detail** | "What's going on with *this* device?" | Dedicated view, one click away |
| **L3 — Configuration** | "Change how things work" | Settings sections inside device detail + global Settings view |

Anything deeper than L0 must never sit on the dashboard. The dashboard is a *triage surface*, not a data dump.

### Spatial organization (dashboard)

```
┌──────────────────────────────────────────────────────────────────────┐
│ SIDEBAR   │  L0 HEALTH BAND (full width, never scrolls away)        │
│           │  [Internet ●] [Latency] [Down/Up Mbps] [Devices] [Alerts]│
│  Dashboard├──────────────────────────────────────────────────────────┤
│  Devices  │  L1 BODY                                                │
│  Alerts   │  ┌────────────────────────────────┐ ┌─────────────────┐  │
│  Settings │  │  DEVICE TABLE (≈65% width)     │ │ Bandwidth chart │  │
│           │  │  sort · filter · search        │ │ (live, 60s)     │  │
│           │  │  status name IP MAC type dBm ↓ │ ├─────────────────┤  │
│           │  │                                │ │ ALERT FEED      │  │
│           │  └────────────────────────────────┘ └─────────────────┘  │
└──────────────────────────────────────────────────────────────────────┘
```

- **Left rail (72–200 px):** persistent navigation — Dashboard, Devices, Alerts, Settings. Icons + labels; collapses to icons on narrow windows.
- **L0 band:** five fixed slots, left→right ordered by triage priority: internet status → latency → throughput → device count → alerts. Red/amber states expand the band with a one-line explanation.
- **Device table dominates** (65% width) because device inventory is the primary object of the product.
- **Right rail (35%):** live bandwidth chart on top (trend context), alert feed below (things needing action). Both are *supporting* context for what the table shows.

### What lives where

| Primary view (dashboard) | Secondary views |
|---|---|
| Internet health, latency, aggregate throughput | Per-device metrics (device detail) |
| Device count + online/warning/offline split | Per-device settings (device detail → Settings tab) |
| Full device table (name, IP, MAC, type, signal, throughput) | Global/network settings (Settings view) |
| Live bandwidth chart (aggregate) | Historical trends (Performance tab) |
| Alert feed | Troubleshooting tools (Troubleshoot tab) |

---

## 2. Component Breakdown

### 2.1 Network health pill
- **Data:** WAN state (up/down/degraded), last-checked timestamp.
- **Behavior:** green pill = online; red pill = offline with elapsed time; amber = degraded (packet loss or high latency). Click → runs simulated ping to 1.1.1.1 and updates.
- **Position:** first slot of L0 band.

### 2.2 KPI cards (L0 band)
Five compact cards:

| Card | Content | Warning threshold | Critical threshold |
|---|---|---|---|
| Internet | up/down pill + ISP gateway IP | loss > 1% | WAN down |
| Latency | ms to 1.1.1.1 + sparkline | > 60 ms | > 150 ms |
| Throughput | ↓ / ↑ Mbps live | — | — |
| Devices | online / total, split chips | — | — |
| Alerts | unresolved count | ≥ 1 amber | ≥ 1 red |

Each card: large number (24–28 px), small label (11 px uppercase), optional 60×20 sparkline. Clicking Devices/Alerts cards navigates to the corresponding view.

### 2.3 Device table
- **Columns:** status dot · name (with vendor + type subline) · IP · MAC · connection type (Wi-Fi 5 GHz / Wi-Fi 2.4 GHz / Ethernet) · signal (bar glyph + dBm) · live throughput (↓/↑) · quick actions (⋯).
- **Row height:** ~48 px — dense enough for 10+ devices above the fold.
- **Interactions:** click row → device detail; column headers → sort; search box filters name/IP/MAC live; connection-type chips filter (All / Wi-Fi / Wired / Offline).
- **IP and MAC:** monospace, click-to-copy (row flashes "copied").
- **Rows carry state:** warning rows get an amber left border; offline rows dim to 60% and show "Last seen 2h ago" under the name.

### 2.4 Live bandwidth chart
- Stacked area chart, down vs up, 60-second rolling window, 1-second sample rate (prototype) / 5-second (real deployment).
- Y-axis auto-scales to link speed (default cap 100 Mbps, configurable).
- Canvas-rendered, no libraries. Hover shows tooltip with sample values.

### 2.5 Alert feed
- Reverse-chronological list, severity icon + one-line message + relative time.
- Clicking an alert navigates to the affected device's **Troubleshoot** tab with the diagnostic pre-staged.
- Severities: `critical` (red), `warning` (amber), `info` (blue-gray).

### 2.6 Signal strength indicator
4-bar glyph + numeric dBm. Color thresholds apply to both glyph and number:

| dBm | Quality | Color |
|---|---|---|
| ≥ −55 | Great | green |
| ≥ −65 | Good | green |
| ≥ −75 | Weak | amber |
| < −75 | Very weak / dropping | red |

Wired devices show an Ethernet glyph instead (no signal).

### 2.7 Device detail view (L2)
Header: status dot + name, vendor, connection type, IP/MAC with copy, and action buttons (Ping, Restart, Block, Forget).

Four tabs:

| Tab | Contents |
|---|---|
| **Overview** | Identity (vendor, MAC, DHCP lease, hostname), connection details (SSID/channel/band or switch port), quick facts grid, last-seen |
| **Performance** | Big-number KPIs (current ↓/↑, avg, peak 24h, signal history), live per-device bandwidth chart, signal-over-time chart |
| **Settings** | Device-specific config: rename, static IP / DHCP reservation toggle, block internet, schedule access, QoS priority, parental controls |
| **Troubleshoot** | Action toolkit: Ping, Traceroute, DNS lookup, Renew DHCP, Restart radio, connection history timeline. Results render in a terminal-style output pane |

### 2.8 Settings interface (global, L3)
Grouped form sections — never a table. Groups for a home/prosumer router:

1. **Internet** — connection type (DHCP/PPPoE/static), WAN IP, DNS (auto/custom), MTU
2. **Wi-Fi** — SSID per band, channel, bandwidth (20/40/80 MHz), security (WPA2/WPA3), password
3. **LAN & DHCP** — router IP, subnet, DHCP range, lease time, reserved addresses list
4. **Security** — firewall, UPnP, remote management, guest network
5. **System** — firmware version, reboot, export/import config

Each section: title + one-line description, rows of label / control / inline hint. Destructive controls (reboot, factory reset) sit at the bottom with confirmation modals.

### 2.9 Quick actions menu (per device)
Row `⋯` menu: Ping · Copy IP · Copy MAC · Rename · Pause internet · Troubleshoot. Non-destructive first; destructive items separated by a divider.

---

## 3. Visual Treatment for Device States

**Rule: never color alone.** Every state = dot shape + color + text label (+ row treatment). Readable in grayscale and for colorblind users.

| State | Dot | Row treatment | Text |
|---|---|---|---|
| **Connected** | ● filled green | normal | "Online" |
| **Warning** (weak signal / high latency / packet loss) | ● filled amber | 3 px amber left border on row | "Weak signal −78 dBm" subline |
| **Offline** | ○ hollow gray | row opacity 60%, no throughput | "Last seen 2h ago" |
| **Critical** (WAN down, loss > 5%) | ● filled red | red L0 banner with explanation | "No internet" |
| **Blocked** (user-disabled) | ● filled gray + slash icon | diagonal-hatch subline, muted | "Blocked by you" |

Signal glyph recolors per the dBm table in §2.6.

**Network-level states** use the same vocabulary in the L0 band: green = healthy, amber = degraded, red = down. When critical, the band shows a banner line ("WAN down since 14:02 — 0% packet loss to gateway") instead of collapsing into a small pill.

**Status legend** is visible in the Devices view footer so the mapping is always discoverable.

---

## 4. User Interaction Model

### Navigation
- **Left rail** is always present: Dashboard · Devices · Alerts · Settings.
- **Hash routing:** `#/dashboard`, `#/devices`, `#/alerts`, `#/settings`, `#/device/<id>` — back button works, deep links work.
- **⌘/Ctrl + K** opens quick-jump: fuzzy search across device names/IPs/MACs → jumps straight to device detail.
- Breadcrumb on detail/settings views ("Devices / Living Room TV") with back affordance.

### Path A — Quick status check (seconds)
```
Open app → L0 band answers "is it okay?"
  ├─ all green → done
  └─ amber/red → scan table's amber-bordered rows / alert feed
```

### Path B — Deep configuration
```
Dashboard → click device row → device detail → Settings tab → edit → Save
                     or
Dashboard → Settings rail icon → global network settings → edit → Save
```
Edits show a "Saved" toast; the prototype updates state live.

### Path C — Troubleshooting a connectivity issue (the important one)
```
Alert appears: "Living Room TV: packet loss 12%"
        │
        ▼ click alert (ONE hop)
Device detail → Troubleshoot tab, pre-staged with that device
        │
        ├── Run Ping ──────→ terminal pane: latency/loss per hop
        ├── Run Traceroute → reveals where loss starts
        ├── DNS lookup ────→ catches resolution issues
        ├── Renew DHCP ────→ fixes address conflicts
        └── Restart radio ─→ last resort, confirmed action
        │
        ▼
Timeline at bottom shows recent state changes ("online → warning, 14:02")
```
Equivalent entry point: hover a table row → `⋯` → Troubleshoot.

### Confirmation rules
- **Confirmed:** Block device, Forget device, Restart radio, Reboot router, Factory reset.
- **Not confirmed:** rename, IP reservation toggle, QoS priority, channel change (auto-applies, shows toast).

---

## 5. Data Display Strategy

| Information | Format | Rationale |
|---|---|---|
| Device inventory | **Sortable/filterable table** | Primary scan + compare surface; columns enable cross-device comparison |
| Network status | **Pill + big-number cards** | Single-value states; glanceable |
| Bandwidth (aggregate) | **Stacked area chart** (live) | Trend and composition matter more than exact numbers |
| Bandwidth (per device) | **Big numbers + small time-series chart** | Summary first, history second |
| Latency / packet loss | **Number + sparkline** | Current value with 60 s context |
| Signal strength | **Bar glyph + dBm** | Qualitative scan, precise value available |
| Alerts | **Chronological severity list** | Triage is time-ordered |
| Settings | **Grouped form sections with hints** | Forms invite editing; tables invite reading |
| IP / MAC / hostname | **Monospace + click-to-copy** | These values get pasted elsewhere constantly |
| Device identity facts | **Definition grid (label/value pairs)** | 6–8 fixed fields; grid beats prose |
| Troubleshooting output | **Terminal-style pane** | Matches the mental model of CLI diagnostics |
| Connection history | **Vertical event timeline** | Sequence of state changes over time |

**Anti-patterns avoided:** pie charts for throughput (area chart instead), gauges for latency (number + sparkline), tables for settings (forms), color-only status (dot + label + border).

---

## 6. Wireframes

### 6.1 Full dashboard

```
┌────┬────────────────────────────────────────────────────────────────────────┐
│ ▣  │  NETDASH                          ⌘K search        ● Live  1s ago  ☾  │
│    ├────────────────────────────────────────────────────────────────────────┤
│ 🖥 │ ┌──────────┐ ┌──────────┐ ┌───────────────┐ ┌──────────┐ ┌──────────┐  │
│Dashboard││ ● ONLINE │ │  14 ms   │ │ ↓ 42.1  ↑ 8.3 │ │ 12 / 14  │ │  ! 2    │  │
│    │ │ INTERNET │ │ LATENCY  │ │   MBPS        │ │ DEVICES  │ │ ALERTS   │  │
│ 📱 │ └──────────┘ └─────▲────┘ └───────────────┘ └────┬─────┘ └────┬─────┘  │
│Devices│                  sparkline                     │            │        │
│    ├───────────────────────────────────────────────────┴────────────┴────────┤
│ 🔔 │ Devices  [All ▾] [Wi-Fi] [Wired] [Offline]   🔍 search devices…        │
│Alerts│ STATUS  NAME / VENDOR        IP ADDRESS   MAC            SIGNAL   ↓↑  │
│    │ ─────────────────────────────────────────────────────────────────────── │
│ ⚙  │ ●●●●  Living Room TV        192.168.1.42  3C:5A:B4:...  ▮▮▮▯ -61  12M │
│Settings│        Samsung · Wi-Fi 5GHz                            ⌯           │
│    │ ▓●●●  Bedroom Speaker ⚠     192.168.1.57  B8:27:EB:...  ▮▯▯▯ -79   0M │
│    │        Sonos · Wi-Fi 2.4GHz  weak signal                    ⌯           │
│    │ ─────────────────────────────────────────────────────────────────────── │
│    │ ●●●●  Max's Laptop          192.168.1.10  F0:2F:74:...  ▮▮▮▮ -48  31M │
│    │        Dell · Wi-Fi 5GHz                             ⌯                  │
│    │ ●●●●  Workstation (wired)   192.168.1.20  00:1A:2B:...  ⏚ ENET   84M │
│    │        Custom · Ethernet                             ⌯                  │
│    │ ○○○○  Old Phone             192.168.1.88  AC:BC:32:...    —      —     │
│    │        Google · offline 2h ago                          ⌯              │
│    │ ●●●●  Nest Cam · Garage     192.168.1.63  18:B4:30:...  ▮▮▮▯ -66   2M │
│    │        Google · Wi-Fi 2.4GHz                            ⌯              │
│    │  … 9 more devices                                                  1–7  │
│    │ ● connected   ● warning   ○ offline   ● blocked     [View all →]      │
│    ├────────────────────────────────────────────────────────────────────────┤
│    │  BANDWIDTH (60s)                  │  ALERTS                          │
│    │  Mbps 100┤      ╭─╮ ╭────╮       │  ⚠ 14:02  Bedroom Speaker:        │
│    │      50 ┤ ╭────╯  ╰─╯     ╰─╮    │      weak signal −79 dBm      ›   │
│    │       0 ┼┴───────────────────→    │  ! 13:47  Old Phone offline        │
│    │         down ▓  up ░             │  ℹ 12:30  2 devices joined         │
│    │                                   │  [View all alerts →]              │
└────┴───────────────────────────────────┴────────────────────────────────────┘
```

### 6.2 Device detail view (tabs annotated)

```
┌────┬────────────────────────────────────────────────────────────────────────┐
│ ▣  │  Devices / Living Room TV                     ● Connected · 3 min ago  │
│    ├────────────────────────────────────────────────────────────────────────┤
│ 🖥 │  Living Room TV                                                  ⌯     │
│    │  Samsung Electronics · Wi-Fi 5 GHz · 192.168.1.42                      │
│ 📱 │  MAC 3C:5A:B4:xx:xx:xx 📋      [Ping]  [Restart]  [Block]  [Forget]    │
│    ├────────────────────────────────────────────────────────────────────────┤
│ 🔔 │  [Overview]  [Performance]  [Settings]  [Troubleshoot]                 │
│    │  ┌──────────────────────────────────────────────────────────────────┐  │
│ ⚙  │ │ TAB: OVERVIEW                                                    │  │
│    │ │ ┌─ Identity ─────────────┐  ┌─ Connection ────────────────────┐  │  │
│    │ │ │ Vendor    Samsung      │  │ SSID        HomeNet-5G         │  │  │
│    │ │ │ Hostname  samsung-tv   │  │ Band        5 GHz · Ch 149     │  │  │
│    │ │ │ MAC       3C:5A:B4:…📋 │  │ Signal      ▮▮▮▯  −61 dBm      │  │  │
│    │ │ │ IP        192.168.1.42 │  │ Security    WPA3               │  │  │
│    │ │ │ DHCP      reserved     │  │ AP          Living Room AP     │  │  │
│    │ │ │ Lease     21h remaining│  │ Roaming     since 09:14        │  │  │
│    │ │ └────────────────────────┘  └────────────────────────────────┘  │  │
│    │ │ ┌─ Quick facts ────────────────────────────────────────────────┐│  │
│    │ │ │ Uptime 6d 4h · ↓12.4 Mbps now · peak 48 Mbps (20:10)       ││  │
│    │ │ └──────────────────────────────────────────────────────────────┘│  │
│    │ └──────────────────────────────────────────────────────────────────┘  │
└────┴────────────────────────────────────────────────────────────────────────┘

TAB: Performance — [↓ 12.4 Mbps] [↑ 0.8 Mbps] [peak 48M] [avg 6M]
                   live per-device area chart · signal-over-time chart

TAB: Settings  —  Device name [Living Room TV____]  [Save]
                  IP assignment  (•) DHCP reservation  ( ) Static  ( ) DHCP
                  Static IP [192.168.1.42]
                  Internet access  [Allowed ▾]     ← block/pause
                  Active hours    [07:00 ──────── 23:00]
                  QoS priority    [ ▾ High ]

TAB: Troubleshoot — [Ping] [Traceroute] [DNS lookup] [Renew DHCP] [Restart radio]
                    ┌─ terminal ──────────────────────────────────────┐
                    │ $ ping 192.168.1.42                             │
                    │ 64 bytes … time=3.1 ms   loss=0%                │
                    └─────────────────────────────────────────────────┘
                    Connection timeline:
                    ● 14:02 warning (packet loss 12%)  ● 14:05 online …
```

### 6.3 Settings interface (global)

```
┌────┬────────────────────────────────────────────────────────────────────────┐
│ ▣  │  Settings                                          [Discard] [Save]    │
│    ├────────────────────────────────────────────────────────────────────────┤
│ 🖥 │  INTERNET — how your network reaches the world                        │
│    │  Connection type   [DHCP ▾]     auto-assigned by ISP                  │
│ 📱 │  WAN IP            100.64.12.34 (lease 18h remaining)                 │
│    │  DNS servers       (•) Auto    ( ) Custom   [1.1.1.1] [9.9.9.9]       │
│ 🔔 │  ─────────────────────────────────────────────────────────────        │
│    │  WIFI — wireless network names and radio settings                     │
│ ⚙  │  2.4 GHz SSID      [HomeNet________]   Channel [Auto ▾]  BW [40MHz▾] │
│    │  5 GHz SSID        [HomeNet-5G_____]   Channel [149▾]    BW [80MHz▾]  │
│    │  Security          [WPA3 ▾]     Password  [••••••••]  👁              │
│    │  Guest network     [Off ▾]                                                   │
│    │  ─────────────────────────────────────────────────────────────        │
│    │  LAN & DHCP — addresses inside your network                           │
│    │  Router IP         192.168.1.1 / 255.255.255.0                        │
│    │  DHCP range        192.168.1.100 ─── 192.168.1.200                    │
│    │  Lease time        [24 hours ▾]    Reserved addresses  (12) ›         │
│    │  ─────────────────────────────────────────────────────────────        │
│    │  SECURITY                                                             │
│    │  Firewall          [On ▾]     UPnP  [Off ▾] ⚠ recommended off        │
│    │  Remote management [Off ▾] ⚠ exposes admin UI to WAN                  │
│    │  ─────────────────────────────────────────────────────────────        │
│    │  SYSTEM                                                              │
│    │  Firmware         v4.2.1 (up to date)        [Check for updates]      │
│    │  [Reboot router]  [Export config]  [Import config]                    │
│    │  ⚠ [Factory reset]  ← confirmation modal                              │
└────┴────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Cross-Platform Notes (Linux + Windows)

The prototype is deliberately platform-neutral:

- **Single HTML file, zero dependencies** — no build toolchain, no Node, no Electron. Works in Firefox/Chrome on Arch and Windows alike. Open via double-click or `python -m http.server`.
- **No OS APIs used** — all data is simulated in-browser (`setInterval` + seeded generators).
- **Keyboard shortcuts use `Ctrl`/`Meta` agnostic binding** (`e.metaKey || e.ctrlKey`) so ⌘K and Ctrl+K both work.
- **System font stack** — resolves to Inter/Segoe UI Variable on Windows, Cantarell/Fira Sans/system-ui on Linux; no webfont download required.

### Future real-data integration (out of scope for prototype)
Data should sit behind a small adapter interface (`fetchDevices()`, `fetchMetrics()`, `runDiagnostic()`) so sources can differ per OS:

| Data | Linux | Windows |
|---|---|---|
| ARP/neighbor table | `ip neigh` / `/proc/net/arp` | `Get-NetNeighbor` / ARP API |
| Wi-Fi signal | `iw dev … station dump` | `netsh wlan show interfaces` |
| Per-interface counters | `/sys/class/net/*/statistics` | `Get-NetAdapterStatistics` |
| Router-level data (DHCP leases, WAN) | router API / SNMP / OpenWrt ubus | same — router is OS-independent |
| Ping/traceroute/DNS | `ping`, `traceroute`, `dig` | `ping`, `tracert`, `Resolve-DnsName` |

A tiny local agent (Python or Node, one file) exposing these over `localhost` HTTP keeps the UI identical on both OSes.

---

## 8. Accessibility & Scannability Rules

1. Status never conveyed by color alone (dot shape + label + border).
2. Minimum 4.5:1 contrast for text; 3:1 for large numbers and icons.
3. All interactive rows keyboard-focusable; visible focus ring.
4. Table sortable by keyboard; search filters as you type with result count announced.
5. Reduced-motion respected (`prefers-reduced-motion`: chart animation and toasts disabled).
6. L0 band never scrolls out of view on the dashboard.
7. Click-to-copy elements show a transient "Copied" toast for confirmation.
