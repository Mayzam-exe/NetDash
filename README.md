# NetDash

A self-hosted home-network dashboard: device discovery, live metrics, alerts,
and internet blocking for the machines on your LAN.

NetDash runs as a single binary on the machine where your traffic crosses
(the router, a Linux gateway, or a Windows host). The web UI is embedded —
no Node runtime, no cloud, no external services.

![stack](https://img.shields.io/badge/backend-Go-00ADD8) ![stack](https://img.shields.io/badge/frontend-Vite%20%2B%20TypeScript-646CFF)

## Features

- **Device inventory** — ARP/SNMP discovery, MAC vendors (IEEE OUI), hostnames,
  connection type (eth / Wi-Fi 5 / Wi-Fi 2) from SNMP bridge-FDB entries.
  mDNS/Bonjour captures fill real names ("maxs-iPhone", "living-room-chromecast")
  when DHCP/reverse DNS stays silent. The machine running NetDash is included
  too ("this machine"), with its real Wi-Fi band, signal and local throughput.
  Per-client Wi-Fi signal is not available — ISP gateways do not expose RSSI, so
  the Signal column is populated for this machine only.
- **Device types** — phone / laptop / TV / router / … inferred from gateway
  position, hostname (incl. model-number names like `SM-G991B`), MAC vendor and
  a ping-TTL fingerprint (128 = Windows → desktop); unknown stays unknown,
  overridable per device; the choice persists.
- **Per-device speed** — real down/up from nftables byte counters when this
  host is on the gateway path; otherwise the UI shows `—` with the reason
  rather than faking numbers.
- **Live metrics** — gateway and WAN latency, host down/up/peak via
  `/proc/net/dev` (Linux) counters (peak is since NetDash started), optional
  SNMP WAN interface rates.
- **Network map** — interactive canvas atlas (probe) with topology, per-device
  state, and keyboard navigation.
- **Alerts** — threshold-based (gateway/WAN down, high latency, device offline)
  with cooldowns and deduplication, streamed over SSE.
- **Blocking** — cut a device's internet via nftables (Linux) or Windows
  Firewall when this host is the gateway, or via **ARP gateway-impersonation**
  from a plain LAN client (the blocked device's frames are redirected here and
  dropped; caches are repaired on unblock). Active-hours schedules included.
  When the host cannot enforce blocks, the API says so instead of faking it.
- **Speed limits** — per-device down/up caps in kbit/s through the same ARP
  bridge: poisoned devices keep working but their frames are relayed through
  a token-bucket shaper, so TCP self-throttles to the configured rate.
  Block overrides limit; limits clear cleanly on unblock/shutdown.
- **Lockdown** — a panic switch in Settings that cuts internet for every
  device at once except this machine, the router, and the devices you marked
  *Keep online during lockdown*. It applies the instant you flip it (no save
  button), rides the same enforcement path as ordinary blocking, and is
  refused outright when the host has no way to enforce it — so the dashboard
  never shows a protected network that is not protected. Releasing it restores
  exactly the previous state: per-device blocks and active-hours schedules
  still stand. The switch is a setting, so it survives a restart, and it is
  announced as a critical alert with the real number of devices cut off.
- **Auto-written settings** — Settings knows the network instead of waiting
  for typing: connection type (DHCP/Static/PPPoE), DNS resolvers, Wi-Fi
  security, channels/bandwidth and both SSIDs come from what this host's own
  stack reports (`nmcli`, `iw`, resolv.conf), plus the public egress address
  from one internet echo. Detection runs at boot, on a network change
  (gateway adoption), every 10 minutes, and on demand via the *Detect
  network* button. Unknown stays unknown: a neighbour's stronger AP is never
  labelled as your second band, and the WAN health probe keeps its own
  reliable target — a ping to your own public IP is answered by the local
  router's NAT, which would keep WAN green with the internet dead.
- **Device actions** — block/allow, forget (10-minute rediscovery grace),
  real ICMP ping from the server, name/priority/reservation settings.
  Priority and reservations are stored and displayed for reference only:
  NetDash does not shape other devices' bandwidth and does not create DHCP
  reservations on your router (a reservation just keeps the device from
  being expired).
- **Troubleshoot** — per-device diagnostics that run for real from the
  server: 4-probe ping, TTL-walk traceroute (system ping, no traceroute
  binary needed), PTR + forward DNS lookup with mDNS fallback, and — for
  this machine only — a genuine DHCP lease cycle (NetworkManager link
  bounce) and Wi-Fi radio restart (`nmcli radio off/on`). Client devices
  get an honest "no agent" explanation instead of fake output.
- **Intercept + intel** — `watched` devices are relayed unmodified while every
  cleartext hostname (DNS queries, TLS SNI, HTTP Host) is parsed off the wire
  and stored per device (7-day retention, deduped). Even fully encrypted
  connections are fingerprinted: `ja3`/`ja4` hashes of the TLS ClientHello
  (cipher/extension order, ALPN) identify the exact app behind the tunnel
  without breaking encryption. Needs the ARP bridge.
- **Port scan** — half-open SYN sweep (crafted raw packets, `CAP_NET_RAW`,
  no connection ever completes) with parallel banner grabs: HTTP status/
  `Server`/title, TLS version + certificate CN + ALPN, SSH/FTP/SMTP/Redis
  greetings. Curated ~110-port top list or explicit port sets (≤2000),
  results stored per device and restored on the Troubleshoot tab; falls
  back to connect-scan when raw sockets are unavailable (Windows build).
- **DNS spoofing** — rules map domain → IP; a matching query from an
  intercepted device is swallowed and answered with a forged A record pointing
  at an IP you control (exact or suffix match, e.g. `example.com` covers
  `a.example.com`).
- **Network change detection** — the OS default route is re-read every 20 s;
  when it moves to a different router (new Wi-Fi, different gateway address
  like `192.168.1.100`), the gateway setting is re-adopted after two
  consecutive confirmations, an alert is raised, and the ARP bridge is
  rebound (old poisons repaired first). Works regardless of subnet overlap.
- **Bridge outage recovery** — the ARP bridge's poison ticker and relay loop
  exit permanently on socket errors (Wi-Fi bounce, cable pull, suspend). A
  supervisor checks every 20 s and reopens the bridge once the machine has
  an address again, so speed limits, intercept and DNS spoofing survive link
  drops instead of silently dying until the next daemon restart.
- **Idle device expiry** — devices unseen for 5 minutes are dropped from the
  inventory and map automatically; they reappear the moment they reconnect.
  Configured devices are kept: blocked, reserved, intercepted (`watched`),
  speed-limited, scheduled, priority-set, manually classified, plus this
  machine and the gateway.

## Quick start

```sh
cd app
./build.sh          # builds web UI, embeds it, cross-compiles
./bin/netdash-linux  # or bin/netdash-windows.exe
```

Open http://127.0.0.1:7420

Flags:

| Flag       | Default                   | Description                        |
|------------|---------------------------|------------------------------------|
| `-addr`    | `127.0.0.1:7420`          | listen address                     |
| `-data`    | platform user data dir    | SQLite + state directory           |
| `-version` | —                         | print version and exit             |

Data directory: `$XDG_DATA_HOME/netdash` or `~/.local/share/netdash` on Linux,
`%APPDATA%\netdash` on Windows. Override with `NETDASH_DATA` or `-data`.

## Run as a service (on/off)

One-time install (from the project root):

```sh
mkdir -p ~/.config/systemd/user
cp netdash.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now netdash     # start now + at login
sudo loginctl enable-linger maxim         # keep it running after logout (boot autostart)
```

Everyday on/off:

| Action        | Command                                    |
|---------------|--------------------------------------------|
| Stop          | `systemctl --user stop netdash`            |
| Start         | `systemctl --user start netdash`           |
| Restart       | `systemctl --user restart netdash`         |
| Auto-start    | `systemctl --user enable netdash`          |
| No autostart  | `systemctl --user disable netdash`         |
| Logs          | `journalctl --user -u netdash -f`          |

`./deploy.sh` detects the service and restarts it after each build;
without the service it falls back to `pkill` + manual start.
Without systemd: `./run/netdash -addr 127.0.0.1:7420 -data ./data &`
(stop with `pkill -x netdash`).

## Development

```sh
cd app
export PATH=$HOME/.local/bin:$PATH
go vet ./... && go test ./...     # backend
cd web && npm ci && npm run dev   # frontend with HMR (proxy -> :7420)
cd .. && go run ./cmd/netdash     # backend with embedded UI (rebuild to re-embed)
```

`go test ./...` covers schedule parsing/enforcement windows, kind inference,
ARP frame crafting/reconciliation and the mDNS DNS parser, plus the intel
TLS parsers (official JA3/JA4 reference vectors), the port scanner
(loopback open/closed/banner classification) and diagnostics result
parsing (TTL-walk, DNS, negative paths).

## API

| Method | Path                         | Purpose                              |
|--------|------------------------------|--------------------------------------|
| GET    | `/api/status`                | gateway/WAN latency, totals, `path`/`metering`/`firewall` capability |
| GET    | `/api/devices`               | device list                          |
| POST   | `/api/devices/{id}`          | patch: `blocked`, `name`, `priority`, `reserved`, `schedule`, `kind`, `speedDown`, `speedUp` (kbit/s, 0 = unlimited), `watched` (intercept) |
| GET    | `/api/devices/{id}/intel`    | findings (`dns`/`sni`/`http`/`ja3`/`ja4`), newest first |
| GET/POST | `/api/spoof-rules`         | list / upsert `{domain, ip}` DNS spoof rules |
| DELETE | `/api/spoof-rules/{id}`      | remove a rule                         |
| DELETE | `/api/devices/{id}`          | forget device (suppresses rediscovery 10 min) |
| POST   | `/api/devices/{id}/ping`     | 4 ICMP probes, returns loss/rtt stats |
| POST   | `/api/devices/{id}/traceroute` | TTL-walk traceroute (real ping probes), hops + RTTs |
| POST   | `/api/devices/{id}/dnslookup` | PTR + forward A/AAAA (mDNS fallback), real timings |
| POST   | `/api/devices/{id}/renew-dhcp` | self only: cycle link, re-acquire DHCP lease |
| POST   | `/api/devices/{id}/restart-radio` | self only: Wi-Fi radio off/on + rejoin wait |
| POST   | `/api/devices/{id}/scan`     | port scan: `{"ports":[...]}` (empty → curated top list), open ports + banners |
| GET    | `/api/devices/{id}/scan`     | device's last stored scan (`{"scan": null}` if never run) |
| GET    | `/api/alerts`                | alert feed                           |
| POST   | `/api/alerts/{id}/ack`       | acknowledge                          |
| GET/PUT| `/api/settings`              | gateway/WAN IPs, SSIDs, SNMP         |
| POST   | `/api/settings/detect`      | detect network now: auto-apply SSIDs/egress, return full detection |
| GET    | `/api/history`               | time series for charts               |
| GET    | `/api/stream`                | SSE: `hello` + `tick` snapshots      |

`schedule` uses `HH:MM-HH:MM` (en dash accepted); internet is allowed only
inside the window. Empty schedules (the default) allow always (fail-open).
`kind` is a device-type id, or `""` to return to auto-inference; invalid ids
get 400. `speedDown`/`speedUp` are kbit/s caps (0 clears; range 0–10000000)
and need the ARP bridge — nftables-gateway mode rejects them with a reason.
`watched: true` starts intercept mode (self/gateway rejected with 400); it also
needs the ARP bridge and coexists with speed limits.
`status.path` is `gateway`/`behind`, `status.metering` and `status.speed` are
`active`/`active (arp bridge)` or `unavailable: <reason>`, and
`status.blocking` is `active (nftables)`, `active (arp poisoning)` or
`unavailable: <reason>` — the UI shows those reasons verbatim.

## Security

NetDash binds `127.0.0.1:7420` by default, so it is reachable only from the
machine it runs on. If you expose it to the LAN (`-addr 0.0.0.0:7420`), protect
it with a token:

```sh
./bin/netdash -addr 0.0.0.0:7420 -auth-token "$(openssl rand -hex 24)"
# or: export NETDASH_AUTH_TOKEN=...
```

With a token set, every `/api/*` request must carry it — as
`Authorization: Bearer <token>`, or as `?token=<token>` (the SSE stream cannot
send headers). The bundled UI reads the token from the browser, so after setting
`localStorage.setItem('netdashToken', '<token>')` it attaches it automatically.
Starting without a token on a non-loopback address prints a loud warning.

Every response also carries `X-Content-Type-Options`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer` and a restrictive `Content-Security-Policy`.

## Platform notes

- **Blocking (gateway mode)** needs `nftables` and `CAP_NET_ADMIN`:
  `sudo setcap cap_net_admin+ep ./bin/netdash-linux` (or run under sudo).
  NetDash manages an isolated `table inet netdash` — it never touches other
  firewall tables, and rebuilds its own table on every change.
- **Blocking (laptop mode)** works behind any router: NetDash ARP-impersonates
  the gateway toward blocked devices only (everyone else is untouched). Needs
  Linux + `CAP_NET_RAW`:
  `sudo setcap cap_net_raw,cap_net_admin+ep <netdash-binary>`.
  The binary must sit on a filesystem **without `nosuid`** (file capabilities
  are ignored on e.g. `tmpfs /tmp`), `net.ipv4.ip_forward` must stay `0`, and
  blocks are fail-open: they last while NetDash runs (caches repair on
  unblock/shutdown; a crash expires with normal ARP TTLs).
- **Blocking (Windows)** needs an elevated process (`netsh advfirewall`
  rules named `netdash-block-<ip>`).
- **Without capability** the dashboard keeps monitoring; the status shows
  `blocking: unavailable: <reason>` and block requests fail with that reason.
- **SNMP** (optional) reads neighbor tables and WAN interface counters from
  your router: SNMPv2c, `host:port` (default 161), community, WAN ifName.
- **Windows/WSL ICMP** may require the ICMP allow rule; ping results are real
  and report loss honestly.

## Design

See [`../DESIGN.md`](../DESIGN.md) for the UX spec the UI is built against.
