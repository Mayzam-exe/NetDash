# NetDash

A self-hosted dashboard for your home network. It finds every device on your
LAN, shows you what's actually happening, and lets you cut a device's internet
with one click.

It runs as a single binary on the machine where your traffic crosses — your
router, a Linux box, or a Windows host. The web UI is baked into the binary, so
there's no Node runtime, no cloud, and nothing phoning home.

![stack](https://img.shields.io/badge/backend-Go-00ADD8) ![stack](https://img.shields.io/badge/frontend-Vite%20%2B%20TypeScript-646CFF)

## Why I built it

I was sitting in a café on their free Wi-Fi, trying to get some work done, and
the connection was crawling. I pulled up the usual troubleshooting tools — and
every single one of them wanted me to log into the router. I didn't have the
password. It wasn't my router. So there I was, a device on the network with no
way to see what was going on and no way to fix it.

That's the gap NetDash fills. Almost every home-network tool assumes you *are*
the admin — that you can log into the router, read its tables, and set the
rules. But you're often just another client on the network: a guest, a tenant,
someone on shared Wi-Fi. NetDash works from that seat. It discovers and manages
devices, measures real traffic, and — when it can — enforces limits, all while
being nothing more than one more machine on the LAN.

The features kept growing out of that same frustration. I wanted to steer my
own connection without touching the router, so speed limits came first. Then I
wanted to redirect a domain to a box I controlled to test something, so DNS
spoofing followed. Then intercept, TLS fingerprinting, port scanning — each one
started as "I wish I could do this from out here." It's now a full dashboard
that happens to work whether or not you own the network it's on.

It's public now, so if you've ever been stuck on a network you couldn't
administer, it's yours too.

## The idea behind it

Most network tools show you a wall of numbers and leave you to figure out what
they mean. NetDash is built around one rule instead:

> **Never show a number you can't actually measure.**

If a real value exists, you get it. If the network won't give it up (most
routers won't tell you another device's Wi-Fi signal, for instance), NetDash
says so plainly instead of inventing a plausible-looking fake. You'll see `—`
with the honest reason next to it. That principle shapes almost every feature
below.

## What it does

**Find everything on your network.**
NetDash discovers devices through ARP and SNMP, resolves MAC vendors, grabs
real hostnames, and figures out the connection type (Ethernet, Wi-Fi 5, Wi-Fi
2). It uses mDNS/Bonjour to pick up friendly names like `maxs-iPhone` or
`living-room-chromecast` when DHCP stays quiet. It even includes the machine
it's running on, with its real Wi-Fi band and signal.

**Guess what each device is.**
Phones, laptops, TVs, routers — inferred from where the device sits on the
network, its hostname (including model numbers like `SM-G991B`), its MAC
vendor, and a ping fingerprint. When it genuinely can't tell, it leaves it as
"unknown" rather than guessing, and you can override any label (your choice
sticks).

**Measure speed and health for real.**
Per-device download/upload comes straight from nftables byte counters when
NetDash is sitting on the gateway path — actual bytes, not estimates. Gateway
and WAN latency, plus host traffic, are read live. When NetDash isn't in a
position to measure something, it tells you why instead of showing a made-up
figure.

**Block a device's internet.**
One click cuts a device off. When NetDash runs on the gateway, it uses
nftables (Linux) or the Windows Firewall. When it's just another device on your
LAN, it uses ARP gateway-impersonation — the blocked device's traffic is
redirected to NetDash and dropped, and its network caches are repaired the
moment you unblock. If NetDash has no way to enforce a block, the API says so
rather than pretending it worked.

**Lock everything down in one flip.**
A panic switch in Settings cuts internet for every device except this machine,
the router, and the ones you've marked *Keep online during lockdown*. It
applies instantly (no save button), and if NetDash can't actually enforce it,
the switch refuses — so you never see a "protected" network that isn't. Letting
go restores exactly the state you had before: individual blocks and schedules
survive.

**Set itself up automatically.**
Connect to a network and NetDash fills in your settings on its own — connection
type (DHCP / static / PPPoE), DNS servers, Wi-Fi security, channels, both
SSIDs, and your public egress address. It reads all of it from your own
machine's stack (`nmcli`, `iw`, `resolv.conf`) plus a single internet echo. It
runs at boot, whenever you join a new network, every 10 minutes, or on demand.
A neighbouring router's stronger signal is never mislabelled as your second
band — and the WAN health check keeps its own reliable target, because pinging
your own public IP would just get answered by your router's NAT and keep the
"internet is up" light green even when it's dead.

**Troubleshoot without leaving the dashboard.**
Per-device diagnostics run for real from the server: a 4-probe ping, a
traceroute (no extra binary needed), DNS lookups with mDNS fallback, and — for
the host itself — a genuine DHCP lease renewal and Wi-Fi radio restart. Devices
that aren't the host get an honest "no agent here" instead of fake output.

**See what's talking, even over encryption.**
Devices you mark as *watched* are relayed untouched while NetDash reads the
cleartext hostname off the wire (DNS queries, TLS SNI, HTTP Host). Fully
encrypted connections still get fingerprinted by their TLS handshake
(`ja3`/`ja4`), which can identify the exact app behind the tunnel — without
breaking the encryption.

**Scan ports and spoof DNS.**
A half-open SYN sweep (crafted raw packets, no connection ever completes) with
parallel banner grabs for HTTP, TLS, SSH, and more. DNS spoofing rules map a
domain to an IP you control and answer matching queries from intercepted
devices with a forged record.

**Stay alive through network changes.**
NetDash re-reads your default route every 20 seconds. Move to a new Wi-Fi and
it re-adopts the new gateway on its own, raises an alert, and rebinds its
bridge (repairing old state first). If the ARP bridge dies — Wi-Fi bounce,
cable pull, suspend — a supervisor notices within 20 seconds and reopens it, so
your limits and intercepts survive a link drop instead of silently dying until
you restart the daemon.

## Quick start

```sh
cd app
./build.sh            # builds the web UI, embeds it, cross-compiles
./bin/netdash-linux   # or bin/netdash-windows.exe
```

Open http://127.0.0.1:7420

Flags:

| Flag       | Default            | Description                 |
|------------|--------------------|-----------------------------|
| `-addr`    | `127.0.0.1:7420`   | listen address              |
| `-data`    | platform data dir  | SQLite + state directory    |
| `-version` | —                  | print version and exit      |

Your data lives in `$XDG_DATA_HOME/netdash` (usually `~/.local/share/netdash`)
on Linux, or `%APPDATA%\netdash` on Windows. Override with `NETDASH_DATA` or
`-data`.

## Run it as a service

One-time setup (from the project root):

```sh
mkdir -p ~/.config/systemd/user
cp netdash.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now netdash   # start now + at every login
sudo loginctl enable-linger $USER       # keep running after logout (boot autostart)
```

Day to day:

| Action       | Command                                 |
|--------------|-----------------------------------------|
| Stop         | `systemctl --user stop netdash`         |
| Start        | `systemctl --user start netdash`        |
| Restart      | `systemctl --user restart netdash`      |
| Auto-start   | `systemctl --user enable netdash`       |
| No autostart | `systemctl --user disable netdash`      |
| Logs         | `journalctl --user -u netdash -f`       |

`./deploy.sh` notices the service and restarts it after each build; without the
service it falls back to `pkill` + a manual start. No systemd at all? Run
`./run/netdash -addr 127.0.0.1:7420 -data ./data &` and stop it with
`pkill -x netdash`.

## Development

```sh
cd app
go vet ./... && go test ./...     # backend
cd web && npm ci && npm run dev   # frontend with hot reload (proxies to :7420)
cd .. && go run ./cmd/netdash     # backend with embedded UI (rebuild to re-embed)
```

The Go tests cover schedule windows, device-kind inference, ARP frame
crafting, the mDNS parser, the TLS `ja3`/`ja4` parsers (checked against the
official reference vectors), the port scanner, and the diagnostics output
parsers.

## API

| Method   | Path                            | Purpose                              |
|----------|---------------------------------|--------------------------------------|
| GET      | `/api/status`                   | gateway/WAN latency, totals, and the `path`/`metering`/`firewall` capability flags |
| GET      | `/api/devices`                  | device list                          |
| POST     | `/api/devices/{id}`             | patch: `blocked`, `name`, `priority`, `reserved`, `schedule`, `kind`, `speedDown`, `speedUp` (kbit/s, 0 = unlimited), `watched` |
| GET      | `/api/devices/{id}/intel`       | findings (`dns`/`sni`/`http`/`ja3`/`ja4`), newest first |
| GET/POST | `/api/spoof-rules`              | list / upsert `{domain, ip}` DNS spoof rules |
| DELETE   | `/api/spoof-rules/{id}`         | remove a rule                        |
| DELETE   | `/api/devices/{id}`             | forget a device (suppresses rediscovery for 10 min) |
| POST     | `/api/devices/{id}/ping`        | 4 ICMP probes, returns loss/rtt      |
| POST     | `/api/devices/{id}/traceroute`  | TTL-walk traceroute (real ping probes) |
| POST     | `/api/devices/{id}/dnslookup`   | PTR + forward A/AAAA (mDNS fallback) |
| POST     | `/api/devices/{id}/renew-dhcp`  | self only: cycle link, re-acquire DHCP lease |
| POST     | `/api/devices/{id}/restart-radio` | self only: Wi-Fi radio off/on + rejoin |
| POST     | `/api/devices/{id}/scan`        | port scan: `{"ports":[...]}` (empty → curated top list) |
| GET      | `/api/devices/{id}/scan`        | the device's last stored scan        |
| GET      | `/api/alerts`                   | alert feed                           |
| POST     | `/api/alerts/{id}/ack`          | acknowledge                           |
| GET/PUT  | `/api/settings`                 | gateway/WAN IPs, SSIDs, SNMP         |
| POST     | `/api/settings/detect`          | detect the network now: auto-apply SSIDs/egress and return the full detection |
| GET      | `/api/history`                  | time series for charts               |
| GET      | `/api/stream`                   | SSE: `hello` + `tick` snapshots      |

A few notes on the parameters:

- `schedule` is `HH:MM-HH:MM`; the internet is allowed only inside that window.
  An empty schedule (the default) allows it always.
- `kind` is a device-type id, or `""` to go back to auto-inference. Invalid ids
  get a `400`.
- `speedDown`/`speedUp` are kbit/s caps and need the ARP bridge — gateway mode
  rejects them with a reason.
- `watched: true` starts intercept mode and also needs the ARP bridge.
- `status.path` is `gateway` or `behind`; `status.metering`, `status.speed`,
  and `status.blocking` are either `active…` or `unavailable: <reason>` — and
  the UI shows those reasons exactly as written.

## Security

By default NetDash listens on `127.0.0.1:7420`, so only the machine it runs on
can reach it. If you expose it to your LAN (`-addr 0.0.0.0:7420`), put a token
in front of it:

```sh
./bin/netdash -addr 0.0.0.0:7420 -auth-token "$(openssl rand -hex 24)"
# or: export NETDASH_AUTH_TOKEN=...
```

With a token set, every `/api/*` request must include it — either as
`Authorization: Bearer <token>` or `?token=<token>` (the SSE stream can't send
headers). The bundled UI picks the token up from the browser, so run
`localStorage.setItem('netdashToken', '<token>')` once and it attaches it for
you. Starting without a token on a non-loopback address prints a loud warning.

Every response also carries `X-Content-Type-Options`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, and a restrictive `Content-Security-Policy`.

## Platform notes

- **Blocking on the gateway** needs `nftables` and `CAP_NET_ADMIN`:
  `sudo setcap cap_net_admin+ep ./bin/netdash-linux` (or just run under sudo).
  NetDash keeps to its own isolated `table inet netdash` and never touches your
  other firewall tables.
- **Blocking from a laptop** (behind any router) uses ARP
  gateway-impersonation toward blocked devices only — everyone else is
  untouched. Needs Linux and `CAP_NET_RAW` +
  `CAP_NET_ADMIN`:
  `sudo setcap cap_net_raw,cap_net_admin+ep <netdash-binary>`. The binary has
  to sit on a filesystem **without `nosuid`** (file capabilities are ignored on
  things like `tmpfs /tmp`), `net.ipv4.ip_forward` must stay `0`, and blocks are
  fail-open: they last while NetDash runs, and normal ARP TTLs clean up the
  rest after a crash.
- **Blocking on Windows** needs an elevated process (it creates
  `netsh advfirewall` rules named `netdash-block-<ip>`).
- **Without the capability**, monitoring keeps working; the status just shows
  `blocking: unavailable: <reason>` and block requests fail with that same
  reason.
- **SNMP** is optional and reads neighbor tables and WAN interface counters
  from your router (SNMPv2c, `host:port`, default 161, community string, WAN
  ifName).
- **Windows/WSL ICMP** may need the ICMP allow rule enabled; ping results are
  real and report loss honestly.

---

MIT licensed. Built as a single offline binary — no telemetry, no external
assets, no dependencies you didn't ask for.
