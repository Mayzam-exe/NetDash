# Design brief: NetDash frontend — "2D office management" theme

Paste everything below this line into any AI. The goal is to collect several
independent design proposals and pick one. Answer format is specified at the
bottom — please follow it so proposals are comparable.

---

You are a senior product designer. Design a complete visual identity + UX
treatment for a self-hosted home-network dashboard. Do not write production
code; deliver a design proposal in the format specified at the end.

## The product

**NetDash** — a single-binary, offline-first dashboard for one household's
home network. No cloud, no external requests, no analytics. It runs on the
owner's own Linux laptop (a Wi-Fi client behind the home router) and is
browsed at `http://127.0.0.1:7420`. ~9 devices on the network: phones,
laptops, a TV, a printer, cameras, IoT.

Screens (all exist today and must keep their function):

1. **Dashboard** — status of internet + gateway latency + this machine's
   throughput; a live 60-second bandwidth chart; a sortable/filterable device
   table (name, state, IP, MAC, connection, signal, ↓/↑ rates); an alerts
   feed. Today's layout: 5 equal-width KPI boxes across the top, chart below,
   table + right rail below that.
2. **Network Map** — a free-form canvas "atlas": devices as nodes on a soft
   dark field with connection links; this machine and the gateway are anchor
   nodes; zoom/pan; click a node → device page.
3. **Devices** — the full device roster table with search, filter chips
   (All / Wi-Fi / Wired / Offline), and per-row menu (Block, Forget, Speed
   limit, Open device page).
4. **Alerts** — a feed of events (device offline/online, weak signal,
   blocked, lockdown engaged...) with severity filters and acknowledge.
5. **Settings** — global sections (SSID, router/SNMP, enforcement status)
   plus a **Lockdown** master switch: one toggle that cuts internet for every
   device except this machine, the router, and devices marked "Keep online".
   The switch applies immediately and is refused outright when the host
   cannot enforce it — honesty ("enforced" vs "reference-only" vs
   "unavailable") is the product's core value.
6. **Device page** — tabs: Overview (identity, connection, uptime, quick
   facts), Intel (hostnames seen, DNS spoof rules), Troubleshoot (real
   server-run ping / traceroute / DNS lookup / DHCP renew rendered in a
   terminal-style pane).

Device states: `online`, `warning` (e.g. weak signal), `offline`, `blocked`
(by user or by lockdown). This machine's own row is labeled as "you".

## The requested direction (the owner's words, keep the spirit)

> "A 2D office-management theme — like a 2D office/management game
> (think Game Dev Story / Theme Hospital / Two Point Hospital). The whole
> frontend is themed as a networking office: the dashboard is the office
> floor, devices are staff at desks, alerts are memos, the bandwidth chart
> is a whiteboard, settings is a filing cabinet, lockdown is a security
> guard at the door. Day/night shift can be the light/dark theme."

Treat this as the fixed direction. If you see a materially better way to
interpret "2D office management" for a network dashboard, put it in a short
appendix — do not let it replace the main proposal.

Non-negotiables of the direction:
- It must read as a *game-like illustrated office world*, not as a normal
  dashboard with a few cartoon stickers.
- Every metaphor must do real work: state must be legible at a glance, the
  theme must never obscure who is online/blocked/weak, and every action
  (block, lockdown, speed limit, diagnostics) must still be one click away.
- Data density stays: the device table with 8+ columns, sorting, filtering,
  copyable MACs etc. must remain usable. Charm on top of a tool, not instead
  of one.

## Hard technical constraints (design within them)

- **Zero webfonts** — system font stacks only (`system-ui`, `ui-monospace`,
  `ui-serif` + common fallbacks). No @font-face, no CDN.
- **Zero external assets** — every graphic is inline SVG or CSS; charts are
  `<canvas>` drawn in JS that reads colors via `getComputedStyle` custom
  properties (so the palette must be CSS variables). No image files.
- **Both themes required**: dark (primary) and light. Frame them as
  "night shift" and "day shift" if that serves the metaphor.
- **Accessibility floor**: WCAG AA text contrast, keyboard-navigable,
  `prefers-reduced-motion` respected (all motion must have a static
  fallback), status never conveyed by color alone.
- Frontend is vanilla TypeScript rendering HTML strings (one partial Preact
  view); CSS is one main stylesheet + a token layer that overrides it via
  custom properties. ~350 lines of CSS already reference the current token
  names (`--bg --panel --panel2 --border --text --muted --accent --green
  --amber --red --blue --term-bg --term-fg --shadow --elev-1..3`), and JS
  reads some of them for canvas drawing. A proposal that keeps compatible
  token names is cheaper to adopt.
- Responsive down to 375px (the sidebar becomes a bottom bar on mobile).

## Current state (why we're redesigning)

Two conflicting palettes are stacked: a legacy cool slate/cyan dark theme,
overridden by a warm "Brass & Ember" layer (ink background, brass gold,
serif display type, letterspaced small-caps eyebrows). The result reads
generic-admin-template underneath a costume: the accent hits every element
equally, there is no hero, and the five identical KPI boxes are the most
templated element on the page. We want a sharp turn, not a retouch.

## Deliverable format (follow exactly, so proposals are comparable)

1. **Identity in one paragraph** — what this office world *is*, and the one
   memorable element (the "signature moment").
2. **Palette** — full token sheet as hex values for both shifts
   (day/night): surfaces, borders, text, accent, the four status colors,
   terminal pane, shadows. Note which tokens map onto the existing names
   listed above.
3. **Typography** — system stacks only; roles (display/UI/mono), sizes,
   weights, how the "game" feel is achieved without a pixel font.
4. **The office world** — how each screen maps onto the metaphor
   (dashboard floor plan, map, roster, memos, filing cabinet, guard at the
   door for lockdown, terminal for diagnostics). Include a small ASCII
   wireframe of the new Dashboard showing the asymmetric hero.
5. **Character/state system** — how an employee/character communicates
   online / warning / offline / blocked / "this is you" / trusted-during-
   lockdown, without relying on color alone.
6. **Motion inventory** — 5–8 named motions max (e.g. typing bob, memo
   drop), each with its reduced-motion fallback.
7. **What explicitly stays plain** — name the parts you deliberately keep
   quiet and boring so the theme doesn't exhaust the eye.
8. **Adoption cost** — which of the 6 screens need structural changes vs.
   a palette/CSS-only pass.
9. **Appendix (optional)** — your alternative interpretation of "2D office
   management", in ≤10 lines.

Be concrete: hex values, pixel sizes, class-level descriptions. No
"consider using..." — decide and state it. Avoid the tired defaults of
AI-generated design (near-black + one acid green, generic rounded cards
with soft gray shadows, gradient washes, ALL-CAPS eyebrow labels on
everything, single-word colored headline accents).
