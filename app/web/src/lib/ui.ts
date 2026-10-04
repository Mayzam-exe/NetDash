import type { Conn, Device } from '../types';
import { displayState, state } from '../state';
import { postDevice } from '../api';

/* ---------- generic helpers ---------- */

export const $ = <T extends Element = HTMLElement>(
  s: string,
  r: ParentNode = document,
): T | null => r.querySelector<T>(s);

export const $$ = <T extends Element = HTMLElement>(
  s: string,
  r: ParentNode = document,
): T[] => Array.from(r.querySelectorAll<T>(s));

export const clamp = (v: number, a: number, b: number) =>
  Math.min(b, Math.max(a, v));

export const esc = (s: unknown) =>
  String(s).replace(
    /[&<>"']/g,
    c =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[
        c
      ] as string),
  );

export const cssVar = (n: string) =>
  getComputedStyle(document.documentElement).getPropertyValue(n).trim();

export const fmtM = (v: number) => (v >= 10 ? String(Math.round(v)) : v.toFixed(1));

// fmtSpeed renders a kbit/s cap: 0 = unlimited, 5000 = "5 Mb/s", 600 = "600 kbit/s".
export const fmtSpeed = (k: number) =>
  k <= 0 ? 'unlimited' : k >= 1000 ? String(Math.round(k / 100) / 10) + ' Mb/s' : k + ' kbit/s';

export function relTime(ts: number): string {
  const s = Math.max(1, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return s + 's ago';
  const m = Math.round(s / 60);
  if (m < 60) return m + 'm ago';
  const h = Math.round(m / 60);
  if (h < 24) return h + 'h ago';
  return Math.round(h / 24) + 'd ago';
}

export function dur(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return d + 'd ' + h + 'h';
  if (h > 0) return h + 'h ' + m + 'm';
  return m + 'm';
}

export const uptimeOf = (d: Device) =>
  d.firstSeen ? dur(Date.now() - Date.parse(d.firstSeen)) : '—';

export const lastSeenOf = (d: Device) =>
  d.lastSeen ? relTime(Date.parse(d.lastSeen)) : 'unknown';

export const hostnameOf = (name: string) =>
  name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');

export const val = (id: string): string =>
  (document.getElementById(id) as HTMLInputElement | null)?.value ?? '';

export const checked = (id: string): boolean =>
  (document.getElementById(id) as HTMLInputElement | null)?.checked ?? false;

/* ---------- icons ---------- */

export type Kind =
  | 'phone'
  | 'laptop'
  | 'desktop'
  | 'tv'
  | 'camera'
  | 'speaker'
  | 'thermostat'
  | 'printer'
  | 'hub'
  | 'console'
  | 'tablet'
  | 'router'
  | 'unknown';

export const ICONS: Record<Kind, string> = {
  phone:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="6.5" y="2.5" width="11" height="19" rx="2.5"/><path d="M10.5 18.5h3"/></svg>',
  laptop:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="4" y="4.5" width="16" height="11" rx="1.5"/><path d="M2.5 19h19"/></svg>',
  desktop:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="3" y="3.5" width="18" height="12.5" rx="1.5"/><path d="M9 20.5h6M12 16v4.5"/></svg>',
  tv: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="2.5" y="4.5" width="19" height="13" rx="2"/><path d="M8 21h8"/></svg>',
  camera:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="2.5" y="6.5" width="19" height="12" rx="2.5"/><circle cx="12" cy="12.5" r="3.2"/></svg>',
  speaker:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="6" y="2.5" width="12" height="19" rx="3"/><circle cx="12" cy="15" r="3.4"/><circle cx="12" cy="7" r="1.4"/></svg>',
  thermostat:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="3.5"/></svg>',
  printer:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M7 8V3h10v5"/><rect x="3" y="8" width="18" height="8" rx="2"/><rect x="7" y="14" width="10" height="7"/></svg>',
  hub: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><circle cx="12" cy="12" r="3"/><path d="M6.5 6.5a7.8 7.8 0 0 0 0 11M17.5 6.5a7.8 7.8 0 0 1 0 11"/></svg>',
  console:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="2.5" y="7" width="19" height="10" rx="4"/><path d="M7 10.5v3M5.5 12h3"/><circle cx="16" cy="11" r="1"/><circle cx="18.5" cy="13.5" r="1"/></svg>',
  tablet:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="4.5" y="2.5" width="15" height="19" rx="2.5"/><path d="M10.5 18.5h3"/></svg>',
  router:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 16.5h.01M11 16.5h.01M12 13V9M12 9a4 4 0 0 1 4-4M12 9a4 4 0 0 0-4-4"/></svg>',
  unknown:
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-dasharray="3 2"><rect x="5" y="4" width="14" height="16" rx="2.5"/><path d="M10 9.5a2 2 0 1 1 2.6 1.9c-.4.2-.6.5-.6 1v.6M12 16h.01"/></svg>',
};

/** Human labels for kind ids (order matches the Type select). */
export const KIND_OPTIONS: Array<[string, string]> = [
  ['', 'Auto'],
  ['phone', 'Phone'],
  ['laptop', 'Laptop'],
  ['desktop', 'Desktop'],
  ['tablet', 'Tablet'],
  ['tv', 'TV'],
  ['camera', 'Camera'],
  ['speaker', 'Speaker'],
  ['thermostat', 'Thermostat'],
  ['printer', 'Printer'],
  ['hub', 'Hub / IoT'],
  ['console', 'Console'],
  ['router', 'Router'],
  ['unknown', 'Unknown'],
];

export function kindLabel(k: string): string {
  for (const [id, label] of KIND_OPTIONS) if (id === k) return label;
  return 'Unknown';
}

export const SUN =
  '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="8" r="3"/><path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.1 3.1l1.4 1.4M11.5 11.5l1.4 1.4M12.9 3.1l-1.4 1.4M4.5 11.5l-1.4 1.4"/></svg>';
export const MOON =
  '<svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M13.5 9.5A5.8 5.8 0 0 1 6.5 2.5a5.8 5.8 0 1 0 7 7Z"/></svg>';

/* ---------- device vocabulary ---------- */

export function connLabel(c: Conn): string {
  return c === 'wifi5'
    ? 'Wi-Fi 5 GHz'
    : c === 'wifi2'
      ? 'Wi-Fi 2.4 GHz'
      : c === 'eth'
        ? 'Ethernet'
        : 'Unknown';
}

export const stateLabel = (st: string) =>
  st === 'on' || st === 'online'
    ? 'Connected'
    : st.charAt(0).toUpperCase() + st.slice(1);

/** Prefer the backend's persisted kind; fall back to a name/vendor heuristic
 *  for rows stored before type inference existed. Unknown stays unknown. */
export function deviceKind(d: Device): Kind {
  if (d.kind && Object.prototype.hasOwnProperty.call(ICONS, d.kind)) return d.kind as Kind;
  const s = (d.name + ' ' + d.vendor).toLowerCase();
  if (/thermostat|ecobee|nest [a-z]*temp/.test(s)) return 'thermostat';
  if (/cam|camera|doorbell|nvr/.test(s)) return 'camera';
  if (/\btv\b|television|display|roku|chromecast/.test(s)) return 'tv';
  if (/printer|canon|epson|brother/.test(s)) return 'printer';
  if (/tablet|ipad|\btab\b/.test(s)) return 'tablet';
  if (/phone|iphone|pixel|galaxy|mobile|android/.test(s)) return 'phone';
  if (/laptop|macbook|notebook|thinkpad|xps/.test(s)) return 'laptop';
  if (/workstation|desktop|\bpc\b|raspberry/.test(s)) return 'desktop';
  if (/speaker|sonos|echo|homepod|audio/.test(s)) return 'speaker';
  if (/hub|bridge|hue|philips|zigbee/.test(s)) return 'hub';
  if (/playstation|\bps\d\b|xbox|console|switch/.test(s)) return 'console';
  return 'unknown';
}

export function subline(d: Device): string {
  const st = displayState(d);
  if (st === 'offline') return '<span>Last seen ' + lastSeenOf(d) + '</span>';
  if (st === 'blocked') return '<span class="blk-text">Blocked by you</span>';
  if (st === 'warning')
    return (
      '<span class="warn-text">' +
      (d.signal != null && d.signal < -77
        ? 'Weak signal ' + d.signal + ' dBm'
        : 'Needs attention') +
      '</span>'
    );
  const kind =
    d.kind && Object.prototype.hasOwnProperty.call(ICONS, d.kind)
      ? kindLabel(d.kind) + ' · '
      : '';
  const cap =
    d.speedDown || d.speedUp
      ? ' · <span class="warn-text">capped ' +
        fmtSpeed(d.speedDown) +
        ' ↓ / ' +
        fmtSpeed(d.speedUp) +
        ' ↑</span>'
      : '';
  const watch = d.watched
    ? ' · <span class="warn-text">watching</span>'
    : '';
  return (
    kind +
    esc(d.vendor || 'Unknown vendor') +
    ' · ' +
    connLabel(d.conn) +
    cap +
    watch +
    (d.self ? ' · <span class="blk-text">this machine</span>' : '')
  );
}

export function sigHtml(d: Device): string {
  if (d.conn === 'eth') return '<span class="sig-txt">▪ Wired</span>';
  if (displayState(d) === 'offline') return '<span class="sig-txt">—</span>';
  if (d.signal == null)
    return '<span class="sig-txt" title="The router does not report client Wi-Fi signal">—</span>';
  const s = d.signal;
  const lvl = s >= -55 ? 4 : s >= -65 ? 3 : s >= -75 ? 2 : 1;
  const col = s >= -65 ? 'var(--green)' : s >= -75 ? 'var(--amber)' : 'var(--red)';
  let bars = '';
  for (let i = 1; i <= 4; i++) bars += '<i class="' + (i <= lvl ? 'on' : '') + '"></i>';
  return (
    '<span class="sig" style="--sg:' + col + '">' + bars + '</span>' +
    '<span class="sig-txt">' + s + '</span>'
  );
}

export function thrHtml(d: Device): string {
  const st = displayState(d);
  if (st === 'offline' || st === 'blocked') return '<span class="sig-txt">—</span>';
  const metering = state.status?.metering ?? '';
  if (d.self)
    return (
      '<span class="thr" title="this machine · measured locally"><span class="dn">↓ ' +
      fmtM(d.down) +
      '</span>&nbsp;&nbsp;<span class="up">↑ ' +
      fmtM(d.up) +
      '</span></span>'
    );
  if (metering !== 'active') {
    return '<span class="sig-txt" title="' + esc(metering || 'metering unavailable') + '">—</span>';
  }
  return (
    '<span class="thr"><span class="dn">↓ ' +
    fmtM(d.down) +
    '</span>&nbsp;&nbsp;<span class="up">↑ ' +
    fmtM(d.up) +
    '</span></span>'
  );
}

/* ---------- navigation ---------- */

export function goTab(devId: number, tab: string): void {
  location.hash = '#/device/' + devId + '/' + tab;
}

/* ---------- toasts / modal / copy ---------- */

export function toast(msg: string, kind?: 'err' | 'warn'): void {
  const t = document.createElement('div');
  t.className = 'toast' + (kind ? ' ' + kind : '');
  t.textContent = msg;
  document.getElementById('toasts')?.appendChild(t);
  setTimeout(() => t.remove(), 3200);
}

export function confirmModal(
  title: string,
  body: string,
  okLabel: string,
  danger: boolean,
  onOk: () => void,
): void {
  const root = document.getElementById('modalRoot');
  if (!root) return;
  root.innerHTML =
    '<div class="modal-back"><div class="modal">' +
    '<h3>' + esc(title) + '</h3><p>' + esc(body) + '</p>' +
    '<div class="m-actions"><button class="btn" data-m="cancel">Cancel</button>' +
    '<button class="btn ' + (danger ? 'danger' : 'primary') + '" data-m="ok">' +
    esc(okLabel) + '</button></div>' +
    '</div></div>';
  const cancel = root.querySelector<HTMLElement>('[data-m="cancel"]');
  const ok = root.querySelector<HTMLElement>('[data-m="ok"]');
  const back = root.querySelector<HTMLElement>('.modal-back');
  if (cancel) cancel.onclick = () => { root.innerHTML = ''; };
  if (ok) ok.onclick = () => { root.innerHTML = ''; onOk(); };
  if (back) back.onclick = e => { if (e.target === e.currentTarget) root.innerHTML = ''; };
}

/* Speed-limit quick editor: two kbit/s fields + Apply / Unlimited / Cancel. */
export function speedModal(d: Device, onSaved?: () => void): void {
  const root = document.getElementById('modalRoot');
  if (!root) return;
  const cur = (v: number) => (v > 0 ? String(v) : '');
  root.innerHTML =
    '<div class="modal-back"><div class="modal">' +
    '<h3>Speed limit — ' + esc(d.name || d.ip) + '</h3>' +
    '<p>Cap in kilobits per second. Leave blank or 0 for unlimited. Both directions are capped independently.</p>' +
    '<div class="speed-row" style="display:flex;gap:10px;flex-wrap:wrap">' +
    '<label style="flex:1;min-width:120px">Download (kbit/s)<input class="inp mono" id="spdDown" type="number" min="0" max="10000000" placeholder="unlimited" value="' +
    cur(d.speedDown) + '"></label>' +
    '<label style="flex:1;min-width:120px">Upload (kbit/s)<input class="inp mono" id="spdUp" type="number" min="0" max="10000000" placeholder="unlimited" value="' +
    cur(d.speedUp) + '"></label>' +
    '</div>' +
    '<div class="m-actions">' +
    '<button class="btn" data-m="cancel">Cancel</button>' +
    '<button class="btn" data-m="unlimited">Unlimited</button>' +
    '<button class="btn primary" data-m="apply">Apply</button>' +
    '</div></div></div>';
  const close = () => { root.innerHTML = ''; };
  const back = root.querySelector<HTMLElement>('.modal-back');
  if (back) back.onclick = e => { if (e.target === e.currentTarget) close(); };
  root.querySelector<HTMLElement>('[data-m="cancel"]')!.onclick = close;
  const send = (speedDown: number, speedUp: number): void => {
    postDevice(d.id, { speedDown, speedUp })
      .then(() => {
        close();
        toast(
          speedDown || speedUp
            ? 'Limit set: ' + (speedDown ? fmtSpeed(speedDown) + ' down' : 'no down cap') +
              (speedUp ? ', ' + fmtSpeed(speedUp) + ' up' : ', no up cap')
            : 'Speed limit cleared',
        );
        onSaved?.();
      })
      .catch(e => toast(e instanceof Error ? e.message : 'Could not set speed limit', 'err'));
  };
  root.querySelector<HTMLElement>('[data-m="unlimited"]')!.onclick = () => send(0, 0);
  root.querySelector<HTMLElement>('[data-m="apply"]')!.onclick = () => {
    const down = Math.max(0, Math.floor(Number(root.querySelector<HTMLInputElement>('#spdDown')?.value) || 0));
    const up = Math.max(0, Math.floor(Number(root.querySelector<HTMLInputElement>('#spdUp')?.value) || 0));
    send(down, up);
  };
  root.querySelector<HTMLInputElement>('#spdDown')?.focus();
}

export function copyText(v: string): void {
  const done = () => toast('Copied ' + v);
  const fallback = () => {
    const ta = document.createElement('textarea');
    ta.value = v;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      done();
    } catch {
      toast('Copy failed', 'err');
    }
    ta.remove();
  };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(v).then(done, fallback);
  } else fallback();
}

/* ---------- context menu ---------- */

export function closeMenu(): void {
  document.getElementById('ctxmenu')?.remove();
}

export function openMenu(btn: HTMLElement, d: Device): void {
  closeMenu();
  const m = document.createElement('div');
  m.className = 'menu';
  m.id = 'ctxmenu';
  m.innerHTML =
    '<button data-action="quick-ping" data-id="' + d.id + '">Ping</button>' +
    '<button data-action="copy" data-value="' + esc(d.ip) + '">Copy IP</button>' +
    '<button data-action="copy" data-value="' + esc(d.mac) + '">Copy MAC</button>' +
    '<button data-action="rename" data-id="' + d.id + '">Rename</button>' +
    '<div class="sep"></div>' +
    (d.self
      ? '<button data-action="troubleshoot" data-id="' + d.id + '">Troubleshoot</button>'
      : (d.blocked
          ? '<button data-action="unblock" data-id="' + d.id + '">Allow internet</button>'
          : '<button data-action="block" data-id="' + d.id + '">Pause internet</button>') +
        '<button data-action="speed" data-id="' + d.id + '">Speed limit…</button>' +
        (d.watched
          ? '<button data-action="intercept" data-id="' + d.id + '">Stop intercepting</button>'
          : '<button data-action="intercept" data-id="' + d.id + '">Intercept traffic</button>') +
        '<button data-action="troubleshoot" data-id="' + d.id + '">Troubleshoot</button>' +
        '<div class="sep"></div>' +
        '<button class="danger" data-action="forget" data-id="' + d.id + '">Forget device</button>');
  document.body.appendChild(m);
  const r = btn.getBoundingClientRect();
  m.style.top =
    Math.min(r.bottom + 4, window.innerHeight - m.offsetHeight - 8) + 'px';
  m.style.left =
    Math.max(8, Math.min(r.left - 150, window.innerWidth - m.offsetWidth - 8)) +
    'px';
}

/* ---------- command palette (Ctrl/Cmd+K) ---------- */

export function openCmdk(): void {
  const root = document.getElementById('cmdk');
  const inp = document.getElementById('cmdkInput') as HTMLInputElement | null;
  if (!root || !inp) return;
  root.classList.remove('hidden');
  inp.value = '';
  state.cmdkSel = 0;
  renderCmdk('');
  setTimeout(() => inp.focus(), 0);
}

export function closeCmdk(): void {
  document.getElementById('cmdk')?.classList.add('hidden');
}

export const cmdkOpen = () =>
  !document.getElementById('cmdk')?.classList.contains('hidden');

export function renderCmdk(q: string): void {
  const query = q.trim().toLowerCase();
  state.cmdkResults = state.devices
    .filter(
      d =>
        !query ||
        d.name.toLowerCase().includes(query) ||
        d.ip.includes(query) ||
        d.mac.toLowerCase().includes(query),
    )
    .slice(0, 8);
  if (state.cmdkSel >= state.cmdkResults.length) state.cmdkSel = 0;
  const list = document.getElementById('cmdkList');
  if (!list) return;
  list.innerHTML = state.cmdkResults.length
    ? state.cmdkResults
        .map(
          (d, i) =>
            '<button class="cmdk-item' +
            (i === state.cmdkSel ? ' sel' : '') +
            '" role="option" aria-selected="' +
            (i === state.cmdkSel) +
            '" id="cmdk-opt-' +
            i +
            '" data-cmdk="' + d.id + '">' +
            '<span class="dot ' + displayState(d) + '"></span>' +
            '<span><span class="ci-name">' + esc(d.name) + '</span><br>' +
            '<span class="ci-meta">' + esc(d.ip) + ' · ' + esc(d.mac) + '</span></span>' +
            '<span class="ci-right">' + connLabel(d.conn) + '</span></button>',
        )
        .join('')
    : '<div class="empty">No devices found.</div>';
  // a11y: combobox points at the active option
  const inp = document.getElementById('cmdkInput');
  if (inp) {
    inp.setAttribute(
      'aria-activedescendant',
      state.cmdkResults.length ? 'cmdk-opt-' + state.cmdkSel : '',
    );
  }
}

export function cmdkGo(): void {
  const d = state.cmdkResults[state.cmdkSel];
  if (d) {
    closeCmdk();
    location.hash = '#/device/' + d.id + '/overview';
  }
}
