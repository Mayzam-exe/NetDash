import './style.css';
import './tokens.css';

import {
  ackAlert,
  addSpoof,
  delSpoof,
  deleteDevice,
  getIntel,
  getSettings,
  getSnapshot,
  listSpoof,
  openStream,
  postDevice,
  putSettings,
} from './api';
import { refreshCharts } from './lib/charts';
import { atlasFit, atlasKeyZoom, atlasResize, mountAtlas, unmountAtlas } from './lib/atlas';
import {
  MOON,
  SUN,
  clamp,
  cmdkGo,
  cmdkOpen,
  closeCmdk,
  closeMenu,
  confirmModal,
  copyText,
  esc,
  fmtM,
  goTab,
  openCmdk,
  openMenu,
  renderCmdk,
  speedModal,
  toast,
} from './lib/ui';
import { applySnapshot, counts, findDevice, gatewayIp, hostDown, hostPeakDown, hostUp, latencyGateway, latencyWan, state, subscribe } from './state';
import type { Prefs } from './state';
import type { Settings } from './types';
import { dashboardView } from './views/dashboard';
import { deviceView, mergeDevice, restoreScan, runDiag, saveDevice } from './views/device';
import { devicesView } from './views/devices';
import { atlasHud, mapView } from './views/map';
import { discardSettings, saveSettings, settingsView } from './views/settings';
import { h, render as renderPreact } from 'preact';
import { AlertsApp } from './views/alerts.app';
import { alertFilterSig, syncSignals, uiTick } from './signals';

const TITLES: Record<string, string> = {
  dashboard: 'Dashboard',
  map: 'Network Map',
  devices: 'Devices',
  alerts: 'Alerts',
  settings: 'Settings',
  device: 'Device',
};

const MAIN_VIEWS = ['dashboard', 'map', 'devices', 'alerts', 'settings'];

/* ---------- routing & rendering ---------- */

function route(): void {
  const hash = location.hash.replace(/^#/, '') || '/dashboard';
  const parts = hash.split('/').filter(Boolean);
  closeMenu();
  if (parts[0] === 'device' && parts[1]) {
    state.view = 'device';
    state.devId = Number(parts[1]);
    if (parts[2]) state.tab = parts[2];
  } else {
    const v = parts[0] || 'dashboard';
    state.view = (MAIN_VIEWS.includes(v) ? v : 'dashboard') as typeof state.view;
    state.devId = null;
  }
  render();
  if (state.view === 'device' && state.tab === 'intel') void loadIntel();
  if (state.view === 'device' && state.tab === 'troubleshoot') void restoreScan(state.devId ?? -1);
}

/** True while a Preact view owns #view's subtree (see render()). */
let preactMounted = false;

function render(preserveScroll = false): void {
  const view = document.getElementById('view');
  if (!view) return;
  syncSignals(state); // keep Preact signals aligned with legacy mutations
  const scroll0 = view.scrollTop;
  const tbl0 = view.querySelector('.tbl-scroll')?.scrollTop ?? 0;
  const prev = document.activeElement as HTMLElement | null;
  const focusKey =
    preserveScroll && prev && view.contains(prev) ? keyFor(prev) : null;
  // Preact-mounted views re-render themselves from signals; the rest are still
  // built as HTML strings. Only one mode can own #view at a time.
  if (state.view === 'alerts') {
    if (preactMounted) {
      uiTick.value = uiTick.value + 1; // force a fresh pass for this render()
    } else {
      view.innerHTML = '';
      renderPreact(h(AlertsApp, {}), view);
      preactMounted = true;
    }
  } else {
    if (preactMounted) {
      renderPreact(null, view); // unmount before taking over innerHTML
      preactMounted = false;
    }
    let html = '';
    switch (state.view) {
      case 'dashboard': html = dashboardView(); break;
      case 'map': html = mapView(); break;
      case 'devices': html = devicesView(); break;
      case 'settings': html = settingsView(); break;
      case 'device': html = deviceView(); break;
      default: html = dashboardView();
    }
    view.innerHTML = html;
  }
  view.classList.toggle('map-mode', state.view === 'map');
  const title = document.getElementById('pageTitle');
  if (title) {
    title.textContent =
      state.view === 'device'
        ? (state.devId != null ? findDevice(state.devId)?.name || 'Device' : 'Device')
        : TITLES[state.view] || 'Dashboard';
  }
  for (const n of document.querySelectorAll<HTMLElement>('.nav-item')) {
    const href = n.getAttribute('data-href');
    const active =
      href === '#/' + state.view || (state.view === 'device' && href === '#/devices');
    n.classList.toggle('active', active);
  }
  updateBadge();
  refreshCharts();
  if (state.view === 'map') {
    mountAtlas();
    atlasHud();
  } else {
    unmountAtlas();
  }
  if (state.focusSearch) {
    const s = document.getElementById('devSearch') as HTMLInputElement | null;
    if (s) {
      s.focus();
      s.setSelectionRange(s.value.length, s.value.length);
    }
    state.focusSearch = false;
  }
  if (state.pendingDiag) {
    const pd = state.pendingDiag;
    state.pendingDiag = null;
    setTimeout(() => runDiag(pd.id, pd.kind), 60);
  }
  if (preserveScroll) {
    view.scrollTop = scroll0;
    const tbl = view.querySelector('.tbl-scroll');
    if (tbl) tbl.scrollTop = tbl0;
  }
  if (focusKey) {
    const el = view.querySelector<HTMLElement>(focusKey);
    if (el) el.focus({ preventScroll: true });
  }
  updateLiveDom();
}

/** Stable selector for the focused element so live re-renders keep focus. */
function keyFor(el: HTMLElement): string | null {
  if (el.id) return '#' + el.id;
  const action = el.dataset.action;
  if (!action) return null;
  let sel = '[data-action="' + action + '"]';
  for (const k of ['id', 'tab', 'filter', 'key', 'href', 'diag', 'value']) {
    const v = el.dataset[k];
    if (v != null) sel += '[data-' + k + '="' + v + '"]';
  }
  return sel;
}

function updateBadge(): void {
  const n = unread();
  const b = document.getElementById('navAlertBadge');
  if (!b) return;
  b.style.display = n ? '' : 'none';
  b.textContent = String(n);
}

function updateRailFoot(): void {
  const el = document.getElementById('railFoot');
  if (!el) return;
  const st = state.status;
  const ssid = state.settings.ssid24 || 'HomeNet';
  const up = st && st.startedAt ? Math.max(0, Date.now() - Date.parse(st.startedAt)) : -1;
  const upStr = up >= 0 ? fmtDays(up) : '—';
  el.innerHTML =
    esc(ssid) + ' · ' + esc(gatewayIp()) + '<br>' +
    esc(st ? st.version : '…') + ' · uptime ' + esc(upStr);
}

function fmtDays(ms: number): string {
  const d = Math.floor(ms / 86400000);
  const h = Math.floor((ms % 86400000) / 3600000);
  if (d > 0) return d + 'd ' + h + 'h';
  const m = Math.floor((ms % 3600000) / 60000);
  if (h > 0) return h + 'h ' + m + 'm';
  return Math.max(1, m) + 'm';
}

function updateLiveDom(): void {
  const td = hostDown();
  const tu = hostUp();
  const lat = latencyWan();
  const gw = latencyGateway();
  const wanUp = lat >= 0;
  const set = (id: string, v: string) => {
    const el = document.getElementById(id);
    if (el) el.textContent = v;
  };
  const dot = document.getElementById('kpiWanDot');
  if (dot) dot.className = 'dot ' + (wanUp ? 'on' : 'critical');
  set('kpiWanState', wanUp ? 'Online' : 'Offline');
  set(
    'kpiGwSub',
    'Gateway ' + gatewayIp() + ' · ' + (gw >= 0 ? Math.round(gw) + ' ms' : '—') +
      ' · click to test',
  );
  set('kpiLat', wanUp ? String(Math.round(lat)) : '—');
  set('kpiLatSub', wanUp ? 'to 1.1.1.1 · 0% loss' : 'no reply from 1.1.1.1');
  set('kpiDown', fmtM(td));
  set('kpiUp', fmtM(tu));
  set('kpiPeak', fmtM(hostPeakDown()));
  set('kpiAlerts', String(unread()));
  set('kpiAlertsSub', unread() ? 'needs attention' : 'all clear');
  const c = counts();
  set('kpiDevOn', String(c.connected));
  set('chipOnline', c.online + ' online');
  set('chipWarn', c.warning + ' warn');
  set('chipOff', c.offline + c.blocked + ' off/blk');
  set('bwNow', '↓ ' + fmtM(td) + ' · ↑ ' + fmtM(tu));
  const bwMax = document.getElementById('bwMax');
  if (bwMax && state.series.down.length) {
    bwMax.textContent = 'peak ' + fmtM(Math.max(...state.series.down)) + ' Mb/s';
  }
  updateRailFoot();
  if (state.view === 'map') atlasHud(td, tu);
  for (const fn of state.charts) fn();
}

const unread = () => state.alerts.filter(a => !a.read && !state.readIds.has(a.id)).length;

function uiBusy(): boolean {
  const root = document.getElementById('modalRoot');
  if (root && root.children.length > 0) return true;
  if (cmdkOpen()) return true;
  const ae = document.activeElement as HTMLElement | null;
  if (
    ae &&
    (ae.tagName === 'INPUT' ||
      ae.tagName === 'TEXTAREA' ||
      ae.tagName === 'SELECT' ||
      ae.isContentEditable)
  )
    return true;
  return false;
}

/** Called on every SSE snapshot: refresh live DOM, re-render only when safe. */
function liveUpdate(): void {
  updateLiveDom();
  if (state.view === 'map') return;
  if (uiBusy()) return;
  render(true);
}

/* ---------- theme ---------- */

function applyTheme(): void {
  try {
    const saved = localStorage.getItem('netdash-theme');
    if (saved) document.documentElement.setAttribute('data-theme', saved);
  } catch {
    /* storage unavailable */
  }
  const btn = document.getElementById('themeBtn');
  if (btn)
    btn.innerHTML =
      document.documentElement.getAttribute('data-theme') === 'light' ? SUN : MOON;
}

function toggleTheme(): void {
  const cur = document.documentElement.getAttribute('data-theme');
  const next = cur === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  const btn = document.getElementById('themeBtn');
  if (btn) btn.innerHTML = next === 'dark' ? MOON : SUN;
  try {
    localStorage.setItem('netdash-theme', next);
  } catch {
    /* storage unavailable */
  }
  refreshCharts();
}

/* ---------- device mutations ---------- */

async function setBlocked(id: number, blocked: boolean): Promise<void> {
  const d = findDevice(id);
  if (!d) return;
  try {
    const upd = await postDevice(id, { blocked });
    mergeDevice(upd);
    toast(
      (upd.name || d.name) + (blocked ? ' blocked from the internet' : ' internet access restored'),
      blocked ? 'warn' : undefined,
    );
  } catch (e) {
    toast(e instanceof Error ? e.message : 'Could not update the device', 'err');
  }
  render();
}

function exportConfig(): void {
  const blob = new Blob(
    [
      JSON.stringify(
        {
          settings: state.settings,
          prefs: state.prefs,
          devices: state.devices.map(d => ({
            name: d.name,
            ip: d.ip,
            mac: d.mac,
            reserved: d.reserved,
          })),
        },
        null,
        2,
      ),
    ],
    { type: 'application/json' },
  );
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'netdash-config.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  toast('Configuration exported');
}

async function handleImport(e: Event): Promise<void> {
  const input = e.target as HTMLInputElement;
  const f = input.files && input.files[0];
  if (!f) return;
  try {
    const data = JSON.parse(await f.text()) as {
      settings?: Partial<Settings>;
      prefs?: Partial<Prefs>;
    };
    if (data.settings) {
      state.settings = { ...state.settings, ...data.settings };
      try {
        state.settings = await putSettings(state.settings);
      } catch {
        toast('Imported locally — could not push settings to the API', 'warn');
      }
    }
    if (data.prefs) state.prefs = { ...state.prefs, ...data.prefs };
    toast('Configuration imported');
    render();
  } catch {
    toast('Invalid configuration file', 'err');
  }
  input.value = '';
}

/* ---------- click delegation ---------- */

async function handleClick(e: MouseEvent): Promise<void> {
  const t = e.target as HTMLElement | null;
  const cmdkItem = t?.closest('[data-cmdk]') as HTMLElement | null;
  if (cmdkItem) {
    state.cmdkSel = state.cmdkResults.findIndex(
      d => d.id === Number(cmdkItem.dataset.cmdk),
    );
    cmdkGo();
    return;
  }
  const el = t?.closest('[data-action]') as HTMLElement | null;
  if (!el) {
    closeMenu();
    return;
  }
  const a = el.dataset.action || '';
  const id = Number(el.dataset.id);
  if (a !== 'menu') closeMenu();

  switch (a) {
    case 'nav':
      location.hash = el.dataset.href || '#/dashboard';
      break;
    case 'open-device':
      location.hash = '#/device/' + id + '/overview';
      break;
    case 'tab':
      state.tab = el.dataset.tab || 'overview';
      render();
      if (state.tab === 'intel') void loadIntel();
      if (state.tab === 'troubleshoot') void restoreScan(state.devId ?? -1);
      break;
    case 'copy':
      copyText(el.dataset.value || '');
      break;
    case 'filter':
      state.filter = el.dataset.filter || 'all';
      state.focusSearch = false;
      render();
      break;
    case 'sort': {
      const k = el.dataset.key || 'name';
      if (state.sort.key === k) state.sort.dir *= -1;
      else state.sort = { key: k, dir: 1 };
      render();
      break;
    }
    case 'menu': {
      e.stopPropagation();
      const d = findDevice(id);
      if (d) openMenu(el, d);
      break;
    }
    case 'alert-filter':
      state.alertFilter = el.dataset.filter || 'all';
      alertFilterSig.value = state.alertFilter; // Preact view reads this
      render();
      break;
    case 'dismiss-alert':
      state.readIds.add(id);
      ackAlert(id).catch(() => {});
      render();
      toast('Alert dismissed');
      break;
    case 'open-alert': {
      const al = state.alerts.find(x => x.id === id);
      if (al) {
        state.readIds.add(al.id);
        ackAlert(al.id).catch(() => {});
      }
      if (al && al.devId != null) goTab(al.devId, 'troubleshoot');
      else render();
      updateBadge();
      break;
    }
    case 'open-cmdk':
      openCmdk();
      break;
    case 'toggle-theme':
      toggleTheme();
      break;
    case 'wan-test': {
      const wanIp = state.status ? state.status.wanIp : 'the WAN';
      const lat = latencyWan();
      if (lat >= 0)
        toast('WAN OK · ' + wanIp + ' replied in ' + Math.round(lat) + ' ms · 0% loss');
      else toast('WAN unreachable — no reply from ' + wanIp, 'err');
      break;
    }
    case 'quick-ping':
      goTab(id, 'troubleshoot');
      state.pendingDiag = { id, kind: 'ping' };
      break;
    case 'locate':
      state.atlasFocus = id;
      location.hash = '#/map';
      break;
    case 'troubleshoot':
      goTab(id, 'troubleshoot');
      break;
    case 'rename':
      goTab(id, 'settings');
      setTimeout(() => {
        const n = document.getElementById('dnName') as HTMLInputElement | null;
        if (n) {
          n.focus();
          n.select();
        }
      }, 80);
      break;
    case 'diag':
      runDiag(id, el.dataset.diag || 'ping');
      break;
    case 'restart-radio':
      runDiag(id, 'restart');
      break;
    case 'block': {
      const d = findDevice(id);
      confirmModal(
        'Block ' + (d ? d.name : 'this device') + '?',
        'The device keeps its Wi-Fi connection but loses internet access until you allow it again.',
        'Block internet',
        true,
        () => {
          void setBlocked(id, true);
        },
      );
      break;
    }
    case 'unblock':
      void setBlocked(id, false);
      break;
    case 'speed': {
      const d = findDevice(id);
      if (d) speedModal(d, () => render());
      break;
    }
    case 'intercept': {
      const d = findDevice(id);
      if (!d) break;
      if (d.watched) {
        void setWatched(id, false);
      } else {
        confirmModal(
          'Intercept ' + (d.name || d.ip) + '?',
          'Traffic is routed through this machine so DNS lookups, TLS SNI and HTTP hosts are logged on the Intel tab. The device keeps working normally.',
          'Start intercepting',
          false,
          () => {
            void setWatched(id, true);
          },
        );
      }
      break;
    }
    case 'refresh-intel':
      void loadIntel(true);
      break;
    case 'spoof-add': {
      const dom = (document.getElementById('spoofDomain') as HTMLInputElement | null)?.value ?? '';
      const ip = (document.getElementById('spoofIp') as HTMLInputElement | null)?.value ?? '';
      try {
        await addSpoof({ domain: dom, ip });
        state.spoofRules = await listSpoof();
        render();
        toast('Spoof rule added');
      } catch (e) {
        toast(e instanceof Error ? e.message : 'Could not add rule', 'err');
      }
      break;
    }
    case 'spoof-del': {
      try {
        await delSpoof(id);
        state.spoofRules = await listSpoof();
        render();
        toast('Spoof rule removed');
      } catch {
        toast('Could not remove rule', 'err');
      }
      break;
    }
    case 'forget': {
      const d = findDevice(id);
      confirmModal(
        'Forget this device?',
        'NetDash will stop tracking it. The device can rejoin the network and reappear later.',
        'Forget',
        true,
        () => {
          const nm = d ? d.name : 'Device';
          deleteDevice(id)
            .then(() => {
              state.hidden.add(id);
              state.devices = state.devices.filter(x => x.id !== id);
              toast(nm + ' forgotten');
              if (state.view === 'device' && state.devId === id) location.hash = '#/devices';
              else render();
            })
            .catch(e => toast(e instanceof Error ? e.message : 'Could not forget device', 'err'));
        },
      );
      break;
    }
    case 'save-device':
      await saveDevice(id);
      render();
      break;
    case 'discard-device':
      render();
      toast('Changes discarded', 'warn');
      break;
    case 'save-settings':
      await saveSettings();
      render();
      break;
    case 'discard-settings':
      await discardSettings();
      render();
      break;
    case 'fw-check':
      toast(
        'Firmware check unavailable — NetDash does not manage router firmware. Running agent ' +
          (state.status ? state.status.version : ''),
        'warn',
      );
      break;
    case 'export-config':
      exportConfig();
      break;
    case 'import-config':
      document.getElementById('importFile')?.click();
      break;
    case 'reboot':
      toast('Reboot unavailable — NetDash monitors this host and does not restart it', 'warn');
      break;
    case 'factory-reset':
      confirmModal(
        'Factory reset?',
        'ALL settings, reservations and rules will be wiped and the router returns to defaults. This cannot be undone.',
        'Erase everything',
        true,
        () => toast('Factory reset is not available yet', 'err'),
      );
      break;
  }
}

/* ---------- input / keyboard / mouse ---------- */

function handleInput(e: Event): void {
  const t = e.target as HTMLElement;
  if (t.id === 'devSearch') {
    state.search = (t as HTMLInputElement).value;
    state.focusSearch = true;
    render(true);
  } else if (t.id === 'cmdkInput') {
    state.cmdkSel = 0;
    renderCmdk((t as HTMLInputElement).value);
  }
}

function cmdkQuery(): string {
  const inp = document.getElementById('cmdkInput') as HTMLInputElement | null;
  return inp ? inp.value : '';
}

function handleKeydown(e: KeyboardEvent): void {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    if (cmdkOpen()) closeCmdk();
    else openCmdk();
    return;
  }
  if (cmdkOpen()) {
    if (e.key === 'Escape') closeCmdk();
    else if (e.key === 'ArrowDown') {
      e.preventDefault();
      state.cmdkSel = Math.min(state.cmdkSel + 1, state.cmdkResults.length - 1);
      renderCmdk(cmdkQuery());
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      state.cmdkSel = Math.max(state.cmdkSel - 1, 0);
      renderCmdk(cmdkQuery());
    } else if (e.key === 'Enter') {
      e.preventDefault();
      cmdkGo();
    }
    return;
  }
  if (e.key === 'Escape') closeMenu();
  const ae = document.activeElement;
  if (
    state.view === 'map' &&
    !e.ctrlKey &&
    !e.metaKey &&
    !(ae && ae.matches('input, textarea'))
  ) {
    if (e.key === '+' || e.key === '=') {
      e.preventDefault();
      atlasKeyZoom(1.2);
    } else if (e.key === '-') {
      e.preventDefault();
      atlasKeyZoom(1 / 1.2);
    } else if (e.key === '0') {
      e.preventDefault();
      atlasFit();
    }
  }
  if (e.key === 'Enter' && ae && ae.matches('tr[data-action="open-device"]')) {
    location.hash = '#/device/' + (ae as HTMLElement).dataset.id + '/overview';
  }
}

function handleMousemove(e: MouseEvent): void {
  const t = e.target as HTMLElement | null;
  const wrap = t && t.closest ? t.closest('#bwChart') : null;
  const tip = document.getElementById('bwTip');
  if (!tip) return;
  if (!wrap) {
    tip.style.display = 'none';
    return;
  }
  const n = state.series.down.length;
  if (!n) {
    tip.style.display = 'none';
    return;
  }
  const r = wrap.getBoundingClientRect();
  const padL = 38;
  const padR = 8;
  const x = clamp(e.clientX - r.left, padL, r.width - padR);
  const idx = Math.round(((x - padL) / (r.width - padL - padR)) * (n - 1));
  const dn = state.series.down[idx];
  const up = state.series.up[idx];
  if (dn == null) {
    tip.style.display = 'none';
    return;
  }
  tip.style.display = 'block';
  tip.textContent = '−' + (60 - idx) + 's · ↓ ' + fmtM(dn) + ' ↑ ' + fmtM(up) + ' Mb/s';
  tip.style.left = clamp(x + 12, 0, r.width - 170) + 'px';
  tip.style.top = '10px';
}

/* ---------- intercept + intel ---------- */

async function setWatched(id: number, on: boolean): Promise<void> {
  try {
    const upd = await postDevice(id, { watched: on });
    mergeDevice(upd);
    toast(
      on
        ? 'Intercepting ' + (upd.name || upd.ip) + ' — hostnames appear on the Intel tab'
        : 'Intercept stopped',
    );
    if (on) goTab(id, 'intel');
    else render();
  } catch (e) {
    toast(e instanceof Error ? e.message : 'Could not change intercept', 'err');
  }
}

async function loadIntel(force = false): Promise<void> {
  const id = state.devId;
  if (id == null) return;
  if (!force && state.intelDevId === id) return;
  state.intel = [];
  state.intelDevId = id;
  try {
    const items = await getIntel(id);
    if (state.devId !== id) return;
    state.intel = items;
    if (state.view === 'device' && state.tab === 'intel') render(true);
  } catch {
    state.intelDevId = null;
  }
}

/* ---------- boot ---------- */

function bindEvents(): void {
  document.addEventListener('click', e => {
    void handleClick(e as MouseEvent);
  });
  document.addEventListener('input', handleInput);
  document.addEventListener('keydown', handleKeydown);
  document.addEventListener('mousemove', handleMousemove);
  const imp = document.getElementById('importFile') as HTMLInputElement | null;
  if (imp) imp.addEventListener('change', e => void handleImport(e));
}

async function boot(): Promise<void> {
  applyTheme();
  bindEvents();
  window.addEventListener('hashchange', route);
  window.addEventListener('resize', () => {
    refreshCharts();
    atlasResize();
  });
  subscribe(() => {
    updateBadge();
    liveUpdate();
  });
  route();
  try {
    applySnapshot(await getSnapshot());
  } catch {
    toast('API unreachable — start the backend on 127.0.0.1:7420', 'err');
  }
  try {
    state.settings = await getSettings();
    if (state.view === 'settings') render();
    else updateLiveDom();
  } catch {
    /* settings are optional */
  }
  try {
    state.spoofRules = await listSpoof();
    if (state.view === 'settings') render();
  } catch {
    /* spoof rules are optional */
  }
  openStream(applySnapshot, () => {
    /* EventSource reconnects on its own */
  });
  // live-refresh the Intel tab while it is open
  window.setInterval(() => {
    if (state.view === 'device' && state.tab === 'intel' && state.devId != null) {
      void loadIntel(true);
    }
  }, 5000);
}

void boot();
