import { dnsLookupDevice, lastScan, pingDevice, postDevice, renewDHCP, restartRadio, scanDevice, tracerouteDevice } from '../api';
import { displayState, findDevice, state } from '../state';
import type { Device, DevicePatch, Priority, ScanResult } from '../types';
import {
  ICONS,
  KIND_OPTIONS,
  checked,
  confirmModal,
  deviceKind,
  esc,
  fmtM,
  fmtSpeed,
  hostnameOf,
  kindLabel,
  lastSeenOf,
  sigHtml,
  toast,
  uptimeOf,
  val,
} from '../lib/ui';

const devSeries = (id: number) =>
  state.devSeries.get(id) ?? { down: [], up: [], sig: [] };

const peakOf = (a: number[]) => (a.length ? Math.max(...a) : 0);
const avgOf = (a: number[]) => (a.length ? a.reduce((x, y) => x + y, 0) / a.length : 0);

const noMeteringNote =
  '<div style="width:100%;font-size:12px;color:var(--muted)">No per-device metering yet — ' +
  'device traffic appears here once the backend reports it.</div>';

export function deviceView(): string {
  const d = state.devId != null ? findDevice(state.devId) : undefined;
  if (!d)
    return '<div class="empty">Device not found. <a href="#/devices">Back to devices</a></div>';
  const st = displayState(d);
  const sigCol =
    d.signal == null
      ? 'var(--muted)'
      : d.signal >= -65
        ? 'var(--green)'
        : d.signal >= -75
          ? 'var(--amber)'
          : 'var(--red)';
  const sigText = st === 'offline' || d.signal == null ? '—' : d.signal + ' dBm';
  const header =
    '<div class="crumbs"><a href="#/devices">Devices</a><span>/</span><span>' +
    esc(d.name) + '</span></div>' +
    '<section class="card">' +
    '<div class="detail-head">' +
    '<div class="dh-left"><div class="dev-badge">' + ICONS[deviceKind(d)] + '</div>' +
    '<div><h2>' + esc(d.name) +
    '<span class="pill ' + st + '">' +
    (st === 'online' ? 'Connected' : st.charAt(0).toUpperCase() + st.slice(1)) +
    '</span></h2>' +
    '<div class="dh-meta">' + esc(d.vendor) + ' · ' + connText(d) +
    (d.self ? ' · <span class="blk-text">this machine</span>' : '') + '</div></div></div>' +
    '<div class="dh-actions">' +
    '<button class="btn primary" data-action="quick-ping" data-id="' + d.id + '">Ping</button>' +
    '<button class="btn" data-action="locate" data-id="' + d.id + '">Show on map</button>' +
    '<button class="btn" data-action="restart-radio" data-id="' + d.id + '">Restart</button>' +
    (d.self
      ? ''
      : (d.blocked
          ? '<button class="btn" data-action="unblock" data-id="' + d.id + '">Allow internet</button>'
          : '<button class="btn danger" data-action="block" data-id="' + d.id + '">Block</button>') +
        (d.watched
          ? '<button class="btn" data-action="intercept" data-id="' + d.id + '">Stop intercepting</button>'
          : '<button class="btn" data-action="intercept" data-id="' + d.id + '">Intercept</button>') +
        '<button class="btn ghostdanger" data-action="forget" data-id="' + d.id + '">Forget</button>') +
    '</div></div>' +
    '<div class="idrow">' +
    '<span>IP <b class="cp mono" data-action="copy" data-value="' + esc(d.ip) + '">' + esc(d.ip) + '</b></span>' +
    '<span>MAC <b class="cp mono" data-action="copy" data-value="' + esc(d.mac) + '">' + esc(d.mac) + '</b></span>' +
    '<span>' +
    (d.conn === 'eth'
      ? 'Wired link'
      : 'Signal <b style="color:' + sigCol + '">' + sigText + '</b>') +
    '</span>' +
    '<span>' +
    (st === 'offline'
      ? 'Last seen <b>' + lastSeenOf(d) + '</b>'
      : 'Connected <b>' + uptimeOf(d) + '</b>') +
    '</span></div></section>';
  const tabs =
    '<div class="tabs" role="tablist">' +
    ['overview', 'performance', 'intel', 'settings', 'troubleshoot']
      .map(
        t =>
          '<button class="tab' +
          (state.tab === t ? ' active' : '') +
          '" role="tab" aria-selected="' +
          (state.tab === t) +
          '" data-action="tab" data-tab="' +
          t +
          '">' +
          t.charAt(0).toUpperCase() + t.slice(1) + '</button>',
      )
      .join('') +
    '</div>';
  return (
    header + tabs + '<div class="tab-body" role="tabpanel">' + deviceTab(d) + '</div>'
  );
}

function connText(d: Device): string {
  const proto =
    d.conn === 'wifi5' ? 'Wi-Fi 5 GHz' : d.conn === 'wifi2' ? 'Wi-Fi 2.4 GHz' : d.conn === 'eth' ? 'Ethernet' : 'Unknown';
  if (d.conn === 'eth') return proto;
  const ssid = d.conn === 'wifi5' ? state.settings.ssid5 : state.settings.ssid24;
  return proto + (ssid ? ' · ' + esc(ssid) : '');
}

function deviceTab(d: Device): string {
  if (state.tab === 'overview') return tabOverview(d);
  if (state.tab === 'performance') return tabPerformance(d);
  if (state.tab === 'intel') return tabIntel(d);
  if (state.tab === 'settings') return tabDeviceSettings(d);
  return tabTroubleshoot(d);
}

function tabOverview(d: Device): string {
  const st = displayState(d);
  const p = state.prefs;
  const ssid = d.conn === 'wifi5' ? state.settings.ssid5 : state.settings.ssid24;
  const conn =
    d.conn === 'eth'
      ? '<div class="subcard"><h4>Connection</h4><dl class="kv">' +
        '<dt>Interface</dt><dd>Ethernet</dd>' +
        '<dt>Link speed</dt><dd>— <span style="color:var(--muted)">not reported by the gateway</span></dd>' +
        '<dt>Since</dt><dd>' + uptimeOf(d) + ' ago</dd></dl></div>'
      : '<div class="subcard"><h4>Connection</h4><dl class="kv">' +
        '<dt>SSID</dt><dd>' + esc(ssid || '—') + '</dd>' +
        '<dt>Band</dt><dd>' +
        (d.conn === 'wifi5'
          ? '5 GHz · Ch ' + p.ch5
          : d.conn === 'wifi2'
            ? '2.4 GHz · Ch ' + p.ch24
            : 'Unknown') +
        '</dd>' +
        '<dt>Signal</dt><dd>' +
        (st === 'offline' || d.signal == null
          ? '—'
          : sigHtml(d) + ' ' + d.signal + ' dBm') +
        '</dd>' +
        '<dt>Security</dt><dd>' + esc(p.sec) + '</dd>' +
        '<dt>Access point</dt><dd>—</dd>' +
        '<dt>Since</dt><dd>' + uptimeOf(d) + ' ago</dd></dl></div>';
  const ds = devSeries(d.id);
  const peak = peakOf(ds.down);
  const avg = avgOf(ds.down);
  const meterActive = state.status?.metering === 'active';
  const showLocal = meterActive || !!d.self; // self is always measured locally
  const meterWhy = esc(state.status?.metering || 'Per-device metering unavailable');
  const idle = showLocal && d.down === 0 && d.up === 0 && peak === 0;
  return (
    '<div class="grid2">' +
    '<div class="subcard"><h4>Identity</h4><dl class="kv">' +
    '<dt>Type</dt><dd>' + kindLabel(deviceKind(d)) + '</dd>' +
    '<dt>Vendor</dt><dd>' + esc(d.vendor || '—') + '</dd>' +
    '<dt>Hostname</dt><dd class="mono">' + esc(hostnameOf(d.name)) + '</dd>' +
    '<dt>IP address</dt><dd class="mono">' + esc(d.ip) + '</dd>' +
    '<dt>MAC</dt><dd class="mono">' + esc(d.mac) + '</dd>' +
    '<dt>DHCP</dt><dd>' +
    (d.reserved ? 'Reserved (marked)' : 'Dynamic') + '</dd>' +
    '<dt>Priority</dt><dd>' +
    d.priority.charAt(0).toUpperCase() + d.priority.slice(1) + '</dd>' +
    '</dl></div>' + conn +
    '</div>' +
    '<div class="facts">' +
    '<div class="fact"><div class="fl">Uptime</div><div class="fv">' +
    (st === 'offline' ? 'Offline' : uptimeOf(d)) + '</div></div>' +
    '<div class="fact"><div class="fl">Down now</div><div class="fv" style="color:var(--green)"' +
    (showLocal ? '' : ' title="' + meterWhy + '"') + '>' +
    (st === 'offline' || st === 'blocked' || !showLocal ? '—' : fmtM(d.down) + ' Mb/s') +
    '</div></div>' +
    '<div class="fact"><div class="fl">Peak 60s</div><div class="fv"' +
    (showLocal ? '' : ' title="' + meterWhy + '"') + '>' +
    (showLocal ? fmtM(peak) + ' Mb/s' : '—') + '</div></div>' +
    '<div class="fact"><div class="fl">Average</div><div class="fv"' +
    (showLocal ? '' : ' title="' + meterWhy + '"') + '>' +
    (showLocal ? fmtM(avg) + ' Mb/s' : '—') + '</div></div>' +
    '<div class="fact"><div class="fl">Access hours</div><div class="fv">' +
    esc(d.schedule || '—') + '</div></div>' +
    '<div class="fact"><div class="fl">Speed limit</div><div class="fv"' +
    ((d.speedDown || d.speedUp) && !d.blocked ? ' style="color:var(--amber)"' : '') + '>' +
    (d.speedDown || d.speedUp
      ? fmtSpeed(d.speedDown) + ' ↓ · ' + fmtSpeed(d.speedUp) + ' ↑'
      : '—') +
    '</div></div>' +
    (showLocal
      ? idle && !d.self
        ? noMeteringNote
        : d.self && !meterActive
          ? '<div style="width:100%;font-size:12px;color:var(--muted)">measured locally on this machine</div>'
          : ''
      : '<div style="width:100%;font-size:12px;color:var(--muted)">' +
        (state.status?.metering || '') + '</div>') +
    '</div>'
  );
}

function tabPerformance(d: Device): string {
  const st = displayState(d);
  const ds = devSeries(d.id);
  const peak = peakOf(ds.down);
  const avg = avgOf(ds.down);
  const meterActive = state.status?.metering === 'active';
  const showLocal = meterActive || !!d.self;
  const meterWhy = esc(state.status?.metering || 'Per-device metering unavailable');
  const idle = ds.down.every(v => v === 0) && ds.up.every(v => v === 0);
  const sigAvg = ds.sig.length
    ? Math.round(ds.sig.reduce((a, b) => a + b, 0) / ds.sig.length)
    : null;
  const sigCard =
    d.conn === 'eth'
      ? '<div class="chart-block"><div class="cb-head">Wired link' +
        '<span class="right">Ethernet · no signal data</span></div>' +
        '<div class="empty" style="padding:34px">Ethernet devices have no wireless signal to report.</div></div>'
      : ds.sig.length === 0
        ? '<div class="chart-block"><div class="cb-head">Signal strength' +
          '<span class="right">no data</span></div>' +
          '<div class="empty" style="padding:34px">No signal data — the router does not report client ' +
          'Wi-Fi signal. ISP gateways (GPON ONTs) never expose RSSI.</div></div>'
        : '<div class="chart-block"><div class="cb-head">Signal strength' +
          '<span class="right">last 60s · avg ' + sigAvg + ' dBm</span></div>' +
          '<div class="chart-wrap"><canvas id="sigChart"></canvas></div></div>';
  return (
    '<div class="kpis-row">' +
    '<div class="card kpi-sm"><div class="kpi-label">Download now</div>' +
    '<div class="kpi-big" style="color:var(--green)"' +
    (showLocal ? '' : ' title="' + meterWhy + '"') + '>' +
    (st === 'offline' || st === 'blocked' || !showLocal ? '—' : fmtM(d.down)) +
    '<span class="unit">Mb/s</span></div></div>' +
    '<div class="card kpi-sm"><div class="kpi-label">Upload now</div>' +
    '<div class="kpi-big" style="color:var(--blue)"' +
    (showLocal ? '' : ' title="' + meterWhy + '"') + '>' +
    (st === 'offline' || st === 'blocked' || !showLocal ? '—' : fmtM(d.up)) +
    '<span class="unit">Mb/s</span></div></div>' +
    '<div class="card kpi-sm"><div class="kpi-label">Peak, 60s</div>' +
    '<div class="kpi-big"' + (showLocal ? '' : ' title="' + meterWhy + '"') + '>' +
    (showLocal ? fmtM(peak) : '—') + '<span class="unit">Mb/s</span></div></div>' +
    '<div class="card kpi-sm"><div class="kpi-label">Average</div>' +
    '<div class="kpi-big"' + (showLocal ? '' : ' title="' + meterWhy + '"') + '>' +
    (showLocal ? fmtM(avg) : '—') + '<span class="unit">Mb/s</span></div></div>' +
    '</div>' +
    '<div class="chart-block"><div class="cb-head">Bandwidth<span class="right">' +
    (!showLocal
      ? esc(state.status?.metering || 'unavailable')
      : d.self && !meterActive
        ? 'local interface counters · this machine'
        : idle
          ? 'no traffic in the last 60s'
          : 'last 60 seconds · 1s interval') +
    '</span></div>' +
    '<div class="chart-wrap"><canvas id="devChart"></canvas></div>' +
    (!showLocal
      ? '<div class="empty" style="padding:10px 6px 14px">' +
        (state.status?.metering || 'Per-device metering unavailable') +
        '</div>'
      : '') +
    '</div>' +
    sigCard
  );
}

function tabIntel(d: Device): string {
  const ago = (ts: number) => {
    const sec = Math.max(0, (Date.now() - ts) / 1000);
    if (sec < 60) return Math.floor(sec) + 's';
    if (sec < 3600) return Math.floor(sec / 60) + 'm';
    if (sec < 86400) return Math.floor(sec / 3600) + 'h';
    return Math.floor(sec / 86400) + 'd';
  };
  const kindCol = (k: string) =>
    k === 'dns'
      ? 'var(--green)'
      : k === 'sni'
        ? 'var(--amber)'
        : k === 'ja3'
          ? 'var(--blue)'
          : k === 'ja4'
            ? 'var(--accent)'
            : 'var(--muted)';
  const active = !!(d.watched || d.speedDown || d.speedUp);
  const list =
    state.intel.length === 0
      ? '<div style="padding:18px 4px;color:var(--muted);font-size:13px;line-height:1.6">' +
        'No hostnames captured yet.<br>' +
        (active
          ? 'Traffic is crossing this machine — results appear as soon as the device looks something up.'
          : 'Turn on <b>Intercept</b> (or apply a speed limit) to route this device through NetDash, then browse this tab again.') +
        '</div>'
      : state.intel
          .map(
            i =>
              '<div style="display:flex;gap:12px;align-items:center;padding:7px 4px;' +
              'border-bottom:1px solid rgba(128,128,128,.14);font-size:13px">' +
              '<span class="mono" style="width:44px;flex:none;color:var(--muted)">' +
              ago(i.ts) + '</span>' +
              '<span class="mono" style="width:36px;flex:none;color:' + kindCol(i.kind) + '">' +
              esc(i.kind) + '</span>' +
              '<span class="mono" data-action="copy" data-value="' + esc(i.value) +
              '" title="Click to copy" style="cursor:pointer;word-break:break-all">' +
              esc(i.value) + '</span></div>',
          )
          .join('');
  return (
    '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">' +
    '<span class="card-title">Hostnames &amp; requests</span>' +
    '<span style="font-size:12.5px;color:' +
    (active ? 'var(--green)' : 'var(--muted)') + '">' +
    (active ? '● collecting' : '○ intercept off') + '</span>' +
    '<button class="btn" style="margin-left:auto" data-action="refresh-intel" data-id="' +
    d.id + '">Refresh</button></div>' +
    '<div class="fhint" style="margin-bottom:8px">Cleartext metadata only — DNS queries, TLS SNI and ' +
    'HTTP Host headers relayed through this machine, plus <span class="mono">ja3</span>/<span class="mono">ja4</span> ' +
    'TLS ClientHello fingerprints (identify the exact app behind an encrypted connection). ' +
    'HTTP <span class="mono">http</span> rows are unencrypted requests; treat everything here as sensitive.</div>' +
    list
  );
}

function tabDeviceSettings(d: Device): string {
  const row = (label: string, control: string, hint?: string) =>
    '<div class="form-row"><div class="flabel">' + label + '</div><div>' + control +
    '</div><div class="fhint">' + (hint || '') + '</div></div>';
  const parts = d.schedule ? d.schedule.split(/[–—-]/) : [];
  const from = (parts[0] || '').trim();
  const to = (parts[1] || '').trim();
  return (
    '<div style="display:flex;gap:10px;align-items:center;margin-bottom:6px">' +
    '<span class="card-title">Device configuration</span>' +
    '<div style="margin-left:auto;display:flex;gap:9px">' +
    '<button class="btn" data-action="discard-device">Discard</button>' +
    '<button class="btn primary" data-action="save-device" data-id="' + d.id +
    '">Save changes</button></div></div>' +
    row('Device name',
      '<input class="inp" id="dnName" value="' + esc(d.name) + '">',
      'Shown across the dashboard') +
    row('Type',
      '<select class="inp" id="dnKind">' +
      KIND_OPTIONS.map(
        ([v, l]) =>
          '<option value="' + v + '"' + ((d.kind || '') === v ? ' selected' : '') + '>' +
          l + '</option>',
      ).join('') +
      '</select>',
      'Inferred from hostname and MAC vendor — override if the guess is wrong') +
    row('IP assignment',
      '<div class="radio-group">' +
      '<label><input type="radio" name="dnIp" id="dnReserve"' +
      (d.reserved ? ' checked' : '') + '> DHCP reservation</label>' +
      '<label><input type="radio" name="dnIp" id="dnDyn"' +
      (!d.reserved ? ' checked' : '') + '> Dynamic</label></div>',
      'Marks the address as reserved in NetDash — it does not create the DHCP reservation on your router') +
    row('Static IP',
      '<input class="inp mono" id="dnStatic" value="' + d.ip + '" disabled>',
      'Enabled when using a manual address') +
    row('Internet access',
      '<select class="inp" id="dnAccess">' +
      '<option value="allowed"' + (!d.blocked ? ' selected' : '') + '>Allowed</option>' +
      '<option value="blocked"' + (d.blocked ? ' selected' : '') + '>Blocked</option>' +
      '</select>',
      'Blocking cuts WAN access but keeps the device on the LAN') +
    row('Speed limit',
      '<div style="display:flex;gap:6px;align-items:center">' +
      '<span style="color:var(--muted)">↓</span>' +
      '<input class="inp mono" id="dnSpDown" value="' +
      (d.speedDown ? String(d.speedDown) : '') +
      '" placeholder="unlimited" style="width:90px"' + (d.self ? ' disabled' : '') + '>' +
      '<span style="color:var(--muted)">kbit/s</span>' +
      '<span style="color:var(--muted);margin-left:6px">↑</span>' +
      '<input class="inp mono" id="dnSpUp" value="' +
      (d.speedUp ? String(d.speedUp) : '') +
      '" placeholder="unlimited" style="width:90px"' + (d.self ? ' disabled' : '') + '>' +
      '<span style="color:var(--muted)">kbit/s</span></div>',
      'Caps the device through the ARP bridge — leave empty for unlimited; a block overrides the cap') +
    row('Intercept',
      '<label style="display:flex;align-items:center;gap:8px;font-size:13.5px">' +
      '<input type="checkbox" id="dnWatched"' + (d.watched ? ' checked' : '') +
      (d.self ? ' disabled' : '') + '>' +
      ' Route traffic through NetDash and log its hostnames (Intel tab)</label>',
      'Needs laptop (ARP bridge) mode; works together with speed limits and DNS spoofing') +
    row('Active hours',
      '<div style="display:flex;gap:8px;align-items:center">' +
      '<input class="inp mono" id="dnFrom" value="' + esc(from) + '" placeholder="07:00" style="width:90px">' +
      '<span style="color:var(--muted)">─</span>' +
      '<input class="inp mono" id="dnTo" value="' + esc(to) + '" placeholder="23:00" style="width:90px"></div>',
      'Internet allowed only inside this window — leave both empty for always allowed') +
    row('QoS priority',
      '<select class="inp" id="dnPriority">' +
      ['low', 'normal', 'high']
        .map(
          p =>
            '<option value="' + p + '"' + (d.priority === p ? ' selected' : '') + '>' +
            p.charAt(0).toUpperCase() + p.slice(1) + '</option>',
        )
        .join('') +
      '</select>',
      'Stored and shown for reference — NetDash does not prioritise bandwidth (no QoS enforcement)')
  );
}

function tabTroubleshoot(d: Device): string {
  const diag = (id: string, label: string) =>
    '<button class="btn" data-action="diag" data-diag="' + id + '" data-id="' +
    d.id + '">' + label + '</button>';
  return (
    '<div class="diag-bar">' +
    diag('ping', 'Ping') + diag('traceroute', 'Traceroute') + diag('dns', 'DNS lookup') +
    diag('renew', 'Renew DHCP') + diag('restart', 'Restart radio') +
    diag('scan', 'Port scan') +
    '<span style="margin-left:auto;color:var(--muted);font-size:12.5px;align-self:center">' +
    'Target: ' + esc(d.ip) + ' · ' + esc(d.name) + '</span></div>' +
    '<div class="term" id="term"><span class="muted-line">Ready — select a diagnostic to run against ' +
    esc(d.name) + '.</span></div>' +
    '<div class="card timeline"><h4>Connection timeline</h4>' + timelineHtml(d) + '</div>'
  );
}

function timelineHtml(d: Device): string {
  const st = displayState(d);
  const items: Array<{ t: string; txt: string; sev: string }> = [];
  if (st === 'offline' && d.lastSeen)
    items.push({ t: lastSeenOf(d), txt: 'Disconnected — last seen', sev: 'critical' });
  if (d.blocked)
    items.push({ t: '—', txt: 'Internet access blocked by admin', sev: 'warning' });
  if (!d.blocked && (d.speedDown || d.speedUp))
    items.push({
      t: '—',
      txt: 'Speed capped at ' + fmtSpeed(d.speedDown) + ' down / ' + fmtSpeed(d.speedUp) + ' up',
      sev: 'info',
    });
  if (d.watched)
    items.push({
      t: '—',
      txt: 'Intercepting traffic — hostnames logged on the Intel tab',
      sev: 'info',
    });
  if (st === 'warning')
    items.push({
      t: '—',
      txt:
        d.signal != null
          ? 'Signal degraded to ' + d.signal + ' dBm'
          : 'Device flagged — needs attention',
      sev: 'warning',
    });
  if (d.firstSeen)
    items.push({ t: 'now', txt: 'Present on network · ' + d.ip, sev: 'info' });
  items.push({
    t: 'now',
    txt:
      'Connected to ' +
      (d.conn === 'eth'
        ? 'Ethernet'
        : d.conn === 'wifi5'
          ? state.settings.ssid5 || '5 GHz network'
          : d.conn === 'wifi2'
            ? state.settings.ssid24 || '2.4 GHz network'
            : 'the network') +
      (d.conn !== 'eth' && d.signal != null ? ' · ' + d.signal + ' dBm' : ''),
    sev: 'info',
  });
  if (d.firstSeen)
    items.push({
      t: uptimeOf(d),
      txt: 'First seen ' + uptimeOf(d) + ' ago',
      sev: 'info',
    });
  return items
    .map(
      i =>
        '<div class="tl-item ' + i.sev + '"><span class="tl-time">' + i.t +
        '</span><span class="tl-dot"></span><span class="tl-txt">' + esc(i.txt) +
        '</span></div>',
    )
    .join('');
}

export function mergeDevice(upd: Device): void {
  const i = state.devices.findIndex(x => x.id === upd.id);
  if (i < 0) return;
  const sched = state.localSchedule.get(upd.id);
  state.devices[i] = { ...upd, schedule: sched || upd.schedule };
}

export async function saveDevice(id: number): Promise<void> {
  const d = findDevice(id);
  if (!d) return;
  const patch: DevicePatch = {};
  const name = val('dnName').trim();
  if (name && name !== d.name) patch.name = name;
  if (document.getElementById('dnReserve')) patch.reserved = checked('dnReserve');
  const access = document.getElementById('dnAccess') as HTMLSelectElement | null;
  if (access) patch.blocked = access.value === 'blocked';
  const prio = document.getElementById('dnPriority') as HTMLSelectElement | null;
  if (prio) patch.priority = prio.value as Priority;
  const kindSel = document.getElementById('dnKind') as HTMLSelectElement | null;
  if (kindSel && kindSel.value !== (d.kind || '')) patch.kind = kindSel.value;
  const from = document.getElementById('dnFrom') as HTMLInputElement | null;
  const to = document.getElementById('dnTo') as HTMLInputElement | null;
  if (from && to && from.value && to.value) {
    const sched = from.value + '–' + to.value;
    if (sched !== d.schedule) {
      state.localSchedule.set(id, sched);
      d.schedule = sched;
      patch.schedule = sched;
    }
  } else if (from && to && !from.value && !to.value && d.schedule) {
    // both cleared: no active-hours window — internet always allowed
    state.localSchedule.set(id, '');
    d.schedule = '';
    patch.schedule = '';
  }
  const spDown = document.getElementById('dnSpDown') as HTMLInputElement | null;
  const spUp = document.getElementById('dnSpUp') as HTMLInputElement | null;
  if (spDown && spUp && !spDown.disabled) {
    const nd = Math.max(0, parseInt(spDown.value, 10) || 0);
    const nu = Math.max(0, parseInt(spUp.value, 10) || 0);
    if (nd !== d.speedDown) patch.speedDown = nd;
    if (nu !== d.speedUp) patch.speedUp = nu;
  }
  const watched = document.getElementById('dnWatched') as HTMLInputElement | null;
  if (watched && !watched.disabled && watched.checked !== d.watched) {
    patch.watched = watched.checked;
  }
  if (Object.keys(patch).length === 0) {
    toast('No changes to save');
    return;
  }
  try {
    const upd = await postDevice(id, patch);
    mergeDevice(upd);
    toast('Settings saved for ' + (patch.name || d.name));
  } catch (e) {
    toast(e instanceof Error ? e.message : 'Could not save device settings', 'err');
  }
}

/* --- diagnostics: real backend probes, rendered into the terminal --- */

interface TermLine {
  t: string;
  cls?: string;
}

function termLineNow(t: string, cls?: string): HTMLDivElement {
  const term = document.getElementById('term');
  const div = document.createElement('div');
  div.className = cls || '';
  div.textContent = t;
  if (term) {
    term.appendChild(div);
    term.scrollTop = term.scrollHeight;
  }
  return div;
}

function termResolve(pending: HTMLDivElement | null, lines: TermLine[]): void {
  pending?.remove();
  lines.forEach((ln, i) => {
    setTimeout(() => termLineNow(ln.t, ln.cls), i * 200);
  });
}

const lineCls = (l: string): string =>
  l.startsWith('✓') ? '' : l.startsWith('✗') ? 'warn-line' : 'muted-line';

function diagFail(pending: HTMLDivElement | null, err: unknown): void {
  termResolve(pending, [
    { t: String(err instanceof Error ? err.message : err), cls: 'warn-line' },
  ]);
}

/** Formats a scan result as terminal lines (shared by run + restore). */
function scanLines(res: ScanResult): TermLine[] {
  const closed = res.probed - res.open - res.filtered;
  const out: TermLine[] = [
    {
      t:
        (res.method === 'syn' ? 'half-open SYN scan' : 'connect scan') +
        ' · ' + res.probed + ' ports · ' + res.ms.toFixed(0) + ' ms',
      cls: 'muted-line',
    },
    {
      t: 'open ' + res.open + ' · closed ' + closed + ' · filtered ' + res.filtered,
      cls: 'muted-line',
    },
  ];
  for (const p of res.ports) {
    out.push({
      t:
        String(p.port).padEnd(6) + 'open  ' +
        (p.service || 'unknown').padEnd(16) +
        (p.banner || ''),
    });
  }
  if (res.open === 0) out.push({ t: 'no open ports' });
  return out;
}

/**
 * Called when the Troubleshoot tab opens: prints the device's stored last
 * scan into the fresh terminal (which resets on every render).
 */
export async function restoreScan(id: number): Promise<void> {
  let res: ScanResult | null = state.scanDevId === id ? state.scanResult : null;
  if (!res) {
    try {
      res = await lastScan(id);
    } catch {
      return;
    }
    if (!res) return;
    state.scanResult = res;
    state.scanDevId = id;
  }
  if (state.devId !== id || state.tab !== 'troubleshoot') return;
  const term = document.getElementById('term');
  if (!term || term.childElementCount > 1) return; // user already ran something
  term.textContent = '';
  termLineNow(
    'last scan — ' + new Date(res.scannedAt).toLocaleTimeString() + ':',
    'muted-line',
  );
  for (const l of scanLines(res)) termLineNow(l.t, l.cls);
}

export function runDiag(id: number, kind: string): void {
  const d = findDevice(id);
  if (!d) return;
  const ip = d.ip;

  if (kind === 'restart') {
    if (!d.self) {
      confirmModal(
        'Restart radio on ' + d.name + '?',
        "NetDash cannot control another device's Wi-Fi radio — client devices have no agent. This machine's own radio can be restarted from its Troubleshoot tab.",
        'OK',
        false,
        () => toast('Radio restart only works for this machine', 'warn'),
      );
      return;
    }
    confirmModal(
      'Restart the Wi-Fi radio?',
      'The radio powers off and on: this machine drops from the network for a few seconds, then rejoins with a fresh DHCP lease.',
      'Restart',
      true,
      () => {
        termLineNow('$ nmcli radio wifi off && nmcli radio wifi on', 'cmd');
        const pend = termLineNow('radio off…', 'muted-line');
        restartRadio(id)
          .then(r => termResolve(pend, r.lines.map(l => ({ t: l, cls: lineCls(l) }))))
          .catch(e => diagFail(pend, e));
      },
    );
    return;
  }

  if (kind === 'renew') {
    if (!d.self) {
      confirmModal(
        'Renew DHCP on ' + d.name + '?',
        'Client devices renew their own leases — NetDash has no agent on them. Renewal works only on this machine.',
        'OK',
        false,
        () => toast('DHCP renew only works for this machine', 'warn'),
      );
      return;
    }
    confirmModal(
      'Renew DHCP on this machine?',
      'NetworkManager cycles the link: a brief disconnect while a fresh lease is requested from the router.',
      'Renew',
      false,
      () => {
        termLineNow('renew DHCP — cycling this machine\u2019s link', 'cmd');
        const pend = termLineNow('releasing lease…', 'muted-line');
        renewDHCP(id)
          .then(r => termResolve(pend, r.lines.map(l => ({ t: l, cls: lineCls(l) }))))
          .catch(e => diagFail(pend, e));
      },
    );
    return;
  }

  if (kind === 'scan') {
    termLineNow('$ scan --top-ports ' + ip, 'cmd');
    const pend = termLineNow('probing ' + ip + '…', 'muted-line');
    scanDevice(id)
      .then(res => {
        state.scanResult = res;
        state.scanDevId = id;
        termResolve(pend, scanLines(res));
      })
      .catch(e => diagFail(pend, e));
    return;
  }

  if (kind === 'ping') {
    termLineNow('$ ping -c 4 ' + ip, 'cmd');
    const pend = termLineNow('Pinging…', 'muted-line');
    pingDevice(id)
      .then(res => {
        const out: TermLine[] = [];
        if (res.reachable) {
          res.rtts.forEach((ms, i) => {
            out.push({
              t: '64 bytes from ' + ip + ': icmp_seq=' + (i + 1) + ' ttl=64 time=' + ms.toFixed(1) + ' ms',
              cls: 'muted-line',
            });
          });
          out.push({
            t:
              '--- ' + res.sent + ' packets transmitted, ' + res.recv + ' received, ' +
              res.loss + '% packet loss ---',
          });
          out.push({
            t:
              'rtt min/avg/max = ' + res.minMs.toFixed(1) + '/' + res.avgMs.toFixed(1) + '/' +
              res.maxMs.toFixed(1) + ' ms',
            cls: 'muted-line',
          });
        } else {
          for (let i = 0; i < res.sent; i++) {
            out.push({ t: 'PING ' + ip + ': Request timeout.', cls: 'warn-line' });
          }
          out.push({
            t: '--- ' + res.sent + ' packets transmitted, 0 received, 100% packet loss ---',
            cls: 'warn-line',
          });
        }
        termResolve(pend, out);
      })
      .catch(e => diagFail(pend, e));
    return;
  }

  if (kind === 'traceroute') {
    termLineNow('traceroute to ' + ip + ' — 5 hops max, 2 probes per hop (TTL walk)', 'cmd');
    const pend = termLineNow('tracing…', 'muted-line');
    tracerouteDevice(id)
      .then(r => {
        const out: TermLine[] = [];
        r.hops.forEach((h, i) => {
          const n = ' ' + (i + 1);
          const rtts = h.rtts || [];
          if (h.ip) {
            out.push({
              t:
                n + '  ' + h.ip + '  ' +
                (rtts.length ? rtts.map(x => x.toFixed(1) + ' ms').join('  ') : 'no RTT') +
                (h.reached ? '   ← target' : ''),
              cls: h.reached ? '' : 'muted-line',
            });
          } else {
            out.push({ t: n + '  * * *', cls: 'warn-line' });
          }
        });
        if (r.reached) {
          out.push({
            t:
              r.hops.length === 1 && r.hops[0].reached
                ? '✓ On-link — reached directly, no router in between.'
                : '✓ Reached in ' + r.hops.length + ' hops (' + r.probes + ' probes).',
          });
        } else {
          out.push({
            t: '✗ No reply from ' + ip + ' after ' + r.hops.length + ' hops — host down or ICMP filtered.',
            cls: 'warn-line',
          });
        }
        termResolve(pend, out);
      })
      .catch(e => diagFail(pend, e));
    return;
  }

  if (kind === 'dns') {
    termLineNow('lookup ' + ip + ' — reverse PTR + forward A/AAAA (mDNS fallback)', 'cmd');
    const pend = termLineNow('querying resolvers…', 'muted-line');
    dnsLookupDevice(id)
      .then(r => {
        const ptr = r.ptr || [];
        const fwd = r.fwd || [];
        const out: TermLine[] = [];
        if (ptr.length) {
          ptr.forEach(p => out.push({ t: '  PTR  ' + ip + ' → ' + p, cls: 'muted-line' }));
        } else {
          out.push({ t: ';; no PTR record for ' + ip, cls: 'warn-line' });
        }
        if (fwd.length) {
          fwd.forEach(a => out.push({ t: '  A    ' + d.name + ' → ' + a, cls: 'muted-line' }));
        }
        if (r.note) {
          out.push({ t: ';; ' + r.note, cls: ptr.length || fwd.length ? 'muted-line' : 'warn-line' });
        }
        out.push({ t: '✓ ' + (ptr.length + fwd.length) + ' record(s) in ' + r.ms.toFixed(1) + ' ms' });
        termResolve(pend, out);
      })
      .catch(e => diagFail(pend, e));
    return;
  }
}
