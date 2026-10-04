import { counts, displayState, state } from '../state';
import type { Device } from '../types';
import { connLabel, esc, sigHtml, subline, thrHtml } from '../lib/ui';

const ipNum = (ip: string) =>
  ip.split('.').reduce((acc, o) => acc * 256 + Number(o), 0);

export function filteredDevices(): Device[] {
  const q = state.search.trim().toLowerCase();
  const list = state.devices.filter(d => {
    const st = displayState(d);
    if (state.filter === 'wifi' && d.conn === 'eth') return false;
    if (state.filter === 'wired' && d.conn !== 'eth') return false;
    if (state.filter === 'offline' && st !== 'offline' && st !== 'blocked') return false;
    if (
      q &&
      !(
        d.name.toLowerCase().includes(q) ||
        d.ip.includes(q) ||
        d.mac.toLowerCase().includes(q) ||
        d.vendor.toLowerCase().includes(q)
      )
    )
      return false;
    return true;
  });
  const k = state.sort.key;
  const dir = state.sort.dir;
  const rank: Record<string, number> = {
    critical: 0,
    warning: 1,
    online: 2,
    blocked: 3,
    offline: 4,
  };
  list.sort((a, b) => {
    let r = 0;
    if (k === 'name') r = a.name.localeCompare(b.name);
    else if (k === 'ip') r = ipNum(a.ip) - ipNum(b.ip);
    else if (k === 'mac') r = a.mac.localeCompare(b.mac);
    else if (k === 'conn') r = connLabel(a.conn).localeCompare(connLabel(b.conn));
    else if (k === 'signal')
      r = (a.signal == null ? -999 : a.signal) - (b.signal == null ? -999 : b.signal);
    else if (k === 'thr') r = a.down + a.up - (b.down + b.up);
    else if (k === 'state') r = rank[displayState(a)] - rank[displayState(b)];
    return r * dir;
  });
  return list;
}

function th(key: string, label: string, cls?: string): string {
  const active = state.sort.key === key;
  return (
    '<th data-action="sort" data-key="' + key + '" class="' + (cls || '') + '">' +
    label +
    (active
      ? '<span class="arr">' + (state.sort.dir > 0 ? '↑' : '↓') + '</span>'
      : '') +
    '</th>'
  );
}

export function tableHtml(): string {
  const list = filteredDevices();
  const rows = list
    .map(d => {
      const st = displayState(d);
      return (
        '<tr class="st-' + st + '" data-action="open-device" data-id="' + d.id + '" tabindex="0">' +
        '<td class="c-status"><span class="dot ' + st + '"></span></td>' +
        '<td class="c-name"><div class="nm">' + esc(d.name) + '</div><div class="sub">' +
        subline(d) + '</div></td>' +
        '<td><span class="copyable" data-action="copy" data-value="' + d.ip +
        '" title="Click to copy">' + d.ip + '</span></td>' +
        '<td class="c-mac"><span class="copyable" data-action="copy" data-value="' + d.mac +
        '" title="Click to copy">' + d.mac + '</span></td>' +
        '<td class="c-conn">' + connLabel(d.conn) + '</td>' +
        '<td>' + sigHtml(d) + '</td>' +
        '<td data-thr="' + d.id + '">' + thrHtml(d) + '</td>' +
        '<td class="c-act"><button class="row-menu-btn" data-action="menu" data-id="' +
        d.id + '" aria-label="Device actions">⋯</button></td>' +
        '</tr>'
      );
    })
    .join('');
  return (
    '<table class="tbl"><thead><tr>' +
    th('state', '') +
    th('name', 'Name') +
    th('ip', 'IP Address') +
    th('mac', 'MAC', 'th-mac') +
    th('conn', 'Connection') +
    th('signal', 'Signal') +
    th('thr', '↓ ↑ Mbps') +
    '<th></th>' +
    '</tr></thead><tbody id="devTbody">' +
    (rows ||
      '<tr><td colspan="8"><div class="empty">No devices match your search.</div></td></tr>') +
    '</tbody></table>'
  );
}

export const legendHtml = () =>
  '<div class="legend">' +
  '<span><span class="dot on"></span> connected</span>' +
  '<span><span class="dot warning"></span> warning</span>' +
  '<span><span class="dot offline"></span> offline</span>' +
  '<span><span class="dot blocked"></span> blocked</span></div>';

export function toolbarHtml(title: string, viewAll: boolean): string {
  const chip = (v: string, l: string) =>
    '<button class="chip' +
    (state.filter === v ? ' active' : '') +
    '" data-action="filter" data-filter="' + v + '">' + l + '</button>';
  return (
    '<div class="table-toolbar">' +
    '<span class="card-title">' + title + '</span>' +
    '<span class="chipmini">' + filteredDevices().length + ' shown</span>' +
    chip('all', 'All') +
    chip('wifi', 'Wi-Fi') +
    chip('wired', 'Wired') +
    chip('offline', 'Offline') +
    '<input class="search-input" id="devSearch" placeholder="Search name / IP / MAC…" value="' +
    esc(state.search) + '">' +
    (viewAll
      ? '<button class="chip" data-action="nav" data-href="#/devices">View all</button>'
      : '') +
    '</div>'
  );
}

export function devicesView(): string {
  const c = counts();
  return (
    '<div class="summary-strip">' +
    '<div class="card sum-card"><span class="dot on"></span><span class="num">' +
    c.connected + '</span><span class="lbl">connected</span></div>' +
    '<div class="card sum-card"><span class="dot warning"></span><span class="num">' +
    c.warning + '</span><span class="lbl">warning</span></div>' +
    '<div class="card sum-card"><span class="dot offline"></span><span class="num">' +
    c.offline + '</span><span class="lbl">offline</span></div>' +
    '<div class="card sum-card"><span class="dot blocked"></span><span class="num">' +
    c.blocked + '</span><span class="lbl">blocked</span></div>' +
    '</div>' +
    '<section class="card table-card" style="height:calc(100vh - 210px)">' +
    toolbarHtml('All devices', false) +
    '<div class="tbl-scroll">' + tableHtml() + '</div>' +
    '<div class="tbl-foot"><span id="tblCount">' + filteredDevices().length +
    ' of ' + state.devices.length + ' devices</span>' + legendHtml() +
    '<span style="margin-left:auto">Click a row for details · click IP/MAC to copy</span></div>' +
    '</section>'
  );
}
