import { findDevice, state, unreadAlerts } from '../state';
import type { Alert } from '../types';
import { esc, relTime } from '../lib/ui';

export function alertItemHtml(a: Alert): string {
  return (
    '<button class="alert-item ' + a.sev + '" data-action="open-alert" data-id="' + a.id + '">' +
    '<span class="sev"></span><div><div class="msg">' + esc(a.msg) + '</div>' +
    '<div class="meta">' + relTime(a.ts) + ' · ' + a.sev + '</div></div></button>'
  );
}

export function alertsView(): string {
  const f = state.alertFilter;
  const list = state.alerts.filter(a => f === 'all' || a.sev === f);
  const chip = (v: string, l: string) =>
    '<button class="chip' +
    (f === v ? ' active' : '') +
    '" data-action="alert-filter" data-filter="' + v + '">' + l + '</button>';
  const rows = list
    .map(a => {
      const dev = a.devId != null ? findDevice(a.devId) : undefined;
      return (
        '<div class="card alert-row ' + a.sev + '">' +
        '<span class="sev"></span>' +
        '<div><div class="msg">' + esc(a.msg) + '</div>' +
        '<div class="meta">' + a.sev.toUpperCase() + ' · ' + relTime(a.ts) +
        (dev ? ' · ' + esc(dev.name) : '') + '</div></div>' +
        '<div class="right">' +
        (dev
          ? '<button class="btn" data-action="open-alert" data-id="' + a.id + '">Open device</button>'
          : '') +
        '<button class="btn" data-action="dismiss-alert" data-id="' + a.id + '">Dismiss</button>' +
        '</div></div>'
      );
    })
    .join('');
  return (
    '<div class="card table-toolbar" style="margin-bottom:14px;border-radius:12px;border-bottom:1px solid var(--border)">' +
    '<span class="card-title">Filter</span>' +
    chip('all', 'All') +
    chip('critical', 'Critical') +
    chip('warning', 'Warning') +
    chip('info', 'Info') +
    '<span class="chipmini" style="margin-left:auto">' + unreadAlerts() +
    ' unresolved</span></div>' +
    '<div class="alerts-view-list">' +
    (rows || '<div class="card empty">Nothing here — no alerts match this filter.</div>') +
    '</div>'
  );
}
