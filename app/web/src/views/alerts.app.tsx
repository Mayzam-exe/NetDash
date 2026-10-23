import { findDevice, unreadAlerts } from '../state';
import { alertFilterSig, alertsSig, snapshotTick, uiTick } from '../signals';
import { Eyebrow } from '../components/ui';
import { esc, relTime } from '../lib/ui';
import type { Alert } from '../types';

const FILTERS: Array<[string, string]> = [
  ['all', 'All'],
  ['critical', 'Critical'],
  ['warning', 'Warning'],
  ['info', 'Info'],
];

function AlertRow({ a }: { a: Alert }) {
  const dev = a.devId != null ? findDevice(a.devId) : undefined;
  return (
    <div class={'card alert-row ' + a.sev}>
      <span class="sev" />
      <div>
        <div class="msg">{esc(a.msg)}</div>
        <div class="meta">
          {a.sev.toUpperCase() + ' · ' + relTime(a.ts)}
          {dev ? ' · ' + esc(dev.name) : ''}
        </div>
      </div>
      <div class="right">
        {dev ? (
          <button class="btn" data-action="open-alert" data-id={String(a.id)}>
            Open device
          </button>
        ) : null}
        <button class="btn" data-action="dismiss-alert" data-id={String(a.id)}>
          Dismiss
        </button>
      </div>
    </div>
  );
}

/**
 * Alerts view, ported to Preact (Phase 1 pilot).
 *
 * Unlike the string views, this component subscribes to signals and re-renders
 * *itself* on every SSE snapshot — Preact diffs preserve DOM nodes (and input
 * focus/scroll), so no full `innerHTML` replacement is needed.
 */
export function AlertsApp() {
  const filter = alertFilterSig.value;
  const alerts = alertsSig.value;
  const list = alerts.filter(a => filter === 'all' || a.sev === filter);
  const unread = unreadAlerts();

  return (
    <>
      <div
        class="card table-toolbar"
        style="margin-bottom:14px"
        data-tick={snapshotTick.value + uiTick.value}
      >
        <Eyebrow>Filter</Eyebrow>
        {FILTERS.map(([v, l]) => (
          <button
            key={v}
            class={'chip' + (filter === v ? ' active' : '')}
            data-action="alert-filter"
            data-filter={v}
          >
            {l}
          </button>
        ))}
        <span class="chipmini unread-chip" style="margin-left:auto">
          {unread + ' unresolved'}
        </span>
      </div>
      <div class="alerts-view-list">
        {list.length === 0 ? (
          <div class="card empty">Nothing here — no alerts match this filter.</div>
        ) : (
          list.map(a => <AlertRow key={String(a.id)} a={a} />)
        )}
      </div>
    </>
  );
}
