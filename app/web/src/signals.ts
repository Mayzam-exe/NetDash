import { signal } from '@preact/signals';

import type { Alert, Device, History, Status } from './types';

/**
 * Preact signals mirroring the slice of app state that components subscribe to.
 *
 * The legacy string views read the plain `state` object (see `../state`); these
 * signals exist so Preact components can re-render *themselves* on every SSE
 * snapshot instead of forcing a whole-view `innerHTML` replacement. `applySnapshot`
 * in `../state` calls `syncSignals` after every update.
 */

export const statusSig = signal<Status | null>(null);
export const devicesSig = signal<Device[]>([]);
export const alertsSig = signal<Alert[]>([]);
export const historySig = signal<History | null>(null);

/** Bumped on every incoming snapshot — a cheap "something changed" dependency. */
export const snapshotTick = signal(0);

/** Alerts view filter (mirrors `state.alertFilter`). */
export const alertFilterSig = signal('all');

/** Bumped by `render()` when legacy code mutates state a view depends on. */
export const uiTick = signal(0);

/** Shape of the legacy state object we mirror (kept structural to avoid a cycle). */
interface StateMirror {
  status: Status | null;
  devices: Device[];
  alerts: Alert[];
  series: History;
}

export function syncSignals(s: StateMirror): void {
  let changed = false;
  if (statusSig.value !== s.status) {
    statusSig.value = s.status;
    changed = true;
  }
  if (devicesSig.value !== s.devices) {
    devicesSig.value = s.devices;
    changed = true;
  }
  if (alertsSig.value !== s.alerts) {
    alertsSig.value = s.alerts;
    changed = true;
  }
  if (historySig.value !== s.series) {
    historySig.value = s.series;
    changed = true;
  }
  // A monotonic tick so components can depend on "state was updated" even when
  // a value they read (e.g. the readIds Set) has no signal of its own.
  if (changed) snapshotTick.value = snapshotTick.value + 1;
}
