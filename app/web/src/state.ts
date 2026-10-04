import type {
  Alert,
  Device,
  History,
  Intel,
  ScanResult,
  Settings,
  SpoofRule,
  Snapshot,
  Status,
} from './types';

export type ViewName =
  | 'dashboard'
  | 'map'
  | 'devices'
  | 'alerts'
  | 'settings'
  | 'device';

/** Settings fields that live only in the client (not part of the API settings object). */
export interface Prefs {
  wanType: string;
  dnsMode: 'auto' | 'custom';
  dns1: string;
  dns2: string;
  ch24: string;
  bw24: string;
  ch5: string;
  bw5: string;
  sec: string;
  pass: string;
  guest: string;
  dhcpStart: string;
  dhcpEnd: string;
  lease: string;
  firewall: string;
  upnp: string;
  remote: string;
}

export interface DevSeries {
  down: number[];
  up: number[];
  sig: number[];
}

export interface SortState {
  key: string;
  dir: number;
}

export interface AppState {
  view: ViewName;
  devId: number | null;
  tab: string;
  search: string;
  filter: string;
  sort: SortState;
  alertFilter: string;
  status: Status | null;
  devices: Device[];
  alerts: Alert[];
  series: History;
  settings: Settings;
  prefs: Prefs;
  latency: number;
  readIds: Set<number>;
  hidden: Set<number>;
  localSchedule: Map<number, string>;
  intel: Intel[];
  intelDevId: number | null;
  scanResult: ScanResult | null;
  scanDevId: number | null;
  spoofRules: SpoofRule[];
  devSeries: Map<number, DevSeries>;
  focusSearch: boolean;
  pendingDiag: { id: number; kind: string } | null;
  cmdkSel: number;
  cmdkResults: Device[];
  charts: Array<() => void>;
  atlasFocus: number | null;
  started: boolean;
}

export const defaultPrefs = (): Prefs => ({
  wanType: 'DHCP',
  dnsMode: 'auto',
  dns1: '1.1.1.1',
  dns2: '9.9.9.9',
  ch24: 'Auto',
  bw24: '40 MHz',
  ch5: '149',
  bw5: '80 MHz',
  sec: 'WPA3',
  pass: 'hunter2secret',
  guest: 'Off',
  dhcpStart: '192.168.1.100',
  dhcpEnd: '192.168.1.200',
  lease: '24 hours',
  firewall: 'On',
  upnp: 'Off',
  remote: 'Off',
});

export const state: AppState = {
  view: 'dashboard',
  devId: null,
  tab: 'overview',
  search: '',
  filter: 'all',
  sort: { key: 'name', dir: 1 },
  alertFilter: 'all',
  status: null,
  devices: [],
  alerts: [],
  series: { down: [], up: [], lat: [], points: 0 },
  settings: {
    ssid24: '', ssid5: '', gatewayIp: '', wanIp: '',
    snmpEnabled: false, snmpHost: '', snmpCommunity: 'public', snmpWanIf: '',
  },
  prefs: defaultPrefs(),
  latency: -1,
  readIds: new Set<number>(),
  hidden: new Set<number>(),
  localSchedule: new Map<number, string>(),
  intel: [],
  intelDevId: null,
  scanResult: null,
  scanDevId: null,
  spoofRules: [],
  devSeries: new Map<number, DevSeries>(),
  focusSearch: false,
  pendingDiag: null,
  cmdkSel: 0,
  cmdkResults: [],
  charts: [],
  atlasFocus: null,
  started: false,
};

type Listener = () => void;
const listeners = new Set<Listener>();

export function subscribe(fn: Listener): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

export function emit(): void {
  for (const fn of listeners) fn();
}

export function push<T>(arr: T[], v: T, cap = 60): void {
  arr.push(v);
  while (arr.length > cap) arr.shift();
}

function seriesFor(id: number): DevSeries {
  let s = state.devSeries.get(id);
  if (!s) {
    s = { down: [], up: [], sig: [] };
    state.devSeries.set(id, s);
  }
  return s;
}

export function applySnapshot(snap: Snapshot): void {
  state.status = snap.status;
  state.devices = snap.devices
    .filter(d => !state.hidden.has(d.id))
    .map(d => ({ ...d }));
  for (const d of state.devices) {
    const sched = state.localSchedule.get(d.id);
    if (sched) d.schedule = sched;
  }
  state.alerts = snap.alerts;
  state.series = {
    down: snap.history.down.slice(),
    up: snap.history.up.slice(),
    lat: snap.history.lat.slice(),
    points: snap.history.points,
  };
  state.latency = snap.status.latencyWan;
  const live = new Set(state.devices.map(d => d.id));
  for (const id of state.devSeries.keys()) {
    if (!live.has(id)) state.devSeries.delete(id); // device expired/was forgotten
  }
  for (const d of state.devices) {
    const ds = seriesFor(d.id);
    push(ds.down, d.down);
    push(ds.up, d.up);
    if (d.signal != null) push(ds.sig, d.signal);
  }
  state.started = true;
  emit();
}

export const displayState = (d: Device) => (d.blocked ? 'blocked' : d.state);

export function counts() {
  const c = { online: 0, warning: 0, offline: 0, blocked: 0, connected: 0, total: 0 };
  for (const d of state.devices) c[displayState(d)]++;
  c.connected = c.online + c.warning;
  c.total = state.devices.length;
  return c;
}

export const unreadAlerts = () =>
  state.alerts.filter(a => !a.read && !state.readIds.has(a.id)).length;

export const findDevice = (id: number) => state.devices.find(d => d.id === id);

export const hostDown = () => state.status?.hostDown ?? 0;
export const hostUp = () => state.status?.hostUp ?? 0;
// hostPeakDown is a peak-since-start figure (the backend never resets it), so
// the UI labels it explicitly instead of presenting it as a rolling peak.
export const hostPeakDown = () => state.status?.hostPeakDown ?? 0;
export const latencyWan = () => state.status?.latencyWan ?? -1;
export const latencyGateway = () => state.status?.latencyGateway ?? -1;
export const gatewayIp = () => state.status?.gatewayIp ?? '—';
