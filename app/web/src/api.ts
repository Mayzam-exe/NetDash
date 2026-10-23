import type {
  Alert,
  CmdResult,
  Device,
  DevicePatch,
  DNSResult,
  History,
  Intel,
  PingResult,
  ProbeReport,
  ScanResult,
  Settings,
  SpoofRule,
  Snapshot,
  Status,
  TracerouteResult,
} from './types';

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let detail = '';
    try {
      detail = (await res.text()).trim();
    } catch {
      /* ignore body read failure */
    }
    throw new Error(detail || 'HTTP ' + res.status);
  }
  return (await res.json()) as T;
}

// Optional bearer token. When the server runs with -auth-token (or
// NETDASH_AUTH_TOKEN), set it once in the browser console:
//   localStorage.setItem('netdashToken', '<token>')
// Requests then carry it; without a server token this is a no-op.
function authToken(): string {
  try {
    return localStorage.getItem('netdashToken') || '';
  } catch {
    return '';
  }
}

function authHeaders(base: Record<string, string> = {}): Record<string, string> {
  const t = authToken();
  return t ? { ...base, Authorization: 'Bearer ' + t } : base;
}

function get<T>(url: string): Promise<T> {
  return fetch(url, { headers: authHeaders() }).then(json<T>);
}

function send<T>(url: string, method: string, body: unknown): Promise<T> {
  return fetch(url, {
    method,
    headers: authHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body),
  }).then(json<T>);
}

export function getStatus(): Promise<Status> {
  return get<Status>('/api/status');
}

export async function getDevices(): Promise<Device[]> {
  return (await get<{ devices: Device[] }>('/api/devices')).devices;
}

export async function getAlerts(): Promise<Alert[]> {
  return (await get<{ alerts: Alert[] }>('/api/alerts')).alerts;
}

export function getHistory(): Promise<History> {
  return get<History>('/api/history');
}

export function getSettings(): Promise<Settings> {
  return get<Settings>('/api/settings');
}

export async function getSnapshot(): Promise<Snapshot> {
  const [status, devices, alerts, history] = await Promise.all([
    getStatus(),
    getDevices(),
    getAlerts(),
    getHistory(),
  ]);
  return { status, devices, alerts, history };
}

export function putSettings(s: Settings): Promise<Settings> {
  return send<Settings>('/api/settings', 'PUT', s);
}

export function postDevice(id: number, body: DevicePatch): Promise<Device> {
  return send<Device>('/api/devices/' + id, 'POST', body);
}

export function deleteDevice(id: number): Promise<{ ok: boolean }> {
  return send<{ ok: boolean }>('/api/devices/' + id, 'DELETE', {});
}

export function pingDevice(id: number): Promise<PingResult> {
  return send<PingResult>('/api/devices/' + id + '/ping', 'POST', {});
}

export function tracerouteDevice(id: number): Promise<TracerouteResult> {
  return send<TracerouteResult>('/api/devices/' + id + '/traceroute', 'POST', {});
}

export function dnsLookupDevice(id: number): Promise<DNSResult> {
  return send<DNSResult>('/api/devices/' + id + '/dnslookup', 'POST', {});
}

export function renewDHCP(id: number): Promise<CmdResult> {
  return send<CmdResult>('/api/devices/' + id + '/renew-dhcp', 'POST', {});
}

export function restartRadio(id: number): Promise<CmdResult> {
  return send<CmdResult>('/api/devices/' + id + '/restart-radio', 'POST', {});
}

export function scanDevice(id: number, ports?: number[]): Promise<ScanResult> {
  return send<ScanResult>('/api/devices/' + id + '/scan', 'POST', {
    ports: ports ?? [],
  });
}

// lastScan returns the device's stored previous scan, or null if it never ran.
export async function lastScan(id: number): Promise<ScanResult | null> {
  const r = await get<ScanResult | { scan: null }>(
    '/api/devices/' + id + '/scan',
  );
  return 'scannedAt' in r ? r : null;
}

export async function getIntel(id: number, limit = 150): Promise<Intel[]> {
  return (
    await get<{ intel: Intel[] }>('/api/devices/' + id + '/intel?limit=' + limit)
  ).intel;
}

export async function listSpoof(): Promise<SpoofRule[]> {
  return (await get<{ rules: SpoofRule[] }>('/api/spoof-rules')).rules;
}

export function addSpoof(body: { domain: string; ip: string }): Promise<SpoofRule> {
  return send<SpoofRule>('/api/spoof-rules', 'POST', body);
}

export function delSpoof(id: number): Promise<{ ok: boolean }> {
  return send<{ ok: boolean }>('/api/spoof-rules/' + id, 'DELETE', {});
}

export function ackAlert(id: number): Promise<{ ok: boolean }> {
  return send<{ ok: boolean }>('/api/alerts/' + id + '/ack', 'POST', {});
}

export function clearAlerts(): Promise<{ ok: boolean }> {
  return send<{ ok: boolean }>('/api/alerts/clear', 'POST', {});
}

export function probeRouter(
  host: string,
  community: string,
): Promise<ProbeReport> {
  return send<ProbeReport>('/api/gateway/probe', 'POST', {
    host: host,
    community: community,
  });
}

export function openStream(
  onSnapshot: (s: Snapshot) => void,
  onError?: () => void,
): EventSource {
  const t = authToken();
  const es = new EventSource(
    '/api/stream' + (t ? '?token=' + encodeURIComponent(t) : ''),
  );
  const handle = (e: Event) => {
    try {
      onSnapshot(JSON.parse((e as MessageEvent<string>).data) as Snapshot);
    } catch {
      /* ignore malformed frame */
    }
  };
  es.addEventListener('hello', handle);
  es.addEventListener('tick', handle);
  es.onerror = () => {
    onError?.();
  };
  return es;
}
