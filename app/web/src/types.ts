export type Conn = 'eth' | 'wifi5' | 'wifi2' | 'unknown';
export type DevState = 'online' | 'offline' | 'warning';
export type Priority = 'normal' | 'high' | 'low';
export type Sev = 'info' | 'warning' | 'critical';

export interface Device {
  id: number;
  ip: string;
  mac: string;
  name: string;
  vendor: string;
  kind: string; // phone|laptop|…|router|"" (auto)
  conn: Conn;
  signal: number | null;
  state: DevState;
  blocked: boolean;
  blockUntil: number; // unix ms; 0 = permanent block (or not blocked)
  reserved: boolean;
  trusted: boolean; // exempt from lockdown mode
  lockdown: boolean; // currently cut off *because* lockdown is on (computed)
  priority: Priority;
  schedule: string;
  speedDown: number; // kbit/s cap, 0 = unlimited
  speedUp: number; // kbit/s cap, 0 = unlimited
  watched: boolean; // intercept: relayed for intel (SNI/DNS/HTTP hostnames)
  down: number;
  up: number;
  self?: boolean; // the machine running NetDash
  lastSeen: string | null;
  firstSeen: string | null;
}

export interface DevicePatch {
  blocked?: boolean;
  blockUntil?: number; // unix ms, 0 = clear expiry; with blocked:true = timed block
  name?: string;
  priority?: Priority;
  reserved?: boolean;
  trusted?: boolean;
  schedule?: string;
  kind?: string; // kind id, or '' = auto
  speedDown?: number; // kbit/s, 0 = unlimited
  speedUp?: number; // kbit/s, 0 = unlimited
  watched?: boolean; // intercept mode on/off
}

export interface Alert {
  id: number;
  sev: Sev;
  msg: string;
  devId: number | null;
  ts: number;
  read: boolean;
}

export interface Status {
  ok: boolean;
  version: string;
  startedAt: string;
  gatewayIp: string;
  wanIp: string;
  latencyGateway: number;
  latencyWan: number;
  hostDown: number;
  hostUp: number;
  hostPeakDown: number;
  metricsSource: 'host' | 'snmp';
  firewall?: string;
  blocking?: string; // 'active (nftables|arp poisoning)' | 'unavailable: reason'
  speed?: string; // 'active (arp bridge)' | 'unavailable: reason'
  path?: string; // 'gateway' | 'behind'
  metering?: string; // 'active' | 'unavailable: reason'
  lockdown?: boolean; // lockdown mode is engaged
  totals: {
    devices: number;
    online: number;
    warning: number;
    offline: number;
    blocked: number;
  };
}

export interface History {
  down: number[];
  up: number[];
  lat: number[];
  points: number;
}

export interface Snapshot {
  status: Status;
  devices: Device[];
  alerts: Alert[];
  history: History;
}

export interface PingResult {
  ip: string;
  sent: number;
  recv: number;
  loss: number;
  avgMs: number;
  minMs: number;
  maxMs: number;
  rtts: number[];
  reachable: boolean;
}

export interface TraceHop {
  ip: string;
  rtts: number[];
  reached: boolean;
}

export interface TracerouteResult {
  hops: TraceHop[];
  reached: boolean;
  probes: number;
}

export interface DNSResult {
  ptr: string[];
  fwd: string[];
  ms: number;
  note: string;
}

export interface CmdResult {
  lines: string[];
  ok: boolean;
}

export interface Intel {
  id: number;
  devId: number;
  ts: number; // unix ms
  kind: string; // dns | sni | http | ja3 | ja4
  value: string;
}

export interface PortResult {
  port: number;
  service: string;
  banner?: string;
}

export interface ScanResult {
  scannedAt: number; // unix ms
  ms: number;
  method: string; // syn | connect
  probed: number;
  open: number;
  filtered: number;
  ports: PortResult[]; // open only
}

export interface SpoofRule {
  id: number;
  domain: string;
  ip: string;
}

export interface ProbeReport {
  reachable: boolean;
  sysName: string;
  sysDescr: string;
  ifaces: string[];
  rssiMib: string; // station-signal MIB label; '' = not exposed by the router
  error: string;
}

export interface Settings {
  ssid24: string;
  ssid5: string;
  gatewayIp: string;
  wanIp: string;
  snmpEnabled: boolean;
  snmpHost: string;
  snmpCommunity: string;
  snmpWanIf: string;
  // Cuts internet for every device except this machine and the Trusted ones.
  lockdown: boolean;
}
