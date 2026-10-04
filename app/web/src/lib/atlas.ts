import { displayState, findDevice, gatewayIp, hostDown, state } from '../state';
import type { Device } from '../types';
import { $$, clamp, cssVar, deviceKind, dur, esc, fmtM, toast } from './ui';

/* --- atlas map renderer (ported from the prototype) --- */

const atlasRM = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

interface Pt {
  x: number;
  y: number;
}

interface AtlasState {
  mounted: boolean;
  raf: number;
  cam: { x: number; y: number; scale: number };
  hoverId: number | null;
  layoutKey: string;
  W: number;
  H: number;
  dpr: number;
  canvas: HTMLCanvasElement | null;
  ctx: CanvasRenderingContext2D | null;
  layout: Map<number | 'gw' | 'wan', Pt>;
  ro: ResizeObserver | null;
}

const atlas: AtlasState = {
  mounted: false,
  raf: 0,
  cam: { x: 0, y: -40, scale: 0.95 },
  hoverId: null,
  layoutKey: '',
  W: 0,
  H: 0,
  dpr: 1,
  canvas: null,
  ctx: null,
  layout: new Map(),
  ro: null,
};

const ATLAS_GW: Pt = { x: 0, y: 0 };
const ATLAS_WAN: Pt = { x: 0, y: -330 };

const ATLAS_MONO: Record<string, string> = {
  phone: 'PH',
  laptop: 'LT',
  desktop: 'PC',
  tv: 'TV',
  camera: 'CM',
  speaker: 'SP',
  thermostat: 'TH',
  printer: 'PR',
  hub: 'HB',
  console: 'GX',
  tablet: 'TB',
  router: 'RT',
  unknown: '??',
};

const atlasGlyph = (d: Device) =>
  ATLAS_MONO[deviceKind(d)] || d.name.slice(0, 2).toUpperCase();

const atlasColor = (st: string) =>
  st === 'online'
    ? cssVar('--green')
    : st === 'warning'
      ? cssVar('--amber')
      : cssVar('--muted');

const atlasRgba = (name: string, a: number) => {
  const v = cssVar(name);
  if (/^#[0-9a-f]{6}$/i.test(v)) {
    const n = parseInt(v.slice(1), 16);
    return 'rgba(' + (n >> 16) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + a + ')';
  }
  return v;
};

const atlasNodeR = (d: Device) => {
  const st = displayState(d);
  if (st === 'offline' || st === 'blocked') return 15;
  return 15 + Math.min(15, Math.sqrt(d.down + d.up) * 2.4);
};

function atlasLayout(): void {
  atlas.layout.clear();
  atlas.layout.set('gw', { x: ATLAS_GW.x, y: ATLAS_GW.y });
  atlas.layout.set('wan', { x: ATLAS_WAN.x, y: ATLAS_WAN.y });
  const groups: Record<string, Device[]> = { eth: [], wifi5: [], wifi2: [], unknown: [] };
  // Sorted so rings stay stable when the API reorders the device list.
  const devs = state.devices.slice().sort((a, b) => a.id - b.id);
  for (const d of devs) {
    (groups[d.conn] || groups.unknown).push(d);
  }
  const GOLD = 2.39996322973;
  Object.keys(groups).forEach((conn, gi) => {
    groups[conn].forEach((d, i) => {
      // Fixed rings: ethernet innermost, unknown/outermost — signal is often null.
      const baseR =
        conn === 'eth' ? 210 : conn === 'wifi5' ? 300 : conn === 'wifi2' ? 370 : 440;
      const st = displayState(d);
      const dim = st === 'offline' || st === 'blocked' ? 70 : 0;
      const ang = i * GOLD + gi * 1.7;
      const jit = Math.abs((Math.sin(d.id * 12.9898) * 43758.5453) % 1) * 46;
      const r = baseR + dim + jit;
      atlas.layout.set(d.id, { x: Math.cos(ang) * r, y: Math.sin(ang) * r * 0.82 });
    });
  });
}

function atlasResize(): void {
  if (!atlas.canvas || !atlas.canvas.isConnected) return;
  atlas.dpr = window.devicePixelRatio || 1;
  atlas.W = atlas.canvas.clientWidth;
  atlas.H = atlas.canvas.clientHeight;
  atlas.canvas.width = Math.round(atlas.W * atlas.dpr);
  atlas.canvas.height = Math.round(atlas.H * atlas.dpr);
}

const a2s = (wx: number, wy: number): [number, number] => [
  (wx - atlas.cam.x) * atlas.cam.scale + atlas.W / 2,
  (wy - atlas.cam.y) * atlas.cam.scale + atlas.H / 2,
];

const s2a = (sx: number, sy: number): [number, number] => [
  (sx - atlas.W / 2) / atlas.cam.scale + atlas.cam.x,
  (sy - atlas.H / 2) / atlas.cam.scale + atlas.cam.y,
];

function atlasFit(): void {
  const pts: Pt[] = [ATLAS_GW, ATLAS_WAN];
  for (const d of state.devices) {
    const p = atlas.layout.get(d.id);
    if (p) pts.push(p);
  }
  let minX = 1e9;
  let maxX = -1e9;
  let minY = 1e9;
  let maxY = -1e9;
  for (const p of pts) {
    minX = Math.min(minX, p.x);
    maxX = Math.max(maxX, p.x);
    minY = Math.min(minY, p.y);
    maxY = Math.max(maxY, p.y);
  }
  const pad = 90;
  atlas.cam.x = (minX + maxX) / 2;
  atlas.cam.y = (minY + maxY) / 2;
  atlas.cam.scale = clamp(
    Math.min(
      (atlas.W - pad * 2) / (maxX - minX + 1),
      (atlas.H - pad * 2) / (maxY - minY + 1),
    ),
    0.3,
    1.6,
  );
}

function atlasZoom(sx: number, sy: number, f: number): void {
  const [wx, wy] = s2a(sx, sy);
  atlas.cam.scale = clamp(atlas.cam.scale * f, 0.3, 2.4);
  atlas.cam.x = wx - (sx - atlas.W / 2) / atlas.cam.scale;
  atlas.cam.y = wy - (sy - atlas.H / 2) / atlas.cam.scale;
}

function atlasHit(sx: number, sy: number): Device | 'gw' | null {
  for (let i = state.devices.length - 1; i >= 0; i--) {
    const d = state.devices[i];
    const p = atlas.layout.get(d.id);
    if (!p) continue;
    const [x, y] = a2s(p.x, p.y);
    const r = atlasNodeR(d) * clamp(atlas.cam.scale, 0.65, 1.35) + 6;
    if ((sx - x) ** 2 + (sy - y) ** 2 <= r * r) return d;
  }
  const [gx, gy] = a2s(ATLAS_GW.x, ATLAS_GW.y);
  if ((sx - gx) ** 2 + (sy - gy) ** 2 <= (30 * atlas.cam.scale + 10) ** 2) return 'gw';
  return null;
}

function atlasTipHtml(d: Device): string {
  const st = displayState(d);
  const link =
    d.conn === 'eth'
      ? 'Ethernet'
      : d.signal == null || st === 'offline'
        ? '—'
        : d.signal + ' dBm';
  return (
    '<div class="tt-name"><span class="d" style="background:' + atlasColor(st) + '"></span>' +
    esc(d.name) + '</div>' +
    '<div class="tt-grid">' +
    '<span>Status</span><span>' + (st === 'online' ? 'Connected' : st.charAt(0).toUpperCase() + st.slice(1)) + '</span>' +
    '<span>IP</span><span>' + d.ip + '</span>' +
    '<span>Link</span><span>' + link + '</span>' +
    '<span>Traffic</span><span>↓ ' + fmtM(d.down) + ' ↑ ' + fmtM(d.up) + '</span></div>' +
    '<div class="tt-hint">Click for device details</div>'
  );
}

function atlasDrawGrid(c: CanvasRenderingContext2D): void {
  const minor = 70;
  const major = minor * 5;
  const [x0, y0] = s2a(0, 0);
  const [x1, y1] = s2a(atlas.W, atlas.H);
  c.lineWidth = 1;
  const lines = (step: number, color: string) => {
    c.strokeStyle = color;
    c.beginPath();
    for (let x = Math.floor(x0 / step) * step; x <= x1; x += step) {
      const [sx] = a2s(x, 0);
      c.moveTo(sx, 0);
      c.lineTo(sx, atlas.H);
    }
    for (let y = Math.floor(y0 / step) * step; y <= y1; y += step) {
      const [, sy] = a2s(0, y);
      c.moveTo(0, sy);
      c.lineTo(atlas.W, sy);
    }
    c.stroke();
  };
  lines(minor, cssVar('--grid'));
  lines(major, cssVar('--grid-major'));
}

function atlasBezier(
  p0: [number, number],
  p1: [number, number],
  p2: [number, number],
  t: number,
): [number, number] {
  const u = 1 - t;
  return [
    u * u * p0[0] + 2 * u * t * p1[0] + t * t * p2[0],
    u * u * p0[1] + 2 * u * t * p1[1] + t * t * p2[1],
  ];
}

interface LinkOpts {
  color: string;
  width?: number;
  dash?: number[];
  bend?: number;
}

function atlasLink(
  c: CanvasRenderingContext2D,
  a: Pt,
  b: Pt,
  o: LinkOpts,
): [number, number, number, number, number, number] {
  const [ax, ay] = a2s(a.x, a.y);
  const [bx, by] = a2s(b.x, b.y);
  const mx = (ax + bx) / 2;
  const my = (ay + by) / 2;
  const dx = bx - ax;
  const dy = by - ay;
  const len = Math.hypot(dx, dy) || 1;
  const bend = o.bend || 0;
  const cx = mx + (-dy / len) * len * bend;
  const cy = my + (dx / len) * len * bend;
  c.beginPath();
  c.moveTo(ax, ay);
  c.quadraticCurveTo(cx, cy, bx, by);
  c.strokeStyle = o.color;
  c.lineWidth = o.width || 1.4;
  c.setLineDash(o.dash || []);
  c.stroke();
  c.setLineDash([]);
  return [ax, ay, cx, cy, bx, by];
}

function atlasPackets(
  c: CanvasRenderingContext2D,
  ctrl: [number, number, number, number, number, number],
  n: number,
  speed: number,
  color: string,
  now: number,
): void {
  if (n <= 0) return;
  const [ax, ay, cx, cy, bx, by] = ctrl;
  c.fillStyle = color;
  for (let i = 0; i < n; i++) {
    const t = atlasRM ? i / n : (now * speed + i / n) % 1;
    const [px, py] = atlasBezier([ax, ay], [cx, cy], [bx, by], t);
    c.beginPath();
    c.arc(px, py, 2.4, 0, Math.PI * 2);
    c.fill();
  }
}

function atlasDrawGw(c: CanvasRenderingContext2D, now: number): void {
  const [x, y] = a2s(ATLAS_GW.x, ATLAS_GW.y);
  const R = 30 * atlas.cam.scale + 8;
  if (!atlasRM) {
    for (let i = 0; i < 3; i++) {
      const ph = (now * 0.00035 + i / 3) % 1;
      c.beginPath();
      c.arc(x, y, R + ph * 70 * atlas.cam.scale, 0, Math.PI * 2);
      c.strokeStyle = atlasRgba('--accent', (1 - ph) * 0.25);
      c.lineWidth = 1.5;
      c.stroke();
    }
    if (typeof c.createConicGradient === 'function') {
      const grad = c.createConicGradient((now * 0.0006) % (Math.PI * 2), x, y);
      grad.addColorStop(0, atlasRgba('--accent', 0.13));
      grad.addColorStop(0.12, atlasRgba('--accent', 0));
      grad.addColorStop(1, atlasRgba('--accent', 0));
      c.beginPath();
      c.arc(x, y, 95 * atlas.cam.scale, 0, Math.PI * 2);
      c.fillStyle = grad;
      c.fill();
    }
  }
  c.beginPath();
  c.arc(x, y, R, 0, Math.PI * 2);
  c.fillStyle = cssVar('--panel');
  c.fill();
  c.strokeStyle = cssVar('--accent');
  c.lineWidth = 2;
  c.stroke();
  c.fillStyle = cssVar('--accent');
  c.font = '700 ' + Math.round(R * 0.62) + 'px ' + cssVar('--mono');
  c.textAlign = 'center';
  c.textBaseline = 'middle';
  c.fillText('GW', x, y + 1);
  c.font = '650 12.5px ' + cssVar('--sans');
  c.fillStyle = cssVar('--text');
  c.fillText((state.settings.ssid24 || 'HomeNet') + ' Gateway', x, y + R + 16);
  c.font = '500 10.5px ' + cssVar('--mono');
  c.fillStyle = cssVar('--muted');
  c.fillText(gatewayIp(), x, y + R + 31);
}

function atlasDrawWan(c: CanvasRenderingContext2D): void {
  const [x, y] = a2s(ATLAS_WAN.x, ATLAS_WAN.y);
  const R = 22 * atlas.cam.scale + 5;
  const up = state.latency >= 0;
  c.beginPath();
  c.arc(x, y, R, 0, Math.PI * 2);
  c.fillStyle = cssVar('--panel');
  c.fill();
  c.strokeStyle = up ? cssVar('--green') : cssVar('--red');
  c.lineWidth = 1.8;
  c.stroke();
  c.lineWidth = 1.4;
  c.beginPath();
  c.ellipse(x, y, R * 0.5, R * 0.85, 0, 0, Math.PI * 2);
  c.stroke();
  c.beginPath();
  c.moveTo(x - R * 0.85, y);
  c.lineTo(x + R * 0.85, y);
  c.stroke();
  c.beginPath();
  c.moveTo(x - R * 0.7, y - R * 0.4);
  c.quadraticCurveTo(x, y - R * 0.1, x + R * 0.7, y - R * 0.4);
  c.stroke();
  c.font = '650 12px ' + cssVar('--sans');
  c.fillStyle = cssVar('--text');
  c.textAlign = 'center';
  c.textBaseline = 'alphabetic';
  c.fillText('Internet', x, y - R - 9);
  c.font = '500 10.5px ' + cssVar('--mono');
  c.fillStyle = cssVar('--muted');
  c.fillText(
    up ? 'ISP · ' + Math.round(state.latency) + ' ms' : 'ISP · unreachable',
    x,
    y + R + 16,
  );
}

function atlasDrawNode(c: CanvasRenderingContext2D, d: Device, now: number): void {
  const p = atlas.layout.get(d.id);
  if (!p) return;
  const [x, y] = a2s(p.x, p.y);
  if (x < -80 || x > atlas.W + 80 || y < -80 || y > atlas.H + 80) return;
  const st = displayState(d);
  const r = atlasNodeR(d) * clamp(atlas.cam.scale, 0.65, 1.35);
  const col = atlasColor(st);
  const isSel = state.view === 'device' && state.devId === d.id;
  const isHov = atlas.hoverId === d.id;

  if (st === 'warning' && !atlasRM) {
    const ph = (now * 0.001 + d.id) % 1;
    c.beginPath();
    c.arc(x, y, r + 4 + ph * 16, 0, Math.PI * 2);
    c.strokeStyle = atlasRgba('--amber', (1 - ph) * 0.5);
    c.lineWidth = 1.5;
    c.stroke();
  }
  c.beginPath();
  c.arc(x, y, r + 5, 0, Math.PI * 2);
  c.globalAlpha = 0.12;
  c.fillStyle = col;
  c.fill();
  c.globalAlpha = 1;

  c.beginPath();
  c.arc(x, y, r, 0, Math.PI * 2);
  c.fillStyle = cssVar('--panel');
  c.fill();
  c.lineWidth = isSel ? 2.6 : 1.8;
  c.strokeStyle = isSel ? cssVar('--accent') : col;
  if (st === 'offline') c.setLineDash([4, 3]);
  c.stroke();
  c.setLineDash([]);

  if (st !== 'offline' && st !== 'blocked') {
    const frac = clamp((d.down + d.up) / 70, 0, 1);
    if (frac > 0.02) {
      c.beginPath();
      c.arc(x, y, r + 3.5, -Math.PI / 2, -Math.PI / 2 + frac * Math.PI * 2);
      c.strokeStyle = cssVar('--accent');
      c.lineWidth = 2.4;
      c.stroke();
    }
  }
  c.fillStyle = st === 'offline' ? cssVar('--muted') : col;
  c.font = '700 ' + Math.round(clamp(r * 0.62, 9, 13)) + 'px ' + cssVar('--mono');
  c.textAlign = 'center';
  c.textBaseline = 'middle';
  c.fillText(atlasGlyph(d), x, y + 0.5);

  if (isSel || isHov || atlas.cam.scale > 1.15) {
    c.textBaseline = 'alphabetic';
    c.font = (isSel || isHov ? 650 : 600) + ' 12px ' + cssVar('--sans');
    c.fillStyle = isSel || isHov ? cssVar('--accent') : cssVar('--text');
    const name = d.name.length > 22 ? d.name.slice(0, 21) + '…' : d.name;
    c.fillText(name, x, y + r + 17);
    if (atlas.cam.scale > 0.75 || isSel || isHov) {
      c.font = '500 10.5px ' + cssVar('--mono');
      c.fillStyle = cssVar('--muted');
      const sig =
        d.conn !== 'eth' && d.signal != null && st !== 'offline'
          ? ' · ' + d.signal + ' dBm'
          : '';
      c.fillText(d.ip + sig, x, y + r + 31);
    }
  }
}

function atlasSyncLayout(): void {
  const key = state.devices
    .map(d => d.id)
    .sort((a, b) => a - b)
    .join(',');
  if (key !== atlas.layoutKey) {
    atlas.layoutKey = key;
    atlasLayout();
  }
}

function atlasRender(now: number): void {
  const c = atlas.ctx;
  if (!c) return;
  // Self-heal: the mount-time measurement can be stale (or the box can change
  // later). If the element's CSS size disagrees with what we drawn with,
  // re-sync the bitmap and camera before painting this frame.
  if (
    atlas.canvas &&
    (atlas.canvas.clientWidth !== atlas.W || atlas.canvas.clientHeight !== atlas.H)
  ) {
    atlasResize();
  }
  atlasSyncLayout();
  c.setTransform(atlas.dpr, 0, 0, atlas.dpr, 0, 0);
  c.clearRect(0, 0, atlas.W, atlas.H);
  atlasDrawGrid(c);

  const wanCtrl = atlasLink(c, ATLAS_GW, ATLAS_WAN, {
    color: cssVar('--link'),
    width: 2.2,
    bend: 0,
  });
  // WAN packets animate at a rate proportional to the global host throughput.
  atlasPackets(
    c,
    wanCtrl,
    3,
    0.00035 + Math.min(0.0006, hostDown() / 400000),
    cssVar('--green'),
    now,
  );

  for (const d of state.devices) {
    const p = atlas.layout.get(d.id);
    if (!p) continue;
    const st = displayState(d);
    const active = st === 'online' || st === 'warning';
    const ctrl = atlasLink(c, ATLAS_GW, p, {
      color:
        st === 'warning'
          ? atlasRgba('--amber', 0.55)
          : active
            ? cssVar('--link')
            : atlasRgba('--muted', 0.25),
      width: active ? clamp(1.2 + Math.sqrt(d.down + d.up) * 0.22, 1.2, 4) : 1,
      dash: st === 'offline' ? [3, 5] : st === 'blocked' ? [7, 5] : [],
      bend: (d.id % 2 ? 1 : -1) * 0.07,
    });
    if (active && d.down + d.up > 0.05) {
      atlasPackets(
        c,
        ctrl,
        clamp(Math.round((d.down + d.up) / 9), 1, 6),
        0.0004 + Math.min(0.001, (d.down + d.up) / 90000),
        st === 'warning' ? cssVar('--amber') : cssVar('--link-hot'),
        now,
      );
    }
    if (atlas.hoverId === d.id) {
      c.beginPath();
      c.moveTo(ctrl[0], ctrl[1]);
      c.quadraticCurveTo(ctrl[2], ctrl[3], ctrl[4], ctrl[5]);
      c.strokeStyle = cssVar('--accent');
      c.lineWidth = 2;
      c.globalAlpha = 0.6;
      c.stroke();
      c.globalAlpha = 1;
    }
  }

  atlasDrawWan(c);
  atlasDrawGw(c, now);
  for (const d of state.devices) atlasDrawNode(c, d, now);
}

function mountAtlas(): void {
  unmountAtlas();
  atlas.canvas = document.getElementById('atlasCanvas') as HTMLCanvasElement | null;
  if (!atlas.canvas) return;
  atlas.ctx = atlas.canvas.getContext('2d');
  atlasLayout();
  atlas.layoutKey = state.devices
    .map(d => d.id)
    .sort((a, b) => a - b)
    .join(',');
  atlasResize();
  atlasFit();
  if (state.atlasFocus) {
    const fd = findDevice(state.atlasFocus);
    state.atlasFocus = null;
    const fp = fd ? atlas.layout.get(fd.id) : undefined;
    if (fp) {
      atlas.cam.x = fp.x;
      atlas.cam.y = fp.y;
      atlas.cam.scale = 1.5;
    }
  }

  const cv = atlas.canvas;
  const tip = document.getElementById('mapTip') as HTMLDivElement | null;
  let panning = false;
  let dragMoved = false;
  let lastX = 0;
  let lastY = 0;
  let downX = 0;
  let downY = 0;

  cv.addEventListener('pointerdown', e => {
    panning = true;
    dragMoved = false;
    lastX = downX = e.clientX;
    lastY = downY = e.clientY;
    cv.setPointerCapture(e.pointerId);
    cv.classList.add('dragging');
  });
  cv.addEventListener('pointermove', e => {
    if (panning) {
      const dx = e.clientX - lastX;
      const dy = e.clientY - lastY;
      if (Math.abs(e.clientX - downX) + Math.abs(e.clientY - downY) > 5) {
        dragMoved = true;
        if (tip) tip.style.display = 'none';
      }
      atlas.cam.x -= dx / atlas.cam.scale;
      atlas.cam.y -= dy / atlas.cam.scale;
      lastX = e.clientX;
      lastY = e.clientY;
      return;
    }
    const rect = cv.getBoundingClientRect();
    const hit = atlasHit(e.clientX - rect.left, e.clientY - rect.top);
    atlas.hoverId = hit && hit !== 'gw' ? hit.id : null;
    cv.classList.toggle('pointing', !!hit);
    if (hit && hit !== 'gw' && tip) {
      tip.innerHTML = atlasTipHtml(hit);
      tip.style.display = 'block';
      const lx = e.clientX - rect.left;
      const ly = e.clientY - rect.top;
      tip.style.left = clamp(lx + 16, 8, atlas.W - tip.offsetWidth - 8) + 'px';
      tip.style.top = clamp(ly + 16, 8, atlas.H - tip.offsetHeight - 8) + 'px';
    } else if (tip) {
      tip.style.display = 'none';
    }
  });
  cv.addEventListener('pointerup', e => {
    panning = false;
    cv.classList.remove('dragging');
    if (dragMoved) return;
    const rect = cv.getBoundingClientRect();
    const hit = atlasHit(e.clientX - rect.left, e.clientY - rect.top);
    if (hit && hit !== 'gw') location.hash = '#/device/' + hit.id + '/overview';
    else if (hit === 'gw') toastGateway();
  });
  cv.addEventListener('pointerleave', () => {
    if (tip) tip.style.display = 'none';
    atlas.hoverId = null;
    cv.classList.remove('pointing');
  });
  cv.addEventListener(
    'wheel',
    e => {
      e.preventDefault();
      const rect = cv.getBoundingClientRect();
      atlasZoom(e.clientX - rect.left, e.clientY - rect.top, Math.exp(-e.deltaY * 0.0014));
    },
    { passive: false },
  );
  cv.addEventListener('dblclick', e => {
    const rect = cv.getBoundingClientRect();
    atlasZoom(e.clientX - rect.left, e.clientY - rect.top, 1.5);
  });
  for (const b of $$<HTMLButtonElement>('.mapctl button')) {
    b.addEventListener('click', () => {
      const a = b.dataset.atlas;
      if (a === 'in') atlasZoom(atlas.W / 2, atlas.H / 2, 1.3);
      else if (a === 'out') atlasZoom(atlas.W / 2, atlas.H / 2, 1 / 1.3);
      else if (a === 'fit') atlasFit();
      else if (a === 'home') {
        atlas.cam.x = ATLAS_GW.x;
        atlas.cam.y = ATLAS_GW.y;
        atlas.cam.scale = 1;
      }
    });
  }

  atlas.mounted = true;
  // The first measurement can race the layout of a freshly-inserted view;
  // re-measure after the next paint, and keep tracking box changes after that.
  requestAnimationFrame(() => {
    if (atlas.mounted) atlasResize();
  });
  if (typeof ResizeObserver !== 'undefined' && atlas.canvas.parentElement) {
    atlas.ro?.disconnect();
    atlas.ro = new ResizeObserver(() => {
      if (atlas.mounted) atlasResize();
    });
    atlas.ro.observe(atlas.canvas.parentElement);
  }
  const loop = (t: number) => {
    if (!atlas.mounted) return;
    atlasRender(t);
    atlas.raf = requestAnimationFrame(loop);
  };
  atlas.raf = requestAnimationFrame(loop);
}

function toastGateway(): void {
  const st = state.status;
  const up = st && st.startedAt ? dur(Date.now() - Date.parse(st.startedAt)) : '—';
  toast(
    'Gateway ' + gatewayIp() + ' · uptime ' + up + ' · ' + (st ? st.version : ''),
  );
}

function unmountAtlas(): void {
  atlas.mounted = false;
  cancelAnimationFrame(atlas.raf);
  atlas.hoverId = null;
  atlas.ro?.disconnect();
  atlas.ro = null;
}

export function atlasKeyZoom(f: number): void {
  atlasZoom(atlas.W / 2, atlas.H / 2, f);
}

export { atlasZoom, atlasFit, atlasResize, mountAtlas, unmountAtlas };
