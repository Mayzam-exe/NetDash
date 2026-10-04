import { findDevice, state } from '../state';
import { $, clamp, cssVar, fmtM } from './ui';

interface CanvasCtx {
  ctx: CanvasRenderingContext2D;
  w: number;
  h: number;
}

export function setupCanvas(c: HTMLCanvasElement): CanvasCtx | null {
  const dpr = window.devicePixelRatio || 1;
  const w = c.clientWidth;
  const h = c.clientHeight;
  if (!w || !h) return null;
  c.width = Math.round(w * dpr);
  c.height = Math.round(h * dpr);
  const ctx = c.getContext('2d');
  if (!ctx) return null;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w, h };
}

export function niceMax(v: number): number {
  if (v <= 5) return 5;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / p;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p;
}

export interface AreaSeries {
  data: number[];
  color: string;
  fill?: string;
}

export interface AreaOpts {
  max?: number;
  min?: number;
  padL?: number;
  fmtY?: (v: number) => string;
}

export function drawArea(
  canvas: HTMLCanvasElement,
  series: AreaSeries[],
  opts?: AreaOpts,
): void {
  const o: AreaOpts = opts || {};
  const s = setupCanvas(canvas);
  if (!s) return;
  const ctx = s.ctx;
  const W = s.w;
  const H = s.h;
  const padL = o.padL || 38;
  const padR = 8;
  const padT = 10;
  const padB = 16;
  let max = o.max;
  if (max == null) {
    let m = 0;
    for (const se of series) for (const v of se.data) if (v > m) m = v;
    max = niceMax(Math.max(m, 1));
  }
  const min = o.min != null ? o.min : 0;
  const n = Math.max(...series.map(se => se.data.length));
  const X = (i: number) =>
    padL + (n <= 1 ? 0 : i / (n - 1)) * (W - padL - padR);
  const Y = (v: number) =>
    padT + (1 - (v - min) / (max - min)) * (H - padT - padB);
  ctx.clearRect(0, 0, W, H);
  ctx.strokeStyle = cssVar('--grid');
  ctx.fillStyle = cssVar('--muted');
  ctx.font = '10px ' + cssVar('--mono');
  ctx.lineWidth = 1;
  const steps = 2;
  for (let g = 0; g <= steps; g++) {
    const v = min + ((max - min) * g) / steps;
    const y = Y(v);
    ctx.beginPath();
    ctx.moveTo(padL, y);
    ctx.lineTo(W - padR, y);
    ctx.stroke();
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    ctx.fillText(o.fmtY ? o.fmtY(v) : fmtM(v), padL - 6, y);
  }
  ctx.textAlign = 'left';
  ctx.textBaseline = 'alphabetic';
  ctx.fillText('-60s', padL, H - 3);
  ctx.textAlign = 'right';
  ctx.fillText('now', W - padR, H - 3);
  for (const se of series) {
    if (!se.data.length) continue;
    const path = () => {
      ctx.beginPath();
      se.data.forEach((v, i) => {
        const x = X(i);
        const y = Y(clamp(v, min, max));
        if (i) ctx.lineTo(x, y);
        else ctx.moveTo(x, y);
      });
    };
    path();
    if (se.fill) {
      ctx.save();
      ctx.lineTo(X(se.data.length - 1), Y(min));
      ctx.lineTo(X(0), Y(min));
      ctx.closePath();
      ctx.fillStyle = se.fill;
      ctx.fill();
      ctx.restore();
      path();
    }
    ctx.strokeStyle = se.color;
    ctx.lineWidth = 1.8;
    ctx.lineJoin = 'round';
    ctx.stroke();
  }
}

export function drawSpark(
  canvas: HTMLCanvasElement,
  data: number[],
  color: string,
): void {
  const s = setupCanvas(canvas);
  if (!s) return;
  const ctx = s.ctx;
  const W = s.w;
  const H = s.h;
  let max = 0;
  for (const v of data) if (v > max) max = v;
  max = Math.max(max, 10);
  ctx.clearRect(0, 0, W, H);
  ctx.beginPath();
  data.forEach((v, i) => {
    const x = 1 + (i / (data.length - 1)) * (W - 2);
    const y = H - 2 - (v / max) * (H - 4);
    if (i) ctx.lineTo(x, y);
    else ctx.moveTo(x, y);
  });
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.5;
  ctx.stroke();
}

/** (Re)bind every chart canvas present in the current view. */
export function refreshCharts(): void {
  state.charts = [];
  const bw = $<HTMLCanvasElement>('#bwChart');
  if (bw) {
    const draw = () =>
      drawArea(bw, [
        { data: state.series.down, color: cssVar('--green'), fill: cssVar('--green-a') },
        { data: state.series.up, color: cssVar('--blue'), fill: cssVar('--blue-a') },
      ]);
    state.charts.push(draw);
    draw();
  }
  const sl = $<HTMLCanvasElement>('#sparkLat');
  if (sl) {
    const draw = () =>
      drawSpark(
        sl,
        state.series.lat,
        state.latency < 0
          ? cssVar('--red')
          : state.latency > 60
            ? cssVar('--amber')
            : cssVar('--blue'),
      );
    state.charts.push(draw);
    draw();
  }
  const dv = $<HTMLCanvasElement>('#devChart');
  if (dv) {
    const d = state.devId != null ? findDevice(state.devId) : undefined;
    const ds = state.devId != null ? state.devSeries.get(state.devId) : undefined;
    if (d && ds) {
      const draw = () =>
        drawArea(dv, [
          { data: ds.down, color: cssVar('--green'), fill: cssVar('--green-a') },
          { data: ds.up, color: cssVar('--blue'), fill: cssVar('--blue-a') },
        ]);
      state.charts.push(draw);
      draw();
    }
  }
  const sg = $<HTMLCanvasElement>('#sigChart');
  if (sg) {
    const ds = state.devId != null ? state.devSeries.get(state.devId) : undefined;
    if (ds && ds.sig.length) {
      const draw = () =>
        drawArea(sg, [{ data: ds.sig, color: cssVar('--amber'), fill: 'rgba(245,185,66,.12)' }], {
          min: -90,
          max: -40,
          fmtY: v => String(Math.round(v)),
        });
      state.charts.push(draw);
      draw();
    }
  }
}
