import { counts, hostDown, hostUp, latencyWan } from '../state';
import { fmtM } from '../lib/ui';

export function mapView(): string {
  const seg = (id: string, label: string, val: string) =>
    '<div class="seg"><span class="sl">' + label + '</span><span class="sv" id="' +
    id + '">' + val + '</span></div>';
  const row = (cls: string, label: string, id: string) =>
    '<div class="row"><span class="' + cls + '"></span>' + label +
    '<b id="' + id + '">0</b></div>';
  const key = (cls: string, label: string) =>
    '<div class="row"><span class="' + cls + '"></span>' + label + '</div>';
  return (
    '<div class="atlas">' +
    '<canvas id="atlasCanvas" role="application" tabindex="0" aria-label="Network topology map. ' +
    'Drag to pan, scroll to zoom, click a device for details. An accessible device list is on the Devices page."></canvas>' +
    '<div class="map-hud map-stats">' +
    seg('atlasLat', 'Latency', '—') +
    seg('atlasDown', 'Download', '—') +
    seg('atlasUp', 'Upload', '—') +
    '</div>' +
    '<aside class="map-hud map-legend" aria-label="Map legend">' +
    '<h4>Map legend</h4>' +
    row('dotc on', 'Connected', 'atlasLgOn') +
    row('dotc warning', 'Warning', 'atlasLgWarn') +
    row('dotc offline', 'Offline', 'atlasLgOff') +
    row('dotc blocked', 'Blocked', 'atlasLgBlk') +
    '<div class="row" style="margin-top:7px;padding-top:8px;border-top:1px solid var(--border)">' +
    '<span class="ln"></span>Active link</div>' +
    key('ln warn', 'Degraded') +
    key('ln off', 'Idle / down') +
    key('sz', 'Size = traffic') +
    '<div class="hint">Drag to pan · Scroll to zoom · Click a device for details</div>' +
    '</aside>' +
    '<div class="map-hud mapctl">' +
    '<button data-atlas="in" title="Zoom in" aria-label="Zoom in">+</button>' +
    '<button data-atlas="out" title="Zoom out" aria-label="Zoom out">−</button>' +
    '<div class="sep"></div>' +
    '<button data-atlas="fit" title="Fit to view" aria-label="Fit map to view">⤢</button>' +
    '<button data-atlas="home" title="Recenter gateway" aria-label="Recenter on gateway">◎</button>' +
    '</div>' +
    '<div class="map-tip" id="mapTip"></div>' +
    '</div>'
  );
}

export function atlasHud(td: number = hostDown(), tu: number = hostUp()): void {
  const set = (id: string, v: string) => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = v;
  };
  const lat = latencyWan();
  set('atlasLat', lat >= 0 ? Math.round(lat) + '<span class="u">ms</span>' : '—');
  set('atlasDown', fmtM(td) + '<span class="u">Mb/s</span>');
  set('atlasUp', fmtM(tu) + '<span class="u">Mb/s</span>');
  const c = counts();
  set('atlasLgOn', String(c.online));
  set('atlasLgWarn', String(c.warning));
  set('atlasLgOff', String(c.offline));
  set('atlasLgBlk', String(c.blocked));
}
