import { counts, gatewayIp, hostDown, hostPeakDown, hostUp, latencyGateway, state, unreadAlerts } from '../state';
import { esc, fmtM } from '../lib/ui';
import { alertItemHtml } from './alerts';
import { deckHtml } from './deck';
import { legendHtml, tableHtml, toolbarHtml, filteredDevices } from './devices';

export function dashboardView(): string {
  const c = counts();
  const alerts = state.alerts.slice(0, 6);
  const seg = (inner: string, action?: string, href?: string) =>
    action
      ? '<button class="kpi clickable" data-action="' + action + '"' +
        (href ? ' data-href="' + href + '"' : '') + '>' + inner + '</button>'
      : '<div class="kpi">' + inner + '</div>';
  const wanUp = state.latency >= 0;
  const gwMs = latencyGateway();
  const unread = unreadAlerts();
  return (
    '<div class="dash">' +
    '<div class="kpis">' +
    seg(
      '<span class="kpi-label">Internet</span>' +
      '<span class="kpi-row"><span class="dot ' + (wanUp ? 'on' : 'critical') +
      '" id="kpiWanDot"></span><span class="kpi-big text" id="kpiWanState">' +
      (wanUp ? 'Online' : 'Offline') + '</span></span>' +
      '<span class="kpi-sub" id="kpiGwSub">Gateway ' + esc(gatewayIp()) + ' · ' +
      (gwMs >= 0 ? Math.round(gwMs) + ' ms' : '—') + ' · click to test</span>',
      'wan-test',
    ) +
    seg(
      '<span class="kpi-label">Latency</span>' +
      '<span class="kpi-big"><span id="kpiLat">' +
      (wanUp ? Math.round(state.latency) : '—') +
      '</span><span class="unit">ms</span></span>' +
      '<span class="kpi-sub pr" id="kpiLatSub">' +
      (wanUp ? 'to 1.1.1.1 · 0% loss' : 'no reply from 1.1.1.1') +
      '</span>' +
      '<canvas class="spark" id="sparkLat"></canvas>',
    ) +
    seg(
      '<span class="kpi-label">Throughput</span>' +
      '<span class="kpi-big"><span class="down-ic">↓</span> <span id="kpiDown">' +
      fmtM(hostDown()) +
      '</span><span class="unit">Mb/s</span></span>' +
      '<span class="kpi-sub"><span class="up-ic">↑</span> <span id="kpiUp">' +
      fmtM(hostUp()) + '</span> Mb/s now</span>' +
      '<span class="kpi-sub" style="color:var(--muted)">peak <span id="kpiPeak">' +
      fmtM(hostPeakDown()) + '</span> Mb/s since start</span>',
    ) +
    seg(
      '<span class="kpi-label">Devices</span>' +
      '<span class="kpi-big"><span id="kpiDevOn">' + c.connected + '</span> / ' +
      c.total + '</span>' +
      '<span class="kpi-split"><span class="chipmini ok" id="chipOnline">' +
      c.online + ' online</span>' +
      '<span class="chipmini warn" id="chipWarn">' + c.warning + ' warn</span>' +
      '<span class="chipmini bad" id="chipOff">' +
      c.offline + c.blocked + ' off/blk</span></span>',
      'nav',
      '#/devices',
    ) +
    seg(
      '<span class="kpi-label">Alerts</span>' +
      '<span class="kpi-big" style="color:' +
      (unread ? 'var(--amber)' : 'inherit') + '"><span id="kpiAlerts">' + unread +
      '</span></span>' +
      '<span class="kpi-sub" id="kpiAlertsSub">' +
      (unread ? 'needs attention' : 'all clear') + '</span>',
      'nav',
      '#/alerts',
    ) +
    '</div>' +
    deckHtml() +
    '<section class="card scope">' +
    '<div class="card-head"><span class="card-title">Bandwidth</span>' +
    '<span class="right"><span id="bwNow">↓ 0 · ↑ 0</span><span class="sep-dot"></span>' +
    'last 60 seconds</span></div>' +
    '<div class="chart-wrap"><canvas id="bwChart"></canvas>' +
    '<div class="chart-tip" id="bwTip"></div></div>' +
    '<div class="chart-legend"><span><i style="background:var(--green)"></i>Download</span>' +
    '<span><i style="background:var(--blue)"></i>Upload</span>' +
    '<span class="chart-vals" id="bwMax"></span></div>' +
    '</section>' +
    '<div class="dash-body">' +
    '<section class="card table-card">' +
    toolbarHtml('Devices', true) +
    '<div class="tbl-scroll">' + tableHtml() + '</div>' +
    '<div class="tbl-foot"><span id="tblCount">' + filteredDevices().length +
    ' of ' + state.devices.length + ' devices</span>' + legendHtml() + '</div>' +
    '</section>' +
    '<div class="right-rail">' +
    '<section class="card alerts-card">' +
    '<div class="card-head"><span class="card-title">Alerts</span>' +
    '<span class="right"><button class="chip" data-action="nav" data-href="#/alerts">' +
    'View all</button></span></div>' +
    '<div class="alert-list" id="alertList">' +
    (alerts.length
      ? alerts.map(alertItemHtml).join('')
      : '<div class="empty">No alerts — the network is healthy.</div>') +
    '</div></section>' +
    '</div></div></div>'
  );
}
