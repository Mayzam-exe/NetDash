import { displayState, gatewayIp, state } from '../state';
import { deviceKind, esc } from '../lib/ui';
import type { Device } from '../types';

/* The2D crew: every device is an operative — state-coloured visor, HP bar
   from link quality, rank chips for YOU / GW / TRUSTED / CUT. Clicking an
   agent opens its dossier (same open-device action as the table row). */

/** The operative sprite — shared by the deck, the roster table and the dossier. */
export const FIG =
  '<svg viewBox="0 0 48 48" fill="none" aria-hidden="true">' +
  '<path d="M9 43c0-8 6.5-12 15-12s15 4 15 12" fill="var(--panel2)" ' +
  'stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/>' +
  '<rect x="13" y="9" width="22" height="19" rx="6" fill="var(--panel2)" ' +
  'stroke="currentColor" stroke-width="2.4"/>' +
  '<rect class="visor" x="18" y="16" width="12" height="5.5" rx="2.75" fill="currentColor"/>' +
  '<path class="antenna" d="M24 9V4" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"/>' +
  '<circle class="antenna" cx="24" cy="3" r="2" fill="currentColor"/>' +
  '</svg>';

/** Link quality as an HP bar: eth = full, wifi maps -50..-90 dBm → 100..10%. */
function hp(d: Device, st: string): number {
  if (st === 'offline') return 0;
  if (st === 'blocked') return 25;
  if (d.conn === 'eth') return 100;
  if (d.signal == null) return 90;
  return Math.max(10, Math.min(100, Math.round(((d.signal + 90) / 40) * 90 + 10)));
}

const rank = (d: Device): number => {
  if (d.self) return 0;
  if (deviceKind(d) === 'router' || d.ip === gatewayIp()) return 1;
  const st = displayState(d);
  return st === 'online' ? 2 : st === 'warning' ? 3 : st === 'blocked' ? 4 : 5;
};

function agentHtml(d: Device): string {
  const st = displayState(d);
  const q = hp(d, st);
  const chips =
    (d.self ? '<span class="op-chip you">YOU</span>' : '') +
    (!d.self && (deviceKind(d) === 'router' || d.ip === gatewayIp())
      ? '<span class="op-chip">GW</span>'
      : '') +
    (d.trusted && !d.self ? '<span class="op-chip">TRST</span>' : '');
  const label =
    st === 'blocked'
      ? d.lockdown
        ? 'CUT'
        : 'BLOCKED'
      : st.toUpperCase();
  const sig = d.signal != null && st !== 'offline' && d.conn !== 'eth'
    ? ' · ' + d.signal + ' dBm'
    : '';
  return (
    '<button class="agent st-' + st + '" data-action="open-device" data-id="' + d.id +
    '" title="' + esc(d.name) + ' — ' + label.toLowerCase() + '" aria-label="' +
    esc(d.name) + ', ' + label.toLowerCase() + ', open dossier">' +
    (chips ? '<span class="op-chips">' + chips + '</span>' : '') +
    '<span class="op-fig">' + FIG + '</span>' +
    '<span class="op-name">' + esc(d.name) + '</span>' +
    '<span class="op-hp"><i style="width:' + q + '%"></i></span>' +
    '<span class="op-state">' + label + sig + '</span>' +
    '</button>'
  );
}

export function deckHtml(): string {
  if (!state.devices.length) return '';
  const list = [...state.devices].sort(
    (a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name),
  );
  const cut = state.devices.filter(d => d.lockdown).length;
  return (
    '<section class="card deck">' +
    '<div class="card-head">' +
    '<span class="card-title">Agent deck</span>' +
    '<span class="chipmini">' + list.length + ' units</span>' +
    (cut
      ? '<span class="deck-lock">LOCKDOWN — ' + cut + ' cut off</span>'
      : '') +
    '<span class="right">click an agent for its dossier</span>' +
    '</div>' +
    '<div class="deck-row">' + list.map(agentHtml).join('') + '</div>' +
    '</section>'
  );
}
