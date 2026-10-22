import { getSettings, putSettings } from '../api';
import { defaultPrefs, state } from '../state';
import { checked, esc, toast, val } from '../lib/ui';
import type { Settings, Status } from '../types';

/**
 * Lockdown — the panic switch. When engaged, every device loses internet
 * except this machine, the router, and anything the user marked Trusted.
 *
 * It applies the moment it is toggled (no "Save changes" round trip): a panic
 * button that waits for a save is not a panic button. The backend refuses the
 * switch when it has no enforcement path, and this section reports that
 * instead of pretending the network is protected.
 */
function lockdownSection(s: Settings, status: Status | null): string {
  const row = (label: string, control: string, hint?: string) =>
    '<div class="form-row"><div class="flabel">' + label + '</div><div>' + control +
    '</div><div class="fhint">' + (hint || '') + '</div></div>';

  const canEnforce = (status?.blocking || '').startsWith('active');
  const cut = state.devices.filter(
    d => !d.self && d.ip !== s.gatewayIp && !d.trusted,
  ).length;
  const total = state.devices.length;
  // status.blocking already reads "unavailable: <reason>", so strip that
  // before prefixing again — otherwise the hint renders "Unavailable:
  // unavailable: …". The reason is also escaped here because it can contain
  // "<netdash binary>", which raw HTML would swallow as an unknown tag (it
  // vanished from the UI entirely before this line existed).
  const reason = (status?.blocking || 'no enforcement path').replace(
    /^unavailable:\s*/i,
    '',
  );
  const hint = canEnforce
    ? 'Applies immediately — no need to press Save. ' +
      (total === 0
        ? 'No devices discovered yet.'
        : cut + ' of ' + total + ' device(s) will lose internet, ' + (total - cut) + ' stay online.')
    : 'Unavailable: ' + esc(reason) +
      '. NetDash will not engage a lockdown it cannot actually enforce — ' +
      'give this machine raw/admin capabilities, or run it on the gateway.';

  return (
    '<section class="card settings-sec" style="border-left:3px solid ' +
    (s.lockdown ? 'var(--red)' : 'var(--border)') + '">' +
    '<div class="card-head"><span class="card-title">Lockdown</span>' +
    '<span class="desc" style="margin-left:12px">Panic switch — the internet stops for everyone but you</span>' +
    (s.lockdown
      ? '<span class="chipmini" style="margin-left:auto;color:var(--red);border-color:var(--red)">' +
        'ENGAGED</span>'
      : '') +
    '</div><div style="padding:6px 18px">' +
    row('Mode',
      '<label style="display:flex;align-items:center;gap:10px;font-size:13.5px;cursor:pointer' +
      (canEnforce ? '' : ';opacity:.55') + '">' +
      '<input type="checkbox" id="gLockdown" data-action="toggle-lockdown"' +
      (s.lockdown ? ' checked' : '') + (canEnforce ? '' : ' disabled') + '>' +
      '<b>Block internet for every device except this machine and Trusted ones</b></label>',
      hint) +
    row('Trusted devices',
      '<a class="btn" href="#/devices">Choose on the Devices page</a>',
      'Open a device → Overview → “Keep online during lockdown”. Anything not marked stays ' +
      'cut off. Per-device blocks and active-hours schedules still apply once lockdown is released.') +
    '</div></section>'
  );
}

export function settingsView(): string {
  const s = state.settings;
  const p = state.prefs;
  const status = state.status;
  const row = (label: string, control: string, hint?: string) =>
    '<div class="form-row"><div class="flabel">' + label + '</div><div>' + control +
    '</div><div class="fhint">' + (hint || '') + '</div></div>';
  const sel = (id: string, opts: string[], v: string) =>
    '<select class="inp" id="' + id + '">' +
    opts.map(o => '<option' + (o === v ? ' selected' : '') + '>' + o + '</option>').join('') +
    '</select>';
  const txt = (id: string, v: string, mono?: boolean) =>
    '<input class="inp' + (mono ? ' mono' : '') + '" id="' + id + '" value="' + esc(v) + '">';
  const sec = (title: string, desc: string, inner: string) =>
    '<section class="card settings-sec"><div class="card-head"><span class="card-title">' +
    title + '</span><span class="desc" style="margin-left:12px">' + desc +
    '</span></div><div style="padding:6px 18px">' + inner + '</div></section>';
  const cap = (label: string, v: string, ok: boolean) => {
    // Enforcement reasons run to 200+ chars and repeat across rows ("behind
    // gateway … (arp: raw packet access denied — need CAP_NET_RAW (sudo
    // setcap …))"), which wrapped the whole panel. Split the remediation hint
    // onto its own muted line so the status itself stays scannable.
    const i = v.indexOf(' (arp: ');
    const head = i > 0 ? v.slice(0, i) : v;
    const fix = i > 0 ? v.slice(i + 7, v.length - 1) : '';
    return (
      '<div style="display:flex;gap:10px;font-size:12.5px;padding:3px 0">' +
      '<span style="width:170px;color:var(--muted);flex:none">' + label + '</span>' +
      '<div style="min-width:0">' +
      '<div style="color:' + (ok ? 'var(--green)' : 'var(--amber)') + '">' +
      esc(head) + '</div>' +
      (fix ? '<div style="color:var(--muted)">' + esc(fix) + '</div>' : '') +
      '</div></div>'
    );
  };
  return (
    '<div style="display:flex;align-items:center;gap:10px;margin-bottom:14px">' +
    '<h2 style="margin:0;font-size:18px">Settings</h2>' +
    '<div style="margin-left:auto;display:flex;gap:9px">' +
    '<button class="btn" data-action="discard-settings">Discard</button>' +
    '<button class="btn primary" data-action="save-settings">Save changes</button></div></div>' +
    '<div class="card" style="padding:12px 16px;margin-bottom:14px;border-left:3px solid var(--amber);font-size:13px;color:var(--muted)">' +
    '<b style="color:var(--text)">NetDash monitors this network — it does not manage your router.</b> ' +
    'Only <b>WAN IP, both SSIDs, router IP and the SNMP block</b> are stored by NetDash and used by the backend. ' +
    'Fields marked <i>reference only</i> (connection type, DNS, Wi-Fi channel/security/password, DHCP range, firewall/UPnP/remote) ' +
    'are kept in your browser for your own reference and are <b>not applied</b> to any device.</div>' +
    lockdownSection(s, status) +
    sec(
      'Internet',
      'How your network reaches the world',
      row('Connection type', sel('gWanType', ['DHCP', 'PPPoE', 'Static'], p.wanType),
        'Reference only — not applied by NetDash') +
      row('WAN IP', txt('gWanIp', s.wanIp, true),
        status ? 'Status reports ' + status.wanIp : 'Reported by the gateway') +
      row('DNS servers',
        '<div class="radio-group">' +
        '<label><input type="radio" name="gDns" id="gDnsAuto"' +
        (p.dnsMode === 'auto' ? ' checked' : '') + '> Auto</label>' +
        '<label><input type="radio" name="gDns" id="gDnsCustom"' +
        (p.dnsMode === 'custom' ? ' checked' : '') + '> Custom</label></div>' +
        '<div style="display:flex;gap:8px;margin-top:8px">' + txt('gDns1', p.dns1, true) +
        txt('gDns2', p.dns2, true) + '</div>',
        'Reference only — not applied by NetDash (DNS is taken from the OS)'),
    ) +
    sec(
      'Wi-Fi',
      'Wireless network names and radio settings',
      row('2.4 GHz SSID', txt('gSsid24', s.ssid24),
        'Used by the dashboard to label 2.4 GHz devices') +
      row('2.4 GHz channel / bandwidth',
        '<div style="display:flex;gap:8px">' +
        sel('gCh24', ['Auto', '1', '6', '11'], p.ch24) +
        sel('gBw24', ['20 MHz', '40 MHz'], p.bw24) + '</div>',
        'Reference only — not applied by NetDash') +
      row('5 GHz SSID', txt('gSsid5', s.ssid5),
        'Used by the dashboard to label 5 GHz devices') +
      row('5 GHz channel / bandwidth',
        '<div style="display:flex;gap:8px">' +
        sel('gCh5', ['Auto', '36', '44', '149', '157'], p.ch5) +
        sel('gBw5', ['40 MHz', '80 MHz', '160 MHz'], p.bw5) + '</div>',
        'Reference only — not applied by NetDash') +
      row('Security', sel('gSec', ['WPA3', 'WPA2/WPA3 mixed', 'WPA2'], p.sec),
        'Reference only — not applied by NetDash') +
      row('Password', txt('gPass', p.pass),
        'Reference only — stored locally in your browser, not applied by NetDash') +
      row('Guest network',
        sel('gGuest', ['Off', 'On — 2.4 GHz', 'On — both bands'], p.guest),
        'Reference only — not applied by NetDash'),
    ) +
    sec(
      'LAN & DHCP',
      'Addresses inside your network',
      row('Router IP', txt('gRouterIp', s.gatewayIp, true), 'Your gateway and admin address — used by NetDash') +
      row('DHCP range',
        '<div style="display:flex;gap:8px;align-items:center">' +
        txt('gDhcpStart', p.dhcpStart, true) +
        '<span style="color:var(--muted)">─</span>' +
        txt('gDhcpEnd', p.dhcpEnd, true) + '</div>',
        'Reference only — not applied by NetDash') +
      row('Lease time', sel('gLease', ['12 hours', '24 hours', '7 days'], p.lease),
        'Reference only — not applied by NetDash'),
    ) +
    sec(
      'Monitoring',
      'Router data source (SNMP v2c)',
      row('SNMP polling',
        '<label style="display:flex;align-items:center;gap:8px;font-size:13.5px">' +
        '<input type="checkbox" id="gSnmp"' + (s.snmpEnabled ? ' checked' : '') + '>' +
        ' Poll the router for neighbors, link types and WAN traffic</label>',
        'Fills connection types (Ethernet/Wi-Fi), DHCP names and true WAN throughput') +
      row('Router (SNMP host)', txt('gSnmpHost', s.snmpHost, true),
        'Usually the same as the router IP') +
      row('Community', txt('gSnmpCommunity', s.snmpCommunity, true),
        'SNMPv2c community string — keep it non-default') +
      row('WAN interface', txt('gSnmpWanIf', s.snmpWanIf, true),
        'Substring of the interface name, e.g. wan0 — empty = auto-detect') +
      '<div style="margin-top:8px;padding-top:10px;border-top:1px solid rgba(128,128,128,.18)">' +
      cap('Network path',
        status?.path === 'gateway'
          ? 'on the gateway path — traffic crosses this host'
          : 'behind gateway — traffic does not cross this host',
        status?.path === 'gateway') +
      cap('Device blocking', status?.blocking || '—',
        (status?.blocking || '').startsWith('active')) +
      cap('Speed limiting', status?.speed || '—',
        (status?.speed || '').startsWith('active')) +
      cap('Per-device metering', status?.metering || '—', status?.metering === 'active') +
      '<div class="fhint" style="padding-top:4px">Blocking and speed limits ride on the same ARP ' +
      'bridge from this machine (setcap cap_net_raw,cap_net_admin+ep) — limits are loss-based, ' +
      'so TCP throttles smoothly. Metering needs NetDash on the gateway itself.</div>' +
      '</div>',
    ) +
    sec(
      'DNS spoofing',
      'Red team — forge answers for intercepted devices',
      (state.spoofRules.length
        ? state.spoofRules
            .map(
              r =>
                '<div class="form-row" style="padding:5px 0">' +
                '<div class="flabel mono">' + esc(r.domain) + '</div>' +
                '<div style="display:flex;gap:10px;align-items:center">' +
                '<span class="mono">→ ' + esc(r.ip) + '</span>' +
                '<button class="btn ghostdanger" data-action="spoof-del" data-id="' + r.id +
                '" style="margin-left:auto">Remove</button></div>' +
                '<div class="fhint"></div></div>',
            )
            .join('')
        : '<div class="fhint" style="padding:6px 0">No rules yet — a matching query from an ' +
          'intercepted device gets your IP back instead of the real answer.</div>') +
      '<div class="form-row" style="border-top:1px solid rgba(128,128,128,.18);padding-top:10px">' +
      '<div class="flabel">New rule</div>' +
      '<div style="display:flex;gap:8px">' +
      '<input class="inp mono" id="spoofDomain" placeholder="updates.example.com" style="flex:1">' +
      '<input class="inp mono" id="spoofIp" placeholder="192.168.1.48" style="width:150px">' +
      '<button class="btn primary" data-action="spoof-add">Add rule</button></div>' +
      '<div class="fhint">Applies to devices routed through this machine (intercept or speed limit) — ' +
      'point the IP at a service you control on the LAN.</div></div>',
    ) +
    sec(
      'Security',
      'Firewall and exposure',
      row('Firewall', sel('gFirewall', ['On', 'Off'], p.firewall),
        'Reference only — not applied by NetDash (it uses nftables/ARP, see Monitoring)') +
      row('UPnP', sel('gUpnp', ['Off', 'On'], p.upnp),
        'Reference only — not applied by NetDash') +
      row('Remote management', sel('gRemote', ['Off', 'On'], p.remote),
        'Reference only — not applied by NetDash'),
    ) +
    '<section class="card settings-sec"><div class="card-head">' +
    '<span class="card-title">System</span>' +
    '<span class="desc" style="margin-left:12px">Firmware and maintenance</span></div>' +
    '<div style="padding:14px 18px">' +
    '<div class="form-row"><div class="flabel">Firmware</div>' +
    '<div class="mono">v' + esc(status ? status.version : '—') + ' (up to date)</div>' +
    '<div class="fhint">Reported by the gateway</div></div>' +
    '<div class="form-actions" style="justify-content:flex-start;flex-wrap:wrap;padding-top:14px">' +
    '<button class="btn" data-action="fw-check">Check for updates</button>' +
    '<button class="btn" data-action="export-config">Export config</button>' +
    '<button class="btn" data-action="import-config">Import config</button>' +
    '<button class="btn" data-action="reboot">Reboot router</button>' +
    '<button class="btn danger" data-action="factory-reset">Factory reset</button>' +
    '</div></div></section>'
  );
}

/** Read the settings form into memory (API fields + client-only prefs). */
export function collectGlobalSettings(): void {
  if (document.getElementById('gWanType') == null) return;
  const s = state.settings;
  const p = state.prefs;
  s.wanIp = val('gWanIp');
  s.ssid24 = val('gSsid24');
  s.ssid5 = val('gSsid5');
  s.gatewayIp = val('gRouterIp');
  s.snmpEnabled = checked('gSnmp');
  s.snmpHost = val('gSnmpHost');
  s.snmpCommunity = val('gSnmpCommunity');
  s.snmpWanIf = val('gSnmpWanIf');
  p.wanType = val('gWanType');
  p.dnsMode = checked('gDnsAuto') ? 'auto' : 'custom';
  p.dns1 = val('gDns1');
  p.dns2 = val('gDns2');
  p.ch24 = val('gCh24');
  p.bw24 = val('gBw24');
  p.ch5 = val('gCh5');
  p.bw5 = val('gBw5');
  p.sec = val('gSec');
  p.pass = val('gPass');
  p.guest = val('gGuest');
  p.dhcpStart = val('gDhcpStart');
  p.dhcpEnd = val('gDhcpEnd');
  p.lease = val('gLease');
  p.firewall = val('gFirewall');
  p.upnp = val('gUpnp');
  p.remote = val('gRemote');
}

export async function saveSettings(): Promise<void> {
  collectGlobalSettings();
  try {
    state.settings = await putSettings(state.settings);
    toast('Saved to NetDash: WAN IP, SSIDs, router IP and SNMP. Network/Wi-Fi controls are reference-only and were not applied.');
  } catch {
    toast('Could not reach the API — settings not saved', 'err');
  }
}

/**
 * Engage or release lockdown right away. The switch deliberately bypasses
 * "Save changes" — and if the backend refuses (no enforcement path, or the
 * API is unreachable) the toggle snaps back rather than showing a protected
 * network that is not protected.
 */
export async function setLockdown(on: boolean): Promise<void> {
  const prev = state.settings.lockdown;
  state.settings.lockdown = on;
  try {
    state.settings = await putSettings(state.settings);
    toast(on ? 'Lockdown engaged — internet cut for untrusted devices' : 'Lockdown released');
  } catch (e) {
    state.settings.lockdown = prev;
    toast(e instanceof Error ? e.message : 'Could not change lockdown', 'err');
  }
}

export async function discardSettings(): Promise<void> {
  state.prefs = defaultPrefs();
  try {
    state.settings = await getSettings();
  } catch {
    /* keep whatever we had */
  }
  toast('Changes discarded', 'warn');
}
