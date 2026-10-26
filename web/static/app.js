/* netscout UI — vanilla JS, no build step. Talks to the local JSON API and
   listens to /api/stream (SSE) for live updates. */
(() => {
  'use strict';

  // ---------- helpers --------------------------------------------------------
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const api = async (path, opts = {}) => {
    const res = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...opts });
    if (res.status === 204) return null;
    const ct = res.headers.get('content-type') || '';
    const body = ct.includes('json') ? await res.json() : await res.text();
    if (!res.ok) throw new Error((body && body.error) || res.statusText);
    return body;
  };
  const post = (path, body) => api(path, { method: 'POST', body: JSON.stringify(body || {}) });
  const patch = (path, body) => api(path, { method: 'PATCH', body: JSON.stringify(body || {}) });
  const del = (path) => api(path, { method: 'DELETE' });

  let toastTimer;
  const toast = (msg, err = false) => {
    const t = $('#toast');
    t.textContent = msg;
    t.classList.toggle('err', err);
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (t.hidden = true), err ? 6000 : 3000);
  };

  const ago = (iso) => {
    if (!iso || iso.startsWith('0001')) return 'never';
    const d = (Date.now() - new Date(iso).getTime()) / 1000;
    if (d < 2) return 'now';
    if (d < 60) return Math.floor(d) + 's';
    if (d < 3600) return Math.floor(d / 60) + 'm';
    if (d < 86400) return Math.floor(d / 3600) + 'h';
    return Math.floor(d / 86400) + 'd';
  };
  const agoText = (iso) => { const a = ago(iso); return a === 'now' ? 'just now' : a === 'never' ? 'never' : a + ' ago'; };
  const when = (iso) => (!iso || iso.startsWith('0001')) ? 'never' : new Date(iso).toLocaleString();
  const hhmmss = (iso) => new Date(iso).toLocaleTimeString([], { hour12: false });
  const ipKey = (ip) => (ip || '').split('.').map((n) => n.padStart(3, '0')).join('.') || '999';

  const SERVICE_NAMES = {
    '_netaudio-arc._udp': 'Dante', '_netaudio-chan._udp': 'Dante', '_netaudio-cmc._udp': 'Dante', '_netaudio-dbc._udp': 'Dante',
    '_airplay._tcp': 'AirPlay', '_raop._tcp': 'AirPlay', '_ipp._tcp': 'Printer', '_printer._tcp': 'Printer', '_pdl-datastream._tcp': 'Printer',
    '_http._tcp': 'HTTP', '_https._tcp': 'HTTPS', '_ssh._tcp': 'SSH', '_sftp-ssh._tcp': 'SSH', '_smb._tcp': 'SMB', '_afpovertcp._tcp': 'AFP',
    '_googlecast._tcp': 'Chromecast', '_spotify-connect._tcp': 'Spotify', '_homekit._tcp': 'HomeKit', '_hap._tcp': 'HomeKit', '_sonos._tcp': 'Sonos',
    '_qsc-qsys._tcp': 'Q-SYS', '_qsys._tcp': 'Q-SYS', '_shure._tcp': 'Shure', '_osc._udp': 'OSC', '_artnet._udp': 'Art-Net', '_sacn._udp': 'sACN',
    '_ndi._tcp': 'NDI', '_rtsp._tcp': 'RTSP', '_workstation._tcp': 'Workstation', '_companion-link._tcp': 'Apple', '_rdlink._tcp': 'Apple', '_device-info._tcp': '',
  };
  const prettyServices = (list) => {
    const out = [];
    for (const s of (list || '').split(',').filter(Boolean)) {
      const name = s in SERVICE_NAMES ? SERVICE_NAMES[s] : s.split('.')[0].replace(/^_/, '');
      if (name && !out.includes(name)) out.push(name);
    }
    return out;
  };
  const infoFor = (d) => {
    const a = d.attrs || {};
    const parts = [];
    if (a.dhcp_vendor_class) parts.push(a.dhcp_vendor_class);
    if (a.lldp_sysdesc) parts.push(a.lldp_sysdesc); else if (a.cdp_platform) parts.push(a.cdp_platform);
    if (a.lldp_port) parts.push('port ' + a.lldp_port);
    if (a.vlan) parts.push('vlan ' + a.vlan);
    return parts.join(' · ');
  };
  const nameFor = (d) => d.label || d.hostname || '';

  // ---------- state ----------------------------------------------------------
  const state = {
    devices: [], status: null, subnets: [], subnet: null, map: null, selectedIP: null,
    sort: JSON.parse(localStorage.getItem('ns.sort') || '{"key":"online","asc":true}'),
    eventKind: '', events: [], selectedMAC: null, tab: localStorage.getItem('ns.tab') || 'live',
    statusFilter: new Set(),
  };

  // ---------- tabs -----------------------------------------------------------
  const showTab = (name) => {
    state.tab = name;
    localStorage.setItem('ns.tab', name);
    $$('#tabs button').forEach((b) => b.classList.toggle('active', b.dataset.tab === name));
    $$('.tab').forEach((s) => s.classList.toggle('active', s.id === 'tab-' + name));
    if (name === 'subnets') loadSubnets();
    if (name === 'events') loadEvents();
    if (name === 'settings') loadSettings();
  };
  $('#tabs').addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (b) showTab(b.dataset.tab);
  });

  // ---------- status ---------------------------------------------------------
  const applyStatus = (s) => {
    state.status = s;
    $('#stat-devices').textContent = s.devices;
    $('#stat-online').textContent = s.online;
    $('#stat-pkts').textContent = Number(s.packets).toLocaleString();
    const cap = s.capture || {};
    const pill = $('#mode-pill');
    const label = cap.interface ? (cap.interface.Description || cap.interface.FriendlyName || cap.interface.Name) : '?';
    if (cap.passive) {
      pill.textContent = 'passive · ' + label;
      pill.className = 'pill warn';
      $('#passive-banner').hidden = false;
      $('#passive-hint').textContent = cap.hint || '';
      $('#live-dot').className = 'dot off';
    } else {
      pill.textContent = (cap.scanning ? 'scanning · ' : 'capturing · ') + label;
      pill.className = 'pill ok';
      $('#passive-banner').hidden = true;
      $('#live-dot').className = 'dot live';
    }
    $('#btn-scan').disabled = !!cap.scanning || !!cap.passive;
    $('#btn-scan').textContent = cap.scanning ? 'Scanning…' : 'Scan subnet';
    if (state.tab === 'settings') renderSettingsStatus();
  };

  // ---------- devices --------------------------------------------------------
  let refreshTimer;
  const scheduleRefresh = () => {
    clearTimeout(refreshTimer);
    refreshTimer = setTimeout(loadDevices, 250);
  };
  const loadDevices = async () => {
    try {
      state.devices = await api('/api/devices');
      renderDevices();
      if (state.selectedMAC && !$('#drawer').hidden) renderDrawer(state.selectedMAC, false);
    } catch (e) { console.error(e); }
  };

  const sortKey = (d, key) => {
    switch (key) {
      case 'ip': return ipKey(d.ips[0]);
      case 'mac': return d.mac;
      case 'vendor': return (d.vendor || (d.randomized ? 'zz-random' : 'zzz')).toLowerCase();
      case 'name': return (nameFor(d) || 'zzz').toLowerCase();
      case 'tags': return (d.tags || []).join(',') || 'zzz';
      case 'info': return (infoFor(d) || prettyServices((d.attrs || {}).services).join() || 'zzz').toLowerCase();
      case 'last_seen': return d.last_seen;
      default: return (d.online ? '0' : '1') + ipKey(d.ips[0]);
    }
  };
  const matches = (d, q) => {
    if (!q) return true;
    const a = d.attrs || {};
    const hay = [d.mac, d.vendor, d.hostname, d.label, d.notes, ...(d.ips || []), ...(d.tags || []), a.services, a.service_names, a.dhcp_vendor_class, a.lldp_sysdesc, prettyServices(a.services).join(' ')].join(' ').toLowerCase();
    return q.split(/\s+/).every((w) => hay.includes(w));
  };

  const renderDevices = () => {
    const q = $('#search').value.trim().toLowerCase();
    const onlyOnline = $('#only-online').checked;
    let rows = state.devices.filter((d) => (!onlyOnline || d.online) && matches(d, q));
    const { key, asc } = state.sort;
    rows.sort((a, b) => {
      const ka = sortKey(a, key), kb = sortKey(b, key);
      const c = ka < kb ? -1 : ka > kb ? 1 : 0;
      return asc ? c : -c;
    });
    $$('#devices th').forEach((th) => {
      th.classList.toggle('sorted', th.dataset.sort === key);
      th.classList.toggle('asc', th.dataset.sort === key && asc);
    });
    const tbody = $('#devices tbody');
    tbody.innerHTML = rows.map((d) => {
      const a = d.attrs || {};
      const conflict = !!a.conflict_ip;
      const cls = [conflict ? 'conflict' : '', d.online ? '' : 'offline', d.mac === state.selectedMAC ? 'selected' : ''].join(' ');
      const vendor = d.vendor ? esc(d.vendor) : (d.randomized ? '<span class="tag rand">randomized</span>' : '<span class="sub">unknown</span>');
      const name = nameFor(d);
      const host = d.label && d.hostname && d.hostname !== d.label ? `<span class="host">${esc(d.hostname)}</span>` : '';
      const self = a.self === 'true' ? '<span class="tag self">this machine</span>' : '';
      const svcs = prettyServices(a.services).map((s) => `<span class="tag svc">${esc(s)}</span>`).join('');
      const ipExtra = d.ips.length > 1 ? `<span class="sub"> +${d.ips.length - 1}</span>` : '';
      const tags = (d.tags || []).map((t) => `<span class="tag">${esc(t)}</span>`).join('');
      return `<tr data-mac="${esc(d.mac)}" class="${cls}">
        <td><span class="state ${conflict ? 'conflict' : d.online ? 'on' : ''}" title="${d.online ? 'online' : 'offline'}"></span></td>
        <td class="mono">${esc(d.ips[0] || '')}${ipExtra}</td>
        <td class="mono">${esc(d.mac)}</td>
        <td>${vendor}</td>
        <td class="name">${esc(name)}${host}${self}</td>
        <td>${tags}</td>
        <td>${svcs}${esc(infoFor(d))}${conflict ? ` <span class="tag" style="background:var(--bad);color:#fff">conflict ${esc(a.conflict_ip)}</span>` : ''}</td>
        <td class="num sub" data-ts="${esc(d.last_seen)}">${ago(d.last_seen)}</td>
      </tr>`;
    }).join('');
    $('#devices-empty').hidden = rows.length > 0;
  };
  $('#search').addEventListener('input', renderDevices);
  $('#only-online').addEventListener('change', renderDevices);
  $('#devices thead').addEventListener('click', (e) => {
    const th = e.target.closest('th');
    if (!th || !th.dataset.sort) return;
    if (state.sort.key === th.dataset.sort) state.sort.asc = !state.sort.asc;
    else state.sort = { key: th.dataset.sort, asc: th.dataset.sort !== 'last_seen' };
    localStorage.setItem('ns.sort', JSON.stringify(state.sort));
    renderDevices();
  });
  $('#devices tbody').addEventListener('click', (e) => {
    const tr = e.target.closest('tr');
    if (tr) openDrawer(tr.dataset.mac);
  });
  // tick relative times
  setInterval(() => $$('#devices td[data-ts]').forEach((td) => (td.textContent = ago(td.dataset.ts))), 5000);

  // ---------- drawer ---------------------------------------------------------
  const openDrawer = (mac) => {
    state.selectedMAC = mac;
    $('#drawer').hidden = false;
    renderDrawer(mac, true);
    renderDevices();
  };
  const closeDrawer = () => {
    $('#drawer').hidden = true;
    state.selectedMAC = null;
    renderDevices();
  };
  $('#drawer-close').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });

  const renderDrawer = async (mac, full) => {
    const body = $('#drawer-body');
    let detail;
    try { detail = await api('/api/devices/' + encodeURIComponent(mac)); }
    catch (e) { body.innerHTML = `<p class="muted">${esc(e.message)}</p>`; return; }
    const d = detail.device, a = d.attrs || {}, v = detail.vendor || {};
    // Preserve in-progress edits when refreshing in the background.
    if (!full && body.querySelector('input:focus, textarea:focus')) return;
    const facts = Object.keys(a).filter((k) => !['self', 'sources'].includes(k)).sort().map((k) => `<div>${esc(k)}</div><div>${esc(a[k])}</div>`).join('');
    const ipHist = (detail.ips || []).map((ip) => `<li><b>${esc(ip.IP)}</b> ${when(ip.FirstSeen)} → ${ago(ip.LastSeen)} ago</li>`).join('');
    const obs = (detail.observations || []).map((o) => `<li>${hhmmss(o.timestamp)} <b>${esc(o.source)}</b> ${esc(o.ip || '')} ${esc(o.hostname || '')} ${esc(Object.entries(o.extra || {}).map(([k, val]) => k + '=' + val).join(' '))}</li>`).join('');
    const evs = (detail.events || []).map((e) => `<li>${hhmmss(e.time)} <b>${esc(e.kind)}</b> ${esc(e.message)}</li>`).join('');
    const vendorLine = d.vendor ? `${esc(d.vendor)} <span class="sub">${esc(v.prefix || '')}</span>` : (d.randomized ? '<span class="tag rand">randomized / locally administered</span>' : '<span class="muted">unknown vendor</span>');
    body.innerHTML = `
      <h1>${esc(d.mac)}</h1>
      <div class="vendor">${vendorLine} ${a.self === 'true' ? '<span class="tag self">this machine</span>' : ''} ${a.conflict_ip ? `<span class="tag" style="background:var(--bad);color:#fff">IP conflict on ${esc(a.conflict_ip)}</span>` : ''}</div>
      <div class="kv">
        <div>state</div><div>${d.online ? '<span style="color:var(--accent)">● online</span>' : '<span class="muted">○ offline</span>'} · seen ${agoText(d.last_seen)}</div>
        <div>ip</div><div class="mono">${esc(d.ips.join(', ') || '—')}</div>
        <div>hostname</div><div>${esc(d.hostname || '—')}</div>
        <div>first seen</div><div>${when(d.first_seen)}</div>
        <div>interface</div><div>${esc(d.interface || '—')}</div>
        <div>seen via</div><div>${esc(a.sources || '—')}</div>
      </div>
      <h3>Label</h3>
      <input class="wide" id="d-label" value="${esc(d.label)}" placeholder="e.g. Dante — Yamaha CL5 primary">
      <h3>Tags</h3>
      <input class="wide" id="d-tags" value="${esc((d.tags || []).join(', '))}" placeholder="comma separated: dante, foh, rack3">
      <h3>Notes</h3>
      <textarea id="d-notes" placeholder="rack position, port, who owns it…">${esc(d.notes)}</textarea>
      <div class="actions">
        <button class="primary" id="d-save">Save</button>
        ${d.ips[0] ? `<button id="d-reserve" title="pin this IP to this MAC in its subnet">Reserve ${esc(d.ips[0])}</button>` : ''}
        ${a.conflict_ip ? `<button id="d-clear">Clear conflict</button>` : ''}
        <span class="spacer"></span>
        <button class="danger" id="d-forget">Forget</button>
      </div>
      ${facts ? `<h3>Facts</h3><div class="kv">${facts}</div>` : ''}
      ${ipHist ? `<h3>IP history</h3><ul class="obs">${ipHist}</ul>` : ''}
      ${evs ? `<h3>Events</h3><ul class="obs">${evs}</ul>` : ''}
      ${obs ? `<h3>Recent observations</h3><ul class="obs">${obs}</ul>` : ''}`;
    $('#d-save').onclick = async () => {
      try {
        await patch('/api/devices/' + encodeURIComponent(mac), {
          label: $('#d-label').value.trim(), notes: $('#d-notes').value,
          tags: $('#d-tags').value.split(/[,;]/).map((t) => t.trim()).filter(Boolean),
        });
        toast('saved');
        loadDevices();
      } catch (e) { toast(e.message, true); }
    };
    const reserveBtn = $('#d-reserve');
    if (reserveBtn) reserveBtn.onclick = async () => {
      try {
        const r = await post('/api/reservations', { ip: d.ips[0], mac: d.mac, label: $('#d-label').value.trim() || nameFor(d) || d.vendor || '' });
        toast(`reserved ${r.ip} for ${r.mac}`);
      } catch (e) { toast(e.message + ' — add the subnet first', true); }
    };
    const clearBtn = $('#d-clear');
    if (clearBtn) clearBtn.onclick = async () => { await post('/api/conflicts/clear', { ip: a.conflict_ip }); toast('conflict cleared'); loadDevices(); renderDrawer(mac, true); };
    $('#d-forget').onclick = async () => {
      if (!confirm(`Forget ${d.mac}? It will reappear if seen again.`)) return;
      await del('/api/devices/' + encodeURIComponent(mac));
      closeDrawer();
      loadDevices();
    };
  };

  // ---------- scan -----------------------------------------------------------
  const startScan = async (cidr) => {
    try {
      await post('/api/scan', { cidr: cidr || '' });
      toast('scan started' + (cidr ? ' on ' + cidr : ''));
    } catch (e) { toast(e.message, true); }
  };
  $('#btn-scan').addEventListener('click', () => startScan(''));

  // ---------- subnets --------------------------------------------------------
  const loadSubnets = async () => {
    try {
      state.subnets = await api('/api/subnets');
      renderSubnetList();
      if (state.subnet && !state.subnets.find((s) => s.id === state.subnet)) state.subnet = null;
      if (!state.subnet && state.subnets.length) state.subnet = state.subnets[0].id;
      if (state.subnet) loadMap(state.subnet);
      else $('#subnet-detail').innerHTML = '<div class="empty">Add a subnet to see its address map.</div>';
    } catch (e) { toast(e.message, true); }
  };
  const renderSubnetList = () => {
    $('#subnet-list').innerHTML = state.subnets.map((s) => {
      const t = s.summary.total || 1;
      const seg = (n, cls) => n ? `<i class="cell ${cls}" style="width:${(100 * n / t).toFixed(1)}%"></i>` : '';
      return `<li data-id="${s.id}" class="${s.id === state.subnet ? 'active' : ''}">
        <span class="cidr">${esc(s.cidr)}${s.vlan ? ` <span class="sub">vlan ${s.vlan}</span>` : ''}</span>
        <span class="sub">${esc(s.name || '')} · ${s.summary.in_use + s.summary.match + s.summary.mismatch + s.summary.conflict}/${s.summary.total} used${s.summary.conflict ? ` · <b style="color:var(--bad)">${s.summary.conflict} conflict</b>` : ''}${s.summary.mismatch ? ` · <b style="color:var(--warn)">${s.summary.mismatch} mismatch</b>` : ''}</span>
        <span class="meter">${seg(s.summary.match, 'match')}${seg(s.summary.mismatch, 'mismatch')}${seg(s.summary.conflict, 'conflict')}${seg(s.summary.in_use, 'in-use')}${seg(s.summary.reserved, 'reserved')}</span>
      </li>`;
    }).join('');
  };
  $('#subnet-list').addEventListener('click', (e) => {
    const li = e.target.closest('li');
    if (!li) return;
    state.subnet = Number(li.dataset.id);
    state.selectedIP = null;
    renderSubnetList();
    loadMap(state.subnet);
  });
  $('#subnet-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try {
      const sn = await post('/api/subnets', { cidr: f.get('cidr'), name: f.get('name'), vlan: Number(f.get('vlan') || 0), gateway: f.get('gateway') });
      e.target.reset();
      state.subnet = sn.id;
      toast('added ' + sn.cidr);
      loadSubnets();
    } catch (err) { toast(err.message, true); }
  });

  const loadMap = async (id) => {
    try {
      state.map = await api(`/api/subnets/${id}/map`);
      renderMap();
    } catch (e) { toast(e.message, true); }
  };
  const renderMap = () => {
    const m = state.map;
    if (!m) return;
    const sn = m.subnet, sum = m.summary;
    const hosts = m.addresses.filter((a) => !a.network && !a.broadcast);
    const cells = m.addresses.map((a) => {
      const edge = a.network || a.broadcast;
      const last = a.ip.split('.').pop();
      const who = (a.devices || []).map((d) => nameFor(d) || d.vendor || d.mac).join(' + ');
      const title = edge ? `${a.ip} (${a.network ? 'network' : 'broadcast'})` : `${a.ip} — ${a.status}${a.reservation ? ' · planned: ' + a.reservation.label : ''}${a.macs && a.macs.length ? ' · ' + a.macs.join(' + ') : ''}${who ? ' · ' + who : ''}${a.note ? '\n' + a.note : ''}`;
      return `<div class="cell ${edge ? 'edge' : a.status} ${a.gateway ? 'gw' : ''} ${a.online ? 'online' : ''} ${a.ip === state.selectedIP ? 'sel' : ''}" data-ip="${esc(a.ip)}" title="${esc(title)}">${last}</div>`;
    }).join('');
    const n = m.addresses.length;
    const cols = n <= 16 ? n : n <= 64 ? 16 : 32;
    const filters = ['reserved', 'in-use', 'match', 'mismatch', 'conflict', 'free'];
    const rows = hosts.filter((a) => state.statusFilter.size ? state.statusFilter.has(a.status) : a.status !== 'free');
    $('#subnet-detail').innerHTML = `
      <div class="panel">
        <header>
          <h2 class="mono">${esc(sn.cidr)}</h2>
          <span>${esc(sn.name || '')}</span>
          ${sn.vlan ? `<span class="sub">VLAN ${sn.vlan}</span>` : ''}
          ${sn.gateway ? `<span class="sub">gw ${esc(sn.gateway)}</span>` : ''}
          <span class="spacer"></span>
          <button id="sn-scan" title="ARP sweep this subnet">Scan</button>
          <button id="sn-edit">Edit</button>
          <button id="sn-del" class="danger">Delete</button>
        </header>
        <div class="summary">
          <span class="pill"><b>${sum.total}</b> addresses</span>
          <span class="pill"><b>${sum.free}</b> free</span>
          <span class="pill"><b style="color:var(--accent2)">${sum.reserved}</b> reserved</span>
          <span class="pill"><b>${sum.in_use}</b> in use</span>
          <span class="pill"><b style="color:var(--accent)">${sum.match}</b> match</span>
          <span class="pill"><b style="color:var(--warn)">${sum.mismatch}</b> mismatch</span>
          <span class="pill"><b style="color:var(--bad)">${sum.conflict}</b> conflict</span>
          <span class="pill"><b>${sum.online}</b> online</span>
        </div>
        <div class="grid" id="grid" style="grid-template-columns:repeat(${cols},minmax(0,1fr));max-width:${cols * 38}px">${cells}</div>
        <div class="legend">
          <span><i class="cell free"></i>free</span><span><i class="cell reserved"></i>reserved</span><span><i class="cell in-use"></i>in use</span>
          <span><i class="cell match"></i>match</span><span><i class="cell mismatch"></i>mismatch</span><span><i class="cell conflict"></i>conflict</span>
          <span>· white dot = online · G = gateway</span>
        </div>
        <div id="addr-pop"></div>
      </div>
      <div class="panel addr">
        <div class="toolbar">
          <div class="chips" id="status-chips">${filters.map((f) => `<button data-status="${f}" class="${state.statusFilter.has(f) ? 'active' : ''}">${f}</button>`).join('')}</div>
          <span class="sub">${rows.length} shown</span>
        </div>
        <div class="table-wrap"><table class="data"><thead><tr><th class="w-dot"></th><th>IP</th><th>Status</th><th>Planned</th><th>Actual</th><th>Device</th><th>Note</th></tr></thead>
        <tbody>${rows.map((a) => `<tr data-ip="${esc(a.ip)}">
          <td><span class="state ${a.online ? 'on' : ''}"></span></td>
          <td class="mono">${esc(a.ip)}${a.gateway ? ' <span class="sub">gw</span>' : ''}</td>
          <td><span class="status ${a.status}">${a.status}</span></td>
          <td>${a.reservation ? esc(a.reservation.label) + (a.reservation.mac ? ` <span class="sub mono">${esc(a.reservation.mac)}</span>` : '') : ''}</td>
          <td class="mono">${esc((a.macs || []).join(' + '))}</td>
          <td>${esc((a.devices || []).map((d) => nameFor(d) || d.vendor || (d.randomized ? 'randomized' : '')).join(' + '))}</td>
          <td class="sub">${esc(a.note || '')}</td></tr>`).join('')}</tbody></table></div>
      </div>`;
    $('#grid').addEventListener('click', (e) => {
      const c = e.target.closest('.cell');
      if (c && !c.classList.contains('edge')) selectAddress(c.dataset.ip);
    });
    $('#subnet-detail tbody').addEventListener('click', (e) => {
      const tr = e.target.closest('tr');
      if (tr) selectAddress(tr.dataset.ip);
    });
    $('#status-chips').addEventListener('click', (e) => {
      const b = e.target.closest('button');
      if (!b) return;
      if (state.statusFilter.has(b.dataset.status)) state.statusFilter.delete(b.dataset.status); else state.statusFilter.add(b.dataset.status);
      renderMap();
    });
    $('#sn-scan').onclick = () => startScan(sn.cidr);
    $('#sn-del').onclick = async () => {
      if (!confirm(`Delete ${sn.cidr} and its reservations?`)) return;
      await del('/api/subnets/' + sn.id);
      state.subnet = null;
      loadSubnets();
    };
    $('#sn-edit').onclick = () => {
      $('#addr-pop').innerHTML = `<div class="popover"><h3>Edit subnet</h3><div class="row">
        <label>name <input id="e-name" value="${esc(sn.name)}"></label>
        <label>vlan <input id="e-vlan" type="number" value="${sn.vlan || ''}"></label>
        <label>gateway <input id="e-gw" value="${esc(sn.gateway)}"></label>
        <label>notes <input id="e-notes" value="${esc(sn.notes)}"></label>
        <button class="primary" id="e-save">Save</button></div></div>`;
      $('#e-save').onclick = async () => {
        try {
          await patch('/api/subnets/' + sn.id, { name: $('#e-name').value, vlan: Number($('#e-vlan').value || 0), gateway: $('#e-gw').value, notes: $('#e-notes').value });
          toast('saved');
          loadSubnets();
        } catch (e) { toast(e.message, true); }
      };
    };
    if (state.selectedIP) renderAddressPop(state.selectedIP);
  };

  const selectAddress = (ip) => {
    state.selectedIP = ip;
    $$('#grid .cell').forEach((c) => c.classList.toggle('sel', c.dataset.ip === ip));
    renderAddressPop(ip);
  };
  const renderAddressPop = (ip) => {
    const a = state.map.addresses.find((x) => x.ip === ip);
    if (!a) return;
    const r = a.reservation;
    const macOptions = state.devices.slice().sort((x, y) => ipKey(x.ips[0]) < ipKey(y.ips[0]) ? -1 : 1)
      .map((d) => `<option value="${esc(d.mac)}">${esc(d.mac)} ${esc(d.ips[0] || '')} ${esc(nameFor(d) || d.vendor || '')}</option>`).join('');
    const devices = (a.devices || []).map((d) => `<div><span class="state ${d.online ? 'on' : ''}"></span> <a href="#" data-mac="${esc(d.mac)}" class="mono">${esc(d.mac)}</a> ${esc(nameFor(d) || '')} <span class="sub">${esc(d.vendor || (d.randomized ? 'randomized' : ''))}</span> · seen ${agoText(d.last_seen)}</div>`).join('');
    $('#addr-pop').innerHTML = `<div class="popover">
      <h3 class="mono" style="text-transform:none;font-size:15px;color:var(--text)">${esc(ip)} <span class="status ${a.status}">${a.status}</span>${a.gateway ? ' <span class="sub">gateway</span>' : ''}</h3>
      ${a.note ? `<p class="muted" style="margin:4px 0 8px">${esc(a.note)}</p>` : ''}
      ${devices || '<p class="muted">nothing seen at this address</p>'}
      ${a.history && a.history.length ? `<p class="sub">previously: ${esc(a.history.join(', '))}</p>` : ''}
      <h3>${r ? 'Reservation' : 'Reserve this address'}</h3>
      <div class="row">
        <label>MAC <input id="r-mac" list="mac-list" class="mono" value="${esc(r ? r.mac : (a.macs && a.macs[0]) || '')}" placeholder="optional"></label>
        <datalist id="mac-list">${macOptions}</datalist>
        <label>Label <input id="r-label" value="${esc(r ? r.label : ((a.devices || [])[0] ? nameFor(a.devices[0]) || a.devices[0].vendor : ''))}" placeholder="Dante — CL5 primary"></label>
        <label>Notes <input id="r-notes" value="${esc(r ? r.notes : '')}"></label>
        <button class="primary" id="r-save">${r ? 'Update' : 'Reserve'}</button>
        ${r ? `<button class="danger" id="r-del">Remove</button>` : ''}
      </div></div>`;
    $$('#addr-pop a[data-mac]').forEach((el) => el.addEventListener('click', (e) => { e.preventDefault(); openDrawer(el.dataset.mac); }));
    $('#r-save').onclick = async () => {
      try {
        await post('/api/reservations', { subnet_id: state.map.subnet.id, ip, mac: $('#r-mac').value.trim(), label: $('#r-label').value.trim(), notes: $('#r-notes').value.trim() });
        toast('reservation saved');
        loadSubnets();
      } catch (e) { toast(e.message, true); }
    };
    const rd = $('#r-del');
    if (rd) rd.onclick = async () => { await del('/api/reservations/' + r.id); toast('reservation removed'); loadSubnets(); };
  };

  // ---------- events ---------------------------------------------------------
  const loadEvents = async () => {
    try {
      state.events = await api('/api/events?limit=300' + (state.eventKind ? '&kind=' + state.eventKind : ''));
      renderEvents();
    } catch (e) { toast(e.message, true); }
  };
  const eventRow = (e) => `<li class="${esc(e.kind)}" data-id="${e.id}">
    <span class="t">${new Date(e.time).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}</span>
    <span class="k">${esc(e.kind.replace('_', ' '))}</span>
    <span>${esc(e.message)}${e.mac ? ` <a href="#" data-mac="${esc(e.mac)}" class="sub mono">${esc(e.mac)}</a>` : ''}</span>
    <span>${e.kind === 'conflict' ? `<button data-clear="${esc(e.ip)}">clear</button>` : ''}</span></li>`;
  const renderEvents = () => {
    $('#event-list').innerHTML = state.events.map(eventRow).join('') || '<li><span></span><span></span><span class="muted">no events yet</span><span></span></li>';
  };
  $('#event-list').addEventListener('click', async (e) => {
    const a = e.target.closest('a[data-mac]');
    if (a) { e.preventDefault(); openDrawer(a.dataset.mac); return; }
    const b = e.target.closest('button[data-clear]');
    if (b) { await post('/api/conflicts/clear', { ip: b.dataset.clear }); toast('conflict cleared for ' + b.dataset.clear); loadDevices(); }
  });
  $('#event-filters').addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    $$('#event-filters button').forEach((x) => x.classList.toggle('active', x === b));
    state.eventKind = b.dataset.kind;
    loadEvents();
  });
  let unseenConflicts = 0;
  const bumpConflicts = (n) => {
    unseenConflicts = n;
    const b = $('#conflict-badge');
    b.textContent = n;
    b.hidden = n === 0;
  };

  // ---------- settings -------------------------------------------------------
  const loadSettings = async () => {
    try {
      const ifaces = await api('/api/ifaces');
      const cur = state.status && state.status.capture.interface ? state.status.capture.interface.Name : '';
      $('#iface-select').innerHTML = ifaces.filter((i) => !i.Loopback).map((i) =>
        `<option value="${esc(i.Name)}" ${i.Name === cur ? 'selected' : ''}>${esc(i.Description || i.FriendlyName || i.Name)}${i.Description && i.Description !== i.Name ? ` (${esc(i.Name)})` : ''} ${esc((i.IPv4 || []).join(', '))}${i.Default ? ' ★' : ''}${i.Up ? '' : ' (down)'}</option>`).join('');
    } catch (e) { $('#iface-status').textContent = e.message; }
    renderSettingsStatus();
  };
  const renderSettingsStatus = () => {
    const s = state.status;
    if (!s) return;
    const c = s.capture;
    $('#iface-status').textContent = c.passive ? 'passive mode — ' + (c.hint || '').split('\n')[0] : `capturing on ${c.interface.Name} · ${Number(c.received).toLocaleString()} frames${c.dropped ? ` · ${c.dropped} dropped` : ''}`;
    $('#scan-status').textContent = (c.scanning ? 'scan running… ' : '') + (c.last_scan && !c.last_scan.startsWith('0001') ? `last scan ${ago(c.last_scan)} ago` : 'no scan yet') + (c.scan_every ? ` · repeating every ${c.scan_every / 1e9}s` : '');
    if (document.activeElement !== $('#scan-every')) $('#scan-every').value = String(c.scan_every / 1e9 || 0);
    if (!$('#scan-cidr').value && c.scan_cidr) $('#scan-cidr').value = c.scan_cidr;
    $('#oui-status').textContent = `${Number(c.oui_entries).toLocaleString()} vendor prefixes · source: ${c.oui_source === 'embedded' ? 'bundled with this build' : 'updated ' + when(c.oui_updated)}`;
    $('#about').innerHTML = `netscout v${esc(c.version)} · running since ${when(c.started_at)}<br>data: <span class="mono">${esc(c.data_dir)}</span><br>devices go offline after ${c.online_window / 6e10} min of silence`;
  };
  $('#btn-iface').addEventListener('click', async () => {
    const name = $('#iface-select').value;
    $('#btn-iface').disabled = true;
    try {
      await post('/api/capture', { interface: name });
      toast('switched to ' + name);
      loadDevices();
    } catch (e) { toast(e.message, true); }
    $('#btn-iface').disabled = false;
  });
  $('#btn-scan2').addEventListener('click', () => startScan($('#scan-cidr').value.trim()));
  $('#scan-every').addEventListener('change', async (e) => {
    try {
      await post('/api/scan/schedule', { every_seconds: Number(e.target.value), cidr: $('#scan-cidr').value.trim() });
      toast(Number(e.target.value) ? 'periodic scan enabled' : 'periodic scan off');
    } catch (err) { toast(err.message, true); }
  });
  $('#btn-oui').addEventListener('click', async () => {
    const b = $('#btn-oui');
    b.disabled = true; b.textContent = 'Downloading…';
    try {
      const r = await post('/api/oui/update');
      toast(`vendor database updated: ${r.Entries.toLocaleString()} entries`);
    } catch (e) { toast(e.message, true); }
    b.disabled = false; b.textContent = 'Download latest from Wireshark';
  });
  $('#lookup-mac').addEventListener('input', async (e) => {
    const v = e.target.value.trim();
    const out = $('#lookup-result');
    if (v.replace(/[^0-9a-f]/gi, '').length < 6) { out.textContent = ''; return; }
    try {
      const r = await api('/api/lookup?mac=' + encodeURIComponent(v.replace(/[^0-9a-f]/gi, '').padEnd(12, '0')));
      out.textContent = r.found ? `${r.vendor} (${r.prefix})` : (r.randomized ? 'randomized / locally administered' : 'unknown');
    } catch (err) { out.textContent = err.message; }
  });
  const doImport = async (dry) => {
    const form = $('#import-form');
    const fd = new FormData(form);
    fd.set('dry_run', dry ? 'true' : 'false');
    fd.set('auto_subnets', form.auto_subnets.checked ? 'true' : 'false');
    const out = $('#import-result');
    out.textContent = 'importing…';
    try {
      const res = await fetch('/api/import', { method: 'POST', body: fd });
      const body = await res.json();
      if (!res.ok) throw new Error(body.error);
      const r = body.report;
      out.textContent = `${dry ? '[dry run] ' : ''}${body.rows} rows: ${r.ReservationsWritten} reservations, ${r.DevicesLabelled} devices labelled` +
        (r.SubnetsCreated.length ? `, subnets created: ${r.SubnetsCreated.join(' ')}` : '') +
        (r.Skipped.length ? `\nskipped:\n  ${r.Skipped.join('\n  ')}` : '');
      if (!dry) { loadDevices(); if (state.tab === 'subnets') loadSubnets(); }
    } catch (e) { out.textContent = 'error: ' + e.message; }
  };
  $('#import-form').addEventListener('submit', (e) => { e.preventDefault(); doImport(false); });
  $('#btn-import-dry').addEventListener('click', () => doImport(true));

  // ---------- live stream ----------------------------------------------------
  const connect = () => {
    const es = new EventSource('/api/stream');
    es.addEventListener('status', (e) => applyStatus(JSON.parse(e.data)));
    es.addEventListener('event', (e) => {
      const ev = JSON.parse(e.data);
      if (ev.details && ev.details.silent === 'true') { scheduleRefresh(); return; }
      scheduleRefresh();
      if (ev.kind === 'conflict') {
        toast('⚠ ' + ev.message, true);
        if (state.tab !== 'events') bumpConflicts(unseenConflicts + 1);
      }
      if (ev.kind === 'scan' && ev.details && ev.details.state === 'done' && state.tab === 'subnets') loadSubnets();
      if (state.tab === 'events' && (!state.eventKind || state.eventKind === ev.kind)) {
        state.events.unshift(ev);
        if (state.events.length > 300) state.events.pop();
        $('#event-list').insertAdjacentHTML('afterbegin', eventRow(ev));
      }
    });
    es.onerror = () => {
      $('#live-dot').className = 'dot off';
      $('#mode-pill').textContent = 'disconnected — is netscout still running?';
      $('#mode-pill').className = 'pill warn';
      es.close();
      setTimeout(connect, 3000);
    };
  };
  $('#tabs').addEventListener('click', (e) => { if (e.target.closest('button') && e.target.closest('button').dataset.tab === 'events') bumpConflicts(0); });

  // ---------- boot -----------------------------------------------------------
  (async () => {
    try { applyStatus(await api('/api/status')); } catch (e) { console.error(e); }
    await loadDevices();
    showTab(state.tab);
    connect();
    setInterval(loadDevices, 10000);
    setInterval(() => { if (state.tab === 'subnets' && state.subnet) loadMap(state.subnet); }, 15000);
  })();
})();
