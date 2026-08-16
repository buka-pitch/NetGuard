function esc(s) { if (typeof s !== 'string') return String(s || ''); return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
function sevLabel(s) { return {1:'critical',2:'high',3:'medium',4:'low'}[s]||'info'; }
function sevClass(s) { return 'sev-'+s; }
function fmtTime(ts) {
  if (!ts) return '-';
  try {
    const d = new Date(ts.includes('T') ? ts : ts*1000);
    const now = new Date();
    const isToday = d.toDateString() === now.toDateString();
    if (isToday) return d.toLocaleTimeString();
    return d.toLocaleString();
  } catch { return ts; }
}

document.getElementById('tabs').addEventListener('click', e => {
  const tab = e.target.closest('.tab');
  if (!tab) return;
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  tab.classList.add('active');
  document.getElementById('tab-'+tab.dataset.tab).classList.add('active');
});

let alertsCache = [];
let filterTimer = null;
let alertOffset = 0;
let alertTotal = 0;
const alertLimit = 100;

function scheduleFilter() {
  if (filterTimer) clearTimeout(filterTimer);
  alertOffset = 0;
  filterTimer = setTimeout(loadAlerts, 250);
}

function clearFilters() {
  document.querySelectorAll('.alert-filters input, .alert-filters select').forEach(el => el.value = '');
  alertOffset = 0;
  loadAlerts();
}

function goPrev() {
  if (alertOffset <= 0) return;
  alertOffset = Math.max(0, alertOffset - alertLimit);
  loadAlerts();
}

function goNext() {
  if (alertOffset + alertLimit >= alertTotal) return;
  alertOffset += alertLimit;
  loadAlerts();
}

function updatePagination() {
  const info = document.getElementById('pagination-info');
  const prev = document.getElementById('btn-prev');
  const next = document.getElementById('btn-next');
  const indicator = document.getElementById('page-indicator');
  if (info) info.textContent = alertTotal + ' total';
  if (indicator) {
    const page = alertTotal > 0 ? Math.floor(alertOffset / alertLimit) + 1 : 1;
    const pages = Math.max(1, Math.ceil(alertTotal / alertLimit));
    indicator.textContent = ' ' + page + '/' + pages + ' ';
  }
  if (prev) prev.style.display = alertOffset > 0 ? 'inline-block' : 'none';
  if (next) next.style.display = alertOffset + alertLimit < alertTotal ? 'inline-block' : 'none';
}

function filterParams() {
  const p = new URLSearchParams();
  const fields = ['q','severity','ip','comm','proto','action','sig'];
  for (const f of fields) {
    const v = document.getElementById('filter-' + f)?.value;
    if (v) p.set(f, v);
  }
  return p.toString();
}

async function fetchJSON(url) {
  try {
    const r = await fetch(url);
    if (!r.ok) {
      console.error('fetchJSON: HTTP ' + r.status + ' for ' + url);
      return null;
    }
    const txt = await r.text();
    return JSON.parse(txt);
  } catch (e) {
    console.error('fetchJSON error for ' + url + ':', e);
    return null;
  }
}

function toast(msg, err) {
  const t = document.createElement('div');
  t.className = 'toast' + (err ? ' error' : '');
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3000);
}

async function checkStatus() {
  const s = await fetchJSON('/api/suricata/status');
  const bar = document.getElementById('suricata-status');
  if (!s) {
    bar.innerHTML = '<span class="status-dot dot-red"></span> cannot reach api';
    return;
  }
  const dot = s.running ? 'dot-green' : (s.installed && s.service_ok ? 'dot-yellow' : 'dot-red');
  const label = s.running ? 'running' : (s.installed ? (s.service_ok ? 'stopped' : 'service missing') : 'not installed');
  let ver = s.version || '';
  if (ver.length > 80) ver = ver.substring(0, 80);

  let html = '<span><span class="status-dot ' + dot + '"></span> ' + label + ' ' + esc(ver) + '</span>';
  html += '<span style="color:#484f58;font-size:11px">' + (s.uptime ? esc(s.uptime) : '') + '</span>';
  html += '<span>';
  if (!s.installed || !s.service_ok) {
    const btnLabel = !s.installed ? 'install' : 'reinstall (service missing)';
    html += '<button class="action-btn primary" onclick="installSuricata(this)">' + btnLabel + '</button>';
  } else if (!s.running) {
    html += '<button class="action-btn primary" onclick="startSuricata(this)">start</button>';
  } else {
    html += '<button class="action-btn danger" onclick="stopSuricata(this)">stop</button>';
    html += ' <button class="action-btn" onclick="restartSuricata(this)">restart</button>';
  }
  html += ' <button class="action-btn" onclick="rollbackSuricata(this)">rollback</button>';
  html += '</span>';
  bar.innerHTML = html;
}

async function action(url, msg, btn) {
  btn.disabled = true;
  btn.textContent = msg + '...';
  try {
    const r = await fetch(url);
    const body = await r.text();
    if (!r.ok) {
      toast(msg + ' failed: ' + (body || r.statusText), true);
      btn.disabled = false;
      btn.textContent = msg;
      return;
    }
    toast(msg + ' succeeded');
    setTimeout(checkStatus, 2000);
  } catch (e) {
    toast(msg + ' failed: ' + e.message, true);
    btn.disabled = false;
    btn.textContent = msg;
  }
}

async function installSuricata(btn) {
    btn.disabled = true;
    btn.textContent = 'inspecting...';
    let logDiv = document.getElementById('install-log');
    if (!logDiv) {
        logDiv = document.createElement('div');
        logDiv.id = 'install-log';
        logDiv.className = 'install-log';
        document.getElementById('suricata-status').after(logDiv);
    }

    // Step 1: dry-run preview
    let plan;
    try {
        const r = await fetch('/api/suricata/install/dry-run');
        if (!r.ok) {
            logDiv.textContent = 'dry-run failed: ' + (await r.text());
            btn.disabled = false;
            btn.textContent = 'install';
            return;
        }
        plan = await r.json();
    } catch (e) {
        logDiv.textContent = 'dry-run failed: ' + e.message;
        btn.disabled = false;
        btn.textContent = 'install';
        return;
    }

    renderPlan(plan);
    const ok = confirm(buildPlanSummary(plan) + '\n\nProceed?');
    if (!ok) {
        logDiv.style.display = 'none';
        btn.disabled = false;
        btn.textContent = 'install';
        return;
    }

    // Step 2: apply
    btn.textContent = 'installing...';
    logDiv.textContent = '';
    logDiv.style.display = 'block';
    try {
        const r = await fetch('/api/suricata/install/apply');
        const reader = r.body.getReader();
        const dec = new TextDecoder();
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            logDiv.textContent += dec.decode(value, { stream: true });
            logDiv.scrollTop = logDiv.scrollHeight;
        }
    } catch (e) {
        logDiv.textContent += '\nfetch failed: ' + e.message + '\n';
    } finally {
        btn.disabled = false;
        btn.textContent = 'install';
        setTimeout(checkStatus, 2000);
    }
}

function buildPlanSummary(plan) {
    const lines = [];
    lines.push('Suricata install plan:');
    lines.push('  distro:   ' + (plan.distro || '?'));
    lines.push('  interface: ' + (plan.interface || '?'));
    if (plan.actions && plan.actions.length) {
        lines.push('  ' + plan.actions.length + ' action(s):');
        for (const a of plan.actions) {
            const rev = a.reversible ? '' : '  [NOT REVERSIBLE]';
            lines.push('    • ' + a.op + ' ' + a.target + ' — ' + a.details + rev);
        }
    } else {
        lines.push('  no actions');
    }
    return lines.join('\n');
}

function renderPlan(plan) {
    let el = document.getElementById('install-plan');
    if (!el) {
        el = document.createElement('div');
        el.id = 'install-plan';
        el.className = 'install-plan';
        const logDiv = document.getElementById('install-log');
        if (logDiv && logDiv.parentNode) logDiv.parentNode.insertBefore(el, logDiv);
        else document.getElementById('suricata-status').after(el);
    }
    el.style.display = 'block';
    const rows = (plan.actions || []).map((a) => {
        const rev = a.reversible ? '<span class="badge badge-preexisting">reversible</span>' : '<span class="badge badge-blocked">NOT reversible</span>';
        return '<tr><td>' + esc(a.op) + '</td><td>' + esc(a.target) + '</td><td>' + esc(a.details) + '</td><td>' + rev + '</td></tr>';
    }).join('');
    el.innerHTML =
      '<div class="panel-header"><span class="panel-title">install plan</span></div>' +
      '<table class="usage-table">' +
        '<thead><tr><th>op</th><th>target</th><th>details</th><th></th></tr></thead>' +
        '<tbody>' + (rows || '<tr><td colspan="4" class="empty-state">no actions</td></tr>') + '</tbody>' +
      '</table>';
}

async function rollbackSuricata(btn) {
    if (!confirm('Roll back the most recent Suricata install? Reversible file changes will be reverted. Package install and downloaded rules are NOT removed.')) return;
    btn.disabled = true;
    btn.textContent = 'rolling back...';
    try {
        const r = await fetch('/api/suricata/install/rollback', { method: 'POST' });
        const body = await r.text();
        if (!r.ok) {
            toast('rollback failed: ' + (body || r.statusText), true);
        } else {
            toast('rollback ok');
            setTimeout(checkStatus, 2000);
        }
    } catch (e) {
        toast('rollback failed: ' + e.message, true);
    } finally {
        btn.disabled = false;
        btn.textContent = 'rollback';
    }
}
function startSuricata(btn)   { action('/api/suricata/start', 'start', btn); }
function stopSuricata(btn)    { action('/api/suricata/stop', 'stop', btn); }
function restartSuricata(btn) { action('/api/suricata/restart', 'restart', btn); }

async function loadAlerts() {
  const params = filterParams();
  const query = new URLSearchParams(params);
  query.set('limit', alertLimit);
  query.set('offset', alertOffset);
  const url = '/api/suricata/alerts?' + query.toString();
  const data = await fetchJSON(url);
  const body = document.getElementById('alerts-body');
  const heading = document.querySelector('#tab-alerts h2');
  if (data === null) {
    if (heading) heading.textContent = 'alerts (error)';
    if (body) body.innerHTML = '<tr><td colspan="8" style="color:#f85149;text-align:center;padding:16px">failed to load</td></tr>';
    updatePagination();
    return;
  }
  const alerts = data.alerts || [];
  alertTotal = data.total || 0;
  if (heading) heading.textContent = 'alerts (' + alertTotal + ')';
  if (alerts.length === 0 && body) {
    const msg = params ? 'no alerts match filter' : 'no alerts';
    body.innerHTML = '<tr><td colspan="8" style="color:#8b949e;text-align:center;padding:16px">' + msg + '</td></tr>';
    alertsCache = [];
    updatePagination();
    return;
  }
  if (alertOffset === 0 && alerts.length === alertsCache.length && alerts.length > 0) {
    const last = alerts[alerts.length-1];
    if (last.timestamp === alertsCache[alertsCache.length-1]?.timestamp) {
      updatePagination();
      return;
    }
  }
  body.innerHTML = '';
  for (const a of alerts) {
    const idx = alerts.indexOf(a);
    const tr = document.createElement('tr');
    tr.style.cursor = 'pointer';
    const sig = esc(a.signature || '').substring(0, 80);
    tr.innerHTML =
      '<td style="color:#484f58;font-size:11px">' + fmtTime(a.timestamp) + '</td>' +
      '<td>' + esc(a.src_ip) + ':' + a.src_port + '</td>' +
      '<td>' + esc(a.dst_ip || '') + ':' + (a.dst_port || '') + '</td>' +
      '<td><span class="proto-badge proto-' + (a.protocol||'tcp') + '">' + esc(a.protocol||'tcp') + '</span></td>' +
      '<td class="signature" title="' + esc(a.signature||'') + '">' + sig + '</td>' +
      '<td><span class="sev-badge sev-' + a.severity + '">' + sevLabel(a.severity) + '</span></td>' +
      '<td style="font-size:11px;color:' + (a.pid ? '#c9d1d9' : '#484f58') + '">' + esc(a.comm||'?') + (a.pid ? ' ('+a.pid+')' : '') + '</td>' +
      '<td><button class="action-btn" onclick="event.stopPropagation();toggleDetail(this,' + idx + ')" style="font-size:10px">+</button></td>';
    tr.addEventListener('click', function() { toggleDetail(this.querySelector('button'), idx); });
    body.appendChild(tr);

    const detail = document.createElement('tr');
    detail.className = 'detail-row';
    detail.id = 'detail-' + alerts.indexOf(a);
    const dc = document.createElement('td');
    dc.colSpan = 8;
    dc.className = 'detail-cell';
    dc.innerHTML = buildDetail(a);
    detail.appendChild(dc);
    body.appendChild(detail);
  }
  alertsCache = alerts;
  updatePagination();
}

function toggleDetail(btn, idx) {
  const row = document.getElementById('detail-' + idx);
  row.classList.toggle('open');
  btn.textContent = row.classList.contains('open') ? '-' : '+';
}

function doLookup(type, ip, el) {
  if (el.dataset.locked) return;
  el.dataset.locked = '1';
  el.textContent = '...';
  fetch('/api/lookup/' + type + '?ip=' + encodeURIComponent(ip))
    .then(r => r.json())
    .then(data => {
      const out = document.getElementById(el.dataset.target);
      if (type === 'rdns') {
        out.textContent = data.ptr || 'no ptr';
      } else if (type === 'geoip') {
        out.innerHTML = [data.country, data.regionName, data.city].filter(Boolean).join(', ') || 'no data';
        if (data.isp) out.innerHTML += '<br><span style="color:#8b949e;font-size:10px">' + esc(data.isp) + '</span>';
        if (data.org) out.innerHTML += '<br><span style="color:#484f58;font-size:10px">' + esc(data.org) + '</span>';
      } else if (type === 'threat') {
        out.innerHTML = data.blocked ? '<span style="color:#f85149">blocklisted</span>' : '<span style="color:#3fb950">clean</span>';
        if (data.sources && data.sources.length) {
          out.innerHTML += '<br><span style="color:#d29922;font-size:10px">' + esc(data.sources.join(', ')) + '</span>';
        }
      }
      el.textContent = 'done';
      setTimeout(() => { el.textContent = type; el.dataset.locked = '0'; }, 3000);
    })
    .catch(e => {
      document.getElementById(el.dataset.target).textContent = 'error';
      el.textContent = 'retry';
      el.dataset.locked = '0';
    });
}

function buildDetail(a) {
  let html = '<table class="dpi-table">';
  html += '<tr><td class="dpi-label">category</td><td class="dpi-val">' + esc(a.category||'-') + '</td></tr>';
  html += '<tr><td class="dpi-label">action</td><td class="dpi-val">' + esc(a.action||'-') + '</td></tr>';
  html += '<tr><td class="dpi-label">signature</td><td class="dpi-val">' + esc(a.signature||'-') + '</td></tr>';

  if (a.cmdline) {
    html += '<tr><td class="dpi-label" style="color:#58a6ff">─ process</td><td></td></tr>';
    html += '<tr><td class="dpi-label">pid</td><td class="dpi-val">' + a.pid + '</td></tr>';
    html += '<tr><td class="dpi-label">comm</td><td class="dpi-val">' + esc(a.comm) + '</td></tr>';
    html += '<tr><td class="dpi-label">cmdline</td><td class="dpi-val" style="font-size:11px">' + esc(a.cmdline) + '</td></tr>';
    if (a.exe) html += '<tr><td class="dpi-label">exe</td><td class="dpi-val" style="font-size:11px">' + esc(a.exe) + '</td></tr>';
    if (a.ppid) html += '<tr><td class="dpi-label">parent</td><td class="dpi-val">' + a.ppid + ' ' + esc(a.pcomm||'') + '</td></tr>';
    if (a.duration) html += '<tr><td class="dpi-label">duration</td><td class="dpi-val">' + esc(a.duration) + '</td></tr>';
  }

  html += '<tr><td class="dpi-label" style="color:#58a6ff">─ connections</td><td></td></tr>';
  html += '<tr><td class="dpi-label">src</td><td class="dpi-val">' + esc(a.src_ip) + ':' + a.src_port + '</td></tr>';
  html += '<tr><td class="dpi-label">dst</td><td class="dpi-val">' + esc(a.dst_ip || '') + ':' + (a.dst_port || '') + '</td></tr>';

  // lookup buttons for dst_ip (remote server)
  const remoteIP = a.dst_ip || a.src_ip;
  html += '<tr><td class="dpi-label">lookup</td><td class="dpi-val" style="padding:0">';
  html += '<span class="lookup-group">';
  html += '<button class="lookup-btn" onclick="doLookup(\'rdns\',\'' + esc(remoteIP) + '\',this)" data-target="rdns-' + esc(remoteIP) + '">rDNS</button>';
  html += '<span id="rdns-' + esc(remoteIP) + '" class="lookup-result"></span>';
  html += '</span>';
  html += '<span class="lookup-group">';
  html += '<button class="lookup-btn" onclick="doLookup(\'geoip\',\'' + esc(remoteIP) + '\',this)" data-target="geoip-' + esc(remoteIP) + '">GeoIP</button>';
  html += '<span id="geoip-' + esc(remoteIP) + '" class="lookup-result"></span>';
  html += '</span>';
  html += '<span class="lookup-group">';
  html += '<button class="lookup-btn" onclick="doLookup(\'threat\',\'' + esc(remoteIP) + '\',this)" data-target="threat-' + esc(remoteIP) + '">threat</button>';
  html += '<span id="threat-' + esc(remoteIP) + '" class="lookup-result"></span>';
  html += '</span>';
  html += '<span class="lookup-group">';
  html += '<button class="lookup-btn" onclick="doWhoisLookup(\'' + esc(remoteIP) + '\',this)" data-target="whois-' + esc(remoteIP) + '">whois</button>';
  html += '<span id="whois-' + esc(remoteIP) + '" class="lookup-result" style="white-space:normal;max-width:300px;font-size:10px"></span>';
  html += '</span>';
  html += '</td></tr>';

  if (a.http) {
    html += '<tr><td class="dpi-label" style="color:#58a6ff">─ http</td><td></td></tr>';
    if (a.http.hostname) html += '<tr><td class="dpi-label">host</td><td class="dpi-val">' + esc(a.http.hostname) + '</td></tr>';
    if (a.http.url) html += '<tr><td class="dpi-label">url</td><td class="dpi-val">' + esc(a.http.url) + '</td></tr>';
    if (a.http.ua) html += '<tr><td class="dpi-label">user-agent</td><td class="dpi-val" style="font-size:11px">' + esc(a.http.ua) + '</td></tr>';
    if (a.http.method) html += '<tr><td class="dpi-label">method</td><td class="dpi-val">' + esc(a.http.method) + '</td></tr>';
    if (a.http.status) html += '<tr><td class="dpi-label">status</td><td class="dpi-val">' + a.http.status + '</td></tr>';
  }
  if (a.tls) {
    html += '<tr><td class="dpi-label" style="color:#58a6ff">─ tls</td><td></td></tr>';
    if (a.tls.sni) html += '<tr><td class="dpi-label">sni</td><td class="dpi-val">' + esc(a.tls.sni) + '</td></tr>';
    if (a.tls.subject) html += '<tr><td class="dpi-label">subject</td><td class="dpi-val">' + esc(a.tls.subject) + '</td></tr>';
    if (a.tls.issuerdn) html += '<tr><td class="dpi-label">issuer</td><td class="dpi-val">' + esc(a.tls.issuerdn) + '</td></tr>';
    if (a.tls.fingerprint) html += '<tr><td class="dpi-label">fingerprint</td><td class="dpi-val">' + esc(a.tls.fingerprint) + '</td></tr>';
    if (a.tls.version) html += '<tr><td class="dpi-label">version</td><td class="dpi-val">' + esc(a.tls.version) + '</td></tr>';
  }
  if (a.dns) {
    html += '<tr><td class="dpi-label" style="color:#58a6ff">─ dns</td><td></td></tr>';
    if (a.dns.query) html += '<tr><td class="dpi-label">query</td><td class="dpi-val">' + esc(a.dns.query) + '</td></tr>';
    if (a.dns.type) html += '<tr><td class="dpi-label">type</td><td class="dpi-val">' + esc(a.dns.type) + '</td></tr>';
    if (a.dns.answers) {
      for (const ans of a.dns.answers) {
        html += '<tr><td class="dpi-label">→</td><td class="dpi-val">' + esc(ans.name) + ' ' + esc(ans.type) + ' ' + esc(ans.data) + '</td></tr>';
      }
    }
  }
  html += '</table>';
  return html;
}

async function loadRules() {
  const rules = await fetchJSON('/api/suricata/rules');
  if (!rules) return;
  const el = document.getElementById('rules-list');
  el.innerHTML = rules.map(r => {
    const checked = r.enabled ? 'checked' : '';
    return '<div class="rule-item">' +
      '<div><span class="rule-name">' + esc(r.name) + '</span><span class="rule-count">' + r.count + ' rules</span></div>' +
      '<label style="cursor:pointer"><input type="checkbox" ' + checked + ' onchange="toggleRule(\'' + esc(r.name) + '\',this.checked)"> enabled</label>' +
      '</div>';
  }).join('');
}

async function toggleRule(name, enable) {
  await fetch('/api/suricata/rules/toggle', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({name, enable})
  });
  toast((enable ? 'enabled' : 'disabled') + ' ' + name);
}

document.getElementById('file-input').addEventListener('change', async e => {
  const file = e.target.files[0];
  if (!file) return;
  const fd = new FormData();
  fd.append('file', file);
  await fetch('/api/suricata/rules/upload', { method: 'POST', body: fd });
  toast('uploaded ' + file.name);
  loadRules();
});

async function loadConfig() {
  const cfg = await fetchJSON('/api/suricata/config');
  if (!cfg) return;
  document.getElementById('cfg-home-net').value = (cfg.home_net || []).join(', ');
  document.getElementById('cfg-interface').value = cfg.interface || '';
  document.getElementById('cfg-rule-path').value = cfg.rule_path || '';
  document.getElementById('cfg-community-id').checked = cfg.community_id !== false;
}

document.getElementById('config-form').addEventListener('submit', async e => {
  e.preventDefault();
  const cfg = {
    home_net: document.getElementById('cfg-home-net').value.split(',').map(s => s.trim()).filter(Boolean),
    interface: document.getElementById('cfg-interface').value,
    rule_path: document.getElementById('cfg-rule-path').value,
    rule_files: [],
    community_id: document.getElementById('cfg-community-id').checked,
  };
  await fetch('/api/suricata/config', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(cfg)
  });
  toast('config saved, engine restarted');
});

async function loadStats() {
  const s = await fetchJSON('/api/suricata/stats');
  if (!s) return;
  document.getElementById('stat-pkts').textContent = (s.packets_total || 0).toLocaleString();
  document.getElementById('stat-drops').textContent = (s.packets_drop || 0).toLocaleString();
  document.getElementById('stat-alert-count').textContent = (s.alerts_total || 0).toLocaleString();
  document.getElementById('stat-alert-rate').textContent = (s.alerts_per_sec || 0).toFixed(1);
  document.getElementById('stat-mem').textContent = (s.mem_usage ? (s.mem_usage / 1024 / 1024).toFixed(0) : '0');
  document.getElementById('stat-uptime').textContent = s.uptime || '-';
}

async function tick() {
  const activeTab = document.querySelector('.tab.active');
  if (!activeTab) return;
  switch (activeTab.dataset.tab) {
    case 'alerts':
      if (alertOffset === 0) await loadAlerts();
      break;
    case 'rules': await loadRules(); break;
    case 'config': break;
    case 'stats': await loadStats(); break;
  }
}

checkStatus();
loadAlerts();
loadConfig();
fetchJSON('/api/firewall/status').then(s => { if (s) renderFwStatus(s); });
setInterval(() => { checkStatus(); }, 5000);
setInterval(() => { tick(); }, 2000);

function renderFwStatus(s) {
  const el = document.getElementById('stat-fw');
  const btn = document.getElementById('btn-panic');
  if (!el || !btn) return;
  if (s.panic_mode) {
    el.textContent = 'PANIC';
    el.style.color = '#ff4444';
    btn.textContent = 'EXIT PANIC';
    btn.classList.add('panic-active');
  } else if (s.enabled) {
    el.textContent = s.policy === 'allow-all' ? 'allow-all' : 'block';
    el.style.color = s.policy === 'block' ? '#ffbb33' : '#66bb6a';
    btn.textContent = 'PANIC';
    btn.classList.remove('panic-active');
  } else {
    el.textContent = 'off';
    el.style.color = '#888';
    btn.textContent = 'PANIC';
    btn.classList.remove('panic-active');
  }

  const title = 'NetGuard';
  const pending = s.pending || 0;
  document.title = pending > 0 ? '[' + pending + '] ' + title : title;
}

document.addEventListener('click', function(e) {
  if (e.target.id === 'btn-panic') {
    fetch('/api/firewall/panic', {method: 'POST'})
      .then(r => r.json()).then(d => console.log('panic:', d)).catch(() => {});
  }
});

// real-time stats via websocket
(function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(proto + '//' + location.host + '/ws');
  ws.onmessage = function(e) {
    try {
      const data = JSON.parse(e.data);
      if (data.suri_stats) {
        const s = data.suri_stats;
        document.getElementById('stat-pkts').textContent = (s.packets_total || 0).toLocaleString();
        document.getElementById('stat-drops').textContent = (s.packets_drop || 0).toLocaleString();
        document.getElementById('stat-alert-count').textContent = (s.alerts_total || 0).toLocaleString();
        document.getElementById('stat-alert-rate').textContent = (s.alerts_per_sec || 0).toFixed(1);
        document.getElementById('stat-mem').textContent = (s.mem_usage ? (s.mem_usage / 1024 / 1024).toFixed(0) : '0');
        document.getElementById('stat-uptime').textContent = s.uptime || '-';
      }
      if (data.fw_status) renderFwStatus(data.fw_status);
    } catch (err) { console.error('ws: parse error', err); }
  };
  ws.onclose = function() { setTimeout(connectWS, 1000); };
  ws.onerror = function() { ws.close(); };
})();

function doWhoisLookup(ip, el) {
  if (el.dataset.locked) return;
  el.dataset.locked = '1';
  el.textContent = '...';
  fetch('/api/lookup/whois?ip=' + encodeURIComponent(ip))
    .then(r => r.text())
    .then(data => {
      const out = document.getElementById(el.dataset.target);
      const lines = data.split('\n').filter(l => l.length > 0 && !l.startsWith('%'));
      out.textContent = lines.slice(0, 15).join('\n').substring(0, 500) || 'no data';
      el.textContent = 'done';
      setTimeout(() => { el.textContent = 'whois'; el.dataset.locked = '0'; }, 3000);
    })
    .catch(() => {
      document.getElementById(el.dataset.target).textContent = 'error';
      el.textContent = 'retry';
      el.dataset.locked = '0';
    });
}
