function esc(s) { if (typeof s !== 'string') return String(s || ''); return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

function fmtTime(ts) {
  if (!ts) return '-';
  const d = new Date(ts * 1000);
  const now = new Date();
  const isToday = d.toDateString() === now.toDateString();
  return isToday ? d.toLocaleTimeString() : d.toLocaleString();
}

function fmtTTL(ttl) {
  if (!ttl || ttl <= 0) return '-';
  if (ttl < 60) return ttl + 's';
  if (ttl < 3600) return Math.floor(ttl / 60) + 'm';
  return Math.floor(ttl / 3600) + 'h';
}

function renderPagination(containerId, page, perPage, total, loadFn) {
  const el = document.getElementById(containerId);
  if (!el) return;
  const pages = Math.max(1, Math.ceil(total / perPage));
  if (pages <= 1) { el.innerHTML = ''; return; }

  let html = '<div style="display:flex;align-items:center;gap:4px;justify-content:center;padding:8px 0">';

  html += '<button class="page-btn" onclick="' + loadFn + '(' + (page - 1) + ')"' + (page <= 1 ? ' disabled style="opacity:0.3"' : '') + '>‹ Prev</button>';

  let start = Math.max(1, page - 2);
  let end = Math.min(pages, page + 2);
  if (end - start < 4) {
    if (start === 1) end = Math.min(pages, start + 4);
    else start = Math.max(1, end - 4);
  }

  if (start > 1) { html += '<span class="page-dot" style="color:#484f58;font-size:11px">…</span>'; }

  for (let i = start; i <= end; i++) {
    html += '<button class="page-btn' + (i === page ? ' page-active' : '') + '" onclick="' + loadFn + '(' + i + ')">' + i + '</button>';
  }

  if (end < pages) { html += '<span class="page-dot" style="color:#484f58;font-size:11px">…</span>'; }

  html += '<button class="page-btn" onclick="' + loadFn + '(' + (page + 1) + ')"' + (page >= pages ? ' disabled style="opacity:0.3"' : '') + '>Next ›</button>';
  html += '<span style="color:#484f58;font-size:10px;margin-left:6px">' + total + ' total</span></div>';
  el.innerHTML = html;
}

function rpcPage(fn, page) { fn(page); }

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
  document.title = (s.pending || 0) > 0 ? '[' + s.pending + '] ' + title : title;
}

async function loadApps() {
  const r = await fetch('/api/firewall/app-allowlist');
  const apps = await r.json();
  const body = document.getElementById('apps-body');
  document.getElementById('app-count').textContent = apps.length;

  if (!apps || apps.length === 0) {
    body.innerHTML = '<tr><td colspan="5" style="color:#8b949e;text-align:center;padding:16px">no approved apps</td></tr>';
    return;
  }

  body.innerHTML = apps.map(a =>
    '<tr>' +
      '<td style="color:#484f58;font-size:11px">' + a.id + '</td>' +
      '<td><span style="color:#d29922;font-weight:500">' + esc(a.process || '?') + '</span></td>' +
      '<td style="font-size:11px;color:#8b949e;max-width:300px;overflow:hidden;text-overflow:ellipsis">' + esc(a.exe_path || '') + '</td>' +
      '<td style="color:#484f58;font-size:11px">' + fmtTime(a.created_at) + '</td>' +
      '<td><button class="btn-deny" onclick="deleteApp(' + a.id + ')" style="background:transparent;border:1px solid #f8514944;color:#f85149;padding:2px 8px;font-size:10px;cursor:pointer;border-radius:3px;font-family:inherit">remove</button></td>' +
    '</tr>'
  ).join('');
}

async function deleteApp(id) {
  if (!confirm('Remove app allowlist entry ' + id + '?')) return;
  await fetch('/api/firewall/app-allowlist?id=' + id, {method: 'DELETE'});
  loadApps();
}

async function loadAllowlist(page) {
  if (page === undefined) page = window._rulePage || 1;
  window._rulePage = page;
  const r = await fetch('/api/firewall/allowlist?page=' + page + '&per_page=25');
  const resp = await r.json();
  const rules = resp.data || [];
  const total = resp.total || 0;
  const perPage = resp.per_page || 25;
  const body = document.getElementById('rules-body');
  document.getElementById('rule-count').textContent = total;

  if (!rules || rules.length === 0) {
    body.innerHTML = '<tr><td colspan="11" style="color:#8b949e;text-align:center;padding:16px">no rules</td></tr>';
    renderPagination('rules-pages', page, perPage, total, 'loadAllowlist');
    return;
  }

  body.innerHTML = rules.map(rule => {
    const dest = rule.ip === '0.0.0.0/0' ? 'any' : esc(rule.ip);
    const dir = rule.direction === 'in' ? '<span class="badge badge-incoming" style="font-size:8px;padding:0 3px;vertical-align:middle">IN</span>' : '';
    return '<tr>' +
      '<td style="color:#484f58;font-size:11px">' + rule.id + '</td>' +
      '<td>' + esc(rule.process || rule.exe_path || '?') + '</td>' +
      '<td style="font-size:11px;color:#8b949e;max-width:200px;overflow:hidden;text-overflow:ellipsis">' + esc(rule.exe_path || '') + '</td>' +
      '<td>' + dest + '</td>' +
      '<td>' + (rule.port || 'any') + '</td>' +
      '<td>' + esc(rule.proto || 'tcp') + '</td>' +
      '<td>' + dir + '</td>' +
      '<td><span style="color:' + (rule.mode === 'always' ? '#3fb950' : '#58a6ff') + '">' + esc(rule.mode) + '</span></td>' +
      '<td style="color:#8b949e;font-size:11px">' + fmtTTL(rule.ttl_secs) + '</td>' +
      '<td style="color:#484f58;font-size:11px">' + fmtTime(rule.created_at) + '</td>' +
      '<td><button class="btn-deny" onclick="deleteRule(' + rule.id + ')" style="background:transparent;border:1px solid #f8514944;color:#f85149;padding:2px 8px;font-size:10px;cursor:pointer;border-radius:3px;font-family:inherit">delete</button></td>' +
      '</tr>';
  }).join('');
  renderPagination('rules-pages', page, perPage, total, 'loadAllowlist');
}

async function deleteRule(id) {
  if (!confirm('Delete rule ' + id + '?')) return;
  await fetch('/api/firewall/allowlist?id=' + id, {method: 'DELETE'});
  loadAllowlist(window._rulePage);
}

async function addRule(e) {
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = {
    exe_path: fd.get('exe_path') || '',
    process: fd.get('process') || '',
    ip: fd.get('ip') || '',
    port: parseInt(fd.get('port')) || 0,
    proto: fd.get('proto') || 'tcp',
    direction: fd.get('direction') || 'out',
    mode: fd.get('mode') || 'once',
    ttl_secs: parseInt(fd.get('ttl_secs')) || 0,
  };
  const r = await fetch('/api/firewall/allowlist', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body),
  });
  if (r.ok) {
    e.target.reset();
    loadAllowlist(window._rulePage);
    showMsg('Rule added');
  } else {
    const txt = await r.text();
    showMsg('Failed: ' + txt, true);
  }
}

async function loadBlocklist(page) {
  if (page === undefined) page = window._blPage || 1;
  window._blPage = page;
  const r = await fetch('/api/firewall/blocklist?page=' + page + '&per_page=25');
  const resp = await r.json();
  const entries = resp.data || [];
  const total = resp.total || 0;
  const perPage = resp.per_page || 25;
  const body = document.getElementById('blocklist-body');
  document.getElementById('blocklist-count').textContent = total;

  if (!entries || entries.length === 0) {
    body.innerHTML = '<tr><td colspan="7" style="color:#8b949e;text-align:center;padding:16px">no denied IPs</td></tr>';
    renderPagination('blocklist-pages', page, perPage, total, 'loadBlocklist');
    return;
  }

  body.innerHTML = entries.map(e =>
    '<tr>' +
      '<td style="color:var(--red)">' + esc(e.ip) + '</td>' +
      '<td>' + esc(e.process || '?') + '</td>' +
      '<td style="color:#8b949e;font-size:11px">' + (e.port || 'any') + '</td>' +
      '<td style="color:#8b949e;font-size:11px">' + esc(e.proto || 'tcp') + '</td>' +
      '<td>' + (e.direction === 'in' ? '<span class="badge badge-incoming" style="font-size:8px;padding:0 3px">IN</span>' : 'out') + '</td>' +
      '<td style="color:#484f58;font-size:11px">' + fmtTime(e.added_at) + ' ' + (e.domain ? '(' + esc(e.domain) + ')' : '') + '</td>' +
      '<td><button class="btn-deny" onclick="unblockIP(\'' + esc(e.ip) + '\')" style="background:transparent;border:1px solid #3fb95044;color:#3fb950;padding:2px 8px;font-size:10px;cursor:pointer;border-radius:3px;font-family:inherit">unblock</button></td>' +
    '</tr>'
  ).join('');
  renderPagination('blocklist-pages', page, perPage, total, 'loadBlocklist');
}

async function unblockIP(ip) {
  if (!confirm('Remove ' + ip + ' from blocklist?')) return;
  await fetch('/api/firewall/blocklist?ip=' + encodeURIComponent(ip), {method: 'DELETE'});
  loadBlocklist(window._blPage);
}

function showMsg(msg, err) {
  let el = document.getElementById('rule-msg');
  if (!el) {
    el = document.createElement('div');
    el.id = 'rule-msg';
    el.style.cssText = 'padding:6px 10px;border-radius:4px;font-size:11px;margin-top:8px';
    document.getElementById('add-rule-form').after(el);
  }
  el.textContent = msg;
  el.style.background = err ? 'rgba(244,112,103,0.12)' : 'rgba(52,211,153,0.12)';
  el.style.color = err ? '#f47067' : '#34d399';
  el.style.border = err ? '1px solid rgba(244,112,103,0.2)' : '1px solid rgba(52,211,153,0.2)';
  setTimeout(() => el.remove(), 3000);
}

document.addEventListener('click', function(e) {
  if (e.target.id === 'btn-panic') {
    fetch('/api/firewall/panic', {method: 'POST'})
      .then(r => r.json()).then(d => console.log('panic:', d)).catch(() => {});
  }
});

async function loadDeniedApps() {
  const r = await fetch('/api/firewall/app-denylist');
  const entries = await r.json();
  const body = document.getElementById('denied-apps-body');
  document.getElementById('denied-apps-count').textContent = entries.length;

  if (!entries || entries.length === 0) {
    body.innerHTML = '<tr><td colspan="5" style="color:#8b949e;text-align:center;padding:16px">no denied apps</td></tr>';
    return;
  }

  body.innerHTML = entries.map(e =>
    '<tr>' +
      '<td style="color:#484f58;font-size:11px">' + e.id + '</td>' +
      '<td><span style="color:var(--red)">' + esc(e.process || '?') + '</span></td>' +
      '<td style="font-size:11px;color:#8b949e;max-width:300px;overflow:hidden;text-overflow:ellipsis">' + esc(e.exe_path || '') + '</td>' +
      '<td style="color:#484f58;font-size:11px">' + fmtTime(e.created_at) + '</td>' +
      '<td><button class="btn-deny" onclick="unDenyApp(' + e.id + ')" style="background:transparent;border:1px solid #3fb95044;color:#3fb950;padding:2px 8px;font-size:10px;cursor:pointer;border-radius:3px;font-family:inherit">unban</button></td>' +
    '</tr>'
  ).join('');
}

async function unDenyApp(id) {
  if (!confirm('Remove app denylist entry ' + id + '?')) return;
  await fetch('/api/firewall/app-denylist?id=' + id, {method: 'DELETE'});
  loadDeniedApps();
}

fetch('/api/firewall/status').then(r => r.json()).then(s => { if (s) renderFwStatus(s); });

loadApps();
loadAllowlist();
loadBlocklist();
loadDeniedApps();

(function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(proto + '//' + location.host + '/ws');
  ws.onmessage = function(e) {
    try {
      const data = JSON.parse(e.data);
      if (data.fw_status) renderFwStatus(data.fw_status);
    } catch (err) { console.error('ws: parse error', err); }
  };
  ws.onclose = function() { setTimeout(connectWS, 1000); };
  ws.onerror = function() { ws.close(); };
})();
