let _allConns = [];
let _connSort = { col: '', dir: 1 };
let _lastWS = 0;

function fmtTime(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString();
}

function sevClass(s) {
  const v = (s || 'info').toLowerCase();
  const map = { critical: 's-critical', high: 's-high', medium: 's-medium', low: 's-low', info: 's-info' };
  return map[v] || 's-info';
}

function cleanComm(c) {
  return c && c.length > 0 ? c : '?';
}

function toast(msg, type) {
  type = type || 'info';
  const container = document.getElementById('toast-container') || (function() {
    const c = document.createElement('div');
    c.id = 'toast-container';
    document.body.appendChild(c);
    return c;
  })();
  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; setTimeout(() => el.remove(), 300); }, 2500);
}

function sortConn(col) {
  if (_connSort.col === col) {
    _connSort.dir = -_connSort.dir;
  } else {
    _connSort.col = col;
    _connSort.dir = 1;
  }
  document.querySelectorAll('.sort-arrow').forEach(e => e.textContent = '');
  const arrow = document.getElementById('sort-' + col);
  if (arrow) arrow.textContent = _connSort.dir === 1 ? '\u25B2' : '\u25BC';
  renderConnections(_allConns);
}

function onConnFilter() {
  renderConnections(_allConns);
}

let _lastConnJSON = '';

function renderConnections(conns) {
  // skip re-render if nothing changed
  const json = JSON.stringify(conns);
  if (json === _lastConnJSON) return;
  _lastConnJSON = json;

  _allConns = conns;
  const filter = (document.getElementById('filter-conn').value || '').toLowerCase();
  const body = document.getElementById('conn-body');
  document.getElementById('conn-count').textContent = conns.length;

  let filtered = conns;
  if (filter) {
    filtered = conns.filter(c =>
      (c.comm || '').toLowerCase().includes(filter) ||
      (c.remote_addr || '').includes(filter) ||
      String(c.remote_port || '').includes(filter) ||
      (c.local_addr || '').includes(filter) ||
      String(c.local_port || '').includes(filter) ||
      (c.protocol || '').toLowerCase().includes(filter) ||
      (c.state || '').toLowerCase().includes(filter) ||
      (c.domain || '').toLowerCase().includes(filter) ||
      (c.tls_sni || '').toLowerCase().includes(filter) ||
      (c.http_host || '').toLowerCase().includes(filter)
    );
  }

  if (_connSort.col) {
    const col = _connSort.col;
    const dir = _connSort.dir;
    filtered = [...filtered].sort((a, b) => {
      let va = a[col], vb = b[col];
      if (typeof va === 'string') va = va.toLowerCase();
      if (typeof vb === 'string') vb = vb.toLowerCase();
      if (va < vb) return -dir;
      if (va > vb) return dir;
      return 0;
    });
  }

  body.innerHTML = '';
  let blocked = 0;

  for (const c of filtered) {
    const isBlocked = c.state === 'SYN_SENT';
    if (isBlocked) blocked++;
    const tr = document.createElement('tr');
    tr.className = 'conn-row';
    tr.dataset.state = (c.state || '').toUpperCase();
    if (c.pre_existing) tr.classList.add('pre');
    if (c.incoming) tr.classList.add('in');
    tr.style.cursor = 'pointer';

    // process avatar (first letter)
    const procName = cleanComm(c.comm);
    const avatar = (procName || '?').charAt(0).toUpperCase();
    const procClass = c.pre_existing ? 'proc-name proc-pre' : 'proc-name';

    // state pill
    const stShort = (c.state || '').split('_')[0].slice(0, 4) || '·';
    const stLong = c.state || '';
    const stKey = (c.state || '').toUpperCase().slice(0, 2);
    let stCls = 's-st';
    if (/SYN/.test(c.state)) stCls = 's-sy';
    else if (/LISTEN/.test(c.state)) stCls = 's-li';
    else if (/CLOSE|TIME_WAIT/.test(c.state)) stCls = 's-cl';

    // badges
    const badge = isBlocked ? ' <span class="badge badge-blocked">BLOCKED</span>' : '';
    const preB = c.pre_existing ? ' <span class="badge badge-preexisting">PRE</span>' : '';
    const inB = c.incoming ? ' <span class="badge badge-incoming">IN</span>' : '';
    const vpnB = c.is_vpn ? ' <span class="badge badge-vpn">VPN</span>' : '';
    const isICMP = c.protocol && (c.protocol === 'icmp' || c.protocol === 'icmp6');
    const icmpB = isICMP ? ' <span class="badge badge-icmp">ICMP</span>' : '';

    const domain = c.domain ? esc(c.domain) : '';
    const domainSrc = c.domain_source ? '<span class="badge badge-domainsrc badge-domainsrc-' + c.domain_source + '">' + c.domain_source.replace('_', ' ') + '</span> ' : '';
    const sni = c.tls_sni ? esc(c.tls_sni) : '';
    const httpHost = c.http_host ? esc(c.http_host) : '';
    const hostInfo = sni || httpHost ? '<span style="color:var(--accent);font-size:11px">' + (sni || httpHost) + '</span><br>' : '';
    const localStr = c.local_addr
      ? esc(c.local_addr) + ':' + (c.local_port || '')
      : (c.local_port ? ':' + c.local_port : '-');
    const idx = _allConns.indexOf(c);
    tr.innerHTML =
      '<td><div class="proc-cell">' +
        '<span class="proc-avatar">' + esc(avatar) + '</span>' +
        '<span><span class="' + procClass + '">' + esc(procName) + '</span> ' +
        badge + preB + inB + vpnB + icmpB + '</span>' +
      '</div></td>' +
      '<td>' + hostInfo + (domain ? '<span style="color:var(--accent);font-size:11px">' + domainSrc + domain + '</span><br>' : '') +
        '<span class="addr">' + esc(c.remote_addr || '') + '</span></td>' +
      '<td><span class="port">' + esc(String(c.remote_port)) + '</span></td>' +
      '<td class="addr">' + localStr + '</td>' +
      '<td><span class="proto">' + esc(c.protocol || '') + '</span></td>' +
      '<td><span class="state ' + stCls + '" title="' + esc(stLong) + '">' + esc(stShort) + '</span></td>' +
      '<td class="addr">' + (c.pid || '') + '</td>';
    tr.addEventListener('click', function() { showConnModal(c, idx); });
    body.appendChild(tr);
  }
  document.getElementById('stat-blocked').textContent = blocked;
}

let _lastAlertRendered = 0;

function renderAlerts(alerts) {
  const feed = document.getElementById('alert-feed');
  document.getElementById('alert-count').textContent = alerts.length;

  for (const a of alerts) {
    if (!a) continue;
    if (a.created_at && a.created_at <= _lastAlertRendered) continue;
    const div = document.createElement('div');
    div.className = 'alert-card';
    const sev = (a.severity || 'info').toUpperCase();
    div.innerHTML =
      '<div class="alert-sev ' + sevClass(a.severity) + '">' + esc(sev.charAt(0)) + '</div>' +
      '<div class="alert-body">' +
        '<div class="alert-head">' +
          '<span class="alert-rule">' + esc(a.rule_name || '') + '</span>' +
          '<span class="alert-ts">' + fmtTime(a.created_at) + '</span>' +
        '</div>' +
        '<div class="alert-msg">' + esc(a.message || '') + '</div>' +
      '</div>';
    feed.prepend(div);
    if (a.created_at && a.created_at > _lastAlertRendered) {
      _lastAlertRendered = a.created_at;
    }
  }

  while (feed.children.length > 200) feed.removeChild(feed.lastChild);
}

function renderStats(stats) {
  document.getElementById('stat-total').textContent = stats.total_conns || 0;
  document.getElementById('stat-active').textContent = stats.active_conns || 0;
  document.getElementById('stat-alerts').textContent = stats.alert_count || 0;
  document.getElementById('stat-procs').textContent = (stats.top_processes || []).length;

  const procsEl = document.getElementById('procs-list');
  procsEl.innerHTML = (stats.top_processes || []).map(p =>
    '<div class="footer-list-row"><span class="label">' + esc(p.comm) + '</span><span class="count">' + p.count + '</span></div>'
  ).join('') || '<div class="footer-list-row"><span class="label" style="color:var(--text-muted)">no traffic yet</span></div>';

  const ipsEl = document.getElementById('ips-list');
  ipsEl.innerHTML = (stats.top_ips || []).map(i =>
    '<div class="footer-list-row"><span class="label">' + esc(i.ip) + '</span><span class="count">' + i.count + '</span></div>'
  ).join('') || '<div class="footer-list-row"><span class="label" style="color:var(--text-muted)">no traffic yet</span></div>';
}

function renderFwStatus(s) {
  const el = document.getElementById('stat-fw');
  const btn = document.getElementById('btn-panic');
  const page = document.querySelector('.live-page');
  if (s.panic_mode) {
    el.textContent = 'PANIC';
    el.style.color = '';
    btn.textContent = 'EXIT PANIC';
    btn.classList.add('panic-active');
    if (page) page.classList.add('panic');
  } else if (s.enabled) {
    el.textContent = s.policy === 'allow-all' ? 'allow-all' : 'block';
    el.style.color = '';
    btn.textContent = 'PANIC';
    btn.classList.remove('panic-active');
    if (page) page.classList.remove('panic');
  } else {
    el.textContent = 'off';
    el.style.color = '';
    btn.textContent = 'PANIC';
    btn.classList.remove('panic-active');
    if (page) page.classList.remove('panic');
  }
  document.getElementById('fw-count').textContent = s.pending || 0;
  document.getElementById('fw-count-header').textContent = s.pending || 0;

  const title = 'NetGuard';
  const pending = s.pending || 0;
  document.title = pending > 0 ? '[' + pending + '] ' + title : title;
}

let _lastPendingJSON = '';
let _pendingData = [];

function removePendingItem(id) {
  // filter out the removed item locally so WS re-render doesn't re-add it
  _pendingData = _pendingData.filter(p => p.id !== id);
  _lastPendingJSON = JSON.stringify(_pendingData);

  const el = document.querySelector('[data-pending-id="' + id + '"]');
  if (el) el.remove();

  // show empty state if last item was removed
  const feed = document.getElementById('fw-feed');
  if (feed && feed.children.length === 0) {
    feed.innerHTML = '<div class="fw-empty">none pending</div>';
  }
}

function renderFwPending(list) {
  const feed = document.getElementById('fw-feed');

  _pendingData = list || [];

  const json = JSON.stringify(list || []);
  if (json === _lastPendingJSON) return;
  _lastPendingJSON = json;

  if (!list || list.length === 0) {
    feed.innerHTML = '<div class="fw-empty">none pending</div>';
    return;
  }

  const frag = document.createDocumentFragment();
  for (const p of list) {
    const div = document.createElement('div');
    div.className = 'fw-card';
    const label = p.process || p.exe_path || 'unknown';

    let dest;
    let dirTag = '';
    if (p.direction === 'in') {
      dirTag = '<span class="fw-dir">[IN]</span> ';
      dest = esc(p.ip) + ' → service:' + p.port;
    } else {
      dirTag = '<span class="fw-dir">[OUT]</span> ';
      dest = p.domain ? esc(p.domain) + ' <span style="color:var(--text-muted)">(' + esc(p.ip) + ':' + p.port + ')</span>' : esc(p.ip) + ':' + p.port;
    }

    const exeAttr = esc(p.exe_path).replace(/'/g, "\\'");
    const procAttr = esc(p.process).replace(/'/g, "\\'");

    const preB = p.source === 'preexisting' ? ' <span class="badge badge-preexisting">PRE</span>' : '';

    div.dataset.pendingId = p.id;
    const allowAppBtn = p.direction !== 'in'
      ? '<button class="fw-action always" onclick="allowApp(\'' + exeAttr + '\',\'' + procAttr + '\')">allow app</button>'
      : '';
    div.innerHTML =
      '<div class="fw-card-head">' +
        '<span class="fw-comm">' + esc(label) + preB + '</span>' +
        '<span class="fw-id">#' + p.id + '</span>' +
      '</div>' +
      '<div class="fw-card-dest">' + dirTag + dest + ' <span style="color:var(--text-muted)">/ ' + esc(p.proto || 'tcp') + '</span></div>' +
      '<div class="fw-card-actions">' +
        '<button class="fw-action once" onclick="approve(' + p.id + ',\'once\')">once</button>' +
        allowAppBtn +
        '<button class="fw-action deny" onclick="deny(' + p.id + ')">deny</button>' +
      '</div>';
    frag.appendChild(div);
  }
  feed.replaceChildren(frag);
}

function toggleDetail(id) {
  const el = document.getElementById(id);
  if (!el) return;
  el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

function denyApp(id) {
  if (!confirm('Permanently deny this app? Future connections from this app will be silently blocked without prompting.')) return;
  fetch('/api/firewall/deny-app', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id: id})
  }).then(r => {
    if (r.ok) { removePendingItem(id); toast('App denied permanently', 'error'); }
    return r.json();
  }).catch(e => { console.error('deny-app err:', e); toast('Deny app failed', 'error'); });
}

function md(s) {
  if (!s) return '';
  // escape HTML first
  var html = esc(s);

  // extract and protect code blocks so inner markdown isn't processed
  var codeBlocks = [];
  html = html.replace(/```(\w*)\n?([\s\S]*?)```/g, function(m, lang, code) {
    var idx = codeBlocks.length;
    codeBlocks.push('<pre><code class="lang-' + lang + '">' + code + '</code></pre>');
    return '%%CODE' + idx + '%%';
  });
  // inline code too
  html = html.replace(/`([^`]+)`/g, function(m, code) {
    var idx = codeBlocks.length;
    codeBlocks.push('<code>' + code + '</code>');
    return '%%CODE' + idx + '%%';
  });

  // tables: find contiguous |...| line blocks, detect separator, build <table>
  html = html.replace(/(?:(?:^\|.+\|\n?)+)/gm, function(block) {
    var lines = block.trim().split('\n').filter(function(l) { return l.trim(); });
    if (lines.length < 2) return block;
    var sep = /^\|[-:\s|]+\|$/;
    if (!sep.test(lines[1].trim())) return block;
    var rows = [];
    for (var i = 0; i < lines.length; i++) {
      if (i === 1) continue; // skip separator
      var cells = lines[i].split('|').map(function(c) { return c.trim(); });
      // remove first/last empty cells from leading/trailing |
      if (cells[0] === '') cells.shift();
      if (cells[cells.length - 1] === '') cells.pop();
      var tag = i === 0 ? 'th' : 'td';
      rows.push('<tr>' + cells.map(function(c) { return '<' + tag + '>' + c + '</' + tag + '>'; }).join('') + '</tr>');
    }
    return '<table>' + rows.join('') + '</table>';
  });

  // headers
  html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
  html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');
  // bold & italic
  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
  // links
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>');
  // lists
  html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>');
  html = html.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>\n?)+/g, function(m) {
    return m.indexOf('<ul>') >= 0 ? m : '<ol>' + m + '</ol>';
  });
  // horizontal rules
  html = html.replace(/^---+\s*$/gm, '<hr>');

  // restore code blocks
  html = html.replace(/%%CODE(\d+)%%/g, function(m, idx) { return codeBlocks[parseInt(idx)]; });

  // wrap in paragraphs (but not if already wrapped in block elements)
  html = html.replace(/\n\n/g, '</p><p>');
  html = '<p>' + html + '</p>';
  // clean empty paragraphs
  html = html.replace(/<p>\s*<\/p>/g, '');
  // clean <p> wrapping block elements
  html = html.replace(/<p>(<(?:table|pre|ul|ol|h[1-3]|hr).*)/g, '$1');
  html = html.replace(/(<\/(?:table|pre|ul|ol|h[1-3]|hr)>)\s*<\/p>/g, '$1');
  return html;
}

function esc(s) {
  if (typeof s !== 'string') return String(s || '');
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function fetchJSON(url) {
  return fetch(url).then(r => r.json()).catch(() => null);
}

function handleWSUpdate(data) {
  if (data.connections) renderConnections(data.connections);
  if (data.alerts) renderAlerts(data.alerts);
  if (data.stats) renderStats(data.stats);
  if (data.fw_status) renderFwStatus(data.fw_status);
  if (data.fw_pending) renderFwPending(data.fw_pending);
}

function updateStatusMeta(txt) {
  const el = document.getElementById('status-meta');
  if (el) el.textContent = txt;
}

function stamp() {
  return new Date().toLocaleTimeString();
}

function approve(id, mode) {
  fetch('/api/firewall/approve', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id: id, mode: mode})
  }).then(r => {
    if (r.ok) { removePendingItem(id); toast('Approved', 'success'); }
    return r.json();
  }).catch(e => { console.error('approve err:', e); toast('Approve failed', 'error'); });
}

function deny(id) {
  if (!confirm('Deny this connection?')) return;
  fetch('/api/firewall/deny', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({id: id})
  }).then(r => {
    if (r.ok) { removePendingItem(id); toast('Denied', 'error'); }
    return r.json();
  }).catch(e => { console.error('deny err:', e); toast('Deny failed', 'error'); });
}

document.getElementById('btn-panic').addEventListener('click', function() {
  fetch('/api/firewall/panic', {method: 'POST'})
    .then(r => r.json()).then(d => {
      if (d.panic_mode) toast('PANIC MODE ACTIVE', 'error');
      else toast('Panic mode deactivated', 'success');
    }).catch(() => {});
});

function allowApp(exe, proc) {
  if (!confirm('Allow all traffic from ' + (proc || exe) + '?')) return;
  fetch('/api/firewall/allow-app', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({exe_path: exe, process: proc})
  }).then(r => {
    if (r.ok) {
      const ids = _pendingData.filter(p => (exe && p.exe_path === exe) || (proc && p.process === proc)).map(p => p.id);
      for (const id of ids) removePendingItem(id);
      toast('App allowed: ' + (proc || exe), 'success');
    }
    return r.json();
  }).then(d => console.log('allow-app:', d)).catch(e => { console.error('allow-app error:', e); toast('Allow app failed', 'error'); });
}

function bulkApprove(mode) {
  const label = mode === 'once' ? 'once' : 'always';
  if (!confirm('Approve all pending ' + label + '?')) return;
  fetch('/api/firewall/approve-all', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({mode: mode})
  }).then(r => r.json()).then(d => {
    toast('All approved (' + label + ')', 'success');
  }).catch(() => { toast('Bulk approve failed', 'error'); });
}

function bulkDeny() {
  if (!confirm('Deny all pending connections?')) return;
  fetch('/api/firewall/deny-all', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'}
  }).then(r => r.json()).then(d => {
    toast('All denied', 'error');
  }).catch(() => { toast('Bulk deny failed', 'error'); });
}

function closeConnModal() {
  document.getElementById('conn-modal').classList.remove('open');
}

function showConnModal(c, idx) {
  const modal = document.getElementById('conn-modal');
  const body = document.getElementById('modal-body');
  let html = '<div class="conn-detail">';
  const items = [
    ['cmdline', c.cmdline],
    ['exe', c.exe],
    ['parent', c.ppid ? c.ppid + (c.pcomm ? ' ' + esc(c.pcomm) : '') : null],
    ['grandparent', c.gpid ? c.gpid + (c.gcomm ? ' ' + esc(c.gcomm) : '') : null],
    ['domain', c.domain],
    ['tls sni', c.tls_sni],
    ['http host', c.http_host],
    ['local', c.local_addr ? esc(c.local_addr) + ':' + c.local_port : (c.local_port ? ':' + c.local_port : null)],
    ['protocol', c.protocol],
    ['state', c.state],
    ['inode', c.inode],
    ['tx_queue', c.tx_queue],
    ['rx_queue', c.rx_queue],
    ['created', c.created_at ? fmtTime(c.created_at) : null],
  ];
  for (const [label, val] of items) {
    if (val && String(val).trim()) {
      html += '<span class="conn-detail-item"><span class="conn-detail-label">' + label + '</span><span class="conn-detail-val">' + esc(String(val)) + '</span></span>';
    }
  }
  const rip = c.remote_addr || '';
  const mid = 'm' + idx;
  if (rip) {
    html += '<span class="conn-detail-item conn-detail-full"><span class="conn-detail-label">lookup</span><span class="conn-detail-val" style="display:flex;flex-wrap:wrap;gap:4px">';
    html += '<button class="lookup-btn" onclick="connLookup(\'rdns\',\'' + esc(rip) + '\',this)" data-target="crdns-' + mid + '">rDNS</button><span id="crdns-' + mid + '" class="lookup-result"></span>';
    html += '<button class="lookup-btn" onclick="connLookup(\'geoip\',\'' + esc(rip) + '\',this)" data-target="cgeoip-' + mid + '">GeoIP</button><span id="cgeoip-' + mid + '" class="lookup-result"></span>';
    html += '<button class="lookup-btn" onclick="connLookup(\'threat\',\'' + esc(rip) + '\',this)" data-target="cthreat-' + mid + '">threat</button><span id="cthreat-' + mid + '" class="lookup-result"></span>';
    html += '<button class="lookup-btn" onclick="connLookup(\'whois\',\'' + esc(rip) + '\',this)" data-target="cwhois-' + mid + '">whois</button><span id="cwhois-' + mid + '" class="lookup-result" style="white-space:normal;max-width:300px;font-size:10px"></span>';
    html += '<button class="lookup-btn" onclick="startPcap(\'' + esc(rip) + '\',\'' + c.remote_port + '\',this)" data-target="cpcap-' + mid + '">pcap</button><span id="cpcap-' + mid + '" class="lookup-result"></span>';
    html += '</span></span>';
  }
  html += '</div>';
  body.innerHTML = html;
  modal.classList.add('open');
}

function connLookup(type, ip, el) {
  if (el.dataset.locked) return;
  el.dataset.locked = '1';
  el.textContent = '...';
  if (type === 'whois') {
    fetch('/api/lookup/whois?ip=' + encodeURIComponent(ip))
      .then(r => r.text())
      .then(data => {
        const out = document.getElementById(el.dataset.target);
        const lines = data.split('\n').filter(l => l.length > 0 && !l.startsWith('%'));
        out.textContent = lines.slice(0, 15).join('\n').substring(0, 500) || 'no data';
        el.textContent = 'done';
        setTimeout(() => { el.textContent = type; el.dataset.locked = '0'; }, 3000);
      })
      .catch(() => {
        document.getElementById(el.dataset.target).textContent = 'error';
        el.textContent = 'retry';
        el.dataset.locked = '0';
      });
    return;
  }
  fetch('/api/lookup/' + type + '?ip=' + encodeURIComponent(ip))
    .then(r => r.json())
    .then(data => {
      const out = document.getElementById(el.dataset.target);
      if (type === 'rdns') {
        out.textContent = data.ptr || 'no ptr';
      } else if (type === 'geoip') {
        out.innerHTML = [data.country, data.regionName, data.city].filter(Boolean).join(', ') || 'no data';
        if (data.isp) out.innerHTML += '<br><span style="color:#8b949e;font-size:10px">' + esc(data.isp) + '</span>';
      } else if (type === 'threat') {
        out.innerHTML = data.blocked ? '<span style="color:#f85149">blocklisted</span>' : '<span style="color:#3fb950">clean</span>';
        if (data.sources && data.sources.length) {
          out.innerHTML += '<br><span style="color:#d29922;font-size:10px">' + esc(data.sources.join(', ')) + '</span>';
        }
      }
      el.textContent = 'done';
      setTimeout(() => { el.textContent = type; el.dataset.locked = '0'; }, 3000);
    })
    .catch(() => {
      document.getElementById(el.dataset.target).textContent = 'error';
      el.textContent = 'retry';
      el.dataset.locked = '0';
    });
}

async function startPcap(host, port, el) {
  if (el.dataset.locked) return;
  el.dataset.locked = '1';
  el.textContent = 'capturing...';
  const dur = 30;
  var data;
  try {
    const res = await fetch('/api/pcap/capture', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({host, port: parseInt(port,10) || 0, duration: dur})
    });
    data = await res.json();
    el.textContent = 'done';
    var target = document.getElementById(el.dataset.target);
    if (target) target.innerHTML = ' <a href="/api/pcap/download/' + encodeURIComponent(data.filename) + '" download style="color:var(--accent)">' + data.filename + ' (' + (data.size/1024).toFixed(1) + 'KB)</a>';
    showPcapPopup(data.filename);
  } catch(e) {
    var target = document.getElementById(el.dataset.target);
    if (target) target.textContent = 'error';
    el.textContent = 'retry';
  }
  el.dataset.locked = '0';
}

function showPcapPopup(filename) {
  var existing = document.getElementById('pcap-modal');
  if (existing) existing.remove();

  const overlay = document.createElement('div');
  overlay.id = 'pcap-modal';
  overlay.className = 'modal-overlay';
  overlay.style.display = 'flex';
  overlay.style.cssText = 'display:flex !important;position:fixed;z-index:1000;left:0;top:0;width:100%;height:100%;background:rgba(0,0,0,0.7);align-items:center;justify-content:center';
  overlay.onclick = function (e) { if (e.target === this) overlay.remove(); };
  overlay.innerHTML =
    '<div class="modal-content" style="max-width:800px;background:var(--surface);border:1px solid var(--border);border-radius:8px;width:90%;max-height:80vh;display:flex;flex-direction:column">' +
      '<div class="modal-header" style="display:flex;justify-content:space-between;align-items:center;padding:12px 16px;border-bottom:1px solid var(--border)">' +
        '<span class="modal-title" style="font-size:12px;font-weight:600;color:var(--text);text-transform:uppercase">pcap capture</span>' +
        '<button class="modal-close" style="background:none;border:none;color:var(--text-muted);font-size:18px;cursor:pointer;padding:0 4px" onclick="this.closest(\'.modal-content\').parentElement.remove()">&times;</button>' +
      '</div>' +
      '<div class="modal-body" style="padding:16px;overflow-y:auto;flex:1">' +
        '<pre id="pcap-content" style="margin:0;white-space:pre-wrap;font-size:11px;line-height:1.5;color:var(--text)">loading...</pre>' +
      '</div>' +
    '</div>';
  document.body.appendChild(overlay);

  fetch('/api/pcap/read/' + encodeURIComponent(filename))
    .then(r => r.text())
    .then(t => { var el = document.getElementById('pcap-content'); if (el) el.textContent = t; })
    .catch(function () { var el = document.getElementById('pcap-content'); if (el) el.textContent = 'failed to read pcap'; });
}

var chatHistory = [];

function openChat() {
  document.getElementById('chat-modal').classList.add('open');
  document.getElementById('chat-input').focus();
  loadModels();
}

function closeChat() {
  document.getElementById('chat-modal').classList.remove('open');
}

function loadModels() {
  fetch('/api/ai/models')
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var sel = document.getElementById('model-select');
      sel.innerHTML = '';
      var models = data.models || [];
      var current = data.current || 'qwen3:8b';
      models.forEach(function(m) {
        var opt = document.createElement('option');
        opt.value = m.name;
        opt.textContent = m.name;
        if (m.name === current) opt.selected = true;
        sel.appendChild(opt);
      });
      if (models.length === 0) {
        var opt = document.createElement('option');
        opt.value = current;
        opt.textContent = current;
        opt.selected = true;
        sel.appendChild(opt);
      }
      sel.dataset.prev = current;
    })
    .catch(function() {});
}

function switchModel(name) {
  var sel = document.getElementById('model-select');
  var prev = sel.dataset.prev || sel.value;
  fetch('/api/ai/models', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({model: name})
  }).then(function(r) {
    if (!r.ok) throw new Error('server returned ' + r.status);
    return r.json();
  }).then(function(data) {
    if (data.model) sel.dataset.prev = data.model;
  }).catch(function() {
    sel.value = prev;
    toast('Model switch failed', 'error');
  });
}

function sendChat() {
  var input = document.getElementById('chat-input');
  var text = input.value.trim();
  if (!text) return;
  input.value = '';

  var msgsDiv = document.getElementById('chat-msgs');
  msgsDiv.innerHTML += '<div><b>you:</b> ' + esc(text) + '</div>';
  msgsDiv.scrollTop = msgsDiv.scrollHeight;

  chatHistory.push({role: 'user', content: text});
  document.getElementById('chat-send').disabled = true;

  var thinkingId = 'thinking-' + Date.now();
  msgsDiv.innerHTML += '<div id="' + thinkingId + '" class="thinking-msg"><b>ai:</b> thinking<span class="dots"></span></div>';
  msgsDiv.scrollTop = msgsDiv.scrollHeight;

  var fullReply = '';
  var aiMsgId = 'ai-msg-' + Date.now();

  fetch('/api/ai/chat/stream', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({messages: chatHistory})
  })
  .then(function(r) {
    if (!r.ok) return r.json().then(function(d) { throw new Error(d.error || 'request failed'); });
    var reader = r.body.getReader();
    var decoder = new TextDecoder();

    function readChunk() {
      return reader.read().then(function(result) {
        if (result.done) return;
        var chunk = decoder.decode(result.value, {stream: true});
        var lines = chunk.split('\n');
        for (var i = 0; i < lines.length; i++) {
          var line = lines[i].trim();
          if (line.indexOf('[ERROR]') >= 0) {
            var errMsg = line.replace(/^data:\s*\[ERROR\]\s*/, '');
            throw new Error(errMsg);
          }
          if (line.indexOf('[DONE]') >= 0) {
            return;
          }
          if (line.indexOf('data: ') !== 0) continue;
          var token = line.slice(6);
          if (!token) continue;

          var el = document.getElementById(thinkingId);
          if (el) el.remove();

          fullReply += token;
          var existing = document.getElementById(aiMsgId);
          if (!existing) {
            msgsDiv.innerHTML += '<div id="' + aiMsgId + '" class="ai-msg"><b>ai:</b> ' + md(fullReply) + '</div>';
          } else {
            existing.innerHTML = '<b>ai:</b> ' + md(fullReply);
          }
          msgsDiv.scrollTop = msgsDiv.scrollHeight;
        }
        return readChunk();
      });
    }
    return readChunk();
  })
  .then(function() {
    if (fullReply) {
      chatHistory.push({role: 'assistant', content: fullReply});
      var el = document.getElementById(aiMsgId);
      if (el) addActionButtons(el);
    }
  })
  .catch(function(err) {
    var el = document.getElementById(thinkingId);
    if (el) el.remove();
    msgsDiv.innerHTML += '<div class="err-msg"><b>ai:</b> ' + esc(err.message || 'error - is Ollama running?') + '</div>';
  })
  .finally(function() {
    document.getElementById('chat-send').disabled = false;
    document.getElementById('chat-input').focus();
  });
}

function addActionButtons(container) {
  var text = container.textContent || container.innerText;
  var ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  var ips = text.match(ipRegex) || [];
  var seen = {};
  var added = false;
  ips.forEach(function(ip) {
    if (seen[ip]) return;
    seen[ip] = true;
    var btn = document.createElement('button');
    btn.className = 'action-btn';
    btn.textContent = 'block ' + ip;
    btn.onclick = function() { blockIP(ip, container); };
    container.appendChild(btn);
    added = true;
  });
  if (added) {
    var sep = document.createElement('div');
    sep.className = 'action-sep';
    container.insertBefore(sep, container.querySelector('.action-btn'));
  }
}

function blockIP(ip, container) {
  var btns = container.querySelectorAll('.action-btn');
  btns.forEach(function(b) { b.disabled = true; b.textContent = 'blocking...'; });
  fetch('/api/firewall/blocklist', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ip: ip, source: 'chat-action'})
  })
  .then(function(r) { return r.json(); })
  .then(function(data) {
    if (data.error) { toast(data.error, 'error'); return; }
    btns.forEach(function(b) { if (b.textContent.indexOf(ip) >= 0) b.textContent = 'blocked'; });
    toast('Blocked ' + ip, 'success');
  })
  .catch(function(err) {
    btns.forEach(function(b) { b.disabled = false; b.textContent = 'block ' + ip; });
    toast(err.message, 'error');
  });
}

document.addEventListener('DOMContentLoaded', function() {
  var input = document.getElementById('chat-input');
  if (input) {
    input.addEventListener('keydown', function(e) {
      if (e.key === 'Enter') sendChat();
    });
  }
});

function analyzePending(id, ip, port) {
  openChat();
  var msg = 'Analyze connection to ' + ip + ':' + port + ' for security. Should I allow or deny this connection?';
  var input = document.getElementById('chat-input');
  input.value = msg;
  sendChat();
}

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const ws = new WebSocket(proto + '//' + location.host + '/ws');

  ws.onmessage = function(e) {
    try {
      const data = JSON.parse(e.data);
      handleWSUpdate(data);
      _lastWS = Date.now();
    } catch (err) {
      console.error('ws: parse error', err);
    }
  };

  ws.onopen = function() {
    updateStatusMeta('connected ' + stamp());
    _lastWS = Date.now();
  };

  ws.onclose = function() {
    updateStatusMeta('disconnected — reconnecting…');
    console.log('ws: disconnected, reconnecting in 1s');
    setTimeout(connectWS, 1000);
  };

  ws.onerror = function() {
    ws.close();
  };
}

function checkHealth() {
  fetch('/api/health')
    .then(r => r.json())
    .then(h => {
      if (_lastWS) return; // WS is the source of truth once connected
      const el = document.getElementById('stat-fw');
      if (el) el.textContent = h.firewall && h.firewall.enabled ? 'active' : 'inactive';
    })
    .catch(() => {});
}

function renderMetrics() {
  fetch('/api/metrics')
    .then(function(r) { return r.json(); })
    .then(function(m) {
      var el = document.getElementById('sys-list');
      if (!el) return;
      var cpu = m.cpu_percent || 0;
      var mem = m.memory_rss_mb || 0;
      var gor = m.num_goroutine || 0;
      var fds = m.open_fds || 0;
      var gc = m.gc_num || 0;
      var uptime = m.uptime || '-';
      el.innerHTML =
        '<div class="sys-kv"><span class="k">cpu</span><span class="v">' + cpu.toFixed(1) + '%</span></div>' +
        '<div class="sys-kv"><span class="k">memory</span><span class="v">' + mem + ' MB</span></div>' +
        '<div class="sys-kv"><span class="k">goroutines</span><span class="v">' + gor + '</span></div>' +
        '<div class="sys-kv"><span class="k">fds</span><span class="v">' + fds + '</span></div>' +
        '<div class="sys-kv"><span class="k">gc cycles</span><span class="v">' + gc + '</span></div>' +
        '<div class="sys-kv"><span class="k">uptime</span><span class="v">' + uptime + '</span></div>' +
        '<div class="sys-kv"><span class="k">go</span><span class="v">' + (m.go_version || '') + '</span></div>';
    })
    .catch(function() {});
}

// initial fetch so dashboard isn't blank on page load
fetch('/api/stats').then(r => r.json()).then(s => {
  document.getElementById('stat-total').textContent = s.total_conns || 0;
  document.getElementById('stat-active').textContent = s.active_conns || 0;
  document.getElementById('stat-alerts').textContent = s.alert_count || 0;
  document.getElementById('stat-procs').textContent = (s.top_processes && s.top_processes.length) || 0;
}).catch(() => {});
checkHealth();
renderMetrics();
setInterval(renderMetrics, 5000);
connectWS();

// stale-connection watchdog: flips the live dot + meta if no WS data for 6s
setInterval(function() {
  const el = document.getElementById('status-meta');
  if (!el || !_lastWS) return;
  const age = Date.now() - _lastWS;
  const strip = document.getElementById('status-strip');
  if (age > 6000) {
    if (!strip.classList.contains('stale')) {
      strip.classList.add('stale');
      el.textContent = 'stale — last update ' + Math.round(age / 1000) + 's ago';
    } else {
      el.textContent = 'stale — last update ' + Math.round(age / 1000) + 's ago';
    }
  } else if (strip.classList.contains('stale')) {
    strip.classList.remove('stale');
    el.textContent = 'live';
  }
}, 2000);
