var state = {
  processes: [],
  captures: [],
  analyses: [],
  selected: new Set(),
  _prevProcessJSON: '',
};

// ── Init ──

document.addEventListener('DOMContentLoaded', function() {
  loadProcesses();
  // auto-refresh process list every 5s
  setInterval(loadProcesses, 5000);
  // escape key closes pcap modal
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closePcapModal();
  });
});

function loadProcesses() {
  fetch('/api/processes')
    .then(function(r) { return r.json(); })
    .then(function(data) {
      var json = JSON.stringify(data);
      if (json === state._prevProcessJSON) return;
      state._prevProcessJSON = json;
      // preserve selections by PID
      var prevSelected = new Set(state.selected);
      state.processes = data || [];
      // re-apply selections that still exist
      var validPIDs = new Set(state.processes.map(function(p) { return p.pid; }));
      state.selected = new Set(Array.from(prevSelected).filter(function(pid) { return validPIDs.has(pid); }));
      renderProcesses();
      updateCounts();
    })
    .catch(function() {
      // only show error on first load, not on auto-refresh
      if (state.processes.length === 0) {
        document.getElementById('proc-list').innerHTML =
          '<div class="empty-state"><div class="empty-icon">⚠</div><div>failed to load processes</div><div class="empty-hint">is the backend running?</div></div>';
      }
    });
}

// ── Process List ──

function renderProcesses() {
  var filter = (document.getElementById('proc-filter').value || '').toLowerCase();
  var list = document.getElementById('proc-list');
  var frag = document.createDocumentFragment();

  var filtered = state.processes;
  if (filter) {
    filtered = state.processes.filter(function(p) {
      return (p.comm || '').toLowerCase().includes(filter) ||
             (p.exe || '').toLowerCase().includes(filter) ||
             String(p.pid).includes(filter);
    });
  }

  if (filtered.length === 0) {
    list.innerHTML = '<div class="empty-state"><div class="empty-icon">🔍</div><div>no processes found</div></div>';
    return;
  }

  filtered.forEach(function(p) {
    var item = document.createElement('div');
    item.className = 'proc-item' + (state.selected.has(p.pid) ? ' selected' : '');
    item.dataset.pid = p.pid;

    var initial = (p.comm || '?').charAt(0).toUpperCase();

    item.innerHTML =
      '<input type="checkbox" class="proc-check" ' + (state.selected.has(p.pid) ? 'checked' : '') + ' onchange="toggleSelect(' + p.pid + ',this.checked)">' +
      '<div class="proc-icon">' + esc(initial) + '</div>' +
      '<div class="proc-info">' +
        '<div class="proc-name">' + esc(p.comm || '?') + '</div>' +
        '<div class="proc-meta">PID ' + p.pid + (p.exe ? ' · ' + esc(trunc(p.exe, 40)) : '') + '</div>' +
      '</div>' +
      '<span class="proc-badge">' + p.conn_count + '</span>' +
      '<span class="proc-expand">▶</span>';

    item.addEventListener('click', function(e) {
      if (e.target.type === 'checkbox') return;
      item.classList.toggle('open');
    });

    frag.appendChild(item);

    // connections sublist
    var conns = document.createElement('div');
    conns.className = 'proc-conns';
    if (p.connections && p.connections.length > 0) {
      p.connections.forEach(function(c) {
        var row = document.createElement('div');
        row.className = 'proc-conn-row';
        var stateLabel = c.state || '';
        var stateClass = (stateLabel.startsWith('EST') || stateLabel.startsWith('LIS')) ? 'est' : 'syn';
        var domain = c.domain ? ' (' + esc(c.domain) + ')' : '';
        row.innerHTML =
          '<span class="conn-addr">' + esc(c.remote_addr || '?') + ':' + '</span>' +
          '<span class="conn-port">' + (c.remote_port || '?') + '</span>' +
          domain +
          '<span class="conn-state ' + stateClass + '" style="margin-left:auto">' + stateLabel + '</span>';
        conns.appendChild(row);
      });
    } else {
      conns.innerHTML = '<div class="proc-conn-row" style="color:var(--text-muted)">no remote connections</div>';
    }
    frag.appendChild(conns);
  });

  list.replaceChildren(frag);
}

function toggleSelect(pid, checked) {
  if (checked) {
    state.selected.add(pid);
  } else {
    state.selected.delete(pid);
  }
  // update visual
  var items = document.querySelectorAll('.proc-item');
  items.forEach(function(el) {
    if (parseInt(el.dataset.pid) === pid) {
      el.classList.toggle('selected', checked);
    }
  });
  updateCounts();
}

function selectAll() {
  state.processes.forEach(function(p) { state.selected.add(p.pid); });
  renderProcesses();
}

function deselectAll() {
  state.selected.clear();
  renderProcesses();
}

function updateCounts() {
  var btn = document.getElementById('btn-capture-sel');
  if (btn) {
    btn.textContent = state.selected.size > 0 ? 'capture (' + state.selected.size + ')' : 'capture sel';
  }
}

// ── Capture ──

function captureSelected() {
  var pids = Array.from(state.selected);
  if (pids.length === 0) { toast('select processes first', 'info'); return; }
  pids.forEach(function(pid) {
    var proc = state.processes.find(function(p) { return p.pid === pid; });
    startCapture(pid, proc ? proc.comm : 'pid-' + pid);
  });
  switchTab('captures');
}

function captureAll() {
  state.processes.forEach(function(p) {
    state.selected.add(p.pid);
    startCapture(p.pid, p.comm);
  });
  switchTab('captures');
}

function startCapture(pid, name) {
  var cap = { pid: pid, procName: name, filename: '', size: 0, status: 'pending', time: Date.now(), elapsed: 0 };
  state.captures.push(cap);
  renderCaptures();
  updateCapCount();

  // countdown timer for capture duration (30s default)
  var capDur = 30;
  cap._timer = setInterval(function() {
    cap.elapsed = (Date.now() - cap.time) / 1000;
    if (cap.status === 'pending') renderCaptures();
  }, 1000);

  fetch('/api/pcap/capture', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pid: pid })
  })
  .then(function(r) {
    if (!r.ok) throw new Error('capture failed');
    return r.json();
  })
  .then(function(data) {
    cap.filename = data.filename;
    cap.size = data.size;
    cap.status = 'done';
    clearInterval(cap._timer);
    renderCaptures();
    toast(name + ': ' + formatSize(data.size), 'success');
  })
  .catch(function(err) {
    cap.status = 'error';
    cap.error = err.message;
    clearInterval(cap._timer);
    renderCaptures();
    toast(name + ': capture failed', 'error');
  });
}

// ── Captures Tab ──

function renderCaptures() {
  var body = document.getElementById('results-body');
  var activeTab = document.querySelector('.results-tab.active');
  if (activeTab && activeTab.dataset.tab !== 'captures') return;

  if (state.captures.length === 0) {
    body.innerHTML =
      '<div class="empty-state">' +
        '<div class="empty-icon">📡</div>' +
        '<div>no captures yet</div>' +
        '<div class="empty-hint">select processes on the left and click "capture sel"</div>' +
      '</div>';
    return;
  }

  var frag = document.createDocumentFragment();
  // show most recent first
  var caps = state.captures.slice().reverse();
  caps.forEach(function(c) {
    var item = document.createElement('div');
    item.className = 'capture-item';

    var statusLabel = c.status === 'done' ? 'done' : (c.status === 'error' ? 'error' : 'capturing');
    var sizeStr = c.status === 'done' ? formatSize(c.size) : (c.status === 'error' ? c.error || 'failed' : (c.elapsed ? Math.round(c.elapsed) + 's' : '<span class="spinner"></span>'));
    var timeStr = formatTime(c.time);

    item.innerHTML =
      '<div class="cap-header">' +
        '<span class="cap-proc">' + esc(c.procName) + '</span>' +
        '<span class="cap-status ' + c.status + '">' + statusLabel + '</span>' +
      '</div>' +
      '<div class="cap-info">' + timeStr + ' · ' + sizeStr + '</div>';

    if (c.status === 'done') {
      var actions = document.createElement('div');
      actions.className = 'cap-actions';
      actions.innerHTML =
        '<button data-action="read" data-filename="' + attr(c.filename) + '" data-proc="' + attr(c.procName) + '">read</button>' +
        '<button data-action="analyze" data-filename="' + attr(c.filename) + '" data-proc="' + attr(c.procName) + '">analyze</button>' +
        '<button data-action="download" data-filename="' + attr(c.filename) + '">download</button>';
      // bind action buttons via event delegation
      actions.querySelectorAll('button').forEach(function(btn) {
        btn.addEventListener('click', function(e) {
          var action = btn.dataset.action;
          var filename = btn.dataset.filename;
          var proc = btn.dataset.proc;
          if (action === 'read') readCapture(filename, proc);
          else if (action === 'analyze') analyzeCapture(filename, proc);
          else if (action === 'download') downloadCapture(filename);
        });
      });
      item.appendChild(actions);
    }

    frag.appendChild(item);
  });

  body.replaceChildren(frag);
}

// ── Analysis Tab ──

function analyzeCapture(filename, procName) {
  var analysis = { procName: procName, filename: filename, content: 'analyzing...', time: Date.now() };
  state.analyses.push(analysis);
  switchTab('analysis');
  renderAnalyses();

  fetch('/api/ai/analyze-pcap', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ filename: filename })
  })
  .then(function(r) {
    if (!r.ok) throw new Error('analysis failed');
    return r.json();
  })
  .then(function(data) {
    analysis.content = data.analysis || 'no analysis returned';
    renderAnalyses();
  })
  .catch(function(err) {
    analysis.content = 'analysis failed: ' + err.message;
    analysis.error = true;
    renderAnalyses();
  });
}

function analyzeAll() {
  var doneCaps = state.captures.filter(function(c) { return c.status === 'done' && c.filename; });
  if (doneCaps.length === 0) { toast('no completed captures to analyze', 'info'); return; }
  doneCaps.forEach(function(c) {
    // skip if already analyzed
    var already = state.analyses.some(function(a) { return a.filename === c.filename; });
    if (!already) analyzeCapture(c.filename, c.procName);
  });
}

function renderAnalyses() {
  var body = document.getElementById('results-body');
  var activeTab = document.querySelector('.results-tab.active');
  if (activeTab && activeTab.dataset.tab !== 'analysis') return;

  if (state.analyses.length === 0) {
    body.innerHTML =
      '<div class="empty-state">' +
        '<div class="empty-icon">🤖</div>' +
        '<div>no analyses yet</div>' +
        '<div class="empty-hint">capture a process, then click "analyze" on the capture</div>' +
      '</div>';
    return;
  }

  var frag = document.createDocumentFragment();
  var ans = state.analyses.slice().reverse();
  ans.forEach(function(a) {
    var item = document.createElement('div');
    item.className = 'analysis-item';

    var isPending = (a.content === 'analyzing...');
    var displayContent = isPending ? 'analyzing...' : a.content;
    var spinnerHtml = isPending ? '<span class="spinner" style="margin-right:6px;vertical-align:middle"></span> ' : '';

    var srcRef = a.filename ? '<span style="font-size:9px;color:var(--text-muted);margin-left:8px">' + esc(a.filename) + '</span>' : '';
    item.innerHTML =
      '<div class="an-hdr">' +
        '<span class="an-proc">' + esc(a.procName) + '</span>' +
        srcRef +
        '<span class="an-time">' + formatTime(a.time) + '</span>' +
      '</div>' +
      '<div class="an-body">' + spinnerHtml + esc(displayContent) + '</div>';

    frag.appendChild(item);
  });

  body.replaceChildren(frag);
}

// ── Tab Switching ──

function switchTab(tab) {
  document.querySelectorAll('.results-tab').forEach(function(t) {
    t.classList.toggle('active', t.dataset.tab === tab);
  });
  if (tab === 'captures') renderCaptures();
  else renderAnalyses();
  updateCapCount();
  updateAnCount();
}

function updateCapCount() {
  var el = document.getElementById('cap-count');
  if (el) el.textContent = state.captures.length;
}

function updateAnCount() {
  var el = document.getElementById('an-count');
  if (el) el.textContent = state.analyses.length;
}

// ── Read Capture (modal) ──

function readCapture(filename, procName) {
  document.getElementById('pcap-modal-title').textContent = esc(procName) + ' — packet capture';
  document.getElementById('pcap-modal-body').textContent = 'loading...';
  document.getElementById('pcap-modal').classList.add('open');

  fetch('/api/pcap/read/' + encodeURIComponent(filename))
    .then(function(r) {
      if (!r.ok) throw new Error('failed to read');
      return r.text();
    })
    .then(function(text) {
      document.getElementById('pcap-modal-body').textContent = text || '(empty capture)';
    })
    .catch(function() {
      document.getElementById('pcap-modal-body').textContent = 'failed to load capture';
    });
}

function closePcapModal() {
  document.getElementById('pcap-modal').classList.remove('open');
}

// ── Download ──

function downloadCapture(filename) {
  var a = document.createElement('a');
  a.href = '/api/pcap/download/' + encodeURIComponent(filename);
  a.download = filename;
  a.click();
}

// ── Helpers ──

function esc(s) {
  if (typeof s !== 'string') return String(s || '');
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function attr(s) {
  if (typeof s !== 'string') return String(s || '');
  return s.replace(/&/g,'&amp;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function trunc(s, max) {
  if (!s || s.length <= max) return s || '';
  return s.substring(0, max) + '...';
}

function formatSize(bytes) {
  if (!bytes) return '0B';
  var units = ['B', 'KB', 'MB'];
  var i = 0;
  var size = bytes;
  while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
  return size.toFixed(i === 0 ? 0 : 1) + units[i];
}

function formatTime(ts) {
  var d = new Date(ts);
  return d.toLocaleTimeString();
}

function toast(msg, type) {
  type = type || 'info';
  var container = document.getElementById('toast-container') || (function() {
    var c = document.createElement('div');
    c.id = 'toast-container';
    c.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:2000;display:flex;flex-direction:column;gap:6px';
    document.body.appendChild(c);
    return c;
  })();
  var el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(function() { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; setTimeout(function() { el.remove(); }, 300); }, 2500);
}
