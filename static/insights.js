let charts = {};
let filterState = { process: '', remote: '' };
let currentData = null;
let heatmapCache = null;

function fmtTime(ts) {
  const d = new Date(ts);
  return String(d.getHours()).padStart(2,'0') + ':' + String(d.getMinutes()).padStart(2,'0');
}

function fmtDate(ts) {
  const d = new Date(ts);
  return d.toLocaleDateString('en-US', {month:'short', day:'numeric'});
}

function fmtBucket(ts, range) {
  return range >= 1440 ? fmtDate(ts) : fmtTime(ts);
}

// ── data fetching ──
async function fetchData() {
  const range = parseInt(document.getElementById('time-range').value, 10);
  let url = '/api/dashboard?minutes=' + range;
  if (filterState.process) url += '&process=' + encodeURIComponent(filterState.process);
  if (filterState.remote) url += '&remote=' + encodeURIComponent(filterState.remote);
  try {
    const res = await fetch(url);
    if (!res.ok) return;
    currentData = await res.json();
    renderAll();
  } catch(e) { console.error('dashboard:', e); }
}

// ── time range ──
function changeRange() { fetchData(); }

// ── filter chips ──
function renderFilters() {
  const area = document.getElementById('filter-area');
  let chips = '';
  if (filterState.process) chips += '<span class="filter-chip">process: ' + filterState.process + ' <span class="remove" onclick="clearFilter(\'process\')">&times;</span></span> ';
  if (filterState.remote) chips += '<span class="filter-chip">remote: ' + filterState.remote + ' <span class="remove" onclick="clearFilter(\'remote\')">&times;</span></span> ';
  area.innerHTML = chips;
}

function clearFilter(key) {
  filterState[key] = '';
  renderFilters();
  fetchData();
}

function setFilter(key, val) {
  filterState[key] = val;
  renderFilters();
  fetchData();
}

// ── stat cards ──
function renderStatCards(data) {
  const s = data.summary;
  const cards = [
    {val: s.total_conns, lbl: 'connections'},
    {val: s.active_conns, lbl: 'active'},
    {val: s.alert_count, lbl: 'alerts'},
    {val: fmtBytes(s.total_tx_queue + s.total_rx_queue), lbl: 'total bw'},
    {val: s.fw_enabled ? (s.fw_panic ? 'PANIC' : 'active') : 'off', lbl: 'fw', cls: s.fw_panic ? 'panic' : (s.fw_enabled ? 'fw-on' : 'fw-off')},
  ];
  document.getElementById('stat-cards').innerHTML = cards.map(c =>
    '<div class="stat-card' + (c.cls ? ' ' + c.cls : '') + '"><div class="val">' + c.val + '</div><div class="lbl">' + c.lbl + '</div></div>'
  ).join('');
}

function fmtBytes(n) {
  if (n < 1024) return n + 'B';
  if (n < 1048576) return (n / 1024).toFixed(1) + 'KB';
  return (n / 1048576).toFixed(1) + 'MB';
}

// ── options helper ──
function chartOpts(extra) {
  return Object.assign({
    responsive: true,
    maintainAspectRatio: true,
    plugins: { legend: { display: false } },
    scales: {
      x: { grid: { color: '#21262d' }, ticks: { color: '#8b949e', font: { size: 10 } } },
      y: { grid: { color: '#21262d' }, ticks: { color: '#8b949e', font: { size: 10 } }, beginAtZero: true }
    },
    interaction: { intersect: false, mode: 'index' }
  }, extra || {});
}

// ── connection + alert timeline (correlation overlay) ──
function renderConnChart(data) {
  const canvas = document.getElementById('chart-conns');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (charts.conns) charts.conns.destroy();

  const range = parseInt(document.getElementById('time-range').value, 10);
  const labels = data.conn_timeline.map(b => fmtBucket(b.bucket, range));
  const connVals = data.conn_timeline.map(b => b.count);

  if (!labels.length) {
    emptyState(canvas, 'no data');
    return;
  }
  clearEmpty(canvas);

  // Build alert map keyed by bucket
  const alertMap = {};
  for (const b of data.alert_timeline) alertMap[b.bucket] = b.count;
  const alertVals = data.conn_timeline.map(b => alertMap[b.bucket] || 0);

  // Anomaly info
  const info = document.getElementById('anomaly-info');
  if (data.anomaly_threshold > 0) {
    info.textContent = ' [anomaly >' + data.anomaly_threshold.toFixed(1) + ']';
  } else {
    info.textContent = '';
  }

  charts.conns = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'connections',
          data: connVals,
          borderColor: '#58a6ff',
          backgroundColor: 'rgba(88,166,255,0.08)',
          fill: true,
          tension: 0.3,
          pointRadius: ctx => {
            if (!data.anomaly_threshold) return 2;
            return data.conn_timeline[ctx.dataIndex] && data.conn_timeline[ctx.dataIndex].count > data.anomaly_threshold ? 6 : 2;
          },
          pointBackgroundColor: ctx => {
            if (!data.anomaly_threshold) return '#58a6ff';
            return data.conn_timeline[ctx.dataIndex] && data.conn_timeline[ctx.dataIndex].count > data.anomaly_threshold ? '#f85149' : '#58a6ff';
          },
          borderWidth: 2
        },
        {
          label: 'alerts',
          data: alertVals,
          borderColor: '#f85149',
          backgroundColor: 'rgba(248,81,73,0.08)',
          fill: true,
          tension: 0.3,
          pointRadius: 2,
          borderWidth: 1,
          yAxisID: 'y1'
        }
      ]
    },
    options: chartOpts({
      scales: {
        x: { grid: { color: '#21262d' }, ticks: { color: '#8b949e', font: { size: 10 } } },
        y: { grid: { color: '#21262d' }, ticks: { color: '#8b949e', font: { size: 10 } }, beginAtZero: true, position: 'left' },
        y1: { grid: { display: false }, ticks: { color: '#f85149', font: { size: 10 } }, beginAtZero: true, position: 'right' }
      },
      plugins: {
        legend: { display: true, position: 'top', labels: { color: '#8b949e', font: { size: 10 }, boxWidth: 10 } }
      }
    })
  });
}

// ── heatmap ──
function renderHeatmap(data) {
  const canvas = document.getElementById('chart-heatmap');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  if (!heatmapCache) {
    fetch('/api/dashboard/heatmap?days=7')
      .then(r => r.json())
      .then(cells => { heatmapCache = cells; renderHeatmap(data); })
      .catch(() => {});
    return;
  }

  if (charts.heatmap) charts.heatmap.destroy();
  const cells = heatmapCache;
  if (!cells || !cells.length) {
    emptyState(canvas, 'no data');
    return;
  }
  clearEmpty(canvas);
  const maxVal = Math.max(...cells.map(c => c.count), 1);
  const days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  charts.heatmap = new Chart(ctx, {
    type: 'matrix',
    data: {
      datasets: [{
        label: 'connections',
        data: cells.map(c => ({x: c.hour, y: c.dow, v: c.count})),
        backgroundColor(ctx) {
          const v = ctx.raw ? ctx.raw.v : 0;
          const alpha = Math.min(v / maxVal, 1);
          return 'rgba(88,166,255,' + (0.1 + alpha * 0.9) + ')';
        },
        borderColor: '#21262d',
        borderWidth: 1,
        width: ctx => (ctx.chart.chartArea ? (ctx.chart.chartArea.right - ctx.chart.chartArea.left) / 25 : 20),
        height: ctx => (ctx.chart.chartArea ? (ctx.chart.chartArea.bottom - ctx.chart.chartArea.top) / 8 : 20)
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: true,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            title(ctx) { return days[ctx[0].raw.y] + ' ' + ctx[0].raw.x + ':00'; },
            label(ctx) { return 'conns: ' + ctx.raw.v; }
          }
        }
      },
      scales: {
        x: {
          type: 'linear',
          offset: false,
          grid: { display: false },
          ticks: { color: '#8b949e', font: { size: 9 }, stepSize: 3 }
        },
        y: {
          type: 'linear',
          offset: false,
          grid: { display: false },
          ticks: { color: '#8b949e', font: { size: 9 }, callback(v) { return days[v] || ''; } }
        }
      }
    }
  });
}

// ── protocol doughnut ──
function renderProtocolChart(data) {
  const canvas = document.getElementById('chart-protocol');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (charts.protocol) charts.protocol.destroy();
  const labels = data.protocol_dist.map(p => p.protocol.toUpperCase());
  const vals = data.protocol_dist.map(p => p.count);
  if (!labels.length) { emptyState(canvas, 'no data'); return; }
  clearEmpty(canvas);
  charts.protocol = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets: [{ data: vals, backgroundColor: ['#58a6ff','#3fb950','#d29922','#f85149'], borderWidth: 0 }] },
    options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { color: '#8b949e', font: { size: 10 } } } } }
  });
}

// ── severity doughnut ──
function renderSeverityChart(data) {
  const canvas = document.getElementById('chart-severity');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (charts.severity) charts.severity.destroy();
  const labels = data.severity_dist.map(s => 'sev ' + s.severity);
  const vals = data.severity_dist.map(s => s.count);
  if (!labels.length) { emptyState(canvas, 'no data'); return; }
  clearEmpty(canvas);
  charts.severity = new Chart(ctx, {
    type: 'doughnut',
    data: { labels, datasets: [{ data: vals, backgroundColor: ['#3fb950','#d29922','#f85149','#ff6b6b','#ff0000'], borderWidth: 0 }] },
    options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { color: '#8b949e', font: { size: 10 } } } } }
  });
}

// ── horizontal bar (generic, with click drill-down) ──
function renderBarChart(id, data, label, filterKey) {
  const canvas = document.getElementById(id);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (charts[id]) charts[id].destroy();
  const labels = data.map(d => d.name);
  const vals = data.map(d => d.count);
  if (!labels.length) { emptyState(canvas, 'no data'); return; }
  clearEmpty(canvas);
  charts[id] = new Chart(ctx, {
    type: 'bar',
    data: { labels, datasets: [{ label: label || 'count', data: vals, backgroundColor: '#58a6ff', borderRadius: 3, borderSkipped: false }] },
    options: chartOpts({
      indexAxis: 'y',
      plugins: { legend: { display: false } },
      onClick(e, el) {
        if (!filterKey || !el.length) return;
        const idx = el[0].index;
        const val = labels[idx];
        if (val) setFilter(filterKey, val.replace(/:.*$/,''));
      }
    })
  });
}

// ── bandwidth chart ──
function renderBandwidthChart(data) {
  const canvas = document.getElementById('chart-bandwidth');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  if (charts.bandwidth) charts.bandwidth.destroy();
  const items = data.bandwidth_top || [];
  const labels = items.map(b => b.name);
  const tx = items.map(b => b.tx_queue);
  const rx = items.map(b => b.rx_queue);
  if (!labels.length) { emptyState(canvas, 'no data'); return; }
  clearEmpty(canvas);
  charts.bandwidth = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        { label: 'tx', data: tx, backgroundColor: '#58a6ff', borderRadius: 3, borderSkipped: false },
        { label: 'rx', data: rx, backgroundColor: '#3fb950', borderRadius: 3, borderSkipped: false }
      ]
    },
    options: chartOpts({
      indexAxis: 'y',
      plugins: { legend: { display: true, position: 'top', labels: { color: '#8b949e', font: { size: 10 }, boxWidth: 10 } } },
      scales: {
        x: { grid: { color: '#21262d' }, ticks: { color: '#8b949e', font: { size: 9 }, callback: v => fmtBytes(v) } },
        y: { grid: { display: false }, ticks: { color: '#8b949e', font: { size: 9 } } }
      }
    })
  });
}

// ── flow diagram (SVG sankey-like) ──
function renderFlow(data) {
  const container = document.getElementById('flow-diagram');
  if (!container) return;
  const flows = data.flows || [];
  if (!flows.length) { container.innerHTML = '<div style="color:var(--text-muted);font-size:11px;text-align:center;padding:20px 0">no data</div>'; return; }

  // Collect unique nodes
  const nodes = new Map();
  const nodeIdx = new Map();
  for (const f of flows) {
    if (!nodes.has(f.source)) { nodes.set(f.source, {id: f.source, type: 'source'}); }
    if (!nodes.has(f.target)) { nodes.set(f.target, {id: f.target, type: 'target'}); }
  }
  const nodeList = [...nodes.values()];
  nodeList.forEach((n, i) => nodeIdx.set(n.id, i));

  const srcNodes = nodeList.filter(n => flows.some(f => f.source === n.id));
  const tgtNodes = nodeList.filter(n => flows.some(f => f.target === n.id));
  const w = Math.max(container.clientWidth || 900, 600);
  const srcCount = srcNodes.length || 1;
  const tgtCount = tgtNodes.length || 1;
  const h = Math.max(300, Math.max(srcCount, tgtCount) * 28);
  const lx = 120;
  const rx = w - 120;

  let svg = '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '">';
  const maxVal = Math.max(...flows.map(f => f.value), 1);
  const srcStep = h / (srcNodes.length + 1);
  const tgtStep = h / (tgtNodes.length + 1);
  const srcY = {};
  srcNodes.forEach((n, i) => srcY[n.id] = (i + 1) * srcStep);
  const tgtY = {};
  tgtNodes.forEach((n, i) => tgtY[n.id] = (i + 1) * tgtStep);

  for (const f of flows) {
    const sy = srcY[f.source] || h / 2;
    const ty = tgtY[f.target] || h / 2;
    const alpha = 0.2 + (f.value / maxVal) * 0.6;
    const sw = 1 + (f.value / maxVal) * 8;
    svg += '<path d="M' + lx + ',' + sy + ' C' + (lx + 80) + ',' + sy + ' ' + (rx - 80) + ',' + ty + ' ' + rx + ',' + ty + '" stroke="#58a6ff" stroke-width="' + sw + '" fill="none" stroke-opacity="' + alpha + '" />';
  }

  // source labels
  for (const n of srcNodes) {
    const y = srcY[n.id];
    svg += '<text x="' + (lx - 6) + '" y="' + (y + 3) + '" text-anchor="end" class="node-label">' + esc(n.id) + '</text>';
    svg += '<circle cx="' + lx + '" cy="' + y + '" r="3" fill="#58a6ff" />';
  }

  // target labels
  for (const n of tgtNodes) {
    const y = tgtY[n.id];
    svg += '<text x="' + (rx + 6) + '" y="' + (y + 3) + '" text-anchor="start" class="node-label">' + esc(n.id) + '</text>';
    svg += '<circle cx="' + rx + '" cy="' + y + '" r="3" fill="#3fb950" />';
  }

  svg += '</svg>';
  container.innerHTML = svg;
}

function emptyState(canvas, msg) {
  let empty = canvas.parentElement.querySelector('.chart-empty');
  if (!empty) {
    empty = document.createElement('div');
    empty.className = 'chart-empty';
    empty.style.cssText = 'color:var(--text-muted);font-size:11px;text-align:center;padding:20px 0;position:absolute;top:50%;left:50%;transform:translate(-50%,-50%)';
    canvas.parentElement.style.position = 'relative';
    canvas.parentElement.appendChild(empty);
  }
  empty.textContent = msg || 'no data';
  canvas.style.display = 'none';
}

function clearEmpty(canvas) {
  const empty = canvas.parentElement.querySelector('.chart-empty');
  if (empty) empty.remove();
  canvas.style.display = '';
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

// ── export PNG ──
function exportPNG() {
  const btn = document.querySelector('[onclick="exportPNG()"]');
  btn.textContent = 'capturing...';
  html2canvas(document.querySelector('.charts-grid'), {
    backgroundColor: '#0d1117',
    scale: 2
  }).then(canvas => {
    const link = document.createElement('a');
    link.download = 'netguard_insights_' + new Date().toISOString().slice(0,19).replace(/[:-]/g,'') + '.png';
    link.href = canvas.toDataURL();
    link.click();
    btn.textContent = 'export PNG';
  }).catch(() => {
    btn.textContent = 'export PNG';
  });
}

// ── render all ──
function renderAll() {
  if (!currentData) return;
  renderStatCards(currentData);
  renderConnChart(currentData);
  renderProtocolChart(currentData);
  renderSeverityChart(currentData);
  renderBarChart('chart-procs', currentData.top_processes, 'connections', 'process');
  renderBarChart('chart-remotes', currentData.top_remotes, 'connections', 'remote');
  renderBarChart('chart-ports', currentData.top_ports, 'connections');
  renderBandwidthChart(currentData);
  renderFlow(currentData);
  renderHeatmap(currentData);
}

// ── init ──
document.addEventListener('DOMContentLoaded', fetchData);
setInterval(fetchData, 15000);
