let currentRules = [];
let currentRuleStats = null;

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s || "";
  return d.innerHTML;
}

function fmtWhen(ms) {
  if (!ms) return "—";
  return new Date(ms).toLocaleString();
}

function readRulePayload(form) {
  const fd = new FormData(form);
  const body = {
    name: fd.get("name") || "",
    severity: fd.get("severity") || "medium",
    conditions: {}
  };

  for (const [k, v] of fd.entries()) {
    if (k === "name" || k === "severity" || !v) continue;
    if (k === "min_interval" || k === "max_interval" || k === "min_samples") {
      const parsed = parseInt(v, 10);
      if (!Number.isNaN(parsed)) body.conditions[k] = parsed;
      continue;
    }
    if (k === "entropy_max") {
      const parsed = parseFloat(v);
      if (!Number.isNaN(parsed)) body.conditions[k] = parsed;
      continue;
    }
    body.conditions[k] = v;
  }

  return body;
}

function renderPreviewEmpty(message) {
  document.getElementById("preview-summary").innerHTML = `
    <span><strong>triggered</strong> <span id="preview-triggered">0</span></span>
    <span><strong>candidates</strong> <span id="preview-candidates">0</span></span>
  `;
  document.getElementById("preview-note").textContent = message || "No preview yet.";
  document.getElementById("preview-results").innerHTML = '<div class="preview-empty">No preview yet.</div>';
}

function renderPreview(result) {
  const triggered = result?.triggered_count ?? 0;
  const candidates = result?.candidate_count ?? 0;
  const ruleName = result?.rule?.name || "draft";
  const severity = result?.rule?.severity || "medium";
  const note = [ruleName, severity].concat(result?.notes || []).join(" · ");

  document.getElementById("preview-triggered").textContent = String(triggered);
  document.getElementById("preview-candidates").textContent = String(candidates);
  document.getElementById("preview-note").textContent = note || "Preview updated.";

  const list = document.getElementById("preview-results");
  const matches = result?.matches || [];
  if (!matches.length) {
    list.innerHTML = '<div class="preview-empty">No live connections matched the current rule.</div>';
    return;
  }

  list.innerHTML = matches.map((m) => {
    const statusClass = m.status === "trigger" ? "status-trigger" : "status-pending";
    const statusLabel = m.status === "trigger" ? "trigger" : "pending";
    const endpoint = `${esc(m.remote_addr || "—")}:${esc(String(m.remote_port || 0))}`;
    const local = m.local_addr ? `${esc(m.local_addr)}:${esc(String(m.local_port || 0))}` : "—";
    const historyLine = m.sample_count
      ? `<div class="preview-meta">${m.sample_count} samples · avg ${Math.round(m.mean_interval_ms || 0)} ms</div>`
      : "";
    return `
      <div class="preview-item">
        <div class="preview-head">
          <div>
            <strong>${esc(m.comm || "(unknown)")}</strong>
            <div class="preview-meta">pid ${m.pid || 0} · ${esc(m.protocol || "n/a")} · ${esc(m.state || "n/a")}</div>
          </div>
          <span class="status-chip ${statusClass}">${statusLabel}</span>
        </div>
        <div class="preview-meta">${endpoint} ← ${local}</div>
        ${m.exe ? `<div class="preview-meta">${esc(m.exe)}</div>` : ""}
        ${historyLine}
      </div>
    `;
  }).join("");
}

async function previewRulePayload(payload) {
  const res = await fetch("/api/rules/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "preview failed");
  }
  return res.json();
}

async function previewDraft(e) {
  if (e) e.preventDefault();
  const form = document.getElementById("add-rule-form");
  try {
    const payload = readRulePayload(form);
    const result = await previewRulePayload(payload);
    renderPreview(result);
  } catch (err) {
    alert(err.message || String(err));
  }
}

async function previewSavedRule(id) {
  const rule = currentRules.find((r) => r.id === id);
  if (!rule) return;
  try {
    const result = await previewRulePayload({
      name: rule.name,
      severity: rule.severity,
      conditions: rule.conditions || {}
    });
    renderPreview(result);
  } catch (err) {
    alert(err.message || String(err));
  }
}

async function addRule(e) {
  e.preventDefault();
  const payload = readRulePayload(e.target);
  const res = await fetch("/api/rules", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (!res.ok) return alert(await res.text());
  e.target.reset();
  await render();
  renderPreviewEmpty("Rule saved. Preview another rule or build a new draft.");
}

async function toggleRule(id, enabled) {
  const res = await fetch("/api/rules/toggle", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id, enabled })
  });
  if (!res.ok) return alert(await res.text());
  await render();
}

async function deleteRule(id) {
  if (!confirm("Delete rule?")) return;
  const res = await fetch(`/api/rules?id=${id}`, { method: "DELETE" });
  if (!res.ok) return alert(await res.text());
  await render();
}

function renderRuleStatsEmpty(message) {
  currentRuleStats = null;
  document.getElementById("rule-stats-total").textContent = "0";
  document.getElementById("rule-stats-enabled").textContent = "0";
  document.getElementById("rule-stats-hits").textContent = "0";
  document.getElementById("rule-stats-hot").textContent = "—";
  document.getElementById("rule-stats-note").textContent = message || "Track which rules actually fire on live traffic.";
  document.getElementById("rule-stats-body").innerHTML = '<tr><td colspan="5" class="usage-empty">No rule analytics yet.</td></tr>';
}

function renderRuleStats(data) {
  currentRuleStats = data || null;
  const summary = data?.summary || {};
  const rules = data?.rules || [];
  document.getElementById("rule-stats-total").textContent = String(summary.total_rules ?? rules.length ?? 0);
  document.getElementById("rule-stats-enabled").textContent = String(summary.enabled_rules ?? 0);
  document.getElementById("rule-stats-hits").textContent = String(summary.total_hits ?? 0);
  document.getElementById("rule-stats-hot").textContent = summary.hot_rule ? `${summary.hot_rule} (${summary.hot_hits || 0})` : "—";
  document.getElementById("rule-stats-note").textContent = summary.last_alert_at
    ? `Last rule hit at ${fmtWhen(summary.last_alert_at)}`
    : "Track which rules actually fire on live traffic.";

  const body = document.getElementById("rule-stats-body");
  if (!rules.length) {
    body.innerHTML = '<tr><td colspan="5" class="usage-empty">No rule analytics yet.</td></tr>';
    return;
  }

  body.innerHTML = rules.map((r) => {
    const lastSeen = r.last_alert_at ? fmtWhen(r.last_alert_at) : "—";
    const endpoint = r.last_remote ? `${esc(r.last_remote)}:${esc(String(r.last_remote_port || 0))}` : "—";
    const proc = r.last_comm || "—";
    const hitClass = r.hit_count > 0 ? "usage-hit" : "usage-zero";
    return `
      <tr>
        <td>
          <strong><a href="#" onclick="previewSavedRule(${r.rule_id});return false" style="color:var(--text)">${esc(r.name)}</a></strong>
          <div class="preview-meta">${esc(r.severity)} · ${r.enabled ? "enabled" : "disabled"}</div>
        </td>
        <td class="${hitClass}">${r.hit_count || 0}</td>
        <td>${lastSeen}</td>
        <td>${endpoint}</td>
        <td>${esc(proc)}</td>
      </tr>
    `;
  }).join("");
}

async function loadRuleStats() {
  try {
    const res = await fetch("/api/rules/stats");
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    renderRuleStats(data);
  } catch (err) {
    renderRuleStatsEmpty(err.message || String(err));
  }
}

function summarizeConditions(c) {
  const parts = [];
  if (c.process_name) parts.push(`proc:${c.process_name}`);
  if (c.ip_range) parts.push(`ip:${c.ip_range}`);
  if (c.port_range) parts.push(`port:${c.port_range}`);
  if (c.min_interval || c.max_interval || c.min_samples) {
    const min = c.min_interval || 0;
    const max = c.max_interval || 0;
    parts.push(`beacon:${min || 0}-${max || "∞"}ms/${c.min_samples || 5}+`);
  }
  if (c.entropy_max) parts.push(`entropy<${c.entropy_max}`);
  return parts.length ? parts.join(" · ") : "catch-all";
}

async function render() {
  try {
    const res = await fetch("/api/rules");
    if (!res.ok) throw new Error(await res.text());
    currentRules = await res.json();
  } catch (err) {
    alert(err.message || String(err));
    currentRules = [];
  }

  document.getElementById("rule-count").textContent = currentRules.length;
  const tbody = document.getElementById("rules-body");
  tbody.innerHTML = "";
  if (!currentRules.length) {
    tbody.innerHTML = '<tr><td colspan="10" class="empty-state">no rules yet</td></tr>';
    await loadRuleStats();
    return;
  }

  for (const r of currentRules) {
    const c = r.conditions || {};
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><a href="#" onclick="toggleRule(${r.id}, ${!r.enabled});return false" class="${r.enabled ? "rule-active" : "rule-inactive"}">${r.enabled ? "●" : "○"}</a></td>
      <td><strong>${esc(r.name)}</strong></td>
      <td><span class="sev-${esc(r.severity)}">${esc(r.severity)}</span></td>
      <td>${esc(c.process_name) || "—"}</td>
      <td>${esc(c.ip_range) || "—"}</td>
      <td>${esc(c.port_range) || "—"}</td>
      <td>${c.min_interval ? `${c.min_interval}-${c.max_interval || "∞"}` : "—"}</td>
      <td>${c.entropy_max ? c.entropy_max : "—"}</td>
      <td>${r.created_at ? new Date(r.created_at * 1000).toLocaleString() : "—"}</td>
      <td>
        <a href="#" onclick="previewSavedRule(${r.id});return false" style="margin-right:8px;color:var(--accent)">preview</a>
        <a href="#" onclick="deleteRule(${r.id});return false" style="color:var(--danger)">delete</a>
      </td>`;
    tr.title = summarizeConditions(c);
    tbody.appendChild(tr);
  }

  await loadRuleStats();
}

document.addEventListener("DOMContentLoaded", () => {
  render();
  renderPreviewEmpty("Preview a draft or one of the saved rules to see how it behaves against live traffic.");
});
