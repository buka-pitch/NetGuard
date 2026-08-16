// events.js — renders the authentication audit log

let autoTimer = null;

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s == null ? '' : String(s);
  return d.innerHTML;
}

function fmtTs(unixSec) {
  if (!unixSec) return '—';
  return new Date(unixSec * 1000).toLocaleString();
}

function tagClass(event) {
  if (!event) return 'event-tag-info';
  if (event.startsWith('login_success') || event.startsWith('user_created') || event.startsWith('password_change_success') || event === 'password_reset') {
    return 'event-tag-success';
  }
  if (event.startsWith('login_failure') || event.startsWith('password_change_denied')) {
    return 'event-tag-failure';
  }
  if (event.startsWith('login_lockout') || event === 'session_revoked') {
    return 'event-tag-warn';
  }
  return 'event-tag-info';
}

function renderEmpty(message) {
  const el = document.getElementById('event-list');
  el.innerHTML = '<div class="empty-state">' + esc(message) + '</div>';
  document.getElementById('event-count').textContent = '0';
}

function renderEvents(events) {
  const el = document.getElementById('event-list');
  document.getElementById('event-count').textContent = events.length;
  if (!events.length) {
    renderEmpty('no events yet');
    return;
  }
  const html = events.map((e) => {
    return '<div class="event-row">' +
      '<div class="event-ts">' + esc(fmtTs(e.ts)) + '</div>' +
      '<div class="event-user">' + esc(e.username || '(unknown)') + '</div>' +
      '<div class="event-ip">' + esc(e.ip || '') + '</div>' +
      '<div><span class="event-tag ' + tagClass(e.event) + '">' + esc(e.event) + '</span></div>' +
    '</div>';
  }).join('');
  el.innerHTML = html;
}

async function loadEvents() {
  const btn = document.getElementById('refresh-btn');
  if (btn) { btn.disabled = true; btn.textContent = 'loading…'; }
  try {
    const r = await fetch('/api/auth/events', { credentials: 'include' });
    if (!r.ok) {
      renderEmpty('failed to load events: HTTP ' + r.status);
      return;
    }
    const data = await r.json();
    renderEvents(data.events || []);
    const meta = document.getElementById('meta');
    if (meta) meta.textContent = 'updated ' + new Date().toLocaleTimeString();
  } catch (e) {
    renderEmpty('network error: ' + e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'refresh'; }
  }
}

function toggleAuto() {
  const btn = document.getElementById('auto-btn');
  if (autoTimer) {
    clearInterval(autoTimer);
    autoTimer = null;
    btn.textContent = 'auto-refresh: off';
  } else {
    loadEvents();
    autoTimer = setInterval(loadEvents, 10000);
    btn.textContent = 'auto-refresh: 10s';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  loadEvents();
});
