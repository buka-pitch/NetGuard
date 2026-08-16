// Auth helper for the NetGuard dashboard.
// - injects the X-XSRF-TOKEN header on every mutating fetch
// - checks /api/auth/status on page load; redirects to /login.html if not
//   authenticated (or /setup.html if no users exist)
// - if the user has a legacy password, redirects to /password-reset.html
// - exposes nmFetch(url, opts) as a drop-in replacement for fetch()
//
// Load this script BEFORE the page's own JS so the redirect happens early.

(function () {
  'use strict';

  const COOKIE_NAME = 'netmon_xsrf';
  const HEADER_NAME = 'X-XSRF-TOKEN';

  function readCookie(name) {
    const m = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
    return m ? decodeURIComponent(m[1]) : '';
  }

  function isMutation(method) {
    return method && method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS';
  }

  // Patch window.fetch so every call automatically carries credentials and
  // the X-XSRF-TOKEN header on mutations. Streaming reads still work because
  // the headers are added before the request is issued.
  const origFetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    init = init || {};
    init.credentials = init.credentials || 'include';
    init.headers = init.headers || {};
    const method = (init.method || (input && input.method) || 'GET').toUpperCase();
    if (isMutation(method)) {
      const tok = readCookie(COOKIE_NAME);
      if (tok) {
        // support both Headers object and plain dict
        if (typeof Headers !== 'undefined' && init.headers instanceof Headers) {
          if (!init.headers.has(HEADER_NAME)) init.headers.set(HEADER_NAME, tok);
        } else {
          init.headers[HEADER_NAME] = tok;
        }
      }
    }
    return origFetch(input, init);
  };

  async function nmFetch(url, opts) {
    return origFetch(url, Object.assign({ credentials: 'include' }, opts || {}));
  }

  async function checkAuth() {
    try {
      const r = await origFetch('/api/auth/status', { credentials: 'include' });
      if (!r.ok) return;
      const s = await r.json();
      if (s.setup_required) {
        window.location.href = '/setup.html';
        return;
      }
      if (!s.authenticated) {
        window.location.href = '/login.html';
        return;
      }
      if (s.password_reset_required) {
        window.location.href = '/password-reset.html?forced=1';
        return;
      }
      window.__netmonUser = { id: s.user_id, username: s.username };
    } catch (e) {
      // network error — let the page render with degraded UI; the next
      // fetch will surface 401 and the wrapper will redirect
    }
  }

  // Intercept 401s globally: if any fetch returns 401, kick to login.
  // Done by wrapping the patched fetch's returned Promise.
  const origPatched = window.fetch;
  window.fetch = function (input, init) {
    return origPatched(input, init).then(function (r) {
      if (r && r.status === 401 && !location.pathname.startsWith('/login') && !location.pathname.startsWith('/setup') && !location.pathname.startsWith('/password-reset')) {
        location.href = '/login.html';
      }
      return r;
    });
  };

  window.nmFetch = nmFetch;
  window.readNetmonXsrf = function () { return readCookie(COOKIE_NAME); };

  // auto-run on script load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', checkAuth);
  } else {
    checkAuth();
  }
})();

