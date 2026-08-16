// NetGuard dashboard service worker.
// Strategy: cache-first for the static asset shell so the UI loads even
// when the daemon is unreachable; network-first (no cache) for everything
// else so live data is always fresh.
//
// The daemon is local, so when it's down we want to at least show the
// login page instead of a network error.
const CACHE_NAME = 'netmon-shell-v6';
const SHELL_ASSETS = [
  '/',
  '/index.html',
  '/login.html',
  '/setup.html',
  '/password-reset.html',
  '/allowlist.html',
  '/suricata.html',
  '/rules.html',
  '/reports.html',
  '/insights.html',
  '/inspect.html',
  '/geo.html',
  '/events.html',
  '/style.css',
  '/auth.js',
  '/app.js',
  '/allowlist.js',
  '/suricata.js',
  '/rules.js',
  '/reports.html', // duplicated to dedupe; harmless
  '/insights.js',
  '/inspect.js',
  '/events.js',
  '/manifest.json',
  '/icon-192.png',
  '/icon-512.png',
  '/icon-maskable-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS).catch(() => {
      // partial pre-cache is OK — individual GETs will populate the cache
    }))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  // never cache API calls or websocket upgrades
  if (url.pathname.startsWith('/api/') || url.pathname === '/ws') {
    return;
  }

  // cache-first for everything else (static assets served by the daemon)
  event.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;
      return fetch(req).then((resp) => {
        if (resp.ok && resp.status === 200) {
          const copy = resp.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, copy)).catch(() => {});
        }
        return resp;
      }).catch(() => cached || new Response('offline', { status: 503 }));
    })
  );
});
