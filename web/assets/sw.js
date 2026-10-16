/* zeropaste service worker: caches the STATIC app shell only.
   Paste traffic (/api/*) always hits the network - meta reads, burn deletes
   and range downloads must never be served from a cache. Keys live in URL
   fragments anyway, so nothing sensitive transits this worker.
   Update SHELL below together with the ?v= query strings in index.html,
   then bump SHELL_VERSION so the old cache is pruned on activate. */
'use strict';

var SHELL_VERSION = 'v0.10.2';
var CACHE = 'zp-shell-' + SHELL_VERSION;
var SHELL = [
  '/',
  '/assets/style.css?v=0.10.2',
  '/assets/app.js?v=0.10.2',
  '/assets/atom-one-light.min.css?v=0.10.2',
  '/assets/atom-one-dark.min.css?v=0.10.2',
  '/assets/highlight.min.js',
  '/assets/qrcode.min.js',
  '/assets/manifest.webmanifest',
  '/assets/icon.svg',
  '/assets/icon-192.png',
  '/assets/icon-512.png',
  '/assets/icon-512-maskable.png',
  '/assets/apple-touch-icon.png',
  '/assets/icon-32.png',
  '/assets/og.png'
];

self.addEventListener('install', function (e) {
  e.waitUntil(
    caches.open(CACHE)
      // cache:"reload": assets carry max-age=86400, so a plain fetch would
      // replay the browser HTTP cache and precache stale bytes after a rebuild
      .then(function (c) { return c.addAll(SHELL.map(function (u) { return new Request(u, { cache: 'reload' }); })); })
      .then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function (e) {
  e.waitUntil(
    caches.keys()
      .then(function (keys) {
        return Promise.all(keys.filter(function (k) { return k !== CACHE; })
          .map(function (k) { return caches.delete(k); }));
      })
      .then(function () { return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function (e) {
  var req = e.request;
  if (req.method !== 'GET') return; // pastes, deletes, chunk PUTs: untouched
  var url = new URL(req.url);
  if (url.origin !== location.origin) return;
  if (url.pathname.indexOf('/api/') === 0) return; // server authority: never cached, never answered

  // navigations: network first; when offline, the cached shell renders any
  // view client-side (compose, read, dash) - actual pastes still need network
  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req).then(function (res) {
        if (res.ok) {
          var copy = res.clone();
          caches.open(CACHE).then(function (c) { return c.put('/', copy); });
        }
        return res;
      }).catch(function () { return caches.match('/'); })
    );
    return;
  }

  // static assets and icons: cache first, refreshed from the network in the
  // background so index.html's ?v= bump swaps stuff in without a hard reload;
  // cache:"reload" skips the HTTP cache (same rationale as the install)
  if (url.pathname.indexOf('/assets/') === 0) {
    e.respondWith(
      caches.match(req).then(function (hit) {
        var net = fetch(req, { cache: 'reload' }).then(function (res) {
          if (res.ok) {
            var copy = res.clone();
            caches.open(CACHE).then(function (c) { return c.put(req, copy); });
          }
          return res;
        });
        return hit || net;
      })
    );
  }
});
