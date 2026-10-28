/* Service worker: app shell precached per version; data files (data.json, atlas.bin, charts) cache-first in
   'rb-data' (URLs carry a content hash, so a new version never collides); files.json network-first. */
const VERSION = '20261028-0903';
const SHELL = ["index.html", "app.css", "app.js", "manifest.webmanifest", "icon-180.png", "icon-192.png", "icon-512.png"];
const SHELL_CACHE = 'rb-shell-' + VERSION;
const DATA_CACHE = 'rb-data';

self.addEventListener('install', ev => {
  ev.waitUntil(caches.open(SHELL_CACHE).then(c => c.addAll(SHELL.map(p => new Request(p, { cache: 'reload' })))));
  self.skipWaiting();
});

self.addEventListener('activate', ev => {
  ev.waitUntil((async () => {
    for (const k of await caches.keys()) if (k.startsWith('rb-shell-') && k !== SHELL_CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', ev => {
  const req = ev.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;            // weather APIs etc.: straight to network
  const scope = new URL(self.registration.scope);
  const rel = url.pathname.startsWith(scope.pathname) ? url.pathname.slice(scope.pathname.length) : url.pathname;

  if (rel === 'files.json') {                                  // network first, fallback to last copy
    ev.respondWith((async () => {
      const c = await caches.open(DATA_CACHE);
      try {
        const r = await fetch(req);
        if (r.ok) await c.put('files.json', r.clone());
        return r;
      } catch (e) {
        return (await c.match('files.json')) || (await caches.match('files.json')) || new Response('{}', { status: 503 });
      }
    })());
    return;
  }
  if (rel === '' || SHELL.includes(rel)) {                     // app shell: cache first
    ev.respondWith((async () => (await caches.match(rel === '' ? 'index.html' : rel, { ignoreSearch: true })) || fetch(req))());
    return;
  }
  ev.respondWith((async () => {                                // data + charts: cache first, then network and store
    const c = await caches.open(DATA_CACHE);
    const hit = await c.match(req);
    if (hit) return hit;
    const r = await fetch(req);
    if (r.ok) await c.put(req, r.clone());
    return r;
  })());
});
