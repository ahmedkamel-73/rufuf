// رفوف PWA - نسخة نهائية بسيطة بتشتغل 100%
const CACHE = 'rufuf-v12-final';

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(['/', '/manifest.json'])).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  if (e.request.url.includes('/api/') || e.request.url.includes('/cdn/')) return;
  e.respondWith(
    fetch(e.request).catch(() => caches.match(e.request).then((m) => m || caches.match('/')))
  );
});
