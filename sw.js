const CACHE_NAME = 'cskh-tram-cache-v9-search';

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(keys.filter(k => k.startsWith('cskh-tram-cache')).map((k) => caches.delete(k)));
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  // Never cache/fallback private JSON or auth responses, including old offline data.
  event.respondWith(fetch(event.request, {cache: 'no-store'}));
});
