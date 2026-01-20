const CACHE_NAME = 'winlab-pwa-v1';
const BASE_URL = new URL('../..', self.location);
const CORE_ASSETS = [
  new URL('index.html', BASE_URL).toString(),
  new URL('pricing.html', BASE_URL).toString(),
  new URL('mobile.html', BASE_URL).toString(),
  new URL('assets/styles.css', BASE_URL).toString(),
  new URL('assets/app.js', BASE_URL).toString(),
  new URL('assets/config.js', BASE_URL).toString(),
  new URL('docs/guia.html', BASE_URL).toString(),
  new URL('assets/pwa/manifest.webmanifest', BASE_URL).toString(),
  new URL('assets/pwa/icon.svg', BASE_URL).toString()
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(CORE_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  event.respondWith(
    caches.match(event.request).then((cached) =>
      cached || fetch(event.request).then((response) => {
        const copy = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        return response;
      })
    )
  );
});
