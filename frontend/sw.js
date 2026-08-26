const CACHE = 'simtrace-analyser-v32';

const PRECACHE = [
    'index.html',
    'manifest.json',
    'icon-192.png',
    'icon-512.png',
    'favicon.png',
    'sim-analyser.svg',
    'sim-analyser-light.svg',
];

self.addEventListener('install', e => {
    self.skipWaiting();
    e.waitUntil(
        caches.open(CACHE)
            .then(cache => cache.addAll(PRECACHE))
            .then(() => console.log('SW: precache done'))
            .catch(err => console.error('SW: precache failed', err))
    );
});

self.addEventListener('activate', e => {
    e.waitUntil(
        caches.keys()
            .then(keys => Promise.all(
                keys.filter(k => k !== CACHE).map(k => caches.delete(k))
            ))
            .then(() => self.clients.claim())
            .then(() => console.log('SW: activated, controlling clients'))
    );
});

self.addEventListener('fetch', e => {
    // Network-first: the local server is always up, so always serve fresh
    // content and fall back to cache only when offline.
    if (!e.request.url.startsWith('http')) return;
    if (e.request.method !== 'GET') return;
    e.respondWith(
        fetch(e.request)
            .then(r => {
                const clone = r.clone();
                caches.open(CACHE).then(c => c.put(e.request, clone)).catch(() => {});
                return r;
            })
            .catch(() => caches.match(e.request))
    );
});
