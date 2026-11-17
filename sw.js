const SHELL = 'shell-v27', DATA = 'data-v4';
const FILES = ['./', 'index.html', 'style.css', 'app.js', 'manifest.webmanifest', 'lib/xlsx.mini.min.js', 'lib/zxing.min.js', 'icons/icon-192.png', 'icons/icon-512.png', 'icons/bigmat-logo.png', 'fonts/montserrat-latin-600-normal.woff2', 'fonts/montserrat-latin-700-normal.woff2', 'fonts/montserrat-latin-800-normal.woff2', 'fonts/montserrat-latin-800-italic.woff2'];

self.addEventListener('install', e => {
  e.waitUntil(Promise.all([
    caches.open(SHELL).then(c => c.addAll(FILES)),
    caches.open(DATA).then(c => Promise.all(['data/ubicaciones-info.enc'].map(u => c.match(u).then(r => r || c.add(u)).catch(() => { }))))
  ]).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => ![SHELL, DATA].includes(k)).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET' || new URL(req.url).origin !== location.origin) return;
  if (req.url.includes('data/ubicaciones')) {   // archivo de ubicaciones: red primero (se actualiza)
    e.respondWith(fetch(req).then(res => { if (res.ok) { const cp = res.clone(); caches.open(DATA).then(c => c.put(req, cp)); } return res; }).catch(() => caches.match(req)));
    return;
  }
  if (req.url.includes('/data/') || req.url.includes('/ocr/')) {            // datos: caché primero
    e.respondWith(caches.match(req).then(r => r || fetch(req).then(res => { caches.open(DATA).then(c => c.put(req, res.clone())); return res; })));
    return;
  }
  e.respondWith(fetch(req).then(res => { const cp = res.clone(); caches.open(SHELL).then(c => c.put(req, cp)); return res; }).catch(() => caches.match(req)));
});
