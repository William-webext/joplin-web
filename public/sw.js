// Service worker con cache reale, non più un no-op che serviva solo a soddisfare i requisiti
// minimi di installabilità PWA senza fare nulla.
//
// Strategia:
// - Navigazione (apertura dell'app): network-first, con fallback alla shell in cache se offline —
//   così online si vede sempre l'ultima versione, offline si apre comunque qualcosa.
// - Asset statici (manifest, icone, librerie CDN marked/DOMPurify): stale-while-revalidate —
//   risposta immediata dalla cache, aggiornamento in background.
// - /api/data e /api/resource/*: stale-while-revalidate anche qui. Le note si modificano solo da
//   Joplin, mai da questa webapp, quindi cachare le letture non rischia di nascondere una scrittura
//   in sospeso — nel peggiore dei casi si vede un dato di qualche minuto/ora vecchio finché non
//   torna la rete. Questo è ciò che rende possibile riaprire l'app offline e vedere ancora le note
//   già lette in precedenza, non solo una shell vuota.
// - Tutto il resto (login, publish, preferences POST, admin) non viene mai intercettato: passa
//   sempre e solo dalla rete, niente cache su azioni che scrivono o autenticano.

const CACHE_VERSION = 'v1';
const SHELL_CACHE = `joplin-web-shell-${CACHE_VERSION}`;
const RUNTIME_CACHE = `joplin-web-runtime-${CACHE_VERSION}`;

const SHELL_URLS = [
  '/manifest.json',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/icon-512-maskable.png',
  'https://cdn.jsdelivr.net/npm/marked/marked.min.js',
  'https://cdn.jsdelivr.net/npm/dompurify@3/dist/purify.min.js'
];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(SHELL_CACHE)
      .then((cache) => cache.addAll(SHELL_URLS))
      .catch(() => {}) // se un asset CDN non è raggiungibile in fase di install, non bloccare l'attivazione
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(
        keys.filter((key) => key !== SHELL_CACHE && key !== RUNTIME_CACHE).map((key) => caches.delete(key))
      ))
      .then(() => self.clients.claim())
  );
});

function isCacheableApiGet(request, url) {
  if (request.method !== 'GET') return false;
  return url.pathname === '/api/data' || url.pathname.startsWith('/api/resource/');
}

function staleWhileRevalidate(request, cacheName) {
  return caches.open(cacheName).then((cache) =>
    cache.match(request).then((cached) => {
      const networkFetch = fetch(request)
        .then((res) => {
          if (res && res.ok) cache.put(request, res.clone());
          return res;
        })
        .catch(() => cached); // offline e nessuna risposta di rete: resta solo la cache, se c'è
      return cached || networkFetch;
    })
  );
}

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return; // mai intercettare scritture: login, publish, preferences restano sempre in rete diretta

  const url = new URL(req.url);

  // Richieste di navigazione (apertura/ricarica pagina): network-first così online si vede sempre
  // l'ultima versione dell'app, offline si ripiega sulla shell salvata in cache.
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((res) => {
          if (res && res.ok) caches.open(SHELL_CACHE).then((cache) => cache.put('/', res.clone()));
          return res;
        })
        .catch(() => caches.match('/').then((cached) => cached || caches.match('/index.html')))
    );
    return;
  }

  if (isCacheableApiGet(req, url)) {
    event.respondWith(staleWhileRevalidate(req, RUNTIME_CACHE));
    return;
  }

  if (url.origin === self.location.origin || SHELL_URLS.includes(req.url)) {
    event.respondWith(staleWhileRevalidate(req, SHELL_CACHE));
  }
});
