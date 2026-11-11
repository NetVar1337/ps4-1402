/* service worker — cache-first, full offline after first visit */
const CACHE = "akatsuki-v7";
const ASSETS = [
  "./",
  "./index.html",
  "./go.html",
  "./go-s.html",
  "./launch.html",
  "./style.css",
  "./afterglow-g.js",
  "./jb-g.js",
  "./launch.js",
  "./core.js",
  "./int64.js",
  "./mem.js",
  "./matrix.js",
  "./ps4_offsets.js",
  "./sp_hx_krw.js",
  "./sp_hx_tables.js",
  "./goldhen.bin",
  "./patchset.bin",
  "./hen.bin",
  "./payload.bin",
  "./kpayload.bin",
  "./keys.json",
  "./logo.png",
  "./akatsuki.mp3",
  "./probe-wk1.html",
];
self.addEventListener("install", function (e) {
  e.waitUntil(
    caches.open(CACHE).then(function (cache) {
      return cache.addAll(ASSETS);
    })
  );
  self.skipWaiting();
});

self.addEventListener("activate", function (e) {
  e.waitUntil(
    caches.keys().then(function (names) {
      return Promise.all(
        names
          .filter(function (n) { return n !== CACHE; })
          .map(function (n) { return caches.delete(n); })
      );
    })
  );
  self.clients.claim();
});

self.addEventListener("fetch", function (e) {
  e.respondWith(
    caches.match(e.request).then(function (cached) {
      return cached || fetch(e.request).then(function (resp) {
        if (resp.ok) {
          var copy = resp.clone();
          caches.open(CACHE).then(function (c) { c.put(e.request, copy); });
        }
        return resp;
      });
    })
  );
});