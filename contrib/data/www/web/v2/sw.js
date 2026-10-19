// Service worker of the TeddyCloud web app: keeps the app shell available so the installed app
// starts instantly. Only files of the app itself (below the scope of this worker) are cached;
// API calls, audio and images of teddyCloud always go to the server.
const CACHE = "tc-web2-v1";
const SCOPE = new URL(self.registration.scope).pathname;

self.addEventListener("install", (event) => {
    event.waitUntil(
        caches
            .open(CACHE)
            .then((cache) => cache.addAll([SCOPE + "index.html", SCOPE + "manifest.json"]))
            .then(() => self.skipWaiting()),
    );
});

self.addEventListener("activate", (event) => {
    event.waitUntil(
        caches
            .keys()
            .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
            .then(() => self.clients.claim()),
    );
});

self.addEventListener("fetch", (event) => {
    const request = event.request;
    if (request.method !== "GET") return;
    const url = new URL(request.url);
    if (url.origin !== self.location.origin || !url.pathname.startsWith(SCOPE)) return;

    // hashed build files never change: cache first
    if (url.pathname.startsWith(SCOPE + "assets/") || url.pathname.startsWith(SCOPE + "icons/")) {
        event.respondWith(
            caches.match(request).then(
                (hit) =>
                    hit ||
                    fetch(request).then((response) => {
                        if (response.ok) {
                            const copy = response.clone();
                            caches.open(CACHE).then((cache) => cache.put(request, copy));
                        }
                        return response;
                    }),
            ),
        );
        return;
    }

    // the page itself: network first, the cached copy when offline
    event.respondWith(
        fetch(request)
            .then((response) => {
                if (response.ok) {
                    const copy = response.clone();
                    caches.open(CACHE).then((cache) => cache.put(request, copy));
                }
                return response;
            })
            .catch(() =>
                caches.match(request).then((hit) => hit || caches.match(SCOPE + "index.html")),
            ),
    );
});
