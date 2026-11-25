// 홈 화면 앱이 신호가 없어도 열리도록 페이지와 아이콘만 저장한다.
// /api/ 요청(로그인, 기록 전송, 관리자 화면)은 저장하지 않고 항상 서버로 보낸다.
// 버전은 run_pipeline.py가 페이지 내용으로 정하므로, 페이지가 바뀌면 옛 저장본이 지워진다.
const CACHE = "tumbler-98df736b2476";
const SHELL = ["/", "/manifest.webmanifest", "/apple-touch-icon.png", "/icon-192.png", "/icon-512.png"];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))
    .then(() => self.clients.claim()));
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== location.origin || url.pathname.startsWith("/api/")) return;
  if (request.mode === "navigate") {
    // 페이지는 늘 최신을 먼저 받고, 연결이 없을 때만 저장본을 연다.
    event.respondWith(fetch(request).then((response) => {
      if (response.ok && url.pathname === "/") {
        const copy = response.clone();
        caches.open(CACHE).then((cache) => cache.put("/", copy));
      }
      return response;
    }).catch(() => caches.match("/")));
    return;
  }
  event.respondWith(caches.match(request).then((hit) => hit || fetch(request)));
});
