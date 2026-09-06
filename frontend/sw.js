
// PushKit PWA Service Worker - REAL IMPLEMENTATION
self.addEventListener('install', e=> self.skipWaiting());
self.addEventListener('activate', e=> e.waitUntil(clients.claim()));

self.addEventListener('push', (e)=>{
  let data = {title:'رفوف', body:'إشعار جديد من رفوف 📚', url:'/'};
  try{ if(e.data) data = {...data, ...e.data.json()}; }catch{}
  e.waitUntil(self.registration.showNotification(data.title, {
    body: data.body,
    icon: '/icon.png',
    badge: '/icon.png',
    data: {url: data.url || '/'},
    vibrate: [200,100,200]
  }));
});

self.addEventListener('notificationclick', (e)=>{
  e.notification.close();
  e.waitUntil(clients.openWindow(e.notification.data.url || '/'));
});

self.addEventListener('fetch', (e)=>{
  // basic cache for offline - lazy loading helper
  if(e.request.url.includes('/api/')) return;
  e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)));
});
