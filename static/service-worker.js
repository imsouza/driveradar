'use strict';

self.addEventListener('push', (event) => {
  let payload = {};
  try { payload = event.data ? event.data.json() : {}; } catch (_) { payload = {}; }
  event.waitUntil(self.registration.showNotification(payload.title || 'DriveRadar', {
    body: payload.body || 'Novo alerta de atualização disponível.',
    icon: '/driveradar/static/logo.png',
    badge: '/driveradar/static/favicon-16.png',
    tag: payload.tag || 'driveradar-alert',
    data: { url: payload.url || '/driveradar/' }
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const target = event.notification.data?.url || '/driveradar/';
  event.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windows) => {
    const existing = windows.find((client) => client.url.startsWith(self.location.origin));
    if (existing) {
      existing.navigate(target);
      return existing.focus();
    }
    return clients.openWindow(target);
  }));
});
