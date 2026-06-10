// Qira Notify — service worker.
//
// Scope: /notify/ (set by file location; we do not request a broader
// Service-Worker-Allowed header). Controls the PWA page and handles
// Web Push messages from the relay.
//
// Push payload (from qev-relay):
//   { "t": "<topic>", "id": "<msg_id>", "ts": <unix_ms> }
//
// We deliberately do NOT attempt to decrypt the message body in the
// SW. The subscriber's phrase never gets persisted anywhere the SW
// can reach; it lives only in the page's localStorage and in user
// memory. The SW shows a generic notification, and tapping it opens
// /notify/?topic=<t> which auto-hydrates the inbox and decrypts.
//
// Versioning: bump `SW_VERSION` to force clients to upgrade.

const SW_VERSION = 'qira-notify-sw-v1';

// ---- Install / activate ----

self.addEventListener('install', (event) => {
  // Take over immediately on first install so users don't have to
  // close and re-open the app to get a working push handler.
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

// ---- Push handler ----
//
// Fires when the push service delivers a message. On Android this
// wakes the device even if the browser is fully closed.
self.addEventListener('push', (event) => {
  let topic = null;
  let msgId = null;
  let ts = null;

  if (event.data) {
    try {
      const payload = event.data.json();
      topic = payload.t || null;
      msgId = payload.id || null;
      ts = payload.ts || null;
    } catch (err) {
      // Not JSON — fall back to text / no data.
      try { topic = event.data.text(); } catch (_) {}
    }
  }

  const title = topic
    ? `\ud83d\udd10 New message on ${topic}`
    : '\ud83d\udd10 Encrypted message';
  const body = 'Tap to unlock and read with your phrase.';

  const options = {
    body,
    icon: '/notify/icon-192.png',
    badge: '/notify/icon-192.png',
    // tag: collapse multiple pushes for the same topic into one
    // notification so an active topic doesn't explode the tray.
    tag: topic ? `qira-notify:${topic}` : 'qira-notify:generic',
    renotify: true,
    requireInteraction: false,
    data: { topic, msgId, ts, sw_version: SW_VERSION },
    timestamp: typeof ts === 'number' ? ts : Date.now(),
  };

  event.waitUntil(self.registration.showNotification(title, options));
});

// ---- Notification click ----
//
// Focuses an existing /notify/ tab if one is open (and auto-loads
// the right topic via hash), otherwise opens a new tab.
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const data = event.notification.data || {};
  const target = data.topic
    ? `/notify/?topic=${encodeURIComponent(data.topic)}`
    : '/notify/';

  event.waitUntil((async () => {
    const all = await self.clients.matchAll({
      type: 'window',
      includeUncontrolled: true,
    });
    // Prefer a same-topic tab if any is open.
    for (const c of all) {
      try {
        const url = new URL(c.url);
        if (url.pathname.startsWith('/notify/')) {
          await c.focus();
          // Ask the page to jump to the right topic. Robust against
          // the page version being older than the SW (the page just
          // ignores unknown message shapes).
          c.postMessage({ type: 'qira-notify:open-topic', topic: data.topic });
          return;
        }
      } catch (_) {}
    }
    await self.clients.openWindow(target);
  })());
});

// ---- Error bookkeeping (optional, low-noise) ----

self.addEventListener('pushsubscriptionchange', (event) => {
  // The push service may rotate endpoints. We can't re-subscribe
  // automatically without user interaction for VAPID, but we can
  // log this for debugging. The page will pick up the new endpoint
  // next time the user opens the app.
  event.waitUntil(Promise.resolve());
});
