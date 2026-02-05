// Service Worker for DashGate PWA
const CACHE_VERSION = 'v7';
const STATIC_CACHE = `dashgate-static-${CACHE_VERSION}`;
const DYNAMIC_CACHE = `dashgate-dynamic-${CACHE_VERSION}`;
const OFFLINE_URL = '/offline.html';

// Static assets to cache on install
// Note: Do NOT include '/' here — it's an authenticated, user-specific page.
// The networkFirstWithOffline strategy caches it on successful navigation instead.
const STATIC_ASSETS = [
  '/manifest.json',
  '/offline.html'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => cache.addAll(STATIC_ASSETS))
      .then(() => self.skipWaiting())
  );
});

// Activate event - clean up ALL old caches (including any from prior branding)
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== STATIC_CACHE && name !== DYNAMIC_CACHE)
          .map((name) => caches.delete(name))
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch event - smart caching strategy
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Skip cross-origin requests
  if (url.origin !== location.origin) {
    return;
  }

  // API requests - network first, cache fallback
  if (url.pathname.startsWith('/api/')) {
    // Don't cache sensitive API endpoints
    const sensitivePatterns = ['/api/auth/', '/api/admin/', '/api/user/'];
    const isSensitive = sensitivePatterns.some(p => url.pathname.startsWith(p));
    if (isSensitive) {
      event.respondWith(fetch(request).catch(() => {
        return new Response(JSON.stringify({ error: 'Offline' }), {
          status: 503,
          headers: { 'Content-Type': 'application/json' }
        });
      }));
      return;
    }
    event.respondWith(networkFirst(request));
    return;
  }

  // Icons - stale while revalidate (user-customizable, may change at same URL)
  if (url.pathname.startsWith('/static/icons/')) {
    event.respondWith(staleWhileRevalidate(request));
    return;
  }

  // Static assets - cache first, network fallback
  if (url.pathname.startsWith('/static/')) {
    event.respondWith(cacheFirst(request));
    return;
  }

  // HTML pages - network first with offline fallback
  if (request.headers.get('accept')?.includes('text/html')) {
    event.respondWith(networkFirstWithOffline(request));
    return;
  }

  // Default - stale while revalidate
  event.respondWith(staleWhileRevalidate(request));
});

// Cache first strategy (for static assets)
async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) {
    return cached;
  }

  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    return new Response('Offline', { status: 503 });
  }
}

// Network first strategy (for API)
async function networkFirst(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    const cached = await caches.match(request);
    if (cached) {
      return cached;
    }
    return new Response(JSON.stringify({ error: 'Offline' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// Network first with offline fallback (for HTML pages)
async function networkFirstWithOffline(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(STATIC_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    const cached = await caches.match(request);
    if (cached) {
      return cached;
    }
    return caches.match(OFFLINE_URL);
  }
}

// Stale while revalidate
async function staleWhileRevalidate(request) {
  const cached = await caches.match(request);

  const fetchPromise = fetch(request).then((response) => {
    if (response.ok) {
      caches.open(DYNAMIC_CACHE).then((cache) => {
        cache.put(request, response.clone());
      });
    }
    return response;
  }).catch(() => cached);

  return cached || fetchPromise;
}

// Clear all caches on logout
self.addEventListener('message', (event) => {
    if (event.data && event.data.type === 'CLEAR_CACHES') {
        event.waitUntil(
            caches.keys().then(names => Promise.all(names.map(name => caches.delete(name))))
        );
    }
});

// Background sync for offline actions
self.addEventListener('sync', (event) => {
  if (event.tag === 'sync-preferences') {
    event.waitUntil(syncPreferences());
  }
});

async function syncPreferences() {
  // Handle offline preference sync when back online
  const cache = await caches.open(DYNAMIC_CACHE);
  // Implementation for syncing pending changes
}

// Push notifications (if enabled in future)
self.addEventListener('push', (event) => {
  if (!event.data) return;

  const data = event.data.json();
  event.waitUntil(
    self.registration.showNotification(data.title || 'DashGate', {
      body: data.body,
      icon: '/static/branding/dashgate-192.png',
      badge: '/static/branding/dashgate-192.png'
    })
  );
});
