const CACHE_VERSION = 'lurker-v1';
const STATIC_CACHE = `${CACHE_VERSION}-static`;
const DYNAMIC_CACHE = `${CACHE_VERSION}-dynamic`;
const OFFLINE_PAGE = '/offline';

// Static assets to cache on install
const STATIC_ASSETS = [
  '/',
  '/styles.css',
  '/offline',
  '/icon-192.png',
  '/icon-512.png'
];

// Install event - cache static assets
self.addEventListener('install', (event) => {
  console.log('[Service Worker] Installing...');

  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => {
        console.log('[Service Worker] Caching static assets');
        return cache.addAll(STATIC_ASSETS);
      })
      .then(() => self.skipWaiting()) // Activate immediately
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  console.log('[Service Worker] Activating...');

  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((cacheName) => {
              // Delete old versions of our caches
              return cacheName.startsWith('lurker-') && cacheName !== STATIC_CACHE && cacheName !== DYNAMIC_CACHE;
            })
            .map((cacheName) => {
              console.log('[Service Worker] Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            })
        );
      })
      .then(() => self.clients.claim()) // Take control immediately
  );
});

// Fetch event - implement caching strategies
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Skip Chrome extension requests
  if (url.protocol === 'chrome-extension:') {
    return;
  }

  // Different strategies for different resource types
  if (isStaticAsset(url)) {
    // Static assets: Cache first, fallback to network
    event.respondWith(cacheFirst(request));
  } else if (isAPIRequest(url)) {
    // API requests: Network only (always fresh data)
    event.respondWith(networkOnly(request));
  } else {
    // HTML pages: Network first, fallback to cache, then offline page
    event.respondWith(networkFirstWithOffline(request));
  }
});

// Helper: Check if request is for a static asset
function isStaticAsset(url) {
  const staticExtensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.svg', '.gif', '.woff', '.woff2'];
  return staticExtensions.some(ext => url.pathname.endsWith(ext)) || url.pathname.startsWith('/icon-');
}

// Helper: Check if request is an API call
function isAPIRequest(url) {
  return url.pathname.startsWith('/api/') ||
         url.pathname.startsWith('/subscribe') ||
         url.pathname.startsWith('/unsubscribe');
}

// Strategy 1: Cache first (for static assets)
async function cacheFirst(request) {
  const cache = await caches.open(STATIC_CACHE);
  const cached = await cache.match(request);

  if (cached) {
    return cached;
  }

  try {
    const response = await fetch(request);
    if (response.ok) {
      cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    console.error('[Service Worker] Cache first failed:', error);
    throw error;
  }
}

// Strategy 2: Network only (for API requests)
async function networkOnly(request) {
  return fetch(request);
}

// Strategy 3: Network first with offline fallback (for HTML pages)
async function networkFirstWithOffline(request) {
  try {
    const response = await fetch(request);

    // Cache successful responses
    if (response.ok) {
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put(request, response.clone());
    }

    return response;
  } catch (error) {
    console.log('[Service Worker] Network failed, trying cache');

    // Try to get from cache
    const cached = await caches.match(request);
    if (cached) {
      return cached;
    }

    // If all else fails, show offline page
    console.log('[Service Worker] Showing offline page');
    const offlineCache = await caches.match(OFFLINE_PAGE);
    if (offlineCache) {
      return offlineCache;
    }

    // Last resort: return a basic offline response
    return new Response(
      '<h1>Offline</h1><p>You are currently offline. Please check your internet connection.</p>',
      {
        status: 503,
        statusText: 'Service Unavailable',
        headers: new Headers({
          'Content-Type': 'text/html'
        })
      }
    );
  }
}

// Listen for messages from clients
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
