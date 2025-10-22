// // IP Cache Module - CRITICAL FIX P1
// // Persistent DNS/IP cache to prevent redundant API calls and quota issues

// export class IPCacheManager {
//   constructor() {
//     this._ipCache = new Map();
//     this._ipRequestQueue = new Set();
//     this.initialized = false;
//     this.initPromise = this.initialize();
//     this.CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours
//     this.MAX_CACHE_SIZE = 1000; // P2-ARCH-2 FIX: Maximum cached IPs
//   }

//   async initialize() {
//     if (this.initialized) return;

//     try {
//       // CRITICAL FIX P0-NEW: Use chrome.storage.local (survives browser restart)
//       const data = await chrome.storage.local.get(['heraIPCache', 'heraIPRequestQueue']);

//       if (data.heraIPCache) {
//         for (const [ip, cacheEntry] of Object.entries(data.heraIPCache)) {
//           // Check if cache entry is still valid
//           if (Date.now() - cacheEntry.timestamp < this.CACHE_TTL) {
//             this._ipCache.set(ip, cacheEntry);
//           }
//         }
//         console.log(`Hera: Restored ${this._ipCache.size} IP cache entries`);
//       }

//       if (data.heraIPRequestQueue) {
//         this._ipRequestQueue = new Set(data.heraIPRequestQueue);
//       }

//       this.initialized = true;
//     } catch (error) {
//       console.error('Hera: Failed to initialize IP cache:', error);
//       this.initialized = true;
//     }
//   }

//   async _syncToStorage() {
//     try {
//       await this.initPromise;

//       const cacheObj = Object.fromEntries(this._ipCache.entries());
//       const queueArr = Array.from(this._ipRequestQueue);

//       // CRITICAL FIX P0-NEW: Use chrome.storage.local (survives browser restart)
//       await chrome.storage.local.set({
//         heraIPCache: cacheObj,
//         heraIPRequestQueue: queueArr
//       });
//     } catch (error) {
//       console.error('Hera: Failed to sync IP cache:', error);
//     }
//   }

//   _debouncedSync() {
//     if (this._syncTimeout) clearTimeout(this._syncTimeout);
//     this._syncTimeout = setTimeout(() => {
//       this._syncToStorage().catch(err => console.error('IP cache sync failed:', err));
//     }, 500); // Longer debounce for IP cache
//   }

//   // Getters for backward compatibility
//   get ipCache() {
//     return this._ipCache;
//   }

//   get ipRequestQueue() {
//     return this._ipRequestQueue;
//   }

//   // Methods to trigger sync after modifications
//   setCacheEntry(ip, data) {
//     // P2-ARCH-2 FIX: Enforce max cache size (LRU eviction)
//     if (this._ipCache.size >= this.MAX_CACHE_SIZE && !this._ipCache.has(ip)) {
//       // Find oldest entry to evict
//       let oldestIP = null;
//       let oldestTime = Infinity;

//       for (const [cachedIP, entry] of this._ipCache.entries()) {
//         if (entry.timestamp < oldestTime) {
//           oldestTime = entry.timestamp;
//           oldestIP = cachedIP;
//         }
//       }

//       if (oldestIP) {
//         this._ipCache.delete(oldestIP);
//         console.log(`Hera: IP cache full, evicted oldest entry: ${oldestIP}`);
//       }
//     }

//     this._ipCache.set(ip, {
//       ...data,
//       timestamp: Date.now()
//     });
//     this._debouncedSync();
//   }

//   addToQueue(ip) {
//     this._ipRequestQueue.add(ip);
//     this._debouncedSync();
//   }

//   removeFromQueue(ip) {
//     this._ipRequestQueue.delete(ip);
//     this._debouncedSync();
//   }

//   async cleanup() {
//     await this.initPromise;
//     const now = Date.now();
//     let cleaned = 0;

//     for (const [ip, cacheEntry] of this._ipCache.entries()) {
//       if (now - cacheEntry.timestamp > this.CACHE_TTL) {
//         this._ipCache.delete(ip);
//         cleaned++;
//       }
//     }

//     if (cleaned > 0) {
//       console.log(`Hera: Cleaned ${cleaned} expired IP cache entries`);
//       await this._syncToStorage();
//     }
//   }
// }

// // Export singleton
// export const ipCacheManager = new IPCacheManager();
