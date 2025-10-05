// Memory Manager - Hybrid in-memory cache + persistent storage
// CRITICAL FIX: Maintains synchronous Map() API for backward compatibility
// while persisting to chrome.storage.session for service worker restarts

export class MemoryManager {
  constructor() {
    this.REQUEST_TTL = 5 * 60 * 1000; // 5 minutes

    // P0-TENTH-3 FIX: Hard limits on in-memory requests
    this.MAX_IN_MEMORY_REQUESTS = 1000; // Hard cap
    this.MAX_REQUESTS_PER_ORIGIN = 50; // Per-origin limit

    // In-memory caches (fast synchronous access)
    this._authRequestsCache = new Map();
    this._debugTargetsCache = new Map();
    this._originRequestCount = new Map(); // P0-TENTH-3 FIX: Track per-origin counts

    // Track pending writes to avoid race conditions
    this._pendingWrites = new Set();

    // Initialization state
    this.initialized = false;
    this.initPromise = this.initialize();

    // Quota monitoring
    this.STORAGE_QUOTA_BYTES = 10 * 1024 * 1024; // 10MB limit for chrome.storage.local
    this.QUOTA_WARNING_THRESHOLD = 0.8; // 80%
  }

  // Initialize by loading from storage.session into in-memory cache
  async initialize() {
    if (this.initialized) return;

    try {
      // Load persisted data into cache
      // CRITICAL FIX P0-NEW: Use chrome.storage.local (survives browser restart)
      const data = await chrome.storage.local.get(['authRequests', 'debugTargets']);

      // Restore authRequests
      if (data.authRequests && typeof data.authRequests === 'object') {
        for (const [key, value] of Object.entries(data.authRequests)) {
          this._authRequestsCache.set(key, value);
        }
        console.log(`Hera: Restored ${this._authRequestsCache.size} auth requests from storage.session`);
      }

      // Restore debugTargets
      if (data.debugTargets && typeof data.debugTargets === 'object') {
        for (const [key, value] of Object.entries(data.debugTargets)) {
          this._debugTargetsCache.set(parseInt(key), value);
        }
        console.log(`Hera: Restored ${this._debugTargetsCache.size} debug targets from storage.session`);
      }

      this.initialized = true;
      console.log('Hera: Memory manager initialized with hybrid cache');
    } catch (error) {
      console.error('Hera: Failed to initialize memory manager:', error);
      // Continue with empty cache - not fatal
      this.initialized = true;
    }
  }

  // Background sync: Write cache to storage.session
  async _syncToStorage() {
    // Avoid concurrent writes
    if (this._pendingWrites.has('sync')) return;
    this._pendingWrites.add('sync');

    try {
      await this.initPromise; // Ensure initialized

      // Check quota before writing
      const estimatedSize = this._estimateStorageSize();
      if (estimatedSize > this.STORAGE_QUOTA_BYTES * this.QUOTA_WARNING_THRESHOLD) {
        console.warn(`Hera: Storage approaching quota (${(estimatedSize / 1024 / 1024).toFixed(2)}MB / 10MB)`);
        await this._performQuotaCleanup();
      }

      // Convert Maps to plain objects for storage
      const authRequestsObj = Object.fromEntries(this._authRequestsCache.entries());
      const debugTargetsObj = Object.fromEntries(this._debugTargetsCache.entries());

      // CRITICAL FIX P0-NEW: Use chrome.storage.local (survives browser restart)
      await chrome.storage.local.set({
        authRequests: authRequestsObj,
        debugTargets: debugTargetsObj
      });
    } catch (error) {
      if (error.message?.includes('QUOTA_BYTES')) {
        console.error('Hera: Storage quota exceeded, forcing cleanup');
        await this._performQuotaCleanup();
        // Retry after cleanup
        await this._syncToStorage();
      } else {
        console.error('Hera: Failed to sync to storage:', error);
      }
    } finally {
      this._pendingWrites.delete('sync');
    }
  }

  // Estimate storage size
  // P2-ARCH-1 FIX: Incremental size calculation to avoid memory spike
  _estimateStorageSize() {
    try {
      let totalSize = 0;

      // Estimate authRequests size incrementally (no full JSON.stringify)
      for (const [key, value] of this._authRequestsCache.entries()) {
        const keySize = key.length * 2; // UTF-16
        const valueSize = JSON.stringify(value).length * 2;
        totalSize += keySize + valueSize + 100; // 100 bytes overhead per entry
      }

      // Estimate debugTargets size incrementally
      for (const [key, value] of this._debugTargetsCache.entries()) {
        const keySize = String(key).length * 2; // UTF-16
        const valueSize = JSON.stringify(value).length * 2;
        totalSize += keySize + valueSize + 100; // 100 bytes overhead per entry
      }

      return totalSize;
    } catch (error) {
      console.error('Hera: Failed to estimate storage size:', error);
      return 0;
    }
  }

  // Quota cleanup: Remove oldest entries
  async _performQuotaCleanup() {
    console.log('Hera: Performing quota cleanup');

    // Get all auth requests with timestamps
    const requestsWithTime = Array.from(this._authRequestsCache.entries())
      .filter(([id, data]) => data && data.timestamp)
      .sort((a, b) => new Date(b[1].timestamp) - new Date(a[1].timestamp));

    // Keep only the most recent 50% if over quota
    if (requestsWithTime.length > 10) {
      const toKeep = Math.floor(requestsWithTime.length * 0.5);
      const toRemove = requestsWithTime.slice(toKeep);

      for (const [id] of toRemove) {
        this._authRequestsCache.delete(id);
      }

      console.log(`Hera: Cleaned up ${toRemove.length} old auth requests (kept ${toKeep})`);
    }

    // Force immediate sync
    await this._syncToStorage();
  }

  // === SYNCHRONOUS API (backward compatible with Map) ===

  get authRequests() {
    // Return actual Map for synchronous access
    return this._authRequestsCache;
  }

  get debugTargets() {
    // Return actual Map for synchronous access
    return this._debugTargetsCache;
  }

  // Sync writes trigger background persistence
  syncWrite() {
    // SECURITY FIX P3-NEW: Reduced debounce from 100ms to 1000ms
    // Reason: onSuspend handler removed (doesn't work in MV3)
    // More aggressive syncing compensates for lack of final sync

    // TODO P1-TENTH-6: 1-second debounce creates data loss window on service worker restart
    // If worker terminates before timeout fires, all pending writes are lost permanently
    // Should reduce to 100ms and add retry logic. See TENTH-REVIEW-FINDINGS.md:1739
    if (this._syncTimeout) clearTimeout(this._syncTimeout);
    this._syncTimeout = setTimeout(() => {
      this._syncToStorage().catch(err =>
        console.error('Hera: Background sync failed:', err)
      );
    }, 1000); // 1 second debounce
  }

  // === ASYNC API (recommended for new code) ===

  async addAuthRequest(requestId, requestData) {
    await this.initPromise;

    // P0-TENTH-3 FIX: Extract origin
    let origin;
    try {
      origin = new URL(requestData.url).origin;
    } catch (e) {
      console.error('Invalid URL in auth request:', requestData.url);
      return false; // Reject invalid
    }

    // P0-TENTH-3 FIX: Check total limit
    if (this._authRequestsCache.size >= this.MAX_IN_MEMORY_REQUESTS) {
      console.warn(`Hera SECURITY: In-memory request limit reached (${this._authRequestsCache.size}/${this.MAX_IN_MEMORY_REQUESTS})`);

      // Force immediate cleanup
      await this.cleanupStaleRequests();

      // If still over limit, remove oldest entry
      if (this._authRequestsCache.size >= this.MAX_IN_MEMORY_REQUESTS) {
        const oldestKey = this._authRequestsCache.keys().next().value;
        this._authRequestsCache.delete(oldestKey);
        console.log('Evicted oldest request to make room');
      }
    }

    // P0-TENTH-3 FIX: Check per-origin limit
    const originCount = this._originRequestCount.get(origin) || 0;
    if (originCount >= this.MAX_REQUESTS_PER_ORIGIN) {
      console.warn(`Hera SECURITY: Origin ${origin} exceeded request limit (${originCount}/${this.MAX_REQUESTS_PER_ORIGIN})`);

      // Remove oldest request from this origin
      for (const [id, data] of this._authRequestsCache.entries()) {
        try {
          if (new URL(data.url).origin === origin) {
            this._authRequestsCache.delete(id);
            this._originRequestCount.set(origin, originCount - 1);
            console.log(`Evicted oldest request from ${origin}`);
            break;
          }
        } catch (e) {
          // Skip invalid entries
        }
      }
    }

    // Add to cache
    this._authRequestsCache.set(requestId, requestData);
    this._originRequestCount.set(origin, (this._originRequestCount.get(origin) || 0) + 1);

    this.syncWrite(); // Background sync
    return true;
  }

  async getAuthRequest(requestId) {
    await this.initPromise;
    return this._authRequestsCache.get(requestId);
  }

  async deleteAuthRequest(requestId) {
    await this.initPromise;

    // P0-TENTH-3 FIX: Update origin count when deleting
    const requestData = this._authRequestsCache.get(requestId);
    if (requestData) {
      try {
        const origin = new URL(requestData.url).origin;
        const count = this._originRequestCount.get(origin) || 0;
        if (count > 0) {
          this._originRequestCount.set(origin, count - 1);
        }
      } catch (e) {
        // Ignore invalid URLs
      }
    }

    const existed = this._authRequestsCache.delete(requestId);
    this.syncWrite(); // Background sync
    return existed;
  }

  async getAllAuthRequests() {
    await this.initPromise;
    return Array.from(this._authRequestsCache.values());
  }

  async clearAuthRequests() {
    await this.initPromise;
    this._authRequestsCache.clear();
    await this._syncToStorage(); // Immediate sync for clears
  }

  async addDebugTarget(tabId, debuggee) {
    await this.initPromise;
    this._debugTargetsCache.set(tabId, debuggee);
    this.syncWrite(); // Background sync
  }

  async getDebugTarget(tabId) {
    await this.initPromise;
    return this._debugTargetsCache.get(tabId);
  }

  async hasDebugTarget(tabId) {
    await this.initPromise;
    return this._debugTargetsCache.has(tabId);
  }

  async deleteDebugTarget(tabId) {
    await this.initPromise;
    const existed = this._debugTargetsCache.delete(tabId);
    this.syncWrite(); // Background sync
    return existed;
  }

  async clearDebugTargets() {
    await this.initPromise;
    this._debugTargetsCache.clear();
    await this._syncToStorage(); // Immediate sync for clears
  }

  // Cleanup stale requests (TTL-based)
  async cleanupStaleRequests() {
    await this.initPromise;
    const now = Date.now();
    let cleaned = 0;

    // Cleanup auth requests
    for (const [requestId, requestData] of this._authRequestsCache.entries()) {
      if (requestData && requestData.timestamp) {
        const age = now - new Date(requestData.timestamp).getTime();
        if (age > this.REQUEST_TTL) {
          this._authRequestsCache.delete(requestId);
          cleaned++;
        }
      }
    }

    if (cleaned > 0) {
      console.log(`Hera: Cleaned up ${cleaned} stale auth requests`);
    }

    // Cleanup debugTargets for closed tabs
    const tabs = await chrome.tabs.query({});
    const activeTabIds = new Set(tabs.map(t => t.id));
    let debugCleaned = 0;

    for (const tabId of this._debugTargetsCache.keys()) {
      if (!activeTabIds.has(tabId)) {
        this._debugTargetsCache.delete(tabId);
        debugCleaned++;
      }
    }

    if (debugCleaned > 0) {
      console.log(`Hera: Cleaned up ${debugCleaned} stale debugger targets`);
    }

    // Sync after cleanup
    if (cleaned > 0 || debugCleaned > 0) {
      await this._syncToStorage();
    }

    // Log stats
    console.log(`Hera: Active requests: ${this._authRequestsCache.size}, Debug targets: ${this._debugTargetsCache.size}`);
  }

  // Get memory statistics
  async getStats() {
    await this.initPromise;
    const estimatedSize = this._estimateStorageSize();

    return {
      authRequests: this._authRequestsCache.size,
      debugTargets: this._debugTargetsCache.size,
      totalMemoryItems: this._authRequestsCache.size + this._debugTargetsCache.size,
      estimatedStorageBytes: estimatedSize,
      quotaUsagePercent: (estimatedSize / this.STORAGE_QUOTA_BYTES) * 100
    };
  }
}

// Export singleton instance
export const memoryManager = new MemoryManager();
