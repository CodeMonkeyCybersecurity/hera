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
    this.STORAGE_QUOTA_BYTES = 10 * 1024 * 1024; // 10MB limit for chrome.storage.local (CANNOT BE INCREASED)
    this.QUOTA_WARNING_THRESHOLD = 0.8; // 80%
    this.MAX_REQUESTS_TO_KEEP = 20; // Aggressively limit stored requests
    this.MAX_REQUEST_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours
  }

  // Initialize by loading from storage.session into in-memory cache
  async initialize() {
    if (this.initialized) return;

    try {
      // Check quota BEFORE loading
      const bytesInUse = await chrome.storage.local.getBytesInUse();
      const quota = chrome.storage.local.QUOTA_BYTES || 10485760;
      const usagePercent = bytesInUse / quota;

      console.log(`Hera: Storage quota at ${(usagePercent * 100).toFixed(1)}% (${(bytesInUse / 1024 / 1024).toFixed(2)} MB / ${(quota / 1024 / 1024).toFixed(0)} MB)`);

      // If over 70%, do aggressive cleanup BEFORE loading
      if (usagePercent > 0.7) {
        console.warn('Hera: Storage over 70% - performing emergency cleanup BEFORE initialization');
        await this._emergencyStorageCleanup();
      }

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

      // Perform cleanup on loaded data if needed
      if (this._authRequestsCache.size > this.MAX_REQUESTS_TO_KEEP) {
        console.warn(`Hera: Loaded ${this._authRequestsCache.size} requests, cleaning up to ${this.MAX_REQUESTS_TO_KEEP}`);
        await this._performQuotaCleanup();
        // Save cleaned data immediately
        await this._immediateSyncToStorage();
      }

      this.initialized = true;
      console.log('Hera: Memory manager initialized with hybrid cache');
    } catch (error) {
      console.error('Hera: Failed to initialize memory manager:', error);
      // Continue with empty cache - not fatal
      this.initialized = true;
    }
  }

  // Emergency cleanup - works directly on storage without loading into memory
  async _emergencyStorageCleanup() {
    try {
      console.log('Hera: Emergency storage cleanup starting...');

      // Get current quota usage
      const initialBytes = await chrome.storage.local.getBytesInUse();
      const quota = chrome.storage.local.QUOTA_BYTES || 10485760;
      console.log(`Hera: Initial storage: ${(initialBytes / 1024 / 1024).toFixed(2)} MB (${(initialBytes / quota * 100).toFixed(1)}%)`);

      // Get all keys and their data
      const allKeys = await chrome.storage.local.get(null);
      const keys = Object.keys(allKeys);

      console.log(`Hera: Found ${keys.length} storage keys`);

      // Calculate size of each key for reporting
      const keySizes = [];
      for (const key of keys) {
        const size = JSON.stringify(allKeys[key]).length;
        keySizes.push({ key, size, sizeMB: (size / 1024 / 1024).toFixed(2) });
      }
      keySizes.sort((a, b) => b.size - a.size);

      // Log top 5 largest keys
      console.log('Hera: Top 5 largest storage keys:');
      keySizes.slice(0, 5).forEach((item, i) => {
        console.log(`  ${i + 1}. ${item.key}: ${item.sizeMB} MB`);
      });

      // Remove large/old data
      const toRemove = [];
      let savedBytes = 0;

      // 1. CLEAR EVIDENCE DATA (usually the largest - can be multiple MB)
      if (allKeys.heraEvidence) {
        const evidenceSize = JSON.stringify(allKeys.heraEvidence).length;
        const evidence = allKeys.heraEvidence;
        const responseCount = evidence.responseCache ? Object.keys(evidence.responseCache).length : 0;
        const timelineCount = evidence.timeline ? evidence.timeline.length : 0;

        console.log(`Hera: Found heraEvidence: ${responseCount} responses, ${timelineCount} timeline events (${(evidenceSize / 1024 / 1024).toFixed(2)} MB)`);

        // Only keep last 10 responses and 50 timeline events
        const cleanedEvidence = {
          responseCache: {},
          flowCorrelation: {},
          proofOfConcepts: [],
          timeline: evidence.timeline ? evidence.timeline.slice(-50) : [],
          activeFlows: {}
        };

        // Keep only most recent 10 responses
        if (evidence.responseCache) {
          const responses = Object.entries(evidence.responseCache)
            .sort((a, b) => (b[1].timestamp || 0) - (a[1].timestamp || 0))
            .slice(0, 10);
          cleanedEvidence.responseCache = Object.fromEntries(responses);
        }

        await chrome.storage.local.set({ heraEvidence: cleanedEvidence });
        savedBytes += evidenceSize - JSON.stringify(cleanedEvidence).length;
        console.log(`Hera: Cleaned heraEvidence - kept 10 responses, 50 timeline events (saved ${(savedBytes / 1024 / 1024).toFixed(2)} MB)`);
      }

      // 2. Remove old heraSessions (keep only most recent 5)
      if (allKeys.heraSessions && Array.isArray(allKeys.heraSessions)) {
        const originalSize = JSON.stringify(allKeys.heraSessions).length;
        const sessions = allKeys.heraSessions
          .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
          .slice(0, 5); // Keep only 5 most recent (down from 10)

        await chrome.storage.local.set({ heraSessions: sessions });
        const newSize = JSON.stringify(sessions).length;
        savedBytes += originalSize - newSize;
        console.log(`Hera: Reduced heraSessions from ${allKeys.heraSessions.length} to ${sessions.length} (saved ${((originalSize - newSize) / 1024).toFixed(0)} KB)`);
      }

      // 3. Remove old evidence_* prefixed keys (if any exist)
      for (const key of keys) {
        if (key.startsWith('evidence_') || key.startsWith('heraEvidence_')) {
          const size = JSON.stringify(allKeys[key]).length;
          toRemove.push(key);
          savedBytes += size;
        }
      }

      // 4. Remove old analysis data (keep only most recent)
      const analysisKeys = keys.filter(k => k.startsWith('heraSiteAnalysis'));
      if (analysisKeys.length > 1) {
        for (let i = 1; i < analysisKeys.length; i++) {
          const size = JSON.stringify(allKeys[analysisKeys[i]]).length;
          toRemove.push(analysisKeys[i]);
          savedBytes += size;
        }
      }

      // 5. Clear authRequests and debugTargets from memory manager (will be rebuilt)
      if (allKeys.authRequests) {
        const size = JSON.stringify(allKeys.authRequests).length;
        toRemove.push('authRequests');
        savedBytes += size;
        console.log(`Hera: Clearing authRequests (${(size / 1024).toFixed(0)} KB)`);
      }

      if (allKeys.debugTargets) {
        const size = JSON.stringify(allKeys.debugTargets).length;
        toRemove.push('debugTargets');
        savedBytes += size;
      }

      // 6. Remove any other large keys (>1MB)
      for (const { key, size } of keySizes) {
        if (size > 1048576 && !toRemove.includes(key) && key !== 'heraEvidence' && key !== 'heraSessions') {
          console.log(`Hera: Removing large key: ${key} (${(size / 1024 / 1024).toFixed(2)} MB)`);
          toRemove.push(key);
          savedBytes += size;
        }
      }

      // Execute removals
      if (toRemove.length > 0) {
        await chrome.storage.local.remove(toRemove);
        console.log(`Hera: Removed ${toRemove.length} storage keys`);
      }

      // Check final quota
      const finalBytes = await chrome.storage.local.getBytesInUse();
      const savedMB = (savedBytes / 1024 / 1024).toFixed(2);
      const finalMB = (finalBytes / 1024 / 1024).toFixed(2);
      const finalPercent = (finalBytes / quota * 100).toFixed(1);

      console.log(`Hera: Emergency cleanup complete:`);
      console.log(`  - Removed: ${toRemove.length} keys`);
      console.log(`  - Saved: ${savedMB} MB`);
      console.log(`  - Final storage: ${finalMB} MB (${finalPercent}%)`);

      // If still over 80%, log warning
      if (finalBytes / quota > 0.8) {
        console.warn('Hera: Storage still over 80% after emergency cleanup!');
        console.warn('Hera: Consider migrating to IndexedDB for unlimited storage');
      }

    } catch (error) {
      console.error('Hera: Emergency cleanup failed:', error);
      console.error('Stack trace:', error.stack);
    }
  }

  // Immediate sync without debounce (for emergency situations)
  async _immediateSyncToStorage() {
    try {
      const authRequestsObj = Object.fromEntries(this._authRequestsCache.entries());
      const debugTargetsObj = Object.fromEntries(this._debugTargetsCache.entries());

      await chrome.storage.local.set({
        authRequests: authRequestsObj,
        debugTargets: debugTargetsObj
      });

      console.log('Hera: Immediate sync completed');
    } catch (error) {
      console.error('Hera: Immediate sync failed:', error);
    }
  }

  // Background sync: Write cache to storage.session
  async _syncToStorage() {
    // Avoid concurrent writes
    if (this._pendingWrites.has('sync')) return;
    this._pendingWrites.add('sync');

    // P0-SIXTEENTH-2 FIX: Circuit breaker - stop syncing after 3 consecutive failures
    if (!this._syncFailureCount) this._syncFailureCount = 0;
    if (this._syncFailureCount >= 3) {
      console.error('Hera: Sync circuit breaker OPEN - too many failures, stopping writes');
      this._pendingWrites.delete('sync');
      return;
    }

    try {
      await this.initPromise; // Ensure initialized

      // P0-SIXTEENTH-2 FIX: Check ACTUAL quota before writing (not just estimated)
      const bytesInUse = await chrome.storage.local.getBytesInUse();
      const quota = chrome.storage.local.QUOTA_BYTES || 10485760; // 10MB
      const usagePercent = bytesInUse / quota;

      if (usagePercent > this.QUOTA_WARNING_THRESHOLD) {
        console.warn(`Hera: Storage at ${(usagePercent * 100).toFixed(1)}% - forcing cleanup BEFORE write`);
        await this._performQuotaCleanup();
      }

      // P0-SIXTEENTH-2 FIX: If still over 95%, refuse to write
      const bytesAfterCleanup = await chrome.storage.local.getBytesInUse();
      if (bytesAfterCleanup / quota > 0.95) {
        console.error('Hera: Storage quota critical (>95%), skipping sync to prevent quota exhaustion');
        this._syncFailureCount++;
        this._pendingWrites.delete('sync');
        return;
      }

      // Convert Maps to plain objects for storage
      const authRequestsObj = Object.fromEntries(this._authRequestsCache.entries());
      const debugTargetsObj = Object.fromEntries(this._debugTargetsCache.entries());

      // CRITICAL FIX P0-NEW: Use chrome.storage.local (survives browser restart)
      await chrome.storage.local.set({
        authRequests: authRequestsObj,
        debugTargets: debugTargetsObj
      });

      // P0-SIXTEENTH-2 FIX: Reset failure count on success
      this._syncFailureCount = 0;
    } catch (error) {
      if (error.message?.includes('QUOTA_BYTES')) {
        console.error('Hera: Storage quota exceeded, forcing aggressive cleanup');
        this._syncFailureCount++;
        
        // P0-SEVENTEENTH-3 FIX: Emergency cleanup - clear in-memory cache too
        if (this._syncFailureCount >= 3) {
          console.error('Hera: Circuit breaker OPEN - clearing in-memory cache to prevent OOM');
          const cacheSize = this._authRequestsCache.size;
          this._authRequestsCache.clear();
          this._debugTargetsCache.clear();
          this._originRequestCount.clear();
          console.error(`Hera: Cleared ${cacheSize} in-memory requests (circuit breaker emergency)`);
        } else {
          await this._performQuotaCleanup();
        }
        // P0-SIXTEENTH-2 FIX: Do NOT retry immediately - causes infinite loop
        // Next syncWrite() will attempt again
      } else {
        console.error('Hera: Failed to sync to storage:', error);
        this._syncFailureCount++;
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

    const now = Date.now();

    // Get all auth requests with timestamps
    const requestsWithTime = Array.from(this._authRequestsCache.entries())
      .filter(([id, data]) => data && data.timestamp)
      .sort((a, b) => new Date(b[1].timestamp) - new Date(a[1].timestamp));

    console.log(`Hera: Cleanup starting with ${requestsWithTime.length} requests`);

    // AGGRESSIVE CLEANUP STRATEGY:
    // 1. Remove requests older than 24 hours
    const oldRequests = requestsWithTime.filter(([id, data]) => {
      const age = now - new Date(data.timestamp).getTime();
      return age > this.MAX_REQUEST_AGE_MS;
    });

    for (const [id] of oldRequests) {
      this._authRequestsCache.delete(id);
    }

    if (oldRequests.length > 0) {
      console.log(`Hera: Removed ${oldRequests.length} requests older than 24 hours`);
    }

    // 2. Keep only the most recent MAX_REQUESTS_TO_KEEP
    const remaining = Array.from(this._authRequestsCache.entries())
      .filter(([id, data]) => data && data.timestamp)
      .sort((a, b) => new Date(b[1].timestamp) - new Date(a[1].timestamp));

    if (remaining.length > this.MAX_REQUESTS_TO_KEEP) {
      const toRemove = remaining.slice(this.MAX_REQUESTS_TO_KEEP);

      for (const [id] of toRemove) {
        this._authRequestsCache.delete(id);
      }

      console.log(`Hera: Removed ${toRemove.length} excess requests (keeping only ${this.MAX_REQUESTS_TO_KEEP} most recent)`);
    }

    // 3. Strip large fields from remaining requests to reduce size
    for (const [id, data] of this._authRequestsCache.entries()) {
      if (data) {
        // Remove response bodies (largest field)
        if (data.responseBody) {
          delete data.responseBody;
        }
        if (data.requestBody && data.requestBody.length > 10000) {
          data.requestBody = data.requestBody.substring(0, 10000) + '... [truncated]';
        }
        // Remove large intelligence data
        if (data.metadata?.intelligence?.html) {
          delete data.metadata.intelligence.html;
        }
        if (data.metadata?.backendSecurity?.pageHtml) {
          delete data.metadata.backendSecurity.pageHtml;
        }
      }
    }

    console.log(`Hera: Cleanup complete - ${this._authRequestsCache.size} requests remaining`);

    // DON'T force immediate sync here - let the caller decide
    // await this._syncToStorage();
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
    // P3-SIXTEENTH-2: DEBOUNCE TIMING RATIONALE
    // 100ms chosen to balance:
    //   1. Data loss risk - Service workers killed after 30s idle, 100ms minimizes loss window
    //   2. Storage API performance - chrome.storage.local.set() takes ~5-20ms
    //   3. Write coalescing - Multiple rapid writes batched into single storage operation
    //   4. Quota exhaustion - Fewer writes = less quota pressure
    // Alternative: 1000ms (used by alert-manager, evidence-collector) prioritizes quota over data loss
    // Choice depends on criticality: auth requests (100ms) vs alert history (1000ms)

    if (this._syncTimeout) clearTimeout(this._syncTimeout);
    this._syncTimeout = setTimeout(() => {
      this._syncToStorage().catch(err => {
        console.error('Hera: Background sync failed:', err);

        // P1-TENTH-6 FIX: Retry once on failure
        setTimeout(() => {
          this._syncToStorage().catch(retryErr =>
            console.error('Hera: Background sync retry failed:', retryErr)
          );
        }, 100);
      });
    }, 100); // 100ms - see rationale above
  }

  // === ASYNC API (recommended for new code) ===

  async addAuthRequest(requestId, requestData) {
    await this.initPromise;

    // P0-SEVENTEENTH-3 FIX: Reject writes if circuit breaker is open
    if (this._syncFailureCount >= 3) {
      console.error('Hera: Circuit breaker OPEN - rejecting new auth request to prevent memory leak');
      return false;
    }

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
