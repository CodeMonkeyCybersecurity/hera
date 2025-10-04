/**
 * Persistent Evidence Collector - CRITICAL FIX P0
 * Migrated from volatile Maps/Arrays to chrome.storage.session
 * Maintains all evidence across service worker restarts
 */

export class PersistentEvidenceCollector {
  constructor() {
    // In-memory caches for fast access
    this._responseCache = new Map();
    this._flowCorrelation = new Map();
    this._proofOfConcepts = [];
    this._activeFlows = new Map();
    this._timeline = [];

    // State tracking
    this.initialized = false;
    this.initPromise = this.initialize();
    this.MAX_CACHE_SIZE = 100; // Limit to prevent quota issues
    this.MAX_TIMELINE = 500;
  }

  async initialize() {
    if (this.initialized) return;

    try {
      const data = await chrome.storage.session.get(['heraEvidence']);

      if (data.heraEvidence) {
        const evidence = data.heraEvidence;

        // Restore responseCache
        if (evidence.responseCache) {
          for (const [id, item] of Object.entries(evidence.responseCache)) {
            this._responseCache.set(id, item);
          }
        }

        // Restore flowCorrelation
        if (evidence.flowCorrelation) {
          for (const [id, item] of Object.entries(evidence.flowCorrelation)) {
            this._flowCorrelation.set(id, item);
          }
        }

        // Restore arrays
        this._proofOfConcepts = evidence.proofOfConcepts || [];
        this._timeline = evidence.timeline || [];

        // Restore activeFlows
        if (evidence.activeFlows) {
          for (const [id, flow] of Object.entries(evidence.activeFlows)) {
            this._activeFlows.set(id, flow);
          }
        }

        console.log(`Hera: Restored evidence collector (${this._responseCache.size} responses, ${this._timeline.length} timeline events)`);
      }

      this.initialized = true;
    } catch (error) {
      console.error('Hera: Failed to initialize evidence collector:', error);
      this.initialized = true;
    }
  }

  async _syncToStorage() {
    try {
      await this.initPromise;

      // Convert Maps to objects
      const evidence = {
        responseCache: Object.fromEntries(this._responseCache.entries()),
        flowCorrelation: Object.fromEntries(this._flowCorrelation.entries()),
        proofOfConcepts: this._proofOfConcepts,
        timeline: this._timeline,
        activeFlows: Object.fromEntries(this._activeFlows.entries())
      };

      await chrome.storage.session.set({ heraEvidence: evidence });
    } catch (error) {
      if (error.message?.includes('QUOTA')) {
        console.warn('Hera: Evidence storage quota exceeded, cleaning up');
        await this._performCleanup();
      } else {
        console.error('Hera: Failed to sync evidence:', error);
      }
    }
  }

  async _performCleanup() {
    // Keep only most recent items
    if (this._responseCache.size > this.MAX_CACHE_SIZE) {
      const sorted = Array.from(this._responseCache.entries())
        .sort((a, b) => b[1].timestamp - a[1].timestamp);
      this._responseCache = new Map(sorted.slice(0, this.MAX_CACHE_SIZE));
    }

    if (this._timeline.length > this.MAX_TIMELINE) {
      this._timeline = this._timeline.slice(-this.MAX_TIMELINE);
    }

    // Re-sync after cleanup
    await this._syncToStorage();
  }

  _debouncedSync() {
    if (this._syncTimeout) clearTimeout(this._syncTimeout);
    this._syncTimeout = setTimeout(() => {
      this._syncToStorage().catch(err => console.error('Evidence sync failed:', err));
    }, 200); // Longer debounce for evidence (less frequent updates)
  }

  // Getters for backward compatibility
  get responseCache() {
    return this._responseCache;
  }

  get flowCorrelation() {
    return this._flowCorrelation;
  }

  get proofOfConcepts() {
    return this._proofOfConcepts;
  }

  get activeFlows() {
    return this._activeFlows;
  }

  get timeline() {
    return this._timeline;
  }

  // Cleanup method for old evidence
  async cleanup() {
    await this.initPromise;
    const now = Date.now();
    const TTL = 30 * 60 * 1000; // 30 minutes

    let cleaned = 0;

    // Cleanup old responses
    for (const [id, evidence] of this._responseCache.entries()) {
      if (now - evidence.timestamp > TTL) {
        this._responseCache.delete(id);
        cleaned++;
      }
    }

    // Cleanup old flows
    for (const [id, flow] of this._activeFlows.entries()) {
      if (now - flow.timestamp > TTL) {
        this._activeFlows.delete(id);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      console.log(`Hera: Evidence cleanup removed ${cleaned} old items`);
      await this._syncToStorage();
    }
  }
}

// Export singleton
export const persistentEvidenceCollector = new PersistentEvidenceCollector();
