/**
 * Storage Sync Helper - P3-SEVENTH-1 FIX
 *
 * Eliminates duplicate storage sync logic across:
 * - alert-manager.js
 * - session-tracker.js
 * - ip-cache.js
 *
 * All three modules had nearly identical _syncToStorage() and _debouncedSync()
 * implementations. This utility provides a reusable debounced sync pattern.
 *
 * @module storage-sync-helper
 */

/**
 * Creates a debounced storage sync function for a module
 *
 * Usage:
 * ```javascript
 * class MyManager {
 *   constructor() {
 *     this._data = new Map();
 *     const syncHelper = createStorageSyncHelper({
 *       storageKey: 'myData',
 *       serialize: () => ({ data: Object.fromEntries(this._data.entries()) }),
 *       debounceMs: 100
 *     });
 *     this.syncWrite = syncHelper.syncWrite;
 *   }
 * }
 * ```
 *
 * @param {Object} options - Configuration
 * @param {string} options.storageKey - Key to store data under in chrome.storage.local
 * @param {Function} options.serialize - Function that returns object to store
 * @param {number} [options.debounceMs=100] - Debounce delay in milliseconds
 * @returns {Object} Object with syncWrite() and syncNow() methods
 */
export function createStorageSyncHelper({ storageKey, serialize, debounceMs = 100 }) {
  let syncTimeout = null;

  /**
   * Perform immediate sync to storage
   *
   * @returns {Promise<void>}
   */
  async function syncNow() {
    try {
      const data = serialize();
      await chrome.storage.local.set({ [storageKey]: data });
    } catch (error) {
      console.error(`Hera: Failed to sync ${storageKey}:`, error);
    }
  }

  /**
   * Schedule a debounced sync to storage
   *
   * @returns {void}
   */
  function syncWrite() {
    if (syncTimeout) clearTimeout(syncTimeout);
    syncTimeout = setTimeout(() => {
      syncNow().catch(err =>
        console.error(`Hera: ${storageKey} sync failed:`, err)
      );
    }, debounceMs);
  }

  return { syncWrite, syncNow };
}

/**
 * Example migration guide:
 *
 * BEFORE (alert-manager.js):
 * ```javascript
 * class AlertManager {
 *   constructor() {
 *     this.alertHistory = new Map();
 *   }
 *
 *   async _syncToStorage() {
 *     try {
 *       const data = { alertHistory: Object.fromEntries(this.alertHistory.entries()) };
 *       await chrome.storage.local.set({ heraAlertHistory: data });
 *     } catch (error) {
 *       console.error('Failed to sync:', error);
 *     }
 *   }
 *
 *   _debouncedSync() {
 *     if (this._syncTimeout) clearTimeout(this._syncTimeout);
 *     this._syncTimeout = setTimeout(() => {
 *       this._syncToStorage().catch(err => console.error('Sync failed:', err));
 *     }, 200);
 *   }
 * }
 * ```
 *
 * AFTER (with helper):
 * ```javascript
 * import { createStorageSyncHelper } from './modules/storage-sync-helper.js';
 *
 * class AlertManager {
 *   constructor() {
 *     this.alertHistory = new Map();
 *
 *     const syncHelper = createStorageSyncHelper({
 *       storageKey: 'heraAlertHistory',
 *       serialize: () => ({
 *         alertHistory: Object.fromEntries(this.alertHistory.entries())
 *       }),
 *       debounceMs: 200
 *     });
 *
 *     this._debouncedSync = syncHelper.syncWrite;
 *     this._syncToStorage = syncHelper.syncNow;
 *   }
 * }
 * ```
 */
