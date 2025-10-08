/**
 * Debugger Manager - Chrome DevTools Protocol debugger attachment
 * Handles debugger lifecycle for response body capture
 */

export class DebuggerManager {
  constructor(memoryManager) {
    this.memoryManager = memoryManager;
    this.version = "1.3";
    this.operationLocks = new Map(); // tabId -> Promise (mutex for concurrent operations)
  }

  /**
   * Attach debugger to a tab for response capture
   * P0-NINTH-1 FIX: Mutex prevents race conditions
   */
  async attachDebugger(tabId) {
    if (tabId <= 0) return;

    // P0-NINTH-1 FIX: Acquire lock to prevent concurrent attach attempts
    if (this.operationLocks.has(tabId)) {
      console.log(`Hera: Debugger operation already in progress for tab ${tabId}, skipping`);
      return;
    }

    // Create lock promise
    let releaseLock;
    const lockPromise = new Promise(resolve => { releaseLock = resolve; });
    this.operationLocks.set(tabId, lockPromise);

    try {
      // P0-NINTH-1 FIX: Double-check under lock
      if (await this.memoryManager.hasDebugTarget(tabId)) {
        console.log(`Hera: Debugger already attached to tab ${tabId}`);
        return;
      }

      const result = await chrome.storage.local.get(['enableResponseCapture']);
      const enabled = result.enableResponseCapture === true;

      if (!enabled) {
        return;
      }

      const debuggee = { tabId: tabId };

      // P0-NINTH-1 FIX: Promisify attach for proper async/await
      const attachSuccess = await new Promise((resolve) => {
        chrome.debugger.attach(debuggee, this.version, () => {
          if (chrome.runtime.lastError) {
            const error = chrome.runtime.lastError.message;
            console.warn(`Hera: Failed to attach debugger to tab ${tabId}: ${error}`);
            resolve(false);
          } else {
            resolve(true);
          }
        });
      });

      if (!attachSuccess) {
        return;
      }

      // P0-NINTH-1 FIX: Only set in map AFTER successful attach
      await this.memoryManager.addDebugTarget(tabId, debuggee);

      // Enable Network domain
      const networkEnabled = await new Promise((resolve) => {
        chrome.debugger.sendCommand(debuggee, "Network.enable", {}, () => {
          if (chrome.runtime.lastError) {
            console.warn(`Failed to enable Network for tab ${tabId}`);
            resolve(false);
          } else {
            resolve(true);
          }
        });
      });

      if (!networkEnabled) {
        // Cleanup on failure
        await new Promise((resolve) => {
          chrome.debugger.detach(debuggee, () => {
            this.memoryManager.deleteDebugTarget(tabId);
            resolve();
          });
        });
      }

    } catch (error) {
      console.error('Hera: debugger attach failed:', error);
      await this.memoryManager.deleteDebugTarget(tabId);
    } finally {
      // P0-NINTH-1 FIX: Always release lock
      this.operationLocks.delete(tabId);
      releaseLock();
    }
  }

  /**
   * Detach debugger from a tab
   */
  async detachDebugger(tabId) {
    const debuggee = await this.memoryManager.getDebugTarget(tabId);
    if (!debuggee) return;

    return new Promise((resolve) => {
      chrome.debugger.detach(debuggee, () => {
        if (chrome.runtime.lastError) {
          console.log(`Debugger auto-detached for tab ${tabId}: ${chrome.runtime.lastError.message}`);
        } else {
          console.log(`Successfully detached debugger from tab ${tabId}`);
        }
        resolve();
      });
    });
  }

  /**
   * Initialize debugger for all existing tabs
   */
  async initializeAllTabs() {
    const tabs = await chrome.tabs.query({});
    for (const tab of tabs) {
      if (tab.id && tab.url && !tab.url.startsWith('chrome://')) {
        await this.attachDebugger(tab.id);
      }
    }
  }

  /**
   * Detach all debuggers (cleanup)
   */
  async detachAll() {
    const debugTargets = this.memoryManager.debugTargets;
    const detachPromises = [];

    for (const [tabId, debuggee] of debugTargets.entries()) {
      detachPromises.push(
        new Promise(resolve => {
          chrome.debugger.detach(debuggee, () => {
            if (chrome.runtime.lastError) {
              console.log(`Debugger auto-detach for tab ${tabId} (permission revoked)`);
            } else {
              console.log(`Successfully detached debugger from tab ${tabId}`);
            }
            resolve();
          });
        })
      );
    }

    await Promise.all(detachPromises);
    
    // Clear all targets from memory
    for (const tabId of debugTargets.keys()) {
      await this.memoryManager.deleteDebugTarget(tabId);
    }
  }

  /**
   * Periodic cleanup of stale debugger entries
   * P1-NINTH-1 FIX: Defense in depth
   */
  async cleanupStaleEntries() {
    const allTabs = await chrome.tabs.query({});
    const validTabIds = new Set(allTabs.map(tab => tab.id));

    const debugTargets = this.memoryManager.debugTargets;
    for (const tabId of debugTargets.keys()) {
      if (!validTabIds.has(tabId)) {
        console.warn(`Hera: Removing stale debugger entry for closed tab ${tabId}`);
        await this.memoryManager.deleteDebugTarget(tabId);
      }
    }
  }
}
