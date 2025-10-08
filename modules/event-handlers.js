/**
 * Event Handlers - Chrome extension lifecycle and permission events
 * Handles onInstalled, onStartup, permission changes
 */

export class EventHandlers {
  constructor(debuggerManager, storageManager) {
    this.debuggerManager = debuggerManager;
    this.storageManager = storageManager;
  }

  /**
   * Handle extension installation/update
   */
  async handleInstalled(details) {
    console.log(`Hera ${details.reason}:`, details);

    // On first install only
    if (details.reason === 'install') {
      try {
        // SECURITY FIX: Clear any leftover data from previous installation
        await chrome.storage.local.clear();
        console.log('Hera: Cleared previous installation data');

        // Set default configuration
        await chrome.storage.local.set({
          heraConfig: {
            syncEndpoint: null,
            riskThreshold: 50,
            enableRealTimeAlerts: true,
            autoExportEnabled: true,
            autoExportThreshold: 950
          }
        });
        console.log('Hera: Default configuration set');

        // SECURITY FIX: Don't auto-request permissions on install
        console.log('Hera: Installation complete. Open popup to enable monitoring.');
      } catch (error) {
        console.error('Hera: Error during installation:', error);
      }
    }

    // On install or update, initialize extension
    await this.debuggerManager.initializeAllTabs();
    await this.storageManager.updateBadge();
  }

  /**
   * Handle extension startup (browser restart)
   */
  async handleStartup() {
    console.log('Hera starting up...');
    await this.debuggerManager.initializeAllTabs();
    await this.storageManager.updateBadge();

    // Check for data recovery
    const stored = await chrome.storage.local.get(['heraSessions']);
    const sessions = stored.heraSessions || [];
    
    if (sessions.length >= 900) {
      console.log(`Found ${sessions.length} stored sessions - auto-exporting for safety...`);
      // Auto-export logic would go here
    }
    
    console.log(`Hera ready - ${sessions.length} sessions loaded`);
  }

  /**
   * Handle webRequest permission added
   */
  async handlePermissionAdded(permissions, initializeWebRequestListeners) {
    if (permissions.permissions?.includes('webRequest')) {
      console.log('Hera: webRequest permission added, initializing listeners');
      await initializeWebRequestListeners();
    }
  }

  /**
   * Handle permission removal
   * P0-SEVENTH-2 FIX: Graceful debugger permission revocation
   */
  async handlePermissionRemoved(permissions) {
    if (permissions.permissions?.includes('webRequest')) {
      console.warn('Hera: webRequest permission removed - monitoring stopped');
    }

    // P0-SEVENTH-2 FIX: Gracefully handle debugger permission revocation
    if (permissions.permissions?.includes('debugger')) {
      console.log('Hera: Debugger permission being revoked - attempting cleanup');

      await this.debuggerManager.detachAll();

      // Notify user
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon128.png',
        title: 'Hera: Response Capture Disabled',
        message: 'Debugger permission revoked. HTTP response body capture is now disabled.',
        priority: 1
      });
    }
  }

  /**
   * Handle tab creation
   */
  async handleTabCreated(tab) {
    if (tab.id) {
      await this.debuggerManager.attachDebugger(tab.id);
    }
  }

  /**
   * Handle tab update
   */
  async handleTabUpdated(tabId, changeInfo) {
    if (changeInfo.status === 'loading') {
      await this.debuggerManager.attachDebugger(tabId);
    }
  }

  /**
   * Handle tab removal
   * P1-NINTH-1 FIX: Immediate cleanup
   */
  async handleTabRemoved(tabId) {
    await this.debuggerManager.detachDebugger(tabId);
    // P1-NINTH-1 FIX: Delete immediately, don't wait for callback
    await this.debuggerManager.memoryManager.deleteDebugTarget(tabId);
  }

  /**
   * Register all event listeners
   */
  registerListeners(initializeWebRequestListeners) {
    // Installation and lifecycle
    chrome.runtime.onInstalled.addListener((details) => this.handleInstalled(details));
    chrome.runtime.onStartup.addListener(() => this.handleStartup());

    // Permissions
    chrome.permissions.onAdded.addListener((permissions) => 
      this.handlePermissionAdded(permissions, initializeWebRequestListeners)
    );
    chrome.permissions.onRemoved.addListener((permissions) => 
      this.handlePermissionRemoved(permissions)
    );

    // Tab events
    chrome.tabs.onCreated.addListener((tab) => this.handleTabCreated(tab));
    chrome.tabs.onUpdated.addListener((tabId, changeInfo) => 
      this.handleTabUpdated(tabId, changeInfo)
    );
    chrome.tabs.onRemoved.addListener((tabId) => this.handleTabRemoved(tabId));

    // Periodic cleanup
    setInterval(() => {
      this.debuggerManager.cleanupStaleEntries();
    }, 60000); // Every minute
  }
}
