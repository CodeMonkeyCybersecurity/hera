/**
 * Alarm Handlers - Chrome alarms for periodic tasks
 * Handles cleanup, quota checks, consent expiry
 */

export class AlarmHandlers {
  constructor(memoryManager, alertManager, evidenceCollector, sessionTracker, storageManager) {
    this.memoryManager = memoryManager;
    this.alertManager = alertManager;
    this.evidenceCollector = evidenceCollector;
    this.sessionTracker = sessionTracker;
    this.storageManager = storageManager;
  }

  /**
   * Initialize all alarms
   */
  async initializeAlarms() {
    // Periodic cleanup
    chrome.alarms.create('cleanupAuthRequests', { periodInMinutes: 2 });
    chrome.alarms.create('checkStorageQuota', { periodInMinutes: 10 });
  }

  /**
   * Handle alarm events
   */
  async handleAlarm(alarm, initializationPromise) {
    await initializationPromise; // Wait for init before cleanup

    if (alarm.name === 'cleanupAuthRequests') {
      await this.memoryManager.cleanupStaleRequests();
      this.alertManager.cleanupAlertHistory();
      this.evidenceCollector.cleanup();
      this.sessionTracker.cleanupOldSessions();
    } 
    else if (alarm.name === 'checkStorageQuota') {
      await this.storageManager.checkStorageQuota();
    } 
    // DISABLED - Probe consent feature removed (auth-only mode)
    // else if (alarm.name.startsWith('heraProbeConsent_')) {
    //   const { probeConsentManager } = await import('./probe-consent.js');
    //   await probeConsentManager.revokeConsent();
    //   console.log('Hera: Probe consent auto-revoked (24h expiry)');
    // }
    // DISABLED - Privacy consent feature removed (auth-only mode)
    // else if (alarm.name === 'heraPrivacyConsentExpiry') {
    //   const { privacyConsentManager } = await import('./privacy-consent.js');
    //   await privacyConsentManager.withdrawConsent();
    //   console.log('Hera: Privacy consent auto-revoked (expiry)');
    // }
  }

  /**
   * Register alarm listener
   */
  registerListener(initializationPromise) {
    chrome.alarms.onAlarm.addListener((alarm) => 
      this.handleAlarm(alarm, initializationPromise)
    );
  }
}
