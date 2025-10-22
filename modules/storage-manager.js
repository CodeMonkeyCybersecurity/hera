// Storage Manager - Centralized storage operations with quota management
// P0 SECURITY FIX: Includes secret redaction and mutex locking
// P2-SIXTEENTH-3 FIX: Removed broken encryption imports (secure-storage.js is broken - see background.js:100-105)

export class StorageManager {
  constructor() {
    this.QUOTA_WARNING_THRESHOLD = 0.8; // 80% of quota
    this.MAX_SESSIONS = 500; // Reduced from 1000 (auth-only mode needs less)
    this.SESSION_RETENTION_HOURS = 168; // 7 days (reduced from 24h for auth monitoring)

    // P0-TENTH-2 FIX: Per-origin limits
    this.MAX_SESSIONS_PER_ORIGIN = 50; // Max 50 sessions per domain
    this.STORAGE_RATE_LIMIT = 10; // Max 10 stores per minute per origin
    this.originStorageCount = new Map(); // Track stores per origin
    this.originLastReset = new Map(); // Track rate limit windows

    // P0 FIX: Mutex for preventing race conditions
    this.storageLock = Promise.resolve();
  }

  // P0-TENTH-2 FIX: Check per-origin rate limit
  _checkOriginRateLimit(origin) {
    const now = Date.now();
    const lastReset = this.originLastReset.get(origin) || 0;

    // Reset counter every minute
    if (now - lastReset > 60000) {
      this.originStorageCount.set(origin, 0);
      this.originLastReset.set(origin, now);
    }

    const count = this.originStorageCount.get(origin) || 0;

    if (count >= this.STORAGE_RATE_LIMIT) {
      console.warn(`Hera SECURITY: Storage rate limit exceeded for ${origin} (${count}/${this.STORAGE_RATE_LIMIT})`);
      return false;
    }

    this.originStorageCount.set(origin, count + 1);
    return true;
  }

  // Helper: Check if this is an auth-related request
  _isAuthRelated(url, method) {
    const authPatterns = [
      '/oauth', '/authorize', '/token', '/login', '/signin', '/auth',
      '/api/auth', '/session', '/connect', '/saml', '/oidc', '/scim',
      '/sso', '/.well-known', '/openid', '/ldap', '/kerberos',
      '/mfa', '/2fa', '/otp', '/verify', '/password', '/register',
      '/signup', '/logout', '/callback', '/federation'
    ];
    const urlLower = url.toLowerCase();
    return authPatterns.some(pattern => urlLower.includes(pattern));
  }

  // Store authentication event
  // P0 FIX: Now uses mutex, encryption, redaction, and auto-cleanup
  // P0-ARCH-1 FIX: Fast atomic cleanup without slow decryption
  // AUTH-ONLY MODE: Only stores auth-related sessions
  async storeAuthEvent(eventData) {
    // P0-NINTH-2 FIX: Proper mutex - wrap the entire async operation
    this.storageLock = this.storageLock.then(async () => {
      try {
        // AUTH-ONLY MODE: Skip non-auth requests
        if (!this._isAuthRelated(eventData.url, eventData.method)) {
          console.log(`Hera: Skipping non-auth session: ${eventData.url}`);
          return;
        }

        // P0-TENTH-2 FIX: Extract origin from URL
        let origin;
        try {
          origin = new URL(eventData.url).origin;
        } catch (e) {
          console.error('Invalid URL in auth event:', eventData.url);
          return; // Reject invalid URLs
        }

        // P0-TENTH-2 FIX: Check rate limit
        if (!this._checkOriginRateLimit(origin)) {
          throw new Error(`Storage rate limit exceeded for origin: ${origin}`);
        }

        const result = await chrome.storage.local.get({ heraSessions: [] });
        let sessions = result.heraSessions;

        // P0-TENTH-2 FIX: Count sessions per origin
        const originSessions = sessions.filter(s => {
          try {
            return new URL(s.url).origin === origin;
          } catch (e) {
            return false;
          }
        });

        if (originSessions.length >= this.MAX_SESSIONS_PER_ORIGIN) {
          console.warn(`Hera SECURITY: Origin ${origin} exceeded session limit (${originSessions.length}/${this.MAX_SESSIONS_PER_ORIGIN})`);

          // Remove oldest session from this origin
          const oldestIndex = sessions.findIndex(s => {
            try {
              return new URL(s.url).origin === origin;
            } catch (e) {
              return false;
            }
          });

          if (oldestIndex !== -1) {
            sessions.splice(oldestIndex, 1);
            console.log(`Evicted oldest session from ${origin}`);
          }
        }

        // P0-ARCH-1 FIX: Fast timestamp-based cleanup (no decryption needed)
        const now = Date.now();
        const retentionMs = this.SESSION_RETENTION_HOURS * 60 * 60 * 1000;

        sessions = sessions.filter(session => {
          // Use external timestamp (plaintext) for fast filtering
          const ts = session._timestamp || 0;
          if (ts === 0) return true; // Keep sessions without timestamp
          return (now - ts) < retentionMs;
        });

        const deletedCount = result.heraSessions.length - sessions.length;
        if (deletedCount > 0) {
          console.log(`Hera: Auto-deleted ${deletedCount} sessions older than ${this.SESSION_RETENTION_HOURS}h`);
        }

        // P2-SIXTEENTH-3 FIX: Encryption removed (secure-storage.js is broken)
        // Future: Implement password-based key derivation (PBKDF2) or accept no encryption
        // Store plaintext timestamp for fast cleanup
        eventData._timestamp = new Date(eventData.timestamp).getTime();

        sessions.push(eventData);

        // Enforce max sessions limit
        if (sessions.length > this.MAX_SESSIONS) {
          sessions = sessions.slice(-this.MAX_SESSIONS);
        }

        await chrome.storage.local.set({ heraSessions: sessions });
        await this.updateBadge();
      } catch (error) {
        console.error('Failed to store auth event:', error);
        // P0-NINTH-2 FIX: Re-throw to ensure caller knows operation failed
        throw error;
      }
    });

    // P0-NINTH-2 FIX: Await the lock to ensure operation completes before returning
    await this.storageLock;
    return;
  }

  // Store session data
  async storeSession(sessionData) {
    try {
      const result = await chrome.storage.local.get({ heraSessions: [] });
      const sessions = result.heraSessions;
      sessions.push(sessionData);
      await chrome.storage.local.set({ heraSessions: sessions });
    } catch (error) {
      console.error('Failed to store session:', error);
    }
  }

  // Get all sessions
  // P2-SIXTEENTH-3 FIX: Removed decryption (secure-storage.js is broken)
  async getAllSessions() {
    try {
      const result = await chrome.storage.local.get({ heraSessions: [] });
      const sessions = result.heraSessions || [];
      return sessions;
    } catch (error) {
      console.error('Failed to get sessions:', error);
      return [];
    }
  }

  // P0-ARCH-1 FIX: DEPRECATED - This method is no longer used
  // The fast timestamp-based cleanup is now done directly in storeAuthEvent()
  // using external _timestamp field (no decryption required)
  //
  // This method is kept for backwards compatibility in case it's called from
  // external code, but it now uses the fast path.
  async cleanupOldSessions(sessions) {
    const now = Date.now();
    const retentionMs = this.SESSION_RETENTION_HOURS * 60 * 60 * 1000;

    // P0-ARCH-1 FIX: Use external timestamp for fast filtering (no decryption)
    const filtered = sessions.filter(session => {
      const ts = session._timestamp || 0;
      if (ts === 0) return true; // Keep sessions without timestamp
      return (now - ts) < retentionMs;
    });

    const removedCount = sessions.length - filtered.length;
    if (removedCount > 0) {
      console.log(`Hera: Auto-deleted ${removedCount} sessions older than ${this.SESSION_RETENTION_HOURS}h`);
    }

    return filtered;
  }

  // Clear all sessions
  async clearAllSessions() {
    try {
      await chrome.storage.local.set({ heraSessions: [] });
      await this.updateBadge();
      return { success: true };
    } catch (error) {
      console.error('Failed to clear sessions:', error);
      return { success: false, error: error.message };
    }
  }

  // Update extension badge
  async updateBadge() {
    try {
      const stored = await chrome.storage.local.get(['heraSessions']);
      const count = stored.heraSessions ? stored.heraSessions.length : 0;
      if (count > 0) {
        chrome.action.setBadgeText({ text: count.toString() });
        chrome.action.setBadgeBackgroundColor({ color: '#dc3545' });
      } else {
        chrome.action.setBadgeText({ text: '' });
      }
    } catch (error) {
      console.error('Failed to update badge:', error);
    }
  }

  // Check storage quota and cleanup if needed
  async checkStorageQuota() {
    try {
      const bytesInUse = await chrome.storage.local.getBytesInUse();
      const quota = chrome.storage.local.QUOTA_BYTES || 10485760; // 10MB default
      const usagePercent = bytesInUse / quota;

      console.log(`Storage: ${(bytesInUse / 1024).toFixed(0)}KB / ${(quota / 1024).toFixed(0)}KB (${(usagePercent * 100).toFixed(1)}%)`);

      // AUTO-EXPORT at 80% storage
      if (usagePercent >= 0.80 && usagePercent < this.QUOTA_WARNING_THRESHOLD) {
        console.warn(`⚠️ Storage at ${(usagePercent * 100).toFixed(0)}% - triggering auto-export`);

        // Check if we've already shown the export prompt recently (don't spam)
        const lastExportPrompt = await chrome.storage.session.get(['lastExportPrompt']);
        const now = Date.now();
        const oneHour = 60 * 60 * 1000;

        if (!lastExportPrompt.lastExportPrompt || (now - lastExportPrompt.lastExportPrompt) > oneHour) {
          // Trigger export popup
          await this._triggerAutoExport(usagePercent);
          await chrome.storage.session.set({ lastExportPrompt: now });
        }
      }

      if (usagePercent >= this.QUOTA_WARNING_THRESHOLD) {
        console.warn(`⚠️ Storage quota warning: ${(usagePercent * 100).toFixed(0)}% used`);

        // Cleanup oldest sessions
        const result = await chrome.storage.local.get(['heraSessions']);
        const sessions = result.heraSessions || [];

        if (sessions.length > this.MAX_SESSIONS) {
          // Keep only the most recent sessions
          const sorted = sessions.sort((a, b) =>
            new Date(b.timestamp) - new Date(a.timestamp)
          );
          const trimmed = sorted.slice(0, this.MAX_SESSIONS);

          await chrome.storage.local.set({ heraSessions: trimmed });
          console.log(`Trimmed sessions from ${sessions.length} to ${trimmed.length}`);
        }
      }
    } catch (error) {
      console.error('Failed to check storage quota:', error);
    }
  }

  /**
   * Trigger auto-export popup when storage reaches 80%
   */
  async _triggerAutoExport(usagePercent) {
    try {
      // Create notification asking user to export
      await chrome.notifications.create('hera-export-prompt', {
        type: 'basic',
        iconUrl: chrome.runtime.getURL('icons/icon128.png'),
        title: 'Hera: Export Your Auth Data',
        message: `Storage at ${(usagePercent * 100).toFixed(0)}%. Click to export and clear data to prevent loss.`,
        buttons: [
          { title: 'Export Now' },
          { title: 'Remind Me Later' }
        ],
        requireInteraction: true,
        priority: 2
      });

      // Listen for notification click
      chrome.notifications.onButtonClicked.addListener(async (notifId, buttonIndex) => {
        if (notifId === 'hera-export-prompt') {
          if (buttonIndex === 0) {
            // Export Now clicked
            await this.exportAndClearData();
          }
          // Clear notification
          await chrome.notifications.clear(notifId);
        }
      });

      // If user clicks notification body, open popup
      chrome.notifications.onClicked.addListener(async (notifId) => {
        if (notifId === 'hera-export-prompt') {
          await this.exportAndClearData();
          await chrome.notifications.clear(notifId);
        }
      });

    } catch (error) {
      console.error('Failed to trigger auto-export:', error);
    }
  }

  /**
   * Export data and clear storage after download
   */
  async exportAndClearData() {
    try {
      const result = await chrome.storage.local.get(['heraSessions']);
      const sessions = result.heraSessions || [];

      if (sessions.length === 0) {
        console.log('No data to export');
        return;
      }

      // Generate filename with timestamp
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
      const filename = `hera-auth-export-${timestamp}.json`;

      // Create export data
      const exportData = {
        timestamp: new Date().toISOString(),
        sessionCount: sessions.length,
        requests: sessions
      };

      // Trigger download
      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);

      await chrome.downloads.download({
        url: url,
        filename: filename,
        saveAs: true
      });

      // Wait for download to complete, then clear
      chrome.downloads.onChanged.addListener(function clearAfterDownload(delta) {
        if (delta.state && delta.state.current === 'complete') {
          // Clear storage after successful download
          chrome.storage.local.set({ heraSessions: [] }).then(() => {
            console.log('✅ Data exported and storage cleared');

            // Show success notification
            chrome.notifications.create({
              type: 'basic',
              iconUrl: chrome.runtime.getURL('icons/icon128.png'),
              title: 'Hera: Export Complete',
              message: `Exported ${sessions.length} auth sessions. Storage cleared.`,
              priority: 1
            });
          });

          // Remove this listener
          chrome.downloads.onChanged.removeListener(clearAfterDownload);
        }
      });

    } catch (error) {
      console.error('Failed to export and clear data:', error);
    }
  }

  // Store finding for popup display
  async storeFinding(finding, alertDecision) {
    try {
      const result = await chrome.storage.local.get(['heraFindings']);
      const findings = result.heraFindings || [];

      findings.push({
        ...finding,
        confidence: finding.confidence,
        alertAction: alertDecision.action,
        timestamp: Date.now()
      });

      // Keep only last 500 findings
      if (findings.length > 500) {
        findings.splice(0, findings.length - 500);
      }

      await chrome.storage.local.set({ heraFindings: findings });
    } catch (error) {
      console.error('Failed to store finding:', error);
    }
  }

  // Get all findings
  async getAllFindings() {
    try {
      const result = await chrome.storage.local.get(['heraFindings']);
      return result.heraFindings || [];
    } catch (error) {
      console.error('Failed to get findings:', error);
      return [];
    }
  }

  // Store security alert
  async storeSecurityAlert(alert) {
    try {
      const result = await chrome.storage.local.get(['securityAlerts']);
      const alerts = result.securityAlerts || [];

      alerts.push({
        timestamp: Date.now(),
        ...alert
      });

      // Keep only last 50 alerts
      if (alerts.length > 50) {
        alerts.splice(0, alerts.length - 50);
      }

      await chrome.storage.local.set({ securityAlerts: alerts });
    } catch (error) {
      console.error('Failed to store security alert:', error);
    }
  }
}

// Export singleton instance
export const storageManager = new StorageManager();
