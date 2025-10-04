// Storage Manager - Centralized storage operations with quota management
// P0 SECURITY FIX: Now includes encryption, secret redaction, and mutex locking

import { securelyStoreSession, retrieveSecureSession } from './secure-storage.js';

export class StorageManager {
  constructor() {
    this.QUOTA_WARNING_THRESHOLD = 0.8; // 80% of quota
    this.MAX_SESSIONS = 1000; // Hard limit on stored sessions
    this.SESSION_RETENTION_HOURS = 24; // P0 FIX: Auto-delete sessions after 24 hours

    // P0 FIX: Mutex for preventing race conditions
    this.storageLock = Promise.resolve();
  }

  // Store authentication event
  // P0 FIX: Now uses mutex, encryption, redaction, and auto-cleanup
  async storeAuthEvent(eventData) {
    // Acquire lock to prevent race conditions
    this.storageLock = this.storageLock.then(async () => {
      try {
        const result = await chrome.storage.local.get({ heraSessions: [] });
        let sessions = result.heraSessions;

        // P0 FIX: Clean up old sessions (retention policy)
        sessions = await this.cleanupOldSessions(sessions);

        // P0 FIX: Redact secrets and encrypt
        const secureData = await securelyStoreSession(eventData);

        sessions.push(secureData);

        // Enforce max sessions limit
        if (sessions.length > this.MAX_SESSIONS) {
          sessions = sessions.slice(-this.MAX_SESSIONS);
        }

        await chrome.storage.local.set({ heraSessions: sessions });
        await this.updateBadge();
      } catch (error) {
        console.error('Failed to store auth event:', error);
      }
    });

    return this.storageLock;
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
  // P0 FIX: Now decrypts sessions
  async getAllSessions() {
    try {
      const result = await chrome.storage.local.get({ heraSessions: [] });
      const encryptedSessions = result.heraSessions || [];

      // Decrypt all sessions
      const decryptedSessions = await Promise.all(
        encryptedSessions.map(session => retrieveSecureSession(session))
      );

      return decryptedSessions.filter(s => s !== null);
    } catch (error) {
      console.error('Failed to get sessions:', error);
      return [];
    }
  }

  // P0 FIX: Clean up sessions older than retention period
  async cleanupOldSessions(sessions) {
    const now = Date.now();
    const retentionMs = this.SESSION_RETENTION_HOURS * 60 * 60 * 1000;

    // Decrypt to check timestamps
    const decryptedSessions = await Promise.all(
      sessions.map(async (session) => {
        const decrypted = await retrieveSecureSession(session);
        return { original: session, decrypted };
      })
    );

    // Filter out old sessions
    const filtered = decryptedSessions.filter(({ decrypted }) => {
      if (!decrypted || !decrypted.timestamp) return true; // Keep if no timestamp

      const sessionTime = new Date(decrypted.timestamp).getTime();
      const age = now - sessionTime;

      return age < retentionMs;
    });

    const removedCount = sessions.length - filtered.length;
    if (removedCount > 0) {
      console.log(`Hera: Auto-deleted ${removedCount} sessions older than ${this.SESSION_RETENTION_HOURS}h`);
    }

    return filtered.map(({ original }) => original);
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
