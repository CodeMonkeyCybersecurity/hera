/**
 * Security Probe Consent Manager
 *
 * SECURITY CRITICAL: Manages user consent for active security probes.
 * Active probes are ATTACKS against web applications and may be illegal.
 * Users must explicitly consent with full understanding of risks.
 *
 * @module probe-consent
 */

export class ProbeConsentManager {
  constructor() {
    this.CONSENT_STORAGE_KEY = 'heraProbeConsent';
    this.CONSENT_EXPIRY_HOURS = 24; // Consent expires after 24 hours
    // P1-SEVENTH-3 FIX: Removed cache entirely - chrome.storage.local is fast enough (~1ms)
    // Cache caused race conditions in multi-popup scenarios
  }

  /**
   * Check if user has given consent for security probes
   *
   * P0-ARCH-2 FIX: No more time-based expiry checks using Date.now()
   * Expiry is now enforced by chrome.alarms (cannot be bypassed by clock manipulation)
   *
   * @param {string} probeType - Type of probe (e.g., 'alg_none', 'repeater')
   * @param {string} targetDomain - Domain being probed
   * @returns {Promise<boolean>} True if consent is valid
   */
  async hasConsent(probeType, targetDomain) {
    const consent = await this.getConsent();

    if (!consent || !consent.enabled) {
      return false;
    }

    // P0-EIGHTH-4 FIX: Validate expiry timestamp (cannot be bypassed by clock manipulation)
    const now = Date.now();

    // Check if expiry timestamp exists (new consent format)
    if (consent.expiryTimestamp) {
      const expiryTime = new Date(consent.expiryTimestamp).getTime();

      if (now > expiryTime) {
        console.warn('Hera: Probe consent expired (timestamp check)');
        await this.revokeConsent(); // Auto-revoke
        return false;
      }
    }

    // P0-EIGHTH-4 FIX: Detect clock manipulation (system time moved backwards)
    if (consent.grantedAtMs && now < consent.grantedAtMs) {
      console.error('Hera SECURITY: System clock moved backwards! Revoking consent for safety.');
      await this.revokeConsent();
      return false;
    }

    // Check if this domain is in the consent list
    if (consent.domains && !consent.domains.includes('*')) {
      return consent.domains.includes(targetDomain);
    }

    return true;
  }

  /**
   * Get current consent status
   *
   * P1-SEVENTH-3 FIX: Removed cache - always fetch fresh from storage
   * chrome.storage.local is fast (~1ms) and avoids race conditions
   *
   * @returns {Promise<Object|null>} Consent object or null
   */
  async getConsent() {
    try {
      const result = await chrome.storage.local.get([this.CONSENT_STORAGE_KEY]);
      return result[this.CONSENT_STORAGE_KEY] || null;
    } catch (error) {
      console.error('Failed to get probe consent:', error);
      return null;
    }
  }

  /**
   * Grant consent for security probes
   *
   * SECURITY: This should only be called after explicit user confirmation
   * of the legal and technical risks.
   *
   * P0-ARCH-2 FIX: Uses chrome.alarms for expiry (cannot be bypassed)
   *
   * @param {Object} options - Consent options
   * @param {Array<string>} options.domains - Domains to allow (or ['*'] for all)
   * @param {string} options.userAcknowledgment - User's typed acknowledgment
   * @returns {Promise<boolean>} Success status
   */
  async grantConsent({ domains = [], userAcknowledgment = '' }) {
    // Validate user acknowledgment
    const requiredPhrase = 'I understand the risks';
    if (userAcknowledgment !== requiredPhrase) {
      console.error('Hera: Invalid consent acknowledgment');
      return false;
    }

    const now = Date.now();
    const expiryMs = this.CONSENT_EXPIRY_HOURS * 60 * 60 * 1000;

    const consent = {
      enabled: true,
      timestamp: new Date().toISOString(),
      grantedAtMs: now, // P0-EIGHTH-4 FIX: Store millisecond timestamp for clock-independent validation
      expiryTimestamp: new Date(now + expiryMs).toISOString(), // P0-EIGHTH-4 FIX: Absolute expiry time
      domains: domains,
      acknowledgment: userAcknowledgment,
      version: '1.0' // Consent version for future changes
    };

    try {
      await chrome.storage.local.set({ [this.CONSENT_STORAGE_KEY]: consent });
      // P1-SEVENTH-3 FIX: Removed consentCache assignment

      // P0-EIGHTH-4 FIX: Create alarm (still useful for normal case, but not sole enforcement)
      // P1-TENTH-3 FIX: Use unique alarm name with UUID to prevent manipulation
      const expiryMinutes = this.CONSENT_EXPIRY_HOURS * 60;
      const alarmName = `heraProbeConsent_${crypto.randomUUID()}`;

      // Store alarm name in consent for tracking
      consent.alarmName = alarmName;
      await chrome.storage.local.set({ [this.CONSENT_STORAGE_KEY]: consent });

      await chrome.alarms.create(alarmName, {
        delayInMinutes: expiryMinutes
      });

      console.log(`Hera: Probe consent granted with expiry at ${consent.expiryTimestamp}`);

      // Log consent event for forensics
      await this.logConsentEvent('granted', domains);

      return true;
    } catch (error) {
      console.error('Failed to grant probe consent:', error);
      return false;
    }
  }

  /**
   * Revoke probe consent
   *
   * P0-ARCH-2 FIX: Also clears the expiry alarm
   *
   * @returns {Promise<void>}
   */
  async revokeConsent() {
    try {
      await chrome.storage.local.remove([this.CONSENT_STORAGE_KEY]);
      // P1-SEVENTH-3 FIX: Removed consentCache assignment

      // P0-ARCH-2 FIX: Clear the expiry alarm
      await chrome.alarms.clear('heraProbeConsentExpiry');

      // Log revocation for forensics
      await this.logConsentEvent('revoked', []);
    } catch (error) {
      console.error('Failed to revoke probe consent:', error);
    }
  }

  /**
   * Log probe execution for forensics and auditing
   *
   * SECURITY P0: Logging is critical for:
   * - Incident response (if user's account is compromised)
   * - Legal defense (proof of what probes were run)
   * - User transparency (review their own probe history)
   *
   * @param {string} probeType - Type of probe executed
   * @param {string} targetUrl - Target URL
   * @param {Object} result - Probe result
   * @returns {Promise<void>}
   */
  async logProbeExecution(probeType, targetUrl, result) {
    try {
      // P1-EIGHTH-1 FIX: Reduce log size - store domain only (not full URL), remove userAgent
      const log = {
        timestamp: new Date().toISOString(),
        probeType: probeType,
        targetDomain: new URL(targetUrl).hostname, // Domain only, not full URL
        success: result.success || false
        // P1-EIGHTH-1 FIX: Removed userAgent and extensionVersion (not needed, waste space)
      };

      // P1-EIGHTH-1 FIX: Reduce max logs from 100 to 50
      const MAX_PROBE_LOGS = 50;
      const MAX_LOG_SIZE_BYTES = 10 * 1024; // 10KB max

      const result_data = await chrome.storage.local.get(['heraProbeLog']);
      const logs = result_data.heraProbeLog || [];
      logs.push(log);

      // Keep only last 50 probe logs
      let trimmed = logs.slice(-MAX_PROBE_LOGS);

      // P1-EIGHTH-1 FIX: Enforce max storage size for logs
      const logSize = JSON.stringify(trimmed).length;
      if (logSize > MAX_LOG_SIZE_BYTES) {
        // Trim further if size exceeds limit
        trimmed = trimmed.slice(-25);
        console.warn(`Hera: Probe log size exceeded ${MAX_LOG_SIZE_BYTES} bytes, trimmed to 25 entries`);
      }

      await chrome.storage.local.set({ heraProbeLog: trimmed });

      console.log('Hera: Logged probe execution:', probeType, log.targetDomain);
    } catch (error) {
      console.error('Failed to log probe execution:', error);
    }
  }

  /**
   * Log consent events for auditing
   *
   * @private
   * @param {string} event - Event type (granted, revoked, expired)
   * @param {Array<string>} domains - Domains involved
   * @returns {Promise<void>}
   */
  async logConsentEvent(event, domains) {
    try {
      const log = {
        timestamp: new Date().toISOString(),
        event: event,
        domains: domains
      };

      const result = await chrome.storage.local.get(['heraConsentLog']);
      const logs = result.heraConsentLog || [];
      logs.push(log);

      // Keep only last 50 consent events
      const trimmed = logs.slice(-50);

      await chrome.storage.local.set({ heraConsentLog: trimmed });
    } catch (error) {
      console.error('Failed to log consent event:', error);
    }
  }

  /**
   * Get probe execution history
   *
   * @returns {Promise<Array>} Array of probe logs
   */
  async getProbeHistory() {
    try {
      const result = await chrome.storage.local.get(['heraProbeLog']);
      return result.heraProbeLog || [];
    } catch (error) {
      console.error('Failed to get probe history:', error);
      return [];
    }
  }

  /**
   * Clear probe history
   *
   * @returns {Promise<void>}
   */
  async clearProbeHistory() {
    try {
      await chrome.storage.local.remove(['heraProbeLog', 'heraConsentLog']);
      console.log('Hera: Cleared probe history');
    } catch (error) {
      console.error('Failed to clear probe history:', error);
    }
  }
}

// Singleton instance
export const probeConsentManager = new ProbeConsentManager();
