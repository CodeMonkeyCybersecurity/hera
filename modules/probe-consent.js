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
    this.consentCache = null; // In-memory cache
  }

  /**
   * Check if user has given consent for security probes
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

    // Check if consent has expired
    const consentAge = Date.now() - new Date(consent.timestamp).getTime();
    const expiryMs = this.CONSENT_EXPIRY_HOURS * 60 * 60 * 1000;

    if (consentAge > expiryMs) {
      console.warn('Hera: Probe consent has expired');
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
   * @returns {Promise<Object|null>} Consent object or null
   */
  async getConsent() {
    if (this.consentCache) {
      return this.consentCache;
    }

    try {
      const result = await chrome.storage.local.get([this.CONSENT_STORAGE_KEY]);
      this.consentCache = result[this.CONSENT_STORAGE_KEY] || null;
      return this.consentCache;
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

    const consent = {
      enabled: true,
      timestamp: new Date().toISOString(),
      domains: domains,
      acknowledgment: userAcknowledgment,
      version: '1.0' // Consent version for future changes
    };

    try {
      await chrome.storage.local.set({ [this.CONSENT_STORAGE_KEY]: consent });
      this.consentCache = consent;

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
   * @returns {Promise<void>}
   */
  async revokeConsent() {
    try {
      await chrome.storage.local.remove([this.CONSENT_STORAGE_KEY]);
      this.consentCache = null;

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
      const log = {
        timestamp: new Date().toISOString(),
        probeType: probeType,
        targetUrl: targetUrl,
        targetDomain: new URL(targetUrl).hostname,
        success: result.success || false,
        userAgent: navigator.userAgent,
        extensionVersion: chrome.runtime.getManifest().version
      };

      // Store in separate log array (max 100 entries)
      const result_data = await chrome.storage.local.get(['heraProbeLog']);
      const logs = result_data.heraProbeLog || [];
      logs.push(log);

      // Keep only last 100 probe logs
      const trimmed = logs.slice(-100);

      await chrome.storage.local.set({ heraProbeLog: trimmed });

      console.log('Hera: Logged probe execution:', probeType, targetUrl);
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
