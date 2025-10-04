/**
 * Privacy Consent Manager
 *
 * P0-NEW-4: GDPR Compliance for Third-Party Data Sharing
 *
 * PRIVACY CRITICAL: Hera shares user browsing data with third parties:
 * - cloudflare-dns.com (DNS resolution)
 * - ipapi.co (IP geolocation)
 *
 * Under GDPR, users must:
 * 1. Be informed what data is shared
 * 2. Give explicit consent before sharing
 * 3. Be able to withdraw consent
 *
 * This module manages privacy consent for third-party lookups.
 *
 * @module privacy-consent
 */

class PrivacyConsentManager {
  constructor() {
    this.CONSENT_KEY = 'heraPrivacyConsent';
    this.CONSENT_EXPIRY_HOURS = 24 * 365; // 1 year (persistent unless withdrawn)
  }

  /**
   * Check if user has granted privacy consent for third-party lookups
   * @returns {Promise<boolean>} True if consent granted and still valid
   */
  async hasPrivacyConsent() {
    try {
      const result = await chrome.storage.local.get([this.CONSENT_KEY]);
      const consent = result[this.CONSENT_KEY];

      if (!consent || !consent.granted) {
        return false;
      }

      // Check if consent has expired
      const consentTime = new Date(consent.timestamp).getTime();
      const expiryMs = this.CONSENT_EXPIRY_HOURS * 60 * 60 * 1000;
      const now = Date.now();

      if (now - consentTime > expiryMs) {
        console.log('Hera: Privacy consent expired');
        return false;
      }

      return true;
    } catch (error) {
      console.error('Hera: Failed to check privacy consent:', error);
      return false; // Fail-safe: deny if check fails
    }
  }

  /**
   * Grant privacy consent for third-party lookups
   * @returns {Promise<void>}
   */
  async grantConsent() {
    try {
      const consent = {
        granted: true,
        timestamp: new Date().toISOString(),
        version: 1 // Track consent version for future changes
      };

      await chrome.storage.local.set({ [this.CONSENT_KEY]: consent });
      console.log('Hera: Privacy consent granted');
    } catch (error) {
      console.error('Hera: Failed to grant privacy consent:', error);
      throw error;
    }
  }

  /**
   * Withdraw privacy consent (GDPR right to withdraw)
   * @returns {Promise<void>}
   */
  async withdrawConsent() {
    try {
      await chrome.storage.local.remove([this.CONSENT_KEY]);
      console.log('Hera: Privacy consent withdrawn');
    } catch (error) {
      console.error('Hera: Failed to withdraw privacy consent:', error);
      throw error;
    }
  }

  /**
   * Get consent status and details
   * @returns {Promise<Object>} Consent status object
   */
  async getConsentStatus() {
    try {
      const result = await chrome.storage.local.get([this.CONSENT_KEY]);
      const consent = result[this.CONSENT_KEY];

      if (!consent) {
        return {
          granted: false,
          timestamp: null,
          expiresAt: null
        };
      }

      const consentTime = new Date(consent.timestamp).getTime();
      const expiryMs = this.CONSENT_EXPIRY_HOURS * 60 * 60 * 1000;
      const expiresAt = new Date(consentTime + expiryMs);

      return {
        granted: consent.granted,
        timestamp: consent.timestamp,
        expiresAt: expiresAt.toISOString(),
        version: consent.version || 1
      };
    } catch (error) {
      console.error('Hera: Failed to get consent status:', error);
      return {
        granted: false,
        timestamp: null,
        expiresAt: null
      };
    }
  }
}

// Export singleton instance
export const privacyConsentManager = new PrivacyConsentManager();
