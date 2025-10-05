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
    // P1-SEVENTH-3 FIX: Removed cache entirely - chrome.storage.local is fast enough (~1ms)
    // Cache caused race conditions in multi-popup scenarios
  }

  /**
   * Check if user has granted privacy consent for third-party lookups
   *
   * P2-SEVENTH-2 FIX: Hybrid expiry approach
   * - For long durations (> 30 days): Use Date.now() based expiry check
   * - For short durations (< 30 days): Use chrome.alarms
   * (chrome.alarms has max delay ~35 days, so 1-year consent needs manual check)
   *
   * P1-SEVENTH-3 FIX: Removed cache - always fetch fresh from storage
   * chrome.storage.local is fast (~1ms) and avoids race conditions
   *
   * @returns {Promise<boolean>} True if consent granted and still valid
   */
  async hasPrivacyConsent() {
    try {
      const result = await chrome.storage.local.get([this.CONSENT_KEY]);
      const consent = result[this.CONSENT_KEY];

      if (!consent || !consent.granted) {
        return false;
      }

      // P2-SEVENTH-2 FIX: For long-duration consents (> 30 days), check expiry manually
      const MAX_ALARM_DELAY_HOURS = 720; // 30 days (safe limit for chrome.alarms)

      if (this.CONSENT_EXPIRY_HOURS > MAX_ALARM_DELAY_HOURS) {
        const consentTime = new Date(consent.timestamp).getTime();
        const expiryMs = this.CONSENT_EXPIRY_HOURS * 60 * 60 * 1000;

        if (Date.now() - consentTime > expiryMs) {
          console.log('Hera: Privacy consent expired (long-duration check)');
          await this.withdrawConsent();
          return false;
        }
      }

      // For short durations (< 30 days), alarm handles expiry
      return true;
    } catch (error) {
      console.error('Hera: Failed to check privacy consent:', error);
      return false; // Fail-safe: deny if check fails
    }
  }

  /**
   * Grant privacy consent for third-party lookups
   *
   * P2-SEVENTH-2 FIX: Only use chrome.alarms for short durations (< 30 days)
   * For long durations, rely on manual expiry check in hasPrivacyConsent()
   *
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

      // P2-SEVENTH-2 FIX: Only create alarm if duration is < 30 days
      const MAX_ALARM_DELAY_HOURS = 720; // 30 days (safe limit for chrome.alarms)
      const expiryMinutes = this.CONSENT_EXPIRY_HOURS * 60;

      if (this.CONSENT_EXPIRY_HOURS <= MAX_ALARM_DELAY_HOURS) {
        // Short duration: Use chrome.alarms
        await chrome.alarms.create('heraPrivacyConsentExpiry', {
          delayInMinutes: expiryMinutes
        });
        console.log(`Hera: Privacy consent granted, alarm set for ${expiryMinutes} minutes`);
      } else {
        // Long duration: Manual expiry check in hasPrivacyConsent()
        console.log(`Hera: Privacy consent granted for ${this.CONSENT_EXPIRY_HOURS} hours (using manual expiry check)`);
      }
    } catch (error) {
      console.error('Hera: Failed to grant privacy consent:', error);
      throw error;
    }
  }

  /**
   * Withdraw privacy consent (GDPR right to withdraw)
   *
   * P0-ARCH-2 FIX: Also clears the expiry alarm
   *
   * @returns {Promise<void>}
   */
  async withdrawConsent() {
    try {
      await chrome.storage.local.remove([this.CONSENT_KEY]);

      // P0-ARCH-2 FIX: Clear the expiry alarm
      await chrome.alarms.clear('heraPrivacyConsentExpiry');

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
