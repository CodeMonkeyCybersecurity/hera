/**
 * Settings Panel
 * Manages extension settings UI and persistence
 * P0-NEW-4: Privacy consent management
 */

export class SettingsPanel {
  constructor() {
    this.panel = null;
    this.enableResponseCaptureCheckbox = null;
    this.enablePrivacyConsentCheckbox = null;
    this.privacyConsentStatus = null;
  }

  /**
   * Initialize settings panel
   */
  initialize() {
    this.panel = document.getElementById('settingsPanel');
    this.enableResponseCaptureCheckbox = document.getElementById('enableResponseCapture');
    this.enablePrivacyConsentCheckbox = document.getElementById('enablePrivacyConsent');
    this.privacyConsentStatus = document.getElementById('privacyConsentStatus');

    // Settings button
    const settingsBtn = document.getElementById('settingsBtn');
    if (settingsBtn) {
      settingsBtn.addEventListener('click', () => {
        this.show();
      });
    }

    // Close button
    const closeSettingsBtn = document.getElementById('closeSettings');
    if (closeSettingsBtn) {
      closeSettingsBtn.addEventListener('click', () => {
        this.hide();
      });
    }

    // Response capture checkbox
    if (this.enableResponseCaptureCheckbox) {
      this.enableResponseCaptureCheckbox.addEventListener('change', (e) => {
        this.handleResponseCaptureChange(e.target.checked);
      });
    }

    // Privacy consent checkbox (P0-NEW-4)
    if (this.enablePrivacyConsentCheckbox) {
      this.enablePrivacyConsentCheckbox.addEventListener('change', async (e) => {
        await this.handlePrivacyConsentChange(e.target.checked);
      });
    }
  }

  /**
   * Show settings panel
   */
  show() {
    if (this.panel) {
      this.panel.style.display = 'block';
      this.loadSettings();
    }
  }

  /**
   * Hide settings panel
   */
  hide() {
    if (this.panel) {
      this.panel.style.display = 'none';
    }
  }

  /**
   * Load current settings
   */
  loadSettings() {
    // Load response capture setting
    chrome.storage.local.get(['enableResponseCapture'], (result) => {
      const enabled = result.enableResponseCapture !== false; // Default to true
      if (this.enableResponseCaptureCheckbox) {
        this.enableResponseCaptureCheckbox.checked = enabled;
      }
    });

    // Load privacy consent status (P0-NEW-4)
    this.updatePrivacyConsentStatus();
  }

  /**
   * Handle response capture setting change
   * @param {boolean} enabled - New setting value
   */
  handleResponseCaptureChange(enabled) {
    chrome.storage.local.set({ enableResponseCapture: enabled }, () => {
      console.log('Response capture setting:', enabled);
      // Notify background script
      chrome.runtime.sendMessage({
        action: 'updateResponseCaptureSetting',
        enabled: enabled
      });
    });
  }

  /**
   * Handle privacy consent change (P0-NEW-4)
   * @param {boolean} enabled - New consent value
   */
  async handlePrivacyConsentChange(enabled) {
    if (enabled) {
      // Grant privacy consent
      try {
        const consent = {
          granted: true,
          timestamp: new Date().toISOString(),
          version: 1
        };
        await chrome.storage.local.set({ heraPrivacyConsent: consent });
        console.log('Privacy consent granted');
        await this.updatePrivacyConsentStatus();
      } catch (error) {
        console.error('Failed to grant privacy consent:', error);
        if (this.enablePrivacyConsentCheckbox) {
          this.enablePrivacyConsentCheckbox.checked = false;
        }
      }
    } else {
      // Withdraw privacy consent
      try {
        await chrome.storage.local.remove(['heraPrivacyConsent']);
        console.log('Privacy consent withdrawn');
        await this.updatePrivacyConsentStatus();
      } catch (error) {
        console.error('Failed to withdraw privacy consent:', error);
      }
    }
  }

  /**
   * Update privacy consent status display (P0-NEW-4)
   */
  async updatePrivacyConsentStatus() {
    try {
      const result = await chrome.storage.local.get(['heraPrivacyConsent']);
      const consent = result.heraPrivacyConsent;

      if (consent && consent.granted) {
        const consentDate = new Date(consent.timestamp);
        const expiryDate = new Date(consentDate.getTime() + (365 * 24 * 60 * 60 * 1000)); // 1 year

        if (this.privacyConsentStatus) {
          this.privacyConsentStatus.textContent = `Consent granted on ${consentDate.toLocaleDateString()}. Expires ${expiryDate.toLocaleDateString()}.`;
          this.privacyConsentStatus.style.color = '#28a745';
        }
        if (this.enablePrivacyConsentCheckbox) {
          this.enablePrivacyConsentCheckbox.checked = true;
        }
      } else {
        if (this.privacyConsentStatus) {
          this.privacyConsentStatus.textContent = 'No consent granted. DNS and IP geolocation features are disabled.';
          this.privacyConsentStatus.style.color = '#dc3545';
        }
        if (this.enablePrivacyConsentCheckbox) {
          this.enablePrivacyConsentCheckbox.checked = false;
        }
      }
    } catch (error) {
      console.error('Failed to update privacy consent status:', error);
    }
  }
}
