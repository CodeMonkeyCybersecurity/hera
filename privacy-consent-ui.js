/*
 * Privacy Consent UI Controller
 *
 * Handles user interaction for privacy consent (GDPR compliance)


// Import privacy consent manager
import { privacyConsentManager } from './modules/privacy-consent.js';

document.addEventListener('DOMContentLoaded', async () => {
  const grantBtn = document.getElementById('grantBtn');
  const declineBtn = document.getElementById('declineBtn');
  const statusMessage = document.getElementById('statusMessage');

  // Check if consent already exists
  const status = await privacyConsentManager.getConsentStatus();
  if (status.granted) {
    showStatus('You have already granted privacy consent. This consent is valid until ' +
                new Date(status.expiresAt).toLocaleDateString() + '.', 'success');
    grantBtn.textContent = 'Re-confirm Consent';
  }

  grantBtn.addEventListener('click', async () => {
    try {
      grantBtn.disabled = true;
      grantBtn.textContent = 'Granting...';

      await privacyConsentManager.grantConsent();

      showStatus('✅ Privacy consent granted! Hera can now perform DNS and IP geolocation lookups. You can withdraw this consent anytime in settings.', 'success');

      // Close window after 3 seconds
      setTimeout(() => {
        window.close();
      }, 3000);

    } catch (error) {
      console.error('Failed to grant privacy consent:', error);
      showStatus('❌ Failed to grant consent: ' + error.message, 'error');
      grantBtn.disabled = false;
      grantBtn.textContent = 'Grant Consent';
    }
  });

  declineBtn.addEventListener('click', async () => {
    try {
      declineBtn.disabled = true;
      declineBtn.textContent = 'Declining...';

      await privacyConsentManager.withdrawConsent();

      showStatus('Privacy consent declined. DNS and IP geolocation features will be disabled. You can grant consent later in settings.', 'error');

      // Close window after 3 seconds
      setTimeout(() => {
        window.close();
      }, 3000);

    } catch (error) {
      console.error('Failed to decline privacy consent:', error);
      showStatus('❌ Failed to decline consent: ' + error.message, 'error');
      declineBtn.disabled = false;
      declineBtn.textContent = 'Decline';
    }
  });
});

function showStatus(message, type) {
  const statusMessage = document.getElementById('statusMessage');
  statusMessage.textContent = message;
  statusMessage.className = `status ${type}`;
  statusMessage.style.display = 'block';
}
 */

