import { probeConsentManager } from './modules/probe-consent.js';

// UI Elements
const acknowledgmentInput = document.getElementById('acknowledgment');
const legalCheck = document.getElementById('legalCheck');
const responsibilityCheck = document.getElementById('responsibilityCheck');
const loggingCheck = document.getElementById('loggingCheck');
const expiryCheck = document.getElementById('expiryCheck');
const grantBtn = document.getElementById('grantBtn');
const cancelBtn = document.getElementById('cancelBtn');
const consentForm = document.getElementById('consentForm');
const probeHistoryDiv = document.getElementById('probeHistory');
const clearHistoryBtn = document.getElementById('clearHistoryBtn');

// Enable submit button only when all requirements met
function checkFormValidity() {
  const ackValid = acknowledgmentInput.value.trim() === 'I understand the risks';
  const allChecked = legalCheck.checked && responsibilityCheck.checked &&
                     loggingCheck.checked && expiryCheck.checked;

  grantBtn.disabled = !(ackValid && allChecked);
}

acknowledgmentInput.addEventListener('input', checkFormValidity);
legalCheck.addEventListener('change', checkFormValidity);
responsibilityCheck.addEventListener('change', checkFormValidity);
loggingCheck.addEventListener('change', checkFormValidity);
expiryCheck.addEventListener('change', checkFormValidity);

// Handle form submission
consentForm.addEventListener('submit', async (e) => {
  e.preventDefault();

  const success = await probeConsentManager.grantConsent({
    domains: ['*'], // Allow all domains (user has accepted responsibility)
    userAcknowledgment: acknowledgmentInput.value.trim()
  });

  if (success) {
    alert('✅ Probe consent granted for 24 hours.\n\nRemember: You are solely responsible for ensuring you have legal authorization to test target systems.');
    window.close();
  } else {
    alert('❌ Failed to grant consent. Please try again.');
  }
});

// Handle cancel
cancelBtn.addEventListener('click', () => {
  window.close();
});

// Load and display probe history
async function loadProbeHistory() {
  const history = await probeConsentManager.getProbeHistory();

  if (history.length === 0) {
    const emptyMsg = document.createElement('p');
    emptyMsg.style.color = '#666';
    emptyMsg.textContent = 'No probes executed yet.';
    probeHistoryDiv.textContent = ''; // Clear
    probeHistoryDiv.appendChild(emptyMsg);
    return;
  }

  // P2-TENTH-3 FIX: Use DOM methods instead of innerHTML to prevent XSS
  // entry.targetDomain is user-controlled, could contain malicious HTML if storage compromised
  probeHistoryDiv.textContent = ''; // Clear existing content

  history.reverse().slice(0, 20).forEach(entry => {
    const logEntry = document.createElement('div');
    logEntry.className = 'log-entry';

    const statusSpan = document.createElement('span');
    statusSpan.className = entry.success ? 'success' : 'error';
    statusSpan.textContent = entry.success ? '✓' : '✗';

    const probeType = document.createElement('strong');
    probeType.textContent = entry.probeType.toUpperCase();

    const targetDomain = document.createTextNode(entry.targetDomain); // Safe - text node
    const separator1 = document.createTextNode(' → ');
    const separator2 = document.createTextNode(' | ');
    const timestamp = document.createTextNode(new Date(entry.timestamp).toLocaleString());

    logEntry.appendChild(statusSpan);
    logEntry.appendChild(document.createTextNode(' '));
    logEntry.appendChild(probeType);
    logEntry.appendChild(separator1);
    logEntry.appendChild(targetDomain);
    logEntry.appendChild(separator2);
    logEntry.appendChild(timestamp);

    probeHistoryDiv.appendChild(logEntry);
  });
}

// Clear history
clearHistoryBtn.addEventListener('click', async () => {
  if (confirm('Clear all probe history? This cannot be undone.')) {
    await probeConsentManager.clearProbeHistory();
    loadProbeHistory();
  }
});

// Load history on page load
loadProbeHistory();

// Check current consent status
(async () => {
  const consent = await probeConsentManager.getConsent();
  if (consent && consent.enabled) {
    const grantedDate = new Date(consent.timestamp);
    const expiryDate = new Date(grantedDate.getTime() + 24 * 60 * 60 * 1000);
    const timeLeft = expiryDate.getTime() - Date.now();

    if (timeLeft > 0) {
      const hoursLeft = Math.floor(timeLeft / (60 * 60 * 1000));
      const minutesLeft = Math.floor((timeLeft % (60 * 60 * 1000)) / (60 * 1000));

      const status = document.createElement('div');
      status.className = 'warning';
      status.innerHTML = `
        <h2>✅ Consent Currently Active</h2>
        <p>Expires in: <strong>${hoursLeft}h ${minutesLeft}m</strong></p>
        <p>Granted: ${grantedDate.toLocaleString()}</p>
        <button type="button" id="revokeBtn" class="btn-danger" style="margin-top: 10px;">
          Revoke Consent Immediately
        </button>
      `;
      consentForm.parentElement.insertBefore(status, consentForm);

      document.getElementById('revokeBtn').addEventListener('click', async () => {
        if (confirm('Revoke probe consent? You will need to re-consent to use security probes.')) {
          await probeConsentManager.revokeConsent();
          alert('✅ Consent revoked');
          window.close();
        }
      });
    }
  }
})();
