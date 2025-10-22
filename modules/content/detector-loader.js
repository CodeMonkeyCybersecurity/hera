// Hera Detector Loader
// Handles loading and initialization of detector modules

import { createStubDetectors } from './content-utils.js';

let detectorsLoaded = false;
let detectors = null;
let loadingPromise = null; // CRITICAL FIX NEW-P0-2: Mutex for concurrent loading

/**
 * AUTH-ONLY MODE: Content script detectors disabled
 * All non-auth detectors removed from manifest.json
 * Auth detection now handled exclusively by background.js via webRequest listeners
 *
 * @returns {Promise<Object>} Empty detector object (for backward compatibility)
 */
export async function loadDetectors() {
  // Return cached detectors if already loaded
  if (detectorsLoaded && detectors) {
    return detectors;
  }

  // AUTH-ONLY MODE: No content script detectors loaded
  // All detection happens in background.js via HTTP interception
  console.log('Hera: Auth-only mode - content script detectors disabled');

  detectors = {
    // Return empty/stub detectors for backward compatibility
    subdomainImpersonationDetector: null,
    darkPatternDetector: null,
    phishingDetector: null,
    privacyViolationDetector: null,
    riskScoringEngine: null
  };

  detectorsLoaded = true;
  return detectors;
}

/**
 * SECURITY FIX P1-1: Request isolated world injection from background script
 * This prevents malicious pages from intercepting or poisoning the response data
 */
export function requestInterceptorInjection() {
  // Generate unique nonce for this page
  const injectionNonce = crypto.randomUUID ? crypto.randomUUID() : Math.random().toString(36).substring(2);
  window.__HERA_INJECTION_NONCE__ = injectionNonce;

  // Request background script to inject interceptor in isolated world
  // P1-SIXTEENTH-1 FIX: CSP failures are expected on many sites - don't log errors
  chrome.runtime.sendMessage({
    type: 'INJECT_RESPONSE_INTERCEPTOR',
    nonce: injectionNonce,
    tabId: null // Background will use sender.tab.id
  }).then(response => {
    if (response?.success) {
      const DEBUG = false;
      if (DEBUG) console.log('Hera: Response interceptor injected in isolated world');
    } else {
      // P1-SIXTEENTH-1 FIX: Downgrade to debug log - CSP blocking is normal and expected
      const DEBUG = false;
      if (DEBUG && response?.error) {
        console.log('Hera: Response interceptor not injected:', response.error);
      }
    }
  }).catch(error => {
    // P1-SIXTEENTH-1 FIX: Only log if DEBUG enabled - CSP errors are expected
    const DEBUG = false;
    if (DEBUG) console.log('Hera: Error requesting interceptor injection:', error.message);
  });

  // SECURITY FIX P1-1: Nonce tracking no longer needed
  // Response interceptor runs in isolated world and sends directly to background
  // No need for replay attack prevention since messages don't go through postMessage

  // SECURITY FIX P1-1: Removed window.addEventListener for postMessage
  // Response interceptor now runs in ISOLATED world and sends directly to background
  // via chrome.runtime.sendMessage, so we no longer need to:
  //   1. Listen for window.postMessage events
  //   2. Validate nonces (isolated world is inherently secure)
  //   3. Check for replay attacks (no cross-context messaging)
  //   4. Forward messages to background (interceptor sends directly)

  console.log('Hera: Response interception uses isolated world injection (no postMessage relay needed)');
}
