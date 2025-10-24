// Hera WebAuthn Relay - ISOLATED World
// Receives WebAuthn detection data from MAIN world and forwards to background
// TWO-SCRIPT ARCHITECTURE: MAIN world → postMessage → ISOLATED world → chrome.runtime

(function() {
  'use strict';

  console.log('Hera: WebAuthn relay initialized (ISOLATED world)');

  // Track seen nonces to prevent replay attacks
  const seenNonces = new Set();
  const MAX_NONCES = 1000; // Prevent memory leak

  // Rate limiting per page
  let messageCount = 0;
  const RATE_LIMIT = 100; // Max 100 WebAuthn detections per page load

  // Clean up nonces periodically
  setInterval(() => {
    if (seenNonces.size > MAX_NONCES) {
      seenNonces.clear();
    }
  }, 60000); // Every minute

  /**
   * Listen for messages from MAIN world
   * SECURITY: Validates origin, structure, and nonce before forwarding
   */
  window.addEventListener('message', (event) => {
    // SECURITY: Validate message structure
    if (!event.data ||
        event.data.source !== 'hera-webauthn-interceptor' ||
        event.data.type !== 'HERA_WEBAUTHN_DETECTION') {
      return; // Not our message
    }

    // SECURITY: Validate origin matches current page
    // This prevents malicious iframes from injecting fake data
    if (event.origin !== window.location.origin) {
      console.warn('Hera: WebAuthn message from wrong origin:', event.origin, 'expected:', window.location.origin);
      return;
    }

    // SECURITY: Check for replay attacks via nonce tracking
    const nonce = event.data.nonce;
    if (!nonce || seenNonces.has(nonce)) {
      console.warn('Hera: Duplicate/missing nonce in WebAuthn message');
      return;
    }
    seenNonces.add(nonce);

    // SECURITY: Rate limiting to prevent DoS
    messageCount++;
    if (messageCount > RATE_LIMIT) {
      console.warn('Hera: WebAuthn detection rate limit exceeded');
      return;
    }

    // Validate required fields
    if (!event.data.subtype || !event.data.url) {
      console.warn('Hera: Invalid WebAuthn message structure - missing required fields');
      return;
    }

    // Forward to background script via chrome.runtime (only available in ISOLATED world)
    try {
      chrome.runtime.sendMessage({
        type: 'WEBAUTHN_DETECTION',
        subtype: event.data.subtype,
        url: event.data.url,
        timestamp: event.data.timestamp,
        issues: event.data.issues || [],
        options: event.data.options || {}
      }).catch((error) => {
        // Silent fail - background may not be ready
        // This is expected when:
        // - Extension is being reloaded
        // - Background service worker is starting up
        // - Extension context is invalidated during navigation
        const DEBUG = false;
        if (DEBUG) console.warn('Hera: Failed to forward WebAuthn detection:', error.message);
      });
    } catch (error) {
      // Silent fail - don't break page JavaScript
      const DEBUG = false;
      if (DEBUG) console.warn('Hera: Error forwarding WebAuthn message:', error);
    }

  }, false);

  console.log('Hera: WebAuthn relay ready to forward messages from MAIN world to background');
})();
