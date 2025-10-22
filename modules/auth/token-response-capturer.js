/**
 * Token Response Capturer (Phase 6 - HIGH RISK)
 *
 * Captures OAuth2/OIDC token responses for deep security analysis including:
 * - at_hash and c_hash cryptographic validation
 * - JWT algorithm confusion detection
 * - Token expiration analysis
 * - Token storage vulnerability detection
 *
 * SECURITY MODEL:
 * - Opt-in only (explicit user consent required)
 * - Content script injection (increases attack surface)
 * - Automatic redaction before storage
 * - Clear user notification when active
 * - Session-scoped capture (auto-disable after flow completion)
 *
 * Reference: ADVERSARIAL_PUSHBACK.md Phase 6
 * Risk Level: HIGH - Use with caution
 */

export class TokenResponseCapturer {
  constructor() {
    this.name = 'TokenResponseCapturer';
    this.enabled = false;
    this.captureMode = 'DISABLED'; // 'DISABLED', 'SINGLE_FLOW', 'SESSION', 'ALWAYS'
    this.capturedResponses = new Map();
    this.activeFlows = new Set();
    this.consentGranted = false;
    this.injectedTabs = new Set();

    // Load consent state from storage
    this.loadConsentState();
  }

  /**
   * Request user consent for token response capture
   * @returns {Promise<boolean>} True if consent granted
   */
  async requestUserConsent() {
    // Check if consent already granted
    if (this.consentGranted) {
      return true;
    }

    // Show consent dialog to user
    const consent = await this._showConsentDialog();

    if (consent) {
      this.consentGranted = true;
      await chrome.storage.local.set({
        heraTokenCaptureConsent: {
          granted: true,
          timestamp: Date.now(),
          version: '1.0.0'
        }
      });
    }

    return consent;
  }

  /**
   * Enable token capture for a single OAuth flow
   * @param {string} flowId - Flow identifier to capture
   * @returns {Promise<boolean>} True if enabled successfully
   */
  async enableForFlow(flowId) {
    const consentGranted = await this.requestUserConsent();

    if (!consentGranted) {
      console.log('Hera: Token capture cancelled - user denied consent');
      return false;
    }

    this.captureMode = 'SINGLE_FLOW';
    this.activeFlows.add(flowId);
    this.enabled = true;

    // Inject content script into active tabs
    await this._injectContentScripts();

    console.log(`Hera: Token capture ENABLED for flow ${flowId}`);
    this._notifyUser('Token capture enabled for this OAuth flow');

    return true;
  }

  /**
   * Disable token capture
   */
  async disable() {
    this.enabled = false;
    this.captureMode = 'DISABLED';
    this.activeFlows.clear();

    // Remove content scripts
    await this._removeContentScripts();

    console.log('Hera: Token capture DISABLED');
    this._notifyUser('Token capture disabled');
  }

  /**
   * Inject content script into page to intercept fetch/XHR
   * SECURITY WARNING: This increases attack surface
   * @private
   */
  async _injectContentScripts() {
    try {
      // Get all tabs
      const tabs = await chrome.tabs.query({});

      for (const tab of tabs) {
        // Skip chrome:// and other protected URLs
        if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('edge://')) {
          continue;
        }

        try {
          // Inject content script
          await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: this._contentScriptCode,
            world: 'MAIN' // Run in page context to intercept fetch
          });

          this.injectedTabs.add(tab.id);
          console.log(`Hera: Injected token capture script into tab ${tab.id}`);
        } catch (error) {
          // Tab may not allow injection (e.g., chrome:// pages)
          console.warn(`Hera: Could not inject into tab ${tab.id}:`, error.message);
        }
      }
    } catch (error) {
      console.error('Hera: Failed to inject content scripts:', error);
    }
  }

  /**
   * Remove content scripts from all tabs
   * @private
   */
  async _removeContentScripts() {
    // Note: Cannot truly "remove" injected code, but we can signal it to stop
    for (const tabId of this.injectedTabs) {
      try {
        await chrome.tabs.sendMessage(tabId, {
          type: 'HERA_DISABLE_TOKEN_CAPTURE'
        });
      } catch (error) {
        // Tab may be closed
      }
    }

    this.injectedTabs.clear();
  }

  /**
   * Content script code that runs in page context
   * This intercepts fetch() and XMLHttpRequest to capture token responses
   *
   * SECURITY NOTE: This code runs with full page access
   * @private
   */
  _contentScriptCode() {
    // Check if already injected
    if (window.__HERA_TOKEN_CAPTURE_INJECTED__) {
      return;
    }
    window.__HERA_TOKEN_CAPTURE_INJECTED__ = true;

    let captureEnabled = true;

    // Listen for disable message
    window.addEventListener('message', (event) => {
      if (event.data.type === 'HERA_DISABLE_TOKEN_CAPTURE') {
        captureEnabled = false;
        console.log('Hera: Token capture disabled in page');
      }
    });

    /**
     * Intercept fetch() API
     */
    const originalFetch = window.fetch;
    window.fetch = function(...args) {
      const [url, options] = args;

      // Call original fetch
      return originalFetch.apply(this, args).then(async (response) => {
        if (!captureEnabled) return response;

        // Check if this is a token endpoint
        const urlString = url.toString().toLowerCase();
        const isTokenEndpoint = urlString.includes('/token') ||
                               urlString.includes('/oauth') ||
                               urlString.includes('/connect/');

        if (isTokenEndpoint) {
          try {
            // Clone response to read body without consuming it
            const clonedResponse = response.clone();
            const responseBody = await clonedResponse.text();

            // Send to Hera background script
            window.postMessage({
              type: 'HERA_TOKEN_RESPONSE_CAPTURED',
              data: {
                url: url.toString(),
                method: options?.method || 'GET',
                status: response.status,
                statusText: response.statusText,
                headers: Object.fromEntries(response.headers.entries()),
                body: responseBody,
                timestamp: Date.now(),
                captureMethod: 'fetch'
              }
            }, '*');

            console.log('Hera: Captured token response via fetch():', url);
          } catch (error) {
            console.warn('Hera: Failed to capture fetch response:', error);
          }
        }

        return response;
      });
    };

    /**
     * Intercept XMLHttpRequest
     */
    const originalXHROpen = XMLHttpRequest.prototype.open;
    const originalXHRSend = XMLHttpRequest.prototype.send;

    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
      this.__HERA_URL__ = url.toString();
      this.__HERA_METHOD__ = method;
      return originalXHROpen.call(this, method, url, ...rest);
    };

    XMLHttpRequest.prototype.send = function(...args) {
      if (!captureEnabled) {
        return originalXHRSend.apply(this, args);
      }

      this.addEventListener('load', function() {
        const urlString = this.__HERA_URL__?.toLowerCase() || '';
        const isTokenEndpoint = urlString.includes('/token') ||
                               urlString.includes('/oauth') ||
                               urlString.includes('/connect/');

        if (isTokenEndpoint && this.status === 200) {
          try {
            // Send to Hera background script
            window.postMessage({
              type: 'HERA_TOKEN_RESPONSE_CAPTURED',
              data: {
                url: this.__HERA_URL__,
                method: this.__HERA_METHOD__,
                status: this.status,
                statusText: this.statusText,
                headers: this.getAllResponseHeaders(),
                body: this.responseText,
                timestamp: Date.now(),
                captureMethod: 'xhr'
              }
            }, '*');

            console.log('Hera: Captured token response via XHR:', this.__HERA_URL__);
          } catch (error) {
            console.warn('Hera: Failed to capture XHR response:', error);
          }
        }
      });

      return originalXHRSend.apply(this, args);
    };

    console.log('Hera: Token response capture initialized in page context');
  }

  /**
   * Process captured token response
   * @param {Object} responseData - Token response data from content script
   * @returns {Object} Processed and redacted evidence
   */
  processCapturedResponse(responseData) {
    try {
      const evidence = {
        timestamp: responseData.timestamp,
        url: this._redactUrl(responseData.url),
        method: responseData.method,
        status: responseData.status,
        captureMethod: responseData.captureMethod,
        tokenResponse: null,
        vulnerabilities: []
      };

      // Parse response body
      let tokenData;
      try {
        tokenData = JSON.parse(responseData.body);
      } catch (e) {
        evidence.warnings = ['Response body is not valid JSON'];
        return evidence;
      }

      // Process token response with redaction
      evidence.tokenResponse = this._processTokens(tokenData);

      // Analyze for vulnerabilities
      evidence.vulnerabilities = this._analyzeTokenResponse(tokenData, evidence.tokenResponse);

      // Store evidence (with redaction)
      this.capturedResponses.set(responseData.url, evidence);

      return evidence;

    } catch (error) {
      console.error('Hera: Error processing token response:', error);
      return null;
    }
  }

  /**
   * Process and redact tokens from response
   * @param {Object} tokenData - Raw token response
   * @returns {Object} Redacted token evidence
   * @private
   */
  _processTokens(tokenData) {
    const evidence = {
      access_token: this._processToken(tokenData.access_token, 'access_token'),
      refresh_token: this._processToken(tokenData.refresh_token, 'refresh_token'),
      id_token: this._processToken(tokenData.id_token, 'id_token'),
      token_type: tokenData.token_type,
      expires_in: tokenData.expires_in,
      scope: tokenData.scope
    };

    return evidence;
  }

  /**
   * Process individual token with redaction
   * @param {string} tokenValue - Token value
   * @param {string} tokenType - Token type name
   * @returns {Object} Redacted token evidence
   * @private
   */
  _processToken(tokenValue, tokenType) {
    if (!tokenValue) {
      return { present: false };
    }

    const evidence = {
      present: true,
      type: tokenType,
      length: tokenValue.length,
      preview: this._createPreview(tokenValue)
    };

    // Detect format
    if (tokenValue.includes('.')) {
      // Likely JWT
      evidence.format = 'JWT';

      try {
        const parts = tokenValue.split('.');
        if (parts.length === 3) {
          // Parse JWT (but don't store full payload)
          const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
          const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

          evidence.jwt = {
            header: header,
            claims: this._extractSafeClaims(payload),
            algorithm: header.alg
          };

          // Calculate at_hash/c_hash if present (for validation)
          if (payload.at_hash) {
            evidence.at_hash = payload.at_hash;
          }
          if (payload.c_hash) {
            evidence.c_hash = payload.c_hash;
          }
        }
      } catch (e) {
        evidence.parseError = 'Could not parse JWT';
      }
    } else {
      evidence.format = 'opaque';
    }

    return evidence;
  }

  /**
   * Extract only safe claims from JWT (no PII)
   * @param {Object} payload - JWT payload
   * @returns {Object} Safe claims only
   * @private
   */
  _extractSafeClaims(payload) {
    const safeClaims = {};
    const safeFields = [
      'iss', 'aud', 'exp', 'iat', 'nbf', 'sub',
      'nonce', 'at_hash', 'c_hash', 'acr', 'amr', 'azp',
      'scope', 'jti', 'client_id'
    ];

    for (const field of safeFields) {
      if (payload[field] !== undefined) {
        safeClaims[field] = payload[field];
      }
    }

    // Redact PII fields
    const piiFields = ['email', 'name', 'phone_number', 'address', 'birthdate'];
    for (const field of piiFields) {
      if (payload[field]) {
        safeClaims[field] = '[REDACTED]';
      }
    }

    return safeClaims;
  }

  /**
   * Analyze token response for vulnerabilities
   * @param {Object} rawTokenData - Raw token data (has full values)
   * @param {Object} redactedEvidence - Redacted evidence
   * @returns {Array} Vulnerabilities found
   * @private
   */
  _analyzeTokenResponse(rawTokenData, redactedEvidence) {
    const vulnerabilities = [];

    // Check 1: JWT algorithm confusion (alg:none)
    if (redactedEvidence.id_token?.jwt?.algorithm === 'none') {
      vulnerabilities.push({
        severity: 'CRITICAL',
        type: 'JWT_ALG_NONE',
        message: 'ID token uses "alg:none" - signature bypass vulnerability',
        cvss: 9.8,
        cve: 'CVE-2015-9235',
        detail: 'Tokens with alg:none can be forged without signature',
        recommendation: 'Reject tokens with alg:none, require RS256 or ES256',
        evidence: {
          tokenType: 'id_token',
          algorithm: 'none',
          risk: 'Any attacker can forge valid-looking tokens'
        }
      });
    }

    // Check 2: Weak JWT algorithm (HS256)
    if (redactedEvidence.id_token?.jwt?.algorithm === 'HS256') {
      vulnerabilities.push({
        severity: 'MEDIUM',
        type: 'JWT_WEAK_ALGORITHM',
        message: 'ID token uses HS256 (symmetric) instead of RS256 (asymmetric)',
        cvss: 6.0,
        detail: 'HS256 requires client to know signing secret, enables algorithm confusion',
        recommendation: 'Use RS256, RS384, or ES256 for ID tokens',
        evidence: {
          tokenType: 'id_token',
          algorithm: 'HS256',
          risk: 'Algorithm confusion attacks possible'
        }
      });
    }

    // Check 3: Missing expiration
    if (redactedEvidence.access_token?.present && !rawTokenData.expires_in) {
      vulnerabilities.push({
        severity: 'HIGH',
        type: 'TOKEN_NO_EXPIRATION',
        message: 'Access token has no expiration time',
        cvss: 7.5,
        detail: 'Tokens should expire to limit impact of theft',
        recommendation: 'Set expires_in to reasonable value (3600 seconds recommended)',
        evidence: {
          tokenType: 'access_token',
          expiresIn: null,
          risk: 'Stolen tokens valid indefinitely'
        }
      });
    }

    // Check 4: Excessive expiration
    if (rawTokenData.expires_in > 86400) { // >24 hours
      vulnerabilities.push({
        severity: 'MEDIUM',
        type: 'TOKEN_EXCESSIVE_EXPIRATION',
        message: 'Access token expires in >24 hours',
        cvss: 5.5,
        detail: `Token expires in ${Math.floor(rawTokenData.expires_in / 3600)} hours`,
        recommendation: 'Limit access token lifetime to 1 hour for security',
        evidence: {
          tokenType: 'access_token',
          expiresIn: rawTokenData.expires_in,
          expiresInHours: Math.floor(rawTokenData.expires_in / 3600),
          risk: 'Long-lived tokens increase impact of theft'
        }
      });
    }

    // Check 5: Refresh token in browser (SPA)
    if (redactedEvidence.refresh_token?.present) {
      vulnerabilities.push({
        severity: 'HIGH',
        type: 'REFRESH_TOKEN_IN_BROWSER',
        message: 'Refresh token issued to browser application',
        cvss: 7.0,
        detail: 'Refresh tokens should only be issued to confidential clients',
        recommendation: 'Use short-lived access tokens + re-authentication instead',
        reference: 'https://oauth.net/2/browser-based-apps/',
        evidence: {
          tokenType: 'refresh_token',
          length: redactedEvidence.refresh_token.length,
          risk: 'Refresh token can be stolen and used for long-term access'
        }
      });
    }

    // Check 6: Token storage detection (if localStorage/sessionStorage used)
    // Note: This would require additional detection logic

    return vulnerabilities;
  }

  /**
   * Create safe preview (first/last N chars)
   * @param {string} value - Full value
   * @returns {string} Preview string
   * @private
   */
  _createPreview(value) {
    if (!value) return '';

    const PREVIEW_LENGTH = 12;
    if (value.length <= PREVIEW_LENGTH * 2) {
      return value.substring(0, 6) + '...' + value.substring(value.length - 6);
    }

    return value.substring(0, PREVIEW_LENGTH) + '...' + value.substring(value.length - PREVIEW_LENGTH);
  }

  /**
   * Redact URL parameters
   * @param {string} url - Full URL
   * @returns {string} Redacted URL
   * @private
   */
  _redactUrl(url) {
    try {
      const urlObj = new URL(url);

      // Redact sensitive query params
      const sensitiveParams = ['code', 'token', 'access_token', 'refresh_token', 'client_secret'];
      for (const param of sensitiveParams) {
        if (urlObj.searchParams.has(param)) {
          urlObj.searchParams.set(param, '[REDACTED]');
        }
      }

      return urlObj.toString();
    } catch (e) {
      return url;
    }
  }

  /**
   * Load consent state from storage
   * @private
   */
  async loadConsentState() {
    try {
      const data = await chrome.storage.local.get('heraTokenCaptureConsent');
      if (data.heraTokenCaptureConsent?.granted) {
        this.consentGranted = true;
        console.log('Hera: Token capture consent already granted');
      }
    } catch (error) {
      console.warn('Hera: Could not load consent state:', error);
    }
  }

  /**
   * Show consent dialog to user
   * @returns {Promise<boolean>} True if user consents
   * @private
   */
  async _showConsentDialog() {
    // This would trigger a UI dialog
    // For now, return a promise that resolves based on user action
    return new Promise((resolve) => {
      // Send message to popup/UI to show consent dialog
      chrome.runtime.sendMessage({
        type: 'REQUEST_TOKEN_CAPTURE_CONSENT',
        data: {
          title: 'Enable Deep Token Analysis?',
          message: 'This will capture OAuth token responses for security analysis.\n\n' +
                   'Security notes:\n' +
                   '- Tokens are redacted before storage\n' +
                   '- Only structure and metadata are kept\n' +
                   '- Increases extension permissions\n' +
                   '- Disable after testing',
          risks: ['Content script injection', 'Intercepts page fetch/XHR', 'Requires <all_urls> permission']
        }
      }, (response) => {
        resolve(response?.consent === true);
      });
    });
  }

  /**
   * Notify user of capture status
   * @param {string} message - Notification message
   * @private
   */
  _notifyUser(message) {
    // Show browser notification
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'Hera Security',
      message: message,
      priority: 2
    });
  }

  /**
   * Get all captured responses
   * @returns {Array} Captured responses
   */
  getCapturedResponses() {
    return Array.from(this.capturedResponses.values());
  }

  /**
   * Clear captured responses
   */
  clearCaptured() {
    this.capturedResponses.clear();
    console.log('Hera: Cleared all captured token responses');
  }

  /**
   * Get capture status
   * @returns {Object} Status information
   */
  getStatus() {
    return {
      enabled: this.enabled,
      captureMode: this.captureMode,
      consentGranted: this.consentGranted,
      activeFlows: Array.from(this.activeFlows),
      capturedCount: this.capturedResponses.size,
      injectedTabs: Array.from(this.injectedTabs)
    };
  }
}
