/**
 * Response Body Capturer - P0-A: BLOCKER for RFC 9700 and MFA Detection
 *
 * PURPOSE:
 * - Capture response bodies for OAuth2 token responses (DPoP validation)
 * - Capture WebAuthn challenges (MFA detection)
 * - Capture TOTP/OTP responses (MFA detection)
 * - Enable evidence-based security analysis of response data
 *
 * ARCHITECTURE:
 * Uses chrome.debugger API to intercept Network.responseReceived events
 *
 * SECURITY:
 * - Only captures auth-related responses (filtered by URL patterns)
 * - Applies 3-tier redaction based on risk level
 * - Never stores plaintext tokens in persistent storage
 * - Uses secure hashing for token tracking (see RefreshTokenTracker)
 *
 * PRIVACY:
 * - User must explicitly grant debugger permission
 * - Clear notification when debugger is active
 * - Can be disabled in settings
 * - Response bodies are ephemeral (not saved to IndexedDB)
 *
 * @see ROADMAP.md P0-A for implementation details
 * @see CLAUDE.md Part 7 for adversarial analysis
 */

export class ResponseBodyCapturer {
  constructor(authRequests, evidenceCollector, refreshTokenTracker = null) {
    this.authRequests = authRequests;
    this.evidenceCollector = evidenceCollector;
    this.refreshTokenTracker = refreshTokenTracker;
    this.activeDebuggees = new Map(); // tabId -> debuggee
    this.requestIdMap = new Map(); // debugger requestId -> webRequest requestId
    this.enabled = false;

    // URL patterns that indicate auth-related responses needing body capture
    this.authResponsePatterns = [
      // OAuth2 token endpoints
      /\/oauth2?\/v?[\d.]*\/token/i,
      /\/token$/i,

      // WebAuthn/FIDO2 endpoints
      /\/webauthn\//i,
      /\/fido2?\//i,
      /\/(begin|complete)[-_]?authentication/i,

      // MFA/OTP endpoints
      /\/(mfa|2fa|otp|verify|authenticate)/i,

      // OpenID Connect
      /\/\.well-known\/openid-configuration/i,
      /\/userinfo/i,

      // SAML
      /\/saml2?\/acs/i,

      // Microsoft-specific
      /login\.microsoftonline\.com.*\/token/i,

      // Auth0
      /\.auth0\.com.*\/oauth\/token/i,

      // Okta
      /\.okta\.com.*\/oauth2\/.*\/token/i,
      /\.okta\.com.*\/api\/v1\/authn/i,
    ];
  }

  /**
   * Check if response body capture is supported and enabled
   */
  async isSupported() {
    // Check if debugger API is available
    if (!chrome.debugger) {
      console.warn('[ResponseCapture] chrome.debugger API not available');
      return false;
    }

    // Check if we have debugger permission
    const hasPermission = await chrome.permissions.contains({
      permissions: ['debugger']
    });

    if (!hasPermission) {
      console.warn('[ResponseCapture] debugger permission not granted');
      return false;
    }

    return true;
  }

  /**
   * Initialize response body capture for a specific tab
   *
   * NOTE: This requires user consent as it shows "DevTools is debugging this browser" notification
   */
  async attachToTab(tabId) {
    if (!await this.isSupported()) {
      return false;
    }

    const debuggee = { tabId };

    try {
      // Attach debugger to tab
      await chrome.debugger.attach(debuggee, '1.3');

      // Enable Network domain to receive response events
      await chrome.debugger.sendCommand(debuggee, 'Network.enable');

      // Store debuggee reference
      this.activeDebuggees.set(tabId, debuggee);

      // Set up event listener for this tab
      this._setupEventListener(debuggee);

      console.log(`[ResponseCapture] Attached to tab ${tabId}`);
      return true;

    } catch (error) {
      console.error(`[ResponseCapture] Failed to attach to tab ${tabId}:`, error);
      return false;
    }
  }

  /**
   * Detach debugger from a tab
   */
  async detachFromTab(tabId) {
    const debuggee = this.activeDebuggees.get(tabId);
    if (!debuggee) {
      return;
    }

    try {
      await chrome.debugger.detach(debuggee);
      this.activeDebuggees.delete(tabId);
      console.log(`[ResponseCapture] Detached from tab ${tabId}`);
    } catch (error) {
      console.error(`[ResponseCapture] Failed to detach from tab ${tabId}:`, error);
    }
  }

  /**
   * Set up debugger event listener for Network.responseReceived
   */
  _setupEventListener(debuggee) {
    chrome.debugger.onEvent.addListener((source, method, params) => {
      // Only process events from our debuggee
      if (source.tabId !== debuggee.tabId) {
        return;
      }

      // We care about Network.responseReceived events
      if (method === 'Network.responseReceived') {
        this._handleResponseReceived(source, params);
      }
    });

    // Handle debugger detach (user closes DevTools or tab closes)
    chrome.debugger.onDetach.addListener((source, reason) => {
      if (source.tabId === debuggee.tabId) {
        console.log(`[ResponseCapture] Debugger detached from tab ${debuggee.tabId}: ${reason}`);
        this.activeDebuggees.delete(debuggee.tabId);
      }
    });
  }

  /**
   * Handle Network.responseReceived event from debugger
   */
  async _handleResponseReceived(debuggee, params) {
    const { requestId, response } = params;
    const url = response.url;

    // Check if this is an auth-related response
    if (!this._isAuthResponse(url)) {
      return;
    }

    // CRITICAL FIX: Check response size before fetching body
    const MAX_RESPONSE_SIZE = 1048576; // 1MB
    const contentLength = response.headers && (
      response.headers['content-length'] ||
      response.headers['Content-Length']
    );

    if (contentLength && parseInt(contentLength) > MAX_RESPONSE_SIZE) {
      console.warn(`[ResponseCapture] Response too large (${contentLength} bytes), skipping: ${url}`);
      return;
    }

    console.debug(`[ResponseCapture] Auth response detected: ${url}`);

    try {
      // Get response body from debugger
      const { body, base64Encoded } = await chrome.debugger.sendCommand(
        debuggee,
        'Network.getResponseBody',
        { requestId }
      );

      // CRITICAL FIX: Double-check actual body size
      if (body && body.length > MAX_RESPONSE_SIZE) {
        console.warn(`[ResponseCapture] Response body exceeds 1MB (${body.length} bytes), truncating: ${url}`);
        return;
      }

      // Decode if base64
      let responseBody = body;
      if (base64Encoded) {
        responseBody = atob(body);
      }

      // Find corresponding webRequest requestId
      const webRequestId = this._findWebRequestId(url, response.headers);

      if (!webRequestId) {
        console.warn('[ResponseCapture] Could not match debugger response to webRequest');
        return;
      }

      // Store response body in authRequests
      const requestData = this.authRequests.get(webRequestId);
      if (requestData) {
        // CRITICAL FIX: Parse and track BEFORE redaction
        let parsedBody = null;
        try {
          parsedBody = JSON.parse(responseBody);

          // Track refresh tokens BEFORE redaction (needs plaintext)
          if (this.refreshTokenTracker && this._isTokenResponse(url)) {
            const domain = new URL(url).hostname;
            const rotationFinding = await this.refreshTokenTracker.trackRefreshToken(
              parsedBody,
              domain
            );

            // Add finding to metadata if token rotation violation detected
            if (rotationFinding) {
              if (!requestData.metadata.securityFindings) {
                requestData.metadata.securityFindings = [];
              }
              requestData.metadata.securityFindings.push(rotationFinding);
              console.debug(`[ResponseCapture] Refresh token rotation violation detected for ${domain}`);
            }
          }
        } catch (error) {
          // Not JSON or parsing failed - skip token tracking
          console.debug(`[ResponseCapture] Response body not JSON, skipping token tracking`);
        }

        // NOW apply redaction for storage
        const redactedBody = this._redactResponseBody(responseBody, url, response.headers);

        requestData.responseBody = redactedBody;
        requestData.metadata.responseBodyCaptured = true;
        requestData.metadata.responseBodyCaptureMethod = 'debugger';

        this.authRequests.set(webRequestId, requestData);

        console.debug(`[ResponseCapture] Captured response body for ${url}`);

        // Pass to evidence collector for DPoP/WebAuthn analysis
        if (this.evidenceCollector) {
          this.evidenceCollector.processResponseBody(webRequestId, redactedBody, url, this.authRequests);
        }
      }

    } catch (error) {
      // CRITICAL FIX: Handle specific error cases
      if (error.message && (error.message.includes('No tab with id') ||
                            error.message.includes('No frame') ||
                            error.message.includes('Target closed'))) {
        // Tab closed before response received - this is normal
        console.debug(`[ResponseCapture] Tab closed before response captured for ${url}`);
        return;
      }

      if (error.message && error.message.includes('No resource with given identifier')) {
        // Response body not available (e.g., 204 No Content, redirect)
        console.debug(`[ResponseCapture] No response body available for ${url}`);
        return;
      }

      // Other errors should be logged
      console.warn(`[ResponseCapture] Error capturing response body for ${url}:`, error.message);
    }
  }

  /**
   * Check if URL matches auth response patterns
   */
  _isAuthResponse(url) {
    try {
      const urlLower = url.toLowerCase();
      return this.authResponsePatterns.some(pattern => pattern.test(urlLower));
    } catch (error) {
      return false;
    }
  }

  /**
   * Find corresponding webRequest requestId for a debugger response
   *
   * CHALLENGE: debugger API and webRequest API use different requestId formats
   * SOLUTION: Match by URL + timing window, prefer closest timestamp
   *
   * CRITICAL FIX: Now uses best-match algorithm to handle duplicate URLs
   */
  _findWebRequestId(url, responseHeaders, responseTime = null) {
    const now = responseTime || Date.now();
    const matchWindow = 5000; // 5 second window

    let bestMatch = null;
    let bestTimeDiff = Infinity;

    for (const [requestId, requestData] of this.authRequests.entries()) {
      // Must match URL
      if (requestData.url !== url) continue;

      const requestTime = new Date(requestData.timestamp).getTime();
      const timeDiff = Math.abs(now - requestTime);

      // Within match window?
      if (timeDiff > matchWindow) continue;

      // Prefer closest timestamp match (handles duplicate URLs)
      if (timeDiff < bestTimeDiff) {
        bestMatch = requestId;
        bestTimeDiff = timeDiff;
      }
    }

    if (!bestMatch) {
      console.warn('[ResponseCapture] No matching webRequest found for debugger response:', url);
    }

    return bestMatch;
  }

  /**
   * Redact sensitive data from response bodies
   *
   * SECURITY: 3-tier redaction based on risk level
   *
   * @see CLAUDE.md Part 7 - Adversarial Analysis on token redaction
   */
  _redactResponseBody(body, url, headers) {
    // Determine content type
    const contentTypeHeader = headers && Object.entries(headers).find(
      ([name]) => name.toLowerCase() === 'content-type'
    );
    const contentType = contentTypeHeader ? contentTypeHeader[1] : '';

    // Only process JSON responses (most auth responses are JSON)
    if (!contentType.includes('application/json')) {
      return '[NON-JSON RESPONSE - NOT CAPTURED]';
    }

    try {
      const data = JSON.parse(body);

      // HIGH RISK: Token responses (OAuth2 /token endpoint)
      if (this._isTokenResponse(url)) {
        return this._redactTokenResponse(data);
      }

      // MEDIUM RISK: MFA challenges (WebAuthn, TOTP)
      if (this._isMFAResponse(url)) {
        return this._redactMFAResponse(data);
      }

      // LOW RISK: Metadata responses (OpenID configuration, userinfo)
      if (this._isMetadataResponse(url)) {
        return data; // No redaction needed
      }

      // Default: redact any field that looks like a token
      return this._redactGenericResponse(data);

    } catch (error) {
      // Not valid JSON
      return '[INVALID JSON - NOT CAPTURED]';
    }
  }

  /**
   * Check if this is an OAuth2 token response
   */
  _isTokenResponse(url) {
    return /\/oauth2?\/.*\/token/i.test(url) || /\/token$/i.test(url);
  }

  /**
   * Check if this is an MFA response
   */
  _isMFAResponse(url) {
    return /\/(webauthn|fido2?|mfa|2fa|otp|verify|authenticate)/i.test(url);
  }

  /**
   * Check if this is a metadata response (safe, no secrets)
   */
  _isMetadataResponse(url) {
    return /\.well-known\/openid-configuration/i.test(url) ||
           /\/userinfo/i.test(url);
  }

  /**
   * Redact OAuth2 token responses
   *
   * HIGH RISK FIELDS (full redaction):
   * - access_token (valid for 1 hour, can access APIs)
   * - refresh_token (valid for 90 days, can get new access tokens)
   * - id_token (contains PII)
   *
   * LOW RISK FIELDS (keep for analysis):
   * - token_type (needed for DPoP detection: "DPoP" vs "Bearer")
   * - expires_in (needed for session lifetime analysis)
   * - scope (needed for privilege analysis)
   */
  _redactTokenResponse(data) {
    const redacted = { ...data };

    // HIGH RISK: Fully redact tokens
    if (redacted.access_token) {
      redacted.access_token = `[REDACTED_ACCESS_TOKEN length=${data.access_token.length}]`;
    }
    if (redacted.refresh_token) {
      redacted.refresh_token = `[REDACTED_REFRESH_TOKEN length=${data.refresh_token.length}]`;
    }
    if (redacted.id_token) {
      redacted.id_token = `[REDACTED_ID_TOKEN length=${data.id_token.length}]`;
    }

    // LOW RISK: Keep for analysis
    // - token_type (DPoP detection)
    // - expires_in (session lifetime)
    // - scope (privilege analysis)

    return redacted;
  }

  /**
   * Redact MFA responses
   *
   * MEDIUM RISK FIELDS (partial redaction):
   * - challenge (WebAuthn challenge - ephemeral, but still sensitive)
   * - session_token (temporary session - redact)
   *
   * LOW RISK FIELDS (keep for analysis):
   * - publicKey.rpId (relying party - needed for WebAuthn analysis)
   * - publicKey.user.id (user handle - not PII)
   * - publicKey.timeout (needed for security analysis)
   */
  _redactMFAResponse(data) {
    const redacted = { ...data };

    // WebAuthn challenge redaction
    if (redacted.publicKey && redacted.publicKey.challenge) {
      const challenge = redacted.publicKey.challenge;
      redacted.publicKey.challenge = `[REDACTED_CHALLENGE length=${challenge.length}]`;
    }

    // Session token redaction
    if (redacted.session_token) {
      redacted.session_token = `[REDACTED_SESSION_TOKEN length=${data.session_token.length}]`;
    }

    return redacted;
  }

  /**
   * Redact generic responses - any field that looks like a token
   */
  _redactGenericResponse(data) {
    const redacted = { ...data };
    const tokenPatterns = [
      'token',
      'secret',
      'key',
      'password',
      'credential',
      'auth'
    ];

    for (const [key, value] of Object.entries(redacted)) {
      if (typeof value === 'string') {
        // Check if key matches token pattern
        const keyLower = key.toLowerCase();
        if (tokenPatterns.some(pattern => keyLower.includes(pattern))) {
          redacted[key] = `[REDACTED_${key.toUpperCase()} length=${value.length}]`;
        }
      }
    }

    return redacted;
  }

  /**
   * Enable response body capture
   *
   * NOTE: This will attach debugger to all tabs where auth requests are detected.
   * User will see "DevTools is debugging this browser" notification.
   */
  async enable() {
    if (!await this.isSupported()) {
      console.error('[ResponseCapture] Cannot enable - debugger API not available or permission not granted');
      return false;
    }

    this.enabled = true;
    console.log('[ResponseCapture] Response body capture enabled');
    return true;
  }

  /**
   * Disable response body capture and detach from all tabs
   */
  async disable() {
    this.enabled = false;

    // Detach from all tabs
    const detachPromises = Array.from(this.activeDebuggees.keys()).map(
      tabId => this.detachFromTab(tabId)
    );
    await Promise.all(detachPromises);

    console.log('[ResponseCapture] Response body capture disabled');
  }

  /**
   * Auto-attach to tab when auth request is detected
   *
   * Called by WebRequestListeners when an auth request is detected
   */
  async handleAuthRequest(tabId, requestId) {
    if (!this.enabled) {
      return;
    }

    // Check if already attached to this tab
    if (this.activeDebuggees.has(tabId)) {
      return;
    }

    // Attach to tab
    await this.attachToTab(tabId);
  }
}
