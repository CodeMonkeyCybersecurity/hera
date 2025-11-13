/**
 * CSRF Protection Detector with OAuth2 Token Endpoint Exemptions
 *
 * Implements context-aware CSRF detection that correctly handles OAuth2 token endpoints
 * per RFC 6749 and RFC 9700 requirements.
 *
 * Key Features:
 * - OAuth2 token endpoint exemption (RFC 6749 Section 3.2)
 * - Grant type validation for exempted endpoints
 * - Standard CSRF token detection for other POST requests
 * - Reduces false positives on legitimate OAuth2 flows
 *
 * @author Hera Security Team
 * @date 2025-11-12
 */

export class CSRFDetector {
  /**
   * OAuth2 token endpoint URL patterns
   * These endpoints use authorization codes/refresh tokens instead of CSRF tokens
   */
  static OAUTH2_TOKEN_ENDPOINT_PATTERNS = [
    /\/oauth2?\/.*\/token$/i,        // Microsoft: /oauth2/v2.0/token
    /\/oauth\/token$/i,                // Standard: /oauth/token
    /\/token$/i,                       // Generic: /token
    /\/auth\/.*\/token$/i,             // Auth0/Okta: /auth/xyz/token
    /\/v\d+\/token$/i,                 // Versioned: /v2/token
    /\/connect\/token$/i,              // OIDC: /connect/token
    /\/realms\/.*\/token$/i            // Keycloak: /realms/xxx/token
  ];

  /**
   * Check if URL matches OAuth2 token endpoint pattern
   * @param {string} url - Request URL
   * @returns {boolean} True if OAuth2 token endpoint
   */
  static isOAuth2TokenEndpoint(url) {
    try {
      const urlObj = new URL(url);
      return this.OAUTH2_TOKEN_ENDPOINT_PATTERNS.some(pattern =>
        pattern.test(urlObj.pathname)
      );
    } catch {
      return false;
    }
  }

  /**
   * Check if request body contains OAuth2 grant type parameters
   * @param {string} requestBody - POST request body
   * @returns {boolean} True if OAuth2 grant type detected
   */
  static hasOAuth2TokenGrant(requestBody) {
    if (!requestBody) return false;

    // OAuth2 grant type indicators
    const oauth2Indicators = [
      'grant_type=authorization_code',  // Authorization code flow
      'grant_type=refresh_token',       // Refresh token flow
      'grant_type=client_credentials',  // Client credentials flow
      'code_verifier=',                 // PKCE verifier
      'refresh_token=',                 // Refresh token parameter
      'code='                           // Authorization code
    ];

    return oauth2Indicators.some(indicator =>
      requestBody.includes(indicator)
    );
  }

  /**
   * Analyze POST request for CSRF protection
   * Exempts OAuth2 token endpoints per RFC 6749
   *
   * @param {Object} request - Request object with url, method, headers, body
   * @returns {Object|null} Security issue or null if protected
   */
  static analyzeCSRFProtection(request) {
    // Only check POST requests
    if (request.method !== 'POST') return null;

    // Check if this is an OAuth2 token endpoint
    if (this.isOAuth2TokenEndpoint(request.url)) {
      // OAuth2 token endpoints don't need CSRF tokens
      // They use authorization codes/refresh tokens for protection

      // However, verify that OAuth2 grant parameters are present
      const hasOAuth2Grant = this.hasOAuth2TokenGrant(request.body);

      if (!hasOAuth2Grant) {
        // Token endpoint without proper OAuth2 parameters is suspicious
        return {
          type: 'WEAK_OAUTH2_TOKEN_REQUEST',
          severity: 'HIGH',
          confidence: 'MEDIUM',
          message: 'OAuth2 token endpoint missing expected grant type parameters',
          details: {
            url: request.url,
            expectedParameters: [
              'grant_type',
              'code or refresh_token',
              'code_verifier (for PKCE)'
            ],
            foundInBody: !!request.body
          },
          recommendation: 'Ensure token requests include proper OAuth2 grant type (authorization_code, refresh_token, or client_credentials)',
          references: [
            'RFC 6749 Section 3.2 - Token Endpoint',
            'RFC 7636 - PKCE'
          ]
        };
      }

      // OAuth2 token endpoint with proper grant type - no CSRF issue
      return null;
    }

    // For non-OAuth2 POST requests, check for CSRF token
    if (!this.hasCSRFToken(request.headers) && !this.hasCSRFToken(request.body)) {
      return {
        type: 'MISSING_CSRF_PROTECTION',
        severity: 'HIGH',
        confidence: 'HIGH',
        message: 'POST request missing CSRF protection',
        details: {
          url: request.url,
          method: request.method,
          checkedLocations: ['headers', 'body'],
          csrfHeadersSearched: [
            'x-csrf-token',
            'x-xsrf-token',
            'csrf-token'
          ],
          csrfParametersSearched: [
            'csrf',
            '_csrf',
            'csrfToken',
            'authenticity_token'
          ]
        },
        recommendation: 'Add CSRF token to request headers (e.g., X-CSRF-Token) or body',
        exploitability: {
          attackComplexity: 'LOW',
          requiredUserAction: 'Click malicious link',
          impact: 'State-changing action performed as victim'
        },
        references: [
          'OWASP CSRF Prevention Cheat Sheet',
          'CWE-352: Cross-Site Request Forgery (CSRF)'
        ]
      };
    }

    // CSRF token present - protected
    return null;
  }

  /**
   * Check if CSRF token is present in headers or body
   * @param {Array|string} data - Headers array or body string
   * @returns {boolean} True if CSRF token found
   */
  static hasCSRFToken(data) {
    if (!data) return false;

    // Common CSRF header names
    const csrfHeaders = [
      'x-csrf-token',
      'x-xsrf-token',
      'csrf-token',
      'x-csrf',
      'x-xsrf'
    ];

    // Common CSRF parameter names
    const csrfParams = [
      'csrf',
      '_csrf',
      'csrfToken',
      'csrf_token',
      'authenticity_token',
      '_token'
    ];

    if (Array.isArray(data)) {
      // Headers array: [{name: 'x-csrf-token', value: 'abc'}]
      return data.some(h =>
        csrfHeaders.includes(h.name.toLowerCase()) && h.value && h.value.length > 0
      );
    } else if (typeof data === 'string') {
      // Request body: "csrf=abc&name=John"
      return csrfParams.some(param =>
        data.includes(`${param}=`) || data.includes(`"${param}":`)
      );
    }

    return false;
  }

  /**
   * Get statistics on CSRF detection
   * @param {Array} requests - Array of analyzed requests
   * @returns {Object} Statistics
   */
  static getStatistics(requests) {
    const stats = {
      totalPOST: 0,
      protectedByCSRF: 0,
      oauth2Endpoints: 0,
      vulnerableTOCSRF: 0,
      weakOAuth2: 0
    };

    requests.forEach(req => {
      if (req.method === 'POST') {
        stats.totalPOST++;

        const issue = this.analyzeCSRFProtection(req);

        if (!issue) {
          if (this.isOAuth2TokenEndpoint(req.url)) {
            stats.oauth2Endpoints++;
          } else {
            stats.protectedByCSRF++;
          }
        } else if (issue.type === 'MISSING_CSRF_PROTECTION') {
          stats.vulnerableTOCSRF++;
        } else if (issue.type === 'WEAK_OAUTH2_TOKEN_REQUEST') {
          stats.weakOAuth2++;
        }
      }
    });

    return stats;
  }
}

// Export for use in hera-auth-detector.js
export default CSRFDetector;
