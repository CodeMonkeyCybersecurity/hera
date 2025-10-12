// Authentication Utility Functions Module
// Core utility methods for parsing, extracting, and validating auth data

class AuthUtilFunctions {
  /**
   * Parse URL parameters
   * @param {string} url - URL to parse
   * @returns {Object} Parsed parameters
   */
  parseParams(url) {
    try {
      const urlObj = new URL(url);
      const params = {};
      for (const [key, value] of urlObj.searchParams) {
        params[key] = value;
      }
      return params;
    } catch {
      return {};
    }
  }

  /**
   * Get header value from request headers
   * Handles both array and object header formats
   * @param {Array|Object} headers - Request headers
   * @param {string} name - Header name to retrieve
   * @returns {string|undefined} Header value
   */
  getHeader(headers, name) {
    if (Array.isArray(headers)) {
      const header = headers.find(h => h.name.toLowerCase() === name.toLowerCase());
      return header?.value;
    }
    return headers[name] || headers[name.toLowerCase()];
  }

  /**
   * Extract session ID from response headers
   * @param {Object} response - Response object
   * @returns {string|null} Session ID if found
   */
  extractSessionId(response) {
    const setCookie = response.headers?.['Set-Cookie'] || '';
    const match = setCookie.match(/SESSIONID=([^;]+)/);
    return match ? match[1] : null;
  }

  /**
   * Verify JWT HS256 signature (simplified)
   * Note: In real implementation, would use crypto library
   * @param {string} jwt - JWT token
   * @param {string} secret - Secret key
   * @returns {boolean} Verification result
   */
  verifyHS256(jwt, secret) {
    // Simplified verification - in real implementation would use crypto
    return false;
  }

  /**
   * Check if string contains repeating patterns
   * @param {string} str - String to analyze
   * @returns {boolean} True if repeating pattern detected
   */
  isRepeatingPattern(str) {
    return /(.)\1{3,}/.test(str) || str === str[0].repeat(str.length);
  }

  /**
   * Calculate the entropy of a string
   * @param {string} str - String to analyze
   * @returns {number} Shannon entropy value
   */
  calculateEntropy(str) {
    if (!str || str.length === 0) return 0;

    const freq = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  /**
   * Detect protocol type from request
   * @param {Object} request - Request object
   * @returns {string} Detected protocol
   */
  detectProtocol(request) {
    const url = request.url || '';
    const headers = request.requestHeaders || request.headers || {};
    const params = this.parseParams(url) || {};
    const body = (request.requestBody && typeof request.requestBody === 'string') ? request.requestBody : '';

    // OAuth 2.0
    if (url.includes('/authorize') && params.response_type) {
      return 'OAuth2';
    }

    // OIDC
    if (params.scope?.includes('openid')) {
      return 'OIDC';
    }

    // SAML
    if (body && (body.includes('SAMLRequest') || body.includes('SAMLResponse'))) {
      return 'SAML';
    }

    // JWT
    const authHeader = this.getHeader(headers, 'Authorization');
    if (authHeader?.startsWith('Bearer eyJ')) {
      return 'JWT';
    }

    // Basic Auth
    if (authHeader?.startsWith('Basic ')) {
      return 'BasicAuth';
    }

    // API Key
    if (this.getHeader(headers, 'X-API-Key') || params.api_key) {
      return 'APIKey';
    }

    // Session
    const cookie = this.getHeader(headers, 'Cookie');
    if (cookie?.includes('SESSIONID') || cookie?.includes('JSESSIONID')) {
      return 'Session';
    }

    // Kerberos
    if (authHeader?.startsWith('Negotiate ')) {
      return 'Kerberos';
    }

    // WebAuthn
    if (url.includes('webauthn') || (body && body.includes('publicKey'))) {
      return 'WebAuthn';
    }

    // MFA
    if (url.includes('2fa') || url.includes('mfa') || (body && body.includes('code'))) {
      return 'MFA';
    }

    // Certificate
    if (this.getHeader(headers, 'X-Client-Cert')) {
      return 'Certificate';
    }

    // ProtonMail API
    if (this.getHeader(headers, 'x-pm-uid') ||
        this.getHeader(headers, 'x-pm-appversion') ||
        (cookie && cookie.includes('AUTH-')) ||
        url.includes('/api/core/v4/') ||
        url.includes('/api/auth/v4/') ||
        url.includes('proton.me/api/')) {
      return 'ProtonMail API';
    }

    return 'Custom';
  }

  /**
   * Detect credentials exposed in URL
   * Uses refined detection to avoid false positives on OAuth2 parameters
   * @param {string} url - URL to analyze
   * @returns {Object|null} Issue object if credentials detected
   */
  detectCredentialsInUrl(url) {
    try {
      const urlObj = new URL(url);
      const params = new URLSearchParams(urlObj.search);
      const fullUrl = url.toLowerCase();

      // Legitimate OAuth2 security parameters - these should NOT be flagged
      const oauthSecurityParams = ['state', 'nonce', 'code_challenge', 'code_verifier'];

      // Public API key patterns that are safe to expose
      const publicKeyPatterns = [
        /pk_[a-zA-Z0-9]+/, // Stripe public keys
        /pub_[a-zA-Z0-9]+/, // Generic public keys
        /public_[a-zA-Z0-9]+/ // Explicit public keys
      ];

      // Check for actual credential exposure in query parameters
      for (const [key, value] of params) {
        const lowerKey = key.toLowerCase();
        const lowerValue = value.toLowerCase();

        // Skip OAuth2 security parameters
        if (oauthSecurityParams.includes(lowerKey)) {
          continue;
        }

        // Skip public API keys
        if (publicKeyPatterns.some(pattern => pattern.test(value))) {
          continue;
        }

        // Look for actual credential patterns
        const credentialPatterns = [
          // Actual passwords
          { pattern: /^(password|passwd|pwd)$/i, paramKey: lowerKey },
          // Private API keys and tokens
          { pattern: /^(api_key|apikey|access_token|auth_token|bearer_token|secret_key|private_key)$/i, paramKey: lowerKey },
          // Database credentials
          { pattern: /^(db_password|database_password|mysql_password|postgres_password)$/i, paramKey: lowerKey },
          // AWS/Cloud credentials
          { pattern: /^(aws_secret_access_key|azure_client_secret|gcp_private_key)$/i, paramKey: lowerKey },
          // High-entropy secrets (likely actual credentials)
          { pattern: /^.{32,}$/, paramKey: lowerKey, value: value, entropyCheck: true }
        ];

        for (const credPattern of credentialPatterns) {
          if (credPattern.pattern.test(credPattern.paramKey)) {
            // For entropy check, ensure it's actually a credential parameter name and high entropy
            if (credPattern.entropyCheck) {
              if (/^(secret|key|token|password)$/i.test(lowerKey) && this.calculateEntropy(value) > 4.5) {
                return {
                  type: 'CREDENTIALS_IN_URL',
                  protocol: 'Universal',
                  severity: 'HIGH',
                  message: `High-entropy credential '${key}' exposed in URL parameters`
                };
              }
            } else {
              return {
                type: 'CREDENTIALS_IN_URL',
                protocol: 'Universal',
                severity: 'HIGH',
                message: `Credential parameter '${key}' exposed in URL`
              };
            }
          }
        }
      }

      // Check for credentials in URL path (rare but possible)
      const pathCredentialPatterns = [
        /\/password\/[^\/]+/i,
        /\/secret\/[^\/]+/i,
        /\/token\/[a-zA-Z0-9]{20,}/i // Long tokens in path
      ];

      for (const pattern of pathCredentialPatterns) {
        if (pattern.test(urlObj.pathname)) {
          // Exclude REST API patterns like /api/token/metadata
          if (!/\/(api|v[0-9]+|metadata|info|status|health)\//.test(urlObj.pathname)) {
            return {
              type: 'CREDENTIALS_IN_URL',
              protocol: 'Universal',
              severity: 'HIGH',
              message: 'Potential credential exposed in URL path'
            };
          }
        }
      }

      return null;
    } catch (error) {
      // Invalid URL, skip detection
      return null;
    }
  }

  /**
   * Analyze response body for security issues
   * @param {string} body - Response body
   * @returns {Array} Array of detected issues
   */
  analyzeResponseBody(body) {
    const issues = [];
    if (!body || typeof body !== 'string') {
      return issues;
    }

    const lowerBody = body.toLowerCase();

    // Check for sensitive data exposure
    const sensitiveKeywords = ['password', 'secret', 'api_key', 'apikey', 'auth_token', 'ssn', 'credit_card'];
    sensitiveKeywords.forEach(keyword => {
      if (lowerBody.includes(keyword)) {
        issues.push({
          type: 'SENSITIVE_DATA_IN_RESPONSE',
          protocol: 'Universal',
          severity: 'HIGH',
          message: `Potential sensitive data exposure: found keyword '${keyword}' in response body.`,
          exploitation: 'Response body may contain secrets, PII, or credentials that should not be exposed to the client.'
        });
      }
    });

    // Check for verbose error messages
    const errorPatterns = ['stack trace', 'sql syntax', 'database error', 'exception', 'uncaught', 'internal server error'];
    errorPatterns.forEach(pattern => {
      if (lowerBody.includes(pattern)) {
        issues.push({
          type: 'VERBOSE_ERROR_MESSAGE',
          protocol: 'Universal',
          severity: 'MEDIUM',
          message: `Verbose error message detected: found keyword '${pattern}'.`,
          exploitation: 'Error messages can reveal server-side technologies, file paths, and application logic, aiding attackers.'
        });
      }
    });

    return issues;
  }

  /**
   * Generate unique verification ID
   * @returns {string} Unique verification ID
   */
  generateVerificationId() {
    return `verification_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Get test description for OAuth2 verification
   * @param {string} testType - Test type identifier
   * @returns {string} Human-readable description
   */
  getTestDescription(testType) {
    const descriptions = {
      'csrf_no_state': 'OAuth2 authorization endpoint lacks CSRF protection via state parameter',
      'state_replay': 'OAuth2 state parameter can be reused, enabling CSRF attacks',
      'state_prediction': 'OAuth2 state parameter is predictable',
      'pkce_missing': 'OAuth2 flow lacks PKCE protection for public clients',
      'pkce_weak_method': 'OAuth2 PKCE uses weak challenge method'
    };

    return descriptions[testType] || `OAuth2 security issue: ${testType}`;
  }
}

export { AuthUtilFunctions };
