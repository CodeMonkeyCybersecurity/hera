/**
 * Request Body Capturer for OAuth2/OIDC Testing
 *
 * Captures POST body content from OAuth2 token requests with automatic redaction
 * to prevent leaking actual credentials, tokens, or secrets.
 *
 * Security principles:
 * 1. NEVER store full sensitive values (tokens, secrets, passwords)
 * 2. Store STRUCTURE and FORMAT only
 * 3. Preview format: first/last 8 characters only
 * 4. Whitelist safe parameters (grant_type, client_id, etc.)
 * 5. Redact sensitive parameters (client_secret, code, refresh_token, password)
 *
 * Reference: ADVERSARIAL_PUSHBACK.md Phase 1
 */

export class RequestBodyCapturer {
  constructor() {
    this.name = 'RequestBodyCapturer';

    // Safe parameters that can be stored in full
    this.SAFE_PARAMS = new Set([
      'grant_type',
      'code_verifier',
      'code_challenge',
      'code_challenge_method',
      'redirect_uri',
      'client_id',
      'scope',
      'response_type',
      'state',
      'nonce',
      'resource',
      'audience',
      'assertion_type'
    ]);

    // Sensitive parameters that must be redacted
    this.REDACTED_PARAMS = new Set([
      'client_secret',
      'code',
      'authorization_code',
      'refresh_token',
      'password',
      'username',
      'access_token',
      'id_token',
      'assertion',
      'client_assertion',
      'token',
      'secret',
      'key'
    ]);
  }

  /**
   * Capture POST body from OAuth2/OIDC token request with redaction
   * @param {Object} requestDetails - Chrome webRequest details from onBeforeRequest
   * @returns {Object} Redacted POST body evidence
   */
  captureRequestBody(requestDetails) {
    const evidence = {
      timestamp: Date.now(),
      requestId: requestDetails.requestId,
      url: this._redactUrl(requestDetails.url),
      method: requestDetails.method,
      contentType: this._extractContentType(requestDetails),
      bodyPresent: false,
      parameters: {},
      redacted: [],
      warnings: []
    };

    // Only capture POST requests
    if (requestDetails.method !== 'POST') {
      evidence.warnings.push('Not a POST request - body capture skipped');
      return evidence;
    }

    // Check if this is a token endpoint
    if (!this._isTokenEndpoint(requestDetails.url)) {
      evidence.warnings.push('Not a token endpoint - body capture skipped');
      return evidence;
    }

    // Chrome webRequest API provides requestBody in onBeforeRequest
    if (!requestDetails.requestBody) {
      evidence.warnings.push('Request body not available (may be due to permissions)');
      return evidence;
    }

    try {
      const bodyData = this._parseRequestBody(requestDetails.requestBody, evidence.contentType);

      if (!bodyData) {
        evidence.warnings.push('Could not parse request body');
        return evidence;
      }

      evidence.bodyPresent = true;

      // Process each parameter with redaction
      for (const [key, value] of Object.entries(bodyData)) {
        if (this.SAFE_PARAMS.has(key)) {
          // Safe parameter - store in full
          evidence.parameters[key] = value;
        } else if (this.REDACTED_PARAMS.has(key) || this._isSensitiveParam(key)) {
          // Sensitive parameter - redact value
          evidence.parameters[key] = this._redactValue(value, key);
          evidence.redacted.push(key);
        } else {
          // Unknown parameter - be cautious and redact
          evidence.parameters[key] = this._redactValue(value, key);
          evidence.redacted.push(key);
          evidence.warnings.push(`Unknown parameter "${key}" was redacted for safety`);
        }
      }

      // Add security metadata
      evidence.security = this._analyzeSecurityProperties(bodyData, evidence.parameters);

    } catch (error) {
      evidence.warnings.push(`Error parsing body: ${error.message}`);
      console.warn('Hera: Error capturing request body:', error);
    }

    return evidence;
  }

  /**
   * Parse request body from Chrome webRequest format
   * @param {Object} requestBody - Chrome webRequest requestBody object
   * @param {string} contentType - Content-Type header value
   * @returns {Object} Parsed key-value pairs
   */
  _parseRequestBody(requestBody, contentType) {
    // Chrome provides requestBody in different formats:
    // - formData: Object with key-value pairs (application/x-www-form-urlencoded)
    // - raw: ArrayBuffer (application/json or other formats)

    if (requestBody.formData) {
      // Form data is already parsed by Chrome
      const parsed = {};
      for (const [key, values] of Object.entries(requestBody.formData)) {
        // Chrome formData values are arrays
        parsed[key] = values.length === 1 ? values[0] : values;
      }
      return parsed;
    }

    if (requestBody.raw && requestBody.raw.length > 0) {
      // Raw data - need to decode
      const rawData = requestBody.raw[0];

      if (rawData.bytes) {
        const decoder = new TextDecoder('utf-8');
        const bodyText = decoder.decode(rawData.bytes);

        // Try to parse based on content type
        if (contentType?.includes('application/json')) {
          try {
            return JSON.parse(bodyText);
          } catch (e) {
            console.warn('Hera: Could not parse JSON body:', e);
            return null;
          }
        } else if (contentType?.includes('application/x-www-form-urlencoded')) {
          // URL-encoded form data
          return this._parseUrlEncoded(bodyText);
        } else {
          // Unknown format - try both
          try {
            return JSON.parse(bodyText);
          } catch (e) {
            try {
              return this._parseUrlEncoded(bodyText);
            } catch (e2) {
              console.warn('Hera: Could not parse body as JSON or form data');
              return null;
            }
          }
        }
      }
    }

    return null;
  }

  /**
   * Parse URL-encoded form data
   * @param {string} bodyText - URL-encoded string
   * @returns {Object} Parsed key-value pairs
   */
  _parseUrlEncoded(bodyText) {
    const params = new URLSearchParams(bodyText);
    const result = {};
    for (const [key, value] of params.entries()) {
      result[key] = value;
    }
    return result;
  }

  /**
   * Redact sensitive value while preserving format information
   * @param {string} value - Original value
   * @param {string} paramName - Parameter name for context
   * @returns {Object} Redacted value with metadata
   */
  _redactValue(value, paramName) {
    if (!value || typeof value !== 'string') {
      return {
        present: false,
        type: typeof value
      };
    }

    const format = this._detectFormat(value);
    const preview = this._createPreview(value, format);

    return {
      present: true,
      length: value.length,
      format: format,
      preview: preview,
      paramName: paramName,
      // Statistical properties (safe to store)
      entropy: this._calculateEntropy(value),
      characterSets: this._analyzeCharacterSets(value)
    };
  }

  /**
   * Detect format of value (JWT, base64, hex, opaque, etc.)
   * @param {string} value - Value to analyze
   * @returns {string} Format type
   */
  _detectFormat(value) {
    // JWT: three parts separated by dots
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
      return 'JWT';
    }

    // Base64url (used in PKCE code_verifier)
    if (/^[A-Za-z0-9_-]+$/.test(value) && value.length >= 43) {
      return 'base64url';
    }

    // Base64
    if (/^[A-Za-z0-9+/]+=*$/.test(value) && value.length % 4 === 0) {
      return 'base64';
    }

    // Hex
    if (/^[0-9a-fA-F]+$/.test(value) && value.length % 2 === 0) {
      return 'hex';
    }

    // UUID
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
      return 'UUID';
    }

    return 'opaque';
  }

  /**
   * Create safe preview (first/last N characters only)
   * @param {string} value - Original value
   * @param {string} format - Detected format
   * @returns {string} Redacted preview
   */
  _createPreview(value, format) {
    const PREVIEW_LENGTH = 8;

    if (!value) return '';

    if (value.length <= PREVIEW_LENGTH * 2) {
      // Value is short, redact middle
      const showLength = Math.min(4, Math.floor(value.length / 3));
      return value.substring(0, showLength) + '...' + value.substring(value.length - showLength);
    }

    // Show first and last N characters
    return value.substring(0, PREVIEW_LENGTH) + '...' + value.substring(value.length - PREVIEW_LENGTH);
  }

  /**
   * Calculate Shannon entropy (bits)
   * @param {string} str - String to analyze
   * @returns {number} Entropy in bits
   */
  _calculateEntropy(str) {
    if (!str) return 0;

    const freq = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return Math.round(entropy * len); // Total bits
  }

  /**
   * Analyze character sets used in value
   * @param {string} str - String to analyze
   * @returns {Object} Character set analysis
   */
  _analyzeCharacterSets(str) {
    return {
      hasUppercase: /[A-Z]/.test(str),
      hasLowercase: /[a-z]/.test(str),
      hasDigits: /[0-9]/.test(str),
      hasSpecial: /[^A-Za-z0-9]/.test(str),
      uniqueChars: new Set(str).size
    };
  }

  /**
   * Check if parameter name suggests sensitive data
   * @param {string} paramName - Parameter name
   * @returns {boolean} True if likely sensitive
   */
  _isSensitiveParam(paramName) {
    const lowerName = paramName.toLowerCase();
    const sensitiveKeywords = [
      'secret', 'token', 'key', 'password', 'pwd',
      'credential', 'auth', 'private', 'code'
    ];

    return sensitiveKeywords.some(keyword => lowerName.includes(keyword));
  }

  /**
   * Analyze security properties of the request
   * @param {Object} rawData - Raw parsed data (before redaction)
   * @param {Object} redactedParams - Redacted parameters
   * @returns {Object} Security analysis
   */
  _analyzeSecurityProperties(rawData, redactedParams) {
    const analysis = {
      grantType: rawData.grant_type || 'unknown',
      hasPKCE: !!(rawData.code_verifier || rawData.code_challenge),
      hasClientSecret: !!rawData.client_secret,
      clientSecretInBrowser: false,
      vulnerabilities: []
    };

    // CRITICAL: Client secret should NEVER be in browser
    if (analysis.hasClientSecret) {
      analysis.clientSecretInBrowser = true;
      analysis.vulnerabilities.push({
        type: 'CLIENT_SECRET_IN_BROWSER',
        severity: 'CRITICAL',
        message: 'Client secret exposed in browser POST request',
        cvss: 9.0,
        cve: 'CWE-522',
        detail: 'Public clients (SPAs, mobile apps) must use PKCE, not client_secret',
        recommendation: 'Remove client_secret, implement PKCE (RFC 7636)',
        evidence: {
          grantType: analysis.grantType,
          hasClientSecret: true,
          hasPKCE: analysis.hasPKCE,
          risk: 'Client secret can be extracted from browser and used to impersonate application'
        }
      });
    }

    // Check PKCE for authorization_code grant
    if (analysis.grantType === 'authorization_code' && !analysis.hasPKCE) {
      analysis.vulnerabilities.push({
        type: 'MISSING_PKCE',
        severity: 'HIGH',
        message: 'Authorization code flow missing PKCE',
        cvss: 7.0,
        detail: 'Public clients MUST use PKCE to prevent authorization code interception',
        recommendation: 'Implement PKCE with code_challenge and code_verifier',
        reference: 'https://oauth.net/2/pkce/',
        evidence: {
          grantType: analysis.grantType,
          hasPKCE: false,
          risk: 'Authorization code can be intercepted and exchanged for tokens'
        }
      });
    }

    // Check code_verifier entropy if present
    if (rawData.code_verifier) {
      const verifier = rawData.code_verifier;
      const entropy = this._calculateEntropy(verifier);

      // RFC 7636 requires 43-128 characters with high entropy
      if (verifier.length < 43) {
        analysis.vulnerabilities.push({
          type: 'WEAK_CODE_VERIFIER',
          severity: 'MEDIUM',
          message: 'PKCE code_verifier too short',
          cvss: 6.0,
          detail: `code_verifier is ${verifier.length} characters (minimum 43 required)`,
          recommendation: 'Generate code_verifier with minimum 43 characters',
          reference: 'https://tools.ietf.org/html/rfc7636#section-4.1',
          evidence: {
            length: verifier.length,
            minimumRequired: 43,
            entropy: entropy
          }
        });
      }

      if (entropy < 128) {
        analysis.vulnerabilities.push({
          type: 'LOW_ENTROPY_CODE_VERIFIER',
          severity: 'MEDIUM',
          message: 'PKCE code_verifier has low entropy',
          cvss: 6.0,
          detail: `code_verifier entropy is ${entropy} bits (minimum 128 bits recommended)`,
          recommendation: 'Use cryptographically random generator for code_verifier',
          evidence: {
            entropy: entropy,
            minimumRecommended: 128
          }
        });
      }
    }

    return analysis;
  }

  /**
   * Extract Content-Type from request
   * @param {Object} requestDetails - Chrome webRequest details
   * @returns {string|null} Content-Type value
   */
  _extractContentType(requestDetails) {
    if (!requestDetails.requestHeaders) return null;

    const contentTypeHeader = requestDetails.requestHeaders.find(h =>
      h.name.toLowerCase() === 'content-type'
    );

    return contentTypeHeader?.value || null;
  }

  /**
   * Check if URL is a token endpoint
   * @param {string} url - Request URL
   * @returns {boolean} True if token endpoint
   */
  _isTokenEndpoint(url) {
    const lowerUrl = url.toLowerCase();
    return lowerUrl.includes('/token') ||
           lowerUrl.includes('/oauth/token') ||
           lowerUrl.includes('/connect/token') ||
           lowerUrl.includes('/oauth2/token');
  }

  /**
   * Redact sensitive parts of URL (client_id, state, etc.)
   * @param {string} url - Full URL
   * @returns {string} Redacted URL
   */
  _redactUrl(url) {
    try {
      const urlObj = new URL(url);

      // Redact sensitive query parameters
      const sensitiveParams = ['client_secret', 'code', 'token', 'access_token', 'refresh_token'];

      for (const param of sensitiveParams) {
        if (urlObj.searchParams.has(param)) {
          const value = urlObj.searchParams.get(param);
          const redacted = this._createPreview(value, this._detectFormat(value));
          urlObj.searchParams.set(param, '[REDACTED:' + redacted + ']');
        }
      }

      return urlObj.toString();
    } catch (e) {
      return url;
    }
  }
}
