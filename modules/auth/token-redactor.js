/**
 * Token Redaction Utility for Hera
 *
 * Provides intelligent redaction of sensitive tokens while preserving
 * enough information for security analysis.
 *
 * Based on ADVERSARIAL_PUSHBACK.md recommendations:
 * - Never store full token values in exports
 * - Preserve structural information for analysis
 * - Redact high-risk credentials (client secrets, refresh tokens)
 * - Keep low-risk data (authorization codes - one-time use)
 */

export class TokenRedactor {
  constructor() {
    // High-risk tokens that should be heavily redacted
    this.HIGH_RISK_PATTERNS = [
      'client_secret',
      'api_key',
      'private_key',
      'refresh_token',
      'password'
    ];

    // Medium-risk tokens (redact but show more structure)
    this.MEDIUM_RISK_PATTERNS = [
      'access_token',
      'id_token',
      'bearer',
      'session_token'
    ];

    // Low-risk tokens (already consumed/one-time use)
    this.LOW_RISK_PATTERNS = [
      'code',  // OAuth2 authorization code (one-time use)
      'code_verifier',  // PKCE verifier (useless without challenge)
      'state',  // OAuth2 state (one-time use)
      'nonce'   // OIDC nonce (one-time use)
    ];
  }

  /**
   * Redact sensitive data from request body
   * @param {string} body - Raw request body
   * @param {Object} options - Redaction options
   * @returns {Object} Redacted body + metadata
   */
  redactRequestBody(body, options = {}) {
    if (!body || typeof body !== 'string') {
      return {
        redactedBody: body,
        redactionApplied: false,
        tokensFound: []
      };
    }

    const tokensFound = [];
    let redactedBody = body;
    let redactionApplied = false;

    // Parse as form data (most common for OAuth2)
    const params = this._parseFormData(body);

    for (const [key, value] of Object.entries(params)) {
      const keyLower = key.toLowerCase();
      const riskLevel = this._assessRiskLevel(keyLower);

      if (riskLevel !== 'none') {
        const redactionInfo = this._redactValue(key, value, riskLevel);
        tokensFound.push(redactionInfo);

        // Replace in body
        const originalPattern = new RegExp(`${key}=[^&]*`, 'g');
        redactedBody = redactedBody.replace(originalPattern, `${key}=${redactionInfo.redactedValue}`);
        redactionApplied = true;
      }
    }

    return {
      redactedBody,
      redactionApplied,
      tokensFound,
      originalLength: body.length,
      redactedLength: redactedBody.length
    };
  }

  /**
   * Redact token from response body (JWT, opaque tokens)
   * @param {Object} responseBody - Parsed response body
   * @returns {Object} Redacted response with metadata
   */
  redactResponseTokens(responseBody) {
    if (!responseBody || typeof responseBody !== 'object') {
      return {
        redactedResponse: responseBody,
        tokensFound: []
      };
    }

    const redacted = { ...responseBody };
    const tokensFound = [];

    // Common OAuth2 response fields
    const tokenFields = ['access_token', 'id_token', 'refresh_token', 'token'];

    for (const field of tokenFields) {
      if (redacted[field]) {
        const riskLevel = this._assessRiskLevel(field);
        const redactionInfo = this._redactValue(field, redacted[field], riskLevel);

        tokensFound.push(redactionInfo);
        redacted[field] = redactionInfo.redactedValue;
      }
    }

    return {
      redactedResponse: redacted,
      tokensFound
    };
  }

  /**
   * Analyze token without storing full value
   * @param {string} tokenName - Token parameter name
   * @param {string} tokenValue - Token value
   * @returns {Object} Token analysis without full value
   */
  analyzeToken(tokenName, tokenValue) {
    if (!tokenValue || typeof tokenValue !== 'string') {
      return { format: 'unknown', length: 0 };
    }

    const analysis = {
      name: tokenName,
      length: tokenValue.length,
      format: this._detectTokenFormat(tokenValue),
      preview: this._generatePreview(tokenValue, this._assessRiskLevel(tokenName)),
      riskLevel: this._assessRiskLevel(tokenName)
    };

    // Additional analysis for JWTs
    if (analysis.format === 'JWT') {
      try {
        const parts = tokenValue.split('.');
        if (parts.length === 3) {
          // Decode header and payload (not signature)
          const header = JSON.parse(atob(parts[0]));
          const payload = JSON.parse(atob(parts[1]));

          analysis.jwt = {
            header,
            claims: {
              iss: payload.iss,
              aud: payload.aud,
              exp: payload.exp,
              iat: payload.iat,
              sub: payload.sub ? '[REDACTED]' : undefined,
              // Include non-sensitive claims
              scope: payload.scope,
              client_id: payload.client_id
            },
            expiresAt: payload.exp ? new Date(payload.exp * 1000).toISOString() : null,
            issuedAt: payload.iat ? new Date(payload.iat * 1000).toISOString() : null
          };

          // Check for security issues
          analysis.jwt.securityIssues = [];
          if (header.alg === 'none') {
            analysis.jwt.securityIssues.push('CRITICAL: alg=none detected');
          }
          if (header.alg === 'HS256' && payload.aud) {
            analysis.jwt.securityIssues.push('WARNING: Symmetric algorithm with public audience');
          }
          if (payload.exp && payload.exp < Date.now() / 1000) {
            analysis.jwt.securityIssues.push('Token expired');
          }
        }
      } catch (e) {
        analysis.jwt = { error: 'Failed to parse JWT', valid: false };
      }
    }

    return analysis;
  }

  /**
   * Assess risk level of a token parameter
   * @private
   */
  _assessRiskLevel(paramName) {
    const nameLower = paramName.toLowerCase();

    // High risk - long-lived credentials
    if (this.HIGH_RISK_PATTERNS.some(pattern => nameLower.includes(pattern))) {
      return 'high';
    }

    // Medium risk - short-lived but valuable
    if (this.MEDIUM_RISK_PATTERNS.some(pattern => nameLower.includes(pattern))) {
      return 'medium';
    }

    // Low risk - one-time use or useless alone
    if (this.LOW_RISK_PATTERNS.some(pattern => nameLower === pattern)) {
      return 'low';
    }

    return 'none';
  }

  /**
   * Redact value based on risk level
   * @private
   */
  _redactValue(name, value, riskLevel) {
    const info = {
      name,
      originalLength: value.length,
      riskLevel,
      format: this._detectTokenFormat(value)
    };

    switch (riskLevel) {
      case 'high':
        // Show only first 4 and last 4 characters
        info.redactedValue = value.length > 8
          ? `${value.substring(0, 4)}...[REDACTED ${value.length - 8} chars]...${value.substring(value.length - 4)}`
          : '[REDACTED]';
        break;

      case 'medium':
        // Show first 12 and last 8 characters (enough to identify, not enough to use)
        if (value.length > 20) {
          info.redactedValue = `${value.substring(0, 12)}...[REDACTED ${value.length - 20} chars]...${value.substring(value.length - 8)}`;
        } else {
          info.redactedValue = `${value.substring(0, 4)}...[REDACTED]`;
        }
        break;

      case 'low':
        // Show more context - these are one-time use
        if (value.length > 32) {
          info.redactedValue = `${value.substring(0, 16)}...[${value.length - 32} chars]...${value.substring(value.length - 16)}`;
        } else {
          info.redactedValue = value; // Keep short low-risk values
        }
        break;

      default:
        info.redactedValue = value;
        break;
    }

    return info;
  }

  /**
   * Detect token format
   * @private
   */
  _detectTokenFormat(value) {
    if (!value || typeof value !== 'string') return 'unknown';

    // JWT format: three base64url parts separated by dots
    if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
      return 'JWT';
    }

    // Base64 format
    if (/^[A-Za-z0-9+/]+=*$/.test(value)) {
      return 'base64';
    }

    // Base64url format (common in OAuth2)
    if (/^[A-Za-z0-9_-]+$/.test(value)) {
      return 'base64url';
    }

    // Hex format
    if (/^[0-9a-fA-F]+$/.test(value) && value.length % 2 === 0) {
      return 'hex';
    }

    // UUID format
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) {
      return 'uuid';
    }

    return 'opaque';
  }

  /**
   * Generate safe preview based on risk level
   * @private
   */
  _generatePreview(value, riskLevel) {
    if (!value) return null;

    switch (riskLevel) {
      case 'high':
        return `${value.substring(0, 4)}...${value.substring(value.length - 4)}`;
      case 'medium':
        return `${value.substring(0, 8)}...${value.substring(value.length - 4)}`;
      case 'low':
        return value.length > 32 ? `${value.substring(0, 32)}...` : value;
      default:
        return value.substring(0, 50);
    }
  }

  /**
   * Parse form-encoded data
   * @private
   */
  _parseFormData(body) {
    const params = {};
    const pairs = body.split('&');

    for (const pair of pairs) {
      const [key, value] = pair.split('=');
      if (key && value) {
        try {
          params[decodeURIComponent(key)] = decodeURIComponent(value);
        } catch (e) {
          params[key] = value;
        }
      }
    }

    return params;
  }

  /**
   * Check if body likely contains sensitive data
   * @param {string} body - Request body
   * @returns {boolean} True if sensitive data detected
   */
  containsSensitiveData(body) {
    if (!body || typeof body !== 'string') return false;

    const sensitivePatterns = [
      ...this.HIGH_RISK_PATTERNS,
      ...this.MEDIUM_RISK_PATTERNS
    ];

    return sensitivePatterns.some(pattern =>
      body.toLowerCase().includes(pattern)
    );
  }
}

export default TokenRedactor;
