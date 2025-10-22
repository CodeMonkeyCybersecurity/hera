// JWT Security Validator
// Validates JWT tokens for common security issues

class JWTValidator {
  constructor() {
    // Weak/dangerous algorithms
    this.weakAlgorithms = ['none', 'HS256']; // HS256 weak if secret is short
    this.deprecatedAlgorithms = ['RS256']; // Not deprecated, but prefer RS512/ES256
    this.strongAlgorithms = ['RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'];
  }

  /**
   * Parse JWT token into components
   * @param {string} token - JWT token string
   * @returns {Object} Parsed token with header, payload, signature
   */
  parseJWT(token) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        return {
          valid: false,
          error: 'Invalid JWT format - must have 3 parts (header.payload.signature)'
        };
      }

      const [headerB64, payloadB64, signatureB64] = parts;

      // Decode header
      const header = JSON.parse(this._base64UrlDecode(headerB64));

      // Decode payload
      const payload = JSON.parse(this._base64UrlDecode(payloadB64));

      return {
        valid: true,
        raw: token,
        header,
        payload,
        signature: signatureB64,
        parts: {
          header: headerB64,
          payload: payloadB64,
          signature: signatureB64
        }
      };
    } catch (error) {
      return {
        valid: false,
        error: `Failed to parse JWT: ${error.message}`
      };
    }
  }

  /**
   * Base64URL decode (handles JWT encoding)
   */
  _base64UrlDecode(str) {
    // Replace URL-safe chars with standard base64
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

    // Add padding if needed
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }

    // Decode base64 to string
    try {
      return decodeURIComponent(
        atob(base64)
          .split('')
          .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join('')
      );
    } catch (e) {
      throw new Error('Invalid base64 encoding');
    }
  }

  /**
   * Comprehensive JWT security validation
   * @param {string} token - JWT token string
   * @returns {Object} Validation results with issues and recommendations
   */
  validateJWT(token) {
    const parsed = this.parseJWT(token);

    if (!parsed.valid) {
      return {
        valid: false,
        riskScore: 0,
        issues: [{ severity: 'CRITICAL', type: 'INVALID_JWT', message: parsed.error }]
      };
    }

    const issues = [];
    let riskScore = 0;

    // 1. Algorithm validation
    const algIssue = this._validateAlgorithm(parsed.header);
    if (algIssue) {
      issues.push(algIssue);
      riskScore += algIssue.severity === 'CRITICAL' ? 50 : 20;
    }

    // 2. Expiration validation
    const expIssue = this._validateExpiration(parsed.payload);
    if (expIssue) {
      issues.push(expIssue);
      riskScore += expIssue.severity === 'HIGH' ? 30 : 10;
    }

    // 3. Claims validation
    const claimsIssues = this._validateClaims(parsed.payload);
    issues.push(...claimsIssues);
    riskScore += claimsIssues.length * 15;

    // 4. Timing attacks
    const timingIssue = this._validateTiming(parsed.payload);
    if (timingIssue) {
      issues.push(timingIssue);
      riskScore += 20;
    }

    // 5. Sensitive data exposure
    const sensitiveIssues = this._detectSensitiveData(parsed.payload);
    issues.push(...sensitiveIssues);
    riskScore += sensitiveIssues.length * 25;

    return {
      valid: true,
      token: parsed,
      riskScore: Math.min(riskScore, 100),
      issues,
      recommendation: this._generateRecommendation(riskScore, issues)
    };
  }

  /**
   * Validate JWT algorithm
   */
  _validateAlgorithm(header) {
    const alg = header.alg;

    if (!alg) {
      return {
        severity: 'CRITICAL',
        type: 'MISSING_ALGORITHM',
        message: 'JWT header missing "alg" field',
        recommendation: 'Reject token - algorithm must be specified'
      };
    }

    // CRITICAL: alg:none vulnerability
    if (alg.toLowerCase() === 'none') {
      return {
        severity: 'CRITICAL',
        type: 'ALG_NONE_VULNERABILITY',
        message: 'JWT uses "alg:none" - signature bypass attack possible',
        recommendation: 'Reject immediately - this allows forging arbitrary tokens',
        cve: 'CVE-2015-9235',
        references: ['https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/']
      };
    }

    // HIGH: Weak symmetric algorithm
    if (alg === 'HS256') {
      return {
        severity: 'HIGH',
        type: 'WEAK_SYMMETRIC_ALGORITHM',
        message: 'JWT uses HS256 with potentially weak shared secret',
        recommendation: 'If secret is <32 bytes, vulnerable to brute force. Prefer RS512 or ES256.',
        detail: 'HS256 security depends entirely on secret strength. Many implementations use weak secrets.'
      };
    }

    // MEDIUM: Deprecated but not critically weak
    if (!this.strongAlgorithms.includes(alg)) {
      return {
        severity: 'MEDIUM',
        type: 'WEAK_ALGORITHM',
        message: `JWT algorithm "${alg}" not recommended`,
        recommendation: `Prefer modern algorithms: ${this.strongAlgorithms.join(', ')}`,
        detail: 'Older algorithms may have known weaknesses or performance issues'
      };
    }

    return null;
  }

  /**
   * Validate expiration and timing claims
   */
  _validateExpiration(payload) {
    const now = Math.floor(Date.now() / 1000);

    // Check exp (expiration time)
    if (!payload.exp) {
      return {
        severity: 'HIGH',
        type: 'MISSING_EXPIRATION',
        message: 'JWT missing "exp" claim - token never expires',
        recommendation: 'Always set expiration time to limit token lifetime',
        detail: 'Tokens without expiration can be replayed indefinitely if stolen'
      };
    }

    if (payload.exp < now) {
      return {
        severity: 'MEDIUM',
        type: 'TOKEN_EXPIRED',
        message: `JWT expired ${this._formatDuration(now - payload.exp)} ago`,
        recommendation: 'Reject expired tokens - request new token',
        expiredAt: new Date(payload.exp * 1000).toISOString()
      };
    }

    // Check for excessively long lifetime
    const lifetime = payload.exp - (payload.iat || now);
    if (lifetime > 86400) { // 24 hours
      return {
        severity: 'MEDIUM',
        type: 'EXCESSIVE_LIFETIME',
        message: `JWT lifetime is ${this._formatDuration(lifetime)} (max recommended: 24h)`,
        recommendation: 'Use shorter token lifetimes (1-24h) and refresh tokens for long sessions',
        lifetime: lifetime
      };
    }

    return null;
  }

  /**
   * Validate required and optional claims
   */
  _validateClaims(payload) {
    const issues = [];

    // Check for issuer (iss)
    if (!payload.iss) {
      issues.push({
        severity: 'MEDIUM',
        type: 'MISSING_ISSUER',
        message: 'JWT missing "iss" (issuer) claim',
        recommendation: 'Include issuer to prevent token substitution attacks'
      });
    }

    // Check for audience (aud)
    if (!payload.aud) {
      issues.push({
        severity: 'MEDIUM',
        type: 'MISSING_AUDIENCE',
        message: 'JWT missing "aud" (audience) claim',
        recommendation: 'Include audience to prevent token misuse across different services'
      });
    }

    // Check for subject (sub)
    if (!payload.sub) {
      issues.push({
        severity: 'LOW',
        type: 'MISSING_SUBJECT',
        message: 'JWT missing "sub" (subject) claim',
        recommendation: 'Include subject to identify the principal (user ID)'
      });
    }

    // Check for jti (JWT ID) for replay prevention
    if (!payload.jti) {
      issues.push({
        severity: 'LOW',
        type: 'MISSING_JTI',
        message: 'JWT missing "jti" (JWT ID) claim',
        recommendation: 'Include unique JWT ID to enable token revocation and replay prevention'
      });
    }

    return issues;
  }

  /**
   * Validate timing attack protection
   */
  _validateTiming(payload) {
    const now = Math.floor(Date.now() / 1000);

    // Check for nbf (not before) claim
    if (payload.nbf && payload.nbf > now) {
      return {
        severity: 'INFO',
        type: 'TOKEN_NOT_YET_VALID',
        message: `JWT not valid until ${new Date(payload.nbf * 1000).toISOString()}`,
        recommendation: 'Wait until nbf time or reject token',
        notBefore: new Date(payload.nbf * 1000).toISOString()
      };
    }

    // Check for iat (issued at) in future (clock skew attack)
    if (payload.iat && payload.iat > now + 300) { // 5 min tolerance
      return {
        severity: 'HIGH',
        type: 'CLOCK_SKEW_ATTACK',
        message: 'JWT "iat" claim is in the future - possible clock skew attack',
        recommendation: 'Reject token or verify server time synchronization',
        detail: 'Attacker may be manipulating timestamps to extend token lifetime'
      };
    }

    return null;
  }

  /**
   * Detect sensitive data in JWT payload
   */
  _detectSensitiveData(payload) {
    const issues = [];
    const sensitiveKeys = ['password', 'secret', 'api_key', 'apikey', 'token', 'ssn', 'credit_card'];

    for (const key of Object.keys(payload)) {
      const lowerKey = key.toLowerCase();

      // Check for sensitive key names
      if (sensitiveKeys.some(sk => lowerKey.includes(sk))) {
        issues.push({
          severity: 'CRITICAL',
          type: 'SENSITIVE_DATA_IN_JWT',
          message: `JWT payload contains sensitive field: "${key}"`,
          recommendation: 'Never store passwords, secrets, or PII in JWT payloads (they are not encrypted)',
          detail: 'JWTs are base64-encoded, not encrypted. Anyone with the token can read the payload.'
        });
      }

      // Check for PII (emails, phone numbers, etc.)
      const value = String(payload[key]);
      if (this._looksLikePII(value)) {
        issues.push({
          severity: 'HIGH',
          type: 'PII_IN_JWT',
          message: `JWT payload may contain PII in field: "${key}"`,
          recommendation: 'Avoid storing PII in JWTs. Use opaque references instead.',
          detail: 'PII exposure violates GDPR/privacy regulations and increases risk if token is stolen'
        });
      }
    }

    return issues;
  }

  /**
   * Detect if value looks like PII
   */
  _looksLikePII(value) {
    // Email pattern
    if (/@.*\..+/.test(value)) return true;

    // Phone number pattern (simplified)
    if (/\d{3}[-.]?\d{3}[-.]?\d{4}/.test(value)) return true;

    // SSN pattern
    if (/\d{3}-\d{2}-\d{4}/.test(value)) return true;

    return false;
  }

  /**
   * Format duration in human-readable form
   */
  _formatDuration(seconds) {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
    return `${Math.floor(seconds / 86400)}d`;
  }

  /**
   * Generate recommendation based on risk score
   */
  _generateRecommendation(riskScore, issues) {
    if (riskScore >= 70) {
      return {
        action: 'REJECT',
        message: 'Critical security issues detected - reject this token immediately',
        color: 'red'
      };
    } else if (riskScore >= 40) {
      return {
        action: 'WARN',
        message: 'Security concerns detected - review before accepting token',
        color: 'orange'
      };
    } else if (riskScore >= 20) {
      return {
        action: 'REVIEW',
        message: 'Minor issues detected - token may be acceptable with caution',
        color: 'yellow'
      };
    } else {
      return {
        action: 'ACCEPT',
        message: 'Token appears secure',
        color: 'green'
      };
    }
  }

  /**
   * Extract JWTs from various locations (headers, body, cookies)
   */
  extractJWTs(headers, body, cookies) {
    const tokens = [];

    // 1. Authorization header (most common)
    const authHeader = headers['authorization'] || headers['Authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
      tokens.push({
        location: 'Authorization header',
        token: authHeader.substring(7)
      });
    }

    // 2. Cookies
    if (cookies) {
      for (const [name, value] of Object.entries(cookies)) {
        if (this._looksLikeJWT(value)) {
          tokens.push({
            location: `Cookie: ${name}`,
            token: value
          });
        }
      }
    }

    // 3. Response body (id_token, access_token, refresh_token)
    if (body) {
      try {
        const bodyObj = typeof body === 'string' ? JSON.parse(body) : body;
        const tokenFields = ['id_token', 'access_token', 'refresh_token', 'token'];

        for (const field of tokenFields) {
          if (bodyObj[field] && this._looksLikeJWT(bodyObj[field])) {
            tokens.push({
              location: `Response body: ${field}`,
              token: bodyObj[field]
            });
          }
        }
      } catch (e) {
        // Not JSON or parse error - skip
      }
    }

    return tokens;
  }

  /**
   * Check if string looks like a JWT
   */
  _looksLikeJWT(str) {
    if (typeof str !== 'string') return false;
    const parts = str.split('.');
    return parts.length === 3 && parts[0].length > 10 && parts[1].length > 10;
  }

  /**
   * Analyze request data for JWTs and return findings
   * Called by WebRequestListeners.registerCompleted()
   */
  analyzeRequest(requestData, url) {
    const findings = [];

    // Extract headers as object
    const headers = {};
    if (requestData.requestHeaders) {
      requestData.requestHeaders.forEach(h => {
        headers[h.name.toLowerCase()] = h.value;
      });
    }
    if (requestData.responseHeaders) {
      requestData.responseHeaders.forEach(h => {
        headers[h.name.toLowerCase()] = h.value;
      });
    }

    // Extract cookies
    const cookies = {};
    if (requestData.metadata?.responseAnalysis?.cookies) {
      requestData.metadata.responseAnalysis.cookies.forEach(c => {
        cookies[c.name] = c.value;
      });
    }

    // Extract body
    const body = requestData.responseBody || requestData.requestBody;

    // Find all JWTs
    const tokens = this.extractJWTs(headers, body, cookies);

    // Validate each token
    for (const { location, token } of tokens) {
      const validation = this.validateJWT(token);

      if (!validation.valid || validation.issues.length > 0) {
        findings.push({
          type: 'JWT_SECURITY',
          severity: validation.riskScore > 70 ? 'CRITICAL' : validation.riskScore > 40 ? 'HIGH' : 'MEDIUM',
          location: location,
          message: validation.issues.map(i => i.message).join('; '),
          details: {
            token: token.substring(0, 50) + '...', // Truncate for display
            issues: validation.issues,
            riskScore: validation.riskScore,
            validationResult: validation
          },
          timestamp: Date.now()
        });
      }
    }

    return findings;
  }
}

export { JWTValidator };
