/**
 * JWT Security Utilities
 * Secure JWT parsing and validation
 */

export const JWTSecurity = {
  /**
   * Validate JWT structure (3 parts separated by dots)
   * @param {string} token - JWT token
   * @returns {boolean} True if valid structure
   */
  isValidJWTStructure: (token) => {
    if (typeof token !== 'string') return false;
    const parts = token.split('.');
    return parts.length === 3 && parts.every(part => part.length > 0);
  },

  /**
   * Safe Base64 URL decoding with validation
   * @param {string} str - Base64 URL encoded string
   * @returns {Object|null} Decoded object or null on error
   */
  safeBase64UrlDecode: (str) => {
    try {
      // Validate input
      if (typeof str !== 'string' || str.length === 0) {
        throw new Error('Invalid input for Base64 URL decoding');
      }

      // Convert Base64 URL to Base64
      let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

      // Add padding if needed
      const padding = base64.length % 4;
      if (padding === 2) {
        base64 += '==';
      } else if (padding === 3) {
        base64 += '=';
      }

      // Validate Base64 format
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) {
        throw new Error('Invalid Base64 format');
      }

      const decoded = atob(base64);

      // Validate JSON structure
      const parsed = JSON.parse(decoded);
      return parsed;
    } catch (error) {
      console.error('JWT decode error:', error);
      return null;
    }
  },

  /**
   * Parse JWT with validation
   * @param {string} token - JWT token
   * @returns {Object} Parsed JWT or error object
   */
  parseJWT: (token) => {
    if (!JWTSecurity.isValidJWTStructure(token)) {
      return { error: 'Invalid JWT structure' };
    }

    const [headerB64, payloadB64, signature] = token.split('.');

    const header = JWTSecurity.safeBase64UrlDecode(headerB64);
    const payload = JWTSecurity.safeBase64UrlDecode(payloadB64);

    if (!header || !payload) {
      return { error: 'Failed to decode JWT parts' };
    }

    return {
      header,
      payload,
      signature,
      raw: token
    };
  },

  /**
   * Validate JWT for security issues
   * @param {Object} parsedJWT - Parsed JWT object
   * @returns {Array} Array of security issues
   */
  validateJWTSecurity: (parsedJWT) => {
    const issues = [];

    if (parsedJWT.error) {
      return [{ severity: 'HIGH', type: 'JWT_PARSE_ERROR', message: parsedJWT.error }];
    }

    // Check for dangerous algorithms
    if (parsedJWT.header.alg === 'none') {
      issues.push({
        severity: 'CRITICAL',
        type: 'JWT_ALG_NONE',
        message: 'JWT uses "none" algorithm - signature verification bypassed'
      });
    }

    // Check for weak algorithms
    const weakAlgs = ['HS256', 'RS256'];
    if (weakAlgs.includes(parsedJWT.header.alg)) {
      issues.push({
        severity: 'MEDIUM',
        type: 'JWT_WEAK_ALG',
        message: `JWT uses potentially weak algorithm: ${parsedJWT.header.alg}`
      });
    }

    // Check expiration
    if (!parsedJWT.payload.exp) {
      issues.push({
        severity: 'HIGH',
        type: 'JWT_NO_EXPIRATION',
        message: 'JWT does not have expiration claim (exp)'
      });
    } else {
      const expTime = parsedJWT.payload.exp * 1000;
      const now = Date.now();
      if (expTime < now) {
        issues.push({
          severity: 'MEDIUM',
          type: 'JWT_EXPIRED',
          message: 'JWT is expired'
        });
      }
    }

    // Check for missing critical claims
    if (!parsedJWT.payload.iss) {
      issues.push({
        severity: 'MEDIUM',
        type: 'JWT_NO_ISSUER',
        message: 'JWT missing issuer claim (iss)'
      });
    }

    if (!parsedJWT.payload.aud) {
      issues.push({
        severity: 'MEDIUM',
        type: 'JWT_NO_AUDIENCE',
        message: 'JWT missing audience claim (aud)'
      });
    }

    return issues;
  }
};
