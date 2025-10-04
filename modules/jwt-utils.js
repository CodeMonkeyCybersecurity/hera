/**
 * JWT Utilities
 *
 * Pure functions for JWT parsing and security analysis.
 * No external dependencies, fully testable.
 */

/**
 * Analyze JWT token for security vulnerabilities
 *
 * SECURITY: Detects critical JWT vulnerabilities:
 * - Algorithm "none" attack (CVE-2015-9235)
 * - Algorithm confusion attacks (symmetric vs asymmetric)
 * - Missing or excessive expiration times
 * - Sensitive data in payload (JWTs are base64, not encrypted)
 * - Missing security claims (iss, aud, sub)
 *
 * @param {string} tokenValue - JWT token (can include "Bearer" or "JWT" prefix)
 * @returns {Object} Security analysis
 * @property {number} riskScore - Overall risk score (0-200+)
 * @property {Array<Object>} riskFactors - Individual risk factors found
 * @property {Array<Object>} vulnerabilities - Security vulnerabilities detected
 * @property {Object|null} decodedToken - Decoded header/payload/signature
 *
 * @example
 * analyzeJWT('Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.')
 * // Returns: {
 * //   riskScore: 100,
 * //   riskFactors: [{ type: 'JWT_ALG_NONE', severity: 'CRITICAL', ... }],
 * //   vulnerabilities: [{ category: 'JWT Security', finding: 'Algorithm None Attack', ... }],
 * //   decodedToken: { header: {...}, payload: {...}, signature: '' }
 * // }
 */
export function analyzeJWT(tokenValue) {
  const analysis = {
    riskScore: 0,
    riskFactors: [],
    vulnerabilities: [],
    decodedToken: null
  };

  try {
    // Extract JWT from various formats
    let jwt = tokenValue.replace(/^Bearer\s+/i, '').replace(/^jwt\s+/i, '').trim();

    // Basic JWT format check
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      return analysis; // Not a valid JWT
    }

    // Decode header and payload
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

    analysis.decodedToken = {
      header: header,
      payload: payload,
      signature: parts[2]
    };

    // Check for critical vulnerabilities

    // 1. Algorithm "none" vulnerability
    if (header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE') {
      analysis.riskScore += 100;
      analysis.riskFactors.push({
        type: 'JWT_ALG_NONE',
        severity: 'CRITICAL',
        points: 100,
        description: 'JWT uses "none" algorithm - signature verification disabled',
        recommendation: 'Use a proper signing algorithm (RS256, ES256, HS256)'
      });
      analysis.vulnerabilities.push({
        category: 'JWT Security',
        finding: 'Algorithm None Attack',
        severity: 'CRITICAL',
        description: 'JWT token uses "none" algorithm, allowing signature bypass',
        impact: 'Attackers can create valid tokens without knowing the secret key'
      });
    }

    // 2. Weak algorithms
    if (['HS256', 'HS384', 'HS512'].includes(header.alg)) {
      analysis.riskScore += 20;
      analysis.riskFactors.push({
        type: 'JWT_WEAK_ALG',
        severity: 'MEDIUM',
        points: 20,
        description: `JWT uses symmetric algorithm ${header.alg} which may be vulnerable to algorithm confusion`,
        recommendation: 'Consider using asymmetric algorithms like RS256 or ES256'
      });
    }

    // 3. No expiration
    if (!payload.exp) {
      analysis.riskScore += 30;
      analysis.riskFactors.push({
        type: 'JWT_NO_EXPIRATION',
        severity: 'HIGH',
        points: 30,
        description: 'JWT has no expiration time (exp claim missing)',
        recommendation: 'Set appropriate expiration time for tokens'
      });
      analysis.vulnerabilities.push({
        category: 'JWT Security',
        finding: 'Missing Token Expiration',
        severity: 'HIGH',
        description: 'JWT token has no expiration claim, creating indefinite validity',
        impact: 'Compromised tokens remain valid indefinitely'
      });
    }

    // 4. Long expiration (more than 24 hours)
    if (payload.exp) {
      const expirationTime = new Date(payload.exp * 1000);
      const issuedTime = payload.iat ? new Date(payload.iat * 1000) : new Date();
      const lifetimeHours = (expirationTime.getTime() - issuedTime.getTime()) / (1000 * 60 * 60);

      if (lifetimeHours > 24) {
        analysis.riskScore += 15;
        analysis.riskFactors.push({
          type: 'JWT_LONG_EXPIRATION',
          severity: 'MEDIUM',
          points: 15,
          description: `JWT has very long expiration time (${Math.round(lifetimeHours)} hours)`,
          recommendation: 'Use shorter token lifetimes with refresh token pattern'
        });
      }
    }

    // 5. Sensitive data in payload
    const sensitiveFields = ['password', 'secret', 'key', 'token', 'ssn', 'credit', 'card'];
    const payloadStr = JSON.stringify(payload).toLowerCase();
    const foundSensitive = sensitiveFields.filter(field => payloadStr.includes(field));

    if (foundSensitive.length > 0) {
      analysis.riskScore += 40;
      analysis.riskFactors.push({
        type: 'JWT_SENSITIVE_DATA',
        severity: 'HIGH',
        points: 40,
        description: `JWT payload contains potentially sensitive fields: ${foundSensitive.join(', ')}`,
        recommendation: 'Avoid storing sensitive data in JWT payload'
      });
      analysis.vulnerabilities.push({
        category: 'Information Disclosure',
        finding: 'Sensitive Data in JWT',
        severity: 'HIGH',
        description: 'JWT payload contains sensitive information',
        impact: 'Sensitive data is exposed as JWTs are only base64 encoded, not encrypted'
      });
    }

    // 6. Missing critical claims
    const requiredClaims = ['iss', 'aud', 'sub'];
    const missingClaims = requiredClaims.filter(claim => !payload[claim]);

    if (missingClaims.length > 0) {
      analysis.riskScore += 10;
      analysis.riskFactors.push({
        type: 'JWT_MISSING_CLAIMS',
        severity: 'LOW',
        points: 10,
        description: `JWT missing recommended claims: ${missingClaims.join(', ')}`,
        recommendation: 'Include issuer (iss), audience (aud), and subject (sub) claims'
      });
    }

  } catch (error) {
    // If we can't decode it, it might not be a valid JWT
    console.log('JWT analysis failed:', error);
  }

  return analysis;
}
