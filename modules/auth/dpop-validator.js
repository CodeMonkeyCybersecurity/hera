/**
 * DPoP Validator - RFC 9449 Demonstrating Proof-of-Possession
 *
 * PURPOSE:
 * - Detect DPoP implementation in OAuth2 token responses
 * - Validate DPoP JWT headers if present
 * - Generate INFO-level findings (DPoP is OPTIONAL per RFC 9449)
 *
 * IMPORTANT:
 * - DPoP is OPTIONAL, not required
 * - Severity is INFO (informational), not MEDIUM/HIGH
 * - Only flag as HIGH if client explicitly registered for DPoP-bound tokens
 *
 * RFC 9449: https://datatracker.ietf.org/doc/html/rfc9449
 *
 * @see ROADMAP.md P1-5 for implementation details
 * @see CLAUDE.md Part 11 for adversarial analysis
 */

export class DPoPValidator {
  constructor() {
    this.dpopBindings = new Map(); // clientId -> dpop_bound_access_tokens setting
  }

  /**
   * Check if DPoP is implemented for OAuth2 token responses
   *
   * @param {Object} request - Original token request
   * @param {Object} responseBody - Parsed token response body
   * @returns {Object|null} Finding if DPoP not implemented, null otherwise
   */
  checkDPoPImplementation(request, responseBody) {
    if (!responseBody || !request) {
      return null;
    }

    // Check for DPoP header in request
    const hasDPoPHeader = request.headers?.some(h =>
      h.name.toLowerCase() === 'dpop'
    ) || false;

    // Check token_type in response
    const tokenType = responseBody.token_type?.toLowerCase();
    const isDPoP = tokenType === 'dpop';

    // Infer client type
    const clientType = this._inferClientType(request);

    // If DPoP is implemented, no finding
    if (isDPoP && hasDPoPHeader) {
      return null;
    }

    // Check if client explicitly registered for DPoP-bound tokens
    const clientId = this._extractClientId(request);
    const requiresDPoP = this.dpopBindings.get(clientId)?.dpop_bound_access_tokens === true;

    if (requiresDPoP && !isDPoP) {
      // CRITICAL: Client registered for DPoP but not using it
      return {
        type: 'DPOP_REQUIRED_BUT_MISSING',
        severity: 'HIGH',
        message: 'Client registered for DPoP-bound tokens but DPoP not detected',
        cwe: 'CWE-319',
        evidence: {
          clientId: clientId,
          tokenType: tokenType || 'bearer',
          dpopHeaderPresent: hasDPoPHeader,
          recommendation: 'Implement DPoP per RFC 9449 - required for this client'
        },
        rfcReference: 'RFC 9449 Section 5'
      };
    }

    // DPoP is optional, generate INFO finding for awareness
    if (clientType === 'public' && !isDPoP) {
      return {
        type: 'DPOP_NOT_IMPLEMENTED',
        severity: 'INFO',  // ← CORRECTED: DPoP is OPTIONAL
        message: 'DPoP not detected - tokens not sender-constrained',
        note: 'DPoP is optional per RFC 9449 Section 1. Consider implementing for enhanced security.',
        cwe: 'CWE-319',
        confidence: 'HIGH',
        evidence: {
          endpoint: request.url,
          clientType: 'public',
          tokenType: tokenType || 'bearer',
          dpopHeaderPresent: hasDPoPHeader,
          recommendation: 'Consider implementing DPoP per RFC 9449 for defense-in-depth'
        },
        rfcReference: 'RFC 9449 Section 1 (optional mechanism)'
      };
    }

    return null; // No finding
  }

  /**
   * Validate DPoP JWT structure if present
   *
   * @param {string} dpopHeader - DPoP JWT from request header
   * @param {Object} context - Request context (method, URL, etc.)
   * @returns {Object|null} Finding if validation fails, null if valid
   */
  validateDPoPJWT(dpopHeader, context) {
    if (!dpopHeader) {
      return null;
    }

    try {
      // Decode JWT (header.payload.signature)
      const parts = dpopHeader.split('.');
      if (parts.length !== 3) {
        return {
          type: 'DPOP_INVALID_JWT',
          severity: 'MEDIUM',
          message: 'DPoP JWT malformed - not 3 parts',
          evidence: { dpopHeader: dpopHeader.substring(0, 50) + '...' }
        };
      }

      // Decode header
      const header = JSON.parse(atob(parts[0]));

      // RFC 9449 Section 4.2: Required header claims
      const requiredClaims = ['typ', 'alg', 'jwk'];
      const missingClaims = requiredClaims.filter(claim => !header[claim]);

      if (missingClaims.length > 0) {
        return {
          type: 'DPOP_MISSING_CLAIMS',
          severity: 'MEDIUM',
          message: `DPoP JWT missing required claims: ${missingClaims.join(', ')}`,
          evidence: {
            header: header,
            missingClaims: missingClaims
          },
          rfcReference: 'RFC 9449 Section 4.2'
        };
      }

      // Check typ is "dpop+jwt"
      if (header.typ !== 'dpop+jwt') {
        return {
          type: 'DPOP_INVALID_TYP',
          severity: 'MEDIUM',
          message: 'DPoP JWT typ must be "dpop+jwt"',
          evidence: { typ: header.typ },
          rfcReference: 'RFC 9449 Section 4.2'
        };
      }

      // Decode payload
      const payload = JSON.parse(atob(parts[1]));

      // RFC 9449 Section 4.2: Required payload claims
      const requiredPayloadClaims = ['jti', 'htm', 'htu', 'iat'];
      const missingPayload = requiredPayloadClaims.filter(claim => !payload[claim]);

      if (missingPayload.length > 0) {
        return {
          type: 'DPOP_MISSING_PAYLOAD_CLAIMS',
          severity: 'MEDIUM',
          message: `DPoP JWT missing required payload claims: ${missingPayload.join(', ')}`,
          evidence: {
            payload: payload,
            missingClaims: missingPayload
          },
          rfcReference: 'RFC 9449 Section 4.2'
        };
      }

      // Validate htm matches request method
      if (context.method && payload.htm !== context.method) {
        return {
          type: 'DPOP_HTM_MISMATCH',
          severity: 'HIGH',
          message: 'DPoP htm claim does not match request method',
          evidence: {
            expected: context.method,
            actual: payload.htm
          },
          rfcReference: 'RFC 9449 Section 4.2'
        };
      }

      // Validate htu matches request URL (without query/fragment)
      if (context.url) {
        const requestUrl = new URL(context.url);
        const expectedHtu = `${requestUrl.origin}${requestUrl.pathname}`;
        if (payload.htu !== expectedHtu) {
          return {
            type: 'DPOP_HTU_MISMATCH',
            severity: 'HIGH',
            message: 'DPoP htu claim does not match request URL',
            evidence: {
              expected: expectedHtu,
              actual: payload.htu
            },
            rfcReference: 'RFC 9449 Section 4.2'
          };
        }
      }

      // All validations passed
      return null;

    } catch (error) {
      return {
        type: 'DPOP_JWT_DECODE_ERROR',
        severity: 'MEDIUM',
        message: 'Failed to decode DPoP JWT',
        evidence: { error: error.message }
      };
    }
  }

  /**
   * Infer client type from request characteristics
   *
   * @param {Object} request - OAuth2 token request
   * @returns {string} 'public', 'confidential', or 'unknown'
   */
  _inferClientType(request) {
    const url = request.url;
    const body = request.requestBody || '';

    // Check redirect_uri if this is authorization request
    const redirectUri = this._extractRedirectUri(url);
    if (redirectUri) {
      const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1|::1)/.test(redirectUri);
      const isCustomScheme = /^[a-z][a-z0-9+.-]*:\/\//.test(redirectUri) &&
                             !redirectUri.startsWith('http');

      if (isLocalhost || isCustomScheme) {
        return 'public'; // Mobile app, SPA, or desktop app
      }
    }

    // Check for client_secret in body (confidential client indicator)
    if (body.includes('client_secret=')) {
      return 'confidential';
    }

    // Check for PKCE (public client indicator)
    if (url.includes('code_challenge=') || body.includes('code_verifier=')) {
      return 'public';
    }

    return 'unknown';
  }

  /**
   * Extract client_id from request
   */
  _extractClientId(request) {
    const url = new URL(request.url);
    const clientId = url.searchParams.get('client_id');
    if (clientId) return clientId;

    // Check in body
    const body = request.requestBody || '';
    const match = body.match(/client_id=([^&]+)/);
    return match ? decodeURIComponent(match[1]) : null;
  }

  /**
   * Extract redirect_uri from request
   */
  _extractRedirectUri(url) {
    const urlObj = new URL(url);
    return urlObj.searchParams.get('redirect_uri');
  }

  /**
   * Register a client's DPoP binding configuration
   *
   * @param {string} clientId - OAuth2 client ID
   * @param {boolean} dpopBound - Whether client requires DPoP-bound tokens
   */
  registerClientDPoPBinding(clientId, dpopBound) {
    this.dpopBindings.set(clientId, {
      dpop_bound_access_tokens: dpopBound,
      registeredAt: Date.now()
    });
  }
}
