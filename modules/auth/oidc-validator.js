// OIDC (OpenID Connect) Validator
// Detects OIDC-specific vulnerabilities beyond base OAuth2
// Reference: https://openid.net/specs/openid-connect-core-1_0.html

export class OIDCValidator {
  constructor() {
    this.name = 'OIDCValidator';
    this.trackedChallenges = new Map(); // Track nonces to detect reuse
  }

  /**
   * Analyze OIDC-specific security issues
   * @param {Object} requestData - Contains URL, method, headers, body
   * @param {Object} responseData - Contains status, headers, body
   * @returns {Array} Array of security issues
   */
  analyzeOIDCRequest(requestData, responseData) {
    const issues = [];

    try {
      const url = new URL(requestData.url);
      const params = Object.fromEntries(url.searchParams);

      // Check if this is an OIDC authorization request
      if (this._isOIDCAuthorizationRequest(params)) {
        issues.push(...this._validateAuthorizationRequest(params));
      }

      // Check if this is an OIDC token response
      if (this._isOIDCTokenResponse(responseData)) {
        issues.push(...this._validateTokenResponse(responseData, requestData));
      }

      // Check for OIDC discovery document over HTTP
      if (url.pathname.includes('/.well-known/openid-configuration')) {
        issues.push(...this._validateDiscoveryEndpoint(url));
      }

      // Check for UserInfo endpoint
      if (url.pathname.includes('/userinfo')) {
        issues.push(...this._validateUserInfoEndpoint(url, requestData));
      }

    } catch (error) {
      console.warn('OIDC validation error:', error);
    }

    return issues;
  }

  /**
   * Validate ID token JWT claims (OIDC-specific)
   * @param {Object} idToken - Parsed ID token
   * @param {Object} context - Request context (clientId, nonce, etc.)
   * @returns {Array} Array of security issues
   */
  validateIDToken(idToken, context = {}) {
    const issues = [];

    if (!idToken || !idToken.header || !idToken.payload) {
      return issues;
    }

    const payload = idToken.payload;

    // P0-1: Missing 'sub' claim (CRITICAL)
    if (!payload.sub) {
      issues.push({
        severity: 'CRITICAL',
        type: 'MISSING_SUB_CLAIM',
        message: 'ID token missing required "sub" (subject) claim',
        recommendation: 'ID token MUST contain "sub" claim - unique user identifier',
        cvss: 7.0,
        detail: 'Without sub claim, cannot identify which user this token represents',
        reference: 'https://openid.net/specs/openid-connect-core-1_0.html#IDToken',
        evidence: {
          claims: Object.keys(payload),
          risk: 'Cannot identify user - authentication meaningless'
        }
      });
    }

    // P0-2: Missing 'iss' claim (CRITICAL)
    if (!payload.iss) {
      issues.push({
        severity: 'CRITICAL',
        type: 'MISSING_ISSUER_CLAIM',
        message: 'ID token missing required "iss" (issuer) claim',
        recommendation: 'ID token MUST contain "iss" claim',
        cvss: 8.0,
        detail: 'Cannot verify which provider issued this token',
        reference: 'https://openid.net/specs/openid-connect-core-1_0.html#IDToken',
        evidence: { claims: Object.keys(payload) }
      });
    }

    // P0-3: Missing 'aud' claim (CRITICAL)
    if (!payload.aud) {
      issues.push({
        severity: 'CRITICAL',
        type: 'MISSING_AUDIENCE_CLAIM',
        message: 'ID token missing required "aud" (audience) claim',
        recommendation: 'ID token MUST contain "aud" claim matching client_id',
        cvss: 8.0,
        detail: 'Cannot verify token intended for this application',
        reference: 'https://openid.net/specs/openid-connect-core-1_0.html#IDToken',
        evidence: { claims: Object.keys(payload) }
      });
    } else if (context.clientId && !this._validateAudience(payload.aud, context.clientId)) {
      // Audience doesn't match client_id
      issues.push({
        severity: 'CRITICAL',
        type: 'AUDIENCE_MISMATCH',
        message: 'ID token audience does not match client_id',
        recommendation: 'Reject token - may be intended for different application',
        cvss: 9.0,
        detail: 'Token substitution attack - attacker swapped token from different client',
        cve: 'CVE-2021-27582',
        evidence: {
          aud: payload.aud,
          expectedClientId: context.clientId,
          risk: 'Token from one client accepted by another'
        }
      });
    }

    // P0-4: Missing 'exp' claim
    if (!payload.exp) {
      issues.push({
        severity: 'HIGH',
        type: 'MISSING_EXPIRATION_CLAIM',
        message: 'ID token missing "exp" (expiration) claim',
        recommendation: 'ID token MUST contain "exp" claim',
        cvss: 7.0,
        detail: 'Token never expires - can be replayed indefinitely',
        evidence: { claims: Object.keys(payload) }
      });
    } else {
      // Check if expired
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp < now) {
        issues.push({
          severity: 'MEDIUM',
          type: 'ID_TOKEN_EXPIRED',
          message: 'ID token has expired',
          recommendation: 'Reject expired tokens',
          cvss: 5.0,
          evidence: {
            exp: payload.exp,
            expiredSeconds: now - payload.exp,
            expiredDate: new Date(payload.exp * 1000).toISOString()
          }
        });
      }
    }

    // P0-5: 'iat' in future
    if (payload.iat) {
      const now = Math.floor(Date.now() / 1000);
      const clockSkewAllowance = 300; // 5 minutes
      if (payload.iat > now + clockSkewAllowance) {
        issues.push({
          severity: 'HIGH',
          type: 'IAT_IN_FUTURE',
          message: 'ID token "iat" (issued at) is in the future',
          recommendation: 'Reject token - possible clock skew attack',
          cvss: 6.0,
          detail: 'Token claims to be issued in the future - suspicious',
          evidence: {
            iat: payload.iat,
            now,
            futureSeconds: payload.iat - now
          }
        });
      }
    }

    // P0-6: Validate nonce if provided in context
    if (context.nonce) {
      if (!payload.nonce) {
        issues.push({
          severity: 'CRITICAL',
          type: 'MISSING_NONCE_IN_ID_TOKEN',
          message: 'ID token missing "nonce" claim when nonce was sent in request',
          recommendation: 'Reject token - nonce MUST be echoed back in ID token',
          cvss: 8.0,
          detail: 'ID token replay attack possible without nonce validation',
          cve: 'CVE-2020-26945',
          reference: 'https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes',
          evidence: {
            requestNonce: context.nonce,
            tokenHasNonce: false,
            risk: 'Attacker can replay ID token to victim session'
          }
        });
      } else if (payload.nonce !== context.nonce) {
        issues.push({
          severity: 'CRITICAL',
          type: 'NONCE_MISMATCH',
          message: 'ID token nonce does not match request nonce',
          recommendation: 'Reject token immediately - possible replay attack',
          cvss: 9.0,
          detail: 'Nonce mismatch indicates token replay or session fixation',
          evidence: {
            requestNonce: context.nonce,
            tokenNonce: payload.nonce
          }
        });
      }
    }

    // P0-7: Validate azp (authorized party) if multiple audiences
    if (Array.isArray(payload.aud) && payload.aud.length > 1) {
      if (!payload.azp) {
        issues.push({
          severity: 'HIGH',
          type: 'MISSING_AZP_CLAIM',
          message: 'ID token has multiple audiences but missing "azp" (authorized party) claim',
          recommendation: 'When multiple audiences, azp MUST be present',
          cvss: 7.0,
          detail: 'Cannot determine which client is authorized to use this token',
          cve: 'CVE-2023-45857',
          reference: 'https://openid.net/specs/openid-connect-core-1_0.html#IDToken',
          evidence: {
            audiences: payload.aud,
            audienceCount: payload.aud.length
          }
        });
      }
    }

    // P0-8: Check for at_hash if access_token present
    if (context.access_token && !payload.at_hash) {
      issues.push({
        severity: 'HIGH',
        type: 'MISSING_AT_HASH',
        message: 'ID token returned alongside access_token but missing "at_hash" claim',
        recommendation: 'When access_token returned with id_token, at_hash MUST be present',
        cvss: 7.5,
        detail: 'Token substitution attack - attacker can swap access_token',
        reference: 'https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken',
        evidence: {
          hasAccessToken: true,
          hasAtHash: false,
          risk: 'Attacker can replace access_token with their own'
        }
      });
    }

    // P0-9: Check for c_hash if authorization code present
    if (context.code && !payload.c_hash) {
      issues.push({
        severity: 'HIGH',
        type: 'MISSING_C_HASH',
        message: 'ID token returned alongside code but missing "c_hash" claim',
        recommendation: 'When code returned with id_token, c_hash MUST be present',
        cvss: 7.5,
        detail: 'Authorization code substitution attack possible',
        reference: 'https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken',
        evidence: {
          hasCode: true,
          hasCHash: false,
          risk: 'Attacker can swap authorization code'
        }
      });
    }

    // P0-10: Check acr (Authentication Context Class Reference)
    if (context.requiresHighAuth && payload.acr) {
      const acrValue = parseInt(payload.acr) || 0;
      if (acrValue < 2) {
        issues.push({
          severity: 'MEDIUM',
          type: 'WEAK_ACR_VALUE',
          message: `ID token has low acr value: ${payload.acr}`,
          recommendation: 'For sensitive operations, require acr >= 2 (MFA)',
          cvss: 6.0,
          detail: 'Application expects MFA but user authenticated with weaker method',
          evidence: {
            acr: payload.acr,
            interpretation: acrValue === 0 ? 'No authentication' :
                          acrValue === 1 ? 'Password only' :
                          'MFA',
            risk: 'User authenticated with weaker method than required'
          }
        });
      }
    }

    return issues;
  }

  // === PRIVATE METHODS ===

  _isOIDCAuthorizationRequest(params) {
    // OIDC requests have scope=openid
    return params.scope && params.scope.includes('openid');
  }

  _isOIDCTokenResponse(responseData) {
    if (!responseData || !responseData.body) return false;

    try {
      const body = typeof responseData.body === 'string' ?
        JSON.parse(responseData.body) : responseData.body;

      // OIDC token response contains id_token
      return body.id_token !== undefined;
    } catch {
      return false;
    }
  }

  _validateAuthorizationRequest(params) {
    const issues = [];
    const responseType = params.response_type || '';

    // P0-11: Check for missing nonce in implicit/hybrid flows
    if (responseType.includes('id_token')) {
      // Implicit or hybrid flow - nonce is REQUIRED
      if (!params.nonce) {
        issues.push({
          severity: 'CRITICAL',
          type: 'MISSING_NONCE_IMPLICIT_FLOW',
          message: 'OIDC implicit/hybrid flow missing required nonce parameter',
          recommendation: 'nonce MUST be included when response_type includes id_token',
          cvss: 8.0,
          detail: 'Without nonce, ID token replay attacks are trivial',
          cve: 'CVE-2020-26945',
          reference: 'https://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest',
          evidence: {
            responseType,
            flow: responseType.includes('token') ? 'implicit' : 'hybrid',
            hasNonce: false,
            risk: 'Attacker can intercept and replay ID token'
          }
        });
      } else {
        // Track nonce for validation later
        this.trackedChallenges.set(params.nonce, {
          timestamp: Date.now(),
          state: params.state
        });

        // Check nonce quality
        if (params.nonce.length < 16) {
          issues.push({
            severity: 'HIGH',
            type: 'WEAK_NONCE',
            message: 'OIDC nonce too short (minimum 16 characters recommended)',
            recommendation: 'Use cryptographically random nonce >= 128 bits',
            cvss: 6.0,
            evidence: {
              nonce: params.nonce,
              length: params.nonce.length
            }
          });
        }
      }
    }

    return issues;
  }

  _validateTokenResponse(responseData, requestData) {
    const issues = [];

    try {
      const body = typeof responseData.body === 'string' ?
        JSON.parse(responseData.body) : responseData.body;

      if (!body.id_token) return issues;

      // Parse ID token (it's a JWT)
      const idToken = this._parseJWT(body.id_token);
      if (!idToken) return issues;

      // Build context for validation
      const context = {
        access_token: body.access_token,
        clientId: this._extractClientId(requestData),
        nonce: this._extractNonce(requestData)
      };

      // Run full ID token validation
      issues.push(...this.validateIDToken(idToken, context));

      // P0-12: Check if ID token used as access token (common mistake)
      if (this._detectIDTokenAsAccessToken(body, requestData)) {
        issues.push({
          severity: 'CRITICAL',
          type: 'ID_TOKEN_USED_AS_ACCESS_TOKEN',
          message: 'ID token being used as access token to call APIs',
          recommendation: 'NEVER use ID token for API access - use access_token only',
          cvss: 8.0,
          detail: 'ID token contains PII and is not designed for API access',
          reference: 'https://auth0.com/blog/why-should-use-accesstokens-to-secure-an-api/',
          evidence: {
            risk: 'ID token (containing email, name, etc.) leaked to API providers',
            correctUsage: 'Use access_token for API calls, id_token only for authentication'
          }
        });
      }

    } catch (error) {
      console.warn('Error validating OIDC token response:', error);
    }

    return issues;
  }

  _validateDiscoveryEndpoint(url) {
    const issues = [];

    // P0-13: Discovery document MUST be over HTTPS
    if (url.protocol === 'http:') {
      issues.push({
        severity: 'CRITICAL',
        type: 'DISCOVERY_DOCUMENT_OVER_HTTP',
        message: 'OIDC discovery document fetched over HTTP',
        recommendation: 'Discovery endpoint MUST use HTTPS',
        cvss: 9.0,
        detail: 'MITM attacker can inject malicious authorization/token endpoints',
        reference: 'https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig',
        evidence: {
          url: url.href,
          protocol: 'HTTP',
          risk: 'Attacker can redirect OAuth flow to malicious endpoints'
        }
      });
    }

    return issues;
  }

  _validateUserInfoEndpoint(url, requestData) {
    const issues = [];

    // P0-14: UserInfo endpoint should be HTTPS
    if (url.protocol === 'http:') {
      issues.push({
        severity: 'MEDIUM',
        type: 'USERINFO_OVER_HTTP',
        message: 'UserInfo endpoint called over HTTP',
        recommendation: 'UserInfo endpoint should use HTTPS (contains PII)',
        cvss: 6.0,
        detail: 'User information (email, name, etc.) transmitted unencrypted',
        evidence: {
          url: url.href,
          risk: 'PII leakage via network sniffing'
        }
      });
    }

    return issues;
  }

  _validateAudience(aud, clientId) {
    // aud can be string or array
    if (Array.isArray(aud)) {
      return aud.includes(clientId);
    }
    return aud === clientId;
  }

  _parseJWT(token) {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
      const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

      return { header, payload, signature: parts[2] };
    } catch {
      return null;
    }
  }

  _extractClientId(requestData) {
    try {
      if (requestData.body) {
        const body = typeof requestData.body === 'string' ?
          JSON.parse(requestData.body) : requestData.body;
        return body.client_id;
      }
    } catch {}
    return null;
  }

  _extractNonce(requestData) {
    try {
      const url = new URL(requestData.url);
      return url.searchParams.get('nonce');
    } catch {}
    return null;
  }

  _detectIDTokenAsAccessToken(tokenResponse, requestData) {
    // Heuristic: If we see ID token being sent in Authorization header later
    // This is hard to detect in real-time, but we can flag if access_token missing
    if (!tokenResponse.access_token && tokenResponse.id_token) {
      return true; // Only ID token provided, likely to be misused
    }
    return false;
  }
}
