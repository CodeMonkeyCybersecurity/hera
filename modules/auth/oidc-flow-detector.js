/**
 * OIDC Flow Detector
 *
 * Detects and validates OIDC flow types from authorization requests.
 * Identifies: Authorization Code Flow, Implicit Flow (deprecated), and Hybrid Flow.
 *
 * Reference:
 * - OpenID Connect Core 1.0: https://openid.net/specs/openid-connect-core-1_0.html
 * - OAuth 2.0 for Browser-Based Apps: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps
 *
 * PHASE 2 Implementation
 */

export class OIDCFlowDetector {
  constructor() {
    this.name = 'OIDCFlowDetector';

    // Flow type definitions based on response_type
    this.FLOW_TYPES = {
      'code': {
        type: 'AUTHORIZATION_CODE',
        description: 'Authorization Code Flow (recommended)',
        security: 'SECURE',
        requiresPKCE: true,
        requiresNonce: false,
        tokenEndpoint: true,
        deprecated: false,
        oidcSpec: 'https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth'
      },
      'id_token': {
        type: 'IMPLICIT',
        description: 'Implicit Flow with ID Token only (DEPRECATED)',
        security: 'INSECURE',
        requiresPKCE: false,
        requiresNonce: true,
        tokenEndpoint: false,
        deprecated: true,
        oidcSpec: 'https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth'
      },
      'id_token token': {
        type: 'IMPLICIT',
        description: 'Implicit Flow with ID Token and Access Token (DEPRECATED)',
        security: 'INSECURE',
        requiresPKCE: false,
        requiresNonce: true,
        tokenEndpoint: false,
        deprecated: true,
        oidcSpec: 'https://openid.net/specs/openid-connect-core-1_0.html#ImplicitFlowAuth'
      },
      'code id_token': {
        type: 'HYBRID',
        description: 'Hybrid Flow (code + id_token)',
        security: 'MEDIUM',
        requiresPKCE: true,
        requiresNonce: true,
        tokenEndpoint: true,
        deprecated: false,
        oidcSpec: 'https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth'
      },
      'code token': {
        type: 'HYBRID',
        description: 'Hybrid Flow (code + access_token)',
        security: 'MEDIUM',
        requiresPKCE: true,
        requiresNonce: true,
        tokenEndpoint: true,
        deprecated: false,
        oidcSpec: 'https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth'
      },
      'code id_token token': {
        type: 'HYBRID',
        description: 'Hybrid Flow (all tokens)',
        security: 'MEDIUM',
        requiresPKCE: true,
        requiresNonce: true,
        tokenEndpoint: true,
        deprecated: false,
        oidcSpec: 'https://openid.net/specs/openid-connect-core-1_0.html#HybridFlowAuth'
      }
    };
  }

  /**
   * Detect OIDC flow type from authorization request
   * @param {Object} requestDetails - Chrome webRequest details or URL object
   * @returns {Object} Flow detection result
   */
  detectFlow(requestDetails) {
    try {
      // Extract URL from different input formats
      const url = this._extractUrl(requestDetails);
      if (!url) {
        return { detected: false, reason: 'invalid_url' };
      }

      const params = new URLSearchParams(url.search);
      const scope = params.get('scope');
      const responseType = params.get('response_type');

      // Check if this is OIDC (must have openid scope)
      if (!scope || !scope.includes('openid')) {
        return {
          detected: false,
          reason: 'not_oidc',
          isOAuth2: !!responseType,
          scope: scope,
          note: 'OAuth2 flow without openid scope'
        };
      }

      // Not an authorization request if no response_type
      if (!responseType) {
        return {
          detected: false,
          reason: 'missing_response_type',
          isOIDC: true,
          note: 'Has openid scope but missing response_type parameter'
        };
      }

      // Lookup flow type
      const flowDef = this.FLOW_TYPES[responseType];

      if (!flowDef) {
        return {
          detected: true,
          oidc: true,
          type: 'UNKNOWN',
          description: `Unknown OIDC response_type: ${responseType}`,
          security: 'UNKNOWN',
          responseType,
          scopes: scope.split(' '),
          warning: 'Non-standard response_type detected'
        };
      }

      // Build flow detection result
      const flow = {
        detected: true,
        oidc: true,
        type: flowDef.type,
        description: flowDef.description,
        security: flowDef.security,
        deprecated: flowDef.deprecated,
        responseType: responseType,
        scopes: scope.split(' '),
        requirements: {
          pkce: flowDef.requiresPKCE,
          nonce: flowDef.requiresNonce,
          tokenEndpoint: flowDef.tokenEndpoint
        },
        reference: flowDef.oidcSpec,
        parameters: this._extractAuthParams(params)
      };

      return flow;

    } catch (error) {
      console.warn('Hera: OIDC flow detection error:', error);
      return {
        detected: false,
        reason: 'detection_error',
        error: error.message
      };
    }
  }

  /**
   * Validate flow security based on detected type
   * @param {Object} flow - Flow detection result from detectFlow()
   * @param {Object} requestParams - Authorization request parameters
   * @returns {Array} Security issues found
   */
  validateFlowSecurity(flow, requestParams = null) {
    const issues = [];

    if (!flow.detected || !flow.oidc) {
      return issues;
    }

    // Extract parameters if not provided
    const params = requestParams || flow.parameters || {};

    // Issue 1: Deprecated implicit flow
    if (flow.deprecated) {
      issues.push({
        severity: 'HIGH',
        type: 'DEPRECATED_OIDC_FLOW',
        message: `Using deprecated OIDC ${flow.type} flow`,
        recommendation: 'Migrate to Authorization Code Flow with PKCE',
        cvss: 7.0,
        detail: 'Implicit flow exposes tokens in URL (browser history, logs, referrer headers)',
        cve: 'CWE-598',
        reference: 'https://oauth.net/2/browser-based-apps/',
        evidence: {
          flow: flow.type,
          responseType: flow.responseType,
          deprecatedSince: '2019',
          risk: 'Tokens exposed in URL fragments (browser history, proxy logs, analytics)',
          mitigationExists: 'Authorization Code Flow + PKCE provides better security'
        }
      });
    }

    // Issue 2: Missing PKCE in flows that require it
    if (flow.requirements.pkce && !params.code_challenge) {
      issues.push({
        severity: 'CRITICAL',
        type: 'MISSING_PKCE_OIDC',
        message: `${flow.type} flow missing required PKCE`,
        recommendation: 'Add code_challenge and code_challenge_method parameters',
        cvss: 8.0,
        detail: 'Public clients MUST use PKCE to prevent authorization code interception',
        cve: 'CWE-863',
        reference: 'https://tools.ietf.org/html/rfc7636',
        evidence: {
          flow: flow.type,
          requiresPKCE: true,
          hasCodeChallenge: false,
          risk: 'Authorization code can be intercepted and exchanged for tokens',
          attackScenario: 'Attacker intercepts redirect, extracts code, exchanges before victim'
        }
      });
    }

    // Issue 3: Missing nonce in flows that require it
    if (flow.requirements.nonce && !params.nonce) {
      issues.push({
        severity: 'CRITICAL',
        type: 'MISSING_NONCE_OIDC',
        message: `${flow.type} flow missing required nonce`,
        recommendation: 'Add nonce parameter to prevent replay attacks',
        cvss: 8.0,
        detail: 'Nonce MUST be included when response_type includes id_token',
        cve: 'CVE-2020-26945',
        reference: 'https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes',
        evidence: {
          flow: flow.type,
          responseType: flow.responseType,
          requiresNonce: true,
          hasNonce: false,
          risk: 'ID token can be replayed to victim session',
          attackScenario: 'Attacker captures ID token and injects into own session'
        }
      });
    }

    // Issue 4: Validate PKCE method if present
    if (params.code_challenge) {
      const method = params.code_challenge_method || 'plain';

      if (method === 'plain') {
        issues.push({
          severity: 'MEDIUM',
          type: 'WEAK_PKCE_METHOD',
          message: 'PKCE using "plain" method instead of S256',
          recommendation: 'Use code_challenge_method=S256 (SHA-256)',
          cvss: 6.0,
          detail: 'Plain method does not hash the verifier, reducing security',
          reference: 'https://tools.ietf.org/html/rfc7636#section-4.2',
          evidence: {
            method: method,
            recommended: 'S256',
            risk: 'Code verifier transmitted unhashed increases attack surface'
          }
        });
      }
    }

    // Issue 5: Weak nonce if present
    if (params.nonce) {
      const nonce = params.nonce;

      if (nonce.length < 16) {
        issues.push({
          severity: 'HIGH',
          type: 'WEAK_NONCE',
          message: 'OIDC nonce too short (minimum 16 characters recommended)',
          recommendation: 'Use cryptographically random nonce >= 128 bits (22+ base64 chars)',
          cvss: 6.5,
          detail: `Nonce is ${nonce.length} characters, should be >=16 for adequate entropy`,
          evidence: {
            nonceLength: nonce.length,
            minimumRecommended: 16,
            actualEntropy: this._estimateEntropy(nonce),
            recommendedEntropy: 128
          }
        });
      }
    }

    // Issue 6: Missing state parameter (CSRF protection)
    if (!params.state) {
      issues.push({
        severity: 'HIGH',
        type: 'MISSING_STATE_PARAMETER',
        message: 'Authorization request missing state parameter',
        recommendation: 'Add state parameter for CSRF protection',
        cvss: 7.5,
        detail: 'State parameter prevents CSRF attacks on the callback endpoint',
        cve: 'CWE-352',
        reference: 'https://tools.ietf.org/html/rfc6749#section-10.12',
        evidence: {
          hasState: false,
          risk: 'Attacker can initiate authorization flow and trick victim into completing it',
          attackScenario: 'CSRF on OAuth callback endpoint'
        }
      });
    } else if (params.state.length < 16) {
      issues.push({
        severity: 'MEDIUM',
        type: 'WEAK_STATE_PARAMETER',
        message: 'State parameter has low entropy',
        recommendation: 'Use cryptographically random state >= 128 bits',
        cvss: 6.0,
        evidence: {
          stateLength: params.state.length,
          minimumRecommended: 16
        }
      });
    }

    // Issue 7: Check for risky scopes
    const riskyScopes = this._analyzeScopes(flow.scopes);
    if (riskyScopes.length > 0) {
      issues.push({
        severity: 'MEDIUM',
        type: 'RISKY_SCOPE_REQUEST',
        message: 'Authorization request includes risky scopes',
        recommendation: 'Review and minimize requested scopes',
        cvss: 5.0,
        detail: 'Requesting excessive permissions increases attack impact',
        evidence: {
          riskyScopes: riskyScopes,
          allScopes: flow.scopes,
          recommendation: 'Only request scopes necessary for application functionality'
        }
      });
    }

    return issues;
  }

  /**
   * Extract authorization parameters from URLSearchParams
   * @param {URLSearchParams} params - URL search parameters
   * @returns {Object} Extracted parameters
   */
  _extractAuthParams(params) {
    return {
      client_id: params.get('client_id'),
      redirect_uri: params.get('redirect_uri'),
      scope: params.get('scope'),
      response_type: params.get('response_type'),
      response_mode: params.get('response_mode'),
      state: params.get('state'),
      nonce: params.get('nonce'),
      code_challenge: params.get('code_challenge'),
      code_challenge_method: params.get('code_challenge_method'),
      prompt: params.get('prompt'),
      max_age: params.get('max_age'),
      ui_locales: params.get('ui_locales'),
      id_token_hint: params.get('id_token_hint'),
      login_hint: params.get('login_hint'),
      acr_values: params.get('acr_values')
    };
  }

  /**
   * Extract URL from various input formats
   * @param {Object|String} input - Request details or URL string
   * @returns {URL|null} Parsed URL object
   */
  _extractUrl(input) {
    try {
      if (typeof input === 'string') {
        return new URL(input);
      }

      if (input instanceof URL) {
        return input;
      }

      if (input.url) {
        return new URL(input.url);
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  /**
   * Estimate entropy of a string (rough calculation)
   * @param {string} str - String to analyze
   * @returns {number} Estimated entropy in bits
   */
  _estimateEntropy(str) {
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

    return Math.round(entropy * len);
  }

  /**
   * Analyze scopes for risky permissions
   * @param {Array} scopes - Array of scope strings
   * @returns {Array} Array of risky scopes
   */
  _analyzeScopes(scopes) {
    const riskyPatterns = [
      { pattern: /admin/i, reason: 'Administrative access' },
      { pattern: /write.*all/i, reason: 'Broad write permissions' },
      { pattern: /delete/i, reason: 'Delete permissions' },
      { pattern: /.*\.all$/i, reason: 'Access to all resources' },
      { pattern: /full_access/i, reason: 'Full access scope' },
      { pattern: /cloud-platform/i, reason: 'Cloud platform access' }
    ];

    const risky = [];

    for (const scope of scopes) {
      for (const { pattern, reason } of riskyPatterns) {
        if (pattern.test(scope)) {
          risky.push({ scope, reason });
          break;
        }
      }
    }

    return risky;
  }

  /**
   * Get flow recommendations based on detected flow type
   * @param {Object} flow - Flow detection result
   * @returns {Object} Recommendations
   */
  getFlowRecommendations(flow) {
    if (!flow.detected || !flow.oidc) {
      return { recommendations: [] };
    }

    const recommendations = {
      current: {
        flow: flow.type,
        security: flow.security,
        deprecated: flow.deprecated
      },
      recommendations: []
    };

    if (flow.deprecated) {
      recommendations.recommendations.push({
        priority: 'HIGH',
        action: 'Migrate to Authorization Code Flow with PKCE',
        reason: 'Implicit flow is deprecated due to security concerns',
        implementation: {
          responseType: 'code',
          addPKCE: true,
          addNonce: false,
          example: 'response_type=code&code_challenge=...&code_challenge_method=S256'
        }
      });
    }

    if (flow.type === 'AUTHORIZATION_CODE' && !flow.parameters?.code_challenge) {
      recommendations.recommendations.push({
        priority: 'CRITICAL',
        action: 'Add PKCE to authorization code flow',
        reason: 'Public clients must use PKCE',
        implementation: {
          steps: [
            '1. Generate random code_verifier (43-128 characters)',
            '2. Calculate code_challenge = BASE64URL(SHA256(code_verifier))',
            '3. Add code_challenge and code_challenge_method=S256 to auth request',
            '4. Send code_verifier in token request'
          ]
        }
      });
    }

    if (flow.type === 'HYBRID') {
      recommendations.recommendations.push({
        priority: 'MEDIUM',
        action: 'Consider using Authorization Code Flow instead of Hybrid',
        reason: 'Hybrid flow complexity rarely justified',
        implementation: {
          responseType: 'code',
          benefits: ['Simpler implementation', 'Fewer token exposure points', 'Easier to audit']
        }
      });
    }

    return recommendations;
  }
}
