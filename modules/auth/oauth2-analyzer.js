// OAuth2 Quality Analysis Module
// Analyzes state parameters, entropy, grant types, redirect URIs, and scopes

class OAuth2Analyzer {
  constructor() {
    // Grant types and their security levels
    this.grantTypes = {
      'authorization_code': { secure: true, recommended: true, pkceRequired: true },
      'implicit': { secure: false, recommended: false, deprecated: true },
      'password': { secure: false, recommended: false, legacy: true },
      'client_credentials': { secure: true, recommended: true, machineToMachine: true },
      'refresh_token': { secure: true, recommended: true },
      'device_code': { secure: true, recommended: true, iot: true }
    };

    // Dangerous OAuth scopes
    this.dangerousScopes = {
      // Google
      'https://www.googleapis.com/auth/admin.directory.user.readonly': 'Read all user data in domain',
      'https://www.googleapis.com/auth/cloud-platform': 'Full GCP access',

      // Microsoft
      'https://graph.microsoft.com/.default': 'All permissions app has consent for',
      'Directory.ReadWrite.All': 'Read/write all directory data',
      'Mail.ReadWrite': 'Read/write all mailboxes',

      // Generic
      'admin': 'Administrative access',
      'write': 'Write access to all resources',
      '*': 'Wildcard - all permissions'
    };

    // Known OAuth providers
    this.knownProviders = [
      { domain: 'login.microsoftonline.com', name: 'Microsoft', type: 'Azure AD' },
      { domain: 'accounts.google.com', name: 'Google', type: 'Google Identity' },
      { domain: 'github.com', name: 'GitHub', type: 'GitHub OAuth' },
      { domain: 'facebook.com', name: 'Facebook', type: 'Facebook Login' },
      { domain: 'auth0.com', name: 'Auth0', type: 'Auth0' },
      { domain: 'okta.com', name: 'Okta', type: 'Okta' },
      { domain: 'salesforce.com', name: 'Salesforce', type: 'Salesforce Identity' },
      { domain: 'linkedin.com', name: 'LinkedIn', type: 'LinkedIn OAuth' },
      { domain: 'amazon.com', name: 'Amazon', type: 'Login with Amazon' },
      { domain: 'apple.com', name: 'Apple', type: 'Sign in with Apple' }
    ];
  }

  /**
   * Calculate the entropy of a string
   * Returns both per-character entropy and total information content
   */
  calculateEntropy(str) {
    if (!str) return { perChar: 0, total: 0 };

    // Count character frequencies
    const freq = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    // Calculate Shannon entropy (bits per character)
    let entropyPerChar = 0;
    const len = str.length;
    for (const char in freq) {
      const p = freq[char] / len;
      entropyPerChar -= p * Math.log2(p);
    }

    return {
      perChar: entropyPerChar,
      total: entropyPerChar * len
    };
  }

  /**
   * Analyze the quality of a state parameter
   */
  analyzeStateQuality(state) {
    const entropyData = this.calculateEntropy(state);

    const analysis = {
      exists: !!state,
      length: state ? state.length : 0,
      entropyPerChar: entropyData.perChar,
      totalEntropy: entropyData.total,
      appearsRandom: false,
      risk: 'HIGH'
    };

    // Check entropy per character (should be >= 3 bits for decent randomness)
    // AND total entropy (should be >= 64 bits minimum for security)
    if (entropyData.perChar >= 3 && entropyData.total >= 128) {
      analysis.appearsRandom = true;
      analysis.risk = 'LOW';
    } else if (entropyData.perChar >= 2 && entropyData.total >= 64) {
      analysis.risk = 'MEDIUM';
    }

    return analysis;
  }

  /**
   * Analyze OAuth2 grant type
   * @param {string} grantType - Grant type from request
   * @param {Object} params - Request parameters
   * @returns {Object} Analysis with security issues
   */
  analyzeGrantType(grantType, params = {}) {
    const issues = [];
    let riskScore = 0;

    if (!grantType) {
      // Try to infer from response_type
      if (params.response_type) {
        if (params.response_type === 'code') {
          grantType = 'authorization_code';
        } else if (params.response_type.includes('token')) {
          grantType = 'implicit';
        }
      }
    }

    const grantInfo = this.grantTypes[grantType];

    if (!grantInfo) {
      issues.push({
        severity: 'MEDIUM',
        type: 'UNKNOWN_GRANT_TYPE',
        message: `Unknown grant type: ${grantType}`,
        recommendation: 'Verify this is a valid OAuth2 grant type'
      });
      riskScore += 20;
    } else {
      // Check for deprecated grant types
      if (grantInfo.deprecated) {
        issues.push({
          severity: 'HIGH',
          type: 'DEPRECATED_GRANT_TYPE',
          message: `Using deprecated grant type: ${grantType}`,
          recommendation: 'Migrate to authorization_code flow with PKCE',
          detail: 'Implicit flow is deprecated due to token leakage risks',
          reference: 'https://oauth.net/2/grant-types/implicit/'
        });
        riskScore += 40;
      }

      // Check for insecure grant types
      if (grantInfo.legacy) {
        issues.push({
          severity: 'CRITICAL',
          type: 'INSECURE_GRANT_TYPE',
          message: `Using insecure grant type: ${grantType}`,
          recommendation: 'Never use password grant - migrate to authorization_code',
          detail: 'Password grant exposes credentials to client application',
          reference: 'https://oauth.net/2/grant-types/password/'
        });
        riskScore += 60;
      }

      // Check for PKCE requirement
      if (grantInfo.pkceRequired && !params.code_challenge) {
        issues.push({
          severity: 'HIGH',
          type: 'MISSING_PKCE',
          message: 'Authorization code flow without PKCE',
          recommendation: 'Implement PKCE (RFC 7636) for authorization code flow',
          detail: 'PKCE prevents authorization code interception attacks',
          reference: 'https://oauth.net/2/pkce/'
        });
        riskScore += 35;
      }
    }

    return {
      grantType,
      info: grantInfo,
      issues,
      riskScore: Math.min(riskScore, 100)
    };
  }

  /**
   * Validate redirect URI security
   * @param {string} redirectUri - Redirect URI from authorization request
   * @param {string} registeredUris - Array of registered redirect URIs (if known)
   * @returns {Object} Validation results with issues
   */
  validateRedirectURI(redirectUri, registeredUris = []) {
    const issues = [];
    let riskScore = 0;

    if (!redirectUri) {
      issues.push({
        severity: 'CRITICAL',
        type: 'MISSING_REDIRECT_URI',
        message: 'No redirect_uri parameter in authorization request',
        recommendation: 'Always specify redirect_uri explicitly',
        detail: 'Missing redirect_uri can lead to authorization code theft'
      });
      return { issues, riskScore: 100 };
    }

    try {
      const uri = new URL(redirectUri);

      // 1. Check for HTTPS (except localhost)
      if (uri.protocol !== 'https:' && uri.hostname !== 'localhost' && uri.hostname !== '127.0.0.1') {
        issues.push({
          severity: 'CRITICAL',
          type: 'HTTP_REDIRECT_URI',
          message: 'Redirect URI uses HTTP instead of HTTPS',
          recommendation: 'Use HTTPS for all redirect URIs (except localhost development)',
          detail: 'Authorization codes sent over HTTP can be intercepted',
          redirectUri
        });
        riskScore += 60;
      }

      // 2. Check for localhost in production
      if ((uri.hostname === 'localhost' || uri.hostname === '127.0.0.1') &&
          !redirectUri.includes('://localhost')) {
        issues.push({
          severity: 'HIGH',
          type: 'LOCALHOST_REDIRECT_URI',
          message: 'Using localhost redirect URI in production',
          recommendation: 'Only use localhost for development',
          detail: 'Localhost redirect URIs can be hijacked by malicious apps',
          redirectUri
        });
        riskScore += 40;
      }

      // 3. Check for wildcards or overly broad patterns
      if (redirectUri.includes('*') || redirectUri.includes('..')) {
        issues.push({
          severity: 'CRITICAL',
          type: 'WILDCARD_REDIRECT_URI',
          message: 'Redirect URI contains wildcards or path traversal',
          recommendation: 'Use exact redirect URI matching',
          detail: 'Wildcard redirect URIs enable open redirect attacks',
          cwe: 'CWE-601',
          redirectUri
        });
        riskScore += 80;
      }

      // 4. Check for open redirect patterns
      if (uri.searchParams.has('redirect') || uri.searchParams.has('url') || uri.searchParams.has('next')) {
        issues.push({
          severity: 'HIGH',
          type: 'OPEN_REDIRECT_RISK',
          message: 'Redirect URI contains redirect parameters',
          recommendation: 'Avoid redirect parameters in OAuth redirect URIs',
          detail: 'Nested redirects can be chained to bypass validation',
          redirectUri
        });
        riskScore += 45;
      }

      // 5. Check for suspicious TLDs
      const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz'];
      if (suspiciousTLDs.some(tld => uri.hostname.endsWith(tld))) {
        issues.push({
          severity: 'MEDIUM',
          type: 'SUSPICIOUS_TLD',
          message: `Redirect URI uses suspicious TLD: ${uri.hostname}`,
          recommendation: 'Verify this is a legitimate domain',
          detail: 'Free TLDs are commonly used for phishing',
          redirectUri
        });
        riskScore += 25;
      }

      // 6. Validate against registered URIs (if provided)
      if (registeredUris.length > 0) {
        const exactMatch = registeredUris.includes(redirectUri);
        const prefixMatch = registeredUris.some(reg => redirectUri.startsWith(reg));

        if (!exactMatch && !prefixMatch) {
          issues.push({
            severity: 'CRITICAL',
            type: 'UNREGISTERED_REDIRECT_URI',
            message: 'Redirect URI does not match any registered URIs',
            recommendation: 'Only allow pre-registered redirect URIs',
            detail: 'Unregistered URIs enable authorization code theft',
            redirectUri,
            registered: registeredUris
          });
          riskScore += 70;
        }
      }

    } catch (error) {
      issues.push({
        severity: 'CRITICAL',
        type: 'INVALID_REDIRECT_URI',
        message: `Invalid redirect_uri format: ${error.message}`,
        recommendation: 'Ensure redirect_uri is a valid URL',
        redirectUri
      });
      riskScore += 80;
    }

    return {
      redirectUri,
      issues,
      riskScore: Math.min(riskScore, 100)
    };
  }

  /**
   * Analyze OAuth2 scopes for excessive permissions
   * @param {string|Array} scopes - Requested scopes (space-separated string or array)
   * @returns {Object} Scope analysis with security concerns
   */
  analyzeScopes(scopes) {
    const issues = [];
    let riskScore = 0;

    // Normalize scopes to array
    const scopeArray = typeof scopes === 'string' ? scopes.split(' ') : scopes;

    if (!scopeArray || scopeArray.length === 0) {
      issues.push({
        severity: 'INFO',
        type: 'NO_SCOPES',
        message: 'No scopes requested',
        recommendation: 'Explicitly request minimum required scopes',
        detail: 'Some providers grant default scopes which may be excessive'
      });
      return { issues, riskScore: 10, scopes: [] };
    }

    const dangerous = [];
    const broad = [];
    const acceptable = [];

    for (const scope of scopeArray) {
      // Check for dangerous scopes
      if (this.dangerousScopes[scope]) {
        dangerous.push({
          scope,
          reason: this.dangerousScopes[scope]
        });
        riskScore += 30;
      }
      // Check for overly broad scopes
      else if (scope.includes('*') || scope.includes('all') || scope.includes('admin')) {
        broad.push(scope);
        riskScore += 20;
      }
      // Check for write access
      else if (scope.toLowerCase().includes('write') || scope.toLowerCase().includes('modify')) {
        broad.push(scope);
        riskScore += 10;
      }
      else {
        acceptable.push(scope);
      }
    }

    // Report dangerous scopes
    if (dangerous.length > 0) {
      issues.push({
        severity: 'HIGH',
        type: 'DANGEROUS_SCOPES',
        message: `Application requests ${dangerous.length} dangerous scope(s)`,
        recommendation: 'Review if application truly needs these permissions',
        detail: 'Dangerous scopes grant broad access that could be abused if compromised',
        scopes: dangerous
      });
    }

    // Report broad scopes
    if (broad.length > 0) {
      issues.push({
        severity: 'MEDIUM',
        type: 'BROAD_SCOPES',
        message: `Application requests ${broad.length} broad scope(s)`,
        recommendation: 'Follow principle of least privilege - request minimum scopes needed',
        scopes: broad
      });
    }

    // Check total scope count
    if (scopeArray.length > 10) {
      issues.push({
        severity: 'MEDIUM',
        type: 'EXCESSIVE_SCOPE_COUNT',
        message: `Application requests ${scopeArray.length} scopes (>10)`,
        recommendation: 'Reduce scope count - request only essential permissions',
        detail: 'Large scope counts suggest overprivileged application'
      });
      riskScore += 15;
    }

    return {
      total: scopeArray.length,
      dangerous: dangerous.length,
      broad: broad.length,
      acceptable: acceptable.length,
      scopes: scopeArray,
      issues,
      riskScore: Math.min(riskScore, 100)
    };
  }

  /**
   * Check if this appears to be a legitimate OAuth2/OIDC provider
   */
  isKnownProvider(url) {
    try {
      const hostname = new URL(url).hostname;
      const provider = this.knownProviders.find(p => hostname.includes(p.domain));
      return provider || false;
    } catch {
      return false;
    }
  }
}

export { OAuth2Analyzer };
