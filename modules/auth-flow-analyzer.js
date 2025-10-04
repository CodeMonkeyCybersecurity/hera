/**
 * Authentication Flow Analysis Module
 *
 * Domain logic functions for analyzing OAuth/OIDC authentication flows,
 * consent requests, provider detection, scope analysis, and auth failures.
 *
 * This is a Tier 2 module (domain logic) that provides comprehensive
 * authentication flow analysis capabilities.
 */

/**
 * Analyze authentication flow specifics
 *
 * Examines URL and request body to identify OAuth/OIDC flow types,
 * grant types, and security features (state, nonce, PKCE).
 *
 * @param {string} url - The request URL
 * @param {Object} [requestBody] - Request body with potential formData
 * @returns {Object} Flow analysis containing:
 *   - flowType: Type of auth flow (authorization_request, token_request, etc.)
 *   - grantType: OAuth grant type (if token request)
 *   - hasState: Whether state parameter is present
 *   - hasNonce: Whether nonce parameter is present
 *   - hasPKCE: Whether PKCE is being used
 *   - responseType: OAuth response_type parameter
 *   - scope: Requested scopes
 *   - clientId: OAuth client ID
 *   - redirectUri: OAuth redirect URI
 *   - securityFeatures: Array of detected security features
 *
 * @example
 * analyzeAuthFlow('https://accounts.google.com/o/oauth2/v2/auth?state=abc&code_challenge=xyz')
 * // Returns: { flowType: 'authorization_request', hasState: true, hasPKCE: true, ... }
 */
export function analyzeAuthFlow(url, requestBody) {
  const urlObj = new URL(url);
  const params = new URLSearchParams(urlObj.search);
  const lowerUrl = url.toLowerCase();

  const analysis = {
    flowType: null,
    grantType: null,
    hasState: params.has('state'),
    hasNonce: params.has('nonce'),
    hasPKCE: params.has('code_challenge') || params.has('code_verifier'),
    responseType: params.get('response_type'),
    scope: params.get('scope'),
    clientId: params.get('client_id'),
    redirectUri: params.get('redirect_uri'),
    securityFeatures: []
  };

  // Detect flow type
  if (lowerUrl.includes('authorize')) {
    analysis.flowType = 'authorization_request';
  } else if (lowerUrl.includes('token')) {
    analysis.flowType = 'token_request';
    if (requestBody && requestBody.formData) {
      analysis.grantType = requestBody.formData.grant_type;
    }
  } else if (lowerUrl.includes('userinfo')) {
    analysis.flowType = 'userinfo_request';
  } else if (lowerUrl.includes('logout') || lowerUrl.includes('signout') || lowerUrl.includes('sign-out')) {
    analysis.flowType = 'logout_request';
  } else if (lowerUrl.includes('revoke')) {
    analysis.flowType = 'token_revocation';
  } else if (lowerUrl.includes('end_session')) {
    analysis.flowType = 'session_termination';
  }

  // Check security features
  if (analysis.hasState) analysis.securityFeatures.push('state_parameter');
  if (analysis.hasNonce) analysis.securityFeatures.push('nonce_parameter');
  if (analysis.hasPKCE) analysis.securityFeatures.push('pkce');

  return analysis;
}

/**
 * Analyze OAuth consent and authorization grants
 *
 * Performs deep analysis of OAuth consent flows including provider detection,
 * scope risk analysis, redirect URI validation, and consent warning generation.
 *
 * @param {string} url - The authorization/consent URL
 * @param {Object} [requestBody] - Request body (optional)
 * @returns {Object} Consent analysis containing:
 *   - isConsentFlow: Whether this is a consent/authorization flow
 *   - provider: Detected OAuth provider
 *   - clientId: OAuth client ID
 *   - redirectUri: OAuth redirect URI
 *   - scopes: Array of requested scopes
 *   - scopeAnalysis: Risk analysis of scopes (high/medium/low risk)
 *   - applicationInfo: Analysis of the requesting application
 *   - consentWarnings: Array of security warnings
 *
 * @example
 * analyzeOAuthConsent('https://accounts.google.com/o/oauth2/v2/auth?scope=email%20profile')
 * // Returns: { isConsentFlow: true, provider: 'Google', scopes: ['email', 'profile'], ... }
 */
export function analyzeOAuthConsent(url, requestBody) {
  const urlObj = new URL(url);
  const params = new URLSearchParams(urlObj.search);
  const lowerUrl = url.toLowerCase();

  const analysis = {
    isConsentFlow: false,
    provider: detectAuthProvider(url),
    clientId: params.get('client_id'),
    redirectUri: params.get('redirect_uri'),
    scopes: [],
    scopeAnalysis: {
      highRisk: [],
      mediumRisk: [],
      lowRisk: [],
      riskScore: 0
    },
    applicationInfo: {
      name: null,
      domain: null,
      verified: false,
      suspicious: false
    },
    consentWarnings: []
  };

  // Check if this is a consent/authorization flow
  if (lowerUrl.includes('authorize') || lowerUrl.includes('consent') || lowerUrl.includes('oauth')) {
    analysis.isConsentFlow = true;

    // Parse scopes
    const scopeParam = params.get('scope');
    if (scopeParam) {
      analysis.scopes = scopeParam.split(/[\s,+]/).filter(s => s.length > 0);
      analysis.scopeAnalysis = analyzeScopeRisks(analysis.scopes, analysis.provider);
    }

    // Analyze redirect URI for suspicious patterns
    if (analysis.redirectUri) {
      analysis.applicationInfo = analyzeRedirectUri(analysis.redirectUri);
    }

    // Generate consent warnings
    analysis.consentWarnings = generateConsentWarnings(analysis);
  }

  return analysis;
}

/**
 * Detect authentication provider from URL
 *
 * Identifies the OAuth/OIDC provider based on URL hostname patterns.
 * Recognizes major providers like Google, Microsoft, GitHub, etc.
 *
 * @param {string} url - The authentication URL
 * @returns {string} Provider name or "Unknown Provider (hostname)"
 *
 * @example
 * detectAuthProvider('https://accounts.google.com/o/oauth2/v2/auth')
 * // Returns: 'Google'
 *
 * detectAuthProvider('https://login.microsoftonline.com/common/oauth2/authorize')
 * // Returns: 'Microsoft Azure/Office 365'
 */
export function detectAuthProvider(url) {
  const lowerUrl = url.toLowerCase();
  const hostname = new URL(url).hostname.toLowerCase();

  if (hostname.includes('login.microsoftonline.com') || hostname.includes('login.live.com')) {
    return 'Microsoft Azure/Office 365';
  }
  if (hostname.includes('accounts.google.com') || hostname.includes('oauth2.googleapis.com')) {
    return 'Google';
  }
  if (hostname.includes('github.com')) {
    return 'GitHub';
  }
  if (hostname.includes('facebook.com') || hostname.includes('graph.facebook.com')) {
    return 'Facebook';
  }
  if (hostname.includes('api.twitter.com') || hostname.includes('twitter.com')) {
    return 'Twitter/X';
  }
  if (hostname.includes('linkedin.com')) {
    return 'LinkedIn';
  }
  if (hostname.includes('okta.com') || hostname.includes('oktapreview.com')) {
    return 'Okta';
  }
  if (hostname.includes('auth0.com')) {
    return 'Auth0';
  }
  if (hostname.includes('salesforce.com')) {
    return 'Salesforce';
  }

  return `Unknown Provider (${hostname})`;
}

/**
 * Analyze scope risks based on provider and permissions
 *
 * Categorizes OAuth scopes into high/medium/low risk categories
 * and calculates an overall risk score.
 *
 * Risk levels:
 * - High: Full access, admin rights, write permissions, sensitive data access
 * - Medium: Read access to sensitive data, profile information
 * - Low: Basic public profile information only
 *
 * @param {string[]} scopes - Array of OAuth scope strings
 * @param {string} provider - OAuth provider name (for context)
 * @returns {Object} Risk analysis containing:
 *   - highRisk: Array of high-risk scopes
 *   - mediumRisk: Array of medium-risk scopes
 *   - lowRisk: Array of low-risk scopes
 *   - riskScore: Numeric risk score (high=10pts, medium=5pts, low=1pt each)
 *
 * @example
 * analyzeScopeRisks(['email', 'profile', 'admin'], 'Google')
 * // Returns: { highRisk: ['admin'], mediumRisk: ['email', 'profile'], lowRisk: [], riskScore: 20 }
 */
export function analyzeScopeRisks(scopes, provider) {
  const analysis = {
    highRisk: [],
    mediumRisk: [],
    lowRisk: [],
    riskScore: 0
  };

  const riskPatterns = {
    // High risk scopes - full access, admin rights, sensitive data
    high: [
      'https://graph.microsoft.com/.default', // Full Microsoft Graph access
      'user.readwrite.all', 'directory.readwrite.all', 'application.readwrite.all',
      'mail.readwrite', 'calendars.readwrite', 'contacts.readwrite',
      'files.readwrite.all', 'sites.readwrite.all',
      'admin', 'root', 'sudo', 'full_access', 'all',
      'delete', 'write_all', 'manage_all'
    ],

    // Medium risk scopes - read access to sensitive data
    medium: [
      'user.read.all', 'directory.read.all', 'mail.read',
      'calendars.read', 'contacts.read', 'files.read.all',
      'profile', 'email', 'openid', 'offline_access',
      'read_user', 'read_repository', 'read_org'
    ],

    // Low risk scopes - basic info only
    low: [
      'user.read', 'profile.basic', 'email.basic',
      'public_profile', 'basic_info'
    ]
  };

  scopes.forEach(scope => {
    const lowerScope = scope.toLowerCase();

    if (riskPatterns.high.some(pattern => lowerScope.includes(pattern.toLowerCase()))) {
      analysis.highRisk.push(scope);
      analysis.riskScore += 10;
    } else if (riskPatterns.medium.some(pattern => lowerScope.includes(pattern.toLowerCase()))) {
      analysis.mediumRisk.push(scope);
      analysis.riskScore += 5;
    } else {
      analysis.lowRisk.push(scope);
      analysis.riskScore += 1;
    }
  });

  return analysis;
}

/**
 * Analyze redirect URI for suspicious patterns
 *
 * Examines OAuth redirect URIs for security issues such as:
 * - Localhost/local IPs (potentially suspicious in production)
 * - URL shorteners (potential phishing)
 * - Temporary hosting services
 * - Free hosting platforms
 *
 * Also checks for known legitimate domains.
 *
 * @param {string} redirectUri - The OAuth redirect_uri parameter
 * @returns {Object} Analysis containing:
 *   - name: Application name (if detected)
 *   - domain: Hostname of redirect URI
 *   - verified: Whether domain is a known legitimate service
 *   - suspicious: Whether domain has suspicious patterns
 *   - warnings: Array of warning messages
 *
 * @example
 * analyzeRedirectUri('https://localhost:3000/callback')
 * // Returns: { domain: 'localhost', verified: false, suspicious: true, warnings: [...] }
 */
export function analyzeRedirectUri(redirectUri) {
  const analysis = {
    name: null,
    domain: null,
    verified: false,
    suspicious: false,
    warnings: []
  };

  try {
    const url = new URL(redirectUri);
    analysis.domain = url.hostname;

    // Check for suspicious patterns
    const suspiciousPatterns = [
      'localhost', '127.0.0.1', '0.0.0.0', // Local redirects (potentially suspicious)
      'bit.ly', 'tinyurl.com', 't.co', // URL shorteners
      'ngrok.io', 'herokuapp.com', // Temporary hosting
      'github.io', 'netlify.app', 'vercel.app' // Free hosting (could be legitimate or suspicious)
    ];

    const isSuspicious = suspiciousPatterns.some(pattern =>
      analysis.domain.toLowerCase().includes(pattern)
    );

    if (isSuspicious) {
      analysis.suspicious = true;
      analysis.warnings.push('Redirect URI uses potentially suspicious domain');
    }

    // Check for legitimate domains
    const legitimateDomains = [
      'microsoft.com', 'office.com', 'sharepoint.com',
      'google.com', 'gmail.com', 'googleusercontent.com',
      'github.com', 'facebook.com', 'linkedin.com'
    ];

    analysis.verified = legitimateDomains.some(domain =>
      analysis.domain.toLowerCase().includes(domain)
    );

  } catch (e) {
    analysis.suspicious = true;
    analysis.warnings.push('Invalid redirect URI format');
  }

  return analysis;
}

/**
 * Generate consent warnings based on analysis
 *
 * Creates structured warning messages for OAuth consent flows based on
 * detected risks including high-risk scopes, suspicious redirect URIs,
 * unknown providers, and high overall risk scores.
 *
 * SECURITY: These warnings help users make informed decisions about
 * granting OAuth permissions to applications.
 *
 * @param {Object} consentAnalysis - Analysis object from analyzeOAuthConsent()
 * @returns {Array<Object>} Array of warning objects, each containing:
 *   - severity: 'critical' or 'warning'
 *   - type: Warning type identifier
 *   - message: Human-readable warning message
 *   - recommendation: Actionable security recommendation
 *
 * @example
 * const analysis = analyzeOAuthConsent(url);
 * const warnings = generateConsentWarnings(analysis);
 * // Returns: [{ severity: 'critical', type: 'high_risk_scopes', message: '...', recommendation: '...' }]
 */
export function generateConsentWarnings(consentAnalysis) {
  const warnings = [];

  // High risk scope warnings
  if (consentAnalysis.scopeAnalysis.highRisk.length > 0) {
    warnings.push({
      severity: 'critical',
      type: 'high_risk_scopes',
      message: ` HIGH RISK: Application requesting dangerous permissions: ${consentAnalysis.scopeAnalysis.highRisk.join(', ')}`,
      recommendation: 'Carefully verify this application before granting access. These permissions allow extensive access to your data.'
    });
  }

  // Suspicious redirect URI
  if (consentAnalysis.applicationInfo.suspicious) {
    warnings.push({
      severity: 'critical',
      type: 'suspicious_redirect',
      message: ` SUSPICIOUS: Redirect URI appears suspicious: ${consentAnalysis.redirectUri}`,
      recommendation: 'This may be a phishing attempt. Verify the application is legitimate before proceeding.'
    });
  }

  // Unknown provider warning
  if (consentAnalysis.provider.includes('Unknown Provider')) {
    warnings.push({
      severity: 'warning',
      type: 'unknown_provider',
      message: `WARNING: Unknown authentication provider: ${consentAnalysis.provider}`,
      recommendation: 'Verify this is a legitimate authentication service before entering credentials.'
    });
  }

  // High risk score
  if (consentAnalysis.scopeAnalysis.riskScore >= 20) {
    warnings.push({
      severity: 'warning',
      type: 'high_risk_score',
      message: `HIGH RISK SCORE: ${consentAnalysis.scopeAnalysis.riskScore} - Multiple sensitive permissions requested`,
      recommendation: 'Consider if this application really needs all these permissions.'
    });
  }

  return warnings;
}

/**
 * Analyze authentication failures and access denied responses
 *
 * Examines HTTP error status codes and response headers to diagnose
 * authentication and authorization failures, including:
 * - Authentication failures (401)
 * - Access denied (403)
 * - Rate limiting (429)
 * - Server errors (5xx)
 * - WAF blocks
 *
 * CRITICAL: Helps identify security incidents and potential attacks.
 *
 * @param {number} statusCode - HTTP status code
 * @param {Array<Object>} responseHeaders - Array of response header objects with name/value
 * @param {string} url - Request URL for context
 * @returns {Object} Failure analysis containing:
 *   - isFailure: Whether this is an auth failure
 *   - failureType: Human-readable failure description
 *   - statusCode: The HTTP status code
 *   - errorDetails: Additional error context from headers
 *   - retryAfter: Retry-After header value if present
 *   - rateLimited: Whether request was rate limited
 *   - blockedByWAF: Whether blocked by WAF/CDN
 *   - suspiciousActivity: Whether attempting to access sensitive endpoints
 *
 * @example
 * analyzeAuthFailure(401, [{ name: 'WWW-Authenticate', value: 'Bearer realm="api"' }], url)
 * // Returns: { isFailure: true, failureType: 'Unauthorized...', errorDetails: '...' }
 */
export function analyzeAuthFailure(statusCode, responseHeaders, url) {
  const analysis = {
    isFailure: false,
    failureType: null,
    statusCode: statusCode,
    errorDetails: null,
    retryAfter: null,
    rateLimited: false,
    blockedByWAF: false,
    suspiciousActivity: false
  };

  // Analyze status codes
  if (statusCode >= 400) {
    analysis.isFailure = true;

    switch (statusCode) {
      case 400:
        analysis.failureType = 'Bad Request - Invalid parameters or malformed request';
        break;
      case 401:
        analysis.failureType = 'Unauthorized - Authentication required or failed';
        break;
      case 403:
        analysis.failureType = 'Forbidden - Access denied or insufficient permissions';
        break;
      case 404:
        analysis.failureType = 'Not Found - Endpoint may not exist or be disabled';
        break;
      case 405:
        analysis.failureType = 'Method Not Allowed - HTTP method not supported';
        break;
      case 429:
        analysis.failureType = 'Too Many Requests - Rate limited';
        analysis.rateLimited = true;
        break;
      case 500:
        analysis.failureType = 'Internal Server Error - Server-side authentication failure';
        break;
      case 502:
        analysis.failureType = 'Bad Gateway - Authentication service unavailable';
        break;
      case 503:
        analysis.failureType = 'Service Unavailable - Authentication service down';
        break;
      default:
        analysis.failureType = `HTTP ${statusCode} - Authentication-related error`;
    }
  }

  // Analyze response headers for additional failure context
  if (responseHeaders) {
    responseHeaders.forEach(header => {
      const name = header.name.toLowerCase();
      const value = header.value.toLowerCase();

      switch (name) {
        case 'www-authenticate':
          analysis.errorDetails = `Authentication challenge: ${header.value}`;
          break;
        case 'retry-after':
          analysis.retryAfter = header.value;
          break;
        case 'x-ratelimit-remaining':
          if (parseInt(header.value) === 0) {
            analysis.rateLimited = true;
          }
          break;
        case 'server':
          if (value.includes('cloudflare') || value.includes('aws') || value.includes('akamai')) {
            analysis.blockedByWAF = statusCode === 403;
          }
          break;
        case 'x-frame-options':
          if (statusCode === 403 && value === 'deny') {
            analysis.errorDetails = 'Request blocked by X-Frame-Options policy';
          }
          break;
      }
    });
  }

  // Check for suspicious patterns
  const lowerUrl = url.toLowerCase();
  if (statusCode === 401 || statusCode === 403) {
    if (lowerUrl.includes('admin') || lowerUrl.includes('api/v') || lowerUrl.includes('internal')) {
      analysis.suspiciousActivity = true;
    }
  }

  return analysis;
}
