// Authentication Risk Scoring Module
// Risk assessment and scoring for authentication security issues

class AuthRiskScorer {
  /**
   * Calculate overall risk score based on issues
   * @param {Array} issues - Array of security issues
   * @returns {number} Risk score (0-100)
   */
  calculateRiskScore(issues) {
    const weights = {
      CRITICAL: 100,
      HIGH: 50,
      MEDIUM: 20,
      LOW: 5
    };

    let score = 0;
    for (const issue of issues) {
      score += weights[issue.severity] || 0;
    }

    return Math.min(100, score / 10);
  }

  /**
   * Get recommendation based on risk score
   * @param {number} riskScore - Risk score (0-100)
   * @returns {string} Risk-based recommendation
   */
  getRecommendation(riskScore) {
    if (riskScore >= 80) return 'BLOCK - Critical security issues detected';
    if (riskScore >= 60) return 'WARN - Multiple security concerns identified';
    if (riskScore >= 30) return 'REVIEW - Some security improvements needed';
    return 'ACCEPT - Authentication appears secure';
  }

  /**
   * Get risk category for visual display
   * @param {number} riskScore - Risk score (0-100)
   * @returns {string} Risk category (insecure/moderate/secure)
   */
  getRiskCategory(riskScore) {
    if (riskScore >= 80) return 'insecure'; // Red
    if (riskScore >= 30) return 'moderate'; // Gold
    return 'secure'; // Green
  }

  /**
   * Assess HSTS risk with context-aware analysis
   * P1: Risk-based HSTS assessment to reduce false positives
   * @param {string} url - Request URL
   * @param {Object} headers - Response headers
   * @param {Object} request - Full request object
   * @returns {Object|null} HSTS issue if detected, null otherwise
   */
  assessHstsRisk(url, headers, request) {
    // First check if HSTS header is present
    const hstsHeader = this.getHeader(headers, 'Strict-Transport-Security');
    if (hstsHeader) {
      return null; // HSTS is present, no issue
    }

    try {
      const urlObj = new URL(url);

      // Skip non-HTTPS URLs (HSTS only applies to HTTPS)
      if (urlObj.protocol !== 'https:') {
        return null;
      }

      // BUGFIX: Skip domains on HSTS preload list (protected at browser level)
      // These major domains have HSTS preloaded in browsers, making header optional
      if (this._isHSTSPreloaded(urlObj.hostname)) {
        return null; // Preloaded - HSTS enforced by browser even without header
      }

      // Risk factors assessment
      let riskScore = 10; // Baseline score for all HTTPS endpoints
      let riskFactors = ['HTTPS endpoint (baseline HSTS consideration)'];
      let severity = 'LOW';

      // 1. Authentication context assessment
      const authRisk = this.assessAuthenticationRisk(url, headers, request);
      if (authRisk.hasAuth) {
        riskScore += authRisk.score;
        riskFactors.push(...authRisk.factors);
      }

      // 2. Data sensitivity assessment
      const dataRisk = this.assessDataSensitivity(url, urlObj);
      if (dataRisk.isSensitive) {
        riskScore += dataRisk.score;
        riskFactors.push(...dataRisk.factors);
      }

      // 3. Application type assessment
      const appRisk = this.assessApplicationType(url, urlObj);
      riskScore += appRisk.score;
      riskFactors.push(...appRisk.factors);

      // 4. CDN/Edge protection assessment
      const edgeProtection = this.assessEdgeProtection(headers, urlObj);
      if (edgeProtection.hasProtection) {
        riskScore -= edgeProtection.reduction;
        riskFactors.push(edgeProtection.factor);
      }

      // Determine severity based on risk score
      if (riskScore >= 70) {
        severity = 'HIGH';
      } else if (riskScore >= 40) {
        severity = 'MEDIUM';
      } else if (riskScore >= 15) {
        severity = 'LOW';
      } else {
        // Very low risk - don't report
        return null;
      }

      return {
        type: 'NO_HSTS',
        protocol: 'Universal',
        severity: severity,
        message: `Missing HSTS header (Risk Score: ${riskScore})`,
        details: {
          riskScore: riskScore,
          riskFactors: riskFactors,
          assessment: this.getHstsRiskAssessment(riskScore, riskFactors)
        },
        // EVIDENCE: Include response headers to prove HSTS is missing
        evidence: {
          url: url,
          protocol: urlObj.protocol,
          responseHeaders: headers || [],
          hstsHeaderPresent: false,
          verification: `Manual check: https://hstspreload.org/?domain=${urlObj.hostname}`
        }
      };

    } catch (error) {
      // Invalid URL, skip assessment
      return null;
    }
  }

  /**
   * Assess authentication risk factors
   * @param {string} url - Request URL
   * @param {Object} headers - Request headers
   * @param {Object} request - Full request object
   * @returns {Object} Authentication risk assessment
   */
  assessAuthenticationRisk(url, headers, request) {
    let score = 0;
    let factors = [];
    let hasAuth = false;

    // Check for authentication headers
    const authHeader = this.getHeader(headers, 'Authorization');
    const cookieHeader = this.getHeader(headers, 'Cookie');

    if (authHeader) {
      hasAuth = true;
      if (authHeader.toLowerCase().includes('bearer')) {
        score += 30;
        factors.push('Bearer token authentication detected');
      } else if (authHeader.toLowerCase().includes('basic')) {
        score += 40;
        factors.push('Basic authentication detected (high risk)');
      } else {
        score += 25;
        factors.push('Custom authentication header detected');
      }
    }

    if (cookieHeader) {
      hasAuth = true;
      // Check for session/auth cookies
      const authCookiePatterns = [
        /sessionid|session_id|auth|token|login|jwt/i,
        /anthropic-device-id|session-key|user-token/i
      ];

      const hasAuthCookie = authCookiePatterns.some(pattern => pattern.test(cookieHeader));
      if (hasAuthCookie) {
        score += 25;
        factors.push('Authentication cookies detected');
      }
    }

    // Check URL patterns for auth endpoints
    const authUrlPatterns = [
      /\/auth\/|\/login\/|\/signin\/|\/oauth\/|\/sso\//i,
      /\/api\/.*\/auth|\/authentication|\/session/i,
      /\/chat_conversations\/|\/conversations\/|\/organizations\//i // AI/collaboration platforms
    ];

    if (authUrlPatterns.some(pattern => pattern.test(url))) {
      hasAuth = true;
      score += 20;
      factors.push('Authentication endpoint detected');
    }

    return { hasAuth, score, factors };
  }

  /**
   * Assess data sensitivity risk factors
   * @param {string} url - Request URL
   * @param {URL} urlObj - Parsed URL object
   * @returns {Object} Data sensitivity assessment
   */
  assessDataSensitivity(url, urlObj) {
    let score = 0;
    let factors = [];
    let isSensitive = false;

    // Financial/payment patterns
    const financialPatterns = [
      /payment|billing|invoice|transaction|financial/i,
      /stripe|paypal|square|checkout/i,
      /bank|secure\.bank|banking|credit|loan/i,
      /login.*bank|bank.*login/i
    ];

    // Healthcare patterns
    const healthcarePatterns = [
      /health|medical|patient|hipaa/i,
      /epic|cerner|allscripts/i
    ];

    // Personal data patterns
    const personalDataPatterns = [
      /profile|account|user|personal|private/i,
      /api\/.*\/(user|profile|account|personal)/i,
      /organizations\/.*\/|conversations\/|chat/i // AI/collaboration platforms
    ];

    // AI/ML service patterns (moderate risk)
    const aiServicePatterns = [
      /claude\.ai|anthropic\.com/i,
      /openai\.com|api\.openai\.com/i,
      /chat|conversation|assistant/i
    ];

    // Check URL for sensitive data indicators
    const urlString = url.toLowerCase();
    const hostname = urlObj.hostname.toLowerCase();

    if (financialPatterns.some(pattern => pattern.test(urlString) || pattern.test(hostname))) {
      isSensitive = true;
      score += 40;
      factors.push('Financial/payment data handling detected');
    }

    if (healthcarePatterns.some(pattern => pattern.test(urlString) || pattern.test(hostname))) {
      isSensitive = true;
      score += 45;
      factors.push('Healthcare data handling detected');
    }

    if (personalDataPatterns.some(pattern => pattern.test(urlString))) {
      isSensitive = true;
      score += 20;
      factors.push('Personal data handling detected');
    }

    if (aiServicePatterns.some(pattern => pattern.test(urlString) || pattern.test(hostname))) {
      isSensitive = true;
      score += 25;
      factors.push('AI/ML service with user data detected');
    }

    // Check for data modification endpoints
    const dataModificationPatterns = [
      /\/api\/.*\/(create|update|delete|modify|edit)/i,
      /\/admin\/|\/management\/|\/dashboard\//i
    ];

    if (dataModificationPatterns.some(pattern => pattern.test(urlString))) {
      isSensitive = true;
      score += 15;
      factors.push('Data modification endpoint detected');
    }

    return { isSensitive, score, factors };
  }

  /**
   * Assess application type risk factors
   * @param {string} url - Request URL
   * @param {URL} urlObj - Parsed URL object
   * @returns {Object} Application type assessment
   */
  assessApplicationType(url, urlObj) {
    let score = 0;
    let factors = [];

    const hostname = urlObj.hostname.toLowerCase();
    const path = urlObj.pathname.toLowerCase();

    // High-risk application types
    if (hostname.includes('admin') || path.includes('/admin')) {
      score += 25;
      factors.push('Administrative interface detected');
    }

    // API endpoints (lower browser exposure risk but still baseline concern)
    if (path.includes('/api/') || hostname.startsWith('api.')) {
      score += 5; // Baseline risk for API endpoints
      factors.push('API endpoint (baseline HSTS consideration)');
    }

    // Static content (very low risk)
    const staticPatterns = [
      /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2)$/i,
      /\/static\/|\/assets\/|\/cdn\//i
    ];

    if (staticPatterns.some(pattern => pattern.test(path))) {
      score -= 15;
      factors.push('Static content (very low risk)');
    }

    // Internal/development indicators
    if (hostname.includes('localhost') || hostname.includes('dev') || hostname.includes('staging')) {
      score -= 50;
      factors.push('Development/internal environment (HSTS not critical)');
    }

    return { score, factors };
  }

  /**
   * Assess edge protection (CDN, security headers)
   * @param {Object} headers - Response headers
   * @param {URL} urlObj - Parsed URL object
   * @returns {Object} Edge protection assessment
   */
  assessEdgeProtection(headers, urlObj) {
    let reduction = 0;
    let hasProtection = false;
    let factor = null;

    // Check for CDN/edge service indicators
    const cdnHeaders = [
      'cf-ray', 'x-amz-cf-id', 'x-served-by', 'x-cache',
      'x-cloudflare-uid', 'x-akamai-transformed'
    ];

    const cdnIndicators = cdnHeaders.some(header =>
      Object.keys(headers).some(h => h.toLowerCase() === header)
    );

    if (cdnIndicators) {
      hasProtection = true;
      reduction = 15;
      factor = 'CDN/Edge service detected (may handle HTTPS redirects)';
    }

    // Check for security-focused headers that suggest good security posture
    const securityHeaders = [
      'content-security-policy', 'x-frame-options', 'x-content-type-options'
    ];

    const hasSecurityHeaders = securityHeaders.some(header =>
      Object.keys(headers).some(h => h.toLowerCase() === header)
    );

    if (hasSecurityHeaders) {
      hasProtection = true;
      reduction += 5;
      factor = factor ? `${factor}; Strong security headers present` : 'Strong security headers present';
    }

    return { hasProtection, reduction, factor };
  }

  /**
   * Get detailed HSTS risk assessment
   * @param {number} riskScore - Calculated risk score
   * @param {Array} riskFactors - Array of risk factors
   * @returns {Object} Detailed assessment with recommendations
   */
  getHstsRiskAssessment(riskScore, riskFactors) {
    if (riskScore >= 70) {
      return {
        level: 'HIGH',
        recommendation: 'Implement HSTS immediately. This application handles sensitive data and authentication.',
        priority: 'Critical'
      };
    } else if (riskScore >= 40) {
      return {
        level: 'MEDIUM',
        recommendation: 'Consider implementing HSTS to prevent downgrade attacks.',
        priority: 'Important'
      };
    } else if (riskScore >= 15) {
      return {
        level: 'LOW',
        recommendation: 'HSTS recommended but not critical for this application type.',
        priority: 'Optional'
      };
    } else {
      return {
        level: 'MINIMAL',
        recommendation: 'HSTS not critical for this use case.',
        priority: 'Low'
      };
    }
  }

  /**
   * Get header value (utility helper)
   * @param {Object|Array} headers - Headers object or array
   * @param {string} name - Header name
   * @returns {string|undefined} Header value
   */
  getHeader(headers, name) {
    if (Array.isArray(headers)) {
      const header = headers.find(h => h.name.toLowerCase() === name.toLowerCase());
      return header?.value;
    }
    return headers[name] || headers[name.toLowerCase()];
  }

  /**
   * Check if domain is on HSTS preload list
   * These domains have HSTS enforced by browsers even without the header
   * @param {string} hostname - Domain to check
   * @returns {boolean} True if preloaded
   */
  _isHSTSPreloaded(hostname) {
    // Major domains on HSTS preload list
    // Source: https://hstspreload.org/
    const preloadedDomains = [
      // Microsoft
      'microsoft.com',
      'microsoftonline.com',
      'login.microsoftonline.com',
      'windows.net',
      'azure.com',
      'office.com',
      'live.com',
      'outlook.com',

      // Google
      'google.com',
      'googleapis.com',
      'gmail.com',
      'youtube.com',
      'gstatic.com',

      // Meta/Facebook
      'facebook.com',
      'fbcdn.net',
      'instagram.com',
      'whatsapp.com',

      // Other major platforms
      'github.com',
      'github.io',
      'twitter.com',
      'linkedin.com',
      'amazon.com',
      'amazonaws.com',
      'cloudflare.com',
      'apple.com',
      'icloud.com',

      // Financial
      'paypal.com',
      'stripe.com',
      'visa.com',
      'mastercard.com'
    ];

    // Check if hostname matches or is subdomain of preloaded domain
    for (const domain of preloadedDomains) {
      if (hostname === domain || hostname.endsWith('.' + domain)) {
        return true;
      }
    }

    return false;
  }
}

export { AuthRiskScorer };
