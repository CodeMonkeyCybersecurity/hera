// Session Security Analyzer
// Detects session fixation, hijacking, and CSRF vulnerabilities

class SessionSecurityAnalyzer {
  constructor() {
    // Track session IDs across requests
    this.sessionTracking = new Map(); // sessionId -> {firstSeen, lastSeen, preAuth, postAuth, requests}

    // CSRF token tracking
    this.csrfTokens = new Map(); // origin -> {tokens: Set, lastSeen}
  }

  /**
   * Analyze session cookie security
   * @param {Object} cookies - Parsed cookie object
   * @param {string} url - Request URL
   * @param {boolean} isHttps - Whether connection is HTTPS
   * @returns {Object} Security analysis with issues
   */
  analyzeSessionCookies(cookies, url, isHttps) {
    const issues = [];
    let riskScore = 0;

    if (!cookies || Object.keys(cookies).length === 0) {
      return { issues, riskScore, hasSessions: false };
    }

    const sessionCookies = this._identifySessionCookies(cookies);

    for (const [name, cookie] of Object.entries(sessionCookies)) {
      // 1. Check Secure flag
      if (!cookie.Secure && isHttps) {
        issues.push({
          severity: 'HIGH',
          type: 'MISSING_SECURE_FLAG',
          cookie: name,
          message: `Session cookie "${name}" missing Secure flag on HTTPS`,
          recommendation: 'Set Secure flag to prevent transmission over HTTP',
          detail: 'Cookie can be intercepted if user downgrades to HTTP',
          cwe: 'CWE-614'
        });
        riskScore += 30;
      }

      // 2. Check HttpOnly flag
      if (!cookie.HttpOnly) {
        issues.push({
          severity: 'CRITICAL',
          type: 'MISSING_HTTPONLY_FLAG',
          cookie: name,
          message: `Session cookie "${name}" missing HttpOnly flag`,
          recommendation: 'Set HttpOnly flag to prevent JavaScript access',
          detail: 'Cookie vulnerable to XSS attacks - malicious scripts can steal session',
          cwe: 'CWE-1004'
        });
        riskScore += 50;
      }

      // 3. Check SameSite attribute
      const sameSiteIssue = this._checkSameSite(name, cookie);
      if (sameSiteIssue) {
        issues.push(sameSiteIssue);
        riskScore += sameSiteIssue.severity === 'HIGH' ? 30 : 15;
      }

      // 4. Check session ID entropy
      const entropyIssue = this._checkSessionEntropy(name, cookie.value);
      if (entropyIssue) {
        issues.push(entropyIssue);
        riskScore += 40;
      }

      // 5. Check expiration
      const expirationIssue = this._checkExpiration(name, cookie);
      if (expirationIssue) {
        issues.push(expirationIssue);
        riskScore += expirationIssue.severity === 'MEDIUM' ? 20 : 10;
      }

      // 6. Check domain scope
      const domainIssue = this._checkDomain(name, cookie, url);
      if (domainIssue) {
        issues.push(domainIssue);
        riskScore += 25;
      }
    }

    return {
      issues,
      riskScore: Math.min(riskScore, 100),
      hasSessions: sessionCookies.length > 0,
      sessionCookies: Object.keys(sessionCookies)
    };
  }

  /**
   * Detect session fixation attacks
   * @param {string} sessionId - Current session ID
   * @param {string} url - Request URL
   * @param {boolean} isAuthRequest - Whether this is an authentication request
   * @param {boolean} isAuthResponse - Whether this is a successful auth response
   * @returns {Object|null} Issue if session fixation detected
   */
  detectSessionFixation(sessionId, url, isAuthRequest, isAuthResponse) {
    const origin = new URL(url).origin;
    const key = `${origin}:${sessionId}`;

    if (!this.sessionTracking.has(key)) {
      // First time seeing this session ID
      this.sessionTracking.set(key, {
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        preAuth: !isAuthResponse,
        postAuth: isAuthResponse,
        requests: 1,
        urls: [url]
      });
      return null;
    }

    const tracking = this.sessionTracking.get(key);
    tracking.lastSeen = Date.now();
    tracking.requests++;
    tracking.urls.push(url);

    // Check if session ID is the same before and after authentication
    if (tracking.preAuth && isAuthResponse) {
      tracking.postAuth = true;

      // SESSION FIXATION: Session ID didn't change after successful login
      return {
        severity: 'CRITICAL',
        type: 'SESSION_FIXATION',
        message: 'Session ID did not change after authentication',
        recommendation: 'Regenerate session ID after successful login',
        detail: 'Attacker can fixate a session ID before victim authenticates, then hijack the session',
        cwe: 'CWE-384',
        evidence: {
          sessionId: sessionId.substring(0, 20) + '...',
          firstSeen: new Date(tracking.firstSeen).toISOString(),
          requestCount: tracking.requests
        }
      };
    }

    return null;
  }

  /**
   * Detect session hijacking indicators
   * @param {Object} request - Request with headers, IP, user-agent
   * @param {string} sessionId - Session ID
   * @returns {Array} Issues detected
   */
  detectSessionHijacking(request, sessionId) {
    const issues = [];

    // Check for session ID in URL (bad practice)
    if (request.url.includes(sessionId) || request.url.match(/[?&](session|sid|sess)=/i)) {
      issues.push({
        severity: 'CRITICAL',
        type: 'SESSION_IN_URL',
        message: 'Session ID transmitted in URL',
        recommendation: 'Use cookies for session management, never URL parameters',
        detail: 'URLs are logged in browser history, proxy logs, and referer headers',
        cwe: 'CWE-598'
      });
    }

    // Check for missing or weak User-Agent binding
    // (In real implementation, you'd track UA per session)

    // Check for IP address changes (if available)
    // (In real implementation, you'd track IP per session)

    return issues;
  }

  /**
   * Detect CSRF vulnerabilities
   * @param {Object} request - Request with method, headers, body
   * @param {string} url - Request URL
   * @returns {Object|null} CSRF issue if detected
   */
  detectCSRF(request, url) {
    const { method, headers, body, cookies } = request;

    // Only check state-changing requests
    if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
      return null;
    }

    const origin = new URL(url).origin;
    let csrfTokenFound = false;
    let sameSiteCookiePresent = false;
    let customHeaderPresent = false;

    // 1. Check for CSRF tokens in common locations
    const csrfHeaders = ['x-csrf-token', 'x-xsrf-token', 'csrf-token'];
    for (const header of csrfHeaders) {
      if (headers[header] || headers[header.toUpperCase()]) {
        csrfTokenFound = true;
        this._trackCSRFToken(origin, headers[header]);
        break;
      }
    }

    // Check for CSRF token in body
    if (body && typeof body === 'string') {
      if (body.includes('csrf') || body.includes('xsrf') || body.includes('_token')) {
        csrfTokenFound = true;
      }
    }

    // 2. Check for SameSite cookies
    if (cookies) {
      for (const cookie of Object.values(cookies)) {
        if (cookie.SameSite && ['Strict', 'Lax'].includes(cookie.SameSite)) {
          sameSiteCookiePresent = true;
          break;
        }
      }
    }

    // 3. Check for custom headers (CORS preflight required)
    if (headers['x-requested-with'] === 'XMLHttpRequest') {
      customHeaderPresent = true;
    }

    // Determine if CSRF protection is adequate
    const protectionMethods = [];
    if (csrfTokenFound) protectionMethods.push('CSRF token');
    if (sameSiteCookiePresent) protectionMethods.push('SameSite cookie');
    if (customHeaderPresent) protectionMethods.push('Custom header');

    if (protectionMethods.length === 0) {
      return {
        severity: 'HIGH',
        type: 'MISSING_CSRF_PROTECTION',
        message: `${method} request missing CSRF protection`,
        recommendation: 'Implement CSRF tokens, SameSite cookies, or custom headers',
        detail: 'Attackers can forge requests from malicious sites to perform unauthorized actions',
        cwe: 'CWE-352',
        evidence: {
          method,
          url
        }
      };
    }

    // Weak protection (only one method)
    if (protectionMethods.length === 1 && protectionMethods[0] === 'Custom header') {
      return {
        severity: 'MEDIUM',
        type: 'WEAK_CSRF_PROTECTION',
        message: 'CSRF protection relies only on custom headers',
        recommendation: 'Add CSRF tokens for defense in depth',
        detail: 'Custom headers can be bypassed in some browser configurations',
        protection: protectionMethods
      };
    }

    return null; // CSRF protection appears adequate
  }

  /**
   * Identify session cookies from cookie jar
   */
  _identifySessionCookies(cookies) {
    const sessionNames = ['sessionid', 'session', 'sid', 'sess', 'phpsessid', 'jsessionid', 'aspsessionid'];
    const sessionCookies = {};

    for (const [name, cookie] of Object.entries(cookies)) {
      const lowerName = name.toLowerCase();

      // Check if name matches common session cookie patterns
      if (sessionNames.some(sn => lowerName.includes(sn)) ||
          lowerName.startsWith('auth') ||
          lowerName.includes('token')) {
        sessionCookies[name] = cookie;
      }
    }

    return sessionCookies;
  }

  /**
   * Check SameSite attribute
   */
  _checkSameSite(name, cookie) {
    if (!cookie.SameSite) {
      return {
        severity: 'HIGH',
        type: 'MISSING_SAMESITE',
        cookie: name,
        message: `Session cookie "${name}" missing SameSite attribute`,
        recommendation: 'Set SameSite=Lax or SameSite=Strict to prevent CSRF',
        detail: 'Cookie will be sent in cross-site requests, enabling CSRF attacks',
        cwe: 'CWE-352'
      };
    }

    if (cookie.SameSite === 'None' && !cookie.Secure) {
      return {
        severity: 'HIGH',
        type: 'SAMESITE_NONE_WITHOUT_SECURE',
        cookie: name,
        message: `Cookie "${name}" has SameSite=None without Secure flag`,
        recommendation: 'SameSite=None requires Secure flag',
        detail: 'Browser will reject this cookie'
      };
    }

    if (cookie.SameSite === 'None') {
      return {
        severity: 'MEDIUM',
        type: 'SAMESITE_NONE',
        cookie: name,
        message: `Session cookie "${name}" uses SameSite=None`,
        recommendation: 'Use SameSite=Lax or Strict unless cross-site access is required',
        detail: 'Cookie will be sent in all cross-site requests'
      };
    }

    return null;
  }

  /**
   * Check session ID entropy (randomness)
   */
  _checkSessionEntropy(name, value) {
    if (!value || value.length < 16) {
      return {
        severity: 'CRITICAL',
        type: 'WEAK_SESSION_ID',
        cookie: name,
        message: `Session ID too short (${value ? value.length : 0} chars, min: 16)`,
        recommendation: 'Use at least 128-bit (16-byte) random session IDs',
        detail: 'Short session IDs are vulnerable to brute force attacks',
        cwe: 'CWE-330'
      };
    }

    // Check if session ID looks sequential/predictable
    if (this._looksSequential(value)) {
      return {
        severity: 'CRITICAL',
        type: 'PREDICTABLE_SESSION_ID',
        cookie: name,
        message: 'Session ID appears sequential or predictable',
        recommendation: 'Use cryptographically secure random number generator',
        detail: 'Attackers can predict session IDs and hijack other users\' sessions',
        cwe: 'CWE-330'
      };
    }

    return null;
  }

  /**
   * Check if value looks sequential/predictable
   */
  _looksSequential(value) {
    // Simple heuristic: if it's all digits, might be sequential
    if (/^\d+$/.test(value)) return true;

    // Check for incrementing patterns
    if (/012|123|234|345|456|567|678|789|abc|bcd|cde/.test(value.toLowerCase())) {
      return true;
    }

    return false;
  }

  /**
   * Check cookie expiration
   */
  _checkExpiration(name, cookie) {
    if (!cookie.Expires && !cookie['Max-Age']) {
      // Session cookie (expires when browser closes)
      return {
        severity: 'INFO',
        type: 'SESSION_COOKIE',
        cookie: name,
        message: `Cookie "${name}" is a session cookie (no explicit expiration)`,
        recommendation: 'Consider using short-lived persistent cookies for better UX',
        detail: 'Session cookies are deleted when browser closes'
      };
    }

    if (cookie['Max-Age']) {
      const maxAge = parseInt(cookie['Max-Age']);
      const days = maxAge / 86400;

      if (days > 30) {
        return {
          severity: 'MEDIUM',
          type: 'LONG_LIVED_SESSION',
          cookie: name,
          message: `Session cookie "${name}" valid for ${Math.floor(days)} days`,
          recommendation: 'Use shorter session lifetimes (1-7 days) with automatic refresh',
          detail: 'Long-lived sessions increase risk if device is compromised',
          maxAge: maxAge
        };
      }
    }

    return null;
  }

  /**
   * Check cookie domain scope
   */
  _checkDomain(name, cookie, url) {
    if (cookie.Domain) {
      const domain = cookie.Domain.toLowerCase();

      // Check for overly broad domain
      if (domain.startsWith('.')) {
        return {
          severity: 'MEDIUM',
          type: 'BROAD_COOKIE_DOMAIN',
          cookie: name,
          message: `Cookie "${name}" accessible to all subdomains (${domain})`,
          recommendation: 'Scope cookies to specific subdomain when possible',
          detail: 'Cookie exposed to all subdomains increases attack surface',
          domain: domain
        };
      }
    }

    return null;
  }

  /**
   * Track CSRF tokens
   */
  _trackCSRFToken(origin, token) {
    if (!this.csrfTokens.has(origin)) {
      this.csrfTokens.set(origin, {
        tokens: new Set(),
        lastSeen: Date.now()
      });
    }

    const tracking = this.csrfTokens.get(origin);
    tracking.tokens.add(token);
    tracking.lastSeen = Date.now();

    // Cleanup old entries (older than 1 hour)
    const now = Date.now();
    for (const [origin, data] of this.csrfTokens.entries()) {
      if (now - data.lastSeen > 3600000) {
        this.csrfTokens.delete(origin);
      }
    }
  }

  /**
   * Parse Set-Cookie header into structured object
   */
  parseCookie(setCookieHeader) {
    const parts = setCookieHeader.split(';').map(p => p.trim());
    const [nameValue, ...attributes] = parts;
    const [name, value] = nameValue.split('=');

    const cookie = { name, value };

    for (const attr of attributes) {
      const [key, val] = attr.split('=');
      const keyLower = key.toLowerCase();

      if (keyLower === 'secure') cookie.Secure = true;
      else if (keyLower === 'httponly') cookie.HttpOnly = true;
      else if (keyLower === 'samesite') cookie.SameSite = val || 'Lax';
      else if (keyLower === 'domain') cookie.Domain = val;
      else if (keyLower === 'path') cookie.Path = val;
      else if (keyLower === 'expires') cookie.Expires = val;
      else if (keyLower === 'max-age') cookie['Max-Age'] = val;
    }

    return cookie;
  }

  /**
   * Analyze request for session security issues
   * Called by WebRequestListeners.registerCompleted()
   */
  analyzeRequest(requestData, url, responseHeaders) {
    const findings = [];

    try {
      const parsedUrl = new URL(url);
      const isHttps = parsedUrl.protocol === 'https:';

      // Extract Set-Cookie headers from response
      const setCookieHeaders = [];
      if (responseHeaders) {
        responseHeaders.forEach(header => {
          if (header.name.toLowerCase() === 'set-cookie') {
            setCookieHeaders.push(header.value);
          }
        });
      }

      // Parse cookies
      const cookies = {};
      for (const setCookie of setCookieHeaders) {
        const cookie = this.parseCookie(setCookie);
        cookies[cookie.name] = cookie;
      }

      // Analyze session cookies
      if (Object.keys(cookies).length > 0) {
        const cookieIssues = this.analyzeSessionCookies(cookies, url, isHttps);
        findings.push(...cookieIssues);
      }

      // Detect CSRF vulnerabilities
      // Transform requestData to the format detectCSRF expects
      const headers = {};
      if (requestData.requestHeaders) {
        requestData.requestHeaders.forEach(h => {
          headers[h.name.toLowerCase()] = h.value;
        });
      }

      const csrfRequest = {
        method: requestData.method || 'GET',
        headers: headers,
        body: requestData.requestBody,
        cookies: cookies
      };

      const csrfIssue = this.detectCSRF(csrfRequest, url);
      if (csrfIssue) {
        findings.push(csrfIssue);
      }

      // Detect session fixation
      const isAuthRequest = url.toLowerCase().includes('/login') ||
                           url.toLowerCase().includes('/signin') ||
                           url.toLowerCase().includes('/auth');
      const isAuthResponse = requestData.statusCode >= 200 && requestData.statusCode < 400;

      if (isAuthRequest && isAuthResponse) {
        const sessionId = this._extractSessionId(cookies);
        if (sessionId) {
          const fixationIssue = this.detectSessionFixation(sessionId, url, isAuthRequest, isAuthResponse);
          if (fixationIssue) {
            findings.push(fixationIssue);
          }
        }
      }

    } catch (error) {
      console.error('SessionSecurityAnalyzer error:', error);
    }

    return findings;
  }

  /**
   * Extract session ID from cookies
   */
  _extractSessionId(cookies) {
    const sessionCookies = this._identifySessionCookies(cookies);
    for (const [name, cookie] of Object.entries(sessionCookies)) {
      return cookie.value; // Return first session cookie value
    }
    return null;
  }
}

export { SessionSecurityAnalyzer };
