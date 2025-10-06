/**
 * Evidence Collection System for Hera
 *
 * This module implements comprehensive evidence collection for vulnerability verification.
 * It captures complete request/response data, correlates authentication flows, and
 * provides the foundation for evidence-based security testing.
 */

class EvidenceCollector {
  constructor() {
    // CRITICAL FIX P0: Persistent storage for service worker restarts
    this._responseCache = new Map();
    this._flowCorrelation = new Map();
    this._proofOfConcepts = [];
    this._activeFlows = new Map();
    this._timeline = [];

    this.initialized = false;
    this.initPromise = this.initialize();
    this.MAX_CACHE_SIZE = 100;
    this.MAX_TIMELINE = 500;

    // SECURITY FIX P2-NEW: Storage schema versioning
    this.SCHEMA_VERSION = 1;
  }

  async initialize() {
    if (this.initialized) return;

    try {
      // CRITICAL FIX P0: Use chrome.storage.local for evidence (survives browser restart)
      // Evidence is critical for vulnerability reports and should persist
      const data = await chrome.storage.local.get(['heraEvidence', 'heraEvidenceSchemaVersion']);

      // SECURITY FIX P2-NEW: Schema version check and migration
      const storedVersion = data.heraEvidenceSchemaVersion || 0;
      if (storedVersion < this.SCHEMA_VERSION) {
        console.log(`Hera: Evidence schema v${storedVersion} → v${this.SCHEMA_VERSION}`);
        // Future migrations would go here
      }

      if (data.heraEvidence) {
        const evidence = data.heraEvidence;

        if (evidence.responseCache) {
          for (const [id, item] of Object.entries(evidence.responseCache)) {
            this._responseCache.set(id, item);
          }
        }

        if (evidence.flowCorrelation) {
          for (const [id, item] of Object.entries(evidence.flowCorrelation)) {
            this._flowCorrelation.set(id, item);
          }
        }

        this._proofOfConcepts = evidence.proofOfConcepts || [];
        this._timeline = evidence.timeline || [];

        if (evidence.activeFlows) {
          for (const [id, flow] of Object.entries(evidence.activeFlows)) {
            this._activeFlows.set(id, flow);
          }
        }

        console.log(`Hera: Restored evidence (${this._responseCache.size} responses, ${this._timeline.length} events)`);
      }

      this.initialized = true;
    } catch (error) {
      console.error('Hera: Failed to initialize evidence collector:', error);
      this.initialized = true;
    }
  }

  async _syncToStorage() {
    try {
      await this.initPromise;

      // P0-SIXTEENTH-2 FIX: Check quota before writing
      const bytesInUse = await chrome.storage.local.getBytesInUse();
      const quota = chrome.storage.local.QUOTA_BYTES || 10485760;
      if (bytesInUse / quota > 0.90) {
        console.warn('Hera: Evidence sync skipped - quota >90%, cleaning up first');
        await this._performCleanup();
        // Check again after cleanup
        const bytesAfter = await chrome.storage.local.getBytesInUse();
        if (bytesAfter / quota > 0.95) {
          console.error('Hera: Evidence sync aborted - quota still >95% after cleanup');
          return;
        }
      }

      const evidence = {
        responseCache: Object.fromEntries(this._responseCache.entries()),
        flowCorrelation: Object.fromEntries(this._flowCorrelation.entries()),
        proofOfConcepts: this._proofOfConcepts.slice(-50), // Keep only last 50
        timeline: this._timeline.slice(-this.MAX_TIMELINE),
        activeFlows: Object.fromEntries(this._activeFlows.entries())
      };

      // CRITICAL FIX P0: Use chrome.storage.local (survives browser restart)
      // SECURITY FIX P2-NEW: Store schema version
      await chrome.storage.local.set({
        heraEvidence: evidence,
        heraEvidenceSchemaVersion: this.SCHEMA_VERSION
      });
    } catch (error) {
      if (error.message?.includes('QUOTA')) {
        console.error('Hera: Failed to sync evidence: Error: Resource::kQuotaBytes quota exceeded');
        await this._performCleanup();
      } else {
        console.error('Hera: Failed to sync evidence:', error);
      }
    }
  }

  async _performCleanup() {
    if (this._responseCache.size > this.MAX_CACHE_SIZE) {
      const sorted = Array.from(this._responseCache.entries())
        .sort((a, b) => b[1].timestamp - a[1].timestamp);
      this._responseCache = new Map(sorted.slice(0, this.MAX_CACHE_SIZE));
    }

    if (this._timeline.length > this.MAX_TIMELINE) {
      this._timeline = this._timeline.slice(-this.MAX_TIMELINE);
    }

    await this._syncToStorage();
  }

  _debouncedSync() {
    // P3-SIXTEENTH-2: DEBOUNCE TIMING - 1000ms (vs memory-manager's 100ms)
    // Evidence collection is medium-priority (used for vulnerability reports)
    // Longer debounce reduces quota pressure from storing large response bodies
    // Acceptable data loss: Response bodies lost if browser crashes (auth requests still persisted)
    if (this._syncTimeout) clearTimeout(this._syncTimeout);
    this._syncTimeout = setTimeout(() => {
      this._syncToStorage().catch(err => console.error('Evidence sync failed:', err));
    }, 1000); // 1 second debounce - see rationale above
  }

  // Getters for backward compatibility
  get responseCache() { return this._responseCache; }
  get flowCorrelation() { return this._flowCorrelation; }
  get proofOfConcepts() { return this._proofOfConcepts; }
  get activeFlows() { return this._activeFlows; }
  get timeline() { return this._timeline; }

  /**
   * Capture complete response data with evidence analysis
   * @param {string} requestId - Unique identifier for the request
   * @param {Array} responseHeaders - Response headers array
   * @param {string} responseBody - Response body content
   * @param {number} statusCode - HTTP status code
   * @param {Object} requestData - Original request data for correlation
   * @returns {Object} Evidence package
   */
  captureResponse(requestId, responseHeaders, responseBody, statusCode, requestData = null) {
    const timestamp = Date.now();
    const requestUrl = requestData?.url || null;

    const evidence = {
      requestId,
      timestamp,
      headers: responseHeaders || [],
      body: responseBody,
      statusCode,
      requestData,
      evidence: {
        hstsPresent: this.checkHSTSHeader(responseHeaders, requestUrl),
        securityHeaders: this.analyzeSecurityHeaders(responseHeaders),
        cookieFlags: this.analyzeCookies(responseHeaders),
        contentType: this.extractContentType(responseHeaders),
        cacheControl: this.extractCacheControl(responseHeaders)
      },
      analysis: {
        vulnerabilities: this.analyzeForVulnerabilities(responseHeaders, responseBody, statusCode),
        flowContext: this.correlateWithFlow(requestId, requestData)
      }
    };

    // Store in cache for correlation
    this.responseCache.set(requestId, evidence);

    // Add to timeline
    this.timeline.push({
      timestamp,
      requestId,
      type: 'response_captured',
      url: requestData?.url,
      method: requestData?.method
    });

    // CRITICAL FIX: Persist to storage.session
    this._debouncedSync();

    return evidence;
  }

  /**
   * Capture complete request data for flow correlation
   * @param {string} requestId - Unique identifier for the request
   * @param {Object} requestDetails - Complete request details
   * @returns {Object} Request evidence package
   */
  captureRequest(requestId, requestDetails) {
    const timestamp = Date.now();
    const evidence = {
      requestId,
      timestamp,
      url: requestDetails.url,
      method: requestDetails.method,
      headers: requestDetails.requestHeaders || [],
      body: requestDetails.requestBody,
      type: requestDetails.type,
      analysis: {
        authFlow: this.analyzeAuthFlow(requestDetails),
        oauth2Flow: this.analyzeOAuth2Flow(requestDetails),
        credentials: this.analyzeCredentials(requestDetails),
        crossOrigin: this.analyzeCrossOrigin(requestDetails)
      }
    };

    // Correlate with active flows
    this.correlateFlow(requestId, evidence);

    // Add to timeline
    this.timeline.push({
      timestamp,
      requestId,
      type: 'request_captured',
      url: requestDetails.url,
      method: requestDetails.method
    });

    // CRITICAL FIX: Persist to storage.session
    this._debouncedSync();

    return evidence;
  }

  /**
   * Check for HSTS header presence and configuration
   * @param {Array} headers - Response headers
   * @param {string} url - Request URL to verify HTTPS usage
   * @returns {Object} HSTS analysis
   */
  checkHSTSHeader(headers, url = null) {
    if (!headers) return { present: false, reason: 'no_headers' };

    // CRITICAL: HSTS is meaningless on HTTP connections
    let isHTTPS = true;
    if (url) {
      try {
        isHTTPS = new URL(url).protocol === 'https:';
      } catch (e) {
        // Invalid URL, assume HTTP for safety
        isHTTPS = false;
      }
    }

    const hstsHeader = headers.find(h =>
      h.name.toLowerCase() === 'strict-transport-security'
    );

    if (!hstsHeader) {
      return {
        present: false,
        reason: 'header_missing',
        isHTTPS: isHTTPS,
        warning: !isHTTPS ? 'Connection not using HTTPS - HSTS not applicable' : null,
        evidence: headers.map(h => ({ name: h.name, value: h.value }))
      };
    }

    // HSTS header on HTTP connection is suspicious (should be stripped by browsers)
    if (!isHTTPS) {
      return {
        present: true,
        isHTTPS: false,
        warning: 'CRITICAL: HSTS header sent over HTTP - potential security misconfiguration',
        value: hstsHeader.value,
        evidence: { name: hstsHeader.name, value: hstsHeader.value, protocol: 'HTTP' }
      };
    }

    // Parse HSTS directive
    const value = hstsHeader.value;
    const maxAgeMatch = value.match(/max-age=(\d+)/i);
    const includeSubDomains = /includeSubDomains/i.test(value);
    const preload = /preload/i.test(value);

    return {
      present: true,
      isHTTPS: true,
      value: value,
      maxAge: maxAgeMatch ? parseInt(maxAgeMatch[1]) : null,
      includeSubDomains,
      preload,
      analysis: {
        maxAgeAppropriate: maxAgeMatch && parseInt(maxAgeMatch[1]) >= 31536000, // 1 year
        hasSubDomains: includeSubDomains,
        preloadReady: preload
      },
      evidence: { name: hstsHeader.name, value: hstsHeader.value, protocol: 'HTTPS' }
    };
  }

  /**
   * Analyze security headers for evidence collection
   * @param {Array} headers - Response headers
   * @returns {Object} Security headers analysis
   */
  analyzeSecurityHeaders(headers) {
    if (!headers) return { count: 0, headers: [], missing: [] };

    const securityHeaders = {
      'strict-transport-security': null,
      'content-security-policy': null,
      'x-frame-options': null,
      'x-content-type-options': null,
      'referrer-policy': null,
      'permissions-policy': null,
      'x-xss-protection': null
    };

    const found = [];
    const missing = [];

    // Check for each security header
    for (const headerName of Object.keys(securityHeaders)) {
      const header = headers.find(h => h.name.toLowerCase() === headerName);
      if (header) {
        securityHeaders[headerName] = header.value;
        found.push({ name: header.name, value: header.value });
      } else {
        missing.push(headerName);
      }
    }

    return {
      count: found.length,
      headers: found,
      missing,
      analysis: {
        score: this.calculateSecurityHeaderScore(found, missing),
        recommendations: this.generateSecurityHeaderRecommendations(missing)
      },
      evidence: headers.map(h => ({ name: h.name, value: h.value }))
    };
  }

  /**
   * Analyze cookie security flags
   * @param {Array} headers - Response headers
   * @returns {Object} Cookie security analysis
   */
  analyzeCookies(headers) {
    if (!headers) return { cookies: [], vulnerabilities: [] };

    const setCookieHeaders = headers.filter(h =>
      h.name.toLowerCase() === 'set-cookie'
    );

    const analysis = {
      cookies: [],
      vulnerabilities: [],
      evidence: setCookieHeaders
    };

    for (const cookieHeader of setCookieHeaders) {
      const cookie = this.parseCookie(cookieHeader.value);
      analysis.cookies.push(cookie);

      // Check for security issues
      if (!cookie.httpOnly) {
        analysis.vulnerabilities.push({
          type: 'missing_httponly',
          cookie: cookie.name,
          severity: 'MEDIUM',
          evidence: cookieHeader.value
        });
      }

      if (!cookie.secure) {
        analysis.vulnerabilities.push({
          type: 'missing_secure',
          cookie: cookie.name,
          severity: 'HIGH',
          evidence: cookieHeader.value
        });
      }

      if (!cookie.sameSite || cookie.sameSite.toLowerCase() === 'none') {
        analysis.vulnerabilities.push({
          type: 'weak_samesite',
          cookie: cookie.name,
          severity: 'MEDIUM',
          evidence: cookieHeader.value
        });
      }
    }

    return analysis;
  }

  /**
   * Parse individual cookie for security analysis
   * @param {string} cookieString - Set-Cookie header value
   * @returns {Object} Parsed cookie with security flags
   */
  parseCookie(cookieString) {
    const parts = cookieString.split(';').map(p => p.trim());
    const [nameValue] = parts;
    const [name, value] = nameValue.split('=');

    const cookie = {
      name: name?.trim(),
      value: value?.trim(),
      httpOnly: false,
      secure: false,
      sameSite: null,
      maxAge: null,
      expires: null,
      domain: null,
      path: null
    };

    // Parse flags
    for (const part of parts.slice(1)) {
      const lower = part.toLowerCase();
      if (lower === 'httponly') {
        cookie.httpOnly = true;
      } else if (lower === 'secure') {
        cookie.secure = true;
      } else if (lower.startsWith('samesite=')) {
        cookie.sameSite = part.split('=')[1];
      } else if (lower.startsWith('max-age=')) {
        cookie.maxAge = parseInt(part.split('=')[1]);
      } else if (lower.startsWith('expires=')) {
        cookie.expires = part.split('=')[1];
      } else if (lower.startsWith('domain=')) {
        cookie.domain = part.split('=')[1];
      } else if (lower.startsWith('path=')) {
        cookie.path = part.split('=')[1];
      }
    }

    return cookie;
  }

  /**
   * Extract content type from headers
   * @param {Array} headers - Response headers
   * @returns {Object} Content type analysis
   */
  extractContentType(headers) {
    if (!headers) return null;

    const contentTypeHeader = headers.find(h =>
      h.name.toLowerCase() === 'content-type'
    );

    if (!contentTypeHeader) return null;

    const value = contentTypeHeader.value;
    const [mediaType, ...params] = value.split(';').map(p => p.trim());

    return {
      mediaType,
      parameters: params,
      full: value,
      evidence: { name: contentTypeHeader.name, value: contentTypeHeader.value }
    };
  }

  /**
   * Extract cache control directives
   * @param {Array} headers - Response headers
   * @returns {Object} Cache control analysis
   */
  extractCacheControl(headers) {
    if (!headers) return null;

    const cacheControlHeader = headers.find(h =>
      h.name.toLowerCase() === 'cache-control'
    );

    if (!cacheControlHeader) return null;

    const directives = cacheControlHeader.value.split(',').map(d => d.trim());

    return {
      directives,
      noCache: directives.includes('no-cache'),
      noStore: directives.includes('no-store'),
      maxAge: this.extractMaxAge(directives),
      evidence: { name: cacheControlHeader.name, value: cacheControlHeader.value }
    };
  }

  /**
   * Analyze response for potential vulnerabilities
   * @param {Array} headers - Response headers
   * @param {string} body - Response body
   * @param {number} statusCode - HTTP status code
   * @returns {Array} List of potential vulnerabilities
   */
  analyzeForVulnerabilities(headers, body, statusCode) {
    const vulnerabilities = [];

    // Check for information disclosure in headers
    if (headers) {
      const serverHeader = headers.find(h => h.name.toLowerCase() === 'server');
      if (serverHeader && this.containsSensitiveServerInfo(serverHeader.value)) {
        vulnerabilities.push({
          type: 'server_info_disclosure',
          severity: 'LOW',
          evidence: serverHeader,
          description: 'Server header reveals sensitive information'
        });
      }

      // Check for debug headers
      const debugHeaders = headers.filter(h =>
        h.name.toLowerCase().includes('debug') ||
        h.name.toLowerCase().includes('trace')
      );

      if (debugHeaders.length > 0) {
        vulnerabilities.push({
          type: 'debug_headers_present',
          severity: 'MEDIUM',
          evidence: debugHeaders,
          description: 'Debug headers present in production response'
        });
      }
    }

    // Check for sensitive data in response body
    if (body && this.containsSensitiveData(body)) {
      vulnerabilities.push({
        type: 'sensitive_data_exposure',
        severity: 'HIGH',
        evidence: this.extractSensitiveDataSamples(body),
        description: 'Response body contains sensitive data'
      });
    }

    return vulnerabilities;
  }

  /**
   * Correlate request with active authentication flows
   * @param {string} requestId - Request identifier
   * @param {Object} requestData - Request data
   * @returns {Object} Flow correlation data
   */
  correlateWithFlow(requestId, requestData) {
    if (!requestData) return null;

    // Try to identify which flow this request belongs to
    const url = new URL(requestData.url);
    const flowKey = this.generateFlowKey(url);

    let flow = this.activeFlows.get(flowKey);
    if (!flow) {
      flow = {
        flowId: this.generateFlowId(),
        startTime: Date.now(),
        requests: [],
        domain: url.hostname,
        protocol: this.detectAuthProtocol(requestData)
      };
      this.activeFlows.set(flowKey, flow);
    }

    flow.requests.push({
      requestId,
      timestamp: Date.now(),
      url: requestData.url,
      method: requestData.method
    });

    return {
      flowId: flow.flowId,
      stepNumber: flow.requests.length,
      protocol: flow.protocol
    };
  }

  /**
   * Calculate security header score
   * @param {Array} found - Found security headers
   * @param {Array} missing - Missing security headers
   * @returns {number} Security score (0-100)
   */
  calculateSecurityHeaderScore(found, missing) {
    const totalHeaders = found.length + missing.length;
    if (totalHeaders === 0) return 0;

    return Math.round((found.length / totalHeaders) * 100);
  }

  /**
   * Generate recommendations for missing security headers
   * @param {Array} missing - Missing header names
   * @returns {Array} Recommendations
   */
  generateSecurityHeaderRecommendations(missing) {
    const recommendations = [];

    for (const header of missing) {
      switch (header) {
        case 'strict-transport-security':
          recommendations.push('Add HSTS header to prevent downgrade attacks');
          break;
        case 'content-security-policy':
          recommendations.push('Implement CSP to prevent XSS attacks');
          break;
        case 'x-frame-options':
          recommendations.push('Add X-Frame-Options to prevent clickjacking');
          break;
        default:
          recommendations.push(`Consider adding ${header} header`);
      }
    }

    return recommendations;
  }

  // Utility methods
  extractMaxAge(directives) {
    const maxAgeDirective = directives.find(d => d.startsWith('max-age='));
    return maxAgeDirective ? parseInt(maxAgeDirective.split('=')[1]) : null;
  }

  containsSensitiveServerInfo(serverValue) {
    return /\d+\.\d+\.\d+/.test(serverValue) || // Version numbers
           /debug|dev|test/i.test(serverValue);   // Debug keywords
  }

  containsSensitiveData(body) {
    const sensitivePatterns = [
      /password["\s]*[:=]["\s]*[^"\s]{6,}/i,
      /api[_-]?key["\s]*[:=]["\s]*[a-zA-Z0-9]{20,}/i,
      /secret["\s]*[:=]["\s]*[a-zA-Z0-9]{16,}/i,
      /token["\s]*[:=]["\s]*[a-zA-Z0-9]{32,}/i
    ];

    return sensitivePatterns.some(pattern => pattern.test(body));
  }

  extractSensitiveDataSamples(body) {
    // Return sanitized samples for evidence
    const samples = [];
    if (body && typeof body === 'string') {
      if (body.includes('password')) samples.push('Contains password field');
      if (body.includes('api_key') || body.includes('apikey')) samples.push('Contains API key');
      if (body.includes('secret')) samples.push('Contains secret');
      if (body.includes('token')) samples.push('Contains token');
    }
    return samples;
  }

  generateFlowKey(url) {
    return `${url.hostname}_${url.pathname.split('/')[1] || 'root'}`;
  }

  generateFlowId() {
    return `flow_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  detectAuthProtocol(requestData) {
    const url = requestData.url.toLowerCase();
    if (url.includes('oauth') || url.includes('authorize')) return 'OAuth2';
    if (url.includes('saml')) return 'SAML';
    if (url.includes('openid')) return 'OpenID';
    if (url.includes('auth') || url.includes('login')) return 'Custom';
    return 'Unknown';
  }

  analyzeAuthFlow(requestDetails) {
    // This will be expanded in Phase 2
    return {
      isAuthRelated: this.isAuthenticationRequest(requestDetails),
      protocol: this.detectAuthProtocol(requestDetails),
      step: this.identifyAuthStep(requestDetails)
    };
  }

  analyzeOAuth2Flow(requestDetails) {
    // This will be expanded in Phase 2
    const url = new URL(requestDetails.url);
    return {
      isOAuth2: url.pathname.includes('oauth') || url.searchParams.has('client_id'),
      clientId: url.searchParams.get('client_id'),
      state: url.searchParams.get('state'),
      scope: url.searchParams.get('scope'),
      responseType: url.searchParams.get('response_type')
    };
  }

  analyzeCredentials(requestDetails) {
    // This will be expanded in Phase 2
    return {
      hasAuthHeader: requestDetails.requestHeaders?.some(h =>
        h.name.toLowerCase() === 'authorization'
      ),
      hasCookies: requestDetails.requestHeaders?.some(h =>
        h.name.toLowerCase() === 'cookie'
      )
    };
  }

  analyzeCrossOrigin(requestDetails) {
    const origin = requestDetails.requestHeaders?.find(h =>
      h.name.toLowerCase() === 'origin'
    )?.value;

    if (!origin) return { isCrossOrigin: false };

    const requestUrl = new URL(requestDetails.url);
    const originUrl = new URL(origin);

    return {
      isCrossOrigin: originUrl.hostname !== requestUrl.hostname,
      origin: origin,
      target: requestUrl.hostname
    };
  }

  correlateFlow(requestId, evidence) {
    // This will be expanded as we build the flow correlation system
    const flowKey = this.generateFlowKey(new URL(evidence.url));

    if (!this.flowCorrelation.has(flowKey)) {
      this.flowCorrelation.set(flowKey, []);
    }

    this.flowCorrelation.get(flowKey).push({
      requestId,
      timestamp: evidence.timestamp,
      evidence
    });
  }

  isAuthenticationRequest(requestDetails) {
    const url = requestDetails.url.toLowerCase();
    const authPatterns = [
      /\/auth\//,
      /\/login/,
      /\/signin/,
      /\/oauth/,
      /\/sso\//,
      /\/authenticate/
    ];

    return authPatterns.some(pattern => pattern.test(url));
  }

  identifyAuthStep(requestDetails) {
    const url = requestDetails.url.toLowerCase();
    if (url.includes('authorize')) return 'authorization_request';
    if (url.includes('token')) return 'token_request';
    if (url.includes('login')) return 'login_form';
    if (url.includes('callback')) return 'callback';
    return 'unknown';
  }

  /**
   * Get evidence for a specific request
   * @param {string} requestId - Request identifier
   * @returns {Object} Complete evidence package
   */
  getEvidence(requestId) {
    return this.responseCache.get(requestId);
  }

  /**
   * Get all evidence for a flow
   * @param {string} flowId - Flow identifier
   * @returns {Array} All evidence for the flow
   */
  getFlowEvidence(flowId) {
    const evidence = [];
    for (const [requestId, responseEvidence] of this.responseCache) {
      if (responseEvidence.analysis?.flowContext?.flowId === flowId) {
        evidence.push(responseEvidence);
      }
    }
    return evidence;
  }

  /**
   * Get timeline of all captured events
   * @returns {Array} Chronological timeline
   */
  getTimeline() {
    return this.timeline.sort((a, b) => a.timestamp - b.timestamp);
  }

  /**
   * Clear old evidence to prevent memory leaks
   * @param {number} maxAge - Maximum age in milliseconds
   */
  cleanup(maxAge = 3600000) { // 1 hour default
    const cutoff = Date.now() - maxAge;

    for (const [requestId, evidence] of this.responseCache) {
      if (evidence.timestamp < cutoff) {
        this.responseCache.delete(requestId);
      }
    }

    // Clean timeline - use private property since timeline is read-only
    this._timeline = this._timeline.filter(event => event.timestamp >= cutoff);
  }
}

export { EvidenceCollector };