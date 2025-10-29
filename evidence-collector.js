/**
 * Evidence Collection System for Hera
 *
 * This module implements comprehensive evidence collection for vulnerability verification.
 * It captures complete request/response data, correlates authentication flows, and
 * provides the foundation for evidence-based security testing.
 *
 * PHASE 1 OIDC ENHANCEMENT:
 * - POST body capture with automatic redaction
 * - Token request evidence collection
 * - PKCE verification support
 */

import { RequestBodyCapturer } from './modules/auth/request-body-capturer.js';

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
    this.MAX_CACHE_SIZE = 50; // Reduced from 100 - debug mode adds more data per request
    this.MAX_TIMELINE = 500;

    // SECURITY FIX P2-NEW: Storage schema versioning
    this.SCHEMA_VERSION = 1;

    // PHASE 1: Initialize request body capturer
    this.bodyCapturer = new RequestBodyCapturer();

    // P0 FIX: IndexedDB for large evidence persistence
    this.db = null;
    this.lastSyncTime = null;
    this.SYNC_INTERVAL_MS = 60000; // Auto-save every 60 seconds
    this.autoSaveTimer = null;
  }

  async initialize() {
    if (this.initialized) return;

    try {
      // P0 FIX: Initialize IndexedDB for persistent evidence storage
      await this._initIndexedDB();

      // Try to restore from IndexedDB first (larger storage)
      const evidence = await this._loadFromIndexedDB();

      if (evidence) {
        if (evidence.responseCache) {
          this._responseCache = new Map(Object.entries(evidence.responseCache));
        }
        if (evidence.flowCorrelation) {
          this._flowCorrelation = new Map(Object.entries(evidence.flowCorrelation));
        }
        this._proofOfConcepts = evidence.proofOfConcepts || [];
        this._timeline = evidence.timeline || [];
        if (evidence.activeFlows) {
          this._activeFlows = new Map(Object.entries(evidence.activeFlows));
        }

        console.log(`[Evidence] Restored ${this._responseCache.size} responses, ${this._timeline.length} events from IndexedDB`);
      } else {
        // Fallback: Try chrome.storage.local (legacy)
        const data = await chrome.storage.local.get(['heraEvidence', 'heraEvidenceSchemaVersion']);

        if (data.heraEvidence) {
          const legacyEvidence = data.heraEvidence;
          if (legacyEvidence.responseCache) {
            this._responseCache = new Map(Object.entries(legacyEvidence.responseCache));
          }
          if (legacyEvidence.flowCorrelation) {
            this._flowCorrelation = new Map(Object.entries(legacyEvidence.flowCorrelation));
          }
          this._proofOfConcepts = legacyEvidence.proofOfConcepts || [];
          this._timeline = legacyEvidence.timeline || [];

          console.log(`[Evidence] Migrated ${this._responseCache.size} responses from chrome.storage.local`);

          // Migrate to IndexedDB and clean up old storage
          await this._saveToIndexedDB();
          await chrome.storage.local.remove(['heraEvidence']);
        }
      }

      // P0 FIX: Start auto-save timer
      this._startAutoSave();

      this.initialized = true;
    } catch (error) {
      console.error('Hera: Failed to initialize evidence collector:', error);
      this.initialized = true;
    }
  }

  /**
   * P0 FIX: Initialize IndexedDB for evidence persistence
   */
  async _initIndexedDB() {
    // Check if IndexedDB is available (not available in service worker in some contexts)
    if (typeof indexedDB === 'undefined') {
      console.warn('[Evidence] IndexedDB not available in this context - using fallback storage');
      return;
    }

    return new Promise((resolve, reject) => {
      try {
        const request = indexedDB.open('HeraEvidence', 1);

        request.onerror = () => {
          console.warn('[Evidence] IndexedDB initialization failed:', request.error);
          resolve(); // Don't reject - fall back to memory-only
        };

        request.onsuccess = () => {
          this.db = request.result;
          console.debug('[Evidence] IndexedDB initialized successfully');
          resolve();
        };

        request.onupgradeneeded = (event) => {
          const db = event.target.result;

          // Create object store for evidence
          if (!db.objectStoreNames.contains('evidence')) {
            db.createObjectStore('evidence', { keyPath: 'id' });
          }
        };
      } catch (error) {
        console.warn('[Evidence] IndexedDB not available:', error.message);
        resolve(); // Don't fail initialization
      }
    });
  }

  /**
   * P0 FIX: Load evidence from IndexedDB
   */
  async _loadFromIndexedDB() {
    if (!this.db) return null;

    try {
      return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['evidence'], 'readonly');
        const store = transaction.objectStore('evidence');
        const request = store.get('current');

        request.onsuccess = () => {
          resolve(request.result?.data || null);
        };
        request.onerror = () => {
          console.warn('[Evidence] Load from IndexedDB failed:', request.error);
          resolve(null); // Don't fail - just return null
        };
      });
    } catch (error) {
      console.warn('[Evidence] IndexedDB load error:', error.message);
      return null;
    }
  }

  /**
   * P0 FIX: Serialize data for IndexedDB (remove non-cloneable objects)
   */
  _serializeForStorage(data) {
    try {
      // Deep clone using JSON (this will fail on non-serializable data)
      // but will help us identify the issue
      return JSON.parse(JSON.stringify(data, (key, value) => {
        // Filter out non-serializable types
        if (value instanceof Promise) {
          console.warn(`[Evidence] Removed Promise from key: ${key}`);
          return undefined;
        }
        if (typeof value === 'function') {
          console.warn(`[Evidence] Removed function from key: ${key}`);
          return undefined;
        }
        if (value instanceof Error) {
          // Serialize errors as objects
          return {
            __error: true,
            message: value.message,
            name: value.name,
            stack: value.stack
          };
        }
        return value;
      }));
    } catch (error) {
      console.error('[Evidence] Serialization failed:', error);
      return null;
    }
  }

  /**
   * P0 FIX: Save evidence to IndexedDB
   */
  async _saveToIndexedDB() {
    if (!this.db) {
      // No IndexedDB available - skip save (fallback to memory-only)
      this.lastSyncTime = Date.now();
      return;
    }

    try {
      // Serialize Maps to plain objects
      const rawEvidence = {
        responseCache: Object.fromEntries(this._responseCache.entries()),
        flowCorrelation: Object.fromEntries(this._flowCorrelation.entries()),
        proofOfConcepts: this._proofOfConcepts,
        timeline: this._timeline,
        activeFlows: Object.fromEntries(this._activeFlows.entries())
      };

      // Clean up non-serializable data
      const evidence = this._serializeForStorage(rawEvidence);

      if (!evidence) {
        console.error('[Evidence] Failed to serialize evidence - skipping save');
        this.lastSyncTime = Date.now();
        return;
      }

      return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['evidence'], 'readwrite');
        const store = transaction.objectStore('evidence');
        const request = store.put({
          id: 'current',
          data: evidence,
          timestamp: Date.now()
        });

        request.onsuccess = () => {
          this.lastSyncTime = Date.now();
          console.debug('[Evidence] Saved to IndexedDB successfully');
          resolve();
        };
        request.onerror = () => {
          const errorMsg = request.error?.message || String(request.error);
          console.warn('[Evidence] IndexedDB save failed:', errorMsg);

          // Log detailed error for debugging
          if (errorMsg.includes('DataCloneError')) {
            console.error('[Evidence] DataCloneError - evidence contains non-cloneable data');
            console.error('[Evidence] Evidence keys:', Object.keys(rawEvidence));
            console.error('[Evidence] ResponseCache size:', this._responseCache.size);
            console.error('[Evidence] FlowCorrelation size:', this._flowCorrelation.size);
          }

          this.lastSyncTime = Date.now();
          resolve(); // Don't fail - just mark as synced
        };
      });
    } catch (error) {
      console.warn('[Evidence] IndexedDB save error:', error.message);
      console.error('[Evidence] Full error:', error);
      this.lastSyncTime = Date.now();
      // Continue without failing
    }
  }

  /**
   * P0 FIX: Start auto-save timer
   */
  _startAutoSave() {
    // Clear existing timer
    if (this.autoSaveTimer) {
      clearInterval(this.autoSaveTimer);
    }

    // Auto-save every 60 seconds
    this.autoSaveTimer = setInterval(async () => {
      try {
        await this._saveToIndexedDB();
        if (this.db) {
          const secondsAgo = Math.floor((Date.now() - this.lastSyncTime) / 1000);
          console.debug(`[Evidence] Auto-saved (last sync: ${secondsAgo}s ago)`);
        }
      } catch (error) {
        console.warn('[Evidence] Auto-save error:', error.message);
      }
    }, this.SYNC_INTERVAL_MS);

    // Note: visibility change not available in service worker context
    // Extension will save on interval and when explicitly called
  }

  async _syncToStorage() {
    try {
      await this.initPromise;

      // P0-SIXTEENTH-2 FIX: Check quota before writing
      const bytesInUse = await chrome.storage.local.getBytesInUse();
      const quota = chrome.storage.local.QUOTA_BYTES || 10485760;
      const usagePercent = (bytesInUse / quota * 100).toFixed(1);

      if (bytesInUse / quota > 0.90) {
        console.warn(`Hera: Evidence sync - quota at ${usagePercent}%, cleaning up in-memory cache first`);

        // Clean up in-memory data WITHOUT recursive sync call
        this._performCleanup();

        // Check again after cleanup
        const bytesAfter = await chrome.storage.local.getBytesInUse();
        const afterPercent = (bytesAfter / quota * 100).toFixed(1);

        if (bytesAfter / quota > 0.95) {
          console.error(`Hera: Evidence sync aborted - quota still at ${afterPercent}% after cleanup`);
          console.error('Hera: Run emergency cleanup in memory-manager or clear storage manually');
          return;
        }

        console.log(`Hera: Evidence cleanup complete, quota now at ${afterPercent}%`);
      }

      // Build evidence object with already-cleaned in-memory data
      // CRITICAL: Strip large fields from responses to prevent storage bloat
      const strippedResponseCache = {};
      for (const [key, response] of this._responseCache.entries()) {
        strippedResponseCache[key] = {
          url: response.url,
          method: response.method,
          statusCode: response.statusCode,
          timestamp: response.timestamp,
          requestId: response.requestId,
          tabId: response.tabId,
          // Strip large fields
          headers: response.headers ? Object.keys(response.headers).slice(0, 20).reduce((obj, k) => {
            obj[k] = response.headers[k];
            return obj;
          }, {}) : {},
          // Keep only first 1000 chars of responseBody
          responseBody: response.responseBody ? response.responseBody.substring(0, 1000) + '...' : null,
          // Strip HTML snapshots entirely
          timing: response.timing,
          findings: response.findings || []
        };
      }

      const evidence = {
        responseCache: strippedResponseCache,
        flowCorrelation: Object.fromEntries(this._flowCorrelation.entries()),
        proofOfConcepts: this._proofOfConcepts.slice(-50), // Keep only last 50
        timeline: this._timeline.slice(-this.MAX_TIMELINE),
        activeFlows: Object.fromEntries(this._activeFlows.entries())
      };

      // Calculate size before storing
      const evidenceSize = JSON.stringify(evidence).length;
      const evidenceMB = (evidenceSize / 1024 / 1024).toFixed(2);

      // Final check: if evidence itself is >8 MB, it's too big to store
      if (evidenceSize > 8388608) { // 8 MB
        console.error(`Hera: Evidence object is ${evidenceMB} MB - too large to store!`);
        console.error('Hera: Performing aggressive cleanup...');

        // Aggressively reduce cache size
        this.MAX_CACHE_SIZE = Math.min(10, this.MAX_CACHE_SIZE);
        this.MAX_TIMELINE = Math.min(50, this.MAX_TIMELINE);
        this._performCleanup();

        console.log(`Hera: Reduced MAX_CACHE_SIZE to ${this.MAX_CACHE_SIZE}, MAX_TIMELINE to ${this.MAX_TIMELINE}`);
        return; // Don't write this sync, wait for next sync with smaller data
      }

      // P0 FIX: Now using IndexedDB for persistent storage (no quota limits)
      // Don't sync to chrome.storage.local - IndexedDB handles it
      const secondsSinceLastSync = this.lastSyncTime
        ? Math.floor((Date.now() - this.lastSyncTime) / 1000)
        : 0;

      const syncStatus = this.lastSyncTime
        ? `✓ Saved ${secondsSinceLastSync}s ago`
        : '⏳ Syncing...';

      console.log(`[Evidence] ${this._responseCache.size} responses, ${this._timeline.length} events (${evidenceMB} MB) - ${syncStatus}`);

    } catch (error) {
      if (error.message?.includes('QUOTA')) {
        console.error('Hera: Evidence sync failed - QUOTA_BYTES exceeded');
        console.error('Hera: Performing aggressive cleanup...');

        // Reduce limits and clean up
        this.MAX_CACHE_SIZE = Math.min(5, this.MAX_CACHE_SIZE); // Reduce to 5
        this.MAX_TIMELINE = Math.min(25, this.MAX_TIMELINE); // Reduce to 25
        this._performCleanup();

        console.log(`Hera: Reduced MAX_CACHE_SIZE to ${this.MAX_CACHE_SIZE}, MAX_TIMELINE to ${this.MAX_TIMELINE}`);
        // Don't recurse - wait for next sync
      } else {
        console.error('Hera: Failed to sync evidence:', error);
      }
    }
  }

  _performCleanup() {
    // IMPORTANT: This is now synchronous and does NOT call _syncToStorage()
    // to prevent infinite recursion

    let cleaned = false;

    if (this._responseCache.size > this.MAX_CACHE_SIZE) {
      const beforeSize = this._responseCache.size;
      const sorted = Array.from(this._responseCache.entries())
        .sort((a, b) => (b[1].timestamp || 0) - (a[1].timestamp || 0));
      this._responseCache = new Map(sorted.slice(0, this.MAX_CACHE_SIZE));
      console.log(`Hera: Cleaned response cache: ${beforeSize} → ${this._responseCache.size}`);
      cleaned = true;
    }

    if (this._timeline.length > this.MAX_TIMELINE) {
      const beforeSize = this._timeline.length;
      this._timeline = this._timeline.slice(-this.MAX_TIMELINE);
      console.log(`Hera: Cleaned timeline: ${beforeSize} → ${this._timeline.length} events`);
      cleaned = true;
    }

    // Clean up Maps that can grow unbounded
    const MAX_FLOW_CORRELATION = 100;
    if (this._flowCorrelation.size > MAX_FLOW_CORRELATION) {
      const beforeSize = this._flowCorrelation.size;
      const entries = Array.from(this._flowCorrelation.entries()).slice(-MAX_FLOW_CORRELATION);
      this._flowCorrelation = new Map(entries);
      console.log(`Hera: Cleaned flow correlation: ${beforeSize} → ${this._flowCorrelation.size}`);
      cleaned = true;
    }

    const MAX_ACTIVE_FLOWS = 50;
    if (this._activeFlows.size > MAX_ACTIVE_FLOWS) {
      const beforeSize = this._activeFlows.size;
      const entries = Array.from(this._activeFlows.entries()).slice(-MAX_ACTIVE_FLOWS);
      this._activeFlows = new Map(entries);
      console.log(`Hera: Cleaned active flows: ${beforeSize} → ${this._activeFlows.size}`);
      cleaned = true;
    }

    if (this._proofOfConcepts.length > 50) {
      const beforeSize = this._proofOfConcepts.length;
      this._proofOfConcepts = this._proofOfConcepts.slice(-50);
      console.log(`Hera: Cleaned POCs: ${beforeSize} → ${this._proofOfConcepts.length}`);
      cleaned = true;
    }

    if (!cleaned) {
      console.log('Hera: Evidence cleanup - no action needed (within limits)');
    }

    // DO NOT call _syncToStorage() here - that creates infinite recursion!
  }

  _debouncedSync() {
    // P0 FIX: Save to IndexedDB (persistent, no quota limits)
    // Debounced to avoid excessive writes on high-traffic sites
    if (this._syncTimeout) clearTimeout(this._syncTimeout);
    this._syncTimeout = setTimeout(async () => {
      try {
        await this._saveToIndexedDB();
        // Also update the console log
        await this._syncToStorage();
      } catch (err) {
        console.error('[Evidence] Sync failed:', err.message);

        // Additional debug info for common errors
        if (err.name === 'DataCloneError') {
          console.error('[Evidence] DataCloneError - evidence contains non-serializable data (Promise, Function, etc.)');
          console.error('[Evidence] Check what is being stored in responseCache or flowCorrelation');
        }
      }
    }, 1000); // 1 second debounce
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
   * P0-A: Process response body captured by ResponseBodyCapturer
   *
   * PURPOSE:
   * - Analyze response bodies for security findings
   * - Detect DPoP token type
   * - Detect WebAuthn/FIDO2 challenges
   * - Detect TOTP/OTP codes
   * - Detect session tokens
   *
   * CRITICAL FIX: Now accepts authRequests Map to avoid responseCache mismatch
   *
   * @param {string} requestId - Request ID to correlate with
   * @param {Object|string} responseBody - Response body (may be redacted)
   * @param {string} url - Request URL for context
   * @param {Map} authRequests - Reference to authRequests Map (passed from ResponseBodyCapturer)
   */
  processResponseBody(requestId, responseBody, url, authRequests = null) {
    // CRITICAL FIX: Use authRequests if provided, otherwise fall back to responseCache
    const requestsMap = authRequests || this.responseCache;

    // Get existing evidence for this request
    const existingEvidence = requestsMap.get(requestId);
    if (!existingEvidence) {
      console.warn(`[Evidence] No existing evidence for request ${requestId}`);
      return;
    }

    // Parse response body if it's a string
    let parsedBody = responseBody;
    if (typeof responseBody === 'string') {
      try {
        parsedBody = JSON.parse(responseBody);
      } catch (error) {
        // Not JSON, skip analysis
        return;
      }
    }

    // Analyze response body for security findings
    const findings = [];

    // P1-5: DPoP Detection
    if (parsedBody.token_type) {
      const tokenType = parsedBody.token_type.toLowerCase();
      if (tokenType === 'dpop') {
        findings.push({
          type: 'DPOP_DETECTED',
          severity: 'INFO',
          confidence: 'HIGH',
          message: 'DPoP token type detected - tokens are sender-constrained',
          evidence: {
            token_type: parsedBody.token_type,
            url,
            note: 'RFC 9449: DPoP provides proof-of-possession for OAuth 2.0 tokens'
          },
          references: ['RFC 9449: OAuth 2.0 Demonstrating Proof-of-Possession']
        });
      } else if (tokenType === 'bearer') {
        // Only report if this is a public client (higher risk)
        findings.push({
          type: 'BEARER_TOKEN_USED',
          severity: 'INFO',
          confidence: 'HIGH',
          message: 'Bearer token type detected - tokens are not sender-constrained',
          evidence: {
            token_type: parsedBody.token_type,
            url,
            note: 'Consider upgrading to DPoP for enhanced security (RFC 9449)'
          },
          references: ['RFC 9449: OAuth 2.0 Demonstrating Proof-of-Possession']
        });
      }
    }

    // P2-7: WebAuthn Challenge Detection
    if (parsedBody.publicKey && parsedBody.publicKey.challenge) {
      findings.push({
        type: 'WEBAUTHN_CHALLENGE_DETECTED',
        severity: 'INFO',
        confidence: 'HIGH',
        message: 'WebAuthn authentication challenge detected',
        evidence: {
          rpId: parsedBody.publicKey.rpId,
          timeout: parsedBody.publicKey.timeout,
          userVerification: parsedBody.publicKey.userVerification,
          url,
          note: 'WebAuthn/FIDO2 provides phishing-resistant MFA'
        },
        references: ['W3C WebAuthn Level 2', 'FIDO2: Web Authentication']
      });
    }

    // P2-7: Session Token Detection
    if (parsedBody.session_token || parsedBody.sessionToken) {
      findings.push({
        type: 'SESSION_TOKEN_IN_RESPONSE',
        severity: 'INFO',
        confidence: 'MEDIUM',
        message: 'Session token detected in response body',
        evidence: {
          url,
          note: 'Verify session token is also set as HttpOnly cookie for CSRF protection'
        }
      });
    }

    // Add findings to evidence
    if (findings.length > 0) {
      if (!existingEvidence.metadata) {
        existingEvidence.metadata = {};
      }
      if (!existingEvidence.metadata.responseBodyFindings) {
        existingEvidence.metadata.responseBodyFindings = [];
      }
      existingEvidence.metadata.responseBodyFindings.push(...findings);

      // CRITICAL FIX: Update the correct Map
      requestsMap.set(requestId, existingEvidence);

      console.debug(`[Evidence] Found ${findings.length} security findings in response body for ${url}`);
    }
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

    // PHASE 1: Capture POST body for OAuth2/OIDC token requests with redaction
    if (requestDetails.method === 'POST' && requestDetails.requestBody) {
      try {
        const bodyEvidence = this.bodyCapturer.captureRequestBody(requestDetails);
        evidence.bodyEvidence = bodyEvidence;

        // Add any vulnerabilities found during body analysis
        if (bodyEvidence.security?.vulnerabilities?.length > 0) {
          evidence.vulnerabilities = bodyEvidence.security.vulnerabilities;
        }
      } catch (error) {
        console.warn('Hera: Failed to capture request body:', error);
      }
    }

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
   * PHASE 6 ENHANCEMENT: Now includes preload list checking with fact-based reporting
   * @param {Array} headers - Response headers
   * @param {string} url - Request URL to verify HTTPS usage
   * @returns {Promise<Object>} HSTS analysis with preload check
   */
  async checkHSTSHeader(headers, url = null) {
    if (!headers) return { present: false, reason: 'no_headers' };

    // CRITICAL: HSTS is meaningless on HTTP connections
    let isHTTPS = true;
    let domain = null;
    if (url) {
      try {
        const urlObj = new URL(url);
        isHTTPS = urlObj.protocol === 'https:';
        domain = urlObj.hostname;
      } catch (e) {
        // Invalid URL, assume HTTP for safety
        isHTTPS = false;
      }
    }

    const hstsHeader = headers.find(h =>
      h.name.toLowerCase() === 'strict-transport-security'
    );

    // ADVERSARIAL DECISION: Do NOT check preload list
    // Per CLAUDE.md ADVERSARIAL_PUSHBACK.md:
    // - Preload list status varies by browser and version
    // - Cannot verify what THIS USER'S BROWSER knows
    // - Adds complexity without certainty
    // - Report facts we can verify, not guesses
    //
    // What Hera does instead: Report header presence/absence with verification URL

    if (!hstsHeader) {
      return {
        present: false,
        reason: 'header_missing',
        isHTTPS: isHTTPS,
        warning: !isHTTPS ? 'Connection not using HTTPS - HSTS not applicable' : null,
        evidence: headers.map(h => ({ name: h.name, value: h.value })),
        // FACT-BASED recommendation (not speculation)
        recommendation: domain ?
          `Add HSTS header. Check preload status: https://hstspreload.org/?domain=${domain}` :
          'Add HSTS header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
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
      evidence: { name: hstsHeader.name, value: hstsHeader.value, protocol: 'HTTPS' },
      // Manual preload check URL (not automated to avoid CSP issues)
      manualPreloadCheckUrl: domain ? `https://hstspreload.org/?domain=${domain}` : null
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