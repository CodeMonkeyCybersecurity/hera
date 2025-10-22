/**
 * HSTS Preload List Checker
 *
 * Checks if domains are on the HSTS preload list with fact-based reporting.
 * Addresses concerns from ADVERSARIAL_PUSHBACK.md about preload checking:
 * - Does NOT claim definitive browser protection status
 * - Provides CHECK recommendation instead of false certainty
 * - Reports facts that can be verified
 * - Separates technical finding from exploitability assessment
 *
 * Design Principles:
 * 1. Report what we CAN verify (domain on preload list at time of check)
 * 2. Do NOT claim what we CANNOT verify (user's browser version, list freshness)
 * 3. Cache results to minimize API calls
 * 4. Provide actionable recommendations
 * 5. Be honest about limitations
 *
 * Reference: ADVERSARIAL_PUSHBACK.md Part 2
 */

export class HSTSPreloadChecker {
  constructor() {
    this.name = 'HSTSPreloadChecker';
    this.cache = new Map(); // domain -> {onList, checkedAt, source}
    this.CACHE_TTL = 7 * 24 * 60 * 60 * 1000; // 7 days
    this.checkInProgress = new Map(); // Prevent duplicate checks

    // Load cache from storage
    this.loadCache();
  }

  /**
   * Check if domain is on HSTS preload list
   * @param {string} domain - Domain to check (e.g., "example.com")
   * @returns {Promise<Object>} Check result with fact-based reporting
   */
  async checkDomain(domain) {
    // Normalize domain
    const normalizedDomain = this._normalizeDomain(domain);

    // Check cache first
    const cached = this.cache.get(normalizedDomain);
    if (cached && (Date.now() - cached.checkedAt) < this.CACHE_TTL) {
      return {
        domain: normalizedDomain,
        onPreloadList: cached.onList,
        source: 'cache',
        checkedAt: cached.checkedAt,
        cacheAge: Math.floor((Date.now() - cached.checkedAt) / 1000 / 60 / 60), // hours
        note: 'Result from cache - may be stale'
      };
    }

    // Check if already in progress
    if (this.checkInProgress.has(normalizedDomain)) {
      return this.checkInProgress.get(normalizedDomain);
    }

    // Perform check
    const checkPromise = this._performCheck(normalizedDomain);
    this.checkInProgress.set(normalizedDomain, checkPromise);

    try {
      const result = await checkPromise;
      this.checkInProgress.delete(normalizedDomain);
      return result;
    } catch (error) {
      this.checkInProgress.delete(normalizedDomain);
      throw error;
    }
  }

  /**
   * Perform actual preload list check
   * @param {string} domain - Normalized domain
   * @returns {Promise<Object>} Check result
   * @private
   */
  async _performCheck(domain) {
    try {
      // Check using hstspreload.org API
      const result = await this._checkViaAPI(domain);

      // Cache result
      this.cache.set(domain, {
        onList: result.onList,
        checkedAt: Date.now(),
        source: result.source
      });

      // Persist cache
      await this.saveCache();

      return {
        domain,
        onPreloadList: result.onList,
        source: result.source,
        checkedAt: Date.now(),
        details: result.details,
        limitations: this._getLimitations()
      };

    } catch (error) {
      console.warn(`Hera: HSTS preload check failed for ${domain}:`, error);

      return {
        domain,
        onPreloadList: null,
        source: 'error',
        error: error.message,
        checkedAt: Date.now(),
        limitations: this._getLimitations()
      };
    }
  }

  /**
   * Check domain via hstspreload.org API
   * @param {string} domain - Domain to check
   * @returns {Promise<Object>} API result
   * @private
   */
  async _checkViaAPI(domain) {
    try {
      // Option 1: Use hstspreload.org API
      // NOTE: This may fail due to CSP restrictions in content script contexts
      const apiUrl = `https://hstspreload.org/api/v2/status?domain=${encodeURIComponent(domain)}`;

      // Check if we're in a context that allows external fetches
      if (typeof chrome === 'undefined' || !chrome.runtime?.id) {
        // Content script context - CSP will block external fetches
        throw new Error('Cannot fetch from content script context - CSP restrictions');
      }

      // We're in background script - fetch should work
      const response = await fetch(apiUrl, {
        method: 'GET',
        headers: {
          'Accept': 'application/json'
        }
      });

      if (!response.ok) {
        throw new Error(`API returned ${response.status}`);
      }

      const data = await response.json();

      // API returns { status: "preloaded" } if on list
      const onList = data.status === 'preloaded';

      return {
        onList,
        source: 'hstspreload.org',
        details: {
          status: data.status,
          includeSubDomains: data.include_subdomains,
          preloadable: data.preloadable
        }
      };

    } catch (apiError) {
      // Fallback: Check using Chromium transport_security_state_static.json
      // (This is a large file, so we only use as fallback)
      console.warn('Hera: hstspreload.org API failed, trying Chromium list:', apiError);
      return await this._checkViaChromiumList(domain);
    }
  }

  /**
   * Check domain via Chromium's static list (fallback)
   * @param {string} domain - Domain to check
   * @returns {Promise<Object>} Check result
   * @private
   */
  async _checkViaChromiumList(domain) {
    try {
      // Chromium HSTS preload list source
      const listUrl = 'https://chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json?format=TEXT';

      const response = await fetch(listUrl);
      if (!response.ok) {
        throw new Error(`Chromium list fetch failed: ${response.status}`);
      }

      // Response is base64 encoded
      const base64Data = await response.text();
      const jsonData = atob(base64Data);
      const listData = JSON.parse(jsonData);

      // Check if domain is in entries
      const entry = listData.entries?.find(e => e.name === domain);
      const onList = !!entry;

      return {
        onList,
        source: 'chromium_list',
        details: entry ? {
          mode: entry.mode,
          includeSubDomains: entry.include_subdomains
        } : null
      };

    } catch (error) {
      console.error('Hera: Chromium list check failed:', error);

      // Return unknown status
      return {
        onList: null,
        source: 'check_failed',
        error: error.message
      };
    }
  }

  /**
   * Generate fact-based HSTS evidence (addresses ADVERSARIAL_PUSHBACK concerns)
   * @param {string} domain - Domain being checked
   * @param {boolean} hstsHeaderPresent - Whether HSTS header is present
   * @param {string} hstsHeaderValue - HSTS header value if present
   * @param {Object} preloadCheckResult - Result from checkDomain()
   * @returns {Object} Fact-based evidence report
   */
  generateHSTSEvidence(domain, hstsHeaderPresent, hstsHeaderValue, preloadCheckResult) {
    const evidence = {
      domain,
      timestamp: Date.now(),

      // FACT: What we observed in the response
      hstsHeader: {
        present: hstsHeaderPresent,
        value: hstsHeaderValue,
        analysis: hstsHeaderPresent ? this._parseHSTSHeader(hstsHeaderValue) : null
      },

      // FACT: What we checked about preload status
      preloadList: {
        checked: !!preloadCheckResult,
        onList: preloadCheckResult?.onPreloadList,
        source: preloadCheckResult?.source,
        checkedAt: preloadCheckResult?.checkedAt,
        limitations: preloadCheckResult?.limitations
      },

      // FACT-BASED ASSESSMENT (not speculation)
      protection: {
        // What we CAN say:
        headerProvides: hstsHeaderPresent ? 'HSTS protection after first visit' : 'No HSTS protection',

        // What we CANNOT say definitively:
        browserProtection: 'UNKNOWN - depends on browser version and list freshness',

        // What users should do:
        verificationRecommendation: this._getVerificationRecommendation(domain, preloadCheckResult)
      },

      // HONEST assessment of exploitability
      exploitability: this._assessExploitability(hstsHeaderPresent, preloadCheckResult),

      // Limitations (be transparent)
      limitations: [
        'Preload list status varies by browser and version',
        'Cannot verify which list version user has',
        'Header only protects after first HTTPS visit',
        'Manual verification recommended for high-value findings'
      ]
    };

    return evidence;
  }

  /**
   * Parse HSTS header value
   * @param {string} headerValue - HSTS header value
   * @returns {Object} Parsed header
   * @private
   */
  _parseHSTSHeader(headerValue) {
    if (!headerValue) return null;

    const maxAgeMatch = headerValue.match(/max-age=(\d+)/i);
    const includeSubDomains = /includeSubDomains/i.test(headerValue);
    const preload = /preload/i.test(headerValue);

    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : null;

    return {
      maxAge,
      maxAgeDays: maxAge ? Math.floor(maxAge / 86400) : null,
      includeSubDomains,
      preload,
      meetsPreloadRequirements: maxAge >= 31536000 && includeSubDomains && preload
    };
  }

  /**
   * Get verification recommendation (fact-based)
   * @param {string} domain - Domain
   * @param {Object} preloadCheck - Preload check result
   * @returns {string} Recommendation
   * @private
   */
  _getVerificationRecommendation(domain, preloadCheck) {
    if (!preloadCheck || preloadCheck.onPreloadList === null) {
      return `Manually check: https://hstspreload.org/?domain=${domain}`;
    }

    if (preloadCheck.onPreloadList === true) {
      return `Domain IS on preload list (verified ${new Date(preloadCheck.checkedAt).toISOString()}). ` +
             `However, protection depends on user's browser version. ` +
             `Check https://hstspreload.org/?domain=${domain} for current status.`;
    }

    if (preloadCheck.onPreloadList === false) {
      return `Domain NOT on preload list (verified ${new Date(preloadCheck.checkedAt).toISOString()}). ` +
             `Consider submitting: https://hstspreload.org/?domain=${domain}`;
    }

    return `Check https://hstspreload.org/?domain=${domain}`;
  }

  /**
   * Assess exploitability honestly (addresses ADVERSARIAL_PUSHBACK severity concerns)
   * @param {boolean} hstsHeaderPresent - HSTS header present
   * @param {Object} preloadCheck - Preload check result
   * @returns {Object} Exploitability assessment
   * @private
   */
  _assessExploitability(hstsHeaderPresent, preloadCheck) {
    const requirements = {
      // Technical requirements
      hstsHeaderMissing: !hstsHeaderPresent,
      notOnPreloadList: preloadCheck?.onPreloadList === false,

      // Attack requirements
      userTypesHttpUrl: 'UNLIKELY - most users click HTTPS links',
      attackerHasMitm: 'UNCOMMON - requires network position',
      userIgnoresWarnings: 'UNCOMMON - browsers show warnings',
      oauth2AllowsHttp: 'RARE - OAuth2 typically enforces HTTPS redirect_uri'
    };

    // Determine severity based on actual exploitability
    let severity = 'INFO';
    let rationale = '';

    if (!hstsHeaderPresent && preloadCheck?.onPreloadList === false) {
      // Missing both header AND preload
      severity = 'LOW';
      rationale = 'Missing HSTS header and not preloaded. ' +
                 'However, exploitation requires: ' +
                 '(1) User types HTTP URL instead of clicking HTTPS link, ' +
                 '(2) Attacker has MitM position, ' +
                 '(3) User ignores browser warnings, ' +
                 '(4) Application accepts HTTP redirect_uri (rare in OAuth2). ' +
                 'Defense-in-depth issue rather than direct vulnerability.';
    } else if (!hstsHeaderPresent && preloadCheck?.onPreloadList === true) {
      // Missing header but IS preloaded
      severity = 'INFO';
      rationale = 'HSTS header missing BUT domain is on preload list. ' +
                 'Browser protection depends on user having updated browser. ' +
                 'Header recommended for defense-in-depth.';
    } else if (hstsHeaderPresent && preloadCheck?.onPreloadList === false) {
      // Has header but NOT preloaded
      severity = 'INFO';
      rationale = 'HSTS header present but domain not preloaded. ' +
                 'First visit vulnerable to MITM before header received. ' +
                 'Consider submitting to preload list.';
    } else {
      // Has both header AND preloaded
      severity = 'NONE';
      rationale = 'HSTS properly configured with both header and preload.';
    }

    return {
      severity,
      rationale,
      requirements,

      // HONEST bug bounty assessment
      bugBountyLikelihood: {
        acceptance: severity === 'LOW' ? 'POSSIBLE' : severity === 'INFO' ? 'UNLIKELY' : 'N/A',
        likelyPayoutRange: severity === 'LOW' ? '$500-$2000' : severity === 'INFO' ? '$0-$500' : 'N/A',
        confidence: 'LOW - depends on program policies',
        note: 'HSTS issues typically informational/best-practice findings, not direct vulnerabilities'
      }
    };
  }

  /**
   * Get limitations of preload checking (be transparent)
   * @returns {Array<string>} Limitations
   * @private
   */
  _getLimitations() {
    return [
      'Preload list is browser-specific (Chrome, Firefox, Safari have separate lists)',
      'Users may have outdated browsers with stale lists',
      'Corporate proxies may strip HSTS headers',
      'Check result is point-in-time (list updates continuously)',
      'Cannot verify actual browser protection on user device'
    ];
  }

  /**
   * Normalize domain name
   * @param {string} domain - Domain or URL
   * @returns {string} Normalized domain
   * @private
   */
  _normalizeDomain(domain) {
    try {
      // If it's a URL, extract hostname
      if (domain.includes('://')) {
        const url = new URL(domain);
        domain = url.hostname;
      }

      // Remove www. prefix
      domain = domain.replace(/^www\./i, '');

      // Lowercase
      domain = domain.toLowerCase();

      return domain;
    } catch (e) {
      return domain.toLowerCase();
    }
  }

  /**
   * Load cache from storage
   * @private
   */
  async loadCache() {
    try {
      const data = await chrome.storage.local.get('heraHstsPreloadCache');
      if (data.heraHstsPreloadCache) {
        this.cache = new Map(Object.entries(data.heraHstsPreloadCache));
        console.log(`Hera: Loaded HSTS preload cache (${this.cache.size} entries)`);
      }
    } catch (error) {
      console.warn('Hera: Could not load HSTS cache:', error);
    }
  }

  /**
   * Save cache to storage
   * @private
   */
  async saveCache() {
    try {
      // Convert Map to object for storage
      const cacheObj = Object.fromEntries(this.cache.entries());

      await chrome.storage.local.set({
        heraHstsPreloadCache: cacheObj
      });

      console.log(`Hera: Saved HSTS preload cache (${this.cache.size} entries)`);
    } catch (error) {
      console.warn('Hera: Could not save HSTS cache:', error);
    }
  }

  /**
   * Clear cache
   */
  async clearCache() {
    this.cache.clear();
    await chrome.storage.local.remove('heraHstsPreloadCache');
    console.log('Hera: Cleared HSTS preload cache');
  }

  /**
   * Get cache statistics
   * @returns {Object} Cache stats
   */
  getCacheStats() {
    const now = Date.now();
    let fresh = 0;
    let stale = 0;

    for (const entry of this.cache.values()) {
      if ((now - entry.checkedAt) < this.CACHE_TTL) {
        fresh++;
      } else {
        stale++;
      }
    }

    return {
      totalEntries: this.cache.size,
      freshEntries: fresh,
      staleEntries: stale,
      cacheTTL: this.CACHE_TTL,
      cacheTTLDays: Math.floor(this.CACHE_TTL / 1000 / 60 / 60 / 24)
    };
  }
}
