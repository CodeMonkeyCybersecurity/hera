/**
 * Debug Mode Manager - Forensic-grade capture for auth flow debugging
 *
 * When enabled for a domain:
 * - Captures full HTTP request/response lifecycle
 * - Records all redirects with timing
 * - Logs console messages from the page
 * - Captures cookies (Set-Cookie + Cookie headers)
 * - Records TLS/certificate info
 * - Exports to HAR format (HTTP Archive)
 *
 * Use case: Debugging complex OAuth/OIDC flows like Authentik + BionicGPT
 */

export class DebugModeManager {
  constructor() {
    this.debugSessions = new Map(); // domain → session data
    this.activeDebuggees = new Map(); // tabId → debugger attached
    this.consoleListeners = new Map(); // tabId → listener
  }

  /**
   * Check if debug mode is enabled for a domain
   */
  async isEnabled(domain) {
    const result = await chrome.storage.local.get(['debugModeEnabled']);
    const enabledDomains = result.debugModeEnabled || [];
    return enabledDomains.includes(domain);
  }

  /**
   * Enable debug mode for a domain
   */
  async enable(domain, tabId = null) {
    console.log(`[DebugMode] Enabling for domain: ${domain}`);

    // Store enabled state
    const result = await chrome.storage.local.get(['debugModeEnabled']);
    const enabledDomains = result.debugModeEnabled || [];
    if (!enabledDomains.includes(domain)) {
      enabledDomains.push(domain);
      await chrome.storage.local.set({ debugModeEnabled: enabledDomains });
    }

    // Initialize session for this domain
    this.debugSessions.set(domain, {
      domain,
      startTime: Date.now(),
      requests: [],
      consoleLogs: [],
      redirectChain: [],
      cookies: [],
      timing: {}
    });

    // If tabId provided, attach debugger for console capture
    if (tabId !== null && tabId >= 0) {
      await this.attachDebugger(tabId, domain);
    }

    return true;
  }

  /**
   * Disable debug mode for a domain
   */
  async disable(domain) {
    console.log(`[DebugMode] Disabling for domain: ${domain}`);

    // Remove from enabled domains
    const result = await chrome.storage.local.get(['debugModeEnabled']);
    const enabledDomains = result.debugModeEnabled || [];
    const filtered = enabledDomains.filter(d => d !== domain);
    await chrome.storage.local.set({ debugModeEnabled: filtered });

    // Detach debugger from any tabs with this domain
    for (const [tabId, debugInfo] of this.activeDebuggees.entries()) {
      if (debugInfo.domain === domain) {
        await this.detachDebugger(tabId);
      }
    }

    return true;
  }

  /**
   * Attach Chrome debugger to a tab for console log capture
   */
  async attachDebugger(tabId, domain) {
    if (this.activeDebuggees.has(tabId)) {
      console.debug(`[DebugMode] Debugger already attached to tab ${tabId}`);
      return;
    }

    try {
      // Attach debugger
      await chrome.debugger.attach({ tabId }, '1.3');
      console.log(`[DebugMode] Debugger attached to tab ${tabId} for ${domain}`);

      this.activeDebuggees.set(tabId, { domain, tabId });

      // Enable Console and Network domains
      await chrome.debugger.sendCommand({ tabId }, 'Console.enable');
      await chrome.debugger.sendCommand({ tabId }, 'Network.enable');

      // Listen for console messages
      const listener = (debuggeeId, method, params) => {
        if (debuggeeId.tabId !== tabId) return;

        if (method === 'Console.messageAdded') {
          this.handleConsoleMessage(domain, params.message);
        } else if (method === 'Network.requestWillBeSent') {
          this.handleNetworkRequest(domain, params);
        } else if (method === 'Network.responseReceived') {
          this.handleNetworkResponse(domain, params);
        }
      };

      chrome.debugger.onEvent.addListener(listener);
      this.consoleListeners.set(tabId, listener);

      // Handle debugger detachment
      chrome.debugger.onDetach.addListener((debuggeeId, reason) => {
        if (debuggeeId.tabId === tabId) {
          console.log(`[DebugMode] Debugger detached from tab ${tabId}: ${reason}`);
          this.cleanup(tabId);
        }
      });

    } catch (error) {
      // Debugger attachment can fail if DevTools already open
      if (error.message.includes('Another debugger')) {
        console.debug(`[DebugMode] Cannot attach debugger - DevTools already open for tab ${tabId}`);
      } else {
        console.warn(`[DebugMode] Failed to attach debugger to tab ${tabId}:`, error.message);
      }
    }
  }

  /**
   * Detach debugger from a tab
   */
  async detachDebugger(tabId) {
    if (!this.activeDebuggees.has(tabId)) {
      return;
    }

    try {
      await chrome.debugger.detach({ tabId });
      console.log(`[DebugMode] Debugger detached from tab ${tabId}`);
    } catch (error) {
      console.debug(`[DebugMode] Error detaching debugger from tab ${tabId}:`, error.message);
    }

    this.cleanup(tabId);
  }

  /**
   * Clean up listeners and maps
   */
  cleanup(tabId) {
    const listener = this.consoleListeners.get(tabId);
    if (listener) {
      chrome.debugger.onEvent.removeListener(listener);
      this.consoleListeners.delete(tabId);
    }
    this.activeDebuggees.delete(tabId);
  }

  /**
   * Handle console message from page
   */
  handleConsoleMessage(domain, message) {
    const session = this.debugSessions.get(domain);
    if (!session) return;

    session.consoleLogs.push({
      timestamp: Date.now(),
      level: message.level,
      text: message.text,
      url: message.url,
      line: message.line,
      column: message.column
    });
  }

  /**
   * Handle network request (via debugger protocol)
   */
  handleNetworkRequest(domain, params) {
    const session = this.debugSessions.get(domain);
    if (!session) return;

    const request = params.request;
    session.requests.push({
      requestId: params.requestId,
      timestamp: params.timestamp,
      url: request.url,
      method: request.method,
      headers: request.headers,
      postData: request.postData,
      type: params.type,
      initiator: params.initiator
    });
  }

  /**
   * Handle network response (via debugger protocol)
   */
  handleNetworkResponse(domain, params) {
    const session = this.debugSessions.get(domain);
    if (!session) return;

    const response = params.response;

    // Find matching request
    const request = session.requests.find(r => r.requestId === params.requestId);
    if (request) {
      request.response = {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
        mimeType: response.mimeType,
        timing: response.timing,
        securityDetails: response.securityDetails
      };
    }
  }

  /**
   * Record enhanced request data (called from WebRequestListeners)
   */
  recordRequest(domain, requestData) {
    const session = this.debugSessions.get(domain);
    if (!session) return;

    // Merge with existing request or create new entry
    const existing = session.requests.find(r => r.url === requestData.url);
    if (existing) {
      Object.assign(existing, requestData);
    } else {
      session.requests.push({
        ...requestData,
        capturedAt: Date.now()
      });
    }
  }

  /**
   * Record redirect chain
   */
  recordRedirect(domain, redirectData) {
    const session = this.debugSessions.get(domain);
    if (!session) return;

    session.redirectChain.push({
      timestamp: Date.now(),
      from: redirectData.from,
      to: redirectData.to,
      statusCode: redirectData.statusCode,
      headers: redirectData.headers
    });
  }

  /**
   * Get session data for a domain
   */
  getSession(domain) {
    return this.debugSessions.get(domain);
  }

  /**
   * Export session as HAR (HTTP Archive) format
   * https://w3c.github.io/web-performance/specs/HAR/Overview.html
   */
  exportHAR(domain) {
    const session = this.debugSessions.get(domain);
    if (!session) {
      throw new Error(`No debug session found for domain: ${domain}`);
    }

    const har = {
      log: {
        version: '1.2',
        creator: {
          name: 'Hera Auth Security Monitor',
          version: '0.1.0',
          comment: 'Forensic debug mode capture'
        },
        pages: [{
          startedDateTime: new Date(session.startTime).toISOString(),
          id: `page_${domain}`,
          title: `Debug Session: ${domain}`,
          pageTimings: session.timing
        }],
        entries: session.requests.map(req => this.convertToHAREntry(req, domain))
      }
    };

    return har;
  }

  /**
   * Convert request to HAR entry format
   */
  convertToHAREntry(request, domain) {
    const entry = {
      startedDateTime: new Date(request.timestamp || request.capturedAt).toISOString(),
      time: 0, // Will be calculated if we have response timing
      request: {
        method: request.method || 'GET',
        url: request.url,
        httpVersion: 'HTTP/1.1',
        headers: this.convertHeaders(request.headers || request.requestHeaders),
        queryString: this.parseQueryString(request.url),
        cookies: this.extractCookies(request.headers || request.requestHeaders),
        headersSize: -1,
        bodySize: request.postData ? request.postData.length : 0
      },
      response: {
        status: request.response?.status || request.statusCode || 0,
        statusText: request.response?.statusText || '',
        httpVersion: 'HTTP/1.1',
        headers: this.convertHeaders(request.response?.headers || request.responseHeaders),
        cookies: this.extractCookies(request.response?.headers || request.responseHeaders, true),
        content: {
          size: 0,
          mimeType: request.response?.mimeType || 'text/html'
        },
        redirectURL: '',
        headersSize: -1,
        bodySize: -1
      },
      cache: {},
      timings: request.response?.timing || {
        blocked: -1,
        dns: -1,
        connect: -1,
        send: -1,
        wait: -1,
        receive: -1,
        ssl: -1
      },
      serverIPAddress: '',
      connection: '',
      comment: `Captured by Hera Debug Mode for ${domain}`
    };

    // Add POST data if present
    if (request.postData) {
      entry.request.postData = {
        mimeType: 'application/x-www-form-urlencoded',
        text: request.postData,
        params: this.parsePostData(request.postData)
      };
    }

    // Add security details if present
    if (request.response?.securityDetails) {
      entry._securityDetails = request.response.securityDetails;
    }

    return entry;
  }

  /**
   * Convert headers to HAR format
   */
  convertHeaders(headers) {
    if (!headers) return [];

    // Handle both object and array formats
    if (Array.isArray(headers)) {
      return headers.map(h => ({ name: h.name, value: h.value }));
    } else if (typeof headers === 'object') {
      return Object.entries(headers).map(([name, value]) => ({ name, value }));
    }

    return [];
  }

  /**
   * Parse query string from URL
   */
  parseQueryString(url) {
    try {
      const urlObj = new URL(url);
      const params = [];
      for (const [name, value] of urlObj.searchParams.entries()) {
        params.push({ name, value });
      }
      return params;
    } catch {
      return [];
    }
  }

  /**
   * Extract cookies from headers
   */
  extractCookies(headers, isSetCookie = false) {
    if (!headers) return [];

    const cookieHeader = isSetCookie ? 'set-cookie' : 'cookie';
    const headerValue = Array.isArray(headers)
      ? headers.find(h => h.name.toLowerCase() === cookieHeader)?.value
      : headers[cookieHeader];

    if (!headerValue) return [];

    // Parse cookie string
    const cookies = [];
    const parts = headerValue.split(isSetCookie ? ';' : ',');

    for (const part of parts) {
      const [name, value] = part.trim().split('=');
      if (name && value) {
        cookies.push({
          name: name.trim(),
          value: value.trim()
        });
      }
    }

    return cookies;
  }

  /**
   * Parse POST data into parameters
   */
  parsePostData(postData) {
    if (!postData) return [];

    try {
      // Try URL-encoded format
      const params = new URLSearchParams(postData);
      return Array.from(params.entries()).map(([name, value]) => ({ name, value }));
    } catch {
      // Return raw text if parsing fails
      return [{ name: 'data', value: postData }];
    }
  }

  /**
   * Export session with enhanced format (includes console logs + HAR)
   */
  exportEnhanced(domain) {
    const session = this.debugSessions.get(domain);
    if (!session) {
      throw new Error(`No debug session found for domain: ${domain}`);
    }

    return {
      metadata: {
        domain,
        startTime: new Date(session.startTime).toISOString(),
        duration: Date.now() - session.startTime,
        capturedBy: 'Hera Debug Mode',
        version: '0.1.0'
      },
      har: this.exportHAR(domain),
      consoleLogs: session.consoleLogs,
      redirectChain: session.redirectChain,
      summary: {
        totalRequests: session.requests.length,
        totalRedirects: session.redirectChain.length,
        totalConsoleLogs: session.consoleLogs.length
      }
    };
  }

  /**
   * Clear session data for a domain
   */
  clearSession(domain) {
    this.debugSessions.delete(domain);
    console.log(`[DebugMode] Cleared session for ${domain}`);
  }

  /**
   * Clear all sessions
   */
  clearAllSessions() {
    this.debugSessions.clear();
    console.log(`[DebugMode] Cleared all debug sessions`);
  }
}
