/**
 * Debugger Events - Chrome DevTools Protocol event handlers
 * Captures response bodies via Network.getResponseBody
 */

export class DebuggerEvents {
  constructor(
    heraReady,
    authRequests,
    debugTargets,
    heraAuthDetector,
    heraSecretScanner,
    storageManager,
    updateBadge
  ) {
    this.heraReady = heraReady;
    this.authRequests = authRequests;
    this.debugTargets = debugTargets;
    this.heraAuthDetector = heraAuthDetector;
    this.heraSecretScanner = heraSecretScanner;
    this.storageManager = storageManager;
    this.updateBadge = updateBadge;
  }

  /**
   * Register debugger event listener
   */
  register() {
    chrome.debugger.onEvent.addListener((source, method, params) => {
      this.handleEvent(source, method, params);
    });
  }

  /**
   * Handle debugger events
   */
  handleEvent(source, method, params) {
    if (method === "Network.responseReceived") {
      this.handleResponseReceived(params);
    } else if (method === "Network.loadingFinished") {
      this.handleLoadingFinished(source, params);
    }
  }

  /**
   * Store response metadata when received
   */
  handleResponseReceived(params) {
    const requestData = this.authRequests.get(params.requestId);
    if (requestData) {
      requestData.responseDetails = params.response;
    }
  }

  /**
   * Capture response body when loading finished
   */
  handleLoadingFinished(source, params) {
    const requestData = this.authRequests.get(params.requestId);
    if (!requestData || !requestData.responseDetails) {
      return;
    }

    // P0-TENTH-1 FIX: Validate source tabId matches request tabId
    if (source.tabId !== requestData.tabId) {
      console.error('Hera SECURITY: debugger event tabId mismatch');
      return;
    }

    // P0-TENTH-1 FIX: Validate request still exists in debugTargets
    if (!this.debugTargets.has(source.tabId)) {
      console.error('Hera SECURITY: debugger event from non-tracked tab');
      return;
    }

    // P0-TENTH-1 FIX: Validate requestId format
    if (!params.requestId || typeof params.requestId !== 'string') {
      console.error('Hera SECURITY: invalid requestId format');
      return;
    }

    const debuggee = { tabId: source.tabId };
    
    chrome.debugger.sendCommand(
      debuggee,
      "Network.getResponseBody",
      { requestId: params.requestId },
      (response) => {
        this.processResponseBody(response, requestData, params.requestId);
      }
    );
  }

  /**
   * Process captured response body
   */
  processResponseBody(response, requestData, requestId) {
    if (!chrome.runtime.lastError && response) {
      let body = response.body;
      
      // Decode base64 if needed
      if (response.base64Encoded) {
        try {
          body = atob(response.body);
        } catch (e) {
          console.warn("Hera: Failed to decode base64 response body.", e);
          body = "[Hera: Failed to decode base64 body]";
        }
      }

      // P0-TENTH-1 FIX: Sanitize response body before storage
      if (typeof body === 'string') {
        if (/<script|onerror=|onclick=|onload=|javascript:/i.test(body)) {
          console.warn('Hera SECURITY: Response contains potentially malicious content, sanitizing');
          requestData.securityFlags = requestData.securityFlags || [];
          requestData.securityFlags.push('SUSPICIOUS_CONTENT_IN_RESPONSE');
        }
      }

      requestData.responseBody = body;
      requestData.captureSource = 'debugger';

      // Ensure metadata structure exists
      if (!requestData.metadata) {
        requestData.metadata = {};
      }
      if (!requestData.metadata.authAnalysis) {
        requestData.metadata.authAnalysis = {
          issues: [],
          riskScore: 0,
          riskCategory: 'low'
        };
      }

      // Scan JavaScript for secrets
      const contentType = requestData.responseDetails?.headers['content-type'] || '';
      if (contentType.includes('javascript') || contentType.includes('application/x-javascript')) {
        const secretFindings = this.heraSecretScanner.scan(body, requestData.url);
        if (secretFindings.length > 0) {
          if (!requestData.metadata.authAnalysis.issues) {
            requestData.metadata.authAnalysis.issues = [];
          }
          requestData.metadata.authAnalysis.issues.push(...secretFindings);
        }
      }

      // Analyze response body for security issues
      const responseBodyIssues = this.heraAuthDetector.analyzeResponseBody(body);
      if (responseBodyIssues.length > 0) {
        if (!requestData.metadata.authAnalysis.issues) {
          requestData.metadata.authAnalysis.issues = [];
        }
        requestData.metadata.authAnalysis.issues.push(...responseBodyIssues);
        
        // Recalculate risk score
        requestData.metadata.authAnalysis.riskScore = 
          this.heraAuthDetector.calculateRiskScore(requestData.metadata.authAnalysis.issues);
        requestData.metadata.authAnalysis.riskCategory = 
          this.heraAuthDetector.getRiskCategory(requestData.metadata.authAnalysis.riskScore);
      }
    }

    // Save complete request
    this.saveRequest(requestData, requestId);
  }

  /**
   * Save request to storage
   */
  saveRequest(requestData, requestId) {
    chrome.storage.local.get({ heraSessions: [] }, (result) => {
      let sessions = result.heraSessions;

      // DOS prevention: Limit total sessions
      const MAX_SESSIONS = 1000;
      if (sessions.length >= MAX_SESSIONS) {
        console.warn(`Session limit reached (${MAX_SESSIONS}), removing oldest`);
        sessions.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        sessions = sessions.slice(0, MAX_SESSIONS - 1);
      }

      // DOS prevention: Limit individual request size
      const MAX_REQUEST_SIZE = 100 * 1024; // 100KB
      const requestSize = JSON.stringify(requestData).length;
      if (requestSize > MAX_REQUEST_SIZE) {
        console.warn(`Request too large (${requestSize} bytes), truncating response body`);
        if (requestData.responseBody) {
          requestData.responseBody = requestData.responseBody.substring(0, 10000) + '... [truncated]';
        }
      }

      sessions.push(requestData);
      chrome.storage.local.set({ heraSessions: sessions }, () => {
        this.updateBadge();
        this.authRequests.delete(requestId);
      });
    });
  }
}
