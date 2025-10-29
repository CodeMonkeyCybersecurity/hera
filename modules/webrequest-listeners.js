/**
 * WebRequest Listeners - Chrome webRequest API event handlers
 * Captures HTTP requests/responses for auth flow analysis
 */

import { analyzeRequestHeaders, analyzeResponseHeaders } from './header-utils.js';

export class WebRequestListeners {
  constructor(
    heraReady,
    authRequests,
    heraAuthDetector,
    heraPortAuthAnalyzer,
    evidenceCollector,
    storageManager,
    sessionTracker,
    decodeRequestBody,
    jwtValidator = null,
    sessionSecurityAnalyzer = null,
    scimAnalyzer = null,
    responseBodyCapturer = null,
    refreshTokenTracker = null,
    debugModeManager = null
  ) {
    this.heraReady = heraReady;
    this.authRequests = authRequests;
    this.heraAuthDetector = heraAuthDetector;
    this.heraPortAuthAnalyzer = heraPortAuthAnalyzer;
    this.evidenceCollector = evidenceCollector;
    this.storageManager = storageManager;
    this.sessionTracker = sessionTracker;
    this.decodeRequestBody = decodeRequestBody;
    this.jwtValidator = jwtValidator;
    this.sessionSecurityAnalyzer = sessionSecurityAnalyzer;
    this.scimAnalyzer = scimAnalyzer;
    this.responseBodyCapturer = responseBodyCapturer;
    this.refreshTokenTracker = refreshTokenTracker;
    this.debugModeManager = debugModeManager;
  }

  /**
   * Initialize all webRequest listeners
   */
  async initialize() {
    const hasPermission = await chrome.permissions.contains({
      permissions: ['webRequest'],
      origins: ['https://*/*', 'http://localhost/*']
    });

    if (!hasPermission) {
      console.warn('Hera: webRequest permission not granted - request monitoring disabled');
      console.warn('Hera: Grant permission in extension settings to enable full functionality');
      return false;
    }

    console.log('Hera: webRequest permissions granted, initializing listeners...');

    // Register all listeners
    this.registerBeforeRequest();
    this.registerBeforeSendHeaders();
    this.registerHeadersReceived();
    this.registerBeforeRedirect();
    this.registerCompleted();
    this.registerErrorOccurred();

    return true;
  }

  /**
   * 1. onBeforeRequest - Capture request initiation
   */
  registerBeforeRequest() {
    chrome.webRequest.onBeforeRequest.addListener(
      (details) => {
        // CRITICAL FIX P0: Wait for initialization before processing
        if (!this.heraReady()) {
          return; // Silent skip during initialization
        }

        try {
          const isAuthRelated = this.heraAuthDetector.isAuthRequest(details.url, {});
          if (isAuthRelated) {
            // SECURITY FIX P2: Generate nonce for request/response matching
            const requestNonce = crypto.randomUUID();

            const domain = new URL(details.url).hostname;
            console.debug(`[Auth] Detected auth request: ${details.method} ${domain}${new URL(details.url).pathname}`);

            this.authRequests.set(details.requestId, {
              id: details.requestId,
              url: details.url,
              method: details.method,
              type: details.type,
              tabId: details.tabId,
              timestamp: new Date().toISOString(),
              requestBody: this.decodeRequestBody(details.requestBody),
              nonce: requestNonce,
              requestHeaders: [],
              responseHeaders: [],
              statusCode: null,
              responseBody: null,
              metadata: {},
            });

            // P0-A: Notify response body capturer to attach debugger to this tab
            // CRITICAL FIX: Add error handling for async operation
            if (this.responseBodyCapturer && details.tabId >= 0) {
              this.responseBodyCapturer.handleAuthRequest(details.tabId, details.requestId)
                .catch(error => {
                  console.debug('[Auth] Response body capturer attachment failed:', error.message);
                  // Don't block request processing - response body capture is optional
                });
            }

            // DEBUG MODE: Record enhanced request data
            if (this.debugModeManager) {
              this.debugModeManager.isEnabled(domain).then(enabled => {
                if (enabled) {
                  this.debugModeManager.recordRequest(domain, {
                    requestId: details.requestId,
                    timestamp: Date.now(),
                    url: details.url,
                    method: details.method,
                    type: details.type,
                    tabId: details.tabId,
                    requestBody: this.decodeRequestBody(details.requestBody)
                  });
                }
              });
            }
          }
        } catch (error) {
          console.error('[Auth] Error in onBeforeRequest:', error);
        }
      },
      { urls: ["<all_urls>"] },
      ["requestBody"]
    );
  }

  /**
   * 2. onBeforeSendHeaders - Capture request headers and analyze
   */
  registerBeforeSendHeaders() {
    chrome.webRequest.onBeforeSendHeaders.addListener(
      (details) => {
        if (!this.heraReady()) return;
        
        const requestData = this.authRequests.get(details.requestId);
        if (requestData) {
          requestData.requestHeaders = details.requestHeaders;
          
          // Perform analysis now that we have headers
          const authAnalysis = this.heraAuthDetector.analyze(
            details.url,
            details.method,
            details.requestHeaders,
            requestData.requestBody
          );
          
          requestData.authType = authAnalysis.protocol;
          
          // Ensure metadata exists
          if (!requestData.metadata) {
            requestData.metadata = {};
          }
          
          requestData.metadata.authAnalysis = authAnalysis;
          requestData.metadata.authAnalysis.riskCategory = 
            this.heraAuthDetector.getRiskCategory(authAnalysis.riskScore);

          // Update port analysis with headers
          requestData.metadata.authTypeAnalysis = this.heraPortAuthAnalyzer.detectAuthType({
            url: details.url,
            method: details.method,
            requestHeaders: details.requestHeaders,
            requestBody: requestData.requestBody
          });

          // Check for default credentials
          requestData.metadata.credentialAnalysis = this.heraPortAuthAnalyzer.checkDefaultCredentials({
            url: details.url,
            requestHeaders: details.requestHeaders,
            requestBody: requestData.requestBody
          });
        }
      },
      { urls: ["<all_urls>"] },
      ["requestHeaders"]
    );
  }

  /**
   * 3. onHeadersReceived - Capture response headers
   */
  registerHeadersReceived() {
    chrome.webRequest.onHeadersReceived.addListener(
      (details) => {
        if (!this.heraReady()) return;
        
        // Capture response evidence using EvidenceCollector
        const responseEvidence = this.evidenceCollector.captureResponse(
          details.requestId,
          details.responseHeaders,
          null, // Response body will be captured separately
          details.statusCode,
          { url: details.url, method: details.method }
        );

        const requestData = this.authRequests.get(details.requestId);
        if (requestData) {
          requestData.responseHeaders = details.responseHeaders;
          requestData.statusCode = details.statusCode;

          // Add evidence-based analysis to metadata
          if (!requestData.metadata) requestData.metadata = {};
          requestData.metadata.evidencePackage = responseEvidence;

          // Analyze response headers for security info
          if (details.responseHeaders) {
            const responseAnalysis = analyzeResponseHeaders(details.responseHeaders);
            requestData.metadata.responseAnalysis = responseAnalysis;
          }

          this.authRequests.set(details.requestId, requestData);

          // DEBUG MODE: Record response data
          if (this.debugModeManager) {
            try {
              const domain = new URL(details.url).hostname;
              this.debugModeManager.isEnabled(domain).then(enabled => {
                if (enabled) {
                  this.debugModeManager.recordRequest(domain, {
                    requestId: details.requestId,
                    statusCode: details.statusCode,
                    responseHeaders: details.responseHeaders
                  });
                }
              });
            } catch (error) {
              // Ignore URL parsing errors
            }
          }
        }
      },
      { urls: ["<all_urls>"] },
      ["responseHeaders", "extraHeaders"]
    );
  }

  /**
   * 4. onBeforeRedirect - Track redirect chains
   */
  registerBeforeRedirect() {
    chrome.webRequest.onBeforeRedirect.addListener(
      (details) => {
        if (!this.heraReady()) return;
        
        const requestData = this.authRequests.get(details.requestId);
        if (requestData) {
          // Ensure metadata structure exists
          if (!requestData.metadata) {
            requestData.metadata = {};
          }
          if (!requestData.metadata.networkChain) {
            requestData.metadata.networkChain = {
              primaryIP: null,
              redirectChain: [],
              dnsChain: null,
              certificateChain: null
            };
          }
          if (!requestData.metadata.networkChain.redirectChain) {
            requestData.metadata.networkChain.redirectChain = [];
          }

          // Track redirect chain with IPs
          requestData.metadata.networkChain.redirectChain.push({
            fromUrl: details.url,
            toUrl: details.redirectUrl,
            ip: details.ip,
            statusCode: details.statusCode,
            timestamp: Date.now()
          });

          this.authRequests.set(details.requestId, requestData);

          // DEBUG MODE: Record redirect
          if (this.debugModeManager) {
            try {
              const domain = new URL(details.url).hostname;
              this.debugModeManager.isEnabled(domain).then(enabled => {
                if (enabled) {
                  this.debugModeManager.recordRedirect(domain, {
                    from: details.url,
                    to: details.redirectUrl,
                    statusCode: details.statusCode,
                    headers: details.responseHeaders
                  });
                }
              });
            } catch (error) {
              // Ignore URL parsing errors
            }
          }
        }
      },
      { urls: ["<all_urls>"] }
    );
  }

  /**
   * 5. onCompleted - Finalize request with session tracking
   * CRITICAL FIX: Handler is now async to properly await async operations
   */
  registerCompleted() {
    chrome.webRequest.onCompleted.addListener(
      async (details) => {  // ← Already async
        if (!this.heraReady()) return;
        
        const requestData = this.authRequests.get(details.requestId);
        if (requestData) {
          requestData.statusCode = details.statusCode;
          requestData.responseHeaders = details.responseHeaders;
          
          // Complete timing data
          if (!requestData.metadata) {
            requestData.metadata = {};
          }
          if (!requestData.metadata.timing) {
            requestData.metadata.timing = {
              startTime: Date.now(),
              endTime: null
            };
          }
          requestData.metadata.timing.endTime = Date.now();
          requestData.metadata.timing.duration = 
            requestData.metadata.timing.endTime - requestData.metadata.timing.startTime;
          
          // Analyze response headers
          const responseAnalysis = analyzeResponseHeaders(details.responseHeaders);
          requestData.metadata.responseAnalysis = responseAnalysis;

          // NEW: JWT validation (check headers and body for JWTs)
          if (this.jwtValidator) {
            const jwtFindings = this.jwtValidator.analyzeRequest(requestData, details.url);
            if (jwtFindings.length > 0) {
              if (!requestData.metadata.securityFindings) {
                requestData.metadata.securityFindings = [];
              }
              requestData.metadata.securityFindings.push(...jwtFindings);
            }
          }

          // NEW: Session security analysis
          if (this.sessionSecurityAnalyzer) {
            const sessionFindings = this.sessionSecurityAnalyzer.analyzeRequest(
              requestData,
              details.url,
              details.responseHeaders
            );
            if (sessionFindings.length > 0) {
              if (!requestData.metadata.securityFindings) {
                requestData.metadata.securityFindings = [];
              }
              requestData.metadata.securityFindings.push(...sessionFindings);
            }
          }

          // NEW: SCIM protocol analysis
          if (this.scimAnalyzer && this.scimAnalyzer.isSCIMEndpoint(details.url)) {
            const scimFindings = this.scimAnalyzer.analyzeSCIMRequest(requestData, details.url);
            if (scimFindings.length > 0) {
              if (!requestData.metadata.securityFindings) {
                requestData.metadata.securityFindings = [];
              }
              requestData.metadata.securityFindings.push(...scimFindings);
            }
          }

          // P0-B: Refresh token rotation tracking
          // CRITICAL FIX: Tracking now happens in ResponseBodyCapturer BEFORE redaction
          // No need to track here - findings are already in requestData.metadata.securityFindings

          // Get tab information for browser context
          if (details.tabId >= 0) {
            chrome.tabs.get(details.tabId, (tab) => {
              if (tab) {
                requestData.metadata.browserContext = {
                  tabUrl: tab.url,
                  tabTitle: tab.title,
                  isIncognito: tab.incognito,
                  userAgent: null
                };
                this.authRequests.set(details.requestId, requestData);
              }
            });
          }
          
          this.authRequests.set(details.requestId, requestData);
          
          // P0-SEVENTEENTH-2: Backend scanning disabled (CSP violations)
          const hostname = new URL(details.url).hostname;
          requestData.metadata.backendSecurity = {
            domain: hostname,
            exposed: [],
            riskScore: 0,
            shouldBlockDataEntry: false,
            scanDisabled: true,
            reason: 'CSP restrictions prevent background script from scanning arbitrary domains'
          };
          
          // Get or create session for this domain with context
          const requestContext = {
            tabId: details.tabId,
            initiator: details.initiator,
            timestamp: Date.now(),
            authHeaders: details.requestHeaders?.filter(h => 
              h.name.toLowerCase().includes('auth') || 
              h.name.toLowerCase() === 'authorization'
            )
          };
          
          // Determine service for this hostname
          const service = this.sessionTracker.identifyService(hostname);
          const sessionInfo = this.sessionTracker.getOrCreateSession(hostname, service, requestContext);
          
          // Add session information to request data
          requestData.sessionInfo = {
            sessionId: sessionInfo.id,
            service: sessionInfo.service,
            domain: sessionInfo.primaryDomain,
            eventNumber: sessionInfo.eventCount,
            ecosystem: sessionInfo.ecosystem,
            correlationFactors: sessionInfo.correlationFactors
          };
          
          // Store in persistent storage - strip large fields to prevent quota errors
          const lightRequestData = {
            id: requestData.id,
            url: requestData.url,
            method: requestData.method,
            statusCode: requestData.statusCode,
            timestamp: requestData.timestamp,
            authType: requestData.authType,
            sessionId: sessionInfo.id,
            service: sessionInfo.service,
            riskScore: this.calculateOverallRiskScore(requestData),
            // Keep only critical metadata
            metadata: {
              securityFindings: requestData.metadata?.securityFindings || [],
              authAnalysis: requestData.metadata?.authAnalysis ? {
                protocol: requestData.metadata.authAnalysis.protocol,
                riskScore: requestData.metadata.authAnalysis.riskScore,
                issues: requestData.metadata.authAnalysis.issues
              } : null
            }
          };

          try {
            await this.storageManager.storeAuthEvent(lightRequestData);
            await this.storageManager.updateBadge();
          } catch (err) {
            console.warn('Storage error (quota exceeded):', err.message);
          }
        }
      },
      { urls: ["<all_urls>"] }
    );
  }

  /**
   * 6. onErrorOccurred - Handle network errors
   */
  registerErrorOccurred() {
    chrome.webRequest.onErrorOccurred.addListener(
      (details) => {
        if (!this.heraReady()) return;
        
        const requestData = this.authRequests.get(details.requestId);
        if (requestData) {
          requestData.error = details.error;
          
          // Ensure metadata structure exists
          if (!requestData.metadata) {
            requestData.metadata = {};
          }
          if (!requestData.metadata.timing) {
            requestData.metadata.timing = {
              startTime: Date.now(),
              endTime: null
            };
          }
          requestData.metadata.timing.endTime = Date.now();
          requestData.metadata.timing.duration = 
            requestData.metadata.timing.endTime - requestData.metadata.timing.startTime;
          
          // Analyze the error for authentication context
          const errorAnalysis = this.analyzeAuthError(details.error, requestData.url);
          requestData.metadata.errorAnalysis = errorAnalysis;
          
          this.authRequests.set(details.requestId, requestData);
          this.storageManager.updateBadge();
        }
      },
      { urls: ["<all_urls>"] }
    );
  }

  /**
   * Analyze network errors for authentication context
   */
  analyzeAuthError(error, url) {
    const analysis = {
      errorType: error,
      isNetworkFailure: true,
      possibleCauses: [],
      securityImplications: []
    };
    
    switch (error) {
      case 'net::ERR_CONNECTION_REFUSED':
        analysis.possibleCauses.push('Authentication server is down or unreachable');
        analysis.securityImplications.push('Service availability issue');
        break;
      case 'net::ERR_CONNECTION_TIMED_OUT':
        analysis.possibleCauses.push('Authentication server timeout');
        analysis.possibleCauses.push('Network connectivity issues');
        break;
      case 'net::ERR_NAME_NOT_RESOLVED':
        analysis.possibleCauses.push('DNS resolution failed for authentication domain');
        analysis.securityImplications.push('Possible DNS hijacking or domain issues');
        break;
      case 'net::ERR_CERT_AUTHORITY_INVALID':
      case 'net::ERR_CERT_COMMON_NAME_INVALID':
      case 'net::ERR_CERT_DATE_INVALID':
        analysis.possibleCauses.push('SSL/TLS certificate validation failed');
        analysis.securityImplications.push('CRITICAL: Potential man-in-the-middle attack');
        break;
      case 'net::ERR_SSL_PROTOCOL_ERROR':
        analysis.possibleCauses.push('SSL/TLS protocol error');
        analysis.securityImplications.push('Possible SSL stripping or protocol downgrade attack');
        break;
      case 'net::ERR_BLOCKED_BY_CLIENT':
        analysis.possibleCauses.push('Request blocked by ad blocker or security extension');
        break;
      case 'net::ERR_NETWORK_ACCESS_DENIED':
        analysis.possibleCauses.push('Network access denied by firewall or proxy');
        break;
      default:
        analysis.possibleCauses.push(`Network error: ${error}`);
    }
    
    return analysis;
  }

  /**
   * Calculate overall risk score (placeholder - will be moved to risk-calculator module)
   */
  calculateOverallRiskScore(requestData) {
    // Simplified version - full implementation in risk-calculator.js
    const metadata = requestData.metadata || {};
    const authAnalysis = metadata.authAnalysis || {};
    return authAnalysis.riskScore || 0;
  }
}
