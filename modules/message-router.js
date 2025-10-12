/**
 * Message Router - Routes chrome.runtime.onMessage events
 * Handles authorization, validation, and routing to appropriate handlers
 */

import { performAlgNoneProbe, performRepeaterRequest } from './security-probes.js';

export class MessageRouter {
  constructor(
    authRequests,
    debugTargets,
    heraAuthDetector,
    storageManager,
    memoryManager,
    updateBadge,
    handleInterceptorInjection,
    generateSessionId,
    heraStore
  ) {
    this.authRequests = authRequests;
    this.debugTargets = debugTargets;
    this.heraAuthDetector = heraAuthDetector;
    this.storageManager = storageManager;
    this.memoryManager = memoryManager;
    this.updateBadge = updateBadge;
    this.handleInterceptorInjection = handleInterceptorInjection;
    this.generateSessionId = generateSessionId;
    this.heraStore = heraStore;

    // Authorization configuration
    this.allowedSenderUrls = [
      chrome.runtime.getURL('popup.html'),
      chrome.runtime.getURL('devtools/devtools.html'),
      chrome.runtime.getURL('probe-consent.html'),
      chrome.runtime.getURL('privacy-consent-ui.html')
    ];

    this.contentScriptAllowedActions = [
      'responseIntercepted',
      'getBackendScan',
      'ANALYSIS_ERROR',
      'INJECT_RESPONSE_INTERCEPTOR'
    ];

    this.highlySecurityActions = [
      'probe:alg_none',
      'repeater:send',
      'clearRequests',
      'updateResponseCaptureSetting'
    ];
  }

  /**
   * Register message listeners
   */
  register() {
    // Action-based messages
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      return this.handleActionMessage(message, sender, sendResponse);
    });

    // Type-based messages (analysis results)
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      return this.handleTypeMessage(message, sender, sendResponse);
    });

    // DevTools port connections
    chrome.runtime.onConnect.addListener((port) => {
      this.handlePortConnection(port);
    });
  }

  /**
   * Handle action-based messages
   */
  handleActionMessage(message, sender, sendResponse) {
    // Sender validation
    if (!sender.id || sender.id !== chrome.runtime.id) {
      console.warn('Message from external source rejected:', sender);
      sendResponse({ success: false, error: 'External messages not allowed' });
      return false;
    }

    // Input validation
    if (!message || typeof message !== 'object') {
      console.warn('Invalid message received:', message);
      sendResponse({ success: false, error: 'Invalid message format' });
      return false;
    }

    // P0-4 FIX: This listener handles 'action' messages ONLY
    if (!message.action) {
      return false; // Let other listener handle it
    }

    // P0-4 FIX: Reject messages with BOTH action AND type
    if (message.type) {
      console.warn('Hera: Message has both action and type - rejecting');
      sendResponse({ success: false, error: 'Invalid message format: cannot have both action and type' });
      return false;
    }

    if (typeof message.action !== 'string') {
      console.warn('Message action is not a string:', message);
      sendResponse({ success: false, error: 'Invalid action' });
      return false;
    }

    // Authorization check
    const senderUrl = sender.url || '';
    const isAuthorizedSender = this.allowedSenderUrls.some(allowed => 
      senderUrl.startsWith(allowed)
    );

    if (!isAuthorizedSender && !this.contentScriptAllowedActions.includes(message.action)) {
      console.error(`Hera SECURITY: Unauthorized message from ${senderUrl}: ${message.action}`);
      sendResponse({ success: false, error: 'Unauthorized sender' });
      return false;
    }

    if (this.highlySecurityActions.includes(message.action) && !isAuthorizedSender) {
      console.warn(`Highly sensitive action '${message.action}' blocked from unauthorized source:`, senderUrl);
      sendResponse({ success: false, error: 'Unauthorized: This action requires popup or devtools context' });
      return false;
    }

    // Route to handler
    return this.routeAction(message, sender, sendResponse);
  }

  /**
   * Route action to appropriate handler
   */
  routeAction(message, sender, sendResponse) {
    const action = message.action;

    switch (action) {
      case 'responseIntercepted':
        return this.handleResponseIntercepted(message, sendResponse);
      
      case 'probe:alg_none':
        return this.handleProbeAlgNone(message, sender, sendResponse);
      
      case 'repeater:send':
        return this.handleRepeaterSend(message, sender, sendResponse);
      
      case 'getRequests':
        return this.handleGetRequests(sendResponse);

      case 'getPortAnalysis':
        return this.handleGetPortAnalysis(sendResponse);

      case 'getExtensionsAnalysis':
        return this.handleGetExtensionsAnalysis(sendResponse);

      case 'getBackendScan':
        return this.handleGetBackendScan(message, sendResponse);
      
      case 'reportBlockedSubmission':
        return this.handleReportBlockedSubmission(message, sendResponse);
      
      case 'clearRequests':
        return this.handleClearRequests(sendResponse);
      
      case 'updateResponseCaptureSetting':
        return this.handleUpdateResponseCapture(message, sendResponse);
      
      case 'openPopup':
      case 'showTechnicalDetails':
        sendResponse({ success: true });
        return false;
      
      default:
        console.warn(`Unknown action: ${action}`);
        sendResponse({ success: false, error: 'Unknown action' });
        return false;
    }
  }

  /**
   * Handle responseIntercepted action
   */
  handleResponseIntercepted(message, sendResponse) {
    if (!message.data || typeof message.data !== 'object') {
      console.warn('responseIntercepted message missing data');
      sendResponse({ success: false, error: 'Missing data' });
      return false;
    }

    const data = message.data;
    let match = null;

    // Try nonce-based matching first
    if (data.nonce) {
      for (const [requestId, requestData] of this.authRequests.entries()) {
        if (requestData.nonce === data.nonce && !requestData.responseBody) {
          match = { requestId, requestData };
          break;
        }
      }
    }

    // Fallback to URL + timestamp matching
    if (!match) {
      let bestMatchScore = Infinity;
      for (const [requestId, requestData] of this.authRequests.entries()) {
        if (requestData.url === data.url && !requestData.responseBody) {
          const reqTime = new Date(requestData.timestamp).getTime();
          const interceptTime = new Date(data.timestamp).getTime();
          const timeDiff = Math.abs(interceptTime - reqTime);

          if (timeDiff < 30000 && timeDiff < bestMatchScore) {
            match = { requestId, requestData };
            bestMatchScore = timeDiff;
          }
        }
      }
    }

    if (match) {
      const { requestId, requestData } = match;

      requestData.responseBody = data.body;
      requestData.statusCode = data.statusCode;
      requestData.captureSource = 'interceptor';

      // Analyze response body
      if (!requestData.metadata) requestData.metadata = {};
      if (!requestData.metadata.authAnalysis) {
        requestData.metadata.authAnalysis = { issues: [], riskScore: 0, riskCategory: 'low' };
      }

      const responseBodyIssues = this.heraAuthDetector.analyzeResponseBody(data.body);
      if (responseBodyIssues.length > 0) {
        requestData.metadata.authAnalysis.issues.push(...responseBodyIssues);
        requestData.metadata.authAnalysis.riskScore = 
          this.heraAuthDetector.calculateRiskScore(requestData.metadata.authAnalysis.issues);
        requestData.metadata.authAnalysis.riskCategory = 
          this.heraAuthDetector.getRiskCategory(requestData.metadata.authAnalysis.riskScore);
      }

      // DOS prevention
      const MAX_REQUEST_SIZE = 100 * 1024;
      const requestSize = JSON.stringify(requestData).length;
      if (requestSize > MAX_REQUEST_SIZE) {
        console.warn(`Request too large (${requestSize} bytes), truncating response body`);
        if (requestData.responseBody) {
          requestData.responseBody = requestData.responseBody.substring(0, 10000) + '... [truncated]';
        }
      }

      // Store
      this.storageManager.storeAuthEvent(requestData).then(() => {
        this.updateBadge();
        this.authRequests.delete(requestId);
      });
    } else {
      console.warn('No matching auth request found for intercepted response:', data.url);
    }

    sendResponse({ success: true });
    return false;
  }

  /**
   * Handle probe:alg_none action
   */
  handleProbeAlgNone(message, sender, sendResponse) {
    if (!message.request || !message.jwt) {
      sendResponse({ success: false, error: 'Missing request or JWT' });
      return false;
    }

    performAlgNoneProbe(message.request, message.jwt, sender)
      .then(sendResponse)
      .catch(error => {
        console.error('Hera: probe:alg_none failed:', error);
        sendResponse({ success: false, error: error.message });
      });
    
    return true;
  }

  /**
   * Handle repeater:send action
   */
  handleRepeaterSend(message, sender, sendResponse) {
    if (!message.rawRequest || typeof message.rawRequest !== 'string') {
      sendResponse({ success: false, error: 'Missing or invalid rawRequest' });
      return false;
    }

    performRepeaterRequest(message.rawRequest, sender)
      .then(sendResponse)
      .catch(error => {
        console.error('Hera: repeater:send failed:', error);
        sendResponse({ success: false, error: error.message });
      });
    
    return true;
  }

  /**
   * Handle getRequests action
   */
  handleGetRequests(sendResponse) {
    chrome.storage.local.get(['heraSessions'], (result) => {
      const storedSessions = result.heraSessions || [];
      const currentRequests = Array.from(this.authRequests.values());

      const byId = new Map();
      for (const item of storedSessions) {
        if (item && item.id) byId.set(item.id, item);
      }
      for (const item of currentRequests) {
        if (item && item.id) byId.set(item.id, item);
      }

      sendResponse(Array.from(byId.values()));
    });
    
    return true;
  }

  /**
   * Handle getBackendScan action
   */
  handleGetBackendScan(message, sendResponse) {
    if (!message.domain || typeof message.domain !== 'string') {
      sendResponse({ success: false, error: 'Missing or invalid domain' });
      return false;
    }

    const requestsArray = Array.from(this.authRequests.values());
    const domainRequests = requestsArray.filter(req =>
      new URL(req.url).hostname === message.domain
    );

    const latestRequest = domainRequests.sort((a, b) =>
      b.timestamp - a.timestamp
    )[0];

    const backendScan = latestRequest?.metadata?.backendSecurity || null;
    if (backendScan && latestRequest?.metadata?.authAnalysis) {
      backendScan.authAnalysis = latestRequest.metadata.authAnalysis;
    }

    sendResponse(backendScan);
    return false;
  }

  /**
   * Handle reportBlockedSubmission action
   */
  handleReportBlockedSubmission(message, sendResponse) {
    console.log(`Blocked form submission on ${message.domain}`);
    
    this.heraStore.storeAuthEvent({
      id: this.generateSessionId(),
      url: `https://${message.domain}`,
      method: 'BLOCKED_FORM_SUBMISSION',
      timestamp: Date.now(),
      authType: 'Form Protection',
      statusCode: null,
      metadata: {
        blockReason: 'Critical backend exposures detected',
        exposures: message.exposures,
        userProtected: true
      },
      sessionId: this.generateSessionId(),
      riskScore: 100
    });
    
    sendResponse({ success: true });
    return false;
  }

  /**
   * Handle clearRequests action
   */
  handleClearRequests(sendResponse) {
    this.authRequests.clear();
    
    this.storageManager.clearAllSessions().then(() => {
      this.updateBadge();
      sendResponse({ success: true });
    }).catch(error => {
      console.error('Hera: clearRequests failed:', error);
      sendResponse({ success: false, error: error.message });
    });
    
    return true;
  }

  /**
   * Handle updateResponseCaptureSetting action
   */
  handleUpdateResponseCapture(message, sendResponse) {
    if (!message.enabled) {
      for (const [tabId, debuggee] of this.debugTargets.entries()) {
        chrome.debugger.detach(debuggee, () => {
          if (chrome.runtime.lastError) {
            console.warn(`Error detaching debugger from tab ${tabId}:`, chrome.runtime.lastError.message);
          } else {
            console.log(`Detached debugger from tab ${tabId}`);
          }
        });
      }
      this.debugTargets.clear();
    }
    
    sendResponse({ success: true });
    return false;
  }

  /**
   * Handle getPortAnalysis action
   */
  handleGetPortAnalysis(sendResponse) {
    try {
      const requestsArray = Array.from(this.authRequests.values());

      // Analyze port distribution
      const ports = {};
      const authTypes = {};
      const risks = [];

      requestsArray.forEach(request => {
        try {
          const url = new URL(request.url);
          const port = url.port || (url.protocol === 'https:' ? '443' : '80');

          // Count ports
          ports[port] = (ports[port] || 0) + 1;

          // Count auth types
          const authType = request.authType || 'Unknown';
          authTypes[authType] = (authTypes[authType] || 0) + 1;

          // Check for port-related risks
          if (url.protocol === 'http:' && (port === '80' || port === '8080')) {
            risks.push({
              severity: 'critical',
              title: 'Unencrypted Authentication',
              description: `Authentication over HTTP on port ${port} (${url.hostname})`
            });
          }

          // Non-standard HTTPS port
          if (url.protocol === 'https:' && port !== '443' && port !== '80') {
            risks.push({
              severity: 'low',
              title: 'Non-standard HTTPS Port',
              description: `HTTPS on non-standard port ${port} (${url.hostname})`
            });
          }
        } catch (e) {
          // Invalid URL, skip
        }
      });

      sendResponse({
        success: true,
        data: {
          ports,
          authTypes,
          risks: risks.slice(0, 10) // Limit to 10 risks
        }
      });
    } catch (error) {
      console.error('Port analysis error:', error);
      sendResponse({
        success: false,
        error: error.message
      });
    }

    return false;
  }

  /**
   * Handle getExtensionsAnalysis action
   */
  handleGetExtensionsAnalysis(sendResponse) {
    // Chrome extensions can't easily query other extensions for security reasons
    // This is a placeholder that would need user permission to access management API
    try {
      chrome.management.getAll((extensions) => {
        if (chrome.runtime.lastError) {
          sendResponse({
            success: false,
            error: chrome.runtime.lastError.message
          });
          return;
        }

        // Filter out this extension and analyze others
        const analyzed = extensions
          .filter(ext => ext.id !== chrome.runtime.id)
          .map(ext => {
            // Basic risk assessment
            let riskLevel = 'low';
            const issues = [];

            // Check permissions
            const dangerousPermissions = ['webRequest', 'webRequestBlocking', 'debugger', '<all_urls>'];
            const hasDangerousPerms = ext.permissions.some(perm =>
              dangerousPermissions.some(danger => perm.includes(danger))
            );

            if (hasDangerousPerms) {
              riskLevel = 'medium';
              issues.push('Has broad permissions that could intercept authentication data');
            }

            if (ext.permissions.includes('cookies') || ext.permissions.includes('webRequest')) {
              issues.push('Can access cookies and network requests');
            }

            // Not from web store
            if (ext.installType === 'development' || ext.installType === 'sideload') {
              riskLevel = 'high';
              issues.push('Sideloaded extension (not from Chrome Web Store)');
            }

            return {
              id: ext.id,
              name: ext.name,
              version: ext.version,
              enabled: ext.enabled,
              permissions: ext.permissions || [],
              installType: ext.installType,
              riskLevel,
              issues
            };
          });

        sendResponse({
          success: true,
          data: {
            extensions: analyzed
          }
        });
      });

      return true; // Async response
    } catch (error) {
      console.error('Extensions analysis error:', error);
      sendResponse({
        success: false,
        error: 'Extension analysis requires management permission'
      });
      return false;
    }
  }

  /**
   * Handle GET_SITE_ANALYSIS type message
   * Returns the most recent analysis for the current tab's domain
   */
  handleGetSiteAnalysis(sendResponse) {
    chrome.storage.local.get(['heraSiteAnalysis'], (result) => {
      if (chrome.runtime.lastError) {
        console.error('Error retrieving site analysis:', chrome.runtime.lastError);
        sendResponse({ success: false, error: chrome.runtime.lastError.message });
        return;
      }

      const analysis = result.heraSiteAnalysis;
      if (analysis && analysis.url) {
        sendResponse({
          success: true,
          analysis: analysis
        });
      } else {
        sendResponse({
          success: false,
          error: 'No analysis data available'
        });
      }
    });

    return true; // Async response
  }

  /**
   * Handle TRIGGER_ANALYSIS type message
   * Triggers analysis on the active tab's content script
   */
  async handleTriggerAnalysis(sendResponse) {
    try {
      // Get the active tab
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });

      if (!tabs || tabs.length === 0) {
        sendResponse({ success: false, error: 'No active tab found' });
        return false;
      }

      const activeTab = tabs[0];

      // Check if tab is valid for content script injection
      if (!activeTab.url || activeTab.url.startsWith('chrome://') || activeTab.url.startsWith('chrome-extension://')) {
        sendResponse({
          success: false,
          error: 'Cannot analyze Chrome internal pages'
        });
        return false;
      }

      console.log('Hera: Triggering analysis on tab:', activeTab.id, activeTab.url);

      // Send message to content script to trigger analysis
      chrome.tabs.sendMessage(activeTab.id, { type: 'TRIGGER_ANALYSIS' }, (response) => {
        if (chrome.runtime.lastError) {
          console.error('Error triggering analysis:', chrome.runtime.lastError);
          sendResponse({
            success: false,
            error: 'Content script not ready. Try refreshing the page.'
          });
        } else if (response && response.success) {
          sendResponse({
            success: true,
            score: response.score
          });
        } else {
          sendResponse({
            success: false,
            error: response?.error || 'Analysis failed'
          });
        }
      });

      return true; // Async response
    } catch (error) {
      console.error('Trigger analysis error:', error);
      sendResponse({ success: false, error: error.message });
      return false;
    }
  }

  /**
   * Handle ANALYSIS_COMPLETE type message
   * Stores analysis results from content script
   */
  handleAnalysisComplete(message, sendResponse) {
    if (!message.url || !message.score) {
      console.warn('ANALYSIS_COMPLETE missing required fields');
      sendResponse({ success: false, error: 'Invalid analysis data' });
      return false;
    }

    console.log('Hera: Analysis complete for:', message.url);

    // Store the analysis results
    const analysisData = {
      url: message.url,
      findings: message.findings || [],
      score: message.score,
      timestamp: message.timestamp || new Date().toISOString(),
      analysisSuccessful: message.analysisSuccessful !== false
    };

    chrome.storage.local.set({ heraSiteAnalysis: analysisData }, () => {
      if (chrome.runtime.lastError) {
        console.error('Error storing analysis:', chrome.runtime.lastError);
        sendResponse({ success: false, error: chrome.runtime.lastError.message });
      } else {
        console.log('Hera: Analysis results stored successfully');
        sendResponse({ success: true });
      }
    });

    return true; // Async response
  }

  /**
   * Handle type-based messages (analysis results)
   */
  handleTypeMessage(message, sender, sendResponse) {
    // Skip if this is an 'action' message
    if (message.action) {
      return false;
    }

    // Sender validation
    if (!sender.id || sender.id !== chrome.runtime.id) {
      console.warn('Hera: Rejecting message from untrusted sender:', sender);
      sendResponse({ success: false, error: 'Unauthorized sender' });
      return false;
    }

    // Authorization for type-based messages
    const senderUrl = sender.url || '';
    const isAuthorizedSender = this.allowedSenderUrls.some(allowed => 
      senderUrl.startsWith(allowed)
    );

    const contentScriptAllowedTypes = [
      'ANALYSIS_COMPLETE',
      'ANALYSIS_ERROR',
      'GET_SITE_ANALYSIS',
      'TRIGGER_ANALYSIS',
      'INJECT_RESPONSE_INTERCEPTOR'
    ];

    if (!isAuthorizedSender && message.type && !contentScriptAllowedTypes.includes(message.type)) {
      console.error(`Hera SECURITY: Unauthorized type message from ${senderUrl}: ${message.type}`);
      sendResponse({ success: false, error: 'Unauthorized sender for this message type' });
      return false;
    }

    // Route type-based messages
    switch (message.type) {
      case 'GET_SITE_ANALYSIS':
        return this.handleGetSiteAnalysis(sendResponse);

      case 'TRIGGER_ANALYSIS':
        return this.handleTriggerAnalysis(sendResponse);

      case 'ANALYSIS_COMPLETE':
        return this.handleAnalysisComplete(message, sendResponse);

      case 'ANALYSIS_ERROR':
        console.error('Analysis error received:', message.error);
        sendResponse({ success: false, error: message.error });
        return false;

      default:
        console.log('Hera: Unhandled type-based message:', message.type);
        return false;
    }
  }

  /**
   * Handle DevTools port connections
   */
  handlePortConnection(port) {
    if (port.name === 'devtools-page') {
      console.log('Hera: DevTools panel connected');

      port.onMessage.addListener(async (message) => {
        console.log('Hera: DevTools message received:', message.type);

        if (message.type === 'INIT_DEVTOOLS') {
          chrome.storage.local.get({ heraSessions: [] }, (result) => {
            result.heraSessions.forEach(session => {
              port.postMessage({
                type: 'AUTH_REQUEST',
                data: session
              });
            });
          });
        } else if (message.type === 'SET_RECORDING_STATE') {
          await chrome.storage.session.set({ heraRecording: message.isRecording });
          console.log(`Hera: Recording ${message.isRecording ? 'enabled' : 'paused'}`);
        } else if (message.type === 'CLEAR_REQUESTS') {
          await this.storageManager.clearAllSessions();
          await this.memoryManager.clearAuthRequests();
          console.log('Hera: All requests cleared');
        }
      });

      port.onDisconnect.addListener(() => {
        console.log('Hera: DevTools panel disconnected');
      });
    }
  }
}
