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
    // (These would be handled by analysis modules - placeholder for now)
    console.log('Hera: Type-based message routing (to be implemented in analysis modules)');
    return false;
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
