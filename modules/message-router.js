/**
 * Message Router - Routes chrome.runtime.onMessage events
 * Handles authorization, validation, and routing to appropriate handlers
 */

// AUTH-ONLY MODE: Security probes disabled
// import { performAlgNoneProbe, performRepeaterRequest } from './security-probes.js';

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
    heraStore,
    errorCollector = null
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
    this.errorCollector = errorCollector;

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
    console.log('MessageRouter: Registering message listeners...');

    // Action-based messages
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      console.log('MessageRouter: Message received (action handler):', {
        action: message.action,
        type: message.type,
        senderUrl: sender.url
      });
      return this.handleActionMessage(message, sender, sendResponse);
    });

    // Type-based messages (analysis results)
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      console.log('MessageRouter: Message received (type handler):', {
        action: message.action,
        type: message.type,
        senderUrl: sender.url
      });
      return this.handleTypeMessage(message, sender, sendResponse);
    });

    // DevTools port connections
    chrome.runtime.onConnect.addListener((port) => {
      console.log('MessageRouter: Port connection:', port.name);
      this.handlePortConnection(port);
    });

    console.log('MessageRouter: All listeners registered successfully');
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

      case 'getErrors':
        return this.handleGetErrors(sendResponse);

      case 'exportErrors':
        return this.handleExportErrors(message, sendResponse);

      case 'clearErrors':
        return this.handleClearErrors(sendResponse);

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
    // AUTH-ONLY MODE: Security probes disabled
    console.warn('Hera: alg:none probe disabled in auth-only mode');
    sendResponse({ success: false, error: 'Security probes disabled in auth-only mode' });
    return false;
  }

  /**
   * Handle repeater:send action
   */
  handleRepeaterSend(message, sender, sendResponse) {
    // AUTH-ONLY MODE: Repeater disabled
    console.warn('Hera: Repeater disabled in auth-only mode');
    sendResponse({ success: false, error: 'Repeater disabled in auth-only mode' });
    return false;
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
   * Automatically injects content script if not present
   */
  async handleTriggerAnalysis(sendResponse) {
    console.log('MessageRouter: handleTriggerAnalysis called');

    try {
      // Get the active tab
      console.log('MessageRouter: Querying active tab...');
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      console.log('MessageRouter: Found tabs:', tabs.length);

      if (!tabs || tabs.length === 0) {
        console.error('MessageRouter: No active tab found');
        sendResponse({ success: false, error: 'No active tab found' });
        return false;
      }

      const activeTab = tabs[0];
      console.log('MessageRouter: Active tab:', { id: activeTab.id, url: activeTab.url });

      // Check if tab is valid for content script injection
      if (!activeTab.url || activeTab.url.startsWith('chrome://') || activeTab.url.startsWith('chrome-extension://')) {
        console.warn('MessageRouter: Cannot analyze Chrome internal page:', activeTab.url);
        sendResponse({
          success: false,
          error: 'Cannot analyze Chrome internal pages'
        });
        return false;
      }

      console.log('MessageRouter: Triggering analysis on tab:', activeTab.id, activeTab.url);

      // First, try to ping the content script to see if it's already loaded
      console.log('MessageRouter: Pinging content script...');
      chrome.tabs.sendMessage(activeTab.id, { type: 'PING' }, async (pingResponse) => {
        console.log('MessageRouter: Ping response:', pingResponse, 'Error:', chrome.runtime.lastError);

        if (chrome.runtime.lastError || !pingResponse || !pingResponse.loaded) {
          // Content script not loaded - inject it dynamically
          console.log('MessageRouter: Content script not found, injecting dynamically...');

          try {
            // Inject content script modules first
            await chrome.scripting.executeScript({
              target: { tabId: activeTab.id },
              files: ['content-script.js']
            });

            console.log('Hera: Content script injected successfully');

            // Wait a moment for content script to initialize
            setTimeout(() => {
              // Now trigger analysis
              chrome.tabs.sendMessage(activeTab.id, { type: 'TRIGGER_ANALYSIS' }, (response) => {
                if (chrome.runtime.lastError) {
                  console.error('Error after injection:', chrome.runtime.lastError);
                  sendResponse({
                    success: false,
                    error: 'Content script injected but analysis failed. Try refreshing the page.'
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
            }, 500); // Wait 500ms for initialization

          } catch (injectionError) {
            console.error('Hera: Failed to inject content script:', injectionError);
            sendResponse({
              success: false,
              error: 'Failed to inject content script. Try refreshing the page.'
            });
          }
        } else {
          // Content script already loaded - trigger analysis directly
          console.log('Hera: Content script already loaded, triggering analysis');

          chrome.tabs.sendMessage(activeTab.id, { type: 'TRIGGER_ANALYSIS' }, (response) => {
            if (chrome.runtime.lastError) {
              console.error('Error triggering analysis:', chrome.runtime.lastError.message || chrome.runtime.lastError);
              console.error('Full error object:', JSON.stringify(chrome.runtime.lastError, null, 2));
              sendResponse({
                success: false,
                error: 'Content script communication failed. Try refreshing the page.'
              });
            } else if (response && response.success) {
              sendResponse({
                success: true,
                score: response.score
              });
            } else {
              console.error('Analysis failed with response:', response);
              sendResponse({
                success: false,
                error: response?.error || 'Analysis failed'
              });
            }
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
    console.log('MessageRouter: handleAnalysisComplete called');
    console.log('MessageRouter: Message data:', {
      url: message.url,
      hasScore: !!message.score,
      findingsCount: message.findings?.length || 0
    });

    if (!message.url || !message.score) {
      console.error('MessageRouter: ANALYSIS_COMPLETE missing required fields:', {
        hasUrl: !!message.url,
        hasScore: !!message.score
      });
      sendResponse({ success: false, error: 'Invalid analysis data' });
      return false;
    }

    console.log('MessageRouter: Analysis complete for:', message.url);
    console.log('MessageRouter: Score data:', message.score);

    // Store the analysis results
    const analysisData = {
      url: message.url,
      findings: message.findings || [],
      score: message.score,
      timestamp: message.timestamp || new Date().toISOString(),
      analysisSuccessful: message.analysisSuccessful !== false
    };

    console.log('MessageRouter: Storing analysis data to chrome.storage.local...');
    chrome.storage.local.set({ heraSiteAnalysis: analysisData }, () => {
      if (chrome.runtime.lastError) {
        console.error('MessageRouter: Error storing analysis:', chrome.runtime.lastError);
        sendResponse({ success: false, error: chrome.runtime.lastError.message });
      } else {
        console.log('MessageRouter: Analysis results stored successfully');
        sendResponse({ success: true });
      }
    });

    return true; // Async response
  }

  /**
   * Handle type-based messages (analysis results)
   */
  handleTypeMessage(message, sender, sendResponse) {
    console.log('MessageRouter: handleTypeMessage called with:', { type: message.type, senderUrl: sender.url });

    // Skip if this is an 'action' message
    if (message.action) {
      console.log('MessageRouter: Skipping - has action property');
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

    console.log('MessageRouter: Authorization check:', {
      senderUrl,
      isAuthorizedSender,
      allowedUrls: this.allowedSenderUrls
    });

    const contentScriptAllowedTypes = [
      'ANALYSIS_COMPLETE',
      'ANALYSIS_ERROR',
      'GET_SITE_ANALYSIS',
      'TRIGGER_ANALYSIS',
      'INJECT_RESPONSE_INTERCEPTOR',
      'WEBAUTHN_DETECTION'
    ];

    if (!isAuthorizedSender && message.type && !contentScriptAllowedTypes.includes(message.type)) {
      console.error(`Hera SECURITY: Unauthorized type message from ${senderUrl}: ${message.type}`);
      sendResponse({ success: false, error: 'Unauthorized sender for this message type' });
      return false;
    }

    // Route type-based messages
    console.log(`MessageRouter: Routing type-based message: ${message.type}`);
    switch (message.type) {
      case 'GET_SITE_ANALYSIS':
        console.log('MessageRouter: Calling handleGetSiteAnalysis');
        return this.handleGetSiteAnalysis(sendResponse);

      case 'TRIGGER_ANALYSIS':
        console.log('MessageRouter: Calling handleTriggerAnalysis');
        return this.handleTriggerAnalysis(sendResponse);

      case 'ANALYSIS_COMPLETE':
        console.log('MessageRouter: Calling handleAnalysisComplete');
        return this.handleAnalysisComplete(message, sendResponse);

      case 'ANALYSIS_ERROR':
        console.error('Analysis error received:', message.error);
        sendResponse({ success: false, error: message.error });
        return false;

      case 'WEBAUTHN_DETECTION':
        console.log('MessageRouter: Calling handleWebAuthnDetection');
        return this.handleWebAuthnDetection(message, sendResponse);

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

  /**
   * Handle getErrors action - Return collected errors
   */
  handleGetErrors(sendResponse) {
    if (!this.errorCollector) {
      sendResponse({ success: false, error: 'Error collector not available' });
      return false;
    }

    const stats = this.errorCollector.getErrorStats();
    sendResponse({
      success: true,
      errors: this.errorCollector.errors,
      warnings: this.errorCollector.warnings,
      stats: stats
    });
    return false;
  }

  /**
   * Handle exportErrors action - Download errors as file
   */
  async handleExportErrors(message, sendResponse) {
    if (!this.errorCollector) {
      sendResponse({ success: false, error: 'Error collector not available' });
      return false;
    }

    try {
      const format = message.format || 'json';
      await this.errorCollector.downloadErrors(format);
      sendResponse({ success: true });
    } catch (error) {
      console.error('Error exporting errors:', error);
      sendResponse({ success: false, error: error.message });
    }
    return false;
  }

  /**
   * Handle clearErrors action - Clear all collected errors
   */
  handleClearErrors(sendResponse) {
    if (!this.errorCollector) {
      sendResponse({ success: false, error: 'Error collector not available' });
      return false;
    }

    this.errorCollector.clearErrors();
    sendResponse({ success: true });
    return false;
  }

  /**
   * Handle WebAuthn detection from content script
   * P0 WebAuthn: Store WebAuthn vulnerabilities detected by content script
   */
  async handleWebAuthnDetection(message, sendResponse) {
    console.log('Hera: WebAuthn detection received:', {
      subtype: message.subtype,
      url: message.url,
      issueCount: message.issues?.length || 0
    });

    if (!message.issues || message.issues.length === 0) {
      sendResponse({ success: true, stored: false });
      return false;
    }

    try {
      // Create a session entry for WebAuthn findings
      const sessionData = {
        id: this.generateSessionId(),
        url: message.url,
        method: 'WebAuthn',
        type: 'webauthn',
        authType: 'WebAuthn/FIDO2',
        timestamp: new Date(message.timestamp).toISOString(),
        statusCode: 200,
        requestHeaders: [],
        responseHeaders: [],
        requestBody: null,
        responseBody: null,
        metadata: {
          authAnalysis: {
            protocol: 'WebAuthn',
            issues: message.issues,
            riskScore: this.heraAuthDetector.calculateRiskScore(message.issues),
            riskCategory: this.heraAuthDetector.getRiskCategory(
              this.heraAuthDetector.calculateRiskScore(message.issues)
            ),
            webauthnSubtype: message.subtype,
            webauthnOptions: message.options || {}
          }
        }
      };

      // Store the WebAuthn session
      await this.storageManager.storeAuthEvent(sessionData);
      await this.updateBadge();

      console.log('Hera: WebAuthn findings stored successfully');
      sendResponse({ success: true, stored: true, issueCount: message.issues.length });

    } catch (error) {
      console.error('Hera: Error storing WebAuthn detection:', error);
      sendResponse({ success: false, error: error.message });
    }

    return false;
  }
}
