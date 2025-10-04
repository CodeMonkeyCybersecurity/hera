import { HeraAuthProtocolDetector } from './hera-auth-detector.js';
import { HeraSecretScanner } from './hera-secret-scanner.js';
import { HeraMaliciousExtensionDetector } from './hera-extension-security.js';
import { HeraAuthSecurityAnalyzer } from './hera-auth-security-analyzer.js';
import { HeraPortAuthAnalyzer } from './hera-port-auth-analyzer.js';
import { EvidenceCollector } from './evidence-collector.js';
import { AlertManager } from './alert-manager.js';

// Security Input Validation Utilities
const SecurityValidation = {
  // Sanitize URLs for safe processing
  sanitizeURL: (url) => {
    if (typeof url !== 'string') return '';
    try {
      const urlObj = new URL(url);
      // Only allow http/https protocols
      if (!['http:', 'https:'].includes(urlObj.protocol)) {
        return '';
      }
      return url;
    } catch (e) {
      return '';
    }
  },

  // Validate and sanitize headers
  sanitizeHeaders: (headers) => {
    if (!Array.isArray(headers)) return [];
    return headers.filter(header => {
      return (
        header &&
        typeof header.name === 'string' &&
        typeof header.value === 'string' &&
        header.name.length < 1000 &&
        header.value.length < 10000
      );
    }).map(header => ({
      name: header.name.toLowerCase().trim(),
      value: header.value.trim()
    }));
  },

  // Validate request body size and content
  validateRequestBody: (body) => {
    if (!body) return null;

    // Limit body size (10MB max)
    const MAX_BODY_SIZE = 10 * 1024 * 1024;
    if (typeof body === 'string' && body.length > MAX_BODY_SIZE) {
      return body.substring(0, MAX_BODY_SIZE) + '[TRUNCATED]';
    }
    return body;
  },

  // Validate and sanitize domain names
  sanitizeDomain: (domain) => {
    if (typeof domain !== 'string') return '';

    // Basic domain validation
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/;
    if (!domainRegex.test(domain) || domain.length > 253) {
      return '';
    }
    return domain.toLowerCase();
  },

  // Rate limiting for request processing
  rateLimiter: {
    requestCounts: new Map(),
    MAX_REQUESTS_PER_MINUTE: 1000,

    checkRateLimit: (clientId) => {
      const now = Date.now();
      const windowStart = now - 60000; // 1 minute window

      if (!SecurityValidation.rateLimiter.requestCounts.has(clientId)) {
        SecurityValidation.rateLimiter.requestCounts.set(clientId, []);
      }

      const requests = SecurityValidation.rateLimiter.requestCounts.get(clientId);

      // Remove old requests outside the window
      const validRequests = requests.filter(timestamp => timestamp > windowStart);

      if (validRequests.length >= SecurityValidation.rateLimiter.MAX_REQUESTS_PER_MINUTE) {
        return false; // Rate limit exceeded
      }

      validRequests.push(now);
      SecurityValidation.rateLimiter.requestCounts.set(clientId, validRequests);
      return true;
    }
  },

  // Validate JWT tokens before processing
  validateJWTInput: (token) => {
    if (typeof token !== 'string') return null;

    // Basic JWT structure validation
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    // Check each part is valid base64url
    for (const part of parts) {
      if (!/^[A-Za-z0-9_-]+$/.test(part)) {
        return null;
      }
    }

    // Reasonable length limits
    if (token.length > 10000) return null;

    return token;
  }
};

// NOTE: Removed unused SecureStorage encryption system (was broken - session key lost on service worker restart)
// If encryption is needed in the future, use:
// 1. Password-based key derivation (PBKDF2) with user password
// 2. OR store key in chrome.storage.session (MV3) - but data still lost on browser restart
// 3. OR accept that sensitive data should NOT be stored locally at all

// --- Global State ---
const authRequests = new Map(); // In-memory store for requests being processed
const version = "1.3";
const debugTargets = new Map();

// Memory leak prevention: Clean up stale requests every 2 minutes
const REQUEST_TTL = 5 * 60 * 1000; // 5 minutes

function cleanupStaleRequests() {
  const now = Date.now();
  let cleaned = 0;

  for (const [requestId, requestData] of authRequests.entries()) {
    const age = now - new Date(requestData.timestamp).getTime();
    if (age > REQUEST_TTL) {
      authRequests.delete(requestId);
      cleaned++;
    }
  }

  if (cleaned > 0) {
    console.log(`Hera: Cleaned up ${cleaned} stale auth requests`);
  }

  // Also cleanup debugTargets for closed tabs
  chrome.tabs.query({}, (tabs) => {
    const activeTabIds = new Set(tabs.map(t => t.id));
    let debugCleaned = 0;

    for (const tabId of debugTargets.keys()) {
      if (!activeTabIds.has(tabId)) {
        debugTargets.delete(tabId);
        debugCleaned++;
      }
    }

    if (debugCleaned > 0) {
      console.log(`Hera: Cleaned up ${debugCleaned} stale debugger targets`);
    }
  });

  // Log memory stats for monitoring
  console.log(`Hera: Active requests: ${authRequests.size}, Debug targets: ${debugTargets.size}`);
}

// Storage quota monitoring
const QUOTA_WARNING_THRESHOLD = 0.8; // 80% of quota
const MAX_SESSIONS = 1000; // Hard limit on stored sessions

async function checkStorageQuota() {
  try {
    const bytesInUse = await chrome.storage.local.getBytesInUse();
    const quota = chrome.storage.local.QUOTA_BYTES || 10485760; // 10MB default
    const usagePercent = bytesInUse / quota;

    console.log(`Storage: ${(bytesInUse / 1024).toFixed(0)}KB / ${(quota / 1024).toFixed(0)}KB (${(usagePercent * 100).toFixed(1)}%)`);

    if (usagePercent >= QUOTA_WARNING_THRESHOLD) {
      console.warn(`⚠️ Storage quota warning: ${(usagePercent * 100).toFixed(0)}% used`);

      // Cleanup oldest sessions
      chrome.storage.local.get(['heraSessions'], (result) => {
        const sessions = result.heraSessions || [];
        if (sessions.length > MAX_SESSIONS) {
          // Keep only the most recent sessions
          const sorted = sessions.sort((a, b) =>
            new Date(b.timestamp) - new Date(a.timestamp)
          );
          const trimmed = sorted.slice(0, MAX_SESSIONS);

          chrome.storage.local.set({ heraSessions: trimmed }, () => {
            console.log(`Trimmed sessions from ${sessions.length} to ${trimmed.length}`);
          });
        }
      });
    }
  } catch (error) {
    console.error('Failed to check storage quota:', error);
  }
}

// Use chrome.alarms API (persists across service worker restarts)
chrome.alarms.create('cleanupAuthRequests', { periodInMinutes: 2 });
chrome.alarms.create('checkStorageQuota', { periodInMinutes: 10 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'cleanupAuthRequests') {
    cleanupStaleRequests();
    alertManager.cleanupAlertHistory(); // Also cleanup alert deduplication history
  } else if (alarm.name === 'checkStorageQuota') {
    checkStorageQuota();
  }
});

// Initialize EvidenceCollector first
const evidenceCollector = new EvidenceCollector(); // Evidence-based vulnerability verification

// Initialize AlertManager for tiered, confidence-based alerting
const alertManager = new AlertManager();

// Then initialize other components that depend on it
const heraAuthDetector = new HeraAuthProtocolDetector(evidenceCollector);
const heraSecretScanner = new HeraSecretScanner();
const heraExtensionDetector = new HeraMaliciousExtensionDetector();
const heraAuthSecurityAnalyzer = new HeraAuthSecurityAnalyzer();
const heraPortAuthAnalyzer = new HeraPortAuthAnalyzer();

// Add missing wrapper methods for HeraAuthProtocolDetector
heraAuthDetector.isAuthRequest = function(url, options) {
  // Simple auth endpoint detection
  const authPatterns = [
    '/oauth', '/authorize', '/token', '/login', '/signin', '/auth',
    '/api/auth', '/session', '/connect', '/saml', '/oidc', '/scim'
  ];
  const urlLower = url.toLowerCase();
  return authPatterns.some(pattern => urlLower.includes(pattern));
};

heraAuthDetector.analyze = function(url, method, headers, body) {
  return this.analyzeRequest({
    url: url,
    method: method,
    headers: headers,
    body: body
  });
};

// --- Storage Helper ---
const heraStore = {
  async storeAuthEvent(eventData) {
    try {
      const result = await chrome.storage.local.get({ heraSessions: [] });
      const sessions = result.heraSessions;
      sessions.push(eventData);
      await chrome.storage.local.set({ heraSessions: sessions });
    } catch (error) {
      console.error('Failed to store auth event:', error);
    }
  },
  async storeSession(sessionData) {
    try {
      const result = await chrome.storage.local.get({ heraSessions: [] });
      const sessions = result.heraSessions;
      sessions.push(sessionData);
      await chrome.storage.local.set({ heraSessions: sessions });
    } catch (error) {
      console.error('Failed to store session:', error);
    }
  }
};

// --- Utility Functions ---

function decodeRequestBody(requestBody) {
    if (!requestBody || !requestBody.raw) return null;
    try {
        const decoder = new TextDecoder('utf-8');
        const decodedParts = requestBody.raw.map(part => {
            if (part.bytes) {
                const byteValues = Object.values(part.bytes);
                return decoder.decode(new Uint8Array(byteValues));
            }
            return '';
        });
        return decodedParts.join('');
    } catch (e) {
        console.error('Hera: Failed to decode request body:', e);
        return '[Hera: Failed to decode body]';
    }
}

async function updateBadge() {
    const stored = await chrome.storage.local.get(['heraSessions']);
    const count = stored.heraSessions ? stored.heraSessions.length : 0;
    if (count > 0) {
        chrome.action.setBadgeText({ text: count.toString() });
        chrome.action.setBadgeBackgroundColor({ color: '#dc3545' });
    } else {
        chrome.action.setBadgeText({ text: '' });
    }
}

// Show security alert for authentication issues (using AlertManager)
function showAuthSecurityAlert(finding, url) {
  try {
    // Enhance finding with URL
    const enrichedFinding = {
      ...finding,
      url: url,
      evidence: finding.evidence || {}
    };

    // Use AlertManager for tiered, confidence-based alerting
    alertManager.processFinding(enrichedFinding);

  } catch (error) {
    console.error('Failed to show auth security alert:', error);
  }
}

// Show security alert for malicious extension detection (using AlertManager)
function showExtensionSecurityAlert(finding) {
  try {
    // Extension threats are always CRITICAL with high confidence
    const enrichedFinding = {
      ...finding,
      severity: 'CRITICAL',
      url: 'chrome://extensions/',
      evidence: {
        verification: finding.details?.extensionId ? `chrome://extensions/?id=${finding.details.extensionId}` : null
      }
    };

    // Use AlertManager for tiered alerting
    alertManager.processFinding(enrichedFinding);

  } catch (error) {
    console.error('Failed to show extension security alert:', error);
  }
}

// --- Main Logic ---

// 1. Listen for requests
chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        const isAuthRelated = heraAuthDetector.isAuthRequest(details.url, {});
        if (isAuthRelated) {
            authRequests.set(details.requestId, {
                id: details.requestId,
                url: details.url,
                method: details.method,
                type: details.type,
                tabId: details.tabId,
                timestamp: new Date().toISOString(),
                requestBody: decodeRequestBody(details.requestBody),
                // Placeholders for data from other listeners
                requestHeaders: [],
                responseHeaders: [],
                statusCode: null,
                responseBody: null,
                metadata: {},
            });
        }
    },
    { urls: ["<all_urls>"] },
    ["requestBody"]
);

// 2. Capture request headers
chrome.webRequest.onBeforeSendHeaders.addListener(
    (details) => {
        const requestData = authRequests.get(details.requestId);
        if (requestData) {
            requestData.requestHeaders = details.requestHeaders;
            // Perform analysis now that we have headers
            const authAnalysis = heraAuthDetector.analyze(details.url, details.method, details.requestHeaders, requestData.requestBody);
            requestData.authType = authAnalysis.protocol;
            // Ensure metadata exists
            if (!requestData.metadata) {
                requestData.metadata = {};
            }
            requestData.metadata.authAnalysis = authAnalysis;
            requestData.metadata.authAnalysis.riskCategory = heraAuthDetector.getRiskCategory(authAnalysis.riskScore);

            // Update port analysis with headers
            requestData.metadata.authTypeAnalysis = heraPortAuthAnalyzer.detectAuthType({
                url: details.url,
                method: details.method,
                requestHeaders: details.requestHeaders,
                requestBody: requestData.requestBody
            });

            // Check for default credentials
            requestData.metadata.credentialAnalysis = heraPortAuthAnalyzer.checkDefaultCredentials({
                url: details.url,
                requestHeaders: details.requestHeaders,
                requestBody: requestData.requestBody
            });
        }
    },
    { urls: ["<all_urls>"] },
    ["requestHeaders"]
);

// 3. Capture response headers and status code
chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        const requestData = authRequests.get(details.requestId);
        if (requestData) {
            requestData.statusCode = details.statusCode;
            requestData.responseHeaders = details.responseHeaders;
        }
    },
    { urls: ["<all_urls>"] },
    ["responseHeaders"]
);

// --- Debugger and Final Save Logic ---

// Attach debugger to all existing and new tabs
async function initializeDebugger() {
    const tabs = await chrome.tabs.query({});
    for (const tab of tabs) {
        if (tab.id && tab.url && !tab.url.startsWith('chrome://')) {
            attachDebugger(tab.id);
        }
    }
}

async function attachDebugger(tabId) {
    if (tabId > 0 && !debugTargets.has(tabId)) {
        // Check if response capture is enabled
        const result = await chrome.storage.local.get(['enableResponseCapture']);
        const enabled = result.enableResponseCapture !== false; // Default to true

        if (!enabled) {
            console.log('Response capture disabled - skipping debugger attachment');
            return;
        }

        const debuggee = { tabId: tabId };
        chrome.debugger.attach(debuggee, version, () => {
            if (chrome.runtime.lastError) {
                // console.warn(`Could not attach debugger to tab ${tabId}:`, chrome.runtime.lastError.message);
                return;
            }
            debugTargets.set(tabId, debuggee);
            chrome.debugger.sendCommand(debuggee, "Network.enable");
        });
    }
}

chrome.tabs.onCreated.addListener((tab) => tab.id && attachDebugger(tab.id));
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'loading') {
        attachDebugger(tabId);
    }
});
chrome.tabs.onRemoved.addListener((tabId) => {
    if (debugTargets.has(tabId)) {
        chrome.debugger.detach({ tabId: tabId }, () => debugTargets.delete(tabId));
    }
});

// Listen for debugger events
chrome.debugger.onEvent.addListener((source, method, params) => {
    // First, get the response details when they are received
    if (method === "Network.responseReceived") {
        const requestData = authRequests.get(params.requestId);
        if (requestData) {
            requestData.responseDetails = params.response; // Store for later
        }
    }

    // When the request is finished, get the body and save everything
    if (method === "Network.loadingFinished") {
        const requestData = authRequests.get(params.requestId);
        if (requestData && requestData.responseDetails) {
            const debuggee = { tabId: source.tabId };
            chrome.debugger.sendCommand(
                debuggee,
                "Network.getResponseBody",
                { requestId: params.requestId },
                (response) => {
                    if (!chrome.runtime.lastError && response) {
                        let body = response.body;
                        if (response.base64Encoded) {
                            try {
                                body = atob(response.body);
                            } catch (e) {
                                console.warn("Hera: Failed to decode base64 response body.", e);
                                body = "[Hera: Failed to decode base64 body]";
                            }
                        }
                        requestData.responseBody = body;

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

                        // If the content is JavaScript, scan it for secrets
                        const contentType = requestData.responseDetails?.headers['content-type'] || '';
                        if (contentType.includes('javascript') || contentType.includes('application/x-javascript')) {
                            const secretFindings = heraSecretScanner.scan(body, requestData.url);
                            if (secretFindings.length > 0) {
                                if (!requestData.metadata.authAnalysis.issues) {
                                    requestData.metadata.authAnalysis.issues = [];
                                }
                                requestData.metadata.authAnalysis.issues.push(...secretFindings);
                            }
                        }

                        // Analyze the response body for security issues
                        const responseBodyIssues = heraAuthDetector.analyzeResponseBody(body);
                        if (responseBodyIssues.length > 0) {
                            if (!requestData.metadata.authAnalysis.issues) {
                                requestData.metadata.authAnalysis.issues = [];
                            }
                            requestData.metadata.authAnalysis.issues.push(...responseBodyIssues);
                            // Recalculate risk score
                            requestData.metadata.authAnalysis.riskScore = heraAuthDetector.calculateRiskScore(requestData.metadata.authAnalysis.issues);
                            requestData.metadata.authAnalysis.riskCategory = heraAuthDetector.getRiskCategory(requestData.metadata.authAnalysis.riskScore);
                        }
                    }

                    // --- FINAL SAVE POINT ---
                    // Now that we have all data, save the complete request object.
                    chrome.storage.local.get({ heraSessions: [] }, (result) => {
                        const sessions = result.heraSessions;
                        sessions.push(requestData);
                        chrome.storage.local.set({ heraSessions: sessions }, () => {
                            updateBadge();
                            authRequests.delete(params.requestId); // Clean up from memory
                        });
                    });
                }
            );
        }
    }
});

// --- Extension Lifecycle ---
chrome.runtime.onInstalled.addListener(() => {
    console.log('Hera extension installed/updated.');
    initializeDebugger();
    updateBadge();
});

chrome.runtime.onStartup.addListener(() => {
    console.log('Hera starting up...');
    initializeDebugger();
    updateBadge();
});

// Consolidated message listener (removed duplicate listener at line 4014)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('Background received message:', message.action);

  // Handle intercepted responses from response-interceptor.js
  if (message.action === 'responseIntercepted') {
    const data = message.data;

    // Find the matching request in authRequests
    // Note: We may not have a requestId from the interceptor, so match by URL
    for (const [requestId, requestData] of authRequests.entries()) {
      if (requestData.url === data.url && !requestData.responseBody) {
        requestData.responseBody = data.body;
        requestData.statusCode = data.statusCode;

        // Analyze response body for security issues
        if (!requestData.metadata) requestData.metadata = {};
        if (!requestData.metadata.authAnalysis) {
          requestData.metadata.authAnalysis = { issues: [], riskScore: 0, riskCategory: 'low' };
        }

        const responseBodyIssues = heraAuthDetector.analyzeResponseBody(data.body);
        if (responseBodyIssues.length > 0) {
          requestData.metadata.authAnalysis.issues.push(...responseBodyIssues);
          requestData.metadata.authAnalysis.riskScore = heraAuthDetector.calculateRiskScore(requestData.metadata.authAnalysis.issues);
          requestData.metadata.authAnalysis.riskCategory = heraAuthDetector.getRiskCategory(requestData.metadata.authAnalysis.riskScore);
        }

        // Save to storage
        chrome.storage.local.get({ heraSessions: [] }, (result) => {
          const sessions = result.heraSessions;
          sessions.push(requestData);
          chrome.storage.local.set({ heraSessions: sessions }, () => {
            updateBadge();
            authRequests.delete(requestId);
          });
        });

        break; // Found matching request
      }
    }

    sendResponse({ success: true });
    return false;
  }

  if (message.action === 'probe:alg_none') {
    performAlgNoneProbe(message.request, message.jwt).then(sendResponse);
    return true;
  }

  if (message.action === 'repeater:send') {
    performRepeaterRequest(message.rawRequest).then(sendResponse);
    return true;
  }

  if (message.action === 'getRequests') {
    chrome.storage.local.get(['heraSessions'], (result) => {
      const storedSessions = result.heraSessions || [];
      const currentRequests = Array.from(authRequests.values());

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

  if (message.action === 'getBackendScan') {
    const requestsArray = Array.from(authRequests.values());
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

  if (message.action === 'reportBlockedSubmission') {
    console.log(` Blocked form submission on ${message.domain}`);
    heraStore.storeAuthEvent({
      id: generateSessionId(),
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
      sessionId: generateSessionId(),
      riskScore: 100
    });
    sendResponse({ success: true });
    return false;
  }

  if (message.action === 'clearRequests') {
    authRequests.clear();
    chrome.storage.local.set({ heraSessions: [] }, () => {
      updateBadge();
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.action === 'updateResponseCaptureSetting') {
    if (!message.enabled) {
      for (const [tabId, debuggee] of debugTargets.entries()) {
        chrome.debugger.detach(debuggee, () => {
          console.log(`Detached debugger from tab ${tabId}`);
        });
      }
      debugTargets.clear();
    }
    sendResponse({ success: true });
    return false;
  }

  if (message.action === 'openPopup' || message.action === 'showTechnicalDetails') {
    sendResponse({ success: true });
    return false;
  }

  return false; // No async response needed
});

async function performAlgNoneProbe(originalRequest, jwt) {
  try {
    const parts = jwt.split('.');
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    const payload = parts[1]; // Keep payload as is

    // Create the malicious header
    header.alg = 'none';
    const maliciousHeader = btoa(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    // Construct the alg:none token (header.payload.)
    const maliciousToken = `${maliciousHeader}.${payload}.`;

    // Re-create the request headers, replacing the original token
    const newHeaders = new Headers();
    originalRequest.requestHeaders.forEach(h => {
      if (h.name.toLowerCase() === 'authorization') {
        newHeaders.set('Authorization', `Bearer ${maliciousToken}`);
      } else {
        newHeaders.set(h.name, h.value);
      }
    });

    // Perform the fetch request
    const response = await fetch(originalRequest.url, {
      method: originalRequest.method,
      headers: newHeaders,
      body: originalRequest.method !== 'GET' && originalRequest.method !== 'HEAD' ? originalRequest.requestBody : undefined,
    });

    return { success: response.ok, status: response.status, statusText: response.statusText };

  } catch (error) {
    console.error('Hera Probe Error:', error);
    return { success: false, error: error.message };
  }
}

function isExtensionRequest(initiator) {
  return initiator && initiator.startsWith('chrome-extension://');
}

function isThirdPartyRequest(requestUrl, initiatorUrl) {
  if (!initiatorUrl) return false;
  try {
    const reqHostname = new URL(requestUrl).hostname;
    const initHostname = new URL(initiatorUrl).hostname;
    // Check if it's not the same domain or a subdomain
    return !reqHostname.endsWith(initHostname);
  } catch (e) {
    return false;
  }
}

function isSensitivePath(path) {
  const sensitiveKeywords = [
    'admin', 'user', 'account', 'profile', 'settings', 'wallet', 'billing',
    'export', 'import', 'download', 'upload', 'delete', 'update', 'edit', 'create',
    'private', 'sensitive', 'internal', 'debug'
  ];
  const lowerPath = path.toLowerCase();
  return sensitiveKeywords.some(keyword => lowerPath.includes(`/${keyword}`));
}

async function performRepeaterRequest(rawRequest) {
  try {
    // Parse the raw HTTP request
    const lines = rawRequest.split('\n');
    const requestLine = lines[0].split(' ');
    const method = requestLine[0];
    const url = requestLine[1];

    const headers = new Headers();
    let bodyIndex = -1;
    for (let i = 1; i < lines.length; i++) {
      if (lines[i] === '') {
        bodyIndex = i + 1;
        break;
      }
      const headerParts = lines[i].split(': ');
      headers.set(headerParts[0], headerParts[1]);
    }

    const body = bodyIndex !== -1 ? lines.slice(bodyIndex).join('\n') : undefined;

    // Perform the fetch request
    const response = await fetch(url, {
      method: method,
      headers: headers,
      body: body,
    });

    // Format the raw HTTP response
    let rawResponse = `HTTP/1.1 ${response.status} ${response.statusText}\n`;
    response.headers.forEach((value, name) => {
      rawResponse += `${name}: ${value}\n`;
    });
    rawResponse += '\n';
    rawResponse += await response.text();

    return { rawResponse: rawResponse };

  } catch (error) {
    console.error('Hera Repeater Error:', error);
    return { error: error.message };
  }
}

// --- Session Manager ---
const sessionTracker = {
  currentSessions: new Map(),
  domainToSession: new Map(), // Maps domains to session IDs
  tabSessions: new Map(), // Maps tab IDs to sets of session IDs
  authenticatedDomains: new Set(), // New: Track domains with active sessions
  temporalWindow: 30000, // 30 seconds for temporal correlation

  // Smart session correlation based on multiple factors
  getOrCreateSession(domain, service, requestContext = {}) {
    const { tabId, initiator, timestamp, authHeaders } = requestContext;
    
    // 1. Check for existing session correlation
    const correlatedSession = this.findCorrelatedSession(domain, service, requestContext);
    
    if (correlatedSession) {
      this.addDomainToSession(correlatedSession.id, domain);
      console.log(`Correlated ${domain} with existing ${service} session (${correlatedSession.correlationReason})`);
      return correlatedSession;
    }
    
    // 2. Create new session with smart grouping
    const sessionId = this.generateSessionId(domain, timestamp);
    const sessionInfo = {
      id: sessionId,
      primaryDomain: domain,
      domains: new Set([domain]),
      service: service,
      startTime: timestamp || Date.now(),
      lastActivity: timestamp || Date.now(),
      eventCount: 1,
      tabIds: new Set(tabId ? [tabId] : []),
      initiators: new Set(initiator ? [initiator] : []),
      authTokenHashes: new Set(), // For auth correlation
      ecosystem: this.detectEcosystem(domain, service),
      correlationFactors: []
    };
    
    this.currentSessions.set(sessionId, sessionInfo);
    this.domainToSession.set(domain, sessionId);
    
    if (tabId) {
      if (!this.tabSessions.has(tabId)) {
        this.tabSessions.set(tabId, new Set());
      }
      this.tabSessions.get(tabId).add(sessionId);
    }
    
    console.log(`New session started for ${service} (${domain}) - Session ID: ${sessionId}`);
    return sessionInfo;
  },
  
  // Multi-factor session correlation
  findCorrelatedSession(domain, service, context) {
    const { tabId, initiator, timestamp, authHeaders } = context;
    const now = timestamp || Date.now();
    
    // Get all active sessions for this service
    const serviceSessions = Array.from(this.currentSessions.values())
      .filter(session => session.service === service && (now - session.lastActivity) < this.temporalWindow);
    
    for (const session of serviceSessions) {
      const correlationScore = this.calculateCorrelationScore(session, domain, context);
      
      if (correlationScore.score > 0.7) { // High confidence threshold
        session.correlationReason = correlationScore.reasons.join(', ');
        return session;
      }
    }
    
    return null;
  },
  
  // Calculate correlation score based on multiple factors
  calculateCorrelationScore(session, domain, context) {
    const { tabId, initiator, timestamp, authHeaders } = context;
    let score = 0;
    const reasons = [];
    
    // 1. Tab correlation (strongest signal)
    if (tabId && session.tabIds.has(tabId)) {
      score += 0.4;
      reasons.push('same tab');
    }
    
    // 2. Temporal proximity
    const timeDiff = Math.abs((timestamp || Date.now()) - session.lastActivity);
    if (timeDiff < 5000) { // 5 seconds
      score += 0.3;
      reasons.push('temporal proximity');
    } else if (timeDiff < 30000) { // 30 seconds
      score += 0.1;
      reasons.push('recent activity');
    }
    
    // 3. Initiator chain correlation
    if (initiator && session.initiators.has(initiator)) {
      score += 0.2;
      reasons.push('same initiator');
    }
    
    // 4. Ecosystem correlation (AWS buckets, Google services, etc.)
    if (this.isEcosystemRelated(domain, session)) {
      score += 0.2;
      reasons.push('ecosystem correlation');
    }
    
    // 5. Domain pattern correlation
    if (this.isDomainPatternRelated(domain, session)) {
      score += 0.15;
      reasons.push('domain pattern');
    }
    
    // 6. Auth token correlation (if available)
    if (authHeaders && this.hasAuthCorrelation(authHeaders, session)) {
      score += 0.25;
      reasons.push('auth correlation');
    }
    
    return { score, reasons };
  },
  
  // Detect service ecosystems (AWS, GCP, Azure, etc.)
  detectEcosystem(domain, service) {
    const ecosystems = {
      'AWS': ['amazonaws.com', 's3.amazonaws.com', 'cloudfront.net', 'aws.amazon.com'],
      'Google Cloud': ['googleapis.com', 'googleusercontent.com', 'gstatic.com', 'storage.googleapis.com'],
      'Microsoft Azure': ['azure.com', 'azurewebsites.net', 'blob.core.windows.net', 'microsoftonline.com'],
      'Cloudflare': ['cloudflare.com', 'cf-assets.com', 'workers.dev'],
      'Fastly': ['fastly.com', 'fastlylb.net'],
      'Proton': ['proton.me', 'protonmail.com', 'protondrive.com', 'docs.proton.me']
    };
    
    for (const [ecosystem, domains] of Object.entries(ecosystems)) {
      if (domains.some(d => domain.includes(d))) {
        return ecosystem;
      }
    }
    
    return service;
  },
  
  // Check if domains are ecosystem-related
  isEcosystemRelated(domain, session) {
    if (session.ecosystem === 'AWS') {
      return domain.includes('amazonaws.com') || domain.includes('cloudfront.net');
    }
    if (session.ecosystem === 'Google Cloud') {
      return domain.includes('googleapis.com') || domain.includes('googleusercontent.com') || domain.includes('gstatic.com');
    }
    if (session.ecosystem === 'Proton') {
      return domain.includes('proton.me') || domain.includes('protonmail.com') || domain.includes('protondrive.com');
    }
    
    return false;
  },
  
  // Check domain pattern relationships
  isDomainPatternRelated(domain, session) {
    const sessionDomains = Array.from(session.domains);
    
    // Check for subdomain relationships
    for (const sessionDomain of sessionDomains) {
      const baseDomain = this.extractBaseDomain(sessionDomain);
      if (domain.includes(baseDomain) || this.extractBaseDomain(domain) === baseDomain) {
        return true;
      }
    }
    
    return false;
  },
  
  // Extract base domain (e.g., "bucket.s3.amazonaws.com" -> "amazonaws.com")
  extractBaseDomain(domain) {
    const parts = domain.split('.');
    if (parts.length >= 2) {
      return parts.slice(-2).join('.');
    }
    return domain;
  },
  
  // Check for authentication correlation
  hasAuthCorrelation(authHeaders, session) {
    // This would compare auth token hashes or patterns
    // Implementation depends on how you want to handle auth correlation
    return false; // Placeholder
  },
  
  // Add domain to existing session
  addDomainToSession(sessionId, domain) {
    const session = this.currentSessions.get(sessionId);
    if (session) {
      session.domains.add(domain);
      session.lastActivity = Date.now();
      session.eventCount++;
      this.domainToSession.set(domain, sessionId);
    }
  },
  
  findActiveSessionForService(service) {
    const now = Date.now();
    const maxAge = 30 * 60 * 1000; // 30 minutes
    
    for (const [domain, session] of this.currentSessions.entries()) {
      if (session.service === service && (now - session.lastActivity) < maxAge) {
        return session;
      }
    }
    return null;
  },
  
  identifyService(domain) {
    const lowerDomain = domain.toLowerCase();
    
    // Enhanced service detection with complex patterns and CDN mapping
    const servicePatterns = {
      'Microsoft': {
        // Core Microsoft domains
        primary: ['microsoft.com', 'outlook.com', 'office.com', 'sharepoint.com', 'onedrive.com', 'teams.microsoft.com'],
        // Microsoft authentication infrastructure
        auth: ['login.microsoftonline.com', 'login.live.com', 'account.microsoft.com'],
        // Microsoft CDNs and services
        cdn: ['msocdn.com', 'sharepointonline.com', 'officeapps.live.com', 'office365.com'],
        // Microsoft Azure/cloud infrastructure
        azure: ['windows.net', 'azure.com', 'azureedge.net', 'azurewebsites.net'],
        // Microsoft S3-like services and CDNs
        storage: ['blob.core.windows.net', 'sharepoint.com', 'onedrive.live.com'],
        // Third-party CDNs used by Microsoft
        thirdParty: ['amazonaws.com', 's3.amazonaws.com', 'cloudfront.net'],
        // Check function
        check: (domain) => {
          // Direct matches
          if (servicePatterns.Microsoft.primary.some(d => domain.includes(d))) return true;
          if (servicePatterns.Microsoft.auth.some(d => domain.includes(d))) return true;
          if (servicePatterns.Microsoft.cdn.some(d => domain.includes(d))) return true;
          if (servicePatterns.Microsoft.azure.some(d => domain.includes(d))) return true;
          if (servicePatterns.Microsoft.storage.some(d => domain.includes(d))) return true;
          
          // Special handling for Microsoft content on AWS/CDNs
          if (domain.includes('amazonaws.com') || domain.includes('s3.amazonaws.com')) {
            // Check if the path or subdomain suggests Microsoft
            return domain.includes('microsoft') || domain.includes('office') || 
                   domain.includes('sharepoint') || domain.includes('onedrive') ||
                   domain.includes('teams') || domain.includes('outlook');
          }
          
          // Microsoft tenant patterns (e.g., company.sharepoint.com)
          if (domain.match(/\w+\.sharepoint\.com/) || domain.match(/\w+\.onmicrosoft\.com/)) return true;
          
          return false;
        }
      },
      
      'Google': {
        primary: ['google.com', 'gmail.com', 'youtube.com', 'drive.google.com', 'docs.google.com'],
        auth: ['accounts.google.com', 'oauth.google.com'],
        cdn: ['googleapis.com', 'googleusercontent.com', 'gstatic.com', 'googlevideo.com'],
        check: (domain) => {
          return servicePatterns.Google.primary.some(d => domain.includes(d)) ||
                 servicePatterns.Google.auth.some(d => domain.includes(d)) ||
                 servicePatterns.Google.cdn.some(d => domain.includes(d));
        }
      },
      
      'Proton': {
        primary: ['proton.me', 'protonmail.com', 'protonvpn.com', 'protoncalendar.com', 'protondrive.com'],
        subdomains: ['mail.proton.me', 'drive.proton.me', 'account.proton.me', 'calendar.proton.me', 'docs.proton.me'],
        check: (domain) => {
          return servicePatterns.Proton.primary.some(d => domain.includes(d)) ||
                 servicePatterns.Proton.subdomains.some(d => domain.includes(d));
        }
      },
      
      'Claude/Anthropic': {
        primary: ['claude.ai', 'anthropic.com'],
        cdn: ['claude-assets.com', 'anthropic-cdn.com'],
        check: (domain) => {
          return servicePatterns['Claude/Anthropic'].primary.some(d => domain.includes(d)) ||
                 servicePatterns['Claude/Anthropic'].cdn.some(d => domain.includes(d));
        }
      },
      
      'GitHub': {
        primary: ['github.com', 'github.io', 'githubusercontent.com', 'githubassets.com'],
        check: (domain) => servicePatterns.GitHub.primary.some(d => domain.includes(d))
      },
      
      'Amazon/AWS': {
        primary: ['amazon.com', 'aws.amazon.com'],
        cdn: ['amazonaws.com', 'cloudfront.net'],
        check: (domain) => {
          // Only classify as Amazon if it's clearly Amazon services, not Microsoft on AWS
          if (domain.includes('microsoft') || domain.includes('office') || 
              domain.includes('sharepoint') || domain.includes('onedrive')) {
            return false; // This should be classified as Microsoft
          }
          return servicePatterns['Amazon/AWS'].primary.some(d => domain.includes(d)) ||
                 servicePatterns['Amazon/AWS'].cdn.some(d => domain.includes(d));
        }
      },
      
      'Facebook/Meta': {
        primary: ['facebook.com', 'instagram.com', 'whatsapp.com', 'meta.com'],
        cdn: ['fbcdn.net', 'facebook.net'],
        check: (domain) => {
          return servicePatterns['Facebook/Meta'].primary.some(d => domain.includes(d)) ||
                 servicePatterns['Facebook/Meta'].cdn.some(d => domain.includes(d));
        }
      },
      
      'Apple': {
        primary: ['apple.com', 'icloud.com', 'me.com', 'mac.com'],
        check: (domain) => servicePatterns.Apple.primary.some(d => domain.includes(d))
      },
      
      'Slack': {
        primary: ['slack.com', 'slack-edge.com', 'slack-imgs.com'],
        check: (domain) => servicePatterns.Slack.primary.some(d => domain.includes(d))
      },
      
      'Zoom': {
        primary: ['zoom.us', 'zoom.com', 'zoomgov.com'],
        check: (domain) => servicePatterns.Zoom.primary.some(d => domain.includes(d))
      },
      
      'Dropbox': {
        primary: ['dropbox.com', 'dropboxapi.com', 'dropboxusercontent.com'],
        check: (domain) => servicePatterns.Dropbox.primary.some(d => domain.includes(d))
      },
      
      'Twitter/X': {
        primary: ['twitter.com', 'x.com', 'twimg.com'],
        shortener: ['t.co'],
        check: (domain) => {
          // Exact matches for main domains
          if (servicePatterns['Twitter/X'].primary.some(d => domain.includes(d))) return true;
          // Exact match for t.co to avoid false positives
          if (domain === 't.co' || domain.endsWith('.t.co')) return true;
          return false;
        }
      },
      
      'LinkedIn': {
        primary: ['linkedin.com', 'licdn.com'],
        cdn: ['media.licdn.com', 'static.licdn.com'],
        check: (domain) => {
          return servicePatterns.LinkedIn.primary.some(d => domain.includes(d)) ||
                 servicePatterns.LinkedIn.cdn.some(d => domain.includes(d));
        }
      },

      'PayPal': {
        primary: ['paypal.com', 'paypal.me'],
        cdn: ['paypalobjects.com'],
        check: (domain) => {
          return servicePatterns.PayPal.primary.some(d => domain.includes(d)) ||
                 servicePatterns.PayPal.cdn.some(d => domain.includes(d));
        }
      },

      'OpenAI': {
        primary: ['openai.com', 'chatgpt.com'],
        cdn: ['oaistatic.com', 'oaiusercontent.com'],
        check: (domain) => {
          return servicePatterns.OpenAI.primary.some(d => domain.includes(d)) ||
                 servicePatterns.OpenAI.cdn.some(d => domain.includes(d));
        }
      },
      
      'Discord': {
        primary: ['discord.com', 'discordapp.com', 'discord.gg'],
        cdn: ['discordapp.net', 'discord.media'],
        check: (domain) => {
          return servicePatterns.Discord.primary.some(d => domain.includes(d)) ||
                 servicePatterns.Discord.cdn.some(d => domain.includes(d));
        }
      }
    };
    
    // Check each service pattern
    for (const [serviceName, pattern] of Object.entries(servicePatterns)) {
      if (pattern.check(lowerDomain)) {
        return serviceName;
      }
    }

    // Special debugging for LinkedIn
    if (lowerDomain.includes('linkedin')) {
      console.log(`🐛 LinkedIn detection: ${lowerDomain} -> should be LinkedIn but wasn't caught`);
    }
    
    // Fallback: try to extract a meaningful name from domain
    const domainParts = lowerDomain.split('.');
    const mainDomain = domainParts.length >= 2 ? domainParts[domainParts.length - 2] : domainParts[0];
    
    // Handle common cases
    const fallbackMap = {
      'amazonaws': 'AWS/Unknown',
      's3': 'AWS/Unknown', 
      'cloudfront': 'AWS/Unknown',
      'azureedge': 'Microsoft',
      'azurewebsites': 'Microsoft',
      'googleapis': 'Google',
      'gstatic': 'Google'
    };
    
    if (fallbackMap[mainDomain]) {
      return fallbackMap[mainDomain];
    }
    
    // Final fallback: capitalize first letter of main domain
    return mainDomain.charAt(0).toUpperCase() + mainDomain.slice(1);
  },
  
  generateSessionId(domain) {
    const service = this.identifyService(domain).toLowerCase();
    const timestamp = Date.now();
    const random = Math.random().toString(36).substr(2, 6);
    return `${service}_${timestamp}_${random}`;
  },
  
  cleanupOldSessions() {
    const now = Date.now();
    const maxAge = 30 * 60 * 1000; // 30 minutes
    
    for (const [domain, session] of this.currentSessions.entries()) {
      if (now - session.lastActivity > maxAge) {
        console.log(`Cleaning up inactive session for ${session.service}`);
        this.currentSessions.delete(domain);
      }
    }
  }
};

// Check if a domain is a known legitimate service (don't scan these)
function isKnownLegitimateService(hostname) {
  const legitimateServices = [
    // Major tech companies
    'google.com', 'googleapis.com', 'googleusercontent.com', 'gstatic.com',
    'microsoft.com', 'microsoftonline.com', 'office.com', 'office365.com',
    'apple.com', 'icloud.com', 'me.com',
    'amazon.com', 'amazonaws.com', 'cloudfront.net',
    'facebook.com', 'instagram.com', 'whatsapp.com',
    'twitter.com', 'x.com',
    
    // Privacy-focused services
    'proton.me', 'protonmail.com', 'protonvpn.com', 'protondrive.com', 'docs.proton.me',
    
    // Development platforms
    'github.com', 'gitlab.com', 'bitbucket.org',
    'claude.ai', 'anthropic.com',
    'openai.com', 'chatgpt.com',
    
    // CDNs and infrastructure
    'cloudflare.com', 'fastly.com', 'jsdelivr.net', 'unpkg.com',
    'cdn.office.net', 'res.cdn.office.net', 'shell.cdn.office.net',
    'aadcdn.msauth.net', 'res.office365.com',
    
    // Known legitimate domains
    'cybermonkey.net.au', // User's own domain
    
    // Common legitimate services
    'slack.com', 'zoom.us', 'zoom.com',
    'dropbox.com', 'box.com',
    'linkedin.com', 'discord.com',
    'netflix.com', 'spotify.com',
    'paypal.com', 'stripe.com'
  ];
  
  const lowerHostname = hostname.toLowerCase();
  
  // Check exact matches and subdomains
  return legitimateServices.some(service => 
    lowerHostname === service || 
    lowerHostname.endsWith('.' + service)
  );
}

// Clean up old sessions every 10 minutes
setInterval(() => sessionTracker.cleanupOldSessions(), 10 * 60 * 1000);

// (Removed duplicate decodeRequestBody - already defined at line 11)

// Startup data recovery check
chrome.runtime.onStartup.addListener(async () => {
  console.log('Hera extension started - checking for data recovery...');
  
  // Check if we have a lot of stored data that needs exporting
  const stored = await chrome.storage.local.get(['heraSessions']);
  const sessions = stored.heraSessions || [];
  
  if (sessions.length >= 900) {
    console.log(`Found ${sessions.length} stored sessions - auto-exporting for safety...`);
    await heraStore.autoExportAndCleanup();
  }
  
  console.log(`Hera ready - ${sessions.length} sessions loaded`);
});

// Helper to decode ArrayBuffer

// Also run on extension install/update
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'startup' || details.reason === 'install') {
    console.log('Hera extension installed/updated');
    
    // Set default configuration if not exists
    const stored = await chrome.storage.local.get(['heraConfig']);
    if (!stored.heraConfig) {
      await chrome.storage.local.set({
        heraConfig: {
          syncEndpoint: null,
          riskThreshold: 50,
          enableRealTimeAlerts: true,
          autoExportEnabled: true,
          autoExportThreshold: 950
        }
      });
      console.log('Default configuration set');
    }
  }
});

// --- Debugger Logic for Response Body Capture ---

chrome.debugger.onEvent.addListener((source, method, params) => {
  if (method === "Network.responseReceived") {
    const requestData = authRequests.get(params.requestId);
    if (requestData) {
      requestData.responseDetails = params;
    }
  } else if (method === "Network.loadingFinished") {
    const requestData = authRequests.get(params.requestId);
    if (requestData && requestData.responseDetails) {
      const debuggee = { tabId: requestData.tabId };
      if (debugTargets.has(requestData.tabId)) { // Ensure we are still debugging this tab
        chrome.debugger.sendCommand(
          debuggee,
          "Network.getResponseBody",
          { requestId: params.requestId },
          (response) => {
            if (chrome.runtime.lastError) {
              // This can happen if the request has no body, so we can often ignore it.
            } else if (response) {
              let body = response.body;
              if (response.base64Encoded) {
                try {
                  body = atob(response.body);
                } catch (e) {
                  console.warn("Failed to decode base64 response body", e);
                }
              }
              requestData.responseBody = body;
            }

            // THIS IS THE NEW FINAL SAVE POINT
            // Now that we have the response body (or know there isn't one), save the complete request.
            heraStore.storeSession(requestData);
            updateBadge();
          }
        );
      }
    }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  if (debugTargets.has(tabId)) {
    chrome.debugger.detach({ tabId: tabId }, () => {
      debugTargets.delete(tabId);
      console.log(`Debugger detached from tab ${tabId}`);
    });
  }
});

// (Removed duplicate attachDebugger - already defined at line 110)

chrome.tabs.onCreated.addListener((tab) => {
  if (tab.id) {
    attachDebugger(tab.id);
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading' && tab.url) {
    attachDebugger(tabId);
  }
});

// Attach to all existing tabs on startup
chrome.tabs.query({}, (tabs) => {
  for (const tab of tabs) {
    if (tab.id && tab.url && !tab.url.startsWith('chrome://')) {
      attachDebugger(tab.id);
    }
  }
});

chrome.webRequest.onBeforeRequest.addListener(
  async (details) => {
    const reqUrl = new URL(details.url);

    // Skip static assets that are definitely not auth-related
    const urlLower = details.url.toLowerCase();
    const staticAssetPatterns = [
        '.css', '.js', '.woff', '.woff2', '.ttf', '.eot', '.svg', '.png', '.jpg', '.jpeg', '.gif', '.ico',
        '.webp', '.mp4', '.webm', '.mp3', '.wav', '.pdf', '.zip', '.tar', '.gz',
        '/static/', '/_next/static/', '/assets/', '/public/', '/cdn-cgi/challenge-platform/',
        'challenge-platform/scripts', 'challenge-platform/h/g/scripts'
    ];

    // Skip if it's clearly a static asset
    if (staticAssetPatterns.some(pattern => urlLower.includes(pattern))) {
        return; // Don't process static assets
    }

    // Capture request evidence
    const requestEvidence = evidenceCollector.captureRequest(details.requestId, {
      url: details.url,
      method: details.method,
      requestHeaders: details.requestHeaders,
      requestBody: details.requestBody,
      type: details.type,
      initiator: details.initiator,
      tabId: details.tabId,
      timestamp: details.timeStamp
    });
    
    // Check for OAuth/OIDC/SAML/SCIM endpoints, logout flows, and auth-related endpoints
    const isAuthRelated = reqUrl.pathname.includes('oauth') || 
        reqUrl.pathname.includes('authorize') || 
        reqUrl.pathname.includes('token') ||
        reqUrl.pathname.includes('userinfo') ||
        reqUrl.pathname.includes('login') ||
        reqUrl.pathname.includes('signin') ||
        reqUrl.pathname.includes('logout') ||
        reqUrl.pathname.includes('signout') ||
        reqUrl.pathname.includes('auth') ||
        reqUrl.pathname.includes('sso') ||
        reqUrl.pathname.includes('saml') ||
        reqUrl.pathname.includes('oidc') ||
        reqUrl.pathname.includes('scim') ||
        reqUrl.pathname.includes('connect') ||
        reqUrl.pathname.includes('federation') ||
        reqUrl.pathname.includes('identity') ||
        reqUrl.pathname.includes('refresh') ||
        reqUrl.pathname.includes('revoke') ||
        reqUrl.pathname.includes('jwks') ||
        reqUrl.pathname.includes('.well-known') ||
        reqUrl.pathname.includes('discovery') ||
        reqUrl.pathname.includes('metadata') ||
        reqUrl.pathname.includes('sessions') ||
        reqUrl.hostname.includes('login.') ||
        reqUrl.hostname.includes('auth.') ||
        reqUrl.hostname.includes('accounts.') ||
        reqUrl.hostname.includes('sso.') ||
        reqUrl.hostname.includes('identity.') ||
        reqUrl.hostname.includes('oauth.') ||
        reqUrl.hostname.includes('oidc.') ||
        reqUrl.hostname.includes('saml.') ||
        reqUrl.hostname.includes('adfs.') ||
        reqUrl.hostname.includes('federation.') ||
        reqUrl.hostname.includes('signin.') ||
        reqUrl.hostname.includes('signup.') ||
        reqUrl.hostname.includes('register.') ||
        reqUrl.hostname.includes('profile.') ||
        (reqUrl.pathname.includes('/api/') && (
            reqUrl.pathname.includes('user') ||
            reqUrl.pathname.includes('profile') ||
            reqUrl.pathname.includes('account') ||
            reqUrl.pathname.includes('session') ||
            reqUrl.pathname.includes('auth') ||
            reqUrl.pathname.includes('login') ||
            reqUrl.pathname.includes('token') ||
            reqUrl.pathname.includes('organizations') ||
            reqUrl.pathname.includes('sync') ||
            reqUrl.pathname.includes('mcp')
        ));

    // Also check for authentication headers in any request
    const hasAuthHeaders = details.requestHeaders && details.requestHeaders.some(header => 
      header.name.toLowerCase() === 'authorization' || 
      header.name.toLowerCase() === 'x-api-key' ||
      header.name.toLowerCase() === 'x-auth-token' ||
      header.name.toLowerCase().includes('auth')
    );

    // Minimal debug logging (only for important auth requests)
    if ((isAuthRelated || hasAuthHeaders) && !urlLower.includes('/_next/') && !urlLower.includes('/cdn-cgi/') && !urlLower.includes('/api/auth/v4/sessions/local')) {
      const url = new URL(details.url);
      console.log(`Auth request: ${details.method} ${url.hostname}${url.pathname}`);
      // Malicious Extension Detection
      if (isExtensionRequest(details.initiator) && isThirdPartyRequest(details.url, details.documentUrl)) {
        const hasCredentials = details.requestBody?.raw?.some(part => {
            try {
                const decoded = new TextDecoder().decode(new Uint8Array(Object.values(part.bytes)));
                return decoded.includes('password=') || decoded.includes('pass=');
            } catch (e) { return false; }
        });

        if (hasCredentials) {
            const finding = {
                type: 'POTENTIAL_CREDENTIAL_THEFT',
                severity: 'CRITICAL',
                message: 'An extension is sending password data to a third-party domain.',
                exploitation: `The extension with initiator ${details.initiator} may be stealing credentials. Disable it immediately.`
            };
            if (!details.metadata) details.metadata = {};
            if (!details.metadata.authAnalysis) details.metadata.authAnalysis = { issues: [] };
            if (!details.metadata.authAnalysis.issues) details.metadata.authAnalysis.issues = [];
            details.metadata.authAnalysis.issues.push(finding);
        }
      }

      // Apply security validation
      const sanitizedURL = SecurityValidation.sanitizeURL(details.url);
      if (!sanitizedURL) {
          console.warn('Invalid URL blocked:', details.url);
          return;
      }

      // Rate limiting check
      const clientId = details.tabId || 'unknown';
      if (!SecurityValidation.rateLimiter.checkRateLimit(clientId)) {
          console.warn('Rate limit exceeded for client:', clientId);
          return;
      }

      const requestId = details.requestId;

      // Get hostname and determine service
      const hostname = new URL(details.url).hostname;
      const service = sessionTracker.identifyService(hostname);
      const sessionInfo = sessionTracker.getOrCreateSession(hostname, service, {
          tabId: details.tabId,
          initiator: details.initiator,
          timestamp: Date.now()
      });

      const requestData = {
          id: requestId,
          url: details.url,
          method: details.method,
          type: details.type,
          timestamp: new Date().toISOString(),
          requestHeaders: null, // Will be populated by onBeforeSendHeaders
          initiator: details.initiator,
          tabId: details.tabId,
          requestBody: decodeRequestBody(details.requestBody),
          responseHeaders: null, // Will be populated by onHeadersReceived
          statusCode: null, // Will be populated by onCompleted
          responseBody: null, // Will be populated by debugger
          service: service,
          sessionId: sessionInfo.id,
          sessionInfo: sessionInfo,
          metadata: {
              // Network metadata
              ip: details.ip || null,
              fromCache: details.fromCache || false,

              // URL analysis
              urlParts: analyzeUrl(details.url),

              // Authentication flow metadata
              authFlow: analyzeAuthFlow(details.url, details.requestBody),

              // OAuth consent and authorization analysis
              consentAnalysis: analyzeOAuthConsent(details.url, details.requestBody),

              // DNS and infrastructure analysis
              dnsIntelligence: null, // Will be populated asynchronously
              cdnAnalysis: null, // Will be populated from response headers

              // Full network chain analysis
              networkChain: {
                  primaryIP: details.ip || null,
                  redirectChain: [], // Will track all redirect IPs
                  dnsChain: null, // Full DNS resolution chain
                  certificateChain: null // Certificate chain IPs
              },

              // Security context
              securityContext: {
                  isSecure: details.url.startsWith('https://'),
                  hasCredentials: false, // Will be updated when headers are available
                  crossOrigin: isCrossOrigin(details.initiator, details.url)
              },

              // Port and authentication analysis
              portAnalysis: heraPortAuthAnalyzer.analyzePortSecurity(details.url),
              authTypeAnalysis: heraPortAuthAnalyzer.detectAuthType({
                  url: details.url,
                  method: details.method,
                  requestHeaders: [],
                  requestBody: details.requestBody
              }),
              ldapAnalysis: heraPortAuthAnalyzer.detectLDAP({
                  url: details.url,
                  requestBody: details.requestBody,
                  requestHeaders: []
              }),

              // Timing data
              timing: {
                  startTime: Date.now(),
                  endTime: null
              },

              // Browser context (will be populated from tab info)
              browserContext: null
          }
      };

      // Store request data
      authRequests.set(requestId, requestData);

      // Ensure debugger is attached for this tab
      if (details.tabId > 0) {
          attachDebugger(details.tabId);
      }

      // Reduced logging - only log every 10th request to reduce spam
      if (authRequests.size % 10 === 0) {
          const url = new URL(details.url);
          console.log(`Stored ${authRequests.size} auth requests (latest: ${requestData.method} ${url.hostname})`);
      }

      // Gather DNS intelligence asynchronously
      gatherDNSIntelligence(details.url, requestId);

      // Update badge
      updateBadge();
    }
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

// Listen for request headers
chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const requestData = authRequests.get(details.requestId);
    if (requestData) {
      requestData.requestHeaders = details.requestHeaders;
      console.log(`Captured ${details.requestHeaders?.length || 0} request headers for ${new URL(details.url).hostname}`);
      
      // Debug: Log some key headers
      if (details.requestHeaders && details.requestHeaders.length > 0) {
        const authHeaders = details.requestHeaders.filter(h => 
          h.name.toLowerCase().includes('auth') || 
          h.name.toLowerCase() === 'cookie' ||
          h.name.toLowerCase() === 'authorization'
        );
        if (authHeaders.length > 0) {
          console.log(`Found ${authHeaders.length} auth-related headers:`, authHeaders.map(h => h.name).join(', '));
        }
      }
      
      // Analyze headers for additional metadata
      if (details.requestHeaders) {
        const headerAnalysis = analyzeRequestHeaders(details.requestHeaders);
        // Ensure metadata structure exists
        if (!requestData.metadata) {
          requestData.metadata = {};
        }
        if (!requestData.metadata.securityContext) {
          requestData.metadata.securityContext = {
            isSecure: details.url.startsWith('https://'),
            hasCredentials: false,
            crossOrigin: false
          };
        }
        requestData.metadata.headerAnalysis = headerAnalysis;
        requestData.metadata.securityContext.hasCredentials = headerAnalysis.hasAuthHeaders;

        // Run comprehensive authentication protocol analysis
        if (heraAuthDetector) {
          try {
            const authAnalysis = heraAuthDetector.analyzeRequest({
              url: details.url,
              method: details.method,
              requestHeaders: details.requestHeaders,
              requestBody: requestData.requestBody
            });

            // Store the full analysis results
            requestData.metadata.authAnalysis = authAnalysis;
            requestData.metadata.authAnalysis.riskCategory = heraAuthDetector.getRiskCategory(authAnalysis.riskScore);

            // Handle OAuth2 callback tracking
            if (authAnalysis.protocol === 'OAuth2') {
              const url = new URL(details.url);
              const isCallback = url.searchParams.has('code') || url.searchParams.has('error');

              if (isCallback) {
                // Track callback and check for flow validation issues
                const callbackIssues = heraAuthDetector.flowTracker.trackCallback({
                  url: details.url,
                  method: details.method,
                  requestHeaders: details.requestHeaders
                });

                if (callbackIssues && callbackIssues.length > 0) {
                  // Add callback validation issues to the analysis
                  authAnalysis.issues.push(...callbackIssues);
                  // Recalculate risk score with new issues
                  authAnalysis.riskScore = heraAuthDetector.calculateRiskScore(authAnalysis.issues);
                  authAnalysis.recommendation = heraAuthDetector.getRecommendation(authAnalysis.riskScore);
                }
              }
            }

            // Run enhanced security analysis for passwords, MFA, and passkeys
            try {
              const authFlow = {
                hasPasswordInURL: new URL(details.url).searchParams.toString().toLowerCase().includes('password'),
                hasUnencryptedTransmission: !details.url.startsWith('https://'),
                authType: authAnalysis.protocol,
                service: new URL(details.url).hostname
              };

              const securityFindings = heraAuthSecurityAnalyzer.analyzeAuthenticationSecurity(requestData, authFlow);

              if (securityFindings.length > 0) {
                // Add security findings to the existing issues
                if (!requestData.metadata.authAnalysis.issues) {
                  requestData.metadata.authAnalysis.issues = [];
                }
                requestData.metadata.authAnalysis.issues.push(...securityFindings);

                // Update risk score based on security findings
                const securityRiskBonus = securityFindings.reduce((total, finding) => {
                  switch (finding.severity) {
                    case 'CRITICAL': return total + 30;
                    case 'HIGH': return total + 20;
                    case 'MEDIUM': return total + 10;
                    default: return total + 5;
                  }
                }, 0);

                requestData.metadata.authAnalysis.riskScore += securityRiskBonus;
                requestData.metadata.authAnalysis.riskCategory = heraAuthDetector.getRiskCategory(requestData.metadata.authAnalysis.riskScore);

                // Show critical security alerts immediately
                const criticalFindings = securityFindings.filter(f => f.severity === 'CRITICAL');
                if (criticalFindings.length > 0) {
                  showAuthSecurityAlert(criticalFindings[0], details.url);
                }
              }
            } catch (securityAnalysisError) {
              console.error('Auth security analysis failed:', securityAnalysisError);
            }

            // Log significant security findings
            if (authAnalysis.riskScore > 50) {
              console.log(`Authentication Security Analysis for ${new URL(details.url).hostname}:`, {
                protocol: authAnalysis.protocol,
                riskScore: authAnalysis.riskScore,
                issues: authAnalysis.issues.length,
                recommendation: authAnalysis.recommendation
              });

              // Alert on critical issues
              if (authAnalysis.riskScore >= 80) {
                const criticalIssues = authAnalysis.issues.filter(i => i.severity === 'CRITICAL');
                if (criticalIssues.length > 0) {
                  console.warn(`CRITICAL Authentication Issues Detected:`, criticalIssues);
                }
              }
            }
          } catch (error) {
            console.warn('Authentication analysis failed:', error);
          }
        }
      }
      authRequests.set(details.requestId, requestData);
    }
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders", "extraHeaders"]
);

// Listen for response headers
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    // Capture response evidence using EvidenceCollector
    const responseEvidence = evidenceCollector.captureResponse(
      details.requestId,
      details.responseHeaders,
      null, // Response body will be captured separately
      details.statusCode,
      { url: details.url, method: details.method }
    );

    const requestData = authRequests.get(details.requestId);
    if (requestData) {
      requestData.responseHeaders = details.responseHeaders;
      requestData.statusCode = details.statusCode;

      // Add evidence-based analysis to metadata
      if (!requestData.metadata) requestData.metadata = {};
      requestData.metadata.evidencePackage = responseEvidence;

      console.log(`Captured ${details.responseHeaders?.length || 0} response headers for ${details.url} (${details.statusCode})`);
      console.log(`Evidence analysis: HSTS=${responseEvidence.evidence.hstsPresent.present}, Security Headers=${responseEvidence.evidence.securityHeaders.count}`);

      // Analyze response headers for security info (legacy)
      if (details.responseHeaders) {
        const responseAnalysis = analyzeResponseHeaders(details.responseHeaders);
        requestData.metadata.responseAnalysis = responseAnalysis;
      }

      authRequests.set(details.requestId, requestData);
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders", "extraHeaders"]
);

// Listen for redirect responses to track the full chain
chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    const requestData = authRequests.get(details.requestId);
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
      authRequests.set(details.requestId, requestData);
    }
  },
  { urls: ["<all_urls>"] }
);

// Listen for completed requests to capture response data
chrome.webRequest.onCompleted.addListener(
  async (details) => {
    const requestData = authRequests.get(details.requestId);
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
      requestData.metadata.timing.duration = requestData.metadata.timing.endTime - requestData.metadata.timing.startTime;
      
      // Analyze response headers
      const responseAnalysis = analyzeResponseHeaders(details.responseHeaders);
      requestData.metadata.responseAnalysis = responseAnalysis;
      
      // Analyze authentication failures and errors
      const authFailureAnalysis = analyzeAuthFailure(details.statusCode, details.responseHeaders, requestData.url);
      requestData.metadata.authFailureAnalysis = authFailureAnalysis;
      
      // Analyze CDN and infrastructure from response headers
      const cdnAnalysis = analyzeCDNFromHeaders(details.responseHeaders, requestData.url);
      requestData.metadata.cdnAnalysis = cdnAnalysis;
      
      // Get tab information for browser context
      if (details.tabId >= 0) {
        chrome.tabs.get(details.tabId, (tab) => {
          if (tab) {
            requestData.metadata.browserContext = {
              tabUrl: tab.url,
              tabTitle: tab.title,
              isIncognito: tab.incognito,
              userAgent: null // Will be extracted from headers
            };
            authRequests.set(details.requestId, requestData);
          }
        });
      }
      
      authRequests.set(details.requestId, requestData);
      
      // Only scan backends for suspicious or unknown domains, not legitimate services
      const hostname = new URL(details.url).hostname;
      const shouldScanBackend = !isKnownLegitimateService(hostname);
      
      if (shouldScanBackend) {
        console.log(`Scanning backend for suspicious domain: ${hostname}`);
        const backendScan = await scanForExposedBackends(hostname);
        requestData.metadata.backendSecurity = backendScan;
      } else {
        console.log(`Skipping backend scan for legitimate service: ${hostname}`);
        requestData.metadata.backendSecurity = {
          domain: hostname,
          exposed: [],
          riskScore: 0,
          shouldBlockDataEntry: false,
          legitimateService: true
        };
      }
      
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
      const service = sessionTracker.identifyService(hostname);
      const sessionInfo = sessionTracker.getOrCreateSession(hostname, service, requestContext);
      
      // Add session information to request data
      requestData.sessionInfo = {
        sessionId: sessionInfo.id,
        service: sessionInfo.service,
        domain: sessionInfo.primaryDomain,
        eventNumber: sessionInfo.eventCount,
        ecosystem: sessionInfo.ecosystem,
        correlationFactors: sessionInfo.correlationFactors
      };
      
      // Store in persistent storage for cross-session analysis
      heraStore.storeAuthEvent({
        ...requestData,
        sessionId: sessionInfo.id,
        service: sessionInfo.service,
        riskScore: calculateOverallRiskScore(requestData)
      });
      
      updateBadge();
    }
  },
  { urls: ["<all_urls>"] }
);

// Listen for failed requests (network errors, timeouts, etc.)
chrome.webRequest.onErrorOccurred.addListener(
  (details) => {
    const requestData = authRequests.get(details.requestId);
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
      requestData.metadata.timing.duration = requestData.metadata.timing.endTime - requestData.metadata.timing.startTime;
      
      // Analyze the error for authentication context
      const errorAnalysis = analyzeAuthError(details.error, requestData.url);
      requestData.metadata.errorAnalysis = errorAnalysis;
      
      authRequests.set(details.requestId, requestData);
      updateBadge();
    }
  },
  { urls: ["<all_urls>"] }
);

// Detect authentication type based on URL and request data
function detectAuthType(url, requestBody) {
  const lowerUrl = url.toLowerCase();
  
  // Check for logout/signout flows first
  if (lowerUrl.includes('logout') || lowerUrl.includes('signout') || lowerUrl.includes('sign-out')) {
    return 'Logout/Signout';
  }
  
  if (lowerUrl.includes('revoke') || lowerUrl.includes('invalidate')) {
    return 'Token Revocation';
  }
  
  if (lowerUrl.includes('end_session') || lowerUrl.includes('disconnect')) {
    return 'Session Termination';
  }
  
  if (lowerUrl.includes('saml') || lowerUrl.includes('saml2')) {
    return 'SAML';
  }
  
  if (lowerUrl.includes('scim')) {
    return 'SCIM';
  }
  
  if (lowerUrl.includes('token') || lowerUrl.includes('oauth') || lowerUrl.includes('authorize')) {
    return requestBody && requestBody.formData && requestBody.formData.grant_type 
      ? `OAuth 2.0 (${requestBody.formData.grant_type})`
      : 'OAuth 2.0';
  }
  
  if (lowerUrl.includes('openid-configuration') || lowerUrl.includes('userinfo')) {
    return 'OIDC';
  }
  
  if (lowerUrl.includes('login') || lowerUrl.includes('signin') || lowerUrl.includes('sign-in')) {
    return 'Login/Signin';
  }
  
  if (lowerUrl.includes('sso')) {
    return 'Single Sign-On';
  }
  
  if (lowerUrl.includes('mfa') || lowerUrl.includes('2fa') || lowerUrl.includes('otp')) {
    return 'Multi-Factor Auth';
  }
  
  if (lowerUrl.includes('verify') || lowerUrl.includes('validate')) {
    return 'Verification';
  }
  
  if (lowerUrl.includes('challenge')) {
    return 'Auth Challenge';
  }
  
  if (lowerUrl.includes('negotiate') || lowerUrl.includes('ntlm') || lowerUrl.includes('kerberos')) {
    return 'Kerberos/NTLM';
  }
  
  if (lowerUrl.includes('spnego')) {
    return 'SPNEGO Negotiation';
  }
  
  if (lowerUrl.includes('ldap') || lowerUrl.includes('directory')) {
    return 'LDAP Authentication';
  }
  
  if (lowerUrl.includes('webauthn') || lowerUrl.includes('fido') || lowerUrl.includes('u2f')) {
    return 'WebAuthn/FIDO2';
  }
  
  if (lowerUrl.includes('api/auth') || lowerUrl.includes('api/login') || lowerUrl.includes('api/token')) {
    return 'API Authentication';
  }
  
  return 'Unknown';
}

// Analyze URL components for security insights
function analyzeUrl(url) {
  try {
    const urlObj = new URL(url);
    const params = new URLSearchParams(urlObj.search);
    
    return {
      protocol: urlObj.protocol,
      hostname: urlObj.hostname,
      port: urlObj.port,
      pathname: urlObj.pathname,
      search: urlObj.search,
      hash: urlObj.hash,
      parameterCount: params.size,
      hasFragment: urlObj.hash.length > 0,
      hasSensitiveParams: hasSensitiveParameters(params),
      suspiciousPatterns: detectSuspiciousUrlPatterns(url)
    };
  } catch (e) {
    return { error: 'Invalid URL', url: url };
  }
}

// Analyze authentication flow specifics
function analyzeAuthFlow(url, requestBody) {
  const urlObj = new URL(url);
  const params = new URLSearchParams(urlObj.search);
  const lowerUrl = url.toLowerCase();
  
  const analysis = {
    flowType: null,
    grantType: null,
    hasState: params.has('state'),
    hasNonce: params.has('nonce'),
    hasPKCE: params.has('code_challenge') || params.has('code_verifier'),
    responseType: params.get('response_type'),
    scope: params.get('scope'),
    clientId: params.get('client_id'),
    redirectUri: params.get('redirect_uri'),
    securityFeatures: []
  };
  
  // Detect flow type
  if (lowerUrl.includes('authorize')) {
    analysis.flowType = 'authorization_request';
  } else if (lowerUrl.includes('token')) {
    analysis.flowType = 'token_request';
    if (requestBody && requestBody.formData) {
      analysis.grantType = requestBody.formData.grant_type;
    }
  } else if (lowerUrl.includes('userinfo')) {
    analysis.flowType = 'userinfo_request';
  } else if (lowerUrl.includes('logout') || lowerUrl.includes('signout') || lowerUrl.includes('sign-out')) {
    analysis.flowType = 'logout_request';
  } else if (lowerUrl.includes('revoke')) {
    analysis.flowType = 'token_revocation';
  } else if (lowerUrl.includes('end_session')) {
    analysis.flowType = 'session_termination';
  }
  
  // Check security features
  if (analysis.hasState) analysis.securityFeatures.push('state_parameter');
  if (analysis.hasNonce) analysis.securityFeatures.push('nonce_parameter');
  if (analysis.hasPKCE) analysis.securityFeatures.push('pkce');
  
  return analysis;
}

// Check for sensitive parameters in URL
function hasSensitiveParameters(params) {
  const sensitiveParams = [
    'access_token', 'id_token', 'refresh_token', 'code', 'password',
    'client_secret', 'api_key', 'token', 'auth', 'session'
  ];
  
  for (const [key] of params) {
    if (sensitiveParams.some(sensitive => key.toLowerCase().includes(sensitive))) {
      return true;
    }
  }
  return false;
}

// Detect suspicious URL patterns
function detectSuspiciousUrlPatterns(url) {
  const patterns = [];
  const lowerUrl = url.toLowerCase();
  
  // Check for common phishing patterns
  if (lowerUrl.includes('oauth') && !lowerUrl.includes('googleapis.com') && 
      !lowerUrl.includes('microsoft.com') && !lowerUrl.includes('github.com')) {
    patterns.push('non_standard_oauth_domain');
  }
  
  // Check for URL shorteners
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly'];
  if (shorteners.some(shortener => lowerUrl.includes(shortener))) {
    patterns.push('url_shortener');
  }
  
  // Check for suspicious TLDs
  const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf'];
  if (suspiciousTlds.some(tld => lowerUrl.includes(tld))) {
    patterns.push('suspicious_tld');
  }
  
  return patterns;
}

// Check if request is cross-origin
function isCrossOrigin(initiator, targetUrl) {
  if (!initiator) return false;
  
  try {
    const initiatorUrl = new URL(initiator);
    const targetUrlObj = new URL(targetUrl);
    
    return initiatorUrl.origin !== targetUrlObj.origin;
  } catch (e) {
    return false;
  }
}

// Analyze request headers for security insights
function analyzeRequestHeaders(headers) {
  if (!headers) return {};
  
  const analysis = {
    hasAuthHeaders: false,
    userAgent: null,
    acceptLanguage: null,
    referer: null,
    origin: null,
    cookieCount: 0,
    authMethods: [],
    securityHeaders: []
  };
  
  headers.forEach(header => {
    const name = header.name.toLowerCase();
    const value = header.value;
    
    switch (name) {
      case 'authorization':
        analysis.hasAuthHeaders = true;
        if (value.startsWith('Bearer ')) {
          analysis.authMethods.push('bearer_token');
        } else if (value.startsWith('Basic ')) {
          analysis.authMethods.push('basic_auth');
        } else if (value.startsWith('Digest ')) {
          analysis.authMethods.push('digest_auth');
        } else if (value.startsWith('Negotiate ')) {
          analysis.authMethods.push('kerberos_spnego');
        } else if (value.startsWith('NTLM ')) {
          analysis.authMethods.push('ntlm');
        } else if (value.startsWith('AWS4-HMAC-SHA256 ')) {
          analysis.authMethods.push('aws_signature');
        }
        break;
      case 'user-agent':
        analysis.userAgent = value;
        break;
      case 'accept-language':
        analysis.acceptLanguage = value;
        break;
      case 'referer':
        analysis.referer = value;
        break;
      case 'origin':
        analysis.origin = value;
        break;
      case 'cookie':
        analysis.cookieCount = (value.match(/;/g) || []).length + 1;
        analysis.cookieDetails = parseCookieHeader(value);
        break;
      case 'x-requested-with':
        if (value === 'XMLHttpRequest') {
          analysis.securityHeaders.push('ajax_request');
        }
        break;
      case 'x-api-key':
      case 'x-auth-token':
      case 'x-access-token':
        analysis.hasAuthHeaders = true;
        analysis.authMethods.push('api_key');
        break;
      case 'x-amz-security-token':
        analysis.hasAuthHeaders = true;
        analysis.authMethods.push('aws_session_token');
        break;
      case 'x-ms-token-aad-id-token':
      case 'x-ms-token-aad-access-token':
        analysis.hasAuthHeaders = true;
        analysis.authMethods.push('azure_ad_token');
        break;
    }
  });
  
  return analysis;
}

// Analyze response headers for security insights
function analyzeResponseHeaders(headers) {
  if (!headers) return {};
  
  const analysis = {
    securityHeaders: {},
    cacheControl: null,
    contentType: null,
    setCookies: [],
    corsHeaders: {},
    hasSecurityHeaders: false
  };
  
  const securityHeadersToCheck = [
    'strict-transport-security',
    'x-frame-options',
    'x-content-type-options',
    'content-security-policy',
    'x-xss-protection',
    'referrer-policy'
  ];
  
  headers.forEach(header => {
    const name = header.name.toLowerCase();
    const value = header.value;
    
    if (securityHeadersToCheck.includes(name)) {
      analysis.securityHeaders[name] = value;
      analysis.hasSecurityHeaders = true;
    }
    
    switch (name) {
      case 'cache-control':
        analysis.cacheControl = value;
        break;
      case 'content-type':
        analysis.contentType = value;
        break;
      case 'set-cookie':
        analysis.setCookies.push(value);
        const cookieAnalysis = analyzeSetCookie(value);
        if (!analysis.cookieAnalysis) analysis.cookieAnalysis = [];
        analysis.cookieAnalysis.push(cookieAnalysis);
        break;
      case 'access-control-allow-origin':
        analysis.corsHeaders.allowOrigin = value;
        break;
      case 'access-control-allow-credentials':
        analysis.corsHeaders.allowCredentials = value;
        break;
      case 'access-control-allow-methods':
        analysis.corsHeaders.allowMethods = value;
        break;
    }
  });
  
  return analysis;
}

// Analyze OAuth consent and authorization grants
function analyzeOAuthConsent(url, requestBody) {
  const urlObj = new URL(url);
  const params = new URLSearchParams(urlObj.search);
  const lowerUrl = url.toLowerCase();
  
  const analysis = {
    isConsentFlow: false,
    provider: detectAuthProvider(url),
    clientId: params.get('client_id'),
    redirectUri: params.get('redirect_uri'),
    scopes: [],
    scopeAnalysis: {
      highRisk: [],
      mediumRisk: [],
      lowRisk: [],
      riskScore: 0
    },
    applicationInfo: {
      name: null,
      domain: null,
      verified: false,
      suspicious: false
    },
    consentWarnings: []
  };
  
  // Check if this is a consent/authorization flow
  if (lowerUrl.includes('authorize') || lowerUrl.includes('consent') || lowerUrl.includes('oauth')) {
    analysis.isConsentFlow = true;
    
    // Parse scopes
    const scopeParam = params.get('scope');
    if (scopeParam) {
      analysis.scopes = scopeParam.split(/[\s,+]/).filter(s => s.length > 0);
      analysis.scopeAnalysis = analyzeScopeRisks(analysis.scopes, analysis.provider);
    }
    
    // Analyze redirect URI for suspicious patterns
    if (analysis.redirectUri) {
      analysis.applicationInfo = analyzeRedirectUri(analysis.redirectUri);
    }
    
    // Generate consent warnings
    analysis.consentWarnings = generateConsentWarnings(analysis);
  }
  
  return analysis;
}

// Detect authentication provider from URL
function detectAuthProvider(url) {
  const lowerUrl = url.toLowerCase();
  const hostname = new URL(url).hostname.toLowerCase();
  
  if (hostname.includes('login.microsoftonline.com') || hostname.includes('login.live.com')) {
    return 'Microsoft Azure/Office 365';
  }
  if (hostname.includes('accounts.google.com') || hostname.includes('oauth2.googleapis.com')) {
    return 'Google';
  }
  if (hostname.includes('github.com')) {
    return 'GitHub';
  }
  if (hostname.includes('facebook.com') || hostname.includes('graph.facebook.com')) {
    return 'Facebook';
  }
  if (hostname.includes('api.twitter.com') || hostname.includes('twitter.com')) {
    return 'Twitter/X';
  }
  if (hostname.includes('linkedin.com')) {
    return 'LinkedIn';
  }
  if (hostname.includes('okta.com') || hostname.includes('oktapreview.com')) {
    return 'Okta';
  }
  if (hostname.includes('auth0.com')) {
    return 'Auth0';
  }
  if (hostname.includes('salesforce.com')) {
    return 'Salesforce';
  }
  
  return `Unknown Provider (${hostname})`;
}

// Analyze scope risks based on provider and permissions
function analyzeScopeRisks(scopes, provider) {
  const analysis = {
    highRisk: [],
    mediumRisk: [],
    lowRisk: [],
    riskScore: 0
  };
  
  const riskPatterns = {
    // High risk scopes - full access, admin rights, sensitive data
    high: [
      'https://graph.microsoft.com/.default', // Full Microsoft Graph access
      'user.readwrite.all', 'directory.readwrite.all', 'application.readwrite.all',
      'mail.readwrite', 'calendars.readwrite', 'contacts.readwrite',
      'files.readwrite.all', 'sites.readwrite.all',
      'admin', 'root', 'sudo', 'full_access', 'all',
      'delete', 'write_all', 'manage_all'
    ],
    
    // Medium risk scopes - read access to sensitive data
    medium: [
      'user.read.all', 'directory.read.all', 'mail.read',
      'calendars.read', 'contacts.read', 'files.read.all',
      'profile', 'email', 'openid', 'offline_access',
      'read_user', 'read_repository', 'read_org'
    ],
    
    // Low risk scopes - basic info only
    low: [
      'user.read', 'profile.basic', 'email.basic',
      'public_profile', 'basic_info'
    ]
  };
  
  scopes.forEach(scope => {
    const lowerScope = scope.toLowerCase();
    
    if (riskPatterns.high.some(pattern => lowerScope.includes(pattern.toLowerCase()))) {
      analysis.highRisk.push(scope);
      analysis.riskScore += 10;
    } else if (riskPatterns.medium.some(pattern => lowerScope.includes(pattern.toLowerCase()))) {
      analysis.mediumRisk.push(scope);
      analysis.riskScore += 5;
    } else {
      analysis.lowRisk.push(scope);
      analysis.riskScore += 1;
    }
  });
  
  return analysis;
}

// Analyze redirect URI for suspicious patterns
function analyzeRedirectUri(redirectUri) {
  const analysis = {
    name: null,
    domain: null,
    verified: false,
    suspicious: false,
    warnings: []
  };
  
  try {
    const url = new URL(redirectUri);
    analysis.domain = url.hostname;
    
    // Check for suspicious patterns
    const suspiciousPatterns = [
      'localhost', '127.0.0.1', '0.0.0.0', // Local redirects (potentially suspicious)
      'bit.ly', 'tinyurl.com', 't.co', // URL shorteners
      'ngrok.io', 'herokuapp.com', // Temporary hosting
      'github.io', 'netlify.app', 'vercel.app' // Free hosting (could be legitimate or suspicious)
    ];
    
    const isSuspicious = suspiciousPatterns.some(pattern => 
      analysis.domain.toLowerCase().includes(pattern)
    );
    
    if (isSuspicious) {
      analysis.suspicious = true;
      analysis.warnings.push('Redirect URI uses potentially suspicious domain');
    }
    
    // Check for legitimate domains
    const legitimateDomains = [
      'microsoft.com', 'office.com', 'sharepoint.com',
      'google.com', 'gmail.com', 'googleusercontent.com',
      'github.com', 'facebook.com', 'linkedin.com'
    ];
    
    analysis.verified = legitimateDomains.some(domain => 
      analysis.domain.toLowerCase().includes(domain)
    );
    
  } catch (e) {
    analysis.suspicious = true;
    analysis.warnings.push('Invalid redirect URI format');
  }
  
  return analysis;
}

// Generate consent warnings based on analysis
function generateConsentWarnings(consentAnalysis) {
  const warnings = [];
  
  // High risk scope warnings
  if (consentAnalysis.scopeAnalysis.highRisk.length > 0) {
    warnings.push({
      severity: 'critical',
      type: 'high_risk_scopes',
      message: ` HIGH RISK: Application requesting dangerous permissions: ${consentAnalysis.scopeAnalysis.highRisk.join(', ')}`,
      recommendation: 'Carefully verify this application before granting access. These permissions allow extensive access to your data.'
    });
  }
  
  // Suspicious redirect URI
  if (consentAnalysis.applicationInfo.suspicious) {
    warnings.push({
      severity: 'critical',
      type: 'suspicious_redirect',
      message: ` SUSPICIOUS: Redirect URI appears suspicious: ${consentAnalysis.redirectUri}`,
      recommendation: 'This may be a phishing attempt. Verify the application is legitimate before proceeding.'
    });
  }
  
  // Unknown provider warning
  if (consentAnalysis.provider.includes('Unknown Provider')) {
    warnings.push({
      severity: 'warning',
      type: 'unknown_provider',
      message: `WARNING: Unknown authentication provider: ${consentAnalysis.provider}`,
      recommendation: 'Verify this is a legitimate authentication service before entering credentials.'
    });
  }
  
  // High risk score
  if (consentAnalysis.scopeAnalysis.riskScore >= 20) {
    warnings.push({
      severity: 'warning',
      type: 'high_risk_score',
      message: `HIGH RISK SCORE: ${consentAnalysis.scopeAnalysis.riskScore} - Multiple sensitive permissions requested`,
      recommendation: 'Consider if this application really needs all these permissions.'
    });
  }
  
  return warnings;
}

// IP Address resolution and geolocation
async function resolveIPAddresses(hostname) {
  const ipInfo = {
    ipv4Addresses: [],
    ipv6Addresses: [],
    geoLocations: [],
    asn: null,
    organization: null,
    country: null,
    city: null,
    isp: null,
    isVPN: false,
    isTor: false,
    isProxy: false,
    threatLevel: 'low'
  };

  try {
    // Use DNS over HTTPS to resolve IP addresses
    const dohEndpoint = `https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`;
    
    const response = await fetch(dohEndpoint, {
      headers: {
        'Accept': 'application/dns-json'
      }
    });
    
    if (response.ok) {
      const dnsData = await response.json();
      
      if (dnsData.Answer) {
        for (const record of dnsData.Answer) {
          if (record.type === 1) { // A record (IPv4)
            const ip = record.data;
            ipInfo.ipv4Addresses.push(ip);
            
            // Get geolocation for each IP
            const geoData = await getIPGeolocation(ip);
            if (geoData) {
              ipInfo.geoLocations.push({
                ip: ip,
                ...geoData
              });
              
              // Use first IP's data for main fields
              if (!ipInfo.country) {
                ipInfo.country = geoData.country;
                ipInfo.city = geoData.city;
                ipInfo.asn = geoData.asn;
                ipInfo.organization = geoData.organization;
                ipInfo.isp = geoData.isp;
                ipInfo.isVPN = geoData.isVPN;
                ipInfo.isTor = geoData.isTor;
                ipInfo.isProxy = geoData.isProxy;
                ipInfo.threatLevel = geoData.threatLevel;
              }
            }
          }
        }
      }
    }
  } catch (error) {
    console.log(`DNS resolution failed for ${hostname}:`, error);
  }

  return ipInfo;
}

// IP Geolocation lookup with rate limiting and caching
const ipCache = new Map();
const ipRequestQueue = new Set();

async function getIPGeolocation(ip) {
  // Check cache first
  if (ipCache.has(ip)) {
    console.log(`Using cached IP data for ${ip}`);
    return ipCache.get(ip);
  }
  
  // Prevent duplicate requests
  if (ipRequestQueue.has(ip)) {
    console.log(`IP request already in progress for ${ip}`);
    return null;
  }
  
  // Rate limiting - only allow IP lookups for legitimate security analysis
  if (ipCache.size > 10) {
    console.log(`IP cache limit reached, skipping lookup for ${ip}`);
    return null;
  }
  
  // Skip IP lookups entirely for known legitimate services to prevent 429 errors
  const knownLegitimateIPs = [
    '160.79.104.10', // Claude.ai
    '151.101.0.176', '151.101.128.176', '151.101.64.176', '151.101.192.176' // Fastly CDN
  ];
  
  if (knownLegitimateIPs.includes(ip)) {
    console.log(`Skipping IP lookup for known legitimate IP: ${ip}`);
    return null;
  }
  
  // Skip IP lookups for known legitimate IP ranges (optional optimization)
  // Most IPs will be processed, but we can skip obvious ones
  
  ipRequestQueue.add(ip);
  
  try {
    console.log(`Looking up IP geolocation for ${ip}`);
    const response = await fetch(`https://ipapi.co/${ip}/json/`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    });
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    
    const data = await response.json();
    
    const geoData = {
      ip: ip,
      country: data.country_name || 'Unknown',
      city: data.city || 'Unknown',
      region: data.region || 'Unknown',
      isp: data.org || 'Unknown ISP',
      asn: data.asn || 'Unknown',
      timezone: data.timezone || 'Unknown',
      isVPN: data.threat?.is_anonymous || false,
      isTor: data.threat?.is_tor || false,
      isProxy: data.threat?.is_proxy || false,
      threatLevel: data.threat?.threat_types?.length > 0 ? 'high' : 'low'
    };
    
    // Cache the result
    ipCache.set(ip, geoData);
    console.log(`IP geolocation cached for ${ip}: ${geoData.city}, ${geoData.country}`);
    
    return geoData;
  } catch (error) {
    console.log(`IP geolocation failed for ${ip}:`, error);
    return null;
  } finally {
    ipRequestQueue.delete(ip);
  }
}

// Gather DNS intelligence for domain analysis with IP resolution
async function gatherDNSIntelligence(url, requestId) {
  try {
    const hostname = new URL(url).hostname;
    
    // Resolve IP addresses first
    const ipInfo = await resolveIPAddresses(hostname);
    
    const intelligence = {
      hostname: hostname,
      isNewDomain: false,
      isDGA: false,
      isHomograph: false,
      cdnProvider: null,
      suspiciousPatterns: [],
      whoisAge: null,
      ipAddresses: ipInfo, // Add IP information
      dnsRecords: {
        aRecords: ipInfo.ipv4Addresses,
        aaaaRecords: ipInfo.ipv6Addresses,
        cnameRecords: [],
        mxRecords: [],
        txtRecords: [],
        nsRecords: []
      },
      networkPath: {
        resolverUsed: 'cloudflare-dns.com',
        ttlValues: [],
        responseTime: null,
        isDohUsed: true
      },
      geoLocation: {
        country: ipInfo.country,
        city: ipInfo.city,
        asn: ipInfo.asn,
        organization: ipInfo.organization,
        isp: ipInfo.isp,
        isVPN: ipInfo.isVPN,
        isTor: ipInfo.isTor,
        isProxy: ipInfo.isProxy,
        threatLevel: ipInfo.threatLevel
      }
    };
    
    // Check for homograph attacks (Unicode lookalikes)
    intelligence.isHomograph = detectHomographAttack(hostname);
    
    // Check for Domain Generation Algorithm patterns
    intelligence.isDGA = detectDGAPattern(hostname);
    
    // Check for suspicious TLDs and patterns
    intelligence.suspiciousPatterns = detectSuspiciousDomainPatterns(hostname);
    
    // Update the stored request with DNS intelligence
    const requestData = authRequests.get(requestId);
    if (requestData) {
      requestData.metadata.dnsIntelligence = intelligence;
      authRequests.set(requestId, requestData);
    }
    
  } catch (error) {
    console.log('DNS intelligence gathering failed:', error);
  }
}

// Detect homograph attacks (Unicode characters that look like ASCII)
function detectHomographAttack(hostname) {
  // Check for mixed scripts or suspicious Unicode characters
  const suspiciousChars = /[а-я]|[α-ω]|[а-я]|[\u0400-\u04FF]|[\u0370-\u03FF]/i; // Cyrillic, Greek
  const hasNonASCII = /[^\x00-\x7F]/.test(hostname);
  const hasMixedScript = suspiciousChars.test(hostname);
  
  // Common homograph targets
  const commonTargets = ['google', 'microsoft', 'apple', 'amazon', 'facebook', 'github'];
  const isTargetLookalike = commonTargets.some(target => {
    const similarity = calculateStringSimilarity(hostname.toLowerCase(), target);
    return similarity > 0.8 && similarity < 1.0;
  });
  
  return hasNonASCII || hasMixedScript || isTargetLookalike;
}

// Detect Domain Generation Algorithm patterns
function detectDGAPattern(hostname) {
  const domain = hostname.split('.')[0];
  
  // DGA characteristics
  const hasRandomPattern = /^[a-z]{8,20}$/.test(domain); // Long random strings
  const hasNumberMix = /^[a-z0-9]{10,}$/.test(domain) && /\d/.test(domain);
  const hasConsonantClusters = /[bcdfghjklmnpqrstvwxyz]{4,}/.test(domain);
  const lowVowelRatio = (domain.match(/[aeiou]/g) || []).length / domain.length < 0.2;
  
  return (hasRandomPattern || hasNumberMix) && (hasConsonantClusters || lowVowelRatio);
}

// Detect suspicious domain patterns
function detectSuspiciousDomainPatterns(hostname) {
  const patterns = [];
  
  // Suspicious TLDs
  const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download'];
  if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
    patterns.push('suspicious_tld');
  }
  
  // Typosquatting patterns
  const legitimateDomains = ['google.com', 'microsoft.com', 'github.com', 'facebook.com'];
  legitimateDomains.forEach(legit => {
    if (hostname !== legit && calculateStringSimilarity(hostname, legit) > 0.7) {
      patterns.push('typosquatting_' + legit.replace('.com', ''));
    }
  });
  
  // Subdomain abuse
  const subdomainCount = hostname.split('.').length - 2;
  if (subdomainCount > 3) {
    patterns.push('excessive_subdomains');
  }
  
  // URL shortener domains
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly'];
  if (shorteners.includes(hostname)) {
    patterns.push('url_shortener');
  }
  
  return patterns;
}

// Analyze CDN and infrastructure from response headers
function analyzeCDNFromHeaders(responseHeaders, url) {
  if (!responseHeaders) return null;
  
  const analysis = {
    cdnProvider: null,
    serverInfo: null,
    cacheStatus: null,
    edgeLocation: null,
    isLegitimateInfrastructure: false,
    suspiciousHeaders: [],
    expectedCDN: null,
    cdnMismatch: false
  };
  
  responseHeaders.forEach(header => {
    if (authHeader && authHeader.value.toLowerCase().startsWith('bearer ')) {
      jwt = authHeader.value.substring(7);
      sessionTracker.authenticatedDomains.add(new URL(request.url).hostname); // Mark domain as authenticated
      sessionTracker.authenticatedPaths.add(new URL(request.url).pathname); // Mark path as authenticated
    }
    // Detect CDN providers
    if (name === 'server') {
      analysis.serverInfo = header.value;
      
      // Common legitimate CDNs
      const lowerValue = header.value.toLowerCase();
      if (lowerValue.includes('cloudflare')) {
        analysis.cdnProvider = 'Cloudflare';
        analysis.isLegitimateInfrastructure = true;
      } else if (lowerValue.includes('amazonaws')) {
        analysis.cdnProvider = 'AWS CloudFront';
        analysis.isLegitimateInfrastructure = true;
      } else if (lowerValue.includes('google')) {
        analysis.cdnProvider = 'Google Cloud CDN';
        analysis.isLegitimateInfrastructure = true;
      } else if (lowerValue.includes('microsoft') || lowerValue.includes('azure')) {
        analysis.cdnProvider = 'Azure CDN';
        analysis.isLegitimateInfrastructure = true;
      }
    }
    
    // CDN-specific headers
    if (name === 'cf-ray') {
      analysis.cdnProvider = 'Cloudflare';
      analysis.isLegitimateInfrastructure = true;
    } else if (name === 'x-amz-cf-id') {
      analysis.cdnProvider = 'AWS CloudFront';
      analysis.isLegitimateInfrastructure = true;
    } else if (name === 'x-cache') {
      analysis.cacheStatus = header.value;
    }
  });
  
  // Check for CDN mismatches with expected providers
  const hostname = new URL(url).hostname;
  if (hostname.includes('microsoft') || hostname.includes('office365') || hostname.includes('azure')) {
    analysis.expectedCDN = 'Azure CDN';
    analysis.cdnMismatch = analysis.cdnProvider && !analysis.cdnProvider.includes('Azure') && !analysis.cdnProvider.includes('Microsoft');
  } else if (hostname.includes('google') || hostname.includes('gmail') || hostname.includes('googleapis')) {
    analysis.expectedCDN = 'Google Cloud CDN';
    analysis.cdnMismatch = analysis.cdnProvider && !analysis.cdnProvider.includes('Google');
  }
  
  return analysis;
}

// Calculate string similarity for homograph detection
function calculateStringSimilarity(str1, str2) {
  const longer = str1.length > str2.length ? str1 : str2;
  const shorter = str1.length > str2.length ? str2 : str1;
  
  if (longer.length === 0) return 1.0;
  
  const editDistance = levenshteinDistance(longer, shorter);
  return (longer.length - editDistance) / longer.length;
}

// Levenshtein distance calculation
function levenshteinDistance(str1, str2) {
  const matrix = [];
  
  for (let i = 0; i <= str2.length; i++) {
    matrix[i] = [i];
  }
  
  for (let j = 0; j <= str1.length; j++) {
    matrix[0][j] = j;
  }
  
  for (let i = 1; i <= str2.length; i++) {
    for (let j = 1; j <= str1.length; j++) {
      if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  
  return matrix[str2.length][str1.length];
}

// Exposed Backend Detection
async function scanForExposedBackends(domain) {
  const results = {
    domain: domain,
    timestamp: Date.now(),
    exposed: [],
    shouldBlockDataEntry: false,
    riskScore: 0,
    sadsAnalysis: null
  };

  try {
    // Use comprehensive intelligence collection if available
    let signals = {};
    let comprehensiveProfile = null;

    // Skip heraIntelligence in service worker context (window not available)
    if (false) {
      // heraIntelligence not available in service worker
      // comprehensiveProfile = await heraIntelligence.collectAllData(`https://${domain}`);

      // Convert comprehensive profile to SADS-compatible signals
      signals = convertComprehensiveProfileToSignals(comprehensiveProfile);
      results.comprehensiveProfile = comprehensiveProfile;
    } else {
      // Fallback to basic signal gathering
      signals = await gatherSecuritySignals(domain);
    }

    // Skip SADS analysis (not available in service worker)
    if (false) {
      // SADS not available in service worker
      // console.log(`Running SADS analysis for ${domain}`);
      // const sadsAnalysis = await heraSADS.analyzeWebsite(domain, signals);
      // results.sadsAnalysis = sadsAnalysis;

      // Use SADS score for risk assessment
      results.riskScore = sadsAnalysis.sScore.normalized;
      results.shouldBlockDataEntry = sadsAnalysis.sScore.category === 'CRITICAL' ||
                                     sadsAnalysis.assessment.isDeceptive;

      // Convert SADS findings to exposure format for compatibility
      if (sadsAnalysis.assessment.isInsecure || sadsAnalysis.assessment.isDeceptive) {
        results.exposed.push({
          exposed: true,
          type: 'sads_anomaly',
          severity: sadsAnalysis.sScore.category.toLowerCase(),
          riskPoints: sadsAnalysis.sScore.normalized,
          details: sadsAnalysis.recommendation.message,
          sadsDetails: {
            websiteType: sadsAnalysis.websiteType,
            surpriseFactors: sadsAnalysis.surpriseScores,
            anomalies: sadsAnalysis.anomalies,
            explanation: sadsAnalysis.explanation
          }
        });
      }

      console.log(`SADS Score: ${sadsAnalysis.sScore.normalized} (${sadsAnalysis.sScore.category})`);
    } else {
      // Fallback to rule-based checking
      console.log(`SADS not available, using rule-based detection for ${domain}`);
      const checks = [
        checkMongoDBExposure(domain),
        checkS3Exposure(domain),
        checkGitExposure(domain),
        checkEnvFileExposure(domain)
      ];

      const scanResults = await Promise.allSettled(checks);

      for (const result of scanResults) {
        if (result.status === 'fulfilled' && result.value?.exposed) {
          results.exposed.push(result.value);
          results.riskScore += result.value.riskPoints || 0;

          if (result.value.severity === 'critical') {
            results.shouldBlockDataEntry = true;
          }
        }
      }
    }
    
  } catch (error) {
    console.error('Backend scan failed:', error);
  }
  
  return results;
}

async function checkMongoDBExposure(domain) {
  try {
    const response = await fetch(`http://${domain}:27017/admin/listDatabases?text=1`, {
      method: 'GET',
      mode: 'no-cors',
      signal: AbortSignal.timeout(3000)
    });
    
    if (response && response.ok) {
      return {
        exposed: true,
        type: 'mongodb',
        severity: 'critical',
        riskPoints: 100,
        details: 'MongoDB instance exposed without authentication!'
      };
    }
  } catch (error) {
    // Expected for most sites
  }
  
  return { exposed: false };
}

async function checkS3Exposure(domain) {
  const bucketUrls = [
    `https://s3.amazonaws.com/${domain}`,
    `https://${domain}.s3.amazonaws.com`
  ];
  
  for (const url of bucketUrls) {
    try {
      const response = await fetch(url, {
        signal: AbortSignal.timeout(3000)
      });
      
      if (response && response.ok) {
        const text = await response.text();
        if (text.includes('<ListBucketResult') || text.includes('<Contents>')) {
          return {
            exposed: true,
            type: 's3_bucket',
            severity: 'critical',
            riskPoints: 95,
            details: 'S3 bucket publicly readable'
          };
        }
      }
    } catch (error) {
      continue;
    }
  }

  return { exposed: false };
}

// Gather comprehensive security signals for SADS analysis
async function gatherSecuritySignals(domain) {
  const signals = {
    domain: domain,
    domainAge: null,
    gitExposed: { exposed: false },
    envFileExposed: { exposed: false },
    certificate: null,
    techStack: [],
    securityHeaders: 0,
    tlsVersion: null,
    hostingProvider: null,
    hasLoginForm: false,
    hasCreditCardForm: false,
    typosquattingScore: 0,
    contentSimilarity: 0,
    stagingIndicators: false
  };

  try {
    // Parallel signal gathering for speed
    const signalTasks = [
      gatherDomainSignals(domain),
      gatherSecurityConfigSignals(domain),
      gatherInfrastructureSignals(domain),
      checkGitExposure(domain),
      checkEnvFileExposure(domain)
    ];

    const results = await Promise.allSettled(signalTasks);

    // Merge results
    results.forEach((result, index) => {
      if (result.status === 'fulfilled' && result.value) {
        switch (index) {
          case 0: // Domain signals
            Object.assign(signals, result.value);
            break;
          case 1: // Security config signals
            Object.assign(signals, result.value);
            break;
          case 2: // Infrastructure signals
            Object.assign(signals, result.value);
            break;
          case 3: // Git exposure
            signals.gitExposed = result.value || { exposed: false };
            break;
          case 4: // Env file exposure
            signals.envFileExposed = result.value || { exposed: false };
            break;
        }
      }
    });

    console.log(`Gathered signals for ${domain}:`, {
      domainAge: signals.domainAge,
      gitExposed: signals.gitExposed.exposed,
      envExposed: signals.envFileExposed.exposed,
      tlsVersion: signals.tlsVersion,
      securityHeaders: signals.securityHeaders
    });

  } catch (error) {
    console.error('Failed to gather security signals:', error);
  }

  return signals;
}

async function gatherDomainSignals(domain) {
  const signals = {};

  try {
    // Estimate domain age (simplified - in production would use WHOIS)
    const domainParts = domain.split('.');
    const tld = domainParts[domainParts.length - 1];

    // Heuristic domain age estimation
    if (domain.includes('github.io') || domain.includes('netlify') || domain.includes('vercel')) {
      signals.domainAge = 365; // Assume 1 year for hosted sites
    } else if (tld === 'gov' || domain.includes('google') || domain.includes('microsoft')) {
      signals.domainAge = 7300; // Assume old for established domains
    } else {
      // For demo purposes, generate pseudo-random age based on domain
      const hash = domain.split('').reduce((a, b) => a + b.charCodeAt(0), 0);
      signals.domainAge = (hash % 2000) + 365; // 1-6 years
    }

    // Check for typosquatting patterns
    signals.typosquattingScore = calculateTyposquattingScore(domain);

  } catch (error) {
    console.error('Failed to gather domain signals:', error);
  }

  return signals;
}

async function gatherSecurityConfigSignals(domain) {
  const signals = {
    securityHeaders: 0,
    tlsVersion: null,
    certificate: null
  };

  try {
    // Try to check TLS and headers (limited by browser security model)
    const testUrl = `https://${domain}`;

    // Attempt basic connectivity test
    const response = await fetch(testUrl, {
      method: 'HEAD',
      signal: AbortSignal.timeout(3000)
    }).catch(() => null);

    if (response) {
      // Estimate security based on response properties
      signals.securityHeaders = estimateSecurityHeaders(response);
      signals.tlsVersion = '1.2'; // Assume modern TLS for successful HTTPS

      // Check if certificate info is available
      signals.certificate = {
        issuer: estimateCertificateIssuer(domain),
        email: null
      };
    }

  } catch (error) {
    // Expected for many requests due to CORS
  }

  return signals;
}

async function gatherInfrastructureSignals(domain) {
  const signals = {
    hostingProvider: null,
    techStack: []
  };

  try {
    // Detect hosting provider from domain patterns
    if (domain.includes('amazonaws') || domain.includes('aws')) {
      signals.hostingProvider = 'AWS';
    } else if (domain.includes('cloudflare')) {
      signals.hostingProvider = 'Cloudflare';
    } else if (domain.includes('github.io')) {
      signals.hostingProvider = 'GitHub Pages';
      signals.techStack.push('static');
    } else if (domain.includes('netlify')) {
      signals.hostingProvider = 'Netlify';
      signals.techStack.push('modern');
    } else if (domain.includes('vercel')) {
      signals.hostingProvider = 'Vercel';
      signals.techStack.push('modern');
    }

    // Detect technology patterns from subdomain
    if (domain.includes('api.')) {
      signals.techStack.push('api');
    }
    if (domain.includes('app.') || domain.includes('webapp.')) {
      signals.techStack.push('webapp');
    }
    if (domain.includes('admin.')) {
      signals.techStack.push('admin');
    }

  } catch (error) {
    console.error('Failed to gather infrastructure signals:', error);
  }

  return signals;
}

function calculateTyposquattingScore(domain) {
  // List of popular domains to check against
  const popularDomains = [
    'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
    'apple.com', 'netflix.com', 'paypal.com', 'twitter.com',
    'instagram.com', 'linkedin.com', 'github.com', 'stackoverflow.com'
  ];

  let maxSimilarity = 0;

  for (const popular of popularDomains) {
    const similarity = calculateStringSimilarity(domain, popular);
    maxSimilarity = Math.max(maxSimilarity, similarity);

    // Check for common typosquatting patterns
    if (domain.includes(popular.split('.')[0]) && domain !== popular) {
      maxSimilarity = Math.max(maxSimilarity, 0.8);
    }
  }

  return maxSimilarity;
}

function estimateSecurityHeaders(response) {
  // Estimate security header presence based on response
  let score = 0.3; // Base score

  // Check available headers (limited by CORS)
  const headers = response.headers;
  if (headers.get('content-security-policy')) score += 0.2;
  if (headers.get('strict-transport-security')) score += 0.2;
  if (headers.get('x-frame-options')) score += 0.1;
  if (headers.get('x-content-type-options')) score += 0.1;

  return Math.min(1.0, score);
}

function estimateCertificateIssuer(domain) {
  // Heuristic certificate issuer estimation
  if (domain.endsWith('.gov')) {
    return 'DigiCert Gov';
  } else if (domain.includes('github') || domain.includes('netlify') || domain.includes('vercel')) {
    return 'Let\'s Encrypt';
  } else if (domain.includes('google') || domain.includes('microsoft')) {
    return 'DigiCert';
  } else {
    // Most common issuers
    const issuers = ['Let\'s Encrypt', 'DigiCert', 'Cloudflare'];
    const hash = domain.split('').reduce((a, b) => a + b.charCodeAt(0), 0);
    return issuers[hash % issuers.length];
  }
}

async function checkGitExposure(domain) {
  try {
    // Whitelist of known legitimate development/design tools
    const developmentToolWhitelist = [
      'penpot.app',
      'design.penpot.app',
      'github.io',
      'netlify.app',
      'vercel.app',
      'gitlab.io',
      'codepen.io',
      'codesandbox.io',
      'stackblitz.com',
      'replit.com'
    ];

    // Check if domain is whitelisted
    if (developmentToolWhitelist.some(whitelisted => domain.includes(whitelisted))) {
      return null; // Skip check for known dev tools
    }

    const response = await fetch(`https://${domain}/.git/config`, {
      signal: AbortSignal.timeout(3000)
    });

    if (response && response.ok) {
      const text = await response.text();
      // More specific check - look for actual git config patterns
      if (text.includes('[core]') && text.includes('bare = false') && text.includes('repositoryformatversion')) {
        return {
          exposed: true,
          type: 'git_exposure',
          severity: 'warning', // Reduced from critical
          riskPoints: 45, // Reduced from 95
          details: 'Potential git repository exposure detected. Verify if this is intentional.',
          verification: `Check: https://${domain}/.git/config`
        };
      }
    }
  } catch (error) {
    // Expected for most sites
  }
  
  return { exposed: false };
}

async function checkEnvFileExposure(domain) {
  const envPaths = ['/.env', '/.env.local', '/.env.production'];
  
  for (const path of envPaths) {
    try {
      const response = await fetch(`https://${domain}${path}`, {
        signal: AbortSignal.timeout(3000)
      });
      
      if (response && response.ok) {
        const text = await response.text();
        if (text.includes('API_KEY=') || text.includes('SECRET=') || text.includes('PASSWORD=')) {
          return {
            exposed: true,
            type: 'env_file',
            severity: 'critical',
            riskPoints: 100,
            details: 'Environment file exposed with secrets!'
          };
        }
      }
    } catch (error) {
      continue;
    }
  }
  
  return { exposed: false };
}

// Parse Cookie header to extract individual cookies
function parseCookieHeader(cookieHeader) {
  const cookies = [];
  const pairs = cookieHeader.split(';');
  
  pairs.forEach(pair => {
    const [name, value] = pair.trim().split('=');
    if (name && value) {
      cookies.push({
        name: name.trim(),
        value: value.trim(),
        isSessionToken: isSessionCookie(name.trim()),
        isAuthToken: isAuthCookie(name.trim())
      });
    }
  });
  
  return cookies;
}

// Analyze Set-Cookie header for security attributes
function analyzeSetCookie(setCookieValue) {
  const analysis = {
    name: null,
    value: null,
    attributes: {
      httpOnly: false,
      secure: false,
      sameSite: null,
      domain: null,
      path: null,
      expires: null,
      maxAge: null
    },
    securityScore: 0,
    isSessionCookie: false,
    isAuthCookie: false
  };
  
  const parts = setCookieValue.split(';');
  
  // Parse cookie name and value
  if (parts[0]) {
    const [name, value] = parts[0].trim().split('=');
    analysis.name = name;
    analysis.value = value;
    analysis.isSessionCookie = isSessionCookie(name);
    analysis.isAuthCookie = isAuthCookie(name);
  }
  
  // Parse attributes
  parts.slice(1).forEach(part => {
    const trimmed = part.trim().toLowerCase();
    
    if (trimmed === 'httponly') {
      analysis.attributes.httpOnly = true;
      analysis.securityScore += 2;
    } else if (trimmed === 'secure') {
      analysis.attributes.secure = true;
      analysis.securityScore += 2;
    } else if (trimmed.startsWith('samesite=')) {
      analysis.attributes.sameSite = trimmed.split('=')[1];
      analysis.securityScore += 1;
    } else if (trimmed.startsWith('domain=')) {
      analysis.attributes.domain = trimmed.split('=')[1];
    } else if (trimmed.startsWith('path=')) {
      analysis.attributes.path = trimmed.split('=')[1];
    } else if (trimmed.startsWith('expires=')) {
      analysis.attributes.expires = trimmed.split('=')[1];
    } else if (trimmed.startsWith('max-age=')) {
      analysis.attributes.maxAge = trimmed.split('=')[1];
    }
  });
  
  return analysis;
}

// Check if cookie name indicates a session cookie
function isSessionCookie(cookieName) {
  const sessionPatterns = [
    'session', 'sess', 'jsessionid', 'phpsessid', 'asp.net_sessionid',
    'connect.sid', 'laravel_session', 'django_session'
  ];
  
  const lowerName = cookieName.toLowerCase();
  return sessionPatterns.some(pattern => lowerName.includes(pattern));
}

// Check if cookie name indicates an authentication cookie
function isAuthCookie(cookieName) {
  const authPatterns = [
    'auth', 'token', 'jwt', 'access', 'refresh', 'bearer',
    'login', 'user', 'identity', 'credential'
  ];
  
  const lowerName = cookieName.toLowerCase();
  return authPatterns.some(pattern => lowerName.includes(pattern));
}

// Analyze authentication failures and access denied responses
function analyzeAuthFailure(statusCode, responseHeaders, url) {
  const analysis = {
    isFailure: false,
    failureType: null,
    statusCode: statusCode,
    errorDetails: null,
    retryAfter: null,
    rateLimited: false,
    blockedByWAF: false,
    suspiciousActivity: false
  };
  
  // Analyze status codes
  if (statusCode >= 400) {
    analysis.isFailure = true;
    
    switch (statusCode) {
      case 400:
        analysis.failureType = 'Bad Request - Invalid parameters or malformed request';
        break;
      case 401:
        analysis.failureType = 'Unauthorized - Authentication required or failed';
        break;
      case 403:
        analysis.failureType = 'Forbidden - Access denied or insufficient permissions';
        break;
      case 404:
        analysis.failureType = 'Not Found - Endpoint may not exist or be disabled';
        break;
      case 405:
        analysis.failureType = 'Method Not Allowed - HTTP method not supported';
        break;
      case 429:
        analysis.failureType = 'Too Many Requests - Rate limited';
        analysis.rateLimited = true;
        break;
      case 500:
        analysis.failureType = 'Internal Server Error - Server-side authentication failure';
        break;
      case 502:
        analysis.failureType = 'Bad Gateway - Authentication service unavailable';
        break;
      case 503:
        analysis.failureType = 'Service Unavailable - Authentication service down';
        break;
      default:
        analysis.failureType = `HTTP ${statusCode} - Authentication-related error`;
    }
  }
  
  // Analyze response headers for additional failure context
  if (responseHeaders) {
    responseHeaders.forEach(header => {
      const name = header.name.toLowerCase();
      const value = header.value.toLowerCase();
      
      switch (name) {
        case 'www-authenticate':
          analysis.errorDetails = `Authentication challenge: ${header.value}`;
          break;
        case 'retry-after':
          analysis.retryAfter = header.value;
          break;
        case 'x-ratelimit-remaining':
          if (parseInt(header.value) === 0) {
            analysis.rateLimited = true;
          }
          break;
        case 'server':
          if (value.includes('cloudflare') || value.includes('aws') || value.includes('akamai')) {
            analysis.blockedByWAF = statusCode === 403;
          }
          break;
        case 'x-frame-options':
          if (statusCode === 403 && value === 'deny') {
            analysis.errorDetails = 'Request blocked by X-Frame-Options policy';
          }
          break;
      }
    });
  }
  
  // Check for suspicious patterns
  const lowerUrl = url.toLowerCase();
  if (statusCode === 401 || statusCode === 403) {
    if (lowerUrl.includes('admin') || lowerUrl.includes('api/v') || lowerUrl.includes('internal')) {
      analysis.suspiciousActivity = true;
    }
  }
  
  return analysis;
}

// Analyze network errors for authentication context
function analyzeAuthError(error, url) {
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
};

// Clean up old sessions every 10 minutes
setInterval(() => sessionTracker.cleanupOldSessions(), 10 * 60 * 1000);

// Generate unique session ID (legacy function for compatibility)
function generateSessionId() {
  return 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

// Calculate overall risk score for an authentication event
function calculateOverallRiskScore(requestData) {
  let riskScore = 0;
  const riskFactors = [];
  const vulnerabilities = [];
  const metadata = requestData.metadata || {};

  // DNS intelligence risks
  const dnsIntel = metadata.dnsIntelligence || {};
  if (dnsIntel.isHomograph) {
    riskScore += 40;
    riskFactors.push({
      type: 'DNS_HOMOGRAPH_ATTACK',
      severity: 'CRITICAL',
      points: 40,
      description: 'Domain uses homograph characters that may impersonate legitimate sites',
      recommendation: 'Verify domain legitimacy before proceeding'
    });
    vulnerabilities.push({
      category: 'Domain Security',
      finding: 'Homograph Attack Domain',
      severity: 'CRITICAL',
      description: 'This domain contains characters that visually mimic a legitimate domain',
      impact: 'Users may be tricked into believing this is a trusted site'
    });
  }
  if (dnsIntel.isDGA) {
    riskScore += 35;
    riskFactors.push({
      type: 'DGA_DOMAIN',
      severity: 'HIGH',
      points: 35,
      description: 'Domain shows characteristics of algorithmically generated domains',
      recommendation: 'Investigate domain registration and purpose'
    });
  }
  if (dnsIntel.suspiciousPatterns?.length > 0) {
    riskScore += 20;
    riskFactors.push({
      type: 'SUSPICIOUS_DNS_PATTERNS',
      severity: 'MEDIUM',
      points: 20,
      description: `Suspicious DNS patterns detected: ${dnsIntel.suspiciousPatterns.join(', ')}`,
      recommendation: 'Review DNS configuration for anomalies'
    });
  }

  // OAuth consent risks
  const consentAnalysis = metadata.consentAnalysis || {};
  if (consentAnalysis.scopeAnalysis) {
    const scopeRisk = consentAnalysis.scopeAnalysis.riskScore || 0;
    riskScore += scopeRisk;
    if (scopeRisk > 0) {
      riskFactors.push({
        type: 'OAUTH_EXCESSIVE_SCOPES',
        severity: scopeRisk >= 20 ? 'HIGH' : 'MEDIUM',
        points: scopeRisk,
        description: `OAuth application requests ${consentAnalysis.scopeAnalysis.totalScopes || 'multiple'} permissions including sensitive scopes`,
        recommendation: 'Review if application truly needs all requested permissions'
      });

      if (consentAnalysis.scopeAnalysis.highRisk?.length > 0) {
        vulnerabilities.push({
          category: 'OAuth Security',
          finding: 'Excessive Permission Scope',
          severity: 'HIGH',
          description: `Application requests high-risk permissions: ${consentAnalysis.scopeAnalysis.highRisk.join(', ')}`,
          impact: 'Application could access sensitive user data beyond its legitimate needs'
        });
      }
    }
  }
  if (consentAnalysis.applicationInfo?.suspicious) {
    riskScore += 30;
    riskFactors.push({
      type: 'SUSPICIOUS_OAUTH_APP',
      severity: 'HIGH',
      points: 30,
      description: 'OAuth application shows suspicious characteristics',
      recommendation: 'Verify application authenticity before granting access'
    });
  }

  // CDN mismatch risks
  const cdnAnalysis = metadata.cdnAnalysis || {};
  if (cdnAnalysis.cdnMismatch) {
    riskScore += 25;
    riskFactors.push({
      type: 'CDN_MISMATCH',
      severity: 'MEDIUM',
      points: 25,
      description: `CDN provider mismatch: expected ${cdnAnalysis.expectedCDN}, found ${cdnAnalysis.cdnProvider}`,
      recommendation: 'Verify if CDN configuration is intentional'
    });
  }
  if (!cdnAnalysis.isLegitimateInfrastructure && cdnAnalysis.cdnProvider) {
    riskScore += 15;
    riskFactors.push({
      type: 'SUSPICIOUS_CDN',
      severity: 'LOW',
      points: 15,
      description: 'CDN infrastructure may not be from expected provider',
      recommendation: 'Verify CDN legitimacy'
    });
  }

  // Security context risks
  const securityContext = metadata.securityContext || {};
  if (!securityContext.isSecure) {
    riskScore += 50;
    riskFactors.push({
      type: 'INSECURE_TRANSPORT',
      severity: 'CRITICAL',
      points: 50,
      description: 'Authentication request sent over HTTP instead of HTTPS',
      recommendation: 'Use HTTPS for all authentication requests'
    });
    vulnerabilities.push({
      category: 'Transport Security',
      finding: 'Unencrypted Authentication',
      severity: 'CRITICAL',
      description: 'Authentication credentials transmitted over unencrypted HTTP connection',
      impact: 'Credentials can be intercepted by network attackers'
    });
  }
  if (securityContext.crossOrigin) {
    riskScore += 10;
    riskFactors.push({
      type: 'CROSS_ORIGIN_AUTH',
      severity: 'LOW',
      points: 10,
      description: 'Authentication request crosses origin boundaries',
      recommendation: 'Verify cross-origin authentication is intentional'
    });
  }

  // Authentication failure risks
  const authFailure = metadata.authFailureAnalysis || {};
  if (authFailure.isFailure) {
    if (authFailure.statusCode === 401 || authFailure.statusCode === 403) {
      riskScore += 20;
      riskFactors.push({
        type: 'AUTH_FAILURE',
        severity: 'MEDIUM',
        points: 20,
        description: `Authentication failed with status ${authFailure.statusCode}: ${authFailure.failureType}`,
        recommendation: 'Investigate cause of authentication failure'
      });
    }
    if (authFailure.suspiciousActivity) {
      riskScore += 30;
      riskFactors.push({
        type: 'SUSPICIOUS_AUTH_ACTIVITY',
        severity: 'HIGH',
        points: 30,
        description: 'Authentication attempt shows suspicious patterns',
        recommendation: 'Monitor for potential attack attempts'
      });
    }
  }

  // URL analysis risks
  const urlParts = metadata.urlParts || {};
  if (urlParts.hasSensitiveParams) {
    riskScore += 25;
    riskFactors.push({
      type: 'SENSITIVE_PARAMS_IN_URL',
      severity: 'HIGH',
      points: 25,
      description: 'URL contains sensitive parameters that may be logged',
      recommendation: 'Use POST body or secure headers for sensitive data'
    });
    vulnerabilities.push({
      category: 'Information Disclosure',
      finding: 'Sensitive Data in URL',
      severity: 'HIGH',
      description: 'Authentication tokens or sensitive parameters exposed in URL',
      impact: 'Sensitive data may be logged in server logs, browser history, or referrer headers'
    });
  }
  if (urlParts.suspiciousPatterns?.length > 0) {
    riskScore += 15;
    riskFactors.push({
      type: 'SUSPICIOUS_URL_PATTERNS',
      severity: 'MEDIUM',
      points: 15,
      description: `Suspicious URL patterns detected: ${urlParts.suspiciousPatterns.join(', ')}`,
      recommendation: 'Review URL structure for security issues'
    });
  }

  // JWT/Token analysis
  if (requestData.responseHeaders || requestData.requestHeaders) {
    const allHeaders = [...(requestData.responseHeaders || []), ...(requestData.requestHeaders || [])];
    const authHeaders = allHeaders.filter(h =>
      h.name.toLowerCase().includes('authorization') ||
      h.name.toLowerCase().includes('auth') ||
      h.value.startsWith('Bearer ') ||
      h.value.startsWith('jwt ')
    );

    authHeaders.forEach(header => {
      if (header.value.includes('eyJ')) { // Potential JWT
        const jwtAnalysis = analyzeJWT(header.value);
        if (jwtAnalysis.vulnerabilities?.length > 0) {
          riskScore += jwtAnalysis.riskScore || 0;
          vulnerabilities.push(...jwtAnalysis.vulnerabilities);
          riskFactors.push(...jwtAnalysis.riskFactors);
        }
      }
    });
  }

  // Store analysis results
  const finalRiskScore = Math.min(riskScore, 100);
  const analysis = {
    riskScore: finalRiskScore,
    riskLevel: finalRiskScore >= 80 ? 'CRITICAL' : finalRiskScore >= 60 ? 'HIGH' : finalRiskScore >= 30 ? 'MEDIUM' : 'LOW',
    riskFactors: riskFactors,
    vulnerabilities: vulnerabilities,
    summary: {
      totalIssues: riskFactors.length,
      criticalIssues: riskFactors.filter(f => f.severity === 'CRITICAL').length,
      highIssues: riskFactors.filter(f => f.severity === 'HIGH').length,
      mediumIssues: riskFactors.filter(f => f.severity === 'MEDIUM').length,
      lowIssues: riskFactors.filter(f => f.severity === 'LOW').length
    }
  };

  // Add to request metadata
  if (!requestData.metadata) requestData.metadata = {};
  requestData.metadata.securityAnalysis = analysis;

  return finalRiskScore;
}

// JWT Analysis Function
function analyzeJWT(tokenValue) {
  const analysis = {
    riskScore: 0,
    riskFactors: [],
    vulnerabilities: [],
    decodedToken: null
  };

  try {
    // Extract JWT from various formats
    let jwt = tokenValue.replace(/^Bearer\s+/i, '').replace(/^jwt\s+/i, '').trim();

    // Basic JWT format check
    const parts = jwt.split('.');
    if (parts.length !== 3) {
      return analysis; // Not a valid JWT
    }

    // Decode header and payload
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

    analysis.decodedToken = {
      header: header,
      payload: payload,
      signature: parts[2]
    };

    // Check for critical vulnerabilities

    // 1. Algorithm "none" vulnerability
    if (header.alg === 'none' || header.alg === 'None' || header.alg === 'NONE') {
      analysis.riskScore += 100;
      analysis.riskFactors.push({
        type: 'JWT_ALG_NONE',
        severity: 'CRITICAL',
        points: 100,
        description: 'JWT uses "none" algorithm - signature verification disabled',
        recommendation: 'Use a proper signing algorithm (RS256, ES256, HS256)'
      });
      analysis.vulnerabilities.push({
        category: 'JWT Security',
        finding: 'Algorithm None Attack',
        severity: 'CRITICAL',
        description: 'JWT token uses "none" algorithm, allowing signature bypass',
        impact: 'Attackers can create valid tokens without knowing the secret key'
      });
    }

    // 2. Weak algorithms
    if (['HS256', 'HS384', 'HS512'].includes(header.alg)) {
      analysis.riskScore += 20;
      analysis.riskFactors.push({
        type: 'JWT_WEAK_ALG',
        severity: 'MEDIUM',
        points: 20,
        description: `JWT uses symmetric algorithm ${header.alg} which may be vulnerable to algorithm confusion`,
        recommendation: 'Consider using asymmetric algorithms like RS256 or ES256'
      });
    }

    // 3. No expiration
    if (!payload.exp) {
      analysis.riskScore += 30;
      analysis.riskFactors.push({
        type: 'JWT_NO_EXPIRATION',
        severity: 'HIGH',
        points: 30,
        description: 'JWT has no expiration time (exp claim missing)',
        recommendation: 'Set appropriate expiration time for tokens'
      });
      analysis.vulnerabilities.push({
        category: 'JWT Security',
        finding: 'Missing Token Expiration',
        severity: 'HIGH',
        description: 'JWT token has no expiration claim, creating indefinite validity',
        impact: 'Compromised tokens remain valid indefinitely'
      });
    }

    // 4. Long expiration (more than 24 hours)
    if (payload.exp) {
      const expirationTime = new Date(payload.exp * 1000);
      const issuedTime = payload.iat ? new Date(payload.iat * 1000) : new Date();
      const lifetimeHours = (expirationTime.getTime() - issuedTime.getTime()) / (1000 * 60 * 60);

      if (lifetimeHours > 24) {
        analysis.riskScore += 15;
        analysis.riskFactors.push({
          type: 'JWT_LONG_EXPIRATION',
          severity: 'MEDIUM',
          points: 15,
          description: `JWT has very long expiration time (${Math.round(lifetimeHours)} hours)`,
          recommendation: 'Use shorter token lifetimes with refresh token pattern'
        });
      }
    }

    // 5. Sensitive data in payload
    const sensitiveFields = ['password', 'secret', 'key', 'token', 'ssn', 'credit', 'card'];
    const payloadStr = JSON.stringify(payload).toLowerCase();
    const foundSensitive = sensitiveFields.filter(field => payloadStr.includes(field));

    if (foundSensitive.length > 0) {
      analysis.riskScore += 40;
      analysis.riskFactors.push({
        type: 'JWT_SENSITIVE_DATA',
        severity: 'HIGH',
        points: 40,
        description: `JWT payload contains potentially sensitive fields: ${foundSensitive.join(', ')}`,
        recommendation: 'Avoid storing sensitive data in JWT payload'
      });
      analysis.vulnerabilities.push({
        category: 'Information Disclosure',
        finding: 'Sensitive Data in JWT',
        severity: 'HIGH',
        description: 'JWT payload contains sensitive information',
        impact: 'Sensitive data is exposed as JWTs are only base64 encoded, not encrypted'
      });
    }

    // 6. Missing critical claims
    const requiredClaims = ['iss', 'aud', 'sub'];
    const missingClaims = requiredClaims.filter(claim => !payload[claim]);

    if (missingClaims.length > 0) {
      analysis.riskScore += 10;
      analysis.riskFactors.push({
        type: 'JWT_MISSING_CLAIMS',
        severity: 'LOW',
        points: 10,
        description: `JWT missing recommended claims: ${missingClaims.join(', ')}`,
        recommendation: 'Include issuer (iss), audience (aud), and subject (sub) claims'
      });
    }

  } catch (error) {
    // If we can't decode it, it might not be a valid JWT
    console.log('JWT analysis failed:', error);
  }

  return analysis;
}

// (Removed duplicate updateBadge - already defined at line 53)


// Convert comprehensive intelligence profile to SADS-compatible signals
function convertComprehensiveProfileToSignals(profile) {
  const signals = {
    domain: profile.domain,
    domainAge: profile.reputation?.historicalData?.domainAge || null,
    gitExposed: { exposed: false },
    envFileExposed: { exposed: false },
    certificate: null,
    techStack: [],
    securityHeaders: 0,
    tlsVersion: null,
    hostingProvider: null,
    hasLoginForm: false,
    hasCreditCardForm: false,
    typosquattingScore: 0,
    contentSimilarity: 0,
    stagingIndicators: false
  };

  try {
    // Map network data
    if (profile.network) {
      signals.hostingProvider = profile.network.hosting?.provider;
      signals.techStack = profile.network.hosting?.cloudServices ?
        Object.keys(profile.network.hosting.cloudServices).filter(service =>
          profile.network.hosting.cloudServices[service]) : [];
    }

    // Map security data
    if (profile.security) {
      signals.securityHeaders = (profile.security.headers?.score || 0) / 100;
      signals.tlsVersion = profile.security.tls?.protocols?.includes('TLS 1.3') ? '1.3' :
                          profile.security.tls?.protocols?.includes('TLS 1.2') ? '1.2' : '1.0';

      if (profile.security.certificates) {
        signals.certificate = {
          issuer: profile.security.certificates.issuer,
          email: null // Not available in current implementation
        };
      }

      // Check for exposed vulnerabilities
      if (profile.security.vulnerabilities?.exposures) {
        const exposures = profile.security.vulnerabilities.exposures;

        exposures.forEach(exposure => {
          if (exposure.path === '/.git/config') {
            signals.gitExposed = {
              exposed: true,
              severity: exposure.risk,
              details: ['/.git/config']
            };
          } else if (exposure.path === '/.env') {
            signals.envFileExposed = {
              exposed: true,
              severity: exposure.risk
            };
          }
        });
      }
    }

    // Map content data
    if (profile.content) {
      signals.hasLoginForm = profile.content.forms?.loginForm || false;
      signals.hasCreditCardForm = profile.content.forms?.paymentForm || false;
      signals.contentSimilarity = profile.content.textAnalysis?.similarity || 0;

      // Add detected technologies
      if (profile.content.technology) {
        if (profile.content.technology.frameworks) {
          signals.techStack = signals.techStack.concat(profile.content.technology.frameworks);
        }
        if (profile.content.technology.cms) {
          signals.techStack.push(profile.content.technology.cms);
        }
      }
    }

    // Map ML features for enhanced analysis
    if (profile.ml?.domain) {
      signals.typosquattingScore = profile.ml.domain.hasBrandName &&
        profile.reputation?.historicalData?.domainAge < 90 ? 0.8 : 0;

      // Add ML-derived staging indicators
      if (profile.ml.domain.suspiciousKeywords > 0 ||
          profile.ml.url?.hasPhishingKeywords) {
        signals.stagingIndicators = true;
      }
    }

    // Map compound metrics
    if (profile.compound) {
      // Use compound metrics to enhance signal accuracy
      if (profile.compound.deceptionProbability > 70) {
        signals.typosquattingScore = Math.max(signals.typosquattingScore, 0.9);
      }
    }

    console.log(`Converted comprehensive profile to SADS signals for ${profile.domain}:`, {
      domainAge: signals.domainAge,
      gitExposed: signals.gitExposed.exposed,
      securityHeaders: signals.securityHeaders,
      hostingProvider: signals.hostingProvider,
      techStackCount: signals.techStack.length
    });

  } catch (error) {
    console.error('Failed to convert comprehensive profile to signals:', error);
  }

  return signals;
}
