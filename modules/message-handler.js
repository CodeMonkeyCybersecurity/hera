// Message Handler - Routes messages from popup, content scripts, and other extension components

import { memoryManager } from './memory-manager.js';
import { storageManager } from './storage-manager.js';

export class MessageHandler {
  constructor(requestProcessor, debuggerManager) {
    this.requestProcessor = requestProcessor;
    this.debuggerManager = debuggerManager;
  }

  // Handle all incoming messages
  async handleMessage(message, sender, sendResponse) {
    console.log('Background received message:', message.action);

    // Handle intercepted responses from response-interceptor.js
    if (message.action === 'responseIntercepted') {
      await this.requestProcessor.handleInterceptedResponse(message.data);
      sendResponse({ success: true });
      return false;
    }

    // Handle active security probes
    if (message.action === 'probe:alg_none') {
      this.performAlgNoneProbe(message.request, message.jwt).then(sendResponse);
      return true;
    }

    if (message.action === 'repeater:send') {
      this.performRepeaterRequest(message.rawRequest).then(sendResponse);
      return true;
    }

    // Get all requests for popup display
    if (message.action === 'getRequests') {
      const storedSessions = await storageManager.getAllSessions();
      const currentRequests = memoryManager.getAllAuthRequests();

      // Merge stored and in-memory requests (prefer in-memory for freshness)
      const byId = new Map();
      for (const item of storedSessions) {
        if (item && item.id) byId.set(item.id, item);
      }
      for (const item of currentRequests) {
        if (item && item.id) byId.set(item.id, item);
      }

      sendResponse(Array.from(byId.values()));
      return true;
    }

    // Get backend scan results for a domain
    if (message.action === 'getBackendScan') {
      const requestsArray = memoryManager.getAllAuthRequests();
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

    // Report blocked form submission
    if (message.action === 'reportBlockedSubmission') {
      console.log(`🛡️ Blocked form submission on ${message.domain}`);
      await storageManager.storeAuthEvent({
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

    // Clear all requests
    if (message.action === 'clearRequests') {
      memoryManager.clearAuthRequests();
      const result = await storageManager.clearAllSessions();
      sendResponse(result);
      return true;
    }

    // Update response capture setting
    if (message.action === 'updateResponseCaptureSetting') {
      if (!message.enabled && this.debuggerManager) {
        await this.debuggerManager.detachAllDebuggers();
      }
      sendResponse({ success: true });
      return false;
    }

    // Generic success response for unknown actions
    if (message.action === 'openPopup' || message.action === 'showTechnicalDetails') {
      sendResponse({ success: true });
      return false;
    }

    return false; // No async response needed
  }

  // Helper: Generate session ID
  generateSessionId() {
    return `session_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Perform alg:none JWT probe (security testing)
  async performAlgNoneProbe(originalRequest, jwt) {
    try {
      const parts = jwt.split('.');
      const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
      const payload = parts[1];

      // Create the malicious header
      header.alg = 'none';
      const maliciousHeader = btoa(JSON.stringify(header))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

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

      // Send the probe request
      const response = await fetch(originalRequest.url, {
        method: originalRequest.method,
        headers: newHeaders,
        credentials: 'include'
      });

      const responseBody = await response.text();

      return {
        success: true,
        vulnerable: response.ok, // If request succeeds, server accepted alg:none
        statusCode: response.status,
        responseBody: responseBody.substring(0, 1000), // Limit response size
        probe: 'alg:none',
        timestamp: Date.now()
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        probe: 'alg:none'
      };
    }
  }

  // Perform custom request (repeater functionality)
  async performRepeaterRequest(rawRequest) {
    try {
      // Parse raw HTTP request
      const lines = rawRequest.split('\n');
      const [method, path, ...rest] = lines[0].split(' ');

      // Parse headers
      const headers = new Headers();
      let i = 1;
      while (i < lines.length && lines[i].trim() !== '') {
        const [name, value] = lines[i].split(': ');
        if (name && value) {
          headers.set(name.trim(), value.trim());
        }
        i++;
      }

      // Parse body (everything after empty line)
      const body = lines.slice(i + 1).join('\n').trim();

      // Get host from headers
      const host = headers.get('Host');
      if (!host) {
        throw new Error('Missing Host header');
      }

      const url = `https://${host}${path}`;

      // Send request
      const response = await fetch(url, {
        method: method,
        headers: headers,
        body: body || undefined,
        credentials: 'include'
      });

      const responseBody = await response.text();

      return {
        success: true,
        statusCode: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
        body: responseBody,
        timestamp: Date.now()
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }
}
