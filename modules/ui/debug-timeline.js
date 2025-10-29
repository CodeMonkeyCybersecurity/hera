/**
 * Debug Timeline - Chat-style visualization of auth flows
 *
 * Displays HTTP requests/responses as a conversation between:
 * - Browser (you)
 * - Auth server (Authentik, Okta, etc.)
 * - Application server (BionicGPT, etc.)
 * - Proxy/Gateway (Caddy, Nginx, etc.)
 *
 * Makes complex OAuth/OIDC flows easier to understand by showing
 * the "conversation" between endpoints.
 */

import { DOMSecurity } from './dom-security.js';

export class DebugTimeline {
  constructor() {
    this.container = null;
  }

  /**
   * Render timeline for a debug session
   */
  render(session, containerElement) {
    this.container = containerElement;
    this.container.innerHTML = '';

    if (!session || !session.requests || session.requests.length === 0) {
      this.renderEmpty();
      return;
    }

    // Create chat container
    const chatContainer = document.createElement('div');
    chatContainer.className = 'debug-chat-container';

    // Add header
    const header = this.renderHeader(session);
    chatContainer.appendChild(header);

    // Add messages
    const messagesContainer = document.createElement('div');
    messagesContainer.className = 'debug-messages';

    // Sort by timestamp
    const sortedRequests = [...session.requests].sort((a, b) => {
      const timeA = a.timestamp || a.capturedAt || 0;
      const timeB = b.timestamp || b.capturedAt || 0;
      return timeA - timeB;
    });

    // Group by endpoint/actor
    let previousActor = null;
    sortedRequests.forEach((request, index) => {
      const actor = this.identifyActor(request.url);
      const message = this.renderMessage(request, actor, previousActor);
      messagesContainer.appendChild(message);
      previousActor = actor;
    });

    // Add console logs if present
    if (session.consoleLogs && session.consoleLogs.length > 0) {
      const consoleDivider = document.createElement('div');
      consoleDivider.className = 'debug-divider';
      consoleDivider.textContent = 'Console Logs';
      messagesContainer.appendChild(consoleDivider);

      session.consoleLogs.forEach(log => {
        const logMessage = this.renderConsoleLog(log);
        messagesContainer.appendChild(logMessage);
      });
    }

    chatContainer.appendChild(messagesContainer);
    this.container.appendChild(chatContainer);

    // Auto-scroll to bottom
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  /**
   * Render header with session info
   */
  renderHeader(session) {
    const header = document.createElement('div');
    header.className = 'debug-chat-header';

    const domain = DOMSecurity.sanitize(session.domain);
    const startTime = new Date(session.startTime).toLocaleString();
    const duration = session.duration
      ? `${Math.round(session.duration / 1000)}s`
      : 'ongoing';

    header.innerHTML = `
      <div class="debug-session-info">
        <h3>🔍 Debug Session: ${domain}</h3>
        <div class="debug-session-meta">
          <span>Started: ${DOMSecurity.sanitize(startTime)}</span>
          <span>Duration: ${DOMSecurity.sanitize(duration)}</span>
          <span>Requests: ${session.requests.length}</span>
        </div>
      </div>
    `;

    return header;
  }

  /**
   * Identify the actor (endpoint) for a request
   */
  identifyActor(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname;
      const pathname = urlObj.pathname;

      // Classify by hostname patterns
      if (hostname.includes('login') || hostname.includes('auth') || hostname.includes('sso')) {
        return {
          type: 'auth-server',
          name: hostname,
          color: '#0ca678',
          icon: '🔐'
        };
      }

      if (hostname.includes('authentik')) {
        return {
          type: 'auth-server',
          name: 'Authentik',
          color: '#fd4b2d',
          icon: '🔐'
        };
      }

      if (hostname.includes('okta')) {
        return {
          type: 'auth-server',
          name: 'Okta',
          color: '#007dc1',
          icon: '🔐'
        };
      }

      if (hostname.includes('microsoft') || hostname.includes('azure') || hostname.includes('office365')) {
        return {
          type: 'auth-server',
          name: 'Microsoft',
          color: '#0078d4',
          icon: '🔐'
        };
      }

      if (hostname.includes('google') || hostname.includes('accounts.google')) {
        return {
          type: 'auth-server',
          name: 'Google',
          color: '#4285f4',
          icon: '🔐'
        };
      }

      // Classify by path patterns
      if (pathname.includes('/oauth') || pathname.includes('/authorize') || pathname.includes('/token')) {
        return {
          type: 'auth-server',
          name: hostname,
          color: '#0ca678',
          icon: '🔐'
        };
      }

      if (pathname.includes('/api')) {
        return {
          type: 'api-server',
          name: hostname,
          color: '#6366f1',
          icon: '⚡'
        };
      }

      // Default to application server
      return {
        type: 'app-server',
        name: hostname,
        color: '#8b5cf6',
        icon: '🌐'
      };

    } catch {
      return {
        type: 'unknown',
        name: 'Unknown',
        color: '#64748b',
        icon: '❓'
      };
    }
  }

  /**
   * Render a request/response as a chat message
   */
  renderMessage(request, actor, previousActor) {
    const message = document.createElement('div');
    message.className = 'debug-message';

    // Show actor header if changed
    const showActor = !previousActor || previousActor.name !== actor.name;

    if (showActor) {
      const actorHeader = document.createElement('div');
      actorHeader.className = 'debug-actor-header';
      actorHeader.style.borderLeftColor = actor.color;
      actorHeader.innerHTML = `
        <span class="debug-actor-icon">${actor.icon}</span>
        <span class="debug-actor-name">${DOMSecurity.sanitize(actor.name)}</span>
        <span class="debug-actor-type">${DOMSecurity.sanitize(actor.type)}</span>
      `;
      message.appendChild(actorHeader);
    }

    // Request bubble
    const requestBubble = this.renderRequestBubble(request, actor);
    message.appendChild(requestBubble);

    // Response bubble (if present)
    if (request.response || request.statusCode) {
      const responseBubble = this.renderResponseBubble(request, actor);
      message.appendChild(responseBubble);
    }

    return message;
  }

  /**
   * Render request as a chat bubble
   */
  renderRequestBubble(request, actor) {
    const bubble = document.createElement('div');
    bubble.className = 'debug-bubble debug-request';
    bubble.style.borderLeftColor = actor.color;

    const method = request.method || 'GET';
    const url = new URL(request.url);
    const timestamp = this.formatTimestamp(request.timestamp || request.capturedAt);

    // Method badge
    const methodClass = this.getMethodClass(method);

    let content = `
      <div class="debug-bubble-header">
        <span class="debug-method ${methodClass}">${DOMSecurity.sanitize(method)}</span>
        <span class="debug-timestamp">${DOMSecurity.sanitize(timestamp)}</span>
      </div>
      <div class="debug-url">${DOMSecurity.sanitize(url.pathname)}${DOMSecurity.sanitize(url.search)}</div>
    `;

    // Headers (collapsed by default)
    if (request.headers || request.requestHeaders) {
      const headers = request.headers || request.requestHeaders;
      content += this.renderHeaders('Request Headers', headers);
    }

    // POST data
    if (request.postData || request.requestBody) {
      const postData = request.postData || request.requestBody;
      content += this.renderPostData(postData);
    }

    bubble.innerHTML = content;
    return bubble;
  }

  /**
   * Render response as a chat bubble
   */
  renderResponseBubble(request, actor) {
    const bubble = document.createElement('div');
    bubble.className = 'debug-bubble debug-response';
    bubble.style.borderLeftColor = actor.color;

    const status = request.response?.status || request.statusCode || 0;
    const statusText = request.response?.statusText || '';
    const statusClass = this.getStatusClass(status);

    let content = `
      <div class="debug-bubble-header">
        <span class="debug-status ${statusClass}">${status} ${DOMSecurity.sanitize(statusText)}</span>
      </div>
    `;

    // Headers
    if (request.response?.headers || request.responseHeaders) {
      const headers = request.response?.headers || request.responseHeaders;
      content += this.renderHeaders('Response Headers', headers);
    }

    // Security details (TLS)
    if (request.response?.securityDetails) {
      content += this.renderSecurityDetails(request.response.securityDetails);
    }

    // Timing
    if (request.response?.timing) {
      content += this.renderTiming(request.response.timing);
    }

    bubble.innerHTML = content;
    return bubble;
  }

  /**
   * Render headers (collapsible)
   */
  renderHeaders(title, headers) {
    if (!headers || (Array.isArray(headers) && headers.length === 0)) {
      return '';
    }

    const headerId = `headers-${Math.random().toString(36).substr(2, 9)}`;

    let headersList = '';
    if (Array.isArray(headers)) {
      headersList = headers
        .map(h => `<div><strong>${DOMSecurity.sanitize(h.name)}:</strong> ${DOMSecurity.sanitize(h.value)}</div>`)
        .join('');
    } else if (typeof headers === 'object') {
      headersList = Object.entries(headers)
        .map(([name, value]) => `<div><strong>${DOMSecurity.sanitize(name)}:</strong> ${DOMSecurity.sanitize(value)}</div>`)
        .join('');
    }

    return `
      <details class="debug-details">
        <summary>${DOMSecurity.sanitize(title)}</summary>
        <div class="debug-details-content">
          ${headersList}
        </div>
      </details>
    `;
  }

  /**
   * Render POST data
   */
  renderPostData(postData) {
    if (!postData) return '';

    let formatted = postData;
    try {
      // Try to parse as JSON
      const parsed = JSON.parse(postData);
      formatted = JSON.stringify(parsed, null, 2);
    } catch {
      // Try to parse as URLSearchParams
      try {
        const params = new URLSearchParams(postData);
        formatted = Array.from(params.entries())
          .map(([key, value]) => `${key}=${value}`)
          .join('\n');
      } catch {
        // Use raw data
      }
    }

    return `
      <details class="debug-details">
        <summary>POST Data</summary>
        <pre class="debug-post-data">${DOMSecurity.sanitize(formatted)}</pre>
      </details>
    `;
  }

  /**
   * Render security details (TLS/SSL)
   */
  renderSecurityDetails(details) {
    return `
      <details class="debug-details">
        <summary>🔒 Security Details</summary>
        <div class="debug-details-content">
          <div><strong>Protocol:</strong> ${DOMSecurity.sanitize(details.protocol)}</div>
          <div><strong>Cipher:</strong> ${DOMSecurity.sanitize(details.cipher)}</div>
          <div><strong>Subject:</strong> ${DOMSecurity.sanitize(details.subjectName)}</div>
          <div><strong>Issuer:</strong> ${DOMSecurity.sanitize(details.issuer)}</div>
          <div><strong>Valid from:</strong> ${DOMSecurity.sanitize(new Date(details.validFrom * 1000).toLocaleDateString())}</div>
          <div><strong>Valid to:</strong> ${DOMSecurity.sanitize(new Date(details.validTo * 1000).toLocaleDateString())}</div>
        </div>
      </details>
    `;
  }

  /**
   * Render timing information
   */
  renderTiming(timing) {
    const total = Object.values(timing).reduce((sum, val) => sum + (val > 0 ? val : 0), 0);

    return `
      <details class="debug-details">
        <summary>⏱️ Timing (${Math.round(total)}ms)</summary>
        <div class="debug-details-content">
          ${timing.blocked > 0 ? `<div><strong>Blocked:</strong> ${Math.round(timing.blocked)}ms</div>` : ''}
          ${timing.dns > 0 ? `<div><strong>DNS:</strong> ${Math.round(timing.dns)}ms</div>` : ''}
          ${timing.connect > 0 ? `<div><strong>Connect:</strong> ${Math.round(timing.connect)}ms</div>` : ''}
          ${timing.ssl > 0 ? `<div><strong>SSL:</strong> ${Math.round(timing.ssl)}ms</div>` : ''}
          ${timing.send > 0 ? `<div><strong>Send:</strong> ${Math.round(timing.send)}ms</div>` : ''}
          ${timing.wait > 0 ? `<div><strong>Wait:</strong> ${Math.round(timing.wait)}ms</div>` : ''}
          ${timing.receive > 0 ? `<div><strong>Receive:</strong> ${Math.round(timing.receive)}ms</div>` : ''}
        </div>
      </details>
    `;
  }

  /**
   * Render console log message
   */
  renderConsoleLog(log) {
    const message = document.createElement('div');
    message.className = `debug-console-log debug-console-${log.level}`;

    const timestamp = this.formatTimestamp(log.timestamp);

    message.innerHTML = `
      <div class="debug-console-header">
        <span class="debug-console-level">${DOMSecurity.sanitize(log.level.toUpperCase())}</span>
        <span class="debug-timestamp">${DOMSecurity.sanitize(timestamp)}</span>
      </div>
      <div class="debug-console-text">${DOMSecurity.sanitize(log.text)}</div>
      ${log.url ? `<div class="debug-console-source">${DOMSecurity.sanitize(log.url)}:${log.line || 0}</div>` : ''}
    `;

    return message;
  }

  /**
   * Render empty state
   */
  renderEmpty() {
    this.container.innerHTML = `
      <div class="debug-empty">
        <div class="debug-empty-icon">📡</div>
        <h3>No Debug Data Captured</h3>
        <p>Enable debug mode for a domain and perform authentication to see the flow here.</p>
      </div>
    `;
  }

  /**
   * Format timestamp for display
   */
  formatTimestamp(timestamp) {
    if (!timestamp) return '';

    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      fractionalSecondDigits: 3
    });
  }

  /**
   * Get CSS class for HTTP method
   */
  getMethodClass(method) {
    const classes = {
      'GET': 'method-get',
      'POST': 'method-post',
      'PUT': 'method-put',
      'DELETE': 'method-delete',
      'PATCH': 'method-patch',
      'OPTIONS': 'method-options'
    };
    return classes[method] || 'method-other';
  }

  /**
   * Get CSS class for HTTP status
   */
  getStatusClass(status) {
    if (status >= 200 && status < 300) return 'status-success';
    if (status >= 300 && status < 400) return 'status-redirect';
    if (status >= 400 && status < 500) return 'status-client-error';
    if (status >= 500) return 'status-server-error';
    return 'status-unknown';
  }
}
