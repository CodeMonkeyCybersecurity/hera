/**
 * Debug Window - Real-time auth traffic feed
 * Displays live stream of authentication requests/responses
 */

import { DOMSecurity } from './modules/ui/dom-security.js';

class DebugWindow {
  constructor() {
    this.domain = null;
    this.startTime = Date.now();
    this.requestCount = 0;
    this.feed = document.getElementById('feed');
    this.port = null;
    this.updateInterval = null;
  }

  async initialize() {
    // Get domain from URL params
    const params = new URLSearchParams(window.location.search);
    this.domain = params.get('domain');

    if (!this.domain) {
      this.showError('No domain specified');
      return;
    }

    // Update header
    document.getElementById('domainName').textContent = this.domain;

    // Connect to background via long-lived port
    this.connectToBackground();

    // Wire up buttons
    document.getElementById('clearBtn').addEventListener('click', () => this.clearFeed());
    document.getElementById('exportBtn').addEventListener('click', () => this.exportSession());
    document.getElementById('closeBtn').addEventListener('click', () => window.close());

    // Update duration counter
    this.updateInterval = setInterval(() => this.updateDuration(), 1000);

    console.log('[DebugWindow] Initialized for domain:', this.domain);
  }

  /**
   * Connect to background script via long-lived port
   */
  connectToBackground() {
    this.port = chrome.runtime.connect({ name: 'debug-window' });

    // Send initial message to register this window
    this.port.postMessage({
      type: 'register',
      domain: this.domain
    });

    // Listen for messages from background
    this.port.onMessage.addListener((message) => {
      this.handleMessage(message);
    });

    // Handle disconnection
    this.port.onDisconnect.addListener(() => {
      console.log('[DebugWindow] Disconnected from background');
      document.getElementById('status').textContent = 'Disconnected';
      document.getElementById('status').style.color = '#f85149';
    });
  }

  /**
   * Handle messages from background script
   */
  handleMessage(message) {
    switch (message.type) {
      case 'request':
        this.addRequest(message.data);
        break;

      case 'response':
        this.updateResponse(message.data);
        break;

      case 'redirect':
        this.addRedirect(message.data);
        break;

      case 'consoleLog':
        this.addConsoleLog(message.data);
        break;

      case 'session':
        // Full session data (for initial load)
        this.loadSession(message.data);
        break;

      default:
        console.warn('[DebugWindow] Unknown message type:', message.type);
    }
  }

  /**
   * Add request to feed
   */
  addRequest(request) {
    // Remove empty state
    const empty = this.feed.querySelector('.feed-empty');
    if (empty) {
      empty.remove();
    }

    const message = document.createElement('div');
    message.className = 'feed-message';
    message.dataset.requestId = request.id || request.requestId;

    const time = this.formatTime(request.timestamp || Date.now());
    const actor = this.identifyActor(request.url);
    const method = request.method || 'GET';
    const urlObj = new URL(request.url);
    const path = urlObj.pathname + urlObj.search;

    message.innerHTML = `
      <div class="message-time">${DOMSecurity.sanitize(time)}</div>
      <div class="message-card request" id="request-${DOMSecurity.sanitize(request.id || request.requestId)}">
        <div class="message-header">
          <span class="actor-icon">${actor.icon}</span>
          <span class="actor-name">${DOMSecurity.sanitize(actor.name)}</span>
          <span class="method ${DOMSecurity.sanitize(method)}">${DOMSecurity.sanitize(method)}</span>
        </div>
        <div class="message-url">${DOMSecurity.sanitize(path)}</div>
        ${request.requestBody ? `
          <div class="message-details">
            <div class="detail-line">
              <span class="detail-key">Body:</span>
              <span class="detail-value">${DOMSecurity.sanitize(this.truncate(request.requestBody, 100))}</span>
            </div>
          </div>
        ` : ''}
      </div>
    `;

    this.feed.appendChild(message);
    this.requestCount++;
    document.getElementById('requestCount').textContent = this.requestCount;

    // Auto-scroll to bottom
    this.feed.scrollTop = this.feed.scrollHeight;
  }

  /**
   * Update request with response data
   */
  updateResponse(response) {
    const card = document.getElementById(`request-${response.requestId}`);
    if (!card) {
      console.warn('[DebugWindow] Response for unknown request:', response.requestId);
      return;
    }

    const statusClass = this.getStatusClass(response.statusCode);
    const statusBadge = `<span class="status-badge ${statusClass}">${response.statusCode}</span>`;

    // Update card
    card.classList.remove('request');
    card.classList.add('response');

    // Add status badge to header
    const header = card.querySelector('.message-header');
    if (header && !header.querySelector('.status-badge')) {
      header.insertAdjacentHTML('beforeend', statusBadge);
    }

    // Add response details
    const existingDetails = card.querySelector('.message-details');
    const responseDetails = `
      <div class="detail-line">
        <span class="detail-key">Status:</span>
        <span class="detail-value">${DOMSecurity.sanitize(response.statusCode)} ${DOMSecurity.sanitize(response.statusText || '')}</span>
      </div>
      ${response.responseHeaders ? `
        <div class="detail-line">
          <span class="detail-key">Headers:</span>
          <span class="detail-value">${response.responseHeaders.length} headers</span>
        </div>
      ` : ''}
    `;

    if (existingDetails) {
      existingDetails.insertAdjacentHTML('beforeend', responseDetails);
    } else {
      card.insertAdjacentHTML('beforeend', `<div class="message-details">${responseDetails}</div>`);
    }
  }

  /**
   * Add redirect to feed
   */
  addRedirect(redirect) {
    const message = document.createElement('div');
    message.className = 'feed-message';

    const time = this.formatTime(redirect.timestamp || Date.now());

    message.innerHTML = `
      <div class="message-time">${DOMSecurity.sanitize(time)}</div>
      <div class="message-card redirect">
        <div class="message-header">
          <span class="actor-icon">↪️</span>
          <span class="actor-name">Redirect</span>
          <span class="status-badge status-3xx">${DOMSecurity.sanitize(redirect.statusCode || '302')}</span>
        </div>
        <div class="message-details">
          <div class="detail-line">
            <span class="detail-key">From:</span>
            <span class="detail-value">${DOMSecurity.sanitize(this.truncate(redirect.from, 80))}</span>
          </div>
          <div class="detail-line">
            <span class="detail-key">To:</span>
            <span class="detail-value">${DOMSecurity.sanitize(this.truncate(redirect.to, 80))}</span>
          </div>
        </div>
      </div>
    `;

    this.feed.appendChild(message);
    this.feed.scrollTop = this.feed.scrollHeight;
  }

  /**
   * Add console log to feed
   */
  addConsoleLog(log) {
    const message = document.createElement('div');
    message.className = 'feed-message';

    const time = this.formatTime(log.timestamp || Date.now());
    const levelClass = log.level === 'error' ? 'error' : 'request';

    message.innerHTML = `
      <div class="message-time">${DOMSecurity.sanitize(time)}</div>
      <div class="message-card ${levelClass}">
        <div class="message-header">
          <span class="actor-icon">📝</span>
          <span class="actor-name">Console</span>
          <span class="method ${DOMSecurity.sanitize(log.level)}">${DOMSecurity.sanitize(log.level.toUpperCase())}</span>
        </div>
        <div class="message-url">${DOMSecurity.sanitize(log.text)}</div>
      </div>
    `;

    this.feed.appendChild(message);
    this.feed.scrollTop = this.feed.scrollHeight;
  }

  /**
   * Load full session data (for initial render)
   */
  loadSession(session) {
    if (!session || !session.requests) return;

    // Clear feed
    this.feed.innerHTML = '';
    this.requestCount = 0;

    // Add all requests
    session.requests.forEach(req => {
      this.addRequest(req);
      if (req.statusCode || req.response) {
        this.updateResponse({
          requestId: req.id || req.requestId,
          statusCode: req.statusCode || req.response?.status,
          statusText: req.response?.statusText,
          responseHeaders: req.responseHeaders || req.response?.headers
        });
      }
    });

    // Add console logs
    if (session.consoleLogs) {
      session.consoleLogs.forEach(log => this.addConsoleLog(log));
    }
  }

  /**
   * Identify actor from URL
   */
  identifyActor(url) {
    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname;

      if (hostname.includes('authentik')) {
        return { icon: '🔐', name: 'Authentik' };
      }
      if (hostname.includes('okta')) {
        return { icon: '🔐', name: 'Okta' };
      }
      if (hostname.includes('microsoft') || hostname.includes('azure')) {
        return { icon: '🔐', name: 'Microsoft' };
      }
      if (hostname.includes('google')) {
        return { icon: '🔐', name: 'Google' };
      }
      if (urlObj.pathname.includes('/api')) {
        return { icon: '⚡', name: hostname };
      }
      return { icon: '🌐', name: hostname };
    } catch {
      return { icon: '❓', name: 'Unknown' };
    }
  }

  /**
   * Get status code CSS class
   */
  getStatusClass(status) {
    if (status >= 200 && status < 300) return 'status-2xx';
    if (status >= 300 && status < 400) return 'status-3xx';
    if (status >= 400 && status < 500) return 'status-4xx';
    if (status >= 500) return 'status-5xx';
    return 'status-2xx';
  }

  /**
   * Format timestamp
   */
  formatTime(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      fractionalSecondDigits: 3
    });
  }

  /**
   * Truncate string
   */
  truncate(str, length) {
    if (!str || str.length <= length) return str;
    return str.substring(0, length) + '...';
  }

  /**
   * Update duration counter
   */
  updateDuration() {
    const seconds = Math.floor((Date.now() - this.startTime) / 1000);
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    const formatted = minutes > 0
      ? `${minutes}m ${secs}s`
      : `${secs}s`;
    document.getElementById('duration').textContent = formatted;
  }

  /**
   * Clear feed
   */
  clearFeed() {
    if (!confirm('Clear all captured requests?')) return;

    this.feed.innerHTML = `
      <div class="feed-empty">
        <div class="feed-empty-icon">📡</div>
        <div>Waiting for authentication traffic...</div>
        <div style="font-size: 10px; margin-top: 8px;">Perform a login to see requests appear here</div>
      </div>
    `;
    this.requestCount = 0;
    document.getElementById('requestCount').textContent = '0';

    // Notify background to clear session
    if (this.port) {
      this.port.postMessage({
        type: 'clearSession',
        domain: this.domain
      });
    }
  }

  /**
   * Export session
   */
  exportSession() {
    if (this.port) {
      this.port.postMessage({
        type: 'exportSession',
        domain: this.domain
      });
    }
  }

  /**
   * Show error
   */
  showError(message) {
    this.feed.innerHTML = `
      <div class="feed-empty">
        <div class="feed-empty-icon">❌</div>
        <div>${DOMSecurity.sanitize(message)}</div>
      </div>
    `;
  }
}

// Initialize when DOM ready
document.addEventListener('DOMContentLoaded', () => {
  const debugWindow = new DebugWindow();
  debugWindow.initialize();
});
