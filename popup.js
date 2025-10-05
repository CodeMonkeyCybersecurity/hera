// P1-NINTH-4 FIX: Validate extension context to prevent clickjacking
(function() {
  'use strict';

  // Detect if popup.html was opened in invalid context (not via extension icon)
  if (window.opener || window.location !== window.parent.location) {
    // Opened by another window or iframed (shouldn't be possible but check anyway)
    document.body.innerHTML = `
      <div style="padding: 20px; text-align: center; font-family: system-ui, -apple-system, sans-serif;">
        <h1>⚠️ Invalid Context</h1>
        <p>This page must be opened via the extension icon.</p>
        <p>Please close this window and click the Hera icon in your browser toolbar.</p>
      </div>
    `;
    throw new Error('Popup opened in invalid context');
  }
})();

// Security utilities for safe DOM manipulation and JWT processing
const DOMSecurity = {
  // Safe HTML sanitization
  sanitizeHTML: (str) => {
    if (typeof str !== 'string') return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  },

  // Safe text content setting
  setTextContent: (element, text) => {
    if (!element) return;
    element.textContent = typeof text === 'string' ? text : String(text);
  },

  // Safe HTML creation with sanitization
  createSafeElement: (tag, content, attributes = {}) => {
    const element = document.createElement(tag);
    if (content) {
      element.textContent = content;
    }
    Object.entries(attributes).forEach(([key, value]) => {
      if (key === 'className') {
        element.className = value; // Class names don't need HTML escaping
      } else if (key === 'title') {
        element.setAttribute(key, value); // Title attributes with URLs don't need HTML escaping
      } else {
        element.setAttribute(key, DOMSecurity.sanitizeHTML(value));
      }
    });
    return element;
  },

  // Clear and append children safely
  replaceChildren: (parent, ...children) => {
    if (!parent) return;
    parent.innerHTML = '';
    children.forEach(child => {
      if (child instanceof Node) {
        parent.appendChild(child);
      }
    });
  }
};

// Secure JWT utilities
const JWTSecurity = {
  // Validate JWT structure before processing
  isValidJWTStructure: (token) => {
    if (typeof token !== 'string') return false;
    const parts = token.split('.');
    return parts.length === 3 && parts.every(part => part.length > 0);
  },

  // Safe Base64 URL decoding
  safeBase64UrlDecode: (str) => {
    try {
      // Validate input
      if (typeof str !== 'string' || str.length === 0) {
        throw new Error('Invalid input for Base64 URL decoding');
      }

      // Convert Base64 URL to Base64
      let base64 = str.replace(/-/g, '+').replace(/_/g, '/');

      // Add padding if needed
      const padding = base64.length % 4;
      if (padding === 2) {
        base64 += '==';
      } else if (padding === 3) {
        base64 += '=';
      }

      // Validate Base64 format
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(base64)) {
        throw new Error('Invalid Base64 format');
      }

      const decoded = atob(base64);

      // Validate JSON structure
      const parsed = JSON.parse(decoded);
      return parsed;
    } catch (error) {
      console.error('JWT decode error:', error);
      return null;
    }
  },

  // Safely parse JWT with validation
  parseJWT: (token) => {
    if (!JWTSecurity.isValidJWTStructure(token)) {
      return { error: 'Invalid JWT structure' };
    }

    const [headerB64, payloadB64, signature] = token.split('.');

    const header = JWTSecurity.safeBase64UrlDecode(headerB64);
    const payload = JWTSecurity.safeBase64UrlDecode(payloadB64);

    if (!header || !payload) {
      return { error: 'Failed to decode JWT parts' };
    }

    return {
      header,
      payload,
      signature,
      raw: token
    };
  },

  // Validate JWT claims for security issues
  validateJWTSecurity: (parsedJWT) => {
    const issues = [];

    if (parsedJWT.error) {
      return [{ severity: 'HIGH', type: 'JWT_PARSE_ERROR', message: parsedJWT.error }];
    }

    // Check for dangerous algorithms
    if (parsedJWT.header.alg === 'none') {
      issues.push({
        severity: 'CRITICAL',
        type: 'JWT_ALG_NONE',
        message: 'JWT uses "none" algorithm - signature verification bypassed'
      });
    }

    // Check for weak algorithms
    const weakAlgs = ['HS256', 'RS256'];
    if (weakAlgs.includes(parsedJWT.header.alg)) {
      issues.push({
        severity: 'MEDIUM',
        type: 'JWT_WEAK_ALG',
        message: `JWT uses potentially weak algorithm: ${parsedJWT.header.alg}`
      });
    }

    // Check expiration
    if (!parsedJWT.payload.exp) {
      issues.push({
        severity: 'HIGH',
        type: 'JWT_NO_EXPIRATION',
        message: 'JWT does not have expiration claim (exp)'
      });
    } else {
      const expTime = parsedJWT.payload.exp * 1000;
      const now = Date.now();
      if (expTime < now) {
        issues.push({
          severity: 'MEDIUM',
          type: 'JWT_EXPIRED',
          message: 'JWT is expired'
        });
      }
    }

    // Check for missing critical claims
    if (!parsedJWT.payload.iss) {
      issues.push({
        severity: 'MEDIUM',
        type: 'JWT_NO_ISSUER',
        message: 'JWT missing issuer claim (iss)'
      });
    }

    if (!parsedJWT.payload.aud) {
      issues.push({
        severity: 'MEDIUM',
        type: 'JWT_NO_AUDIENCE',
        message: 'JWT missing audience claim (aud)'
      });
    }

    return issues;
  }
};

// Time formatting utilities
const TimeUtils = {
  // Format time with relative display and full timestamp on hover
  formatTimeWithRelative: (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMinutes = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    let relativeTime;
    if (diffMinutes < 1) {
      relativeTime = 'Just now';
    } else if (diffMinutes < 60) {
      relativeTime = `${diffMinutes}m ago`;
    } else if (diffHours < 24) {
      relativeTime = `${diffHours}h ago`;
    } else if (diffDays < 7) {
      relativeTime = `${diffDays}d ago`;
    } else {
      relativeTime = date.toLocaleDateString();
    }

    return {
      relative: relativeTime,
      full: date.toLocaleString(),
      iso: date.toISOString()
    };
  },

  // Create a time element with relative display and full timestamp on hover
  createTimeElement: (timestamp, className = 'time') => {
    const timeInfo = TimeUtils.formatTimeWithRelative(timestamp);
    const element = DOMSecurity.createSafeElement('span', timeInfo.relative, {
      className: className,
      title: timeInfo.full
    });
    return element;
  },

  // Format duration in human readable format
  formatDuration: (durationMs) => {
    if (!durationMs || durationMs < 0) return 'Unknown';

    if (durationMs < 1000) {
      return `${Math.round(durationMs)}ms`;
    } else if (durationMs < 60000) {
      return `${(durationMs / 1000).toFixed(1)}s`;
    } else {
      const minutes = Math.floor(durationMs / 60000);
      const seconds = ((durationMs % 60000) / 1000).toFixed(1);
      return `${minutes}m ${seconds}s`;
    }
  }
};

document.addEventListener('DOMContentLoaded', () => {
  const requestsList = document.getElementById('requestsList');
  const clearBtn = document.getElementById('clearBtn');
  const exportBtn = document.getElementById('exportBtn');
  const exportAllBtn = document.getElementById('exportAllBtn');
  const viewStorageBtn = document.getElementById('viewStorageBtn');
  const refreshBtn = document.getElementById('refreshBtn');
  const collapseAllBtn = document.getElementById('collapseAllBtn');
  const settingsBtn = document.getElementById('settingsBtn');
  const settingsPanel = document.getElementById('settingsPanel');
  const closeSettingsBtn = document.getElementById('closeSettings');
  const enableResponseCaptureCheckbox = document.getElementById('enableResponseCapture');
  const requestDetails = document.getElementById('requestDetails');
  
  // Debug: Check if buttons exist
  console.log('Button elements found:', {
    clearBtn: !!clearBtn,
    exportBtn: !!exportBtn,
    exportAllBtn: !!exportAllBtn,
    viewStorageBtn: !!viewStorageBtn,
    requestDetails: !!requestDetails
  });
  const closeDetailsBtn = document.getElementById('closeDetails');
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  const findingsBtn = document.getElementById('findingsBtn');
  const requestsBtn = document.getElementById('requestsBtn');
  const findingsList = document.getElementById('findingsList');
  const extensionsBtn = document.getElementById('extensionsBtn');
  const extensionsList = document.getElementById('extensionsList');
  const portsBtn = document.getElementById('portsBtn');
  const portsAnalysis = document.getElementById('portsAnalysis');
  const repeaterPanel = document.getElementById('repeaterPanel');
  const sendToRepeaterBtn = document.getElementById('sendToRepeaterBtn');
  const closeRepeaterBtn = document.getElementById('closeRepeaterBtn');
  const sendRepeaterBtn = document.getElementById('sendRepeaterBtn');
  const repeaterRequestEl = document.getElementById('repeaterRequest');
  const repeaterResponseEl = document.getElementById('repeaterResponse');
  
  let requests = [];
  let selectedRequest = null;
  
  // Rate limiting for loadRequests
  let lastLoadTime = 0;
  const LOAD_COOLDOWN = 1000; // 1 second cooldown
  
  // Load requests when popup opens
  loadRequests();
  
  // Debug: Check if detail panel elements exist
  console.log('Detail panel elements check:');
  console.log('detailUrl exists:', !!document.getElementById('detailUrl'));
  console.log('detailMethod exists:', !!document.getElementById('detailMethod'));
  console.log('chatMessages exists:', !!document.getElementById('chatMessages'));
  console.log('dnsHostname exists:', !!document.getElementById('dnsHostname'));
  
  // Auto-refresh when popup gains focus (user opens it)
  window.addEventListener('focus', () => {
    console.log('Popup gained focus - auto-refreshing data');
    loadRequests();
  });
  
  // Also refresh when popup becomes visible
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      console.log('Popup became visible - auto-refreshing data');
      loadRequests();
    }
  });
  
  // Initialize collapse state variable
  let allCollapsed = false;

  // Set up refresh button event listener
  if (refreshBtn) {
    refreshBtn.addEventListener('click', () => {
      console.log('Manual refresh triggered');
      loadRequests();
    });
  }

  // Set up collapse all button event listener
  if (collapseAllBtn) {
    collapseAllBtn.addEventListener('click', () => {
    const serviceHeaders = document.querySelectorAll('.service-header.collapsible');
    const sessionContainers = document.querySelectorAll('.session-container');
    
    if (allCollapsed) {
      // Expand all
      sessionContainers.forEach(container => {
        container.style.display = 'block';
      });
      serviceHeaders.forEach(header => {
        const icon = header.querySelector('.collapse-icon');
        if (icon) icon.textContent = '▼';
        header.classList.remove('collapsed');
      });
      collapseAllBtn.textContent = 'Collapse All';
      allCollapsed = false;
      console.log('📂 Expanded all sessions');
    } else {
      // Collapse all
      sessionContainers.forEach(container => {
        container.style.display = 'none';
      });
      serviceHeaders.forEach(header => {
        const icon = header.querySelector('.collapse-icon');
        if (icon) icon.textContent = '▶';
        header.classList.add('collapsed');
      });
      collapseAllBtn.textContent = 'Expand All';
      allCollapsed = true;
      console.log('📁 Collapsed all sessions');
    }
    });
  }

  // Settings panel functionality
  if (settingsBtn) {
    settingsBtn.addEventListener('click', () => {
      settingsPanel.style.display = 'block';
      loadSettings();
    });
  }

  if (closeSettingsBtn) {
    closeSettingsBtn.addEventListener('click', () => {
      settingsPanel.style.display = 'none';
    });
  }

  if (enableResponseCaptureCheckbox) {
    enableResponseCaptureCheckbox.addEventListener('change', (e) => {
      const enabled = e.target.checked;
      chrome.storage.local.set({ enableResponseCapture: enabled }, () => {
        console.log('Response capture setting:', enabled);
        // Notify background script of setting change
        chrome.runtime.sendMessage({
          action: 'updateResponseCaptureSetting',
          enabled: enabled
        });
      });
    });
  }

  // P0-NEW-4: Privacy consent checkbox handler
  const enablePrivacyConsentCheckbox = document.getElementById('enablePrivacyConsent');
  const privacyConsentStatus = document.getElementById('privacyConsentStatus');

  if (enablePrivacyConsentCheckbox) {
    enablePrivacyConsentCheckbox.addEventListener('change', async (e) => {
      const enabled = e.target.checked;

      if (enabled) {
        // Grant privacy consent
        try {
          const consent = {
            granted: true,
            timestamp: new Date().toISOString(),
            version: 1
          };
          await chrome.storage.local.set({ heraPrivacyConsent: consent });
          console.log('Privacy consent granted');
          updatePrivacyConsentStatus();
        } catch (error) {
          console.error('Failed to grant privacy consent:', error);
          e.target.checked = false;
        }
      } else {
        // Withdraw privacy consent
        try {
          await chrome.storage.local.remove(['heraPrivacyConsent']);
          console.log('Privacy consent withdrawn');
          updatePrivacyConsentStatus();
        } catch (error) {
          console.error('Failed to withdraw privacy consent:', error);
        }
      }
    });
  }

  // P0-NEW-4: Update privacy consent status display
  async function updatePrivacyConsentStatus() {
    try {
      const result = await chrome.storage.local.get(['heraPrivacyConsent']);
      const consent = result.heraPrivacyConsent;

      if (consent && consent.granted) {
        const consentDate = new Date(consent.timestamp);
        const expiryDate = new Date(consentDate.getTime() + (365 * 24 * 60 * 60 * 1000)); // 1 year

        if (privacyConsentStatus) {
          privacyConsentStatus.textContent = `Consent granted on ${consentDate.toLocaleDateString()}. Expires ${expiryDate.toLocaleDateString()}.`;
          privacyConsentStatus.style.color = '#28a745';
        }
        if (enablePrivacyConsentCheckbox) {
          enablePrivacyConsentCheckbox.checked = true;
        }
      } else {
        if (privacyConsentStatus) {
          privacyConsentStatus.textContent = 'No consent granted. DNS and IP geolocation features are disabled.';
          privacyConsentStatus.style.color = '#dc3545';
        }
        if (enablePrivacyConsentCheckbox) {
          enablePrivacyConsentCheckbox.checked = false;
        }
      }
    } catch (error) {
      console.error('Failed to update privacy consent status:', error);
    }
  }

  // Load current settings
  function loadSettings() {
    chrome.storage.local.get(['enableResponseCapture'], (result) => {
      const enabled = result.enableResponseCapture !== false; // Default to true
      if (enableResponseCaptureCheckbox) {
        enableResponseCaptureCheckbox.checked = enabled;
      }
    });

    // P0-NEW-4: Load privacy consent status
    updatePrivacyConsentStatus();
  }

  // Set up event listeners with error handling
  clearBtn.addEventListener('click', (e) => {
    console.log('Clear button clicked');
    clearRequests();
  });
  
  exportBtn.addEventListener('click', (e) => {
    console.log('Export button clicked');
    exportRequests();
  });
  
  if (exportAllBtn) {
    exportAllBtn.addEventListener('click', (e) => {
      console.log('Export All button clicked');
      e.preventDefault();
      exportAllSessions();
    });
  } else {
    console.error('exportAllBtn not found!');
  }
  
  if (viewStorageBtn) {
    viewStorageBtn.addEventListener('click', (e) => {
      console.log('View Storage button clicked');
      e.preventDefault();
      viewStorageStats();
    });
  } else {
    console.error('viewStorageBtn not found!');
  }
  
  closeDetailsBtn.addEventListener('click', (e) => {
    console.log('Close details button clicked');
    hideDetails();
  });
  
  // Tab switching
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const tabName = button.getAttribute('data-tab');
      switchTab(tabName);
    });
  });
  
  // Load requests from background
  function loadRequests() {
    const now = Date.now();
    if (now - lastLoadTime < LOAD_COOLDOWN) {
      console.log('Load requests rate limited');
      return;
    }
    lastLoadTime = now;
    
    console.log('Loading requests...'); // Debug log
    
    // Add loading indicator
    if (requestsList) {
      const loadingDiv = DOMSecurity.createSafeElement('div', 'Loading sessions...', { className: 'loading' });
      DOMSecurity.replaceChildren(requestsList, loadingDiv);
    }
    
    chrome.runtime.sendMessage({ action: 'getRequests' }, response => {
      console.log('Received response:', response); // Debug log
      if (chrome.runtime.lastError) {
        console.error('Runtime error:', chrome.runtime.lastError);
        if (requestsList) {
          const errorDiv = DOMSecurity.createSafeElement('div', '', { className: 'error-state' });
          const errorMsg = DOMSecurity.createSafeElement('p', `Error loading data: ${chrome.runtime.lastError.message}`);
          const retryBtn = DOMSecurity.createSafeElement('button', 'Retry');
          retryBtn.onclick = loadRequests;
          errorDiv.appendChild(errorMsg);
          errorDiv.appendChild(retryBtn);
          DOMSecurity.replaceChildren(requestsList, errorDiv);
        }
        return;
      }
      
      if (!response) {
        console.warn('No response received from background script');
        if (requestsList) {
          const errorDiv = DOMSecurity.createSafeElement('div', '', { className: 'error-state' });
          const errorMsg = DOMSecurity.createSafeElement('p', 'No response from background script');
          const retryBtn = DOMSecurity.createSafeElement('button', 'Retry');
          retryBtn.onclick = loadRequests;
          errorDiv.appendChild(errorMsg);
          errorDiv.appendChild(retryBtn);
          DOMSecurity.replaceChildren(requestsList, errorDiv);
        }
        return;
      }
      
      requests = Array.isArray(response) ? response : []; // Ensure it's an array
      console.log('Parsed requests:', requests.length, 'items'); // Debug log
      
      // Sort by timestamp (newest first) to ensure latest data appears first
      requests.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
      
      renderRequests();
      renderFindings();
    });
  }
  
  // Render the list of requests organized by sessions
  function renderRequests() {
    if (requests.length === 0) {
      const emptyDiv = DOMSecurity.createSafeElement('div', '', { className: 'empty-state' });
      const msg1 = DOMSecurity.createSafeElement('p', 'No authentication requests captured yet.');
      const msg2 = DOMSecurity.createSafeElement('p', 'Navigate to a website that uses OAuth, OIDC, SAML, or SCIM.');
      emptyDiv.appendChild(msg1);
      emptyDiv.appendChild(msg2);
      DOMSecurity.replaceChildren(requestsList, emptyDiv);
      return;
    }

    // Group requests by service/session
    const sessionGroups = {};
    requests.forEach(request => {
      const service = request.service || request.sessionInfo?.service || 'Unknown';
      const sessionId = request.sessionId || request.sessionInfo?.sessionId || 'unknown';
      
      if (!sessionGroups[service]) {
        sessionGroups[service] = {};
      }
      
      if (!sessionGroups[service][sessionId]) {
        sessionGroups[service][sessionId] = {
          requests: [],
          domain: request.sessionInfo?.domain || new URL(request.url).hostname,
          startTime: request.timestamp,
          eventCount: 0
        };
      }
      
      sessionGroups[service][sessionId].requests.push(request);
      sessionGroups[service][sessionId].eventCount++;
    });
    
    console.log('Session groups:', sessionGroups);
    requestsList.innerHTML = '';

    // Check for security issues
    checkSecurityIssues(requests);

    // Render each service group
    Object.entries(sessionGroups).forEach(([service, sessions]) => {
      // Service header with collapse functionality
      const serviceHeader = document.createElement('div');
      serviceHeader.className = 'service-header collapsible';

      const headerContent = DOMSecurity.createSafeElement('div', '', { className: 'service-header-content' });
      const collapseIcon = DOMSecurity.createSafeElement('span', '▼', { className: 'collapse-icon' });
      const serviceTitle = DOMSecurity.createSafeElement('h3', service);
      const sessionCount = DOMSecurity.createSafeElement('span', `${Object.keys(sessions).length} session(s)`, { className: 'session-count' });

      headerContent.appendChild(collapseIcon);
      headerContent.appendChild(serviceTitle);
      headerContent.appendChild(sessionCount);
      serviceHeader.appendChild(headerContent);
      
      // Create container for sessions
      const sessionContainer = document.createElement('div');
      sessionContainer.className = 'session-container';
      sessionContainer.style.display = 'block'; // Start expanded
      
      // Add click handler for collapse/expand
      serviceHeader.addEventListener('click', () => {
        const isCollapsed = sessionContainer.style.display === 'none';
        const icon = serviceHeader.querySelector('.collapse-icon');
        
        if (isCollapsed) {
          sessionContainer.style.display = 'block';
          icon.textContent = '▼';
          serviceHeader.classList.remove('collapsed');
          console.log(`📂 Expanded ${service} session`);
        } else {
          sessionContainer.style.display = 'none';
          icon.textContent = '▶';
          serviceHeader.classList.add('collapsed');
          console.log(`📁 Collapsed ${service} session`);
        }
      });
      
      requestsList.appendChild(serviceHeader);
      
      // Render each session within the service
      Object.entries(sessions).forEach(([sessionId, sessionData]) => {
        const sessionHeader = document.createElement('div');
        sessionHeader.className = 'session-header';
        
        // Get all unique domains for this session
        const domains = [...new Set(sessionData.requests.map(r => {
          try {
            return new URL(r.url).hostname;
          } catch {
            return r.sessionInfo?.domain || 'unknown';
          }
        }))];
        
        const domainDisplay = domains.length === 1
          ? DOMSecurity.sanitizeHTML(domains[0])
          : `${domains.length} domains: ${domains.slice(0, 2).map(d => DOMSecurity.sanitizeHTML(d)).join(', ')}${domains.length > 2 ? '...' : ''}`;

        const sessionInfo = DOMSecurity.createSafeElement('div', '', { className: 'session-info' });
        const sessionMain = DOMSecurity.createSafeElement('div', '', { className: 'session-main' });
        const sessionDomain = DOMSecurity.createSafeElement('span', domainDisplay, {
          className: 'session-domain',
          title: domains.map(d => DOMSecurity.sanitizeHTML(d)).join(', ')
        });
        const sessionEvents = DOMSecurity.createSafeElement('span', `${sessionData.eventCount} events`, { className: 'session-events' });
        const sessionTimeInfo = TimeUtils.formatTimeWithRelative(sessionData.startTime);
        const sessionTime = DOMSecurity.createSafeElement('span', sessionTimeInfo.relative, {
          className: 'session-time',
          title: sessionTimeInfo.full
        });

        sessionMain.appendChild(sessionDomain);
        sessionMain.appendChild(sessionEvents);
        sessionInfo.appendChild(sessionMain);
        sessionInfo.appendChild(sessionTime);
        sessionHeader.appendChild(sessionInfo);
        sessionContainer.appendChild(sessionHeader);
        
        // Render requests in this session (newest first)
        sessionData.requests.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).forEach(request => {
          const requestEl = document.createElement('div');
          requestEl.className = 'request-item session-request';
          requestEl.dataset.id = request.id;

          const statusCode = request.statusCode || 'Pending';
          const statusClass = statusCode >= 400 ? 'error' : statusCode >= 200 && statusCode < 300 ? 'success' : '';
          const riskCategory = request.metadata?.authAnalysis?.riskCategory || 'secure';
          requestEl.classList.add(riskCategory);

          // Create elements safely
          const securityDot = DOMSecurity.createSafeElement('span', '', { className: 'security-dot' });
          const methodDiv = DOMSecurity.createSafeElement('div', DOMSecurity.sanitizeHTML(request.method || 'GET'), {
            className: `request-method ${statusClass}`
          });
          const urlDiv = DOMSecurity.createSafeElement('div', request.url, {
            className: 'request-url',
            title: request.url
          });
          const typeDiv = DOMSecurity.createSafeElement('div', DOMSecurity.sanitizeHTML(request.authType || 'Unknown'), {
            className: 'request-type'
          });
          const statusDiv = DOMSecurity.createSafeElement('div', DOMSecurity.sanitizeHTML(String(statusCode)), {
            className: 'request-status'
          });

          requestEl.appendChild(securityDot);
          requestEl.appendChild(methodDiv);
          requestEl.appendChild(urlDiv);
          requestEl.appendChild(typeDiv);
          requestEl.appendChild(statusDiv);

          requestEl.addEventListener('click', () => {
            console.log('🖱️ Request clicked:', request.id, request.url);
            showRequestDetails(request.id);
          });
          sessionContainer.appendChild(requestEl);
        });
      });
      
      // Add the session container to the main list
      requestsList.appendChild(sessionContainer);
    });
  }

  // Render the aggregated list of security findings
  // Identify service from domain
  function identifyService(domain) {
    const servicePatterns = {
      'Microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'azure.com', 'microsoftonline.com'],
      'Google': ['google.com', 'gmail.com', 'googleapis.com', 'googleusercontent.com'],
      'Amazon/AWS': ['amazon.com', 'amazonaws.com', 'aws.com'],
      'Facebook/Meta': ['facebook.com', 'fb.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com'],
      'Apple': ['apple.com', 'icloud.com'],
      'GitHub': ['github.com', 'githubusercontent.com'],
      'LinkedIn': ['linkedin.com', 'licdn.com'],
      'Twitter/X': ['twitter.com', 'x.com', 'twimg.com'],
      'Salesforce': ['salesforce.com', 'force.com'],
      'Oracle': ['oracle.com', 'oraclecloud.com'],
      'IBM': ['ibm.com', 'ibmcloud.com'],
      'Adobe': ['adobe.com', 'adobelogin.com'],
      'PayPal': ['paypal.com', 'paypalobjects.com'],
      'Netflix': ['netflix.com', 'nflxvideo.net'],
      'Spotify': ['spotify.com', 'spotifycdn.com'],
      'Dropbox': ['dropbox.com', 'dropboxusercontent.com'],
      'Zoom': ['zoom.us', 'zoom.com'],
      'Slack': ['slack.com', 'slack-edge.com'],
      'Atlassian': ['atlassian.com', 'jira.com', 'confluence.com', 'bitbucket.org']
    };

    for (const [service, patterns] of Object.entries(servicePatterns)) {
      if (patterns.some(pattern => domain.includes(pattern))) {
        return service;
      }
    }

    // Check if it's a government site
    if (domain.endsWith('.gov')) return 'Government';
    if (domain.endsWith('.edu')) return 'Educational';
    if (domain.endsWith('.mil')) return 'Military';

    // Check if it's a bank or financial institution
    if (domain.includes('bank') || domain.includes('credit')) return 'Banking';

    return null;
  }

  // Get service priority (higher = more important)
  function getServicePriority(service, domain) {
    const priorityMap = {
      'Microsoft': 100,
      'Google': 95,
      'Amazon/AWS': 90,
      'Banking': 85,
      'Government': 85,
      'Military': 90,
      'Apple': 80,
      'GitHub': 75,
      'Salesforce': 75,
      'Oracle': 70,
      'IBM': 70,
      'PayPal': 80,
      'Facebook/Meta': 65,
      'LinkedIn': 60,
      'Twitter/X': 55,
      'Educational': 50
    };

    if (service && priorityMap[service]) {
      return priorityMap[service];
    }

    // Check domain reputation
    if (domain.includes('localhost') || domain.includes('127.0.0.1')) return 1;
    if (domain.endsWith('.local')) return 5;
    if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) return 10; // IP address

    return 20; // Default for unknown domains
  }

  // Get the most important affected domain
  function getTopAffectedDomain(affectedDomains) {
    if (!affectedDomains || affectedDomains.size === 0) return null;

    let topDomain = null;
    let maxPriority = 0;

    for (const [domain, info] of affectedDomains) {
      if (info.priority > maxPriority) {
        maxPriority = info.priority;
        topDomain = {
          domain: domain,
          service: info.service,
          count: info.count,
          priority: info.priority
        };
      }
    }

    return topDomain;
  }

  // Get service icon/emoji
  function getServiceIcon(service) {
    const serviceIcons = {
      'Microsoft': '🪟',
      'Google': '🔍',
      'Amazon/AWS': '📦',
      'Banking': '🏦',
      'Government': '🏛️',
      'Military': '🪖',
      'Apple': '🍎',
      'GitHub': '🐙',
      'Salesforce': '☁️',
      'Oracle': '🔮',
      'IBM': '💼',
      'PayPal': '💰',
      'Facebook/Meta': '📘',
      'LinkedIn': '💼',
      'Twitter/X': '🐦',
      'Educational': '🎓',
      'Netflix': '📺',
      'Spotify': '🎵',
      'Dropbox': '📂',
      'Zoom': '📹',
      'Slack': '💬',
      'Atlassian': '🔧',
      'Adobe': '🎨'
    };

    return serviceIcons[service] || '🌐';
  }

  function renderFindings() {
    if (requests.length === 0) {
      const emptyDiv = DOMSecurity.createSafeElement('div', '', { className: 'empty-state' });
      const emptyMsg = DOMSecurity.createSafeElement('p', 'No security findings yet.');
      emptyDiv.appendChild(emptyMsg);
      DOMSecurity.replaceChildren(findingsList, emptyDiv);
      return;
    }

    const allIssues = {};
    requests.forEach(request => {
      const issues = request.metadata?.authAnalysis?.issues || [];
      issues.forEach(issue => {
        const key = `${issue.type}|${issue.severity}`;
        if (!allIssues[key]) {
          allIssues[key] = {
            ...issue,
            count: 0,
            requests: [],
            affectedDomains: new Map()
          };
        }
        allIssues[key].count++;
        allIssues[key].requests.push(request.id);

        // Track affected domains
        try {
          const url = new URL(request.url);
          const domain = url.hostname;
          const service = request.service || identifyService(domain);

          if (!allIssues[key].affectedDomains.has(domain)) {
            allIssues[key].affectedDomains.set(domain, {
              count: 0,
              service: service,
              priority: getServicePriority(service, domain)
            });
          }
          allIssues[key].affectedDomains.get(domain).count++;
        } catch (e) {
          // Invalid URL
        }
      });
    });

    const sortedIssues = Object.values(allIssues).sort((a, b) => {
      const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
      return (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
    });

    if (sortedIssues.length === 0) {
      const emptyDiv = DOMSecurity.createSafeElement('div', '', { className: 'empty-state' });
      const emptyMsg = DOMSecurity.createSafeElement('p', 'No security issues detected.');
      emptyDiv.appendChild(emptyMsg);
      DOMSecurity.replaceChildren(findingsList, emptyDiv);
      return;
    }

    findingsList.innerHTML = '';
    sortedIssues.forEach(issue => {
      const findingEl = document.createElement('div');
      findingEl.className = `finding-item ${issue.severity.toLowerCase()}`;

      const findingHeader = DOMSecurity.createSafeElement('div', '', { className: 'finding-header' });
      const findingType = DOMSecurity.createSafeElement('span', issue.type, { className: 'finding-type' });
      const findingCount = DOMSecurity.createSafeElement('span', `${issue.count} found`, { className: 'finding-count' });

      // Add action buttons
      const findingActions = DOMSecurity.createSafeElement('div', '', { className: 'finding-actions' });
      const copyBtn = DOMSecurity.createSafeElement('button', '📋', {
        className: 'action-btn copy-btn',
        title: 'Copy finding details'
      });
      const exportBtn = DOMSecurity.createSafeElement('button', '📥', {
        className: 'action-btn export-btn',
        title: 'Export for investigation'
      });

      copyBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        copyFindingDetails(issue);
      });

      exportBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        exportFindingForInvestigation(issue);
      });

      findingActions.appendChild(copyBtn);
      findingActions.appendChild(exportBtn);

      // Get the most important affected domain
      const topDomain = getTopAffectedDomain(issue.affectedDomains);

      // Create affected service line
      const affectedService = DOMSecurity.createSafeElement('div', '', { className: 'affected-service' });
      if (topDomain) {
        const serviceIcon = getServiceIcon(topDomain.service);
        const serviceName = topDomain.service || 'Unknown Service';
        const domainText = topDomain.domain;

        const serviceDisplay = `${serviceIcon} ${serviceName}${serviceName !== domainText ? ` (${domainText})` : ''}`;
        const additionalCount = issue.affectedDomains.size - 1;

        affectedService.textContent = serviceDisplay;
        if (additionalCount > 0) {
          const additionalSpan = DOMSecurity.createSafeElement('span', ` +${additionalCount} more`, {
            className: 'additional-domains'
          });
          affectedService.appendChild(additionalSpan);
        }

        // Add priority indicator for high-value targets
        if (topDomain.priority >= 80) {
          const priorityBadge = DOMSecurity.createSafeElement('span', '⚠️', {
            className: 'priority-badge high-priority',
            title: 'High-value target'
          });
          affectedService.appendChild(priorityBadge);
        }
      } else {
        affectedService.textContent = '🌐 Multiple domains affected';
      }

      const findingDetails = DOMSecurity.createSafeElement('div', issue.message, { className: 'finding-details' });

      findingHeader.appendChild(findingType);
      findingHeader.appendChild(findingCount);
      findingHeader.appendChild(findingActions);
      findingEl.appendChild(findingHeader);
      findingEl.appendChild(affectedService);
      findingEl.appendChild(findingDetails);

      // Make finding clickable to show related requests
      findingEl.style.cursor = 'pointer';
      findingEl.addEventListener('click', () => showRequestsForFinding(issue));
      findingsList.appendChild(findingEl);
    });
  }

  // Copy finding details to clipboard
  function copyFindingDetails(issue) {
    // Get all related requests
    const relatedRequests = requests.filter(r => issue.requests.includes(r.id));

    const findingReport = `
SECURITY FINDING REPORT
=======================
Type: ${issue.type}
Severity: ${issue.severity}
Message: ${issue.message}
Count: ${issue.count} occurrence(s)

${issue.exploitation ? `Exploitation: ${issue.exploitation}\n` : ''}
${issue.recommendation ? `Recommendation: ${issue.recommendation}\n` : ''}

AFFECTED URLS:
--------------
${relatedRequests.slice(0, 10).map(r => `- ${r.url}`).join('\n')}
${relatedRequests.length > 10 ? `... and ${relatedRequests.length - 10} more URLs` : ''}

INVESTIGATION NOTES:
-------------------
[ ] Verified as true positive
[ ] Verified as false positive
[ ] Requires manual testing
[ ] Security impact assessed

Evidence:
-

Next Steps:
-

Generated: ${new Date().toISOString()}
By: Hera Security Extension
    `.trim();

    navigator.clipboard.writeText(findingReport).then(() => {
      // Show success feedback
      const btn = event.target;
      const originalText = btn.textContent;
      btn.textContent = '✅';
      setTimeout(() => {
        btn.textContent = originalText;
      }, 1000);
    }).catch(err => {
      console.error('Failed to copy:', err);
      alert('Failed to copy to clipboard');
    });
  }

  // Export finding for detailed investigation
  function exportFindingForInvestigation(issue) {
    // Get all related requests with full details
    const relatedRequests = requests.filter(r => issue.requests.includes(r.id));

    const investigationData = {
      metadata: {
        generated: new Date().toISOString(),
        tool: 'Hera Security Extension',
        version: '1.0',
        purpose: 'Security Finding Investigation'
      },
      finding: {
        type: issue.type,
        severity: issue.severity,
        message: issue.message,
        count: issue.count,
        exploitation: issue.exploitation || null,
        recommendation: issue.recommendation || null
      },
      affected_requests: relatedRequests.map(req => ({
        id: req.id,
        url: req.url,
        method: req.method,
        timestamp: req.timestamp,
        status: req.statusCode,
        auth_type: req.authType,

        // Include relevant headers for investigation
        auth_headers: (req.requestHeaders || []).filter(h =>
          h.name.toLowerCase().includes('auth') ||
          h.name.toLowerCase().includes('cookie') ||
          h.name.toLowerCase().includes('token')
        ).map(h => ({ name: h.name, value: h.value.substring(0, 20) + '...' })),

        // Include security context
        security_context: {
          is_https: req.url.startsWith('https'),
          has_credentials: req.metadata?.securityContext?.hasCredentials,
          port: req.metadata?.portAnalysis?.port,
          service: req.metadata?.portAnalysis?.service
        },

        // Include any specific issue details
        issue_details: (req.metadata?.authAnalysis?.issues || [])
          .filter(i => i.type === issue.type)
          .map(i => ({
            message: i.message,
            exploitation: i.exploitation,
            location: i.location
          }))
      })),

      investigation_checklist: {
        false_positive_checks: [
          'Verify if the finding applies to the specific context',
          'Check if compensating controls are in place',
          'Confirm the affected functionality is security-sensitive',
          'Validate that the detection pattern is accurate'
        ],
        impact_assessment: [
          'Determine data sensitivity of affected endpoints',
          'Identify potential attack vectors',
          'Assess likelihood of exploitation',
          'Calculate risk score (likelihood × impact)'
        ],
        remediation_steps: [
          'Document the specific fix required',
          'Identify responsible team/developer',
          'Set appropriate priority based on risk',
          'Create tracking ticket/issue'
        ]
      },

      curl_commands: relatedRequests.slice(0, 5).map(req => {
        let curl = `curl -X ${req.method} '${req.url}'`;

        // Add important headers
        const headers = req.requestHeaders || [];
        headers.forEach(h => {
          if (!h.name.toLowerCase().includes('cookie') &&
              !h.name.toLowerCase().includes('authorization')) {
            curl += ` \\\n  -H '${h.name}: ${h.value}'`;
          }
        });

        if (req.requestBody) {
          curl += ` \\\n  -d '${JSON.stringify(req.requestBody)}'`;
        }

        return curl;
      })
    };

    // Create and download the investigation file
    const now = new Date();
    const date = now.toISOString().slice(2, 10);
    const time = now.toISOString().slice(11, 19).replace(/:/g, '-');
    const filename = `${date}_${time}_hera-finding-${issue.type.toLowerCase()}.json`;

    const blob = new Blob([JSON.stringify(investigationData, null, 2)], {
      type: 'application/json'
    });
    const url = URL.createObjectURL(blob);

    chrome.downloads.download({
      url: url,
      filename: filename,
      saveAs: true
    });
  }

  // Show requests that have a specific finding
  function showRequestsForFinding(finding) {
    // Switch back to requests view
    findingsList.style.display = 'none';
    requestsList.style.display = 'block';
    requestsBtn.classList.add('active');
    findingsBtn.classList.remove('active');

    // Filter and highlight requests with this finding
    const matchingRequests = finding.requests || [];

    // Clear current selection and scroll to first matching request
    if (matchingRequests.length > 0) {
      const firstMatchId = matchingRequests[0];
      const firstRequestEl = document.querySelector(`[data-id="${firstMatchId}"]`);

      if (firstRequestEl) {
        // Highlight the finding in the UI
        highlightFindingInRequests(finding.type, matchingRequests);

        // Scroll to and show details of first matching request
        firstRequestEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
        setTimeout(() => {
          firstRequestEl.click();
        }, 500);
      }
    }
  }

  // Highlight requests that contain a specific finding
  function highlightFindingInRequests(findingType, requestIds) {
    // Remove any existing highlighting
    document.querySelectorAll('.request-item').forEach(el => {
      el.classList.remove('highlighted-finding');
    });

    // Add highlighting to matching requests
    requestIds.forEach(requestId => {
      const requestEl = document.querySelector(`[data-id="${requestId}"]`);
      if (requestEl) {
        requestEl.classList.add('highlighted-finding');

        // Add a temporary badge showing the finding type
        const badge = document.createElement('div');
        badge.className = 'finding-badge';
        badge.textContent = findingType;
        requestEl.appendChild(badge);

        // Remove highlighting after 10 seconds
        setTimeout(() => {
          requestEl.classList.remove('highlighted-finding');
          badge.remove();
        }, 10000);
      }
    });
  }

  // Show details for a specific request
  function showRequestDetails(requestId) {
    console.log('Showing details for request:', requestId);
    selectedRequest = requests.find(r => r.id === requestId);
    if (!selectedRequest) {
      console.error('Request not found:', requestId);
      return;
    }
    
    console.log('Selected request:', selectedRequest);
    console.log('Request headers:', selectedRequest.requestHeaders);
    console.log('Response headers:', selectedRequest.responseHeaders);
    console.log('Request body:', selectedRequest.requestBody);
    console.log('Response body:', selectedRequest.responseBody);
    console.log('Metadata:', selectedRequest.metadata);
    
    // Debug header data specifically
    console.log('Header Debug Info:');
    console.log('  - requestHeaders type:', typeof selectedRequest.requestHeaders);
    console.log('  - requestHeaders length:', selectedRequest.requestHeaders?.length);
    console.log('  - responseHeaders type:', typeof selectedRequest.responseHeaders);
    console.log('  - responseHeaders length:', selectedRequest.responseHeaders?.length);
    
    if (selectedRequest.requestHeaders) {
      console.log('  - First few request headers:', selectedRequest.requestHeaders.slice(0, 3));
    }
    if (selectedRequest.responseHeaders) {
      console.log('  - First few response headers:', selectedRequest.responseHeaders.slice(0, 3));
    }
    
    const elements = {
      detailUrl: document.getElementById('detailUrl'),
      detailMethod: document.getElementById('detailMethod'),
      detailStatus: document.getElementById('detailStatus'),
      detailType: document.getElementById('detailType'),
      detailTime: document.getElementById('detailTime'),
      detailDuration: document.getElementById('detailDuration'),
      detailInitiator: document.getElementById('detailInitiator'),
      detailServerIP: document.getElementById('detailServerIP'),
      detailLocation: document.getElementById('detailLocation')
    };
    if (elements.detailUrl) {
      elements.detailUrl.textContent = selectedRequest.url;
      console.log('Set URL:', selectedRequest.url);
    } else {
      console.error('detailUrl element not found');
    }
    
    if (detailMethod) {
      detailMethod.textContent = selectedRequest.method || 'GET';
      console.log('Set method:', selectedRequest.method || 'GET');
    } else {
      console.error('detailMethod element not found');
    }
    
    if (detailStatus) {
      detailStatus.textContent = selectedRequest.statusCode || 'Pending';
      console.log('Set status:', selectedRequest.statusCode || 'Pending');
    } else {
      console.error('detailStatus element not found');
    }
    
    if (detailType) {
      detailType.textContent = selectedRequest.authType || 'Unknown';
      console.log('Set type:', selectedRequest.authType || 'Unknown');
    } else {
      console.error('detailType element not found');
    }
    
    if (detailTime) {
      const timeInfo = TimeUtils.formatTimeWithRelative(selectedRequest.timestamp);
      detailTime.textContent = `${timeInfo.relative} (${timeInfo.full})`;
      detailTime.title = `Full timestamp: ${timeInfo.iso}`;
      console.log('Set time:', timeInfo.relative, 'Full:', timeInfo.full);
    } else {
      console.error('detailTime element not found');
    }

    // Display duration
    if (elements.detailDuration) {
      const timing = selectedRequest.metadata?.timing;
      if (timing?.duration) {
        const durationMs = timing.duration;
        let durationText;
        if (durationMs < 1000) {
          durationText = `${durationMs}ms`;
        } else if (durationMs < 60000) {
          durationText = `${(durationMs / 1000).toFixed(2)}s`;
        } else {
          durationText = `${(durationMs / 60000).toFixed(2)}m`;
        }
        elements.detailDuration.textContent = durationText;
      } else {
        elements.detailDuration.textContent = 'Unknown';
      }
    }

    if (elements.detailInitiator) {
      elements.detailInitiator.textContent = selectedRequest.initiator || 'Unknown';
    }
    
    // Display IP and location data
    if (elements.detailServerIP) {
      const dnsIntel = selectedRequest.metadata?.dnsIntelligence;
      if (dnsIntel?.ipAddresses?.ipv4Addresses?.length > 0) {
        elements.detailServerIP.textContent = dnsIntel.ipAddresses.ipv4Addresses[0];
      } else {
        elements.detailServerIP.textContent = 'Not resolved';
      }
    }
    
    if (elements.detailLocation) {
      const dnsIntel = selectedRequest.metadata?.dnsIntelligence;
      const geoData = dnsIntel?.ipAddresses?.geoLocations?.[0];

      if (geoData) {
        // Build comprehensive location string
        const locationParts = [];

        if (geoData.city) locationParts.push(geoData.city);
        if (geoData.region && geoData.region !== geoData.city) locationParts.push(geoData.region);
        if (geoData.country) locationParts.push(geoData.country);

        const location = locationParts.length > 0 ? locationParts.join(', ') : 'Unknown location';

        // Add organization if available
        const organization = geoData.organization || dnsIntel?.geoLocation?.organization;
        const fullLocation = organization ? `${location} (${organization})` : location;

        elements.detailLocation.textContent = fullLocation;

        // Add tooltip with additional details
        const tooltipParts = [];
        if (geoData.latitude && geoData.longitude) {
          tooltipParts.push(`Coordinates: ${geoData.latitude}, ${geoData.longitude}`);
        }
        if (geoData.timezone) {
          tooltipParts.push(`Timezone: ${geoData.timezone}`);
        }
        if (geoData.isp) {
          tooltipParts.push(`ISP: ${geoData.isp}`);
        }
        if (tooltipParts.length > 0) {
          elements.detailLocation.title = tooltipParts.join('\n');
        }
      } else {
        elements.detailLocation.textContent = 'Location unknown';
        elements.detailLocation.title = 'Geographic location could not be determined';
      }
    }

    // Setup copy button event listeners
    setupCopyButtons();

    // Populate security overview
    populateSecurityOverview(selectedRequest);

    // Populate cookie overview
    populateCookieOverview(selectedRequest);

    // Populate authentication security overview
    populateAuthSecurityOverview(selectedRequest);

    console.log('Updated overview tab elements');
    
    // DNS Intelligence Tab with IP Information
    const dnsIntel = selectedRequest.metadata?.dnsIntelligence || {};
    const ipAddresses = dnsIntel.ipAddresses || {};
    
    const dnsHostnameEl = document.getElementById('dnsHostname');
    const dnsHomographEl = document.getElementById('dnsHomograph');
    const dnsDGAEl = document.getElementById('dnsDGA');
    const dnsCountryEl = document.getElementById('dnsCountry');
    const dnsOrgEl = document.getElementById('dnsOrg');
    
    if (dnsHostnameEl) dnsHostnameEl.textContent = dnsIntel.hostname || 'N/A';
    if (dnsHomographEl) dnsHomographEl.textContent = dnsIntel.isHomograph ? 'Yes (Warning)' : 'No';
    if (dnsDGAEl) dnsDGAEl.textContent = dnsIntel.isDGA ? 'Yes (Warning)' : 'No';
    if (dnsCountryEl) dnsCountryEl.textContent = dnsIntel.geoLocation?.country || 'Unknown';
    if (dnsOrgEl) dnsOrgEl.textContent = dnsIntel.geoLocation?.organization || 'Unknown';
    
    // Display IP addresses
    const ipContainer = document.getElementById('ipAddresses') || createIPContainer();
    if (ipContainer) {
      ipContainer.innerHTML = '';
      
      if (ipAddresses.ipv4Addresses && ipAddresses.ipv4Addresses.length > 0) {
        const ipSection = document.createElement('div');
        ipSection.className = 'ip-section';

        // P0-NEW-1 FIX: Use DOM methods instead of innerHTML to prevent XSS
        const title = document.createElement('h4');
        title.textContent = 'IP Addresses & Locations';
        ipSection.appendChild(title);

        ipAddresses.ipv4Addresses.forEach(ip => {
          const geoData = ipAddresses.geoLocations?.find(geo => geo.ip === ip);

          const ipItem = document.createElement('div');
          ipItem.className = 'ip-item';

          const ipAddress = document.createElement('div');
          ipAddress.className = 'ip-address';
          ipAddress.textContent = ip; // Safe - textContent auto-escapes
          ipItem.appendChild(ipAddress);

          if (geoData) {
            const ipDetails = document.createElement('div');
            ipDetails.className = 'ip-details';

            const location = document.createElement('span');
            location.className = 'ip-location';
            // P0-NEW-1: Sanitize untrusted data from IPapi.co
            location.textContent = `${geoData.city || 'Unknown'}, ${geoData.country || 'Unknown'}`;
            ipDetails.appendChild(location);

            const isp = document.createElement('span');
            isp.className = 'ip-isp';
            isp.textContent = geoData.isp || 'Unknown ISP'; // Safe
            ipDetails.appendChild(isp);

            if (geoData.isVPN) {
              const vpn = document.createElement('span');
              vpn.className = 'ip-warning';
              vpn.textContent = 'VPN Detected';
              ipDetails.appendChild(vpn);
            }

            if (geoData.isTor) {
              const tor = document.createElement('span');
              tor.className = 'ip-warning';
              tor.textContent = 'Tor Network';
              ipDetails.appendChild(tor);
            }

            if (geoData.isProxy) {
              const proxy = document.createElement('span');
              proxy.className = 'ip-warning';
              proxy.textContent = 'Proxy Detected';
              ipDetails.appendChild(proxy);
            }

            if (geoData.threatLevel === 'high') {
              const threat = document.createElement('span');
              threat.className = 'ip-threat';
              threat.textContent = 'High Threat';
              ipDetails.appendChild(threat);
            }

            ipItem.appendChild(ipDetails);
          } else {
            const noData = document.createElement('div');
            noData.className = 'ip-details';
            noData.textContent = 'Location data unavailable';
            ipItem.appendChild(noData);
          }

          ipSection.appendChild(ipItem);
        });

        ipContainer.appendChild(ipSection);
      } else {
        const noData = document.createElement('div');
        noData.className = 'ip-section';
        noData.textContent = 'No IP address data available';
        ipContainer.innerHTML = ''; // Clear first
        ipContainer.appendChild(noData);
      }
    }
    
    // Update headers tab
    const requestHeadersEl = document.getElementById('requestHeaders');
    const responseHeadersEl = document.getElementById('responseHeaders');
    const requestBodyEl = document.getElementById('requestBody');
    const responseBodyEl = document.getElementById('responseBody');
    
    if (requestHeadersEl) {
      const formattedHeaders = formatHeaders(selectedRequest.requestHeaders);
      requestHeadersEl.textContent = formattedHeaders || 'No request headers available';
    }
    if (responseHeadersEl) {
      const formattedHeaders = formatHeaders(selectedRequest.responseHeaders);
      responseHeadersEl.textContent = formattedHeaders || 'No response headers available';
    }
    // Update body tab with enhanced status
    updateBodyTabWithStatus(selectedRequest);
    
    // Update conversation tab
    updateConversationView(selectedRequest);
    
    // Update consent tab
    updateConsentDisplay(selectedRequest);
    
    // Update security tab
    updateSecurityAnalysis(selectedRequest);

    // Update headers tab
    updateHeadersTab(selectedRequest);

    // Update body tab with enhanced status
    updateBodyTabWithStatus(selectedRequest);

    // Update DNS tab
    updateDNSTab(selectedRequest);

    // Update Token Analysis tab
    renderTokenAnalysis(selectedRequest);

    // Show the details panel
    requestDetails.style.display = 'flex';
    requestDetails.classList.add('show');
    console.log('Detail panel shown');
    
    // Activate the first tab
    switchTab('overview');
    console.log('Switched to overview tab');

    // Show the 'Send to Repeater' button
    if (sendToRepeaterBtn) {
      sendToRepeaterBtn.style.display = 'block';
    }
  }

  // Render JWT analysis tab
  function renderTokenAnalysis(request) {
    const tokenTab = document.getElementById('tokenTab');
    const tokenAnalysisEl = document.getElementById('tokenAnalysis');
    const tokenTabButton = document.querySelector('[data-tab="token"]');
    const probeBtn = document.getElementById('probeAlgNoneBtn');

    if (!tokenAnalysisEl || !tokenTab || !tokenTabButton) return;

    let jwt = null;

    // 1. Look for JWT in Authorization header
    const authHeader = request.requestHeaders?.find(h => h.name.toLowerCase() === 'authorization');
    if (authHeader && authHeader.value.toLowerCase().startsWith('bearer ')) {
      jwt = authHeader.value.substring(7);
    }

    // 2. If not in header, look in request or response body
    if (!jwt) {
      try {
        const requestBody = JSON.parse(request.requestBody || '{}');
        jwt = requestBody.access_token || requestBody.id_token;
      } catch (e) {}
    }
    if (!jwt) {
      try {
        const responseBody = JSON.parse(request.responseBody || '{}');
        jwt = responseBody.access_token || responseBody.id_token;
      } catch (e) {}
    }

    if (jwt && typeof jwt === 'string' && JWTSecurity.isValidJWTStructure(jwt)) {
      tokenTabButton.style.display = 'block'; // Show the tab
      probeBtn.style.display = 'block'; // Show the probe button

      // Parse JWT securely
      const parsedJWT = JWTSecurity.parseJWT(jwt);

      if (parsedJWT.error) {
        const errorDiv = DOMSecurity.createSafeElement('div', `JWT Parse Error: ${parsedJWT.error}`, { className: 'error-state' });
        DOMSecurity.replaceChildren(tokenAnalysisEl, errorDiv);
      } else {
        // Security analysis
        const securityIssues = JWTSecurity.validateJWTSecurity(parsedJWT);

        // Clear previous content
        tokenAnalysisEl.innerHTML = '';

        // Security warnings first
        if (securityIssues.length > 0) {
          const warningsSection = DOMSecurity.createSafeElement('div', '', { className: 'jwt-warnings' });
          const warningsTitle = DOMSecurity.createSafeElement('h4', 'Security Issues Found:');
          warningsSection.appendChild(warningsTitle);

          securityIssues.forEach(issue => {
            const issueDiv = DOMSecurity.createSafeElement('div', '', { className: `jwt-warning ${issue.severity.toLowerCase()}` });
            const severitySpan = DOMSecurity.createSafeElement('span', issue.severity, { className: 'jwt-severity' });
            const typeSpan = DOMSecurity.createSafeElement('span', issue.type, { className: 'jwt-type' });
            const messageDiv = DOMSecurity.createSafeElement('div', issue.message, { className: 'jwt-message' });

            issueDiv.appendChild(severitySpan);
            issueDiv.appendChild(typeSpan);
            issueDiv.appendChild(messageDiv);
            warningsSection.appendChild(issueDiv);
          });
          tokenAnalysisEl.appendChild(warningsSection);
        }

        // Header section
        const headerSection = DOMSecurity.createSafeElement('div', '', { className: 'jwt-section' });
        const headerTitle = DOMSecurity.createSafeElement('h4', 'Header');
        const headerPre = DOMSecurity.createSafeElement('pre', JSON.stringify(parsedJWT.header, null, 2), { className: 'jwt-part jwt-header' });
        headerSection.appendChild(headerTitle);
        headerSection.appendChild(headerPre);
        tokenAnalysisEl.appendChild(headerSection);

        // Payload section
        const payloadSection = DOMSecurity.createSafeElement('div', '', { className: 'jwt-section' });
        const payloadTitle = DOMSecurity.createSafeElement('h4', 'Payload');
        const payloadPre = DOMSecurity.createSafeElement('pre', JSON.stringify(parsedJWT.payload, null, 2), { className: 'jwt-part jwt-payload' });
        payloadSection.appendChild(payloadTitle);
        payloadSection.appendChild(payloadPre);
        tokenAnalysisEl.appendChild(payloadSection);

        // Signature section
        const signatureSection = DOMSecurity.createSafeElement('div', '', { className: 'jwt-section' });
        const signatureTitle = DOMSecurity.createSafeElement('h4', 'Signature');
        const signaturePre = DOMSecurity.createSafeElement('pre', parsedJWT.signature, { className: 'jwt-part jwt-signature' });
        signatureSection.appendChild(signatureTitle);
        signatureSection.appendChild(signaturePre);
        tokenAnalysisEl.appendChild(signatureSection);
      }

      // Add event listener for the probe button
      probeBtn.onclick = () => {
        probeBtn.textContent = 'Probing...';
        probeBtn.disabled = true;
        chrome.runtime.sendMessage({
          action: 'probe:alg_none',
          request: request,
          jwt: jwt
        }, (response) => {
          probeBtn.textContent = 'Probe for alg:none';
          probeBtn.disabled = false;
          // TODO: Display the probe result in the UI
          alert(`Probe Result: ${response.success ? 'Vulnerable!' : 'Not Vulnerable.'} (Status: ${response.status})`);
          console.log('Probe response:', response);
        });
      };
    } else {
      tokenTabButton.style.display = 'none'; // Hide tab if no JWT
      probeBtn.style.display = 'none';
      tokenAnalysisEl.innerHTML = '';
    }
  }

  // Main view switching
  if (findingsBtn && requestsBtn && extensionsBtn && portsBtn) {
    findingsBtn.addEventListener('click', () => {
      requestsList.style.display = 'none';
      findingsList.style.display = 'block';
      extensionsList.style.display = 'none';
      portsAnalysis.style.display = 'none';

      findingsBtn.classList.add('active');
      requestsBtn.classList.remove('active');
      extensionsBtn.classList.remove('active');
      portsBtn.classList.remove('active');

      renderFindings();
    });

    portsBtn.addEventListener('click', () => {
      requestsList.style.display = 'none';
      findingsList.style.display = 'none';
      extensionsList.style.display = 'none';
      portsAnalysis.style.display = 'block';

      portsBtn.classList.add('active');
      requestsBtn.classList.remove('active');
      findingsBtn.classList.remove('active');
      extensionsBtn.classList.remove('active');

      loadPortAnalysis();
    });

    extensionsBtn.addEventListener('click', () => {
      requestsList.style.display = 'none';
      findingsList.style.display = 'none';
      extensionsList.style.display = 'block';
      portsAnalysis.style.display = 'none';

      extensionsBtn.classList.add('active');
      requestsBtn.classList.remove('active');
      findingsBtn.classList.remove('active');
      portsBtn.classList.remove('active');

      loadExtensionAssessments();
    });

    requestsBtn.addEventListener('click', () => {
      findingsList.style.display = 'none';
      extensionsList.style.display = 'none';
      requestsList.style.display = 'block';
      portsAnalysis.style.display = 'none';

      requestsBtn.classList.add('active');
      findingsBtn.classList.remove('active');
      extensionsBtn.classList.remove('active');
      portsBtn.classList.remove('active');
    });
  }

  // Refresh extensions button
  const refreshExtensionsBtn = document.getElementById('refreshExtensionsBtn');
  if (refreshExtensionsBtn) {
    refreshExtensionsBtn.addEventListener('click', loadExtensionAssessments);
  }
  
  // Update conversation view with chat-like interface
  function updateConversationView(request) {
    const chatMessages = document.getElementById('chatMessages');
    if (!chatMessages) return;
    
    chatMessages.innerHTML = '';
    
    // Create request message (from browser)
    const requestMessage = document.createElement('div');
    requestMessage.className = 'chat-message browser-message';
    
    const timeInfo = TimeUtils.formatTimeWithRelative(request.timestamp);
    const requestTime = timeInfo.relative;
    const requestUrl = new URL(request.url);
    
    // Extract meaningful data from request
    let requestData = '';
    if (request.requestBody) {
      try {
        const body = JSON.parse(request.requestBody);
        if (body.grant_type) requestData += `Grant Type: ${body.grant_type}\n`;
        if (body.client_id) requestData += `Client ID: ${body.client_id}\n`;
        if (body.scope) requestData += `Scopes: ${body.scope}\n`;
        if (body.username) requestData += `Username: ${body.username}\n`;
      } catch (e) {
        if (request.requestBody.length < 200) {
          requestData = request.requestBody;
        }
      }
    }
    
    // SECURITY FIX: Use DOM methods instead of innerHTML to prevent XSS
    const messageHeader = document.createElement('div');
    messageHeader.className = 'message-header';

    const senderSpan = document.createElement('span');
    senderSpan.className = 'sender';
    senderSpan.textContent = 'Your Browser';

    const timeSpan = document.createElement('span');
    timeSpan.className = 'time';
    timeSpan.setAttribute('title', timeInfo.full);
    timeSpan.textContent = requestTime;

    messageHeader.appendChild(senderSpan);
    messageHeader.appendChild(timeSpan);

    const messageBubble = document.createElement('div');
    messageBubble.className = 'message-bubble browser-bubble';

    const messageContent = document.createElement('div');
    messageContent.className = 'message-content';

    const strong = document.createElement('strong');
    strong.textContent = `${request.method} ${requestUrl.pathname}`;

    const messageDetails = document.createElement('div');
    messageDetails.className = 'message-details';
    let detailsText = `To: ${requestUrl.hostname}`;
    if (request.authType) detailsText += `\nAuth Type: ${request.authType}`;
    if (requestData) detailsText += `\n\nData:\n${requestData}`;
    messageDetails.textContent = detailsText;

    messageContent.appendChild(strong);
    messageContent.appendChild(messageDetails);
    messageBubble.appendChild(messageContent);

    requestMessage.appendChild(messageHeader);
    requestMessage.appendChild(messageBubble);
    
    chatMessages.appendChild(requestMessage);
    
    // Create response message (from server) if available
    if (request.statusCode) {
      const responseMessage = document.createElement('div');
      responseMessage.className = 'chat-message server-message';
      
      const statusEmoji = request.statusCode >= 400 ? 'ERROR' : request.statusCode >= 200 ? 'SUCCESS' : 'PENDING';
      const statusText = request.statusCode >= 400 ? 'Error' : request.statusCode >= 200 ? 'Success' : 'Pending';
      
      // Extract meaningful data from response
      let responseData = '';
      if (request.responseBody) {
        try {
          const body = JSON.parse(request.responseBody);
          if (body.access_token) responseData += `Access Token: ${body.access_token.substring(0, 20)}...\n`;
          if (body.refresh_token) responseData += ` Refresh Token: ${body.refresh_token.substring(0, 20)}...\n`;
          if (body.expires_in) responseData += `Expires: ${body.expires_in}s\n`;
          if (body.token_type) responseData += `Token Type: ${body.token_type}\n`;
          if (body.scope) responseData += `Granted Scopes: ${body.scope}\n`;
          if (body.error) responseData += `Error: ${body.error}\n`;
          if (body.error_description) responseData += `Description: ${body.error_description}\n`;
        } catch (e) {
          if (request.responseBody.length < 200) {
            responseData = request.responseBody;
          }
        }
      }
      
      // SECURITY FIX: Use DOM methods instead of innerHTML to prevent XSS
      const respHeader = document.createElement('div');
      respHeader.className = 'message-header';

      const respSender = document.createElement('span');
      respSender.className = 'sender';
      respSender.textContent = requestUrl.hostname;

      const respTime = document.createElement('span');
      respTime.className = 'time';
      respTime.setAttribute('title', timeInfo.full);
      respTime.textContent = requestTime;

      respHeader.appendChild(respSender);
      respHeader.appendChild(respTime);

      const respBubble = document.createElement('div');
      respBubble.className = 'message-bubble server-bubble';

      const respContent = document.createElement('div');
      respContent.className = 'message-content';

      const respStrong = document.createElement('strong');
      respStrong.textContent = `${statusEmoji} ${request.statusCode} ${statusText}`;

      const respDetails = document.createElement('div');
      respDetails.className = 'message-details';
      respDetails.textContent = responseData || 'Response received';

      respContent.appendChild(respStrong);
      respContent.appendChild(respDetails);
      respBubble.appendChild(respContent);

      responseMessage.appendChild(respHeader);
      responseMessage.appendChild(respBubble);
      
      chatMessages.appendChild(responseMessage);
    } else {
      // Show waiting for response
      const waitingMessage = document.createElement('div');
      waitingMessage.className = 'chat-message server-message waiting';
      // SECURITY FIX: Use DOM methods instead of innerHTML to prevent XSS
      const waitHeader = document.createElement('div');
      waitHeader.className = 'message-header';

      const waitSender = document.createElement('span');
      waitSender.className = 'sender';
      waitSender.textContent = requestUrl.hostname;

      const waitTime = document.createElement('span');
      waitTime.className = 'time';
      waitTime.textContent = '...';

      waitHeader.appendChild(waitSender);
      waitHeader.appendChild(waitTime);

      const waitBubble = document.createElement('div');
      waitBubble.className = 'message-bubble server-bubble waiting-bubble';

      const waitContent = document.createElement('div');
      waitContent.className = 'message-content';

      const waitStrong = document.createElement('strong');
      waitStrong.textContent = 'Waiting for response...';

      const waitDetails = document.createElement('div');
      waitDetails.className = 'message-details';
      waitDetails.textContent = 'Server is processing the request';

      waitContent.appendChild(waitStrong);
      waitContent.appendChild(waitDetails);
      waitBubble.appendChild(waitContent);

      waitingMessage.appendChild(waitHeader);
      waitingMessage.appendChild(waitBubble);
      
      chatMessages.appendChild(waitingMessage);
    }
  }

  // Create IP container if it doesn't exist
  function createIPContainer() {
    const dnsTab = document.querySelector('[data-tab="dns"]');
    if (!dnsTab) return null;
    
    let ipContainer = document.getElementById('ipAddresses');
    if (!ipContainer) {
      ipContainer = document.createElement('div');
      ipContainer.id = 'ipAddresses';
      ipContainer.className = 'ip-container';
      dnsTab.appendChild(ipContainer);
    }
    return ipContainer;
  }
  
  // Hide request details
  function hideDetails() {
    requestDetails.style.display = 'none';
    requestDetails.classList.remove('show');
    if (sendToRepeaterBtn) {
      sendToRepeaterBtn.style.display = 'none';
    }
  }

  // Repeater Logic
  if (sendToRepeaterBtn) {
    sendToRepeaterBtn.addEventListener('click', () => {
      if (selectedRequest) {
        // Format the full HTTP request for the textarea
        let rawRequest = `${selectedRequest.method} ${selectedRequest.url} HTTP/1.1\n`;
        selectedRequest.requestHeaders.forEach(h => {
          rawRequest += `${h.name}: ${h.value}\n`;
        });
        rawRequest += '\n';
        if (selectedRequest.requestBody) {
          rawRequest += formatBody(selectedRequest.requestBody);
        }
        repeaterRequestEl.value = rawRequest;
        repeaterResponseEl.textContent = '';
        repeaterPanel.style.display = 'flex';
      }
    });
  }

  if (closeRepeaterBtn) {
    closeRepeaterBtn.addEventListener('click', () => {
      repeaterPanel.style.display = 'none';
    });
  }

  if (sendRepeaterBtn) {
    sendRepeaterBtn.addEventListener('click', () => {
      sendRepeaterBtn.textContent = 'Sending...';
      sendRepeaterBtn.disabled = true;
      chrome.runtime.sendMessage({
        action: 'repeater:send',
        rawRequest: repeaterRequestEl.value
      }, response => {
        sendRepeaterBtn.textContent = 'Send';
        sendRepeaterBtn.disabled = false;
        if (response.error) {
          repeaterResponseEl.textContent = `Error: ${response.error}`;
        } else {
          repeaterResponseEl.textContent = response.rawResponse;
        }
      });
    });
  }
  
  // Switch between tabs
  function switchTab(tabName) {
    console.log('Switching to tab:', tabName);
    
    // Hide all tab contents
    const allTabContents = document.querySelectorAll('.tab-content');
    allTabContents.forEach(content => {
      content.classList.remove('active');
    });
    
    // Remove active class from all buttons
    const allTabButtons = document.querySelectorAll('.tab-btn');
    allTabButtons.forEach(button => {
      button.classList.remove('active');
    });
    
    // Show selected tab content
    const selectedTab = document.getElementById(tabName + 'Tab');
    if (selectedTab) {
      selectedTab.classList.add('active');
      console.log('Activated tab:', tabName + 'Tab');
    } else {
      console.error('Tab not found:', tabName + 'Tab');
    }
    
    // Add active class to selected button
    const selectedButton = document.querySelector(`[data-tab="${tabName}"]` );
    if (selectedButton) {
      selectedButton.classList.add('active');
      console.log('Activated button for:', tabName);
    } else {
      console.error('Button not found for tab:', tabName);
    }
  }
  
  // Clear all requests
  function clearRequests() {
    if (confirm('Are you sure you want to clear all captured requests?')) {
      chrome.runtime.sendMessage({ action: 'clearRequests' }, response => {
        if (response && response.success) {
          requests = [];
          renderRequests();
          hideDetails();
        }
      });
    }
  }
  
  // Export captured requests
  function exportRequests() {
    // Show export format selection modal
    showExportModal(requests, 'current');
  }

  // Show export format selection modal
  function showExportModal(data, type) {
    const modal = document.createElement('div');
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0,0,0,0.8);
      z-index: 10000;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, sans-serif;
    `;

    modal.innerHTML = `
      <div style="
        background: white;
        padding: 30px;
        border-radius: 12px;
        max-width: 600px;
        width: 90%;
      ">
        <h2 style="margin: 0 0 20px 0; color: #333;">Export ${type === 'current' ? 'Current View' : 'All Sessions'}</h2>

        <div style="margin-bottom: 20px; color: #666;">
          Choose the export format for your security testing workflow:
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 30px;">
          <button class="export-option" data-format="json" style="
            padding: 20px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            background: white;
            cursor: pointer;
            text-align: left;
            transition: all 0.2s;
          ">
            <strong style="display: block; margin-bottom: 5px;">JSON (Default)</strong>
            <small style="color: #666;">Complete data for analysis</small>
          </button>

          <button class="export-option" data-format="burp" style="
            padding: 20px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            background: white;
            cursor: pointer;
            text-align: left;
            transition: all 0.2s;
          ">
            <strong style="display: block; margin-bottom: 5px;">Burp Suite</strong>
            <small style="color: #666;">Import-ready session file</small>
          </button>

          <button class="export-option" data-format="nuclei" style="
            padding: 20px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            background: white;
            cursor: pointer;
            text-align: left;
            transition: all 0.2s;
          ">
            <strong style="display: block; margin-bottom: 5px;">Nuclei Targets</strong>
            <small style="color: #666;">Host list for vulnerability scanning</small>
          </button>

          <button class="export-option" data-format="curl" style="
            padding: 20px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            background: white;
            cursor: pointer;
            text-align: left;
            transition: all 0.2s;
          ">
            <strong style="display: block; margin-bottom: 5px;">cURL Commands</strong>
            <small style="color: #666;">Replay requests manually</small>
          </button>
        </div>

        <div style="display: flex; gap: 10px; justify-content: flex-end;">
          <button id="cancelExport" style="
            background: #666;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
          ">
            Cancel
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    // Add hover effects
    const options = modal.querySelectorAll('.export-option');
    options.forEach(option => {
      option.addEventListener('mouseenter', () => {
        option.style.borderColor = '#4CAF50';
        option.style.backgroundColor = '#f8f8f8';
      });
      option.addEventListener('mouseleave', () => {
        option.style.borderColor = '#e0e0e0';
        option.style.backgroundColor = 'white';
      });
      option.addEventListener('click', () => {
        const format = option.dataset.format;
        modal.remove();
        performExport(data, format, type);
      });
    });

    // Cancel button
    modal.querySelector('#cancelExport').addEventListener('click', () => {
      modal.remove();
    });
  }

  // Perform the actual export based on format
  function performExport(data, format, type) {
    const now = new Date();
    const date = now.toISOString().slice(2, 10); // YY-MM-DD format (25-09-27)
    const time = now.toISOString().slice(11, 19).replace(/:/g, '-'); // HH-MM-SS format

    switch (format) {
      case 'json':
        exportAsJSON(data, type, date, time);
        break;
      case 'burp':
        exportAsBurp(data, type, date, time);
        break;
      case 'nuclei':
        exportAsNuclei(data, type, date, time);
        break;
      case 'curl':
        exportAsCurl(data, type, date, time);
        break;
      default:
        exportAsJSON(data, type, date, time);
    }
  }

  // Export as JSON (original functionality)
  function exportAsJSON(data, type, date, time) {
    const exportData = type === 'current'
      ? { timestamp: new Date().toISOString(), requests: data }
      : data;

    // Safe JSON serialization
    let jsonString;
    try {
      jsonString = JSON.stringify(exportData, (_, value) => {
        if (typeof value === 'function') return '[Function]';
        if (value instanceof Error) return value.message;
        if (value === undefined) return null;
        return value;
      }, 2);
    } catch (jsonError) {
      console.error('JSON serialization error:', jsonError);
      alert('Error creating export file: ' + jsonError.message);
      return;
    }

    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    chrome.downloads.download({
      url: url,
      filename: `${date}_${time}_hera-${type}.json`,
      saveAs: true
    });
  }

  // Export as Burp Suite session
  function exportAsBurp(data, type, date, time) {
    const requests = type === 'current' ? data : getAllRequestsFromSessions(data);

    const burpSession = {
      metadata: {
        version: "1.0.0",
        tool: "Hera Browser Extension",
        timestamp: new Date().toISOString(),
        description: "Authentication security analysis session"
      },
      proxy: {
        history: requests.map((req, index) => ({
          id: index + 1,
          url: req.url,
          method: req.method || 'GET',
          status: req.statusCode || 0,
          length: req.responseBody ? req.responseBody.length : 0,
          mime_type: req.responseHeaders?.find(h => h.name.toLowerCase() === 'content-type')?.value || 'text/html',
          protocol: req.url.startsWith('https') ? 'https' : 'http',
          host: new URL(req.url).hostname,
          path: new URL(req.url).pathname + new URL(req.url).search,
          request: {
            raw: buildRawRequest(req),
            headers: req.requestHeaders || [],
            body: req.requestBody || ''
          },
          response: {
            raw: buildRawResponse(req),
            headers: req.responseHeaders || [],
            body: req.responseBody || ''
          },
          comment: `Hera: ${req.authType || 'Unknown'} - Risk: ${req.metadata?.authAnalysis?.riskCategory || 'unknown'}`
        }))
      }
    };

    const jsonString = JSON.stringify(burpSession, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    chrome.downloads.download({
      url: url,
      filename: `${date}_${time}_hera-burp-session.json`,
      saveAs: true
    });
  }

  // Export as Nuclei target list
  function exportAsNuclei(data, type, date, time) {
    const requests = type === 'current' ? data : getAllRequestsFromSessions(data);

    // Extract unique hosts and create target file
    const hosts = [...new Set(requests.map(req => {
      try {
        return new URL(req.url).origin;
      } catch (e) {
        return null;
      }
    }))].filter(Boolean);

    const nucleiConfig = {
      // Target URLs
      targets: hosts,

      // Config for Nuclei
      config: {
        "rate-limit": 150,
        "timeout": 10,
        "retries": 1,
        "severity": ["critical", "high", "medium"],
        "tags": ["auth", "oauth", "saml", "oidc", "jwt"]
      },

      // Additional context from Hera analysis
      context: {
        tool: "Hera Browser Extension",
        timestamp: new Date().toISOString(),
        total_hosts: hosts.length,
        auth_flows_detected: requests.length,
        high_risk_hosts: hosts.filter(host => {
          return requests.some(req =>
            req.url.includes(host) &&
            req.metadata?.authAnalysis?.riskScore > 70
          );
        })
      }
    };

    // Create both JSON config and plain text target list
    const configBlob = new Blob([JSON.stringify(nucleiConfig, null, 2)], { type: 'application/json' });
    const targetsBlob = new Blob([hosts.join('\n')], { type: 'text/plain' });

    // Download config file
    const configUrl = URL.createObjectURL(configBlob);
    chrome.downloads.download({
      url: configUrl,
      filename: `${date}_${time}_hera-nuclei-config.json`,
      saveAs: false
    });

    // Download target list
    const targetsUrl = URL.createObjectURL(targetsBlob);
    chrome.downloads.download({
      url: targetsUrl,
      filename: `${date}_${time}_hera-nuclei-targets.txt`,
      saveAs: true
    });
  }

  // Export as cURL commands
  function exportAsCurl(data, type, date, time) {
    const requests = type === 'current' ? data : getAllRequestsFromSessions(data);

    const curlCommands = requests.map((req, index) => {
      let curl = `# Request ${index + 1}: ${req.authType || 'Unknown'} - ${req.url}\n`;
      curl += `curl -X ${req.method || 'GET'} \\\n`;
      curl += `  '${req.url}' \\\n`;

      // Add headers
      if (req.requestHeaders && Array.isArray(req.requestHeaders)) {
        req.requestHeaders.forEach(header => {
          if (header.name && header.value) {
            curl += `  -H '${header.name}: ${header.value}' \\\n`;
          }
        });
      }

      // Add body if present
      if (req.requestBody) {
        curl += `  -d '${req.requestBody.replace(/'/g, "'\\''")}'\\\n`;
      }

      // Add common options
      curl += `  --silent \\\n`;
      curl += `  --show-error \\\n`;
      curl += `  --location \\\n`;
      curl += `  --max-time 30`;

      return curl;
    }).join('\n\n');

    const header = `#!/bin/bash
# Hera Authentication Flow Replay Script
# Generated: ${new Date().toISOString()}
# Total Requests: ${requests.length}
#
# Usage: bash ${date}_${time}_hera-curl-commands.sh
#

`;

    const fullScript = header + curlCommands;

    const blob = new Blob([fullScript], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);

    chrome.downloads.download({
      url: url,
      filename: `${date}_${time}_hera-curl-commands.sh`,
      saveAs: true
    });
  }

  // Helper function to build raw HTTP request
  function buildRawRequest(req) {
    const url = new URL(req.url);
    let raw = `${req.method || 'GET'} ${url.pathname}${url.search} HTTP/1.1\r\n`;
    raw += `Host: ${url.hostname}\r\n`;

    if (req.requestHeaders && Array.isArray(req.requestHeaders)) {
      req.requestHeaders.forEach(header => {
        if (header.name && header.value) {
          raw += `${header.name}: ${header.value}\r\n`;
        }
      });
    }

    raw += '\r\n';
    if (req.requestBody) {
      raw += req.requestBody;
    }

    return raw;
  }

  // Helper function to build raw HTTP response
  function buildRawResponse(req) {
    let raw = `HTTP/1.1 ${req.statusCode || 200} OK\r\n`;

    if (req.responseHeaders && Array.isArray(req.responseHeaders)) {
      req.responseHeaders.forEach(header => {
        if (header.name && header.value) {
          raw += `${header.name}: ${header.value}\r\n`;
        }
      });
    }

    raw += '\r\n';
    if (req.responseBody) {
      raw += req.responseBody;
    }

    return raw;
  }

  // Helper function to extract all requests from sessions
  function getAllRequestsFromSessions(data) {
    if (Array.isArray(data)) {
      return data;
    }

    const allRequests = [];
    if (data.sessions && Array.isArray(data.sessions)) {
      data.sessions.forEach(session => {
        if (session.requests && Array.isArray(session.requests)) {
          allRequests.push(...session.requests);
        }
      });
    }
    return allRequests;
  }
  
  // Export all stored sessions
  function exportAllSessions() {
    console.log('exportAllSessions function called');
    try {
      chrome.storage.local.get(['heraSessions'], (result) => {
        console.log('Retrieved sessions for export:', result);

        if (chrome.runtime.lastError) {
          console.error('Chrome runtime error:', chrome.runtime.lastError);
          alert('Error accessing storage: ' + chrome.runtime.lastError.message);
          return;
        }

        const allSessions = result.heraSessions || [];

        // Generate security summary
        const securitySummary = generateSecuritySummary(allSessions);

        const data = {
          exportType: 'all_sessions',
          timestamp: new Date().toISOString(),
          totalSessions: allSessions.length,
          securitySummary: securitySummary,
          sessions: allSessions,
          metadata: {
            exportedBy: 'Hera Browser Extension',
            version: '1.0.0',
            description: 'Complete authentication security analysis data'
          }
        };

        // Show export format selection modal for all sessions
        showExportModal(data, 'all');
      });
    } catch (error) {
      console.error('Error in exportAllSessions:', error);
      alert('Error exporting sessions: ' + error.message);
    }
  }
  
  // View storage statistics
  function viewStorageStats() {
    console.log('viewStorageStats function called');
    try {
      chrome.storage.local.get(null, (allData) => {
        console.log('Storage data retrieved:', allData);
        const stats = {
          heraSessions: allData.heraSessions?.length || 0,
          syncQueue: allData.syncQueue?.length || 0,
          heraConfig: allData.heraConfig ? 'Configured' : 'Not configured',
          totalStorageKeys: Object.keys(allData).length,
          estimatedSize: JSON.stringify(allData).length
        };
        
        // Create stats modal
        const modal = document.createElement('div');
        modal.style.cssText = `
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0,0,0,0.8);
          z-index: 10000;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: -apple-system, sans-serif;
        `;
        
        modal.innerHTML = `
          <div style="
            background: white;
            padding: 30px;
            border-radius: 12px;
            max-width: 500px;
            width: 90%;
          ">
            <h2 style="margin: 0 0 20px 0; color: #333;">Hera Storage Statistics</h2>
            
            <div style="margin-bottom: 15px;">
              <strong>Total Sessions Stored:</strong> ${stats.heraSessions.toLocaleString()}
            </div>
            
            <div style="margin-bottom: 15px;">
              <strong>Pending Sync Events:</strong> ${stats.syncQueue}
            </div>
            
            <div style="margin-bottom: 15px;">
              <strong>Configuration:</strong> ${stats.heraConfig}
            </div>
            
            <div style="margin-bottom: 15px;">
              <strong>Storage Keys:</strong> ${stats.totalStorageKeys}
            </div>
            
            <div style="margin-bottom: 25px;">
              <strong>Estimated Size:</strong> ${(stats.estimatedSize / 1024).toFixed(1)} KB
            </div>
            
            <div style="background: #f5f5f5; padding: 15px; border-radius: 6px; margin-bottom: 20px;">
              <strong>Storage Location:</strong><br>
              <code style="font-size: 11px; color: #666;">
                ~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/
              </code>
            </div>
            
            <div style="display: flex; gap: 10px; justify-content: flex-end;">
              <button id="closeStatsModal" style="
                background: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                cursor: pointer;
              ">
                Close
              </button>
              <button id="exportAllDataModal" style="
                background: #2196F3;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                cursor: pointer;
              ">
                Export All Data
              </button>
            </div>
          </div>
        `;
        
        document.body.appendChild(modal);
        
        // Add event listeners for modal buttons
        const closeBtn = modal.querySelector('#closeStatsModal');
        const exportBtn = modal.querySelector('#exportAllDataModal');
        
        if (closeBtn) {
          closeBtn.addEventListener('click', () => {
            modal.remove();
          });
        }
        
        if (exportBtn) {
          exportBtn.addEventListener('click', () => {
            exportAllSessions();
            modal.remove();
          });
        }
        
      });
    } catch (error) {
      console.error('Error in viewStorageStats:', error);
      alert('Error viewing storage stats: ' + error.message);
    }
  }

  // Format body helper function
  function formatBody(body) {
    try {
      // Try to parse and pretty-print JSON
      if (typeof body === 'string') {
        const parsed = JSON.parse(body);
        return JSON.stringify(parsed, (key, value) => {
          // Handle circular references and non-serializable objects
          if (typeof value === 'function') return '[Function]';
          if (value instanceof Error) return value.message;
          if (value === undefined) return null;
          return value;
        }, 2);
      } else if (typeof body === 'object') {
        return JSON.stringify(body, (key, value) => {
          // Handle circular references and non-serializable objects
          if (typeof value === 'function') return '[Function]';
          if (value instanceof Error) return value.message;
          if (value === undefined) return null;
          return value;
        }, 2);
      }
      return String(body);
    } catch (e) {
      // If not JSON or serialization fails, return as string
      return String(body);
    }
  }
  
  
  // Test function for debugging buttons
  function testAllButtons() {
    console.log('Testing all buttons...');
    console.log('clearBtn exists:', !!clearBtn);
    console.log('exportBtn exists:', !!exportBtn);
    console.log('exportAllBtn exists:', !!exportAllBtn);
    console.log('viewStorageBtn exists:', !!viewStorageBtn);
    
    // Test if functions exist
    console.log('clearRequests function exists:', typeof clearRequests === 'function');
    console.log('exportRequests function exists:', typeof exportRequests === 'function');
    console.log('exportAllSessions function exists:', typeof exportAllSessions === 'function');
    console.log('viewStorageStats function exists:', typeof viewStorageStats === 'function');
    
    // Test storage access
    console.log('Testing storage access...');
    chrome.storage.local.get(['heraSessions'], (result) => {
      if (chrome.runtime.lastError) {
        console.error('Storage test failed:', chrome.runtime.lastError);
      } else {
        console.log('Storage access works. Sessions found:', result.heraSessions?.length || 0);
      }
    });
  }
  
  // Make functions globally available
  window.hera = window.hera || {};
  window.hera.exportAllData = exportAllSessions;
  window.hera.testButtons = testAllButtons;
  
  // Make dismissAlert globally available
  window.dismissAlert = function() {
    const alertsEl = document.getElementById('consentAlerts');
    if (alertsEl) alertsEl.style.display = 'none';
  };
  
  // Format headers for display
  function formatHeaders(headers) {
    if (!headers) return null;
    
    // Handle different header formats
    if (Array.isArray(headers)) {
      if (headers.length === 0) return null;
      return headers
        .map(header => `${header.name}: ${header.value || ''}`)
        .join('\n');
    } else if (typeof headers === 'object') {
      const headerEntries = Object.entries(headers);
      if (headerEntries.length === 0) return null;
      return headerEntries
        .map(([name, value]) => `${name}: ${value}`)
        .join('\n');
    }
    
    return null;
  }

  // Format request/response body for display
  function formatBody(body) {
    if (!body) return null;
    
    try {
      // Try to parse and pretty-print JSON
      if (typeof body === 'string') {
        const parsed = JSON.parse(body);
        return JSON.stringify(parsed, (key, value) => {
          // Handle circular references and non-serializable objects
          if (typeof value === 'function') return '[Function]';
          if (value instanceof Error) return value.message;
          if (value === undefined) return null;
          return value;
        }, 2);
      } else if (typeof body === 'object') {
        return JSON.stringify(body, (key, value) => {
          // Handle circular references and non-serializable objects
          if (typeof value === 'function') return '[Function]';
          if (value instanceof Error) return value.message;
          if (value === undefined) return null;
          return value;
        }, 2);
      }
      return String(body);
    } catch (e) {
      // If not JSON or serialization fails, return as string
      return String(body);
    }
  }

  // Update consent display tab
  function updateConsentDisplay(request) {
    const consentAnalysisEl = document.getElementById('consentAnalysis');
    const consentWarningsEl = document.getElementById('consentWarnings');
    const scopeAnalysisEl = document.getElementById('scopeAnalysis');
    const applicationInfoEl = document.getElementById('applicationInfo');
    
    if (consentAnalysisEl) {
      consentAnalysisEl.innerHTML = request.metadata?.consentAnalysis ? 
        `<pre>${JSON.stringify(request.metadata.consentAnalysis, null, 2)}</pre>` :
        'No consent analysis data available';
    }
    
    if (consentWarningsEl) {
      consentWarningsEl.innerHTML = 'No consent warnings detected';
    }
    
    if (scopeAnalysisEl) {
      scopeAnalysisEl.innerHTML = 'No scope analysis available';
    }
    
    if (applicationInfoEl) {
      applicationInfoEl.innerHTML = 'No application information available';
    }
  }

  // Update security analysis tab
  function updateSecurityAnalysis(request) {
    const securityTab = document.getElementById('securityTab');
    if (!securityTab) return;

    const authAnalysis = request.metadata?.authAnalysis;

    if (!authAnalysis || !authAnalysis.issues) {
      securityTab.innerHTML = '<div class="no-analysis">No security analysis available for this request.</div>';
      return;
    }

    const issues = authAnalysis.issues || [];
    const riskScore = authAnalysis.riskScore || 0;
    const riskCategory = authAnalysis.riskCategory || 'secure';

    let issuesHTML = '<div class="security-summary risk-' + riskCategory + '">Risk Score: ' + riskScore + '/100</div>';

    if (issues.length > 0) {
      issuesHTML += '<div class="issues-list"><h4>Detected Issues:</h4>';
      issues.forEach(issue => {
        issuesHTML += `
          <div class="security-issue issue-${issue.severity.toLowerCase()}">
            <div class="issue-header">
              <span class="issue-severity">${issue.severity}</span>
              <span class="issue-type">${issue.type}</span>
            </div>
            <div class="issue-message">${issue.message}</div>
            ${issue.exploitation ? `<div class="issue-exploitation">${issue.exploitation}</div>` : ''}
          </div>
        `;
      });
      issuesHTML += '</div>';
    } else {
      issuesHTML += '<div class="no-issues">No security issues detected.</div>';
    }

    securityTab.innerHTML = issuesHTML;
  }

  // Update headers tab
  function updateHeadersTab(request) {
    const requestHeadersEl = document.getElementById('requestHeaders');
    const responseHeadersEl = document.getElementById('responseHeaders');

    if (requestHeadersEl) {
      if (request.requestHeaders && Object.keys(request.requestHeaders).length > 0) {
        requestHeadersEl.textContent = JSON.stringify(request.requestHeaders, null, 2);
      } else {
        requestHeadersEl.textContent = 'No request headers available';
      }
    }

    if (responseHeadersEl) {
      if (request.responseHeaders && Object.keys(request.responseHeaders).length > 0) {
        responseHeadersEl.textContent = JSON.stringify(request.responseHeaders, null, 2);
      } else {
        responseHeadersEl.textContent = 'No response headers available';
      }
    }
  }

  // Update body tab with enhanced status
  function updateBodyTabWithStatus(request) {
    const requestBodyEl = document.getElementById('requestBody');
    const responseBodyEl = document.getElementById('responseBody');
    const requestBodyStatus = document.getElementById('requestBodyStatus');
    const responseBodyStatus = document.getElementById('responseBodyStatus');

    // Analyze request body
    if (requestBodyEl && requestBodyStatus) {
      if (request.requestBody) {
        const formattedBody = formatBody(request.requestBody);
        requestBodyEl.textContent = formattedBody;
        requestBodyStatus.textContent = `${request.requestBody.length} bytes captured`;
        requestBodyStatus.className = 'body-status captured';
      } else {
        requestBodyEl.textContent = 'No request body';

        // Determine if this is expected or unexpected
        const method = request.method?.toUpperCase();
        const url = request.url || '';
        const isBodyExpected = shouldHaveRequestBody(method, url);

        if (isBodyExpected) {
          requestBodyStatus.textContent = 'Body expected but not captured';
          requestBodyStatus.className = 'body-status empty-unexpected';
        } else {
          requestBodyStatus.textContent = 'No body expected for this request';
          requestBodyStatus.className = 'body-status empty-expected';
        }
      }
    }

    // Analyze response body
    if (responseBodyEl && responseBodyStatus) {
      if (request.responseBody) {
        const formattedBody = formatBody(request.responseBody);
        responseBodyEl.textContent = formattedBody;
        responseBodyStatus.textContent = `${request.responseBody.length} bytes captured`;
        responseBodyStatus.className = 'body-status captured';
      } else {
        responseBodyEl.textContent = 'No response body';

        // Check if response body capture is enabled
        chrome.storage.local.get(['enableResponseCapture'], (result) => {
          const captureEnabled = result.enableResponseCapture !== false;

          if (!captureEnabled) {
            responseBodyStatus.textContent = 'Response capture disabled in settings';
            responseBodyStatus.className = 'body-status capture-disabled';
          } else {
            // Determine if response body is expected
            const statusCode = request.statusCode;
            const isBodyExpected = shouldHaveResponseBody(statusCode, request.url);

            if (isBodyExpected) {
              responseBodyStatus.textContent = 'Body expected but capture may have failed';
              responseBodyStatus.className = 'body-status capture-failed';
            } else {
              responseBodyStatus.textContent = 'No response body expected';
              responseBodyStatus.className = 'body-status empty-expected';
            }
          }
        });
      }
    }
  }

  // Helper function to determine if request should have a body
  function shouldHaveRequestBody(method, url) {
    // Methods that typically have bodies
    const bodyMethods = ['POST', 'PUT', 'PATCH'];
    if (!bodyMethods.includes(method)) return false;

    // Auth-specific patterns that should have bodies
    const authPatterns = [
      '/token',        // OAuth token exchange
      '/oauth/token',  // OAuth endpoints
      '/auth/token',   // Auth endpoints
      '/login',        // Login forms
      '/authenticate', // Auth forms
      '/saml',         // SAML assertions
      '/oidc',         // OIDC endpoints
    ];

    return authPatterns.some(pattern => url.includes(pattern));
  }

  // Helper function to determine if response should have a body
  function shouldHaveResponseBody(statusCode, url) {
    // Redirect responses typically don't have bodies
    if (statusCode >= 300 && statusCode < 400) return false;

    // 204 No Content explicitly has no body
    if (statusCode === 204) return false;

    // Auth endpoints that typically return data
    const authDataPatterns = [
      '/token',        // OAuth token responses
      '/userinfo',     // OIDC user info
      '/me',           // User profile endpoints
      '/.well-known',  // Discovery documents
      '/jwks',         // Key sets
    ];

    const hasAuthData = authDataPatterns.some(pattern => url.includes(pattern));

    // Success responses with auth data should have bodies
    return (statusCode >= 200 && statusCode < 300) && hasAuthData;
  }

  // Legacy body tab function for backwards compatibility
  function updateBodyTab(request) {

    if (requestBodyEl) {
      if (request.requestBody) {
        requestBodyEl.textContent = formatBody(request.requestBody);
      } else {
        requestBodyEl.textContent = 'No request body';
      }
    }

    if (responseBodyEl) {
      if (request.responseBody) {
        responseBodyEl.textContent = formatBody(request.responseBody);
      } else {
        responseBodyEl.textContent = 'No response body';
      }
    }
  }

  // Update DNS tab
  function updateDNSTab(request) {
    const hostnameEl = document.getElementById('dnsHostname');
    const homographEl = document.getElementById('dnsHomograph');
    const dgaEl = document.getElementById('dnsDGA');
    const countryEl = document.getElementById('dnsCountry');
    const orgEl = document.getElementById('dnsOrg');
    const ipAddressesEl = document.getElementById('ipAddresses');

    // Extract hostname from URL
    let hostname = 'N/A';
    try {
      const url = new URL(request.url);
      hostname = url.hostname;
    } catch (e) {
      console.error('Error parsing URL for DNS analysis:', e);
    }

    if (hostnameEl) {
      hostnameEl.textContent = hostname;
    }

    // Check for DNS intelligence data in metadata
    const dnsIntel = request.metadata?.dnsIntelligence;

    if (homographEl) {
      homographEl.textContent = dnsIntel?.homographAttack ? 'Detected' : 'None detected';
      homographEl.className = dnsIntel?.homographAttack ? 'warning' : 'safe';
    }

    if (dgaEl) {
      dgaEl.textContent = dnsIntel?.dgaPattern ? 'Suspicious pattern detected' : 'None detected';
      dgaEl.className = dnsIntel?.dgaPattern ? 'warning' : 'safe';
    }

    if (countryEl) {
      countryEl.textContent = dnsIntel?.country || 'Unknown';
    }

    if (orgEl) {
      orgEl.textContent = dnsIntel?.organization || 'Unknown';
    }

    // Display IP addresses if available
    if (ipAddressesEl) {
      if (dnsIntel?.ipAddresses && dnsIntel.ipAddresses.length > 0) {
        // P0-SIXTH-2 FIX: Add warning about DNS data trustworthiness
        ipAddressesEl.innerHTML = `
          <div class="security-warning" style="background: #fff3cd; border: 1px solid #ffc107; padding: 8px; margin-bottom: 10px; border-radius: 4px; font-size: 0.9em;">
            <strong>⚠️ Trust Warning:</strong> DNS and geolocation data is from third-party APIs (Cloudflare DNS, IPapi.co).
            If your network uses a proxy or has been compromised, this data may be inaccurate. Do not rely solely on
            this information for security decisions.
          </div>
          <h4>IP Addresses</h4>
          ${dnsIntel.ipAddresses.map(ip => `
            <div class="ip-address">
              <strong>${ip.address}</strong>
              ${ip.geolocation ? `<span class="location">${ip.geolocation.city}, ${ip.geolocation.country}</span>` : ''}
              ${ip.organization ? `<span class="org">${ip.organization}</span>` : ''}
            </div>
          `).join('')}
        `;
      } else {
        ipAddressesEl.innerHTML = '<p>No IP address information available</p>';
      }
    }
  }

  // Security alert functions
  function showSecurityAlert(message) {
    const alertsEl = document.getElementById('securityAlerts');
    const messageEl = document.getElementById('alertMessage');
    
    if (alertsEl && messageEl) {
      messageEl.textContent = message;
      alertsEl.style.display = 'block';
      
      // Auto-hide after 10 seconds
      setTimeout(() => {
        alertsEl.style.display = 'none';
      }, 10000);
    }
  }
  
  window.dismissSecurityAlert = function() {
    const alertsEl = document.getElementById('securityAlerts');
    if (alertsEl) {
      alertsEl.style.display = 'none';
    }
  };
  
  // Check for security issues in requests
  function checkSecurityIssues(requests) {
    requests.forEach(request => {
      // Check for authentication misconfigurations
      if (request.metadata?.backendSecurity?.riskScore > 70) {
        showSecurityAlert(`High risk backend detected: ${new URL(request.url).hostname}`);
      }
      
      // Check for suspicious domains
      if (request.metadata?.dnsIntelligence?.isHomograph) {
        showSecurityAlert(`Potential phishing domain detected: ${new URL(request.url).hostname}`);
      }
      
      // Check for insecure authentication flows
      if (request.authType === 'OAuth 2.0' && !request.url.includes('https://')) {
        showSecurityAlert(`Insecure OAuth flow detected (HTTP instead of HTTPS)`);
      }
    });
  }

  // Generate security summary for exports
  function generateSecuritySummary(sessions) {
    const summary = {
      totalSessions: sessions.length,
      totalRequests: 0,
      riskBreakdown: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        secure: 0
      },
      vulnerabilities: {},
      authTypes: {},
      domains: new Set(),
      criticalFindings: []
    };

    sessions.forEach(session => {
      if (session.requests && Array.isArray(session.requests)) {
        summary.totalRequests += session.requests.length;

        session.requests.forEach(req => {
          // Count domains
          try {
            summary.domains.add(new URL(req.url).hostname);
          } catch (e) {}

          // Count auth types
          const authType = req.authType || 'Unknown';
          summary.authTypes[authType] = (summary.authTypes[authType] || 0) + 1;

          // Analyze security findings
          const analysis = req.metadata?.authAnalysis;
          if (analysis) {
            const riskCategory = analysis.riskCategory || 'secure';
            summary.riskBreakdown[riskCategory] = (summary.riskBreakdown[riskCategory] || 0) + 1;

            // Count vulnerability types
            if (analysis.issues && Array.isArray(analysis.issues)) {
              analysis.issues.forEach(issue => {
                const key = `${issue.type}_${issue.severity}`;
                summary.vulnerabilities[key] = (summary.vulnerabilities[key] || 0) + 1;

                // Track critical findings
                if (issue.severity === 'CRITICAL' || issue.severity === 'HIGH') {
                  summary.criticalFindings.push({
                    url: req.url,
                    type: issue.type,
                    severity: issue.severity,
                    message: issue.message
                  });
                }
              });
            }
          }
        });
      }
    });

    // Convert domains set to count
    summary.uniqueDomains = summary.domains.size;
    delete summary.domains;

    return summary;
  }

  // Make loadRequests globally available for retry buttons
  window.loadRequests = loadRequests;

  // Load and assess extension security
  // Load and display port analysis
  async function loadPortAnalysis() {
    const portsContent = document.getElementById('portsContent');
    const portDistribution = document.getElementById('portDistribution');
    const authTypes = document.getElementById('authTypes');
    const portRisks = document.getElementById('portRisks');

    if (!portsContent) return;

    // Get all sessions from storage
    const { sessions = [] } = await chrome.storage.local.get(['sessions']);

    // Process port and auth data
    const portData = new Map();
    const authTypeData = new Map();
    const riskData = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    const ldapRequests = [];
    const defaultCredRequests = [];

    sessions.forEach(session => {
      if (session.metadata) {
        // Port analysis
        if (session.metadata.portAnalysis) {
          const port = session.metadata.portAnalysis.port;
          const service = session.metadata.portAnalysis.service;
          const risk = session.metadata.portAnalysis.risk;

          if (!portData.has(port)) {
            portData.set(port, {
              count: 0,
              service: service,
              risk: risk,
              urls: []
            });
          }
          portData.get(port).count++;
          portData.get(port).urls.push(session.url);

          if (risk) riskData[risk]++;
        }

        // Auth type analysis
        if (session.metadata.authTypeAnalysis) {
          const isAuth = session.metadata.authTypeAnalysis.isAuthentication;
          const isAuthz = session.metadata.authTypeAnalysis.isAuthorization;
          const mechanism = session.metadata.authTypeAnalysis.authMechanism;

          if (isAuth) {
            authTypeData.set('Authentication (AuthN)', (authTypeData.get('Authentication (AuthN)') || 0) + 1);
          }
          if (isAuthz) {
            authTypeData.set('Authorization (AuthZ)', (authTypeData.get('Authorization (AuthZ)') || 0) + 1);
          }
          if (mechanism) {
            authTypeData.set(mechanism, (authTypeData.get(mechanism) || 0) + 1);
          }
        }

        // LDAP detection
        if (session.metadata.ldapAnalysis && session.metadata.ldapAnalysis.length > 0) {
          ldapRequests.push(session);
        }

        // Default credentials detection
        if (session.metadata.credentialAnalysis && session.metadata.credentialAnalysis.length > 0) {
          defaultCredRequests.push(session);
        }
      }
    });

    // Render port distribution
    if (portDistribution) {
      const sortedPorts = Array.from(portData.entries())
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 10);

      portDistribution.innerHTML = sortedPorts.map(([port, data]) => `
        <div class="port-item ${data.risk ? data.risk.toLowerCase() : ''}">
          <span class="port-number">Port ${port}</span>
          <span class="port-service">${data.service}</span>
          <span class="port-count">${data.count} requests</span>
          <span class="port-risk risk-${data.risk ? data.risk.toLowerCase() : 'unknown'}">${data.risk || 'UNKNOWN'}</span>
        </div>
      `).join('');
    }

    // Render auth types
    if (authTypes) {
      authTypes.innerHTML = Array.from(authTypeData.entries())
        .sort((a, b) => b[1] - a[1])
        .map(([type, count]) => `
          <div class="auth-type-item">
            <span class="auth-type-name">${type}</span>
            <span class="auth-type-count">${count} requests</span>
          </div>
        `).join('');
    }

    // Render risk summary
    if (portRisks) {
      const totalRisks = Object.values(riskData).reduce((a, b) => a + b, 0);
      portRisks.innerHTML = `
        <div class="risk-summary">
          <div class="risk-item critical">
            <span class="risk-label">Critical</span>
            <span class="risk-count">${riskData.CRITICAL}</span>
          </div>
          <div class="risk-item high">
            <span class="risk-label">High</span>
            <span class="risk-count">${riskData.HIGH}</span>
          </div>
          <div class="risk-item medium">
            <span class="risk-label">Medium</span>
            <span class="risk-count">${riskData.MEDIUM}</span>
          </div>
          <div class="risk-item low">
            <span class="risk-label">Low</span>
            <span class="risk-count">${riskData.LOW}</span>
          </div>
        </div>
      `;
    }

    // Render detailed findings
    portsContent.innerHTML = `
      <div class="port-findings">
        ${defaultCredRequests.length > 0 ? `
          <div class="finding-section critical">
            <h3>⚠️ Default Credentials Detected</h3>
            <div class="finding-list">
              ${defaultCredRequests.map(req => `
                <div class="finding-item">
                  <div class="finding-url">${req.url}</div>
                  <div class="finding-details">
                    ${req.metadata.credentialAnalysis.map(cred => `
                      <div class="credential-finding">
                        <span class="severity-badge ${cred.severity.toLowerCase()}">${cred.severity}</span>
                        <span>${cred.message}</span>
                      </div>
                    `).join('')}
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
        ` : ''}

        ${ldapRequests.length > 0 ? `
          <div class="finding-section">
            <h3>🔐 LDAP Authentication Detected</h3>
            <div class="finding-list">
              ${ldapRequests.map(req => `
                <div class="finding-item">
                  <div class="finding-url">${req.url}</div>
                  <div class="finding-details">
                    ${req.metadata.ldapAnalysis.map(ldap => `
                      <div class="ldap-finding">
                        <span class="severity-badge ${ldap.severity.toLowerCase()}">${ldap.severity}</span>
                        <span>${ldap.message}</span>
                      </div>
                    `).join('')}
                  </div>
                </div>
              `).join('')}
            </div>
          </div>
        ` : ''}

        <div class="finding-section">
          <h3> Port Security Analysis</h3>
          <div class="port-details">
            ${Array.from(portData.entries())
              .filter(([port, data]) => data.risk === 'CRITICAL' || data.risk === 'HIGH')
              .map(([port, data]) => `
                <div class="port-detail-item ${data.risk.toLowerCase()}">
                  <h4>Port ${port} - ${data.service}</h4>
                  <p>Risk Level: ${data.risk}</p>
                  <p>Total Requests: ${data.count}</p>
                  <details>
                    <summary>Affected URLs</summary>
                    <ul>
                      ${data.urls.slice(0, 5).map(url => `<li>${url}</li>`).join('')}
                      ${data.urls.length > 5 ? `<li>... and ${data.urls.length - 5} more</li>` : ''}
                    </ul>
                  </details>
                </div>
              `).join('')}
          </div>
        </div>
      </div>
    `;
  }

  async function loadExtensionAssessments() {
    const extensionsContent = document.getElementById('extensionsContent');
    if (!extensionsContent) return;

    // Show loading state
    extensionsContent.innerHTML = '<div class="loading-state"><p>Loading extension security assessments...</p></div>';

    try {
      // Get all installed extensions
      const extensions = await chrome.management.getAll();

      // Filter out themes and this extension itself
      const installExtensions = extensions.filter(ext =>
        ext.type === 'extension' &&
        ext.id !== chrome.runtime.id
      );

      if (installExtensions.length === 0) {
        extensionsContent.innerHTML = '<div class="loading-state"><p>No other extensions found to assess.</p></div>';
        return;
      }

      // Assess each extension
      const assessments = await Promise.all(
        installExtensions.map(ext => assessExtensionSecurity(ext))
      );

      // Sort by risk level (critical, high, medium, low)
      const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      assessments.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel]);

      // Render assessments
      renderExtensionAssessments(assessments);

    } catch (error) {
      console.error('Error loading extension assessments:', error);
      extensionsContent.innerHTML = `
        <div class="loading-state">
          <p>Error loading extensions: ${error.message}</p>
          <button onclick="loadExtensionAssessments()" class="refresh-btn">Retry</button>
        </div>
      `;
    }
  }

  // Assess security of a single extension
  async function assessExtensionSecurity(extension) {
    const assessment = {
      id: extension.id,
      name: extension.name,
      version: extension.version,
      enabled: extension.enabled,
      permissions: extension.permissions || [],
      hostPermissions: extension.hostPermissions || [],
      installType: extension.installType,
      updateUrl: extension.updateUrl,
      homepageUrl: extension.homepageUrl,
      findings: [],
      riskScore: 0,
      riskLevel: 'low'
    };

    // Check for dangerous permissions
    const dangerousPermissions = [
      'debugger', 'desktopCapture', 'management', 'nativeMessaging',
      'proxy', 'system.cpu', 'system.memory', 'system.storage'
    ];

    const sensitivePermissions = [
      'cookies', 'history', 'bookmarks', 'tabs', 'activeTab',
      'webRequest', 'webRequestBlocking', 'storage', 'unlimitedStorage'
    ];

    // Analyze permissions
    assessment.permissions.forEach(permission => {
      if (dangerousPermissions.includes(permission)) {
        assessment.findings.push({
          type: 'DANGEROUS_PERMISSION',
          severity: 'high',
          message: `Has dangerous permission: ${permission}`
        });
        assessment.riskScore += 30;
      } else if (sensitivePermissions.includes(permission)) {
        assessment.findings.push({
          type: 'SENSITIVE_PERMISSION',
          severity: 'medium',
          message: `Has sensitive permission: ${permission}`
        });
        assessment.riskScore += 10;
      }
    });

    // Check host permissions
    if (assessment.hostPermissions.includes('<all_urls>') ||
        assessment.hostPermissions.includes('*://*/*')) {
      assessment.findings.push({
        type: 'BROAD_HOST_ACCESS',
        severity: 'high',
        message: 'Has access to all websites'
      });
      assessment.riskScore += 25;
    }

    // Check install type
    if (assessment.installType === 'development') {
      assessment.findings.push({
        type: 'DEVELOPMENT_EXTENSION',
        severity: 'medium',
        message: 'Development extension (unpacked)'
      });
      assessment.riskScore += 15;
    } else if (assessment.installType === 'sideload') {
      assessment.findings.push({
        type: 'SIDELOADED_EXTENSION',
        severity: 'high',
        message: 'Sideloaded extension (not from Chrome Web Store)'
      });
      assessment.riskScore += 35;
    }

    // Check for suspicious update URLs
    if (assessment.updateUrl && !assessment.updateUrl.includes('chrome.google.com')) {
      assessment.findings.push({
        type: 'EXTERNAL_UPDATE_URL',
        severity: 'medium',
        message: 'Updates from external source'
      });
      assessment.riskScore += 20;
    }

    // Determine risk level
    if (assessment.riskScore >= 70) {
      assessment.riskLevel = 'critical';
    } else if (assessment.riskScore >= 50) {
      assessment.riskLevel = 'high';
    } else if (assessment.riskScore >= 20) {
      assessment.riskLevel = 'medium';
    } else {
      assessment.riskLevel = 'low';
    }

    return assessment;
  }

  // Render extension assessments in the UI
  function renderExtensionAssessments(assessments) {
    const extensionsContent = document.getElementById('extensionsContent');
    if (!extensionsContent) return;

    if (assessments.length === 0) {
      extensionsContent.innerHTML = '<div class="loading-state"><p>No extensions to assess.</p></div>';
      return;
    }

    const extensionsHtml = assessments.map(assessment => `
      <div class="extension-item" data-extension-id="${assessment.id}">
        <div class="extension-header">
          <div class="extension-icon">🧩</div>
          <div class="extension-info">
            <div class="extension-name">${DOMSecurity.sanitizeHTML(assessment.name)}</div>
            <div class="extension-id">${DOMSecurity.sanitizeHTML(assessment.id)}</div>
          </div>
          <div class="extension-risk-badge ${assessment.riskLevel}">
            ${assessment.riskLevel} Risk
          </div>
        </div>

        <div class="extension-details">
          <div class="extension-permissions">
            <h4>Permissions (${assessment.permissions.length + assessment.hostPermissions.length})</h4>
            <div class="permission-list">
              ${assessment.permissions.map(perm => {
                const dangerous = ['debugger', 'desktopCapture', 'management', 'nativeMessaging', 'proxy'].includes(perm);
                const sensitive = ['cookies', 'history', 'bookmarks', 'tabs', 'webRequest'].includes(perm);
                const className = dangerous ? 'dangerous' : sensitive ? 'sensitive' : 'normal';
                return `<span class="permission-tag ${className}">${DOMSecurity.sanitizeHTML(perm)}</span>`;
              }).join('')}
              ${assessment.hostPermissions.map(host =>
                `<span class="permission-tag ${host.includes('*') ? 'dangerous' : 'normal'}">${DOMSecurity.sanitizeHTML(host)}</span>`
              ).join('')}
            </div>
          </div>

          ${assessment.findings.length > 0 ? `
            <div class="extension-findings">
              <h4>Security Findings (${assessment.findings.length})</h4>
              ${assessment.findings.map(finding => `
                <div class="finding-item ${finding.severity}">
                  <strong>${finding.type.replace(/_/g, ' ')}</strong>: ${DOMSecurity.sanitizeHTML(finding.message)}
                </div>
              `).join('')}
            </div>
          ` : ''}

          <div class="extension-status">
            <div class="status-indicator ${assessment.enabled ? 'enabled' : 'disabled'}"></div>
            <span>${assessment.enabled ? 'Enabled' : 'Disabled'}</span>
            <span class="extension-version">v${DOMSecurity.sanitizeHTML(assessment.version)}</span>
            <span class="extension-install-type">${DOMSecurity.sanitizeHTML(assessment.installType)}</span>
          </div>

          <div class="extension-actions">
            <button class="action-btn" onclick="chrome.management.setEnabled('${assessment.id}', ${!assessment.enabled})">
              ${assessment.enabled ? 'Disable' : 'Enable'}
            </button>
            <button class="action-btn" onclick="chrome.management.uninstall('${assessment.id}')">
              Uninstall
            </button>
          </div>
        </div>
      </div>
    `).join('');

    extensionsContent.innerHTML = extensionsHtml;
  }

  // Make functions globally available
  window.loadExtensionAssessments = loadExtensionAssessments;
});

// Populate security overview section
function populateSecurityOverview(request) {
  const securityOverview = document.getElementById('securityOverview');
  const scoreValue = document.getElementById('scoreValue');
  const riskCategory = document.getElementById('overviewRiskCategory');
  const securitySummary = document.getElementById('overviewSecuritySummary');
  const riskScore = document.getElementById('overviewRiskScore');

  if (!securityOverview) return;

  const authAnalysis = request.metadata?.authAnalysis;

  if (authAnalysis && (authAnalysis.riskScore || authAnalysis.issues?.length > 0)) {
    // Show the security overview section
    securityOverview.style.display = 'block';

    // Set risk score
    const score = authAnalysis.riskScore || 0;
    const category = authAnalysis.riskCategory || 'secure';

    if (scoreValue) scoreValue.textContent = score;
    if (riskCategory) {
      riskCategory.textContent = category.charAt(0).toUpperCase() + category.slice(1);
      riskCategory.className = `risk-category ${category}`;
    }
    if (riskScore) {
      riskScore.className = `risk-score ${category}`;
    }

    // Build security summary
    const issues = authAnalysis.issues || [];
    if (securitySummary) {
      if (issues.length > 0) {
        const criticalCount = issues.filter(i => i.severity === 'CRITICAL').length;
        const highCount = issues.filter(i => i.severity === 'HIGH').length;
        const mediumCount = issues.filter(i => i.severity === 'MEDIUM').length;
        const lowCount = issues.filter(i => i.severity === 'LOW').length;

        let summaryText = '';
        if (criticalCount > 0) summaryText += `<span class="issue-count critical">${criticalCount} Critical</span>`;
        if (highCount > 0) summaryText += `<span class="issue-count high">${highCount} High</span>`;
        if (mediumCount > 0) summaryText += `<span class="issue-count medium">${mediumCount} Medium</span>`;
        if (lowCount > 0) summaryText += `<span class="issue-count low">${lowCount} Low</span>`;

        if (summaryText) {
          summaryText = `Security issues found: ${summaryText}`;
        } else {
          summaryText = 'No specific security issues detected';
        }

        securitySummary.innerHTML = summaryText;
      } else {
        securitySummary.textContent = 'No security issues detected in this authentication request';
      }
    }
  } else {
    // Hide the security overview section if no security data
    securityOverview.style.display = 'none';
  }
}

// Populate cookie overview section
function populateCookieOverview(request) {
  const cookieOverview = document.getElementById('cookieOverview');
  const cookieSummary = document.getElementById('cookieSummary');
  const cookieDetails = document.getElementById('cookieDetails');

  if (!cookieOverview) return;

  // Extract cookies from request and response headers
  const cookies = new Map();

  // Parse cookies from request headers (Cookie header)
  const requestHeaders = request.requestHeaders || [];
  requestHeaders.forEach(header => {
    if (header.name.toLowerCase() === 'cookie') {
      const cookiesParsed = parseCookieHeader(header.value);
      cookiesParsed.forEach((value, name) => {
        cookies.set(name, { name, value, source: 'request' });
      });
    }
  });

  // Parse cookies from response headers (Set-Cookie headers)
  const responseHeaders = request.responseHeaders || [];
  responseHeaders.forEach(header => {
    if (header.name.toLowerCase() === 'set-cookie') {
      const cookie = parseSetCookieHeader(header.value);
      if (cookie) {
        cookies.set(cookie.name, { ...cookie, source: 'response' });
      }
    }
  });

  if (cookies.size > 0) {
    cookieOverview.style.display = 'block';

    // Create summary
    const requestCookies = Array.from(cookies.values()).filter(c => c.source === 'request').length;
    const responseCookies = Array.from(cookies.values()).filter(c => c.source === 'response').length;

    let summaryText = `${cookies.size} cookie(s) found`;
    if (requestCookies > 0 && responseCookies > 0) {
      summaryText += ` (${requestCookies} sent, ${responseCookies} set)`;
    } else if (requestCookies > 0) {
      summaryText += ` (${requestCookies} sent to server)`;
    } else if (responseCookies > 0) {
      summaryText += ` (${responseCookies} set by server)`;
    }

    if (cookieSummary) {
      cookieSummary.textContent = summaryText;
    }

    // Create detailed cookie display
    if (cookieDetails) {
      DOMSecurity.replaceChildren(cookieDetails, ...Array.from(cookies.values()).map(cookie => {
        const cookieItem = DOMSecurity.createSafeElement('div', '', { className: 'cookie-item' });

        // Cookie name and value
        const nameSpan = DOMSecurity.createSafeElement('span', cookie.name, { className: 'cookie-name' });
        const valueSpan = DOMSecurity.createSafeElement('span',
          cookie.value.length > 50 ? cookie.value.substring(0, 50) + '...' : cookie.value,
          { className: 'cookie-value', title: cookie.value }
        );

        cookieItem.appendChild(nameSpan);
        cookieItem.appendChild(DOMSecurity.createSafeElement('span', ': '));
        cookieItem.appendChild(valueSpan);

        // Security flags for Set-Cookie headers
        if (cookie.source === 'response') {
          const flagsDiv = DOMSecurity.createSafeElement('div', '', { className: 'cookie-flags' });

          if (cookie.secure) {
            flagsDiv.appendChild(DOMSecurity.createSafeElement('span', 'Secure', { className: 'cookie-flag secure' }));
          } else {
            flagsDiv.appendChild(DOMSecurity.createSafeElement('span', 'Not Secure', { className: 'cookie-flag missing' }));
          }

          if (cookie.httpOnly) {
            flagsDiv.appendChild(DOMSecurity.createSafeElement('span', 'HttpOnly', { className: 'cookie-flag httponly' }));
          } else {
            flagsDiv.appendChild(DOMSecurity.createSafeElement('span', 'No HttpOnly', { className: 'cookie-flag missing' }));
          }

          if (cookie.sameSite) {
            flagsDiv.appendChild(DOMSecurity.createSafeElement('span', `SameSite=${cookie.sameSite}`, { className: 'cookie-flag samesite' }));
          } else {
            flagsDiv.appendChild(DOMSecurity.createSafeElement('span', 'No SameSite', { className: 'cookie-flag missing' }));
          }

          cookieItem.appendChild(flagsDiv);
        }

        return cookieItem;
      }));
    }
  } else {
    cookieOverview.style.display = 'none';
  }
}

// Helper function to parse Cookie header value
function parseCookieHeader(cookieString) {
  const cookies = new Map();
  if (!cookieString) return cookies;

  cookieString.split(';').forEach(cookie => {
    const [name, value] = cookie.trim().split('=');
    if (name && value) {
      cookies.set(name.trim(), decodeURIComponent(value.trim()));
    }
  });

  return cookies;
}

// Helper function to parse Set-Cookie header value
function parseSetCookieHeader(setCookieString) {
  if (!setCookieString) return null;

  const parts = setCookieString.split(';').map(part => part.trim());
  const [name, value] = parts[0].split('=');

  if (!name || value === undefined) return null;

  const cookie = {
    name: name.trim(),
    value: value ? decodeURIComponent(value.trim()) : '',
    secure: false,
    httpOnly: false,
    sameSite: null
  };

  // Parse attributes
  parts.slice(1).forEach(part => {
    const [attr, attrValue] = part.split('=');
    const attrName = attr.toLowerCase();

    switch (attrName) {
      case 'secure':
        cookie.secure = true;
        break;
      case 'httponly':
        cookie.httpOnly = true;
        break;
      case 'samesite':
        cookie.sameSite = attrValue || 'true';
        break;
    }
  });

  return cookie;
}

// Populate authentication security overview section
function populateAuthSecurityOverview(request) {
  const authSecurityOverview = document.getElementById('authSecurityOverview');
  const authSecurityContent = document.getElementById('authSecurityContent');

  if (!authSecurityOverview || !authSecurityContent) return;

  const authAnalysis = request.metadata?.authAnalysis;
  if (!authAnalysis || !authAnalysis.issues) {
    authSecurityOverview.style.display = 'none';
    return;
  }

  // Filter for authentication security issues
  const authSecurityIssues = authAnalysis.issues.filter(issue =>
    ['password_security', 'mfa_security', 'passkey_opportunity', 'phishing_protection', 'flow_security'].includes(issue.category)
  );

  if (authSecurityIssues.length === 0) {
    authSecurityOverview.style.display = 'none';
    return;
  }

  authSecurityOverview.style.display = 'block';

  // Create recommendations HTML
  const recommendationsHtml = authSecurityIssues.map(issue => {
    const icons = {
      'VERY_WEAK_PASSWORD': '⚠️',
      'WEAK_PASSWORD': '⚠️',
      'POOR_PASSWORD': '⚠️',
      'COMMON_PASSWORD': '🚨',
      'WEAK_PASSWORD_PATTERN': '⚠️',
      'MISSING_MFA_HIGH_RISK': '',
      'MISSING_MFA': '',
      'WEAK_MFA_METHOD': '',
      'PASSKEY_OPPORTUNITY': '',
      'PHISHING_RISK_NO_PASSKEY': '',
      'PASSWORD_IN_URL': '🚨',
      'UNENCRYPTED_AUTH': '🚨'
    };

    const icon = icons[issue.type] || '';
    const severity = (issue.severity || 'low').toLowerCase();

    let detailsHtml = '';
    if (issue.details) {
      if (issue.details.recommendations && Array.isArray(issue.details.recommendations)) {
        detailsHtml += `
          <div class="auth-recommendation-details">
            <strong>Recommendations:</strong>
            <ul class="auth-recommendation-list">
              ${issue.details.recommendations.map(rec => `<li>${DOMSecurity.sanitizeHTML(rec)}</li>`).join('')}
            </ul>
          </div>
        `;
      }

      if (issue.details.benefits && Array.isArray(issue.details.benefits)) {
        detailsHtml += `
          <div class="auth-recommendation-details">
            <strong>Benefits:</strong>
            <ul class="auth-recommendation-list">
              ${issue.details.benefits.map(benefit => `<li>${DOMSecurity.sanitizeHTML(benefit)}</li>`).join('')}
            </ul>
          </div>
        `;
      }

      if (issue.details.mfaOptions && Array.isArray(issue.details.mfaOptions)) {
        detailsHtml += `
          <div class="auth-recommendation-details">
            <strong>MFA Options:</strong>
            <ul class="auth-recommendation-list">
              ${issue.details.mfaOptions.map(option => `<li>${DOMSecurity.sanitizeHTML(option)}</li>`).join('')}
            </ul>
          </div>
        `;
      }

      if (issue.details.howToEnable) {
        detailsHtml += `
          <div class="auth-recommendation-details">
            <strong>How to Enable:</strong> ${DOMSecurity.sanitizeHTML(issue.details.howToEnable)}
          </div>
        `;
      }

      if (issue.details.entropy !== undefined) {
        detailsHtml += `
          <div class="auth-recommendation-details">
            <strong>Password Entropy:</strong> ${Math.round(issue.details.entropy)} bits
            ${issue.details.length ? `(${issue.details.length} characters)` : ''}
          </div>
        `;
      }
    }

    // Determine special CSS classes
    let extraClasses = '';
    if (issue.category === 'passkey_opportunity') extraClasses = 'passkey-promotion';
    if (issue.category === 'mfa_security') extraClasses = 'mfa-promotion';
    if (issue.category === 'password_security' && severity === 'critical') extraClasses = 'password-warning';

    return `
      <div class="auth-recommendation ${severity} ${extraClasses}">
        <div class="auth-recommendation-header">
          <span class="auth-recommendation-icon">${icon}</span>
          <span class="auth-recommendation-title">${issue.type.replace(/_/g, ' ')}</span>
        </div>
        <div class="auth-recommendation-message">${DOMSecurity.sanitizeHTML(issue.message)}</div>
        ${detailsHtml}
      </div>
    `;
  }).join('');

  authSecurityContent.innerHTML = recommendationsHtml;
}

// Setup copy button functionality
function setupCopyButtons() {
  // URL copy button
  const copyUrlBtn = document.getElementById("copyUrl");
  if (copyUrlBtn) {
    copyUrlBtn.addEventListener("click", () => {
      const urlText = document.getElementById("detailUrl")?.textContent;
      if (urlText && urlText !== "Click a request to see details") {
        navigator.clipboard.writeText(urlText).then(() => {
          copyUrlBtn.textContent = "✓";
          setTimeout(() => {
            copyUrlBtn.textContent = "📋";
          }, 1000);
        }).catch(err => {
          console.error("Failed to copy URL:", err);
        });
      }
    });
  }

  // Server IP copy button
  const copyServerIPBtn = document.getElementById("copyServerIP");
  if (copyServerIPBtn) {
    copyServerIPBtn.addEventListener("click", () => {
      const ipText = document.getElementById("detailServerIP")?.textContent;
      if (ipText && ipText !== "Resolving..." && ipText !== "Not resolved") {
        navigator.clipboard.writeText(ipText).then(() => {
          copyServerIPBtn.textContent = "✓";
          setTimeout(() => {
            copyServerIPBtn.textContent = "📋";
          }, 1000);
        }).catch(err => {
          console.error("Failed to copy IP:", err);
        });
      }
    });
  }
}

// ==================== SITE SAFETY DASHBOARD ====================
// Modern dashboard for all-in-one deception/design detection

class HeraDashboard {
  constructor() {
    this.dashboardPanel = document.getElementById('dashboardPanel');
    this.dashboardContent = document.getElementById('dashboardContent');
    this.triggerAnalysisBtn = document.getElementById('triggerAnalysisBtn');

    this.setupEventListeners();
  }

  setupEventListeners() {
    // Trigger analysis button
    if (this.triggerAnalysisBtn) {
      this.triggerAnalysisBtn.addEventListener('click', () => {
        this.triggerManualAnalysis();
      });
    }
  }

  async loadDashboard() {
    try {
      // Show loading state
      this.showLoadingState();

      // Request analysis from background script
      const response = await chrome.runtime.sendMessage({ type: 'GET_SITE_ANALYSIS' });

      if (response && response.success && response.analysis) {
        this.renderDashboard(response.analysis);
      } else {
        this.showEmptyState();
      }
    } catch (error) {
      console.error('Failed to load dashboard:', error);
      this.showErrorState(error.message);
    }
  }

  async triggerManualAnalysis() {
    try {
      this.showLoadingState('Analyzing current page...');

      const response = await chrome.runtime.sendMessage({ type: 'TRIGGER_ANALYSIS' });

      if (response && response.success && response.score) {
        // Reload dashboard with new results
        setTimeout(() => this.loadDashboard(), 500);
      } else {
        this.showErrorState('Analysis failed. Please try again.');
      }
    } catch (error) {
      console.error('Manual analysis failed:', error);
      this.showErrorState(error.message);
    }
  }

  renderDashboard(analysis) {
    const { url, findings, score, timestamp } = analysis;

    // Clear content
    DOMSecurity.replaceChildren(this.dashboardContent);

    // Create dashboard structure
    const container = document.createElement('div');
    container.className = 'hera-dashboard';

    // 1. Score Card
    const scoreCard = this.createScoreCard(score);
    container.appendChild(scoreCard);

    // 2. Category Breakdown
    const categoryBreakdown = this.createCategoryBreakdown(score);
    container.appendChild(categoryBreakdown);

    // 3. Findings List
    const findingsList = this.createFindingsList(findings, score);
    container.appendChild(findingsList);

    // 4. Site Info
    const siteInfo = this.createSiteInfo(url, timestamp);
    container.appendChild(siteInfo);

    this.dashboardContent.appendChild(container);
  }

  createScoreCard(score) {
    const card = document.createElement('div');
    card.className = 'dashboard-score-card';

    // Grade display
    const gradeDisplay = document.createElement('div');
    gradeDisplay.className = `dashboard-grade grade-${score.grade.charAt(0).toLowerCase()}`;

    const gradeValue = document.createElement('div');
    gradeValue.className = 'grade-value';
    gradeValue.textContent = score.grade;

    const gradeLabel = document.createElement('div');
    gradeLabel.className = 'grade-label';
    gradeLabel.textContent = `${Math.round(score.overallScore)}/100`;

    gradeDisplay.appendChild(gradeValue);
    gradeDisplay.appendChild(gradeLabel);

    // Risk level badge
    const riskBadge = document.createElement('div');
    riskBadge.className = `dashboard-risk-badge risk-${score.riskLevel}`;
    riskBadge.textContent = score.riskLevel.toUpperCase();

    // Summary text
    const summary = document.createElement('p');
    summary.className = 'dashboard-summary';
    summary.textContent = score.summary;

    // Stats
    const stats = document.createElement('div');
    stats.className = 'dashboard-stats';

    const statItems = [
      { label: 'Total Issues', value: score.totalFindings, className: 'total' },
      { label: 'Critical', value: score.criticalIssues, className: 'critical' },
      { label: 'High', value: score.highIssues, className: 'high' },
      { label: 'Medium', value: score.mediumIssues, className: 'medium' },
      { label: 'Low', value: score.lowIssues, className: 'low' }
    ];

    statItems.forEach(item => {
      const statItem = document.createElement('div');
      statItem.className = `stat-item ${item.className}`;

      const statValue = document.createElement('div');
      statValue.className = 'stat-value';
      statValue.textContent = item.value;

      const statLabel = document.createElement('div');
      statLabel.className = 'stat-label';
      statLabel.textContent = item.label;

      statItem.appendChild(statValue);
      statItem.appendChild(statLabel);
      stats.appendChild(statItem);
    });

    card.appendChild(gradeDisplay);
    card.appendChild(riskBadge);
    card.appendChild(summary);
    card.appendChild(stats);

    return card;
  }

  createCategoryBreakdown(score) {
    const section = document.createElement('div');
    section.className = 'dashboard-section';

    const title = document.createElement('h3');
    title.textContent = 'Category Breakdown';
    section.appendChild(title);

    const categories = document.createElement('div');
    categories.className = 'dashboard-categories';

    // Sort categories by finding count
    const sortedCategories = Object.entries(score.categoryScores)
      .sort((a, b) => b[1].findingCount - a[1].findingCount);

    for (const [name, data] of sortedCategories) {
      const categoryCard = document.createElement('div');
      categoryCard.className = 'category-card';

      const categoryHeader = document.createElement('div');
      categoryHeader.className = 'category-header';

      const categoryName = document.createElement('div');
      categoryName.className = 'category-name';
      categoryName.textContent = this.formatCategoryName(name);

      const categoryScore = document.createElement('div');
      categoryScore.className = 'category-score';
      categoryScore.textContent = `${Math.round(data.score)}/100`;

      categoryHeader.appendChild(categoryName);
      categoryHeader.appendChild(categoryScore);

      const categoryBar = document.createElement('div');
      categoryBar.className = 'category-bar';

      const categoryFill = document.createElement('div');
      categoryFill.className = 'category-fill';
      categoryFill.style.width = `${data.score}%`;
      categoryFill.style.backgroundColor = this.getScoreColor(data.score);

      categoryBar.appendChild(categoryFill);

      const categoryFindings = document.createElement('div');
      categoryFindings.className = 'category-findings';
      categoryFindings.textContent = `${data.findingCount} issue${data.findingCount !== 1 ? 's' : ''}`;

      categoryCard.appendChild(categoryHeader);
      categoryCard.appendChild(categoryBar);
      categoryCard.appendChild(categoryFindings);

      categories.appendChild(categoryCard);
    }

    section.appendChild(categories);
    return section;
  }

  createFindingsList(findings, score) {
    const section = document.createElement('div');
    section.className = 'dashboard-section';

    const header = document.createElement('div');
    header.className = 'findings-section-header';

    const title = document.createElement('h3');
    title.textContent = 'Top Issues';

    header.appendChild(title);
    section.appendChild(header);

    if (findings.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'empty-findings';
      empty.textContent = 'No issues detected. This site looks great!';
      section.appendChild(empty);
      return section;
    }

    // Show top recommendations first
    if (score.recommendations && score.recommendations.length > 0) {
      const recommendations = document.createElement('div');
      recommendations.className = 'dashboard-recommendations';

      for (const rec of score.recommendations.slice(0, 3)) {
        const recCard = document.createElement('div');
        recCard.className = `recommendation-card priority-${rec.priority}`;

        const recTitle = document.createElement('div');
        recTitle.className = 'recommendation-title';
        recTitle.textContent = rec.title;

        const recDesc = document.createElement('div');
        recDesc.className = 'recommendation-description';
        recDesc.textContent = rec.description;

        const recAction = document.createElement('div');
        recAction.className = 'recommendation-action';
        recAction.textContent = `Action: ${rec.action}`;

        recCard.appendChild(recTitle);
        recCard.appendChild(recDesc);
        recCard.appendChild(recAction);

        recommendations.appendChild(recCard);
      }

      section.appendChild(recommendations);
    }

    // Show top findings
    const findingsContainer = document.createElement('div');
    findingsContainer.className = 'dashboard-findings';

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sortedFindings = [...findings].sort((a, b) => {
      return severityOrder[a.severity] - severityOrder[b.severity];
    });

    // Show top 10 findings
    for (const finding of sortedFindings.slice(0, 10)) {
      const findingCard = document.createElement('div');
      findingCard.className = `finding-card severity-${finding.severity}`;

      const findingHeader = document.createElement('div');
      findingHeader.className = 'finding-header';

      const findingSeverity = document.createElement('span');
      findingSeverity.className = `finding-severity ${finding.severity}`;
      findingSeverity.textContent = finding.severity.toUpperCase();

      const findingTitle = document.createElement('span');
      findingTitle.className = 'finding-title';
      findingTitle.textContent = finding.title;

      findingHeader.appendChild(findingSeverity);
      findingHeader.appendChild(findingTitle);

      const findingDesc = document.createElement('div');
      findingDesc.className = 'finding-description';
      findingDesc.textContent = finding.description;

      const findingRec = document.createElement('div');
      findingRec.className = 'finding-recommendation';
      findingRec.textContent = `Recommendation: ${finding.recommendation}`;

      findingCard.appendChild(findingHeader);
      findingCard.appendChild(findingDesc);
      findingCard.appendChild(findingRec);

      // Show reasoning (WHY we flagged this)
      if (finding.reasoning) {
        const reasoningSection = document.createElement('div');
        reasoningSection.className = 'finding-reasoning';
        reasoningSection.style.marginTop = '12px';
        reasoningSection.style.padding = '12px';
        reasoningSection.style.backgroundColor = '#fffbeb';
        reasoningSection.style.borderLeft = '4px solid #f59e0b';
        reasoningSection.style.borderRadius = '4px';

        const reasoningLabel = document.createElement('div');
        reasoningLabel.style.fontWeight = 'bold';
        reasoningLabel.style.color = '#92400e';
        reasoningLabel.style.marginBottom = '6px';
        reasoningLabel.textContent = '⚠️ Why we flagged this:';

        const reasoningText = document.createElement('div');
        reasoningText.style.color = '#78350f';
        reasoningText.style.fontSize = '13px';
        reasoningText.style.lineHeight = '1.6';
        reasoningText.textContent = finding.reasoning;

        reasoningSection.appendChild(reasoningLabel);
        reasoningSection.appendChild(reasoningText);
        findingCard.appendChild(reasoningSection);
      }

      // Expand/collapse for evidence (technical details)
      if (finding.evidence && Object.keys(finding.evidence).length > 0) {
        const evidenceToggle = document.createElement('button');
        evidenceToggle.className = 'evidence-toggle btn-primary';
        evidenceToggle.textContent = '🔍 View Evidence';
        evidenceToggle.style.marginTop = '10px';
        evidenceToggle.style.padding = '8px 16px';
        evidenceToggle.style.cursor = 'pointer';

        const evidenceContent = document.createElement('div');
        evidenceContent.className = 'evidence-content';
        evidenceContent.style.display = 'none';
        evidenceContent.style.marginTop = '10px';
        evidenceContent.style.padding = '10px';
        evidenceContent.style.backgroundColor = '#f5f5f5';
        evidenceContent.style.borderRadius = '4px';
        evidenceContent.style.border = '1px solid #ddd';

        const evidencePre = document.createElement('pre');
        evidencePre.textContent = JSON.stringify(finding.evidence, null, 2);
        evidencePre.style.margin = '0';
        evidencePre.style.fontSize = '12px';
        evidencePre.style.whiteSpace = 'pre-wrap';
        evidencePre.style.wordBreak = 'break-word';
        evidenceContent.appendChild(evidencePre);

        evidenceToggle.addEventListener('click', (e) => {
          e.stopPropagation();
          if (evidenceContent.style.display === 'none') {
            evidenceContent.style.display = 'block';
            evidenceToggle.textContent = '🔼 Hide Evidence';
          } else {
            evidenceContent.style.display = 'none';
            evidenceToggle.textContent = '🔍 View Evidence';
          }
        });

        findingCard.appendChild(evidenceToggle);
        findingCard.appendChild(evidenceContent);
      } else {
        // Debug: Log findings without evidence
        console.log('Hera: Finding without evidence:', finding.title, finding);
      }

      findingsContainer.appendChild(findingCard);
    }

    if (sortedFindings.length > 10) {
      const moreText = document.createElement('p');
      moreText.className = 'more-findings';
      moreText.textContent = `... and ${sortedFindings.length - 10} more issues`;
      findingsContainer.appendChild(moreText);
    }

    section.appendChild(findingsContainer);
    return section;
  }

  createSiteInfo(url, timestamp) {
    const section = document.createElement('div');
    section.className = 'dashboard-section dashboard-site-info';

    const title = document.createElement('h3');
    title.textContent = 'Analysis Details';
    section.appendChild(title);

    const info = document.createElement('div');
    info.className = 'site-info';

    const urlRow = document.createElement('div');
    urlRow.className = 'info-row';
    const urlLabel = document.createElement('span');
    urlLabel.className = 'info-label';
    urlLabel.textContent = 'URL:';
    const urlValue = document.createElement('span');
    urlValue.className = 'info-value';
    urlValue.textContent = url;
    urlRow.appendChild(urlLabel);
    urlRow.appendChild(urlValue);

    const timeRow = document.createElement('div');
    timeRow.className = 'info-row';
    const timeLabel = document.createElement('span');
    timeLabel.className = 'info-label';
    timeLabel.textContent = 'Analyzed:';
    const timeValue = document.createElement('span');
    timeValue.className = 'info-value';
    timeValue.textContent = new Date(timestamp).toLocaleString();
    timeRow.appendChild(timeLabel);
    timeRow.appendChild(timeValue);

    info.appendChild(urlRow);
    info.appendChild(timeRow);
    section.appendChild(info);

    return section;
  }

  showLoadingState(message = 'Loading site analysis...') {
    DOMSecurity.replaceChildren(this.dashboardContent);

    const loading = document.createElement('div');
    loading.className = 'loading-state';

    const loadingText = document.createElement('p');
    loadingText.textContent = message;

    loading.appendChild(loadingText);
    this.dashboardContent.appendChild(loading);
  }

  showEmptyState() {
    DOMSecurity.replaceChildren(this.dashboardContent);

    const empty = document.createElement('div');
    empty.className = 'empty-state';

    const emptyTitle = document.createElement('h3');
    emptyTitle.textContent = 'No Analysis Available';

    const emptyText = document.createElement('p');
    emptyText.textContent = 'Click "Analyze Current Page" to scan this site for security, privacy, and design issues.';

    empty.appendChild(emptyTitle);
    empty.appendChild(emptyText);
    this.dashboardContent.appendChild(empty);
  }

  showErrorState(message) {
    DOMSecurity.replaceChildren(this.dashboardContent);

    const error = document.createElement('div');
    error.className = 'error-state';

    const errorTitle = document.createElement('h3');
    errorTitle.textContent = 'Analysis Error';

    const errorText = document.createElement('p');
    errorText.textContent = message;

    error.appendChild(errorTitle);
    error.appendChild(errorText);
    this.dashboardContent.appendChild(error);
  }

  formatCategoryName(category) {
    return category
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  }

  getScoreColor(score) {
    if (score >= 90) return '#28a745';
    if (score >= 80) return '#17a2b8';
    if (score >= 70) return '#ffc107';
    if (score >= 60) return '#fd7e14';
    return '#dc3545';
  }
}

// Initialize dashboard
let heraDashboard;

document.addEventListener('DOMContentLoaded', () => {
  heraDashboard = new HeraDashboard();

  // Handle dashboard button click
  const dashboardBtn = document.getElementById('dashboardBtn');
  if (dashboardBtn) {
    dashboardBtn.addEventListener('click', () => {
      // Hide all panels
      document.querySelectorAll('.dashboard-panel, .requests-list, .findings-list, .ports-analysis, .extensions-list').forEach(panel => {
        panel.style.display = 'none';
      });

      // Show dashboard
      document.getElementById('dashboardPanel').style.display = 'block';

      // Update active button
      document.querySelectorAll('.controls button').forEach(btn => btn.classList.remove('active'));
      dashboardBtn.classList.add('active');

      // Load dashboard data
      heraDashboard.loadDashboard();
    });
  }

  // Auto-load dashboard on popup open
  if (dashboardBtn && dashboardBtn.classList.contains('active')) {
    heraDashboard.loadDashboard();
  }
});

