/**
 * Session Renderer
 * Renders authentication requests grouped by sessions and services
 */

import { DOMSecurity } from './dom-security.js';
import { TimeUtils } from './time-utils.js';

export class SessionRenderer {
  constructor() {
    this.requests = [];
    this.requestsList = null;
    this.vulnerabilitiesList = null; // Renamed from findingsList
    this.lastLoadTime = 0;
    this.LOAD_COOLDOWN = 1000; // 1 second
    this.allCollapsed = false;
  }

  /**
   * Initialize renderer
   */
  initialize() {
    this.requestsList = document.getElementById('requestsList');
    this.vulnerabilitiesList = document.getElementById('vulnerabilitiesList'); // Renamed from findingsList

    // Set up refresh button
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', () => {
        console.log('Manual refresh triggered');
        this.loadRequests();
      });
    }

    // Set up collapse all button
    const collapseAllBtn = document.getElementById('collapseAllBtn');
    if (collapseAllBtn) {
      collapseAllBtn.addEventListener('click', () => this.toggleCollapseAll());
    }

    // Auto-refresh on focus
    window.addEventListener('focus', () => {
      console.log('Popup gained focus - auto-refreshing data');
      this.loadRequests();
    });

    // Auto-refresh on visibility change
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        console.log('Popup became visible - auto-refreshing data');
        this.loadRequests();
      }
    });

    // Load initial data
    this.loadRequests();
  }

  /**
   * Load requests from background script
   */
  loadRequests() {
    const now = Date.now();
    if (now - this.lastLoadTime < this.LOAD_COOLDOWN) {
      console.log('Load requests rate limited');
      return;
    }
    this.lastLoadTime = now;

    console.log('Loading requests...');

    // Show loading indicator
    if (this.requestsList) {
      const loadingDiv = DOMSecurity.createSafeElement('div', 'Loading sessions...', { className: 'loading' });
      DOMSecurity.replaceChildren(this.requestsList, loadingDiv);
    }

    chrome.runtime.sendMessage({ action: 'getRequests' }, response => {
      console.log('Received response:', response);
      
      if (chrome.runtime.lastError) {
        console.error('Runtime error:', chrome.runtime.lastError);
        this.showError(`Error loading data: ${chrome.runtime.lastError.message}`);
        return;
      }

      if (!response) {
        console.warn('No response received from background script');
        this.showError('No response from background script');
        return;
      }

      this.requests = Array.isArray(response) ? response : [];
      console.log('Parsed requests:', this.requests.length, 'items');

      // Sort by timestamp (newest first)
      this.requests.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

      // Dispatch event to update global requests
      window.dispatchEvent(new CustomEvent('requestsUpdated', { detail: this.requests }));

      this.renderRequests();
      this.renderFindings();
    });
  }

  /**
   * Show error message
   */
  showError(message) {
    if (!this.requestsList) return;
    
    const errorDiv = DOMSecurity.createSafeElement('div', '', { className: 'error-state' });
    const errorMsg = DOMSecurity.createSafeElement('p', message);
    const retryBtn = DOMSecurity.createSafeElement('button', 'Retry');
    retryBtn.onclick = () => this.loadRequests();
    errorDiv.appendChild(errorMsg);
    errorDiv.appendChild(retryBtn);
    DOMSecurity.replaceChildren(this.requestsList, errorDiv);
  }

  /**
   * Render requests grouped by sessions
   */
  renderRequests() {
    if (this.requests.length === 0) {
      const emptyDiv = DOMSecurity.createSafeElement('div', '', { className: 'empty-state' });
      const msg1 = DOMSecurity.createSafeElement('p', 'No authentication requests captured yet.');
      const msg2 = DOMSecurity.createSafeElement('p', 'Navigate to a website that uses OAuth, OIDC, SAML, or SCIM.');
      emptyDiv.appendChild(msg1);
      emptyDiv.appendChild(msg2);
      DOMSecurity.replaceChildren(this.requestsList, emptyDiv);
      return;
    }

    // Group requests by service/session
    const sessionGroups = this.groupRequestsBySession();
    console.log('Session groups:', sessionGroups);
    
    this.requestsList.innerHTML = '';

    // Render each service group
    Object.entries(sessionGroups).forEach(([service, sessions]) => {
      this.renderServiceGroup(service, sessions);
    });
  }

  /**
   * Group requests by session
   */
  groupRequestsBySession() {
    const sessionGroups = {};
    
    this.requests.forEach(request => {
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

    return sessionGroups;
  }

  /**
   * Render a service group
   */
  renderServiceGroup(service, sessions) {
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

    this.requestsList.appendChild(serviceHeader);

    // Render each session within the service
    Object.entries(sessions).forEach(([sessionId, sessionData]) => {
      this.renderSession(sessionContainer, sessionData);
    });

    // Add the session container to the main list
    this.requestsList.appendChild(sessionContainer);
  }

  /**
   * Render a single session
   */
  renderSession(container, sessionData) {
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
    container.appendChild(sessionHeader);

    // Render requests in this session (newest first)
    sessionData.requests.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)).forEach(request => {
      this.renderRequest(container, request);
    });
  }

  /**
   * Render a single request
   */
  renderRequest(container, request) {
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
      // Dispatch custom event for request details
      window.dispatchEvent(new CustomEvent('showRequestDetails', { detail: request.id }));
    });

    container.appendChild(requestEl);
  }

  /**
   * Toggle collapse all sessions
   */
  toggleCollapseAll() {
    const serviceHeaders = document.querySelectorAll('.service-header.collapsible');
    const sessionContainers = document.querySelectorAll('.session-container');
    const collapseAllBtn = document.getElementById('collapseAllBtn');

    if (this.allCollapsed) {
      // Expand all
      sessionContainers.forEach(container => {
        container.style.display = 'block';
      });
      serviceHeaders.forEach(header => {
        const icon = header.querySelector('.collapse-icon');
        if (icon) icon.textContent = '▼';
        header.classList.remove('collapsed');
      });
      if (collapseAllBtn) collapseAllBtn.textContent = 'Collapse All';
      this.allCollapsed = false;
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
      if (collapseAllBtn) collapseAllBtn.textContent = 'Expand All';
      this.allCollapsed = true;
      console.log('📁 Collapsed all sessions');
    }
  }

  /**
   * Render security findings
   */
  renderFindings() {
    if (this.requests.length === 0) {
      const emptyDiv = DOMSecurity.createSafeElement('div', '', { className: 'empty-state' });
      const emptyMsg = DOMSecurity.createSafeElement('p', 'No security findings yet.');
      emptyDiv.appendChild(emptyMsg);
      DOMSecurity.replaceChildren(this.vulnerabilitiesList, emptyDiv);
      return;
    }

    const allIssues = this.aggregateIssues();
    const sortedIssues = Object.values(allIssues).sort((a, b) => {
      const severityOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
      return (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
    });

    if (sortedIssues.length === 0) {
      const emptyDiv = DOMSecurity.createSafeElement('div', '', { className: 'empty-state' });
      const emptyMsg = DOMSecurity.createSafeElement('p', 'No security issues detected.');
      emptyDiv.appendChild(emptyMsg);
      DOMSecurity.replaceChildren(this.vulnerabilitiesList, emptyDiv);
      return;
    }

    this.vulnerabilitiesList.innerHTML = '';
    sortedIssues.forEach(issue => {
      this.renderFinding(issue);
    });
  }

  /**
   * Aggregate issues from all requests
   */
  aggregateIssues() {
    const allIssues = {};
    
    this.requests.forEach(request => {
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
          const service = request.service || this.identifyService(domain);

          if (!allIssues[key].affectedDomains.has(domain)) {
            allIssues[key].affectedDomains.set(domain, {
              count: 0,
              service: service,
              priority: this.getServicePriority(service, domain)
            });
          }
          allIssues[key].affectedDomains.get(domain).count++;
        } catch (e) {
          // Invalid URL
        }
      });
    });

    return allIssues;
  }

  /**
   * Render a single finding
   */
  renderFinding(issue) {
    const findingEl = document.createElement('div');
    findingEl.className = `finding-item ${issue.severity.toLowerCase()}`;

    const findingHeader = DOMSecurity.createSafeElement('div', '', { className: 'finding-header' });
    const findingType = DOMSecurity.createSafeElement('span', issue.type, { className: 'finding-type' });
    const findingCount = DOMSecurity.createSafeElement('span', `${issue.count} found`, { className: 'finding-count' });

    // Get the most important affected domain
    const topDomain = this.getTopAffectedDomain(issue.affectedDomains);

    // Create affected service line
    const affectedService = DOMSecurity.createSafeElement('div', '', { className: 'affected-service' });
    if (topDomain) {
      const serviceIcon = this.getServiceIcon(topDomain.service);
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
    findingEl.appendChild(findingHeader);
    findingEl.appendChild(affectedService);
    findingEl.appendChild(findingDetails);

    // Make finding clickable
    findingEl.style.cursor = 'pointer';
    findingEl.addEventListener('click', () => {
      window.dispatchEvent(new CustomEvent('showRequestsForFinding', { detail: issue }));
    });

    this.vulnerabilitiesList.appendChild(findingEl);
  }

  /**
   * Identify service from domain
   */
  identifyService(domain) {
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

    // Check special TLDs
    if (domain.endsWith('.gov')) return 'Government';
    if (domain.endsWith('.edu')) return 'Educational';
    if (domain.endsWith('.mil')) return 'Military';
    if (domain.includes('bank') || domain.includes('credit')) return 'Banking';

    return null;
  }

  /**
   * Get service priority (higher = more important)
   */
  getServicePriority(service, domain) {
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

  /**
   * Get the most important affected domain
   */
  getTopAffectedDomain(affectedDomains) {
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

  /**
   * Get service icon/emoji
   */
  getServiceIcon(service) {
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
}
