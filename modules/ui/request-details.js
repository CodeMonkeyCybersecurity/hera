/**
 * Request Details Panel
 * Shows detailed information about selected authentication requests
 */

import { DOMSecurity } from './dom-security.js';
import { JWTSecurity } from './jwt-security.js';
import { TimeUtils } from './time-utils.js';
import { CookieParser } from './cookie-parser.js';

export class RequestDetails {
  constructor() {
    this.selectedRequest = null;
    this.requestDetails = null;
  }

  /**
   * Initialize request details panel
   */
  initialize() {
    this.requestDetails = document.getElementById('requestDetails');
    const closeDetailsBtn = document.getElementById('closeDetails');

    if (closeDetailsBtn) {
      closeDetailsBtn.addEventListener('click', () => this.hide());
    }

    // Listen for custom event from session renderer
    window.addEventListener('showRequestDetails', (e) => {
      this.show(e.detail);
    });

    // Tab switching
    const tabButtons = document.querySelectorAll('.tab-btn');
    tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        const tabName = btn.dataset.tab;
        this.switchTab(tabName);
      });
    });
  }

  /**
   * Show details for a specific request
   * @param {string} requestId - Request ID to show
   */
  show(requestId) {
    // Get requests from session renderer
    const requests = window.heraRequests || [];
    this.selectedRequest = requests.find(r => r.id === requestId);

    if (!this.selectedRequest) {
      console.error('Request not found:', requestId);
      return;
    }

    console.log('Showing details for request:', requestId);

    // Populate all sections
    this.populateOverview();
    this.populateSecurityOverview();
    this.populateCookieOverview();
    this.populateAuthSecurityOverview();
    this.populateDNSTab();
    this.populateHeadersTab();
    this.populateBodyTab();
    this.populateSecurityTab();
    this.populateTokenTab();
    this.setupCopyButtons();

    // Show the panel
    if (this.requestDetails) {
      this.requestDetails.style.display = 'flex';
      this.requestDetails.classList.add('show');
    }

    // Activate first tab
    this.switchTab('overview');
  }

  /**
   * Hide details panel
   */
  hide() {
    if (this.requestDetails) {
      this.requestDetails.style.display = 'none';
      this.requestDetails.classList.remove('show');
    }
  }

  /**
   * Switch between tabs
   */
  switchTab(tabName) {
    // Hide all tabs
    const tabs = document.querySelectorAll('.tab-content');
    tabs.forEach(tab => tab.classList.remove('active'));

    // Deactivate all buttons
    const buttons = document.querySelectorAll('.tab-btn');
    buttons.forEach(btn => btn.classList.remove('active'));

    // Show selected tab
    const selectedTab = document.getElementById(`${tabName}Tab`);
    if (selectedTab) {
      selectedTab.classList.add('active');
    }

    // Activate selected button
    const selectedBtn = document.querySelector(`[data-tab="${tabName}"]`);
    if (selectedBtn) {
      selectedBtn.classList.add('active');
    }
  }

  /**
   * Populate overview tab
   */
  populateOverview() {
    const req = this.selectedRequest;
    
    // Basic info
    this.setElementText('detailUrl', req.url);
    this.setElementText('detailMethod', req.method || 'GET');
    this.setElementText('detailStatus', req.statusCode || 'Pending');
    this.setElementText('detailType', req.authType || 'Unknown');

    // Time info
    const detailTime = document.getElementById('detailTime');
    if (detailTime) {
      const timeInfo = TimeUtils.formatTimeWithRelative(req.timestamp);
      detailTime.textContent = `${timeInfo.relative} (${timeInfo.full})`;
      detailTime.title = `Full timestamp: ${timeInfo.iso}`;
    }

    // Duration
    const timing = req.metadata?.timing;
    if (timing?.duration) {
      this.setElementText('detailDuration', TimeUtils.formatDuration(timing.duration));
    } else {
      this.setElementText('detailDuration', 'Unknown');
    }

    // Initiator
    this.setElementText('detailInitiator', req.initiator || 'Unknown');

    // IP and location
    const dnsIntel = req.metadata?.dnsIntelligence;
    if (dnsIntel?.ipAddresses?.ipv4Addresses?.length > 0) {
      this.setElementText('detailServerIP', dnsIntel.ipAddresses.ipv4Addresses[0]);
    } else {
      this.setElementText('detailServerIP', 'Not resolved');
    }

    const geoData = dnsIntel?.ipAddresses?.geoLocations?.[0];
    if (geoData) {
      const locationParts = [];
      if (geoData.city) locationParts.push(geoData.city);
      if (geoData.region && geoData.region !== geoData.city) locationParts.push(geoData.region);
      if (geoData.country) locationParts.push(geoData.country);
      const location = locationParts.length > 0 ? locationParts.join(', ') : 'Unknown location';
      const organization = geoData.organization || dnsIntel?.geoLocation?.organization;
      const fullLocation = organization ? `${location} (${organization})` : location;
      this.setElementText('detailLocation', fullLocation);
    } else {
      this.setElementText('detailLocation', 'Location unknown');
    }
  }

  /**
   * Populate security overview
   */
  populateSecurityOverview(request) {
    // Implementation from popup.js line 3586
    const securityOverview = document.getElementById('securityOverview');
    if (!securityOverview) return;

    const req = request || this.selectedRequest;
    const authAnalysis = req.metadata?.authAnalysis;
    
    if (!authAnalysis) {
      securityOverview.innerHTML = '<p>No security analysis available</p>';
      return;
    }

    const riskScore = authAnalysis.riskScore || 0;
    const riskCategory = authAnalysis.riskCategory || 'secure';
    const issues = authAnalysis.issues || [];

    securityOverview.innerHTML = '';
    
    const scoreDiv = DOMSecurity.createSafeElement('div', `Risk Score: ${riskScore}/100`, {
      className: `risk-score risk-${riskCategory}`
    });
    securityOverview.appendChild(scoreDiv);

    if (issues.length > 0) {
      const issuesList = DOMSecurity.createSafeElement('div', '', { className: 'issues-summary' });
      const title = DOMSecurity.createSafeElement('h4', `${issues.length} Issue(s) Found`);
      issuesList.appendChild(title);

      issues.slice(0, 5).forEach(issue => {
        const issueDiv = DOMSecurity.createSafeElement('div', '', {
          className: `issue-item ${issue.severity.toLowerCase()}`
        });
        const severitySpan = DOMSecurity.createSafeElement('span', issue.severity, { className: 'severity' });
        const typeSpan = DOMSecurity.createSafeElement('span', issue.type, { className: 'type' });
        issueDiv.appendChild(severitySpan);
        issueDiv.appendChild(typeSpan);
        issuesList.appendChild(issueDiv);
      });

      securityOverview.appendChild(issuesList);
    }
  }

  /**
   * Populate cookie overview
   */
  populateCookieOverview(request) {
    const cookieOverview = document.getElementById('cookieOverview');
    if (!cookieOverview) return;

    const req = request || this.selectedRequest;
    const requestHeaders = req.requestHeaders || [];
    const responseHeaders = req.responseHeaders || [];

    // Parse cookies
    const cookieHeader = requestHeaders.find(h => h.name.toLowerCase() === 'cookie');
    const setCookieHeaders = responseHeaders.filter(h => h.name.toLowerCase() === 'set-cookie');

    cookieOverview.innerHTML = '';

    if (cookieHeader || setCookieHeaders.length > 0) {
      const summary = DOMSecurity.createSafeElement('div', '', { className: 'cookie-summary' });
      
      if (cookieHeader) {
        const cookies = CookieParser.parseCookieHeader(cookieHeader.value);
        const countDiv = DOMSecurity.createSafeElement('p', `${cookies.size} cookie(s) sent`);
        summary.appendChild(countDiv);
      }

      if (setCookieHeaders.length > 0) {
        const countDiv = DOMSecurity.createSafeElement('p', `${setCookieHeaders.length} cookie(s) set`);
        summary.appendChild(countDiv);
      }

      cookieOverview.appendChild(summary);
    } else {
      cookieOverview.textContent = 'No cookies found';
    }
  }

  /**
   * Populate authentication security overview
   */
  populateAuthSecurityOverview(request) {
    const authSecurityOverview = document.getElementById('authSecurityOverview');
    if (!authSecurityOverview) return;

    const req = request || this.selectedRequest;
    const authAnalysis = req.metadata?.authAnalysis;

    if (!authAnalysis || !authAnalysis.issues) {
      authSecurityOverview.innerHTML = '<p>No authentication security issues detected</p>';
      return;
    }

    authSecurityOverview.innerHTML = '';
    
    const issues = authAnalysis.issues.filter(i => 
      i.type.includes('AUTH') || i.type.includes('PASSWORD') || i.type.includes('MFA')
    );

    if (issues.length > 0) {
      const issuesList = DOMSecurity.createSafeElement('div', '', { className: 'auth-issues' });
      issues.forEach(issue => {
        const issueDiv = DOMSecurity.createSafeElement('div', '', {
          className: `auth-issue ${issue.severity.toLowerCase()}`
        });
        const messageDiv = DOMSecurity.createSafeElement('div', issue.message, { className: 'message' });
        issueDiv.appendChild(messageDiv);
        issuesList.appendChild(issueDiv);
      });
      authSecurityOverview.appendChild(issuesList);
    } else {
      authSecurityOverview.textContent = 'No authentication-specific issues found';
    }
  }

  /**
   * Populate DNS tab
   */
  populateDNSTab() {
    const req = this.selectedRequest;
    const dnsIntel = req.metadata?.dnsIntelligence || {};

    this.setElementText('dnsHostname', dnsIntel.hostname || 'N/A');
    this.setElementText('dnsHomograph', dnsIntel.isHomograph ? 'Yes (Warning)' : 'No');
    this.setElementText('dnsDGA', dnsIntel.isDGA ? 'Yes (Warning)' : 'No');
    this.setElementText('dnsCountry', dnsIntel.geoLocation?.country || 'Unknown');
    this.setElementText('dnsOrg', dnsIntel.geoLocation?.organization || 'Unknown');
  }

  /**
   * Populate headers tab
   */
  populateHeadersTab() {
    const req = this.selectedRequest;
    
    const requestHeadersEl = document.getElementById('requestHeaders');
    const responseHeadersEl = document.getElementById('responseHeaders');

    if (requestHeadersEl) {
      const formatted = this.formatHeaders(req.requestHeaders);
      requestHeadersEl.textContent = formatted || 'No request headers available';
    }

    if (responseHeadersEl) {
      const formatted = this.formatHeaders(req.responseHeaders);
      responseHeadersEl.textContent = formatted || 'No response headers available';
    }
  }

  /**
   * Populate body tab
   */
  populateBodyTab() {
    const req = this.selectedRequest;
    
    const requestBodyEl = document.getElementById('requestBody');
    const responseBodyEl = document.getElementById('responseBody');

    if (requestBodyEl) {
      requestBodyEl.textContent = this.formatBody(req.requestBody) || 'No request body';
    }

    if (responseBodyEl) {
      responseBodyEl.textContent = this.formatBody(req.responseBody) || 'No response body';
    }
  }

  /**
   * Populate security tab
   */
  populateSecurityTab() {
    const req = this.selectedRequest;
    const securityTab = document.getElementById('securityTab');
    if (!securityTab) return;

    const authAnalysis = req.metadata?.authAnalysis;

    if (!authAnalysis || !authAnalysis.issues) {
      securityTab.innerHTML = '<div class="no-analysis">No security analysis available</div>';
      return;
    }

    const issues = authAnalysis.issues || [];
    const riskScore = authAnalysis.riskScore || 0;
    const riskCategory = authAnalysis.riskCategory || 'secure';

    // P0-FOURTEENTH-1 FIX: Build DOM safely
    securityTab.innerHTML = '';

    const summaryDiv = DOMSecurity.createSafeElement('div', `Risk Score: ${riskScore}/100`, {
      className: `security-summary risk-${riskCategory}`
    });
    securityTab.appendChild(summaryDiv);

    if (issues.length > 0) {
      const issuesList = DOMSecurity.createSafeElement('div', '', { className: 'issues-list' });
      const heading = DOMSecurity.createSafeElement('h4', 'Detected Issues:');
      issuesList.appendChild(heading);

      issues.forEach(issue => {
        const issueDiv = DOMSecurity.createSafeElement('div', '', {
          className: `security-issue issue-${(issue.severity || 'unknown').toLowerCase()}`
        });

        const headerDiv = DOMSecurity.createSafeElement('div', '', { className: 'issue-header' });
        const severitySpan = DOMSecurity.createSafeElement('span', issue.severity || 'UNKNOWN', { className: 'issue-severity' });
        const typeSpan = DOMSecurity.createSafeElement('span', issue.type || 'Unknown Type', { className: 'issue-type' });
        headerDiv.appendChild(severitySpan);
        headerDiv.appendChild(typeSpan);
        issueDiv.appendChild(headerDiv);

        const messageDiv = DOMSecurity.createSafeElement('div', issue.message || 'No description', { className: 'issue-message' });
        issueDiv.appendChild(messageDiv);

        if (issue.exploitation) {
          const exploitDiv = DOMSecurity.createSafeElement('div', issue.exploitation, { className: 'issue-exploitation' });
          issueDiv.appendChild(exploitDiv);
        }

        issuesList.appendChild(issueDiv);
      });

      securityTab.appendChild(issuesList);
    } else {
      const noIssuesDiv = DOMSecurity.createSafeElement('div', 'No security issues detected.', { className: 'no-issues' });
      securityTab.appendChild(noIssuesDiv);
    }
  }

  /**
   * Populate token analysis tab
   */
  populateTokenTab() {
    const req = this.selectedRequest;
    const tokenAnalysisEl = document.getElementById('tokenAnalysis');
    const tokenTabButton = document.querySelector('[data-tab="token"]');

    if (!tokenAnalysisEl || !tokenTabButton) return;

    let jwt = null;

    // Look for JWT in Authorization header
    const authHeader = req.requestHeaders?.find(h => h.name.toLowerCase() === 'authorization');
    if (authHeader && authHeader.value.toLowerCase().startsWith('bearer ')) {
      jwt = authHeader.value.substring(7);
    }

    // Look in request/response body
    if (!jwt) {
      try {
        const requestBody = JSON.parse(req.requestBody || '{}');
        jwt = requestBody.access_token || requestBody.id_token;
      } catch (e) {}
    }
    if (!jwt) {
      try {
        const responseBody = JSON.parse(req.responseBody || '{}');
        jwt = responseBody.access_token || responseBody.id_token;
      } catch (e) {}
    }

    if (jwt && typeof jwt === 'string' && JWTSecurity.isValidJWTStructure(jwt)) {
      tokenTabButton.style.display = 'block';

      const parsedJWT = JWTSecurity.parseJWT(jwt);

      if (parsedJWT.error) {
        const errorDiv = DOMSecurity.createSafeElement('div', `JWT Parse Error: ${parsedJWT.error}`, { className: 'error-state' });
        DOMSecurity.replaceChildren(tokenAnalysisEl, errorDiv);
      } else {
        const securityIssues = JWTSecurity.validateJWTSecurity(parsedJWT);

        tokenAnalysisEl.innerHTML = '';

        // Security warnings
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
      }
    } else {
      tokenTabButton.style.display = 'none';
    }
  }

  /**
   * Setup copy buttons
   */
  setupCopyButtons() {
    const copyUrlBtn = document.getElementById('copyUrl');
    if (copyUrlBtn) {
      copyUrlBtn.onclick = () => this.copyToClipboard(this.selectedRequest.url, copyUrlBtn);
    }
  }

  /**
   * Copy text to clipboard
   */
  copyToClipboard(text, button) {
    navigator.clipboard.writeText(text).then(() => {
      const originalText = button.textContent;
      button.textContent = '✅ Copied!';
      setTimeout(() => {
        button.textContent = originalText;
      }, 2000);
    }).catch(err => {
      console.error('Failed to copy:', err);
      alert('Failed to copy to clipboard');
    });
  }

  /**
   * Format headers for display
   */
  formatHeaders(headers) {
    if (!headers) return null;

    if (Array.isArray(headers)) {
      if (headers.length === 0) return null;
      return headers.map(h => `${h.name}: ${h.value || ''}`).join('\n');
    } else if (typeof headers === 'object') {
      const entries = Object.entries(headers);
      if (entries.length === 0) return null;
      return entries.map(([name, value]) => `${name}: ${value}`).join('\n');
    }

    return null;
  }

  /**
   * Format body for display
   */
  formatBody(body) {
    if (!body) return null;

    try {
      if (typeof body === 'string') {
        const parsed = JSON.parse(body);
        return JSON.stringify(parsed, null, 2);
      } else if (typeof body === 'object') {
        return JSON.stringify(body, null, 2);
      }
      return String(body);
    } catch (e) {
      return String(body);
    }
  }

  /**
   * Helper to set element text safely
   */
  setElementText(id, text) {
    const element = document.getElementById(id);
    if (element) {
      element.textContent = text;
    }
  }
}
