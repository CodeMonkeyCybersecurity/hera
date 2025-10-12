// Hera Form Protector
// HeraFormProtector class - Main form protection and warning system

import { sanitizeHTML, humanizeFactor } from './content-utils.js';

/**
 * HeraFormProtector class
 * Monitors forms, displays warnings, and blocks insecure submissions
 */
export class HeraFormProtector {
  constructor() {
    this.domain = window.location.hostname;
    this.backendScanResults = null;
    this.blockedSubmissions = 0;
    this.currentAlert = null;
    this.alertQueue = [];

    this.init();
    this.injectBrandedAlertStyles();
  }

  async init() {
    // Get backend scan results from background script
    this.backendScanResults = await this.getBackendScanResults();

    // Set up form monitoring
    this.setupFormMonitoring();

    // Show immediate warnings if critical issues found
    if (this.backendScanResults?.shouldBlockDataEntry) {
      this.showPageWarning();
    }
  }

  async getBackendScanResults() {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({
        action: 'getBackendScan',
        domain: this.domain
      }, (response) => {
        resolve(response);
      });
    });
  }

  setupFormMonitoring() {
    // Monitor all form submissions
    document.addEventListener('submit', (e) => {
      this.handleFormSubmission(e);
    }, true);

    // Monitor password fields for real-time warnings
    document.addEventListener('input', (e) => {
      if (e.target.type === 'password' || e.target.name?.toLowerCase().includes('password')) {
        this.handlePasswordInput(e.target);
      }
    });

    // Monitor for dynamically added forms
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            const forms = node.querySelectorAll ? node.querySelectorAll('form') : [];
            forms.forEach(form => this.monitorForm(form));
          }
        });
      });
    });

    observer.observe(document.body, { childList: true, subtree: true });

    // Monitor existing forms
    document.querySelectorAll('form').forEach(form => this.monitorForm(form));
  }

  handleFormSubmission(e) {
    const form = e.target;

    // Check if this form contains sensitive data
    const hasSensitiveData = this.containsSensitiveData(form);

    if (hasSensitiveData && this.backendScanResults?.shouldBlockDataEntry) {
      e.preventDefault();
      e.stopPropagation();

      this.showCriticalFormWarning(form);
      this.blockedSubmissions++;

      // Report blocked submission
      chrome.runtime.sendMessage({
        action: 'reportBlockedSubmission',
        domain: this.domain,
        exposures: this.backendScanResults.exposed
      });

      return false;
    }

    // Show warning for high-risk but not critical
    if (hasSensitiveData && this.backendScanResults?.riskScore > 50) {
      const userChoice = this.showRiskWarning(form);
      if (!userChoice) {
        e.preventDefault();
        return false;
      }
    }
  }

  containsSensitiveData(form) {
    const sensitiveFields = [
      'input[type="password"]',
      'input[type="email"]',
      'input[name*="password"]',
      'input[name*="email"]',
      'input[name*="phone"]',
      'input[name*="credit"]',
      'input[name*="card"]',
      'input[name*="ssn"]',
      'input[name*="social"]',
      'input[name*="address"]',
      'textarea[name*="message"]',
      'textarea[name*="comment"]'
    ];

    return sensitiveFields.some(selector => form.querySelector(selector));
  }

  showCriticalFormWarning(form) {
    // Remove any existing warnings
    const existingWarning = form.querySelector('.hera-form-warning');
    if (existingWarning) existingWarning.remove();

    // Create warning element
    const warning = document.createElement('div');
    warning.className = 'hera-form-warning critical';
    warning.style.cssText = `
      position: relative;
      background: linear-gradient(135deg, #ff4444, #cc0000);
      color: white;
      padding: 20px;
      border-radius: 8px;
      margin: 15px 0;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
      font-size: 14px;
      box-shadow: 0 4px 12px rgba(255, 0, 0, 0.3);
      border: 2px solid #ff0000;
      z-index: 10000;
    `;

    const criticalExposures = this.backendScanResults.exposed.filter(e => e.severity === 'critical');

    // Build DOM safely without innerHTML
    const container = document.createElement('div');
    container.style.cssText = 'display: flex; align-items: center; gap: 15px;';

    const iconDiv = document.createElement('div');
    iconDiv.style.fontSize = '48px';
    iconDiv.textContent = '';

    const contentDiv = document.createElement('div');
    contentDiv.style.flex = '1';

    const heading = document.createElement('h3');
    heading.style.cssText = 'margin: 0 0 10px 0; font-size: 18px;';
    heading.textContent = 'FORM SUBMISSION BLOCKED';

    const description = document.createElement('div');
    description.style.marginBottom = '15px';
    // SECURITY FIX: Use textContent to prevent XSS
    const descText = document.createTextNode('This website has ');
    const strongCount = document.createElement('strong');
    strongCount.textContent = `${criticalExposures.length} critical security vulnerabilities`;
    const descText2 = document.createTextNode(' that could expose your data:');
    description.appendChild(descText);
    description.appendChild(strongCount);
    description.appendChild(descText2);

    const exposuresDiv = document.createElement('div');
    exposuresDiv.style.cssText = 'background: rgba(255,255,255,0.1); padding: 12px; border-radius: 4px; margin: 10px 0;';

    criticalExposures.forEach(exp => {
      const expDiv = document.createElement('div');
      expDiv.style.marginBottom = '8px';
      // SECURITY FIX: Use DOM methods instead of innerHTML
      expDiv.textContent = `• `;
      const strong = document.createElement('strong');
      strong.textContent = exp.type.toUpperCase() + ':';
      expDiv.appendChild(strong);
      const details = document.createTextNode(' ' + exp.details);
      expDiv.appendChild(details);
      exposuresDiv.appendChild(expDiv);
    });

    const warningText = document.createElement('div');
    warningText.style.cssText = 'font-weight: bold; font-size: 16px;';
    warningText.textContent = '⛔ Your data would be stored insecurely and could be stolen!';

    contentDiv.appendChild(heading);
    contentDiv.appendChild(description);
    contentDiv.appendChild(exposuresDiv);
    contentDiv.appendChild(warningText);

    container.appendChild(iconDiv);
    container.appendChild(contentDiv);

    const buttonsDiv = document.createElement('div');
    buttonsDiv.style.cssText = 'margin-top: 20px; display: flex; gap: 10px; justify-content: center;';

    const understoodBtn = document.createElement('button');
    understoodBtn.style.cssText = 'background: white; color: #cc0000; border: none; padding: 10px 20px; border-radius: 4px; font-weight: bold; cursor: pointer;';
    understoodBtn.textContent = 'Understood';
    understoodBtn.onclick = () => warning.remove();

    const detailsBtn = document.createElement('button');
    detailsBtn.style.cssText = 'background: transparent; color: white; border: 2px solid white; padding: 10px 20px; border-radius: 4px; cursor: pointer;';
    detailsBtn.textContent = 'Technical Details';
    detailsBtn.onclick = () => window.hera.showTechnicalDetails();

    buttonsDiv.appendChild(understoodBtn);
    buttonsDiv.appendChild(detailsBtn);

    warning.appendChild(container);
    warning.appendChild(buttonsDiv);

    // Insert warning above the form
    form.parentNode.insertBefore(warning, form);

    // Disable form inputs
    const inputs = form.querySelectorAll('input, textarea, select, button');
    inputs.forEach(input => {
      input.style.opacity = '0.5';
      input.style.pointerEvents = 'none';
      input.disabled = true;
    });
  }

  // SECURITY FIX P0: Use DOM elements instead of HTML strings
  showPageWarning() {
    // Use SADS analysis if available
    if (this.backendScanResults.sadsAnalysis) {
      const sads = this.backendScanResults.sadsAnalysis;
      const detailsDOM = this.formatSADSAlertDOM(sads);

      // Add authentication analysis if available
      if (this.backendScanResults.authAnalysis && this.backendScanResults.authAnalysis.riskScore > 30) {
        detailsDOM.appendChild(document.createElement('br'));
        const hr = document.createElement('hr');
        hr.style.cssText = 'border-top: 1px solid #444; margin: 15px 0;';
        detailsDOM.appendChild(hr);
        detailsDOM.appendChild(document.createElement('br'));
        detailsDOM.appendChild(this.formatAuthAnalysisDOM(this.backendScanResults.authAnalysis));
      }

      const alertData = {
        title: `${sads.recommendation.icon} ${sads.sScore.category} Risk Detected`,
        detailsDOM: detailsDOM, // Pass DOM element
        severity: sads.sScore.category.toLowerCase(),
        verification: sads.anomalies[0]?.verification || null
      };

      this.showBrandedAlert(alertData);
    } else {
      // Fallback to rule-based alerts
      const criticalExposures = this.backendScanResults.exposed.filter(e => e.severity === 'critical');

      const detailsDOM = document.createElement('div');
      detailsDOM.appendChild(document.createTextNode(`Hera detected ${criticalExposures.length} critical security vulnerabilities on this website that could expose your data:`));
      detailsDOM.appendChild(document.createElement('br'));
      detailsDOM.appendChild(document.createElement('br'));

      criticalExposures.forEach(exp => {
        detailsDOM.appendChild(document.createTextNode('• '));
        const typeStrong = document.createElement('strong');
        typeStrong.textContent = exp.type.toUpperCase() + ':';
        detailsDOM.appendChild(typeStrong);
        detailsDOM.appendChild(document.createTextNode(' ' + exp.details));
        detailsDOM.appendChild(document.createElement('br'));
      });

      detailsDOM.appendChild(document.createElement('br'));
      const warning = document.createElement('strong');
      warning.textContent = '⛔ Avoid entering personal information on this site!';
      detailsDOM.appendChild(warning);

      // Add authentication analysis if available
      if (this.backendScanResults.authAnalysis && this.backendScanResults.authAnalysis.riskScore > 30) {
        detailsDOM.appendChild(document.createElement('br'));
        const hr = document.createElement('hr');
        hr.style.cssText = 'border-top: 1px solid #444; margin: 15px 0;';
        detailsDOM.appendChild(hr);
        detailsDOM.appendChild(document.createElement('br'));
        detailsDOM.appendChild(this.formatAuthAnalysisDOM(this.backendScanResults.authAnalysis));
      }

      const alertData = {
        title: 'Critical Security Warning',
        detailsDOM: detailsDOM, // Pass DOM element
        severity: 'critical',
        verification: criticalExposures[0]?.verification || null
      };

      this.showBrandedAlert(alertData);
    }
  }

  // SECURITY FIX P0: Build DOM elements instead of HTML strings to prevent XSS
  formatSADSAlertDOM(sadsAnalysis) {
    const container = document.createElement('div');

    // S-Score
    const scoreStrong = document.createElement('strong');
    scoreStrong.textContent = `S-Score: ${sadsAnalysis.sScore.normalized}/100`;
    container.appendChild(scoreStrong);
    container.appendChild(document.createElement('br'));

    // Site Type
    const siteType = document.createTextNode(`Site Type: ${sadsAnalysis.websiteType}`);
    container.appendChild(siteType);
    container.appendChild(document.createElement('br'));
    container.appendChild(document.createElement('br'));

    // Recommendation
    const recStrong = document.createElement('strong');
    recStrong.textContent = sadsAnalysis.recommendation.message;
    container.appendChild(recStrong);
    container.appendChild(document.createElement('br'));
    container.appendChild(document.createElement('br'));

    // Top surprise factors
    const topSurprises = Object.entries(sadsAnalysis.surpriseScores)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 3);

    if (topSurprises.length > 0) {
      const surpriseHeading = document.createElement('strong');
      surpriseHeading.textContent = 'Unusual characteristics:';
      container.appendChild(surpriseHeading);
      container.appendChild(document.createElement('br'));

      topSurprises.forEach(([factor, score]) => {
        const item = document.createTextNode(`• ${humanizeFactor(factor)}: ${score.toFixed(1)}x unexpected`);
        container.appendChild(item);
        container.appendChild(document.createElement('br'));
      });
      container.appendChild(document.createElement('br'));
    }

    // Anomaly patterns
    if (sadsAnalysis.anomalies.length > 0) {
      const anomalyHeading = document.createElement('strong');
      anomalyHeading.textContent = 'Patterns detected:';
      container.appendChild(anomalyHeading);
      container.appendChild(document.createElement('br'));

      sadsAnalysis.anomalies.forEach(anomaly => {
        const item = document.createTextNode(`• ${anomaly.description} (${Math.round(anomaly.confidence * 100)}% confidence)`);
        container.appendChild(item);
        container.appendChild(document.createElement('br'));
      });
      container.appendChild(document.createElement('br'));
    }

    // Assessment
    if (sadsAnalysis.assessment.primaryConcerns.length > 0) {
      const concernHeading = document.createElement('strong');
      concernHeading.textContent = 'Primary concerns:';
      container.appendChild(concernHeading);
      container.appendChild(document.createElement('br'));

      sadsAnalysis.assessment.primaryConcerns.forEach(concern => {
        const item = document.createTextNode(`• ${concern}`);
        container.appendChild(item);
        container.appendChild(document.createElement('br'));
      });
    }

    return container;
  }

  // SECURITY FIX P0: Build DOM elements instead of HTML strings to prevent XSS
  formatAuthAnalysisDOM(authAnalysis) {
    const container = document.createElement('div');

    // Heading
    const heading = document.createElement('strong');
    heading.textContent = 'Authentication Analysis';
    container.appendChild(heading);
    container.appendChild(document.createElement('br'));

    // Protocol
    container.appendChild(document.createTextNode('Protocol: '));
    const protocolStrong = document.createElement('strong');
    protocolStrong.textContent = authAnalysis.protocol;
    container.appendChild(protocolStrong);
    container.appendChild(document.createElement('br'));

    // Risk Score
    container.appendChild(document.createTextNode('Risk Score: '));
    const scoreStrong = document.createElement('strong');
    scoreStrong.textContent = `${Math.round(authAnalysis.riskScore)}/100`;
    container.appendChild(scoreStrong);
    container.appendChild(document.createElement('br'));

    // Recommendation
    container.appendChild(document.createTextNode('Recommendation: '));
    const recStrong = document.createElement('strong');
    recStrong.textContent = authAnalysis.recommendation;
    container.appendChild(recStrong);
    container.appendChild(document.createElement('br'));
    container.appendChild(document.createElement('br'));

    if (authAnalysis.issues && authAnalysis.issues.length > 0) {
      // Group issues by severity
      const criticalIssues = authAnalysis.issues.filter(i => i.severity === 'CRITICAL');
      const highIssues = authAnalysis.issues.filter(i => i.severity === 'HIGH');
      const mediumIssues = authAnalysis.issues.filter(i => i.severity === 'MEDIUM');

      if (criticalIssues.length > 0) {
        const critHeading = document.createElement('strong');
        critHeading.textContent = `🔴 Critical Issues (${criticalIssues.length}):`;
        container.appendChild(critHeading);
        container.appendChild(document.createElement('br'));

        criticalIssues.forEach(issue => {
          container.appendChild(document.createTextNode(`• ${issue.message}`));
          container.appendChild(document.createElement('br'));
          if (issue.exploitation) {
            const em = document.createElement('em');
            em.style.color = '#cc0000';
            em.textContent = `  ${issue.exploitation}`;
            container.appendChild(em);
            container.appendChild(document.createElement('br'));
          }
        });
        container.appendChild(document.createElement('br'));
      }

      if (highIssues.length > 0) {
        const highHeading = document.createElement('strong');
        highHeading.textContent = `🟠 High Risk Issues (${highIssues.length}):`;
        container.appendChild(highHeading);
        container.appendChild(document.createElement('br'));

        highIssues.forEach(issue => {
          container.appendChild(document.createTextNode(`• ${issue.message}`));
          container.appendChild(document.createElement('br'));
        });
        container.appendChild(document.createElement('br'));
      }

      if (mediumIssues.length > 0) {
        const medHeading = document.createElement('strong');
        medHeading.textContent = `🟡 Medium Risk Issues (${mediumIssues.length}):`;
        container.appendChild(medHeading);
        container.appendChild(document.createElement('br'));

        mediumIssues.forEach(issue => {
          container.appendChild(document.createTextNode(`• ${issue.message}`));
          container.appendChild(document.createElement('br'));
        });
        container.appendChild(document.createElement('br'));
      }

      // Security recommendations
      if (authAnalysis.riskScore >= 80) {
        const recHeading = document.createElement('strong');
        recHeading.style.color = '#cc0000';
        recHeading.textContent = '⛔ Recommended Action:';
        container.appendChild(recHeading);
        container.appendChild(document.createElement('br'));

        container.appendChild(document.createTextNode('• Avoid entering sensitive credentials on this site'));
        container.appendChild(document.createElement('br'));
        container.appendChild(document.createTextNode('• Use alternative authentication methods if available'));
        container.appendChild(document.createElement('br'));
        container.appendChild(document.createTextNode('• Contact the site administrator about security issues'));
        container.appendChild(document.createElement('br'));
      } else if (authAnalysis.riskScore >= 60) {
        const recHeading = document.createElement('strong');
        recHeading.style.color = '#ff8800';
        recHeading.textContent = 'Recommended Action:';
        container.appendChild(recHeading);
        container.appendChild(document.createElement('br'));

        container.appendChild(document.createTextNode('• Exercise caution when authenticating'));
        container.appendChild(document.createElement('br'));
        container.appendChild(document.createTextNode('• Consider using multi-factor authentication'));
        container.appendChild(document.createElement('br'));
        container.appendChild(document.createTextNode('• Monitor for suspicious activity'));
        container.appendChild(document.createElement('br'));
      }
    } else {
      container.appendChild(document.createTextNode('No significant authentication issues detected.'));
      container.appendChild(document.createElement('br'));
    }

    return container;
  }

  monitorForm(form) {
    // Add visual indicator for monitored forms
    if (this.backendScanResults?.riskScore > 30) {
      const indicator = document.createElement('div');
      indicator.className = 'hera-form-indicator';
      indicator.style.cssText = `
        position: absolute;
        top: -5px;
        right: -5px;
        background: ${this.backendScanResults.shouldBlockDataEntry ? '#ff4444' : '#ff8800'};
        color: white;
        padding: 2px 6px;
        border-radius: 3px;
        font-size: 10px;
        font-weight: bold;
        z-index: 1000;
      `;
      indicator.textContent = this.backendScanResults.shouldBlockDataEntry ? 'BLOCKED' : 'RISKY';

      form.style.position = 'relative';
      form.appendChild(indicator);
    }
  }

  handlePasswordInput(passwordField) {
    // Show real-time warning for password fields on risky sites
    if (this.backendScanResults?.riskScore > 50) {
      this.showPasswordWarning(passwordField);
    }
  }

  showPasswordWarning(passwordField) {
    // Remove existing warning
    const existingWarning = passwordField.parentNode.querySelector('.hera-password-warning');
    if (existingWarning) return; // Don't spam warnings

    const warning = document.createElement('div');
    warning.className = 'hera-password-warning';
    warning.style.cssText = `
      background: rgba(255, 68, 68, 0.1);
      border: 1px solid #ff4444;
      color: #cc0000;
      padding: 8px 12px;
      border-radius: 4px;
      margin-top: 5px;
      font-size: 12px;
      font-family: -apple-system, BlinkMacSystemFont, sans-serif;
    `;

    // SECURITY FIX: Use DOM methods instead of innerHTML
    const strong = document.createElement('strong');
    strong.textContent = 'Security Risk:';
    warning.appendChild(strong);
    warning.appendChild(document.createTextNode(' This site has backend vulnerabilities. Consider using a temporary password.'));

    passwordField.parentNode.insertBefore(warning, passwordField.nextSibling);

    // Remove warning after 10 seconds
    setTimeout(() => warning.remove(), 10000);
  }

  // ===== NEW BRANDED ALERT SYSTEM =====
  injectBrandedAlertStyles() {
    // Check if styles are already injected
    if (document.getElementById('hera-branded-alert-styles')) return;

    const styleSheet = document.createElement('style');
    styleSheet.id = 'hera-branded-alert-styles';
    styleSheet.textContent = `
      .hera-security-alert {
        position: fixed !important;
        top: 45px !important;
        right: 8px !important;
        background: #e45549 !important;
        color: white !important;
        padding: 20px !important;
        border-radius: 16px !important;
        border: 3px solid #0ca678 !important;
        min-width: 320px !important;
        max-width: 400px !important;
        z-index: 999999 !important;
        animation: heraAlertSlideIn 0.5s ease-out !important;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif !important;
        font-size: 14px !important;
        line-height: 1.4 !important;
        box-shadow: 0 12px 40px rgba(0,0,0,0.4), 0 0 0 1px rgba(12, 166, 120, 0.3) !important;
      }

      /* Speech bubble tail pointing to extension icon */
      .hera-security-alert::before {
        content: '' !important;
        position: absolute !important;
        top: -15px !important;
        right: 24px !important;
        width: 0 !important;
        height: 0 !important;
        border-left: 15px solid transparent !important;
        border-right: 15px solid transparent !important;
        border-bottom: 15px solid #0ca678 !important;
        z-index: 2 !important;
        filter: drop-shadow(0 -2px 3px rgba(0,0,0,0.2)) !important;
      }

      /* Inner triangle for speech bubble effect */
      .hera-security-alert::after {
        content: '' !important;
        position: absolute !important;
        top: -11px !important;
        right: 27px !important;
        width: 0 !important;
        height: 0 !important;
        border-left: 12px solid transparent !important;
        border-right: 12px solid transparent !important;
        border-bottom: 12px solid #e45549 !important;
        z-index: 3 !important;
      }

      .hera-alert-header {
        display: flex !important;
        align-items: center !important;
        gap: 12px !important;
        margin-bottom: 16px !important;
        padding-bottom: 12px !important;
        border-bottom: 2px solid rgba(255,255,255,0.2) !important;
      }

      .hera-logo {
        width: 24px !important;
        height: 24px !important;
        background: #0ca678 !important;
        border-radius: 6px !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        font-weight: bold !important;
        font-size: 14px !important;
        color: white !important;
      }

      .hera-brand-text {
        font-weight: 600 !important;
        font-size: 16px !important;
        color: white !important;
        margin: 0 !important;
      }

      .hera-extension-label {
        background: rgba(255,255,255,0.2) !important;
        padding: 2px 8px !important;
        border-radius: 4px !important;
        font-size: 11px !important;
        font-weight: 500 !important;
        margin-left: auto !important;
      }

      .hera-alert-content {
        display: flex !important;
        align-items: flex-start !important;
        gap: 12px !important;
      }

      .hera-alert-icon {
        font-size: 20px !important;
        margin-top: 2px !important;
        flex-shrink: 0 !important;
      }

      .hera-alert-message {
        flex: 1 !important;
        font-weight: 500 !important;
        line-height: 1.4 !important;
        margin: 0 !important;
      }

      .hera-alert-details {
        font-size: 13px !important;
        margin-top: 12px !important;
        opacity: 0.9 !important;
        padding: 12px !important;
        background: rgba(255,255,255,0.1) !important;
        border-radius: 8px !important;
        border-left: 4px solid #0ca678 !important;
      }

      .hera-alert-actions {
        margin-top: 16px !important;
        display: flex !important;
        gap: 10px !important;
        justify-content: flex-end !important;
      }

      .hera-alert-close, .hera-alert-verify {
        background: rgba(255,255,255,0.2) !important;
        border: 1px solid rgba(255,255,255,0.3) !important;
        color: white !important;
        font-size: 13px !important;
        cursor: pointer !important;
        padding: 8px 16px !important;
        border-radius: 8px !important;
        font-weight: 500 !important;
        transition: all 0.2s ease !important;
        font-family: inherit !important;
      }

      .hera-alert-verify {
        background: #0ca678 !important;
        border-color: #0ca678 !important;
      }

      .hera-alert-verify:hover {
        background: #51a14f !important;
        border-color: #51a14f !important;
      }

      @keyframes heraAlertSlideIn {
        0% {
          opacity: 0;
          transform: translate(20px, -20px) scale(0.3);
          transform-origin: top right;
        }
        50% {
          opacity: 0.8;
          transform: translate(5px, -5px) scale(1.05);
          transform-origin: top right;
        }
        100% {
          opacity: 1;
          transform: translate(0, 0) scale(1);
          transform-origin: top right;
        }
      }

      @keyframes heraAlertSlideOut {
        0% {
          opacity: 1;
          transform: translate(0, 0) scale(1);
          transform-origin: top right;
        }
        100% {
          opacity: 0;
          transform: translate(20px, -20px) scale(0.3);
          transform-origin: top right;
        }
      }

      .hera-security-alert.critical {
        animation: heraAlertSlideIn 0.5s ease-out, heraCriticalPulse 2s infinite 0.5s !important;
      }

      @keyframes heraCriticalPulse {
        0%, 100% {
          border-color: #0ca678;
        }
        50% {
          border-color: #FFD700;
        }
      }
    `;
    document.head.appendChild(styleSheet);
  }

  showBrandedAlert(alertData) {
    // Don't show duplicate alerts
    if (this.currentAlert) {
      this.alertQueue.push(alertData);
      return;
    }

    this.currentAlert = this.createBrandedAlertElement(alertData);
    document.body.appendChild(this.currentAlert);

    // Auto-dismiss after 15 seconds unless it's critical
    if (alertData.severity !== 'critical') {
      setTimeout(() => {
        this.dismissCurrentAlert();
      }, 15000);
    }
  }

  createBrandedAlertElement(alertData) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `hera-security-alert ${alertData.severity || ''}`;

    // Header
    const header = document.createElement('div');
    header.className = 'hera-alert-header';

    const logo = document.createElement('div');
    logo.className = 'hera-logo';
    logo.textContent = 'H';

    const brandText = document.createElement('div');
    brandText.className = 'hera-brand-text';
    brandText.textContent = 'Hera Security';

    const label = document.createElement('div');
    label.className = 'hera-extension-label';
    label.textContent = 'Extension Alert';

    header.appendChild(logo);
    header.appendChild(brandText);
    header.appendChild(label);

    // Content
    const content = document.createElement('div');
    content.className = 'hera-alert-content';

    const icon = document.createElement('div');
    icon.className = 'hera-alert-icon';
    icon.textContent = this.getAlertIcon(alertData.severity);

    const messageDiv = document.createElement('div');
    messageDiv.className = 'hera-alert-message';

    const titleStrong = document.createElement('strong');
    titleStrong.textContent = alertData.title || 'Security Alert';
    messageDiv.appendChild(titleStrong);

    const detailsDiv = document.createElement('div');
    detailsDiv.className = 'hera-alert-details';

    // SECURITY FIX P0: Use DOM elements instead of innerHTML to prevent XSS
    if (alertData.detailsDOM) {
      // Use pre-built DOM element (safe)
      detailsDiv.appendChild(alertData.detailsDOM);
    } else {
      // Fallback for legacy callers - use textContent only (safe)
      const fallbackText = alertData.details || alertData.message || 'Security issue detected on this website.';
      detailsDiv.textContent = fallbackText;
    }

    if (alertData.verification) {
      const br1 = document.createElement('br');
      const br2 = document.createElement('br');
      const verifyLabel = document.createElement('strong');
      verifyLabel.textContent = 'Verify: ';
      const verifyLink = document.createElement('a');
      verifyLink.href = sanitizeHTML(alertData.verification);
      verifyLink.target = '_blank';
      verifyLink.style.cssText = 'color: #FFD700; text-decoration: underline;';
      verifyLink.textContent = alertData.verification;

      detailsDiv.appendChild(br1);
      detailsDiv.appendChild(br2);
      detailsDiv.appendChild(verifyLabel);
      detailsDiv.appendChild(verifyLink);
    }

    messageDiv.appendChild(detailsDiv);
    content.appendChild(icon);
    content.appendChild(messageDiv);

    // Actions
    const actions = document.createElement('div');
    actions.className = 'hera-alert-actions';

    if (alertData.verification) {
      const verifyBtn = document.createElement('button');
      verifyBtn.className = 'hera-alert-verify';
      verifyBtn.textContent = 'Verify Issue';
      verifyBtn.addEventListener('click', () => {
        window.open(alertData.verification, '_blank');
      });
      actions.appendChild(verifyBtn);
    }

    const closeBtn = document.createElement('button');
    closeBtn.className = 'hera-alert-close';
    closeBtn.textContent = 'Dismiss';
    closeBtn.addEventListener('click', () => this.dismissCurrentAlert());
    actions.appendChild(closeBtn);

    // Assemble
    alertDiv.appendChild(header);
    alertDiv.appendChild(content);
    alertDiv.appendChild(actions);

    return alertDiv;
  }

  getAlertIcon(severity) {
    switch (severity) {
      case 'critical': return '';
      case 'warning': return '⚠️';
      case 'info': return 'ℹ️';
      default: return '';
    }
  }

  dismissCurrentAlert() {
    if (this.currentAlert) {
      // Fade out animation
      this.currentAlert.style.animation = 'heraAlertSlideOut 0.3s ease-in forwards';

      setTimeout(() => {
        if (this.currentAlert && this.currentAlert.parentNode) {
          this.currentAlert.parentNode.removeChild(this.currentAlert);
        }
        this.currentAlert = null;

        // Show next alert in queue
        if (this.alertQueue.length > 0) {
          const nextAlert = this.alertQueue.shift();
          setTimeout(() => this.showBrandedAlert(nextAlert), 500);
        }
      }, 300);
    }
  }
}
