// Hera Content Script Utilities
// Shared utility functions for content script modules

// CODE QUALITY FIX P3-1: Conditional debug logging
const DEBUG = false; // Set to true for development

/**
 * Debug logging utility
 */
export function debug(...args) {
  if (DEBUG) console.log('[Hera Debug]', ...args);
}

/**
 * PERFORMANCE FIX P2-2: Shadow DOM support for detectors
 * Recursively query selector including shadow DOM trees
 * @param {string} selector - CSS selector
 * @param {Document|DocumentFragment} root - Root element to search from
 * @returns {Array} Array of matching elements
 */
export function querySelectorAllDeep(selector, root = document) {
  const elements = [];

  // Query regular DOM
  elements.push(...root.querySelectorAll(selector));

  // Query shadow roots recursively
  const allElements = root.querySelectorAll('*');
  for (const element of allElements) {
    if (element.shadowRoot) {
      elements.push(...querySelectorAllDeep(selector, element.shadowRoot));
    }
  }

  return elements;
}

/**
 * Sanitize HTML to prevent XSS from backend scan results
 * @param {string} str - String to sanitize
 * @returns {string} Sanitized HTML
 */
export function sanitizeHTML(str) {
  if (typeof str !== 'string') return '';
  const div = document.createElement('div');
  div.textContent = str; // This escapes HTML entities
  return div.innerHTML;
}

/**
 * CRITICAL FIX P0-5 & NEW-P1-1: Fallback stub detectors with clear error indication
 * Creates stub detector objects when actual detectors fail to load
 * @returns {Object} Stub detector objects
 */
export function createStubDetectors() {
  console.error('Hera: CRITICAL - Using stub detectors, full analysis unavailable');
  console.error('Hera: This page may be blocking the extension with CSP or module loading failed');

  // Create a critical error finding that will be shown to the user
  const errorFinding = {
    type: 'analysis_error',
    category: 'extension_blocked',
    severity: 'critical',
    title: '⚠️ Security Analysis Unavailable',
    description: 'This page is blocking Hera\'s security analysis, possibly through Content Security Policy (CSP) restrictions. The extension cannot verify if this site is safe.',
    recommendation: 'Exercise extreme caution. Do not enter sensitive information unless you trust this site from other sources.',
    evidence: {
      reason: 'Detector modules failed to load - CSP blocking or module error',
      extensionId: chrome.runtime.id
    },
    timestamp: new Date().toISOString()
  };

  return {
    darkPatternDetector: {
      detectPatterns: async () => {
        console.warn('Hera: Dark pattern detector unavailable (stub)');
        return [errorFinding];
      }
    },
    phishingDetector: {
      detectPhishing: async () => {
        console.warn('Hera: Phishing detector unavailable (stub)');
        return [];
      }
    },
    privacyViolationDetector: {
      detectViolations: async () => {
        console.warn('Hera: Privacy detector unavailable (stub)');
        return [];
      }
    },
    riskScoringEngine: {
      calculateRiskScore: (findings) => {
        console.warn('Hera: Risk scoring unavailable (stub)');
        // Return FAILING grade to alert user
        return {
          overallScore: 0,
          grade: 'F',
          riskLevel: 'CRITICAL',
          criticalIssues: findings.filter(f => f.severity === 'critical').length || 1,
          warnings: 0,
          info: 0,
          breakdown: { security: 0, privacy: 0, ux: 0 },
          message: '⚠️ ANALYSIS BLOCKED - Cannot verify site safety due to restrictions. Proceed with extreme caution.',
          analysisMode: 'stub',
          analysisBlocked: true
        };
      }
    }
  };
}

/**
 * CRITICAL FIX NEW-P2-2: Create stub for individual detector
 * @param {string} name - Detector name
 * @param {string} method - Method name
 * @returns {Object} Stub detector object
 */
export function createStubDetector(name, method) {
  return {
    [method]: async () => {
      console.warn(`Hera: ${name} unavailable (stub)`);
      return [];
    }
  };
}

/**
 * Humanize camelCase factor names for display
 * @param {string} factor - Factor name in camelCase
 * @returns {string} Human-readable name
 */
export function humanizeFactor(factor) {
  const humanNames = {
    gitExposure: 'Git repository exposure',
    envExposure: 'Environment file exposure',
    unexpectedCertIssuer: 'Unusual certificate issuer',
    domainAgeMismatch: 'Domain age inconsistency',
    techStackMismatch: 'Technology stack anomaly',
    weakSecurity: 'Security header deficiency',
    weakTLS: 'Outdated TLS configuration'
  };

  return humanNames[factor] || factor.replace(/([A-Z])/g, ' $1').toLowerCase();
}

// Expose helper for detectors to use
if (typeof window !== 'undefined') {
  window.__heraQuerySelectorAllDeep = querySelectorAllDeep;
}
