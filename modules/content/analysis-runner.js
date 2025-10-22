// Hera Analysis Runner
// Analysis orchestration (runComprehensiveAnalysis, shouldRunAnalysis)

import { loadDetectors } from './detector-loader.js';
import { sendThrottledMessage } from './message-queue.js';
import { debug } from './content-utils.js';

// SECURITY FIX P0-2: Deduplication flags to prevent race conditions
let analysisRunning = false;
let analysisCompleted = false;

/**
 * PERFORMANCE FIX P2-6 & NEW-P2-3: Skip analysis on extension internal pages
 * Determines if analysis should run on the current page
 * @returns {boolean} True if analysis should run
 */
export function shouldRunAnalysis() {
  const protocol = window.location.protocol;
  const hostname = window.location.hostname;

  // SECURITY FIX NEW-P2-3: Whitelist only http: and https:
  const allowedProtocols = ['http:', 'https:'];
  if (!allowedProtocols.includes(protocol)) {
    console.log(`Hera: Skipping analysis on ${protocol} page (only http/https allowed)`);
    return false;
  }

  // SECURITY FIX NEW-P2-3: Block localhost and private IPs
  if (hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname.startsWith('192.168.') ||
      hostname.startsWith('10.') ||
      hostname.startsWith('172.16.') ||
      hostname === '[::1]') {
    console.log('Hera: Skipping analysis on local/private IP');
    return false;
  }

  return true;
}

/**
 * Main analysis function - runs detectors with direct DOM access
 * ARCHITECTURE FIX P0-1: Run all detectors in content script where document/window exist
 * @returns {Promise<Object>} Analysis results with success status, findings, and score
 */
export async function runComprehensiveAnalysis() {
  console.log('AnalysisRunner: runComprehensiveAnalysis called');
  console.log('AnalysisRunner: State check - running:', analysisRunning, 'completed:', analysisCompleted);

  // CRITICAL FIX P0-2: Prevent duplicate analysis runs
  if (analysisRunning) {
    console.log('Hera: Analysis already running, skipping duplicate call');
    return { success: false, error: 'Analysis already in progress' };
  }

  if (analysisCompleted) {
    console.log('Hera: Analysis already completed for this page');
    return { success: false, error: 'Analysis already completed' };
  }

  console.log('AnalysisRunner: Starting analysis - setting analysisRunning = true');
  analysisRunning = true;

  try {
    // P0-TENTH-4 FIX: Take immutable snapshot of DOM before analysis
    const domSnapshot = {
      url: window.location.href,
      title: document.title,
      timestamp: Date.now(),
      // Capture key DOM elements for TOCTOU protection
      formCount: document.querySelectorAll('form').length,
      inputCount: document.querySelectorAll('input[type="password"], input[type="email"]').length,
      scriptCount: document.querySelectorAll('script').length,
      linkCount: document.querySelectorAll('a').length
    };

    // P0-TENTH-4 FIX: Freeze snapshot to prevent tampering
    Object.freeze(domSnapshot);

    console.log('Hera: DOM snapshot captured:', domSnapshot);

    // CRITICAL FIX P0-1: Load detectors dynamically first
    const detectors = await loadDetectors();

    console.log('Hera: Starting comprehensive analysis in content script');

    const allFindings = [];
    let analysisSuccessful = true;

    // ==================== NON-AUTH DETECTORS DISABLED ====================
    // All content script detectors disabled to focus on auth vulnerabilities only.
    // Auth detection happens in background.js via webRequest listeners.

    // 0. Subdomain Impersonation Detection - DISABLED (non-auth)
    // try {
    //   console.log('Hera: Running subdomain impersonation detection...');
    //   const subdomain = await detectors.subdomainImpersonationDetector.detectImpersonation(domSnapshot.url);
    //   allFindings.push(...subdomain);
    // } catch (error) {
    //   console.error('Hera: Subdomain impersonation detection failed:', error);
    //   analysisSuccessful = false;
    // }

    // 1. Dark Pattern Detection - DISABLED (non-auth)
    // try {
    //   console.log('Hera: Running dark pattern detection...');
    //   const darkPatterns = await detectors.darkPatternDetector.detectPatterns(document);
    //   allFindings.push(...darkPatterns);
    // } catch (error) {
    //   console.error('Hera: Dark pattern detection failed:', error);
    //   analysisSuccessful = false;
    // }

    // 2. Phishing Detection - DISABLED (non-auth)
    // try {
    //   console.log('Hera: Running phishing detection...');
    //   const phishing = await detectors.phishingDetector.detectPhishing(window.location.href, document);
    //   allFindings.push(...phishing);
    // } catch (error) {
    //   console.error('Hera: Phishing detection failed:', error);
    //   analysisSuccessful = false;
    // }

    // 3. Privacy Violation Detection - DISABLED (non-auth)
    // try {
    //   console.log('Hera: Running privacy violation detection...');
    //   const privacy = await detectors.privacyViolationDetector.detectViolations(window.location.href, document);
    //   allFindings.push(...privacy);
    // } catch (error) {
    //   console.error('Hera: Privacy violation detection failed:', error);
    //   analysisSuccessful = false;
    // }

    // 4. Accessibility Analysis - Already removed

    // 5. Calculate risk score - DISABLED (no findings from content scripts)
    console.log('Hera: Content script analysis disabled - auth detection handled by background.js');
    const scoreData = { score: 0, grade: 'N/A', message: 'Auth-only mode' };

    console.log(`Hera: Analysis complete - ${allFindings.length} findings, grade: ${scoreData.grade}`);

    // Send results to background script for storage
    // SECURITY FIX P1-4: Use throttled messaging
    // P1-THIRTEENTH-2: Include HTML for compression analysis
    sendThrottledMessage({
      type: 'ANALYSIS_COMPLETE',
      url: window.location.href,
      findings: allFindings,
      score: scoreData,
      analysisSuccessful: analysisSuccessful,
      timestamp: new Date().toISOString(),
      html: document.documentElement.outerHTML // For PhishZip compression analysis
    });

    // Display overlay (load it dynamically if needed)
    await injectReputationOverlay(scoreData);

    // CRITICAL FIX P0-2: Mark analysis as completed successfully
    analysisCompleted = true;
    analysisRunning = false;

    return { success: true, findings: allFindings, score: scoreData };

  } catch (error) {
    console.error('Hera: Comprehensive analysis failed:', error);

    // CRITICAL FIX P0-2: Reset running flag on error
    analysisRunning = false;
    // Don't set analysisCompleted - allow retry

    // Report error to background
    // SECURITY FIX P1-4: Use throttled messaging
    sendThrottledMessage({
      type: 'ANALYSIS_ERROR',
      url: window.location.href,
      error: error.message,
      timestamp: new Date().toISOString()
    });

    return { success: false, error: error.message };
  }
}

/**
 * SECURITY FIX P0-3: Proper error handling for overlay injection
 * Injects the reputation overlay script and displays results
 * @param {Object} scoreData - Analysis score data to display
 */
async function injectReputationOverlay(scoreData) {
  // CRITICAL FIX: Check if script already exists before injecting again
  const existingScript = document.querySelector('script[src*="site-reputation-overlay.js"]');

  if (!window.heraReputationOverlay && !existingScript) {
    try {
      const script = document.createElement('script');
      script.src = chrome.runtime.getURL('site-reputation-overlay.js');
      script.id = 'hera-reputation-overlay-script'; // Add ID to prevent duplicates

      // Wait for script to load or fail
      await new Promise((resolve, reject) => {
        script.onload = () => {
          console.log('Hera: Overlay script loaded successfully');

          // Give it a moment to execute and initialize
          setTimeout(() => {
            if (window.heraReputationOverlay) {
              resolve();
            } else {
              // Try manual initialization
              try {
                if (typeof SiteReputationOverlay !== 'undefined') {
                  window.heraReputationOverlay = new SiteReputationOverlay();
                  window.heraReputationOverlay.initialize();
                  console.log('Hera: Overlay manually initialized');
                  resolve();
                } else {
                  reject(new Error('SiteReputationOverlay class not found'));
                }
              } catch (initError) {
                reject(new Error('Manual initialization failed: ' + initError.message));
              }
            }
          }, 100);
        };

        script.onerror = () => {
          reject(new Error('Overlay injection blocked (likely by CSP)'));
        };

        // Inject script
        if (document.head) {
          document.head.appendChild(script);
        } else {
          reject(new Error('No document.head available for overlay injection'));
        }

        // Timeout fallback
        setTimeout(() => reject(new Error('Overlay load timeout')), 3000);
      });

    } catch (error) {
      // P1-SIXTEENTH-1 FIX: Downgrade CSP errors to debug log - expected behavior on protected sites
      const DEBUG = false;
      if (DEBUG) {
        console.log('Hera: Reputation overlay not injected:', error.message);
        console.log('Hera: Overlay injection blocked (likely by CSP)');
      }
      // Continue without overlay - analysis still completed successfully
    }
  }

  // Display reputation if overlay is available
  if (window.heraReputationOverlay) {
    try {
      window.heraReputationOverlay.displayReputation(scoreData);
    } catch (error) {
      console.error('Hera: Failed to display reputation overlay:', error);
    }
  } else {
    console.log('Hera: Analysis complete but overlay unavailable. Results stored in extension.');
  }
}

/**
 * Message handler for manual analysis trigger
 * @param {Object} message - Message from background script
 * @param {Object} sender - Message sender
 * @param {Function} sendResponse - Response callback
 * @returns {boolean} True to keep message channel open
 */
export function handleAnalysisMessage(message, sender, sendResponse) {
  // CRITICAL FIX: Handle PING to check if content script is loaded
  if (message.type === 'PING') {
    sendResponse({ success: true, loaded: true });
    return false;
  }

  if (message.type === 'TRIGGER_ANALYSIS') {
    // CRITICAL FIX NEW-P0-1: Reset completion flag for manual triggers
    console.log('Hera: Manual analysis trigger received');
    analysisCompleted = false; // Allow re-analysis
    analysisRunning = false;   // Reset running flag too
    runComprehensiveAnalysis().then(sendResponse);
    return true; // Keep message channel open for async response
  }

  if (message.type === 'GET_ANALYSIS_STATUS') {
    // Popup asking for status
    sendResponse({ ready: true, url: window.location.href });
    return false;
  }

  return false;
}

/**
 * Auto-run analysis on page load if appropriate
 */
export function autoRunAnalysis() {
  if (shouldRunAnalysis()) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        // Wait a bit for dynamic content to load
        setTimeout(runComprehensiveAnalysis, 1000);
      });
    } else if (document.readyState === 'interactive' || document.readyState === 'complete') {
      // Page already loaded
      setTimeout(runComprehensiveAnalysis, 1000);
    }
  }
}
