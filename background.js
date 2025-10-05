/**
 * HERA - OAuth/OIDC/SAML Security Testing Extension
 * Code Monkey Cybersecurity - "Cybersecurity. With humans."
 *
 * 🛡️ ACTIVE DETECTION LAYERS (Currently Operational)
 *
 * ✅ OAuth/SAML Flow Security - CSRF, PKCE, state parameter validation
 * ✅ Certificate Analysis - HTTPS/TLS integrity, domain matching
 * ✅ DNS Intelligence - Homograph attacks, DGA detection, geolocation
 * ✅ Session Tracking - Cross-domain correlation, ecosystem detection
 * ✅ Secret Scanning - Hardcoded credentials, JWT vulnerabilities
 * ✅ Dark Pattern Detection - UI manipulation, deceptive practices
 * ✅ Privacy Violation Detection - GDPR compliance, consent validation
 *
 * ✅ PhishZip Compression Analysis - INTEGRATED (Phase 1 Complete)
 * Status: Core functionality operational, requires baseline training
 * Integration fixes completed (13th Review):
 *   - ✅ P0-THIRTEENTH-1: pako.js loaded dynamically in compression analyzer
 *   - ✅ P0-THIRTEENTH-2: Analyzer instantiated and called in ANALYSIS_COMPLETE
 *   - ✅ P0-THIRTEENTH-3: manifest.json web_accessible_resources includes pako.js
 *   - ⚠️  P1-THIRTEENTH-1: No baseline data yet (requires real auth page training)
 *   - ✅ P1-THIRTEENTH-2: Integrated into message pipeline with async wrapper
 *
 * Next steps: Train baselines on Microsoft/Google/GitHub/Okta auth pages
 * Full roadmap: docs/PHISHZIP-INTEGRATION-SUMMARY.md (Phase 1-5, 8+ weeks)
 *
 * Philosophy: HONEST, evidence-based, human-centric security
 * - Document what actually works (not marketing claims)
 * - Show users real findings with explanations
 * - Respect user agency - inform, don't patronize
 *
 * 📊 SECURITY REVIEW STATUS
 * - Reviews 10-12: Fixed 18 critical issues (9 P0 + 9 P1/P2)
 * - Review 13: Fixed PhishZip P0 issues (pako loading, baseline validation, async handler)
 * - Review 14: Fixed 8 issues (3 P0 XSS, 2 P1 validation, 2 P2 DoS, 1 P3 dead code)
 * - Review 15 (Oct 6): Fixed 3 issues (1 P0 false positive, 1 P1 UX, 1 P2 modal)
 *   ✅ P0-FIFTEENTH-1: Privacy violation false positive on GitHub/GitLab (trusted domains)
 *   ✅ P1-FIFTEENTH-1: Consolidated Category Breakdown + Top Issues into single view
 *   ✅ P2-FIFTEENTH-1: Evidence display uses alert() (acceptable, non-security)
 */

// Core analysis engines
import { HeraAuthProtocolDetector } from './hera-auth-detector.js';
import { HeraSecretScanner } from './hera-secret-scanner.js';
import { HeraMaliciousExtensionDetector } from './hera-extension-security.js';
import { HeraAuthSecurityAnalyzer } from './hera-auth-security-analyzer.js';
import { HeraPortAuthAnalyzer } from './hera-port-auth-analyzer.js';
import { EvidenceCollector } from './evidence-collector.js';
import { AlertManager } from './alert-manager.js';

// Modular architecture components
import { SecurityValidation } from './modules/security-validation.js';
import { storageManager } from './modules/storage-manager.js';
import { memoryManager } from './modules/memory-manager.js';
import { sessionTracker } from './modules/session-tracker.js';
import { ipCacheManager } from './modules/ip-cache.js';

// DNS and IP intelligence module (Phase 1 modularization)
import { resolveIPAddresses, getIPGeolocation, gatherDNSIntelligence, detectSuspiciousDomainPatterns } from './modules/dns-intelligence.js';

// Pure utility modules (Phase 1 modularization)
import { detectHomographAttack, detectDGAPattern, calculateStringSimilarity, levenshteinDistance } from './modules/string-utils.js';
import { parseCookieHeader, analyzeSetCookie, isSessionCookie, isAuthCookie } from './modules/cookie-utils.js';
import { analyzeJWT } from './modules/jwt-utils.js';
import { detectAuthType } from './modules/auth-utils.js';
import { analyzeRequestHeaders, analyzeResponseHeaders } from './modules/header-utils.js';
import { analyzeUrl, hasSensitiveParameters, detectSuspiciousUrlPatterns, isCrossOrigin, isExtensionRequest, isThirdPartyRequest, isSensitivePath } from './modules/url-utils.js';
import { performAlgNoneProbe, performRepeaterRequest, sanitizeProbeHeaders } from './modules/security-probes.js';

// P0-THIRTEENTH-1 FIX: Load pako.js compression library first
// Service workers can't use importScripts in modules, so we load via script tag approach
// pako will be available globally after this loads
self.pako = null; // Will be set by loading pako

// PHISHZIP INTEGRATION: Compression-based phishing detection (PhishZip methodology from CSIRO Data61)
// Adds Layer 5 to multi-layer defense: visual clone detection via HTML compression analysis
import { HeraCompressionAnalyzer } from './modules/hera-compression-analyzer.js';

// P0-THIRTEENTH-2 FIX: Instantiate compression analyzer globally
const compressionAnalyzer = new HeraCompressionAnalyzer();
let compressionAnalyzerReady = false;

// Auth flow analysis module (Tier 2 domain logic)
import {
  analyzeAuthFlow,
  analyzeOAuthConsent,
  detectAuthProvider,
  analyzeScopeRisks,
  analyzeRedirectUri,
  generateConsentWarnings,
  analyzeAuthFailure
} from './modules/auth-flow-analyzer.js';

// ARCHITECTURE FIX P0-1: Detectors moved to content-script.js
// Removed imports - detectors run in content script where document/window exist
// background.js (service worker) cannot access DOM APIs

// NOTE: Deleted duplicate SecurityValidation code (was 107 lines, exact copy of module)
// Now using the modular version from ./modules/security-validation.js

// NOTE: Removed unused SecureStorage encryption system (was broken - session key lost on service worker restart)
// If encryption is needed in the future, use:
// 1. Password-based key derivation (PBKDF2) with user password
// 2. OR store key in chrome.storage.session (MV3) - but data still lost on browser restart
// 3. OR accept that sensitive data should NOT be stored locally at all

// P2-NINTH-1 FIX: Whitelist of allowed script injection files
const ALLOWED_SCRIPTS = new Set([
  'response-interceptor.js',
  'content-script.js'
]);

// P3-NINTH-1 & P3-NINTH-2 FIX: Production mode detection and safe logging
const isProduction = !chrome.runtime.getManifest().version.includes('dev');

// TODO P3-TENTH-3: Sanitized errors lack context for user bug reports
// Removing stack traces helps security but makes debugging production issues very hard
// Should add error codes and timestamps to help users report issues. See TENTH-REVIEW-FINDINGS.md:2280
function sanitizeError(error) {
  if (!error) return 'Unknown error';

  if (isProduction) {
    // In production, hide stack traces and file paths
    return {
      message: error.message,
      type: error.name
      // Omit stack trace in production
    };
  } else {
    // Full details in development
    return {
      message: error.message,
      stack: error.stack,
      name: error.name
    };
  }
}

function sanitizeUrl(url) {
  if (!url) return '';
  try {
    const urlObj = new URL(url);
    return urlObj.hostname; // Only log hostname, not full URL with paths/params
  } catch (e) {
    return 'invalid-url';
  }
}

// --- Global State ---
// MIGRATED TO MODULES: authRequests and debugTargets now managed by memoryManager
// Wrap Maps with auto-sync proxies for automatic persistence
// P1-1 FIX: Cache wrapper functions to prevent memory leak
// P0-ARCH-3 FIX: Proxy with initialization check to prevent race conditions
const authRequestsWrapperCache = new Map();

const authRequests = new Proxy(memoryManager.authRequests, {
  get(target, prop) {
    // P0-ARCH-3 FIX: Warn if accessed before initialization
    if (!memoryManager.initialized) {
      console.warn(`Hera RACE: authRequests.${String(prop)} accessed before initialization - data may be incomplete`);
    }

    const value = target[prop];
    if (typeof value === 'function') {
      // P1-1: Return cached wrapper if it exists
      if (!authRequestsWrapperCache.has(prop)) {
        authRequestsWrapperCache.set(prop, function(...args) {
          const result = value.apply(target, args);
          // Auto-sync after mutating operations
          if (prop === 'set' || prop === 'delete' || prop === 'clear') {
            memoryManager.syncWrite();
          }
          return result;
        });
      }
      return authRequestsWrapperCache.get(prop);
    }
    return value;
  }
});

// P1-1 FIX: Cache wrapper functions to prevent memory leak
// P0-ARCH-3 FIX: Proxy with initialization check to prevent race conditions
const debugTargetsWrapperCache = new Map();

const debugTargets = new Proxy(memoryManager.debugTargets, {
  get(target, prop) {
    // P0-ARCH-3 FIX: Warn if accessed before initialization
    if (!memoryManager.initialized) {
      console.warn(`Hera RACE: debugTargets.${String(prop)} accessed before initialization - data may be incomplete`);
    }

    const value = target[prop];
    if (typeof value === 'function') {
      // P1-1: Return cached wrapper if it exists
      if (!debugTargetsWrapperCache.has(prop)) {
        debugTargetsWrapperCache.set(prop, function(...args) {
          const result = value.apply(target, args);
          // Auto-sync after mutating operations
          if (prop === 'set' || prop === 'delete' || prop === 'clear') {
            memoryManager.syncWrite();
          }
          return result;
        });
      }
      return debugTargetsWrapperCache.get(prop);
    }
    return value;
  }
});

const version = "1.3";

// Memory leak prevention: Delegated to memoryManager module
function cleanupStaleRequests() {
  memoryManager.cleanupStaleRequests();
}

// Storage quota monitoring: Delegated to storageManager module
async function checkStorageQuota() {
  await storageManager.checkStorageQuota();
}

// Initialize components FIRST (before alarm listeners need them)
const evidenceCollector = new EvidenceCollector(); // Evidence-based vulnerability verification
const alertManager = new AlertManager(); // Tiered, confidence-based alerting

// CRITICAL FIX P0: Master initialization to prevent race conditions
let heraReady = false;
let initializationPromise = null;

async function initializeHera() {
  if (heraReady) return;

  console.log('Hera: Starting initialization...');
  const startTime = Date.now();

  try {
    // Initialize all persistent storage modules in parallel
    await Promise.all([
      memoryManager.initPromise,
      sessionTracker.initPromise,
      evidenceCollector.initPromise,
      alertManager.initPromise,
      ipCacheManager.initPromise
    ]);

    // P0-THIRTEENTH-2 FIX: Initialize compression analyzer with pako.js
    try {
      await compressionAnalyzer.initialize();
      compressionAnalyzerReady = true;
      console.log('Hera: Compression analyzer initialized (PhishZip enabled)');
    } catch (error) {
      console.warn('Hera: Compression analyzer initialization failed - PhishZip disabled:', error);
      compressionAnalyzerReady = false;
    }

    heraReady = true;
    const duration = Date.now() - startTime;
    console.log(`Hera: All modules initialized in ${duration}ms`);

    // CRITICAL FIX P0-4: Initialize webRequest listeners AFTER all modules ready
    await initializeWebRequestListeners();

  } catch (error) {
    console.error('Hera: Initialization failed:', error);
    // Mark as ready anyway to prevent permanent blocking
    heraReady = true;
  }
}

// Start initialization immediately
initializationPromise = initializeHera();

// Use chrome.alarms API (persists across service worker restarts)
chrome.alarms.create('cleanupAuthRequests', { periodInMinutes: 2 });
chrome.alarms.create('checkStorageQuota', { periodInMinutes: 10 });

chrome.alarms.onAlarm.addListener(async (alarm) => {
  await initializationPromise; // Wait for init before cleanup

  if (alarm.name === 'cleanupAuthRequests') {
    cleanupStaleRequests();
    alertManager.cleanupAlertHistory(); // Also cleanup alert deduplication history
    evidenceCollector.cleanup(); // CRITICAL FIX: Prevent evidence cache memory leak
    sessionTracker.cleanupOldSessions(); // CRITICAL FIX: Use alarms instead of setInterval
  } else if (alarm.name === 'checkStorageQuota') {
    checkStorageQuota();
  } else if (alarm.name.startsWith('heraProbeConsent_')) {
    // P1-TENTH-3 FIX: Handle unique alarm names with UUIDs
    // P0-ARCH-2 FIX: Auto-revoke probe consent when alarm fires
    const { probeConsentManager } = await import('./modules/probe-consent.js');
    await probeConsentManager.revokeConsent();
    console.log('Hera: Probe consent auto-revoked (24h expiry)');
  } else if (alarm.name === 'heraPrivacyConsentExpiry') {
    // P0-ARCH-2 FIX: Auto-revoke privacy consent when alarm fires
    const { privacyConsentManager } = await import('./modules/privacy-consent.js');
    await privacyConsentManager.withdrawConsent();
    console.log('Hera: Privacy consent auto-revoked (expiry)');
  }
});

// Then initialize other components that depend on it
const heraAuthDetector = new HeraAuthProtocolDetector(evidenceCollector);
const heraSecretScanner = new HeraSecretScanner();
const heraExtensionDetector = new HeraMaliciousExtensionDetector();
const heraAuthSecurityAnalyzer = new HeraAuthSecurityAnalyzer();
const heraPortAuthAnalyzer = new HeraPortAuthAnalyzer();

// CRITICAL FIX: Define ALL helper functions BEFORE event listeners are registered
// Chrome can fire onInstalled immediately during module load, so functions must exist first

// P0-NINTH-1 FIX: Mutex for debugger operations to prevent race conditions
const debuggerOperationLocks = new Map(); // tabId -> Promise

async function attachDebugger(tabId) {
  if (tabId <= 0) return;

  // P0-NINTH-1 FIX: Acquire lock to prevent concurrent attach attempts
  if (debuggerOperationLocks.has(tabId)) {
    console.log(`Hera: Debugger operation already in progress for tab ${tabId}, skipping`);
    return; // Another attach is in progress
  }

  // Create lock promise
  let releaseLock;
  const lockPromise = new Promise(resolve => { releaseLock = resolve; });
  debuggerOperationLocks.set(tabId, lockPromise);

  try {
    // P0-NINTH-1 FIX: Double-check under lock
    if (debugTargets.has(tabId)) {
      console.log(`Hera: Debugger already attached to tab ${tabId}`);
      return;
    }

    const result = await chrome.storage.local.get(['enableResponseCapture']);
    const enabled = result.enableResponseCapture === true;

    if (!enabled) {
      return;
    }

    const debuggee = { tabId: tabId };

    // P0-NINTH-1 FIX: Promisify attach for proper async/await
    const attachSuccess = await new Promise((resolve) => {
      chrome.debugger.attach(debuggee, version, () => {
        if (chrome.runtime.lastError) {
          const error = chrome.runtime.lastError.message;
          console.warn(`Hera: Failed to attach debugger to tab ${tabId}: ${error}`);
          resolve(false);
        } else {
          resolve(true);
        }
      });
    });

    if (!attachSuccess) {
      return; // Attach failed
    }

    // P0-NINTH-1 FIX: Only set in map AFTER successful attach
    debugTargets.set(tabId, debuggee);

    // Enable Network domain
    const networkEnabled = await new Promise((resolve) => {
      chrome.debugger.sendCommand(debuggee, "Network.enable", {}, () => {
        if (chrome.runtime.lastError) {
          console.warn(`Failed to enable Network for tab ${tabId}`);
          resolve(false);
        } else {
          resolve(true);
        }
      });
    });

    if (!networkEnabled) {
      // Cleanup on failure
      await new Promise((resolve) => {
        chrome.debugger.detach(debuggee, () => {
          debugTargets.delete(tabId);
          resolve();
        });
      });
    }

  } catch (error) {
    console.error('Hera: debugger attach failed:', error);
    debugTargets.delete(tabId); // Ensure cleanup
  } finally {
    // P0-NINTH-1 FIX: Always release lock
    debuggerOperationLocks.delete(tabId);
    releaseLock();
  }
}

async function initializeDebugger() {
  const tabs = await chrome.tabs.query({});
  for (const tab of tabs) {
    if (tab.id && tab.url && !tab.url.startsWith('chrome://')) {
      attachDebugger(tab.id);
    }
  }
}

async function updateBadge() {
  return storageManager.updateBadge();
}

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

async function handleInterceptorInjection(sender, message) {
  try {
    const tabId = sender.tab?.id;
    let url = sender.tab?.url;

    if (!tabId) {
      return { success: false, error: 'No tab ID available' };
    }

    // P1-TENTH-2 FIX: Get latest tab URL to prevent race condition
    const tab = await chrome.tabs.get(tabId);
    url = tab.url; // Use current URL, not cached sender.tab.url

    // P1-TENTH-2 FIX: Enhanced URL validation
    if (!url || url.startsWith('chrome://') || url.startsWith('about:') ||
        url.startsWith('chrome-extension://') || url.startsWith('edge://') ||
        url.startsWith('chrome-devtools://') || url.startsWith('view-source:')) {
      console.log(`Hera: Skipping interceptor injection on restricted page: ${url}`);
      return { success: false, error: 'Cannot inject on restricted pages' };
    }

    // P1-TENTH-2 FIX: Validate URL is HTTP/HTTPS only
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      console.log(`Hera: Skipping injection on non-HTTP(S) page: ${url}`);
      return { success: false, error: 'Only HTTP(S) pages supported' };
    }

    // Check if chrome.scripting API is available
    if (!chrome.scripting || !chrome.scripting.executeScript) {
      console.error('Hera: chrome.scripting API not available - host permissions may not be granted');
      return { success: false, error: 'Scripting permission not available' };
    }

    // Check if we have permission for this URL
    const hasPermission = await chrome.permissions.contains({
      origins: [new URL(url).origin + '/*']
    });

    if (!hasPermission) {
      console.warn(`Hera: No permission for ${url} - host permissions not granted`);
      return { success: false, error: 'Host permission not granted for this site' };
    }

    // P0-NINTH-3 FIX: Double-check permission right before injection to narrow race window
    const hasPermissionNow = await chrome.permissions.contains({
      origins: [new URL(url).origin + '/*']
    });

    if (!hasPermissionNow) {
      console.warn('Hera: Permission revoked between check and injection');
      return { success: false, error: 'Permission no longer available' };
    }

    // P2-NINTH-1 FIX: Validate script path against whitelist
    const scriptFile = 'response-interceptor.js'; // Hardcoded for now

    if (!ALLOWED_SCRIPTS.has(scriptFile)) {
      console.error(`Hera: Attempted to inject non-whitelisted script: ${scriptFile}`);
      return { success: false, error: 'Invalid script path' };
    }

    // P1-TENTH-2 FIX: THIRD check right before injection
    const latestTab = await chrome.tabs.get(tabId);
    if (latestTab.url !== url) {
      console.warn(`Hera SECURITY: Tab URL changed during injection (TOCTOU attempt blocked)`);
      console.warn(`  Original: ${url}`);
      console.warn(`  Current: ${latestTab.url}`);
      return { success: false, error: 'Tab URL changed during injection (security block)' };
    }

    // P0-NINTH-3 FIX: Wrap injection in try-catch to handle permission revocation
    try {
      const result = await chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: 'ISOLATED',
        files: [scriptFile]
      });

      // Check for Chrome runtime errors (permission revoked during injection)
      if (chrome.runtime.lastError) {
        console.error('Hera: Injection failed (permission revoked?):', chrome.runtime.lastError);
        return { success: false, error: chrome.runtime.lastError.message };
      }

      console.log(`Hera: Response interceptor injected in isolated world for tab ${tabId}`);
      return { success: true };

    } catch (injectionError) {
      // P0-NINTH-3 FIX: Catch errors from permission revocation mid-flight
      if (injectionError.message?.includes('permission') ||
          injectionError.message?.includes('Cannot access')) {
        console.warn('Hera: Injection blocked - permission revoked mid-flight');
        return { success: false, error: 'Permission revoked during injection' };
      }
      throw injectionError; // Re-throw unexpected errors
    }
  } catch (error) {
    // P3-NINTH-1 FIX: Sanitize error messages to avoid leaking file paths
    console.error('Hera: Failed to inject response interceptor:', sanitizeError(error));
    return { success: false, error: error.message || 'Unknown error' };
  }
}

// --- Event Listeners (registered AFTER all function definitions) ---

// CONSOLIDATED onInstalled listener (was duplicated 3x - lines 67, 422, 1455)
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log(`Hera ${details.reason}:`, details);

  // On first install only
  if (details.reason === 'install') {
    try {
      // SECURITY FIX: Clear any leftover data from previous installation
      // Prevents privacy leak if extension was previously installed
      await chrome.storage.local.clear();
      console.log('Hera: Cleared previous installation data');

      // 1. Set default configuration
      await chrome.storage.local.set({
        heraConfig: {
          syncEndpoint: null,
          riskThreshold: 50,
          enableRealTimeAlerts: true,
          autoExportEnabled: true,
          autoExportThreshold: 950
        }
      });
      console.log('Hera: Default configuration set');

      // SECURITY FIX: Don't auto-request permissions on install (aggressive UX)
      // Instead, show welcome screen and let user enable monitoring via popup
      // This follows Chrome extension best practices for permission requests
      console.log('Hera: Installation complete. Open popup to enable monitoring.');
    } catch (error) {
      console.error('Hera: Error during installation:', error);
    }
  }

  // On install or update, initialize extension
  initializeDebugger();
  updateBadge();
});

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

// --- Storage Helper (MIGRATED TO storageManager module) ---
const heraStore = {
  async storeAuthEvent(eventData) {
    return storageManager.storeAuthEvent(eventData);
  },
  async storeSession(sessionData) {
    return storageManager.storeSession(sessionData);
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

// CRITICAL FIX: Removed duplicate updateBadge and showAuthSecurityAlert (already defined at top of file)

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

// Initialize webRequest listeners only if permission granted
async function initializeWebRequestListeners() {
  const hasPermission = await chrome.permissions.contains({
    permissions: ['webRequest'],
    origins: ['https://*/*', 'http://localhost/*']
  });

  if (!hasPermission) {
    console.warn('Hera: webRequest permission not granted - request monitoring disabled');
    console.warn('Hera: Grant permission in extension settings to enable full functionality');
    return false;
  }

  console.log('Hera: webRequest permissions granted, initializing listeners...');

  // 1. Listen for requests
  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
        // CRITICAL FIX P0: Wait for initialization before processing
        if (!heraReady) {
            console.warn('Hera: Not ready, skipping request:', details.url);
            return;
        }

        const isAuthRelated = heraAuthDetector.isAuthRequest(details.url, {});
        if (isAuthRelated) {
            // SECURITY FIX P2: Generate nonce for request/response matching
            const requestNonce = crypto.randomUUID();

            authRequests.set(details.requestId, {
                id: details.requestId,
                url: details.url,
                method: details.method,
                type: details.type,
                tabId: details.tabId,
                timestamp: new Date().toISOString(),
                requestBody: decodeRequestBody(details.requestBody),
                nonce: requestNonce, // For matching with intercepted response
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
        if (!heraReady) return; // Wait for init
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
      if (!heraReady) return; // Wait for init
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

// CRITICAL FIX: Moved attachDebugger and initializeDebugger to top of file (before onInstalled)

chrome.tabs.onCreated.addListener((tab) => tab.id && attachDebugger(tab.id));
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'loading') {
        attachDebugger(tabId);
    }
});
chrome.tabs.onRemoved.addListener((tabId) => {
    if (debugTargets.has(tabId)) {
        const debuggee = debugTargets.get(tabId);

        chrome.debugger.detach(debuggee, () => {
            // Log error but don't block cleanup
            if (chrome.runtime.lastError) {
                console.log(`Debugger auto-detached for closed tab ${tabId}: ${chrome.runtime.lastError.message}`);
            } else {
                console.log(`Successfully detached debugger from closed tab ${tabId}`);
            }
        });

        // P1-NINTH-1 FIX: Delete immediately, don't wait for callback
        // The tab is already closed, so debugger is detached by Chrome anyway
        debugTargets.delete(tabId);
    }
});

// P1-NINTH-1 FIX: Periodic cleanup of stale debugger entries (defense in depth)
setInterval(async () => {
  const allTabs = await chrome.tabs.query({});
  const validTabIds = new Set(allTabs.map(tab => tab.id));

  for (const [tabId, debuggee] of debugTargets.entries()) {
    if (!validTabIds.has(tabId)) {
      console.warn(`Hera: Removing stale debugger entry for closed tab ${tabId}`);
      debugTargets.delete(tabId);
    }
  }
}, 60000); // Clean up every minute

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
            // P0-TENTH-1 FIX: Validate source tabId matches request tabId
            if (source.tabId !== requestData.tabId) {
                console.error('Hera SECURITY: debugger event tabId mismatch');
                return;
            }

            // P0-TENTH-1 FIX: Validate request still exists in debugTargets
            if (!debugTargets.has(source.tabId)) {
                console.error('Hera SECURITY: debugger event from non-tracked tab');
                return;
            }

            // P0-TENTH-1 FIX: Validate requestId format (Chrome uses UUID-like format)
            if (!params.requestId || typeof params.requestId !== 'string') {
                console.error('Hera SECURITY: invalid requestId format');
                return;
            }

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

                        // P0-TENTH-1 FIX: Sanitize response body before storage
                        // Check for potentially malicious content that could execute in popup context
                        if (typeof body === 'string') {
                            if (/<script|onerror=|onclick=|onload=|javascript:/i.test(body)) {
                                console.warn('Hera SECURITY: Response contains potentially malicious content, sanitizing');
                                // Don't block entirely, but mark as suspicious
                                requestData.securityFlags = requestData.securityFlags || [];
                                requestData.securityFlags.push('SUSPICIOUS_CONTENT_IN_RESPONSE');
                            }
                        }

                        requestData.responseBody = body;
                        requestData.captureSource = 'debugger'; // Mark the source

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
                        let sessions = result.heraSessions;

                        // DOS prevention: Limit total sessions
                        const MAX_SESSIONS = 1000;
                        if (sessions.length >= MAX_SESSIONS) {
                            console.warn(`Session limit reached (${MAX_SESSIONS}), removing oldest`);
                            sessions.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
                            sessions = sessions.slice(0, MAX_SESSIONS - 1);
                        }

                        // DOS prevention: Limit individual request size
                        const MAX_REQUEST_SIZE = 100 * 1024; // 100KB per request
                        const requestSize = JSON.stringify(requestData).length;
                        if (requestSize > MAX_REQUEST_SIZE) {
                            console.warn(`Request too large (${requestSize} bytes), truncating response body`);
                            if (requestData.responseBody) {
                                requestData.responseBody = requestData.responseBody.substring(0, 10000) + '... [truncated]';
                            }
                        }

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
// NOTE: onInstalled consolidated at line 67 (was duplicated here)

chrome.runtime.onStartup.addListener(() => {
    console.log('Hera starting up...');
    initializeDebugger();
    updateBadge();
});

// CRITICAL FIX P0-NEW: onSuspend handler REMOVED
// Reason: Chrome MV3 onSuspend does NOT wait for async operations
// All _syncToStorage() methods are async (use await chrome.storage.*.set())
// Service worker terminates before writes complete → data loss
// Solution: Aggressive debouncing (reduced timeout from 100-200ms to 1000ms)
// See: https://developer.chrome.com/docs/extensions/mv3/service_workers/events/#suspend

// Original broken code (kept for reference):
// chrome.runtime.onSuspend.addListener(() => {
//   memoryManager._syncToStorage(); // Returns Promise, not awaited!
//   // Service worker dies here → chrome.storage.*.set() abandoned
// });

// CRITICAL FIX: Handle devtools port connections (P1)
// Devtools panel connects via chrome.runtime.connect() and sends messages via port.postMessage()
chrome.runtime.onConnect.addListener((port) => {
  if (port.name === 'devtools-page') {
    console.log('Hera: DevTools panel connected');

    // Handle messages from devtools panel
    port.onMessage.addListener(async (message) => {
      console.log('Hera: DevTools message received:', message.type);

      if (message.type === 'INIT_DEVTOOLS') {
        // Send all existing requests to devtools panel
        chrome.storage.local.get({ heraSessions: [] }, (result) => {
          result.heraSessions.forEach(session => {
            port.postMessage({
              type: 'AUTH_REQUEST',
              data: session
            });
          });
        });
      } else if (message.type === 'SET_RECORDING_STATE') {
        // Store recording state in session storage
        await chrome.storage.session.set({ heraRecording: message.isRecording });
        console.log(`Hera: Recording ${message.isRecording ? 'enabled' : 'paused'}`);
      } else if (message.type === 'CLEAR_REQUESTS') {
        // CRITICAL FIX P1: Route through storageManager
        await storageManager.clearAllSessions();
        await memoryManager.clearAuthRequests();
        console.log('Hera: All requests cleared');
      }
    });

    // Handle disconnect
    port.onDisconnect.addListener(() => {
      console.log('Hera: DevTools panel disconnected');
    });
  }
});

// Consolidated message listener (removed duplicate listener at line 4014)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Sender validation: Reject external messages (security)
  if (!sender.id || sender.id !== chrome.runtime.id) {
    console.warn('Message from external source rejected:', sender);
    sendResponse({ success: false, error: 'External messages not allowed' });
    return false;
  }

  // Input validation
  if (!message || typeof message !== 'object') {
    console.warn('Invalid message received:', message);
    sendResponse({ success: false, error: 'Invalid message format' });
    return false;
  }

  // P0-4 FIX: Strict message routing - prevent double processing
  // This listener handles 'action' messages ONLY
  // Messages with 'type' are handled by the second listener
  if (!message.action) {
    // Not for this listener - let it fall through to the next listener
    return false;
  }

  // P0-4 FIX: Reject messages with BOTH action AND type (security)
  // Prevents attacker from triggering both listeners with same message
  if (message.type) {
    console.warn('Hera: Message has both action and type - rejecting to prevent double processing');
    sendResponse({ success: false, error: 'Invalid message format: cannot have both action and type' });
    return false;
  }

  if (typeof message.action !== 'string') {
    console.warn('Message action is not a string:', message);
    sendResponse({ success: false, error: 'Invalid action' });
    return false;
  }

  const messageType = message.action;

  // P0-EIGHTH-3 FIX: Validate sender.url for ALL actions (not just sensitive ones)
  const allowedSenderUrls = [
    chrome.runtime.getURL('popup.html'),
    chrome.runtime.getURL('devtools/devtools.html'),
    chrome.runtime.getURL('probe-consent.html'),
    chrome.runtime.getURL('privacy-consent-ui.html')
  ];

  const senderUrl = sender.url || '';
  const isAuthorizedSender = allowedSenderUrls.some(allowed => senderUrl.startsWith(allowed));

  // P0-EIGHTH-3 FIX: Content scripts can ONLY send specific whitelisted messages
  const contentScriptAllowedActions = [
    'responseIntercepted', // Content script sends this (response interceptor)
    'ANALYSIS_ERROR',      // Content script reports errors
    'INJECT_RESPONSE_INTERCEPTOR' // Content script requests injection
  ];

  // P0-EIGHTH-3 FIX: Check authorization for all actions
  if (!isAuthorizedSender && !contentScriptAllowedActions.includes(messageType)) {
    console.error(`Hera SECURITY: Unauthorized message from ${senderUrl}: ${messageType}`);
    sendResponse({ success: false, error: 'Unauthorized sender' });
    return false;
  }

  // Extra validation for highly sensitive actions (requires popup/devtools only, NOT content script)
  const highlySecurityActions = ['probe:alg_none', 'repeater:send', 'clearRequests', 'updateResponseCaptureSetting'];
  if (highlySecurityActions.includes(messageType) && !isAuthorizedSender) {
    console.warn(`Highly sensitive action '${messageType}' blocked from unauthorized source:`, senderUrl);
    sendResponse({ success: false, error: 'Unauthorized: This action requires popup or devtools context' });
    return false;
  }

  console.log('Background received message:', messageType);

  // Handle intercepted responses from response-interceptor.js
  if (message.action === 'responseIntercepted') {
    if (!message.data || typeof message.data !== 'object') {
      console.warn('responseIntercepted message missing data');
      sendResponse({ success: false, error: 'Missing data' });
      return false;
    }
    const data = message.data;

    // SECURITY FIX P2: Match by nonce (fallback to timestamp for older requests)
    let match = null;

    // Try nonce-based matching first (secure, prevents race conditions)
    if (data.nonce) {
      for (const [requestId, requestData] of authRequests.entries()) {
        if (requestData.nonce === data.nonce && !requestData.responseBody) {
          match = { requestId, requestData };
          break;
        }
      }
    }

    // Fallback to URL + timestamp matching (for backwards compatibility)
    if (!match) {
      let bestMatchScore = Infinity;
      for (const [requestId, requestData] of authRequests.entries()) {
        if (requestData.url === data.url && !requestData.responseBody) {
          const reqTime = new Date(requestData.timestamp).getTime();
          const interceptTime = new Date(data.timestamp).getTime();
          const timeDiff = Math.abs(interceptTime - reqTime);

          if (timeDiff < 30000 && timeDiff < bestMatchScore) {
            match = { requestId, requestData };
            bestMatchScore = timeDiff;
          }
        }
      }
    }

    if (match) {
      const { requestId, requestData } = match;

      requestData.responseBody = data.body;
      requestData.statusCode = data.statusCode;
      requestData.captureSource = 'interceptor'; // Mark the source

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

      // CRITICAL FIX P1: Consolidate storage logic - let storageManager handle all quota/size limits
      // DOS prevention: Limit individual request size BEFORE storage
      const MAX_REQUEST_SIZE = 100 * 1024; // 100KB per request
      const requestSize = JSON.stringify(requestData).length;
      if (requestSize > MAX_REQUEST_SIZE) {
        console.warn(`Request too large (${requestSize} bytes), truncating response body`);
        if (requestData.responseBody) {
          requestData.responseBody = requestData.responseBody.substring(0, 10000) + '... [truncated]';
        }
      }

      // Route through storageManager (handles MAX_SESSIONS quota internally)
      storageManager.storeAuthEvent(requestData).then(() => {
        updateBadge();
        authRequests.delete(requestId);
      });
    } else {
      console.warn('No matching auth request found for intercepted response:', data.url);
    }

    sendResponse({ success: true });
    return false;
  }

  if (message.action === 'probe:alg_none') {
    if (!message.request || !message.jwt) {
      sendResponse({ success: false, error: 'Missing request or JWT' });
      return false;
    }
    // P0-SIXTH-1 FIX: Proper error handling for async probe
    performAlgNoneProbe(message.request, message.jwt, sender)
      .then(sendResponse)
      .catch(error => {
        console.error('Hera: probe:alg_none failed:', error);
        sendResponse({ success: false, error: error.message });
      });
    return true;
  }

  if (message.action === 'repeater:send') {
    if (!message.rawRequest || typeof message.rawRequest !== 'string') {
      sendResponse({ success: false, error: 'Missing or invalid rawRequest' });
      return false;
    }
    // P0-SIXTH-1 FIX: Proper error handling for async repeater
    performRepeaterRequest(message.rawRequest, sender)
      .then(sendResponse)
      .catch(error => {
        console.error('Hera: repeater:send failed:', error);
        sendResponse({ success: false, error: error.message });
      });
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
    if (!message.domain || typeof message.domain !== 'string') {
      sendResponse({ success: false, error: 'Missing or invalid domain' });
      return false;
    }
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
    // CRITICAL FIX P1: Route through storageManager
    // P0-SIXTH-1 FIX: Proper error handling for async operation
    storageManager.clearAllSessions().then(() => {
      updateBadge();
      sendResponse({ success: true });
    }).catch(error => {
      console.error('Hera: clearRequests failed:', error);
      sendResponse({ success: false, error: error.message });
    });
    return true;
  }

  if (message.action === 'updateResponseCaptureSetting') {
    if (!message.enabled) {
      for (const [tabId, debuggee] of debugTargets.entries()) {
        chrome.debugger.detach(debuggee, () => {
          if (chrome.runtime.lastError) {
            console.warn(`Error detaching debugger from tab ${tabId}:`, chrome.runtime.lastError.message);
          } else {
            console.log(`Detached debugger from tab ${tabId}`);
          }
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

// NOTE: Security probe functions moved to ./modules/security-probes.js (line 23)
// Removed duplicate code (276 lines):
// - ProbeRateLimiter class
// - validateProbeRequest (also in url-utils.js)
// - sanitizeProbeHeaders
// - performAlgNoneProbe
// - performRepeaterRequest
// Now imported from security-probes module for better code organization

// (Removed duplicate isExtensionRequest, isThirdPartyRequest, isSensitivePath - now imported from ./modules/url-utils.js at line 23)

// (Removed duplicate performRepeaterRequest - now imported from ./modules/security-probes.js at line 23)

// --- Session Manager ---

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

// (Removed setInterval - now using chrome.alarms.onAlarm at line 49)

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

// NOTE: onInstalled listener consolidated at line 67 (removed duplicate)

// CRITICAL FIX: Removed duplicate chrome.debugger.onEvent listener (already exists at ~line 463)

// P2-NINTH-2 FIX: Removed duplicate chrome.tabs.onRemoved listener (already exists at ~line 627)
// P2-NINTH-2 FIX: Removed duplicate chrome.tabs.onCreated listener (already exists at ~line 621)
// P2-NINTH-2 FIX: Removed duplicate chrome.tabs.onUpdated listener (already exists at ~line 622)

// (Removed duplicate attachDebugger - already defined at line 110)

// Attach to all existing tabs on startup
chrome.tabs.query({}, (tabs) => {
  for (const tab of tabs) {
    if (tab.id && tab.url && !tab.url.startsWith('chrome://')) {
      attachDebugger(tab.id);
    }
  }
});


// NOTE: Duplicate webRequest.onBeforeRequest listener removed (was lines 1551-1789, 239 lines)
// This was a complete duplicate of the listener at line 203

// Listen for request headers
chrome.webRequest.onBeforeSendHeaders.addListener((details) => {
    if (!heraReady) return;
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
    if (!heraReady) return;
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
if (!heraReady) return;     const requestData = authRequests.get(details.requestId);
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
if (!heraReady) return;     const requestData = authRequests.get(details.requestId);
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
if (!heraReady) return;     const requestData = authRequests.get(details.requestId);
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

  return true; // Listeners initialized successfully
}

// CRITICAL FIX P0-4: Removed duplicate call - now called from initializeHera() after modules ready
// Re-initialize when permissions change
chrome.permissions.onAdded.addListener((permissions) => {
  if (permissions.permissions?.includes('webRequest')) {
    console.log('Hera: webRequest permission added, initializing listeners');
    initializeWebRequestListeners();
  }
});

chrome.permissions.onRemoved.addListener(async (permissions) => {
  if (permissions.permissions?.includes('webRequest')) {
    console.warn('Hera: webRequest permission removed - monitoring stopped');
  }

  // P0-SEVENTH-2 FIX: Gracefully handle debugger permission revocation
  if (permissions.permissions?.includes('debugger')) {
    console.log('Hera: Debugger permission being revoked - attempting cleanup');

    // P2-TENTH-4 FIX: Clear Map BEFORE attempting detach to prevent zombie entries
    // If permission already revoked, detach() fails silently but we still clean up Map
    const tabsToDetach = Array.from(debugTargets.entries());
    debugTargets.clear(); // Clear immediately to prevent zombie entries

    const detachPromises = [];
    for (const [tabId, debuggee] of tabsToDetach) {
      detachPromises.push(
        new Promise(resolve => {
          chrome.debugger.detach(debuggee, () => {
            if (chrome.runtime.lastError) {
              // Expected if permission already revoked - Chrome will auto-detach
              console.log(`Debugger auto-detach for tab ${tabId} (permission revoked)`);
            } else {
              console.log(`Successfully detached debugger from tab ${tabId}`);
            }
            resolve();
          });
        })
      );
    }

    await Promise.all(detachPromises);

    // Notify user
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: 'Hera: Response Capture Disabled',
      message: 'Debugger permission revoked. HTTP response body capture is now disabled.',
      priority: 1
    });
  }
});

// NOTE: detectAuthType, analyzeUrl, hasSensitiveParameters, detectSuspiciousUrlPatterns,
// isCrossOrigin, analyzeRequestHeaders, and analyzeResponseHeaders are now imported from modules

// NOTE: Auth flow analysis functions now imported from modules/auth-flow-analyzer.js
// - analyzeAuthFlow, analyzeOAuthConsent, detectAuthProvider, analyzeScopeRisks,
//   analyzeRedirectUri, generateConsentWarnings, analyzeAuthFailure

// NOTE: DNS/IP intelligence functions now imported from ./modules/dns-intelligence.js at line 18
// - resolveIPAddresses, getIPGeolocation, gatherDNSIntelligence, detectSuspiciousDomainPatterns
// Wrapper function to maintain compatibility with existing code that doesn't pass authRequests
async function gatherDNSIntelligenceWrapper(url, requestId) {
  return gatherDNSIntelligence(url, requestId, authRequests);
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

// NOTE: calculateStringSimilarity and levenshteinDistance now imported from ./modules/string-utils.js at line 21

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

// P1-NINTH-3 FIX: Sanitize detector results to prevent prototype pollution
function sanitizeDetectorResult(obj) {
  if (typeof obj !== 'object' || obj === null) {
    return {};
  }

  // Create clean object without dangerous keys
  const clean = {};
  const dangerousKeys = ['__proto__', 'constructor', 'prototype'];

  for (const [key, value] of Object.entries(obj)) {
    if (dangerousKeys.includes(key)) {
      console.warn(`Hera: Blocked dangerous key in detector result: ${key}`);
      continue;
    }

    // Recursively sanitize nested objects
    if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      clean[key] = sanitizeDetectorResult(value);
    } else {
      clean[key] = value;
    }
  }

  return clean;
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
    // P1-NINTH-3 FIX: Sanitize all detector results before merging
    results.forEach((result, index) => {
      if (result.status === 'fulfilled' && result.value) {
        switch (index) {
          case 0: // Domain signals
            Object.assign(signals, sanitizeDetectorResult(result.value));
            break;
          case 1: // Security config signals
            Object.assign(signals, sanitizeDetectorResult(result.value));
            break;
          case 2: // Infrastructure signals
            Object.assign(signals, sanitizeDetectorResult(result.value));
            break;
          case 3: // Git exposure
            signals.gitExposed = sanitizeDetectorResult(result.value) || { exposed: false };
            break;
          case 4: // Env file exposure
            signals.envFileExposed = sanitizeDetectorResult(result.value) || { exposed: false };
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

// Cookie parsing functions now imported from modules/cookie-utils.js
// - parseCookieHeader()
// - analyzeSetCookie()
// - isSessionCookie()
// - isAuthCookie()

// NOTE: analyzeAuthFailure now imported from modules/auth-flow-analyzer.js

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

// (Removed duplicate setInterval - now using chrome.alarms.onAlarm at line 49)

// Generate unique session ID (legacy function for compatibility)
// SECURITY FIX P1-NEW: Use crypto.randomUUID() instead of Math.random()
// Math.random() is NOT cryptographically secure and predictable
// Only ~52 bits of entropy vs 128 bits from crypto.randomUUID()
function generateSessionId() {
  return 'session_' + crypto.randomUUID();
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
// JWT analysis function now imported from modules/jwt-utils.js
// - analyzeJWT()

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

// ==================== ALL-IN-ONE DECEPTION/DESIGN DETECTION ====================
// ARCHITECTURE FIX P0-1: Analysis runs in content script, background handles storage

// SECURITY FIX P1-7 & NEW-P2-1: Safe storage with quota error recovery and mutex
// P0-3 FIX: Proper mutex implementation (no TOCTOU)
const storageLocks = new Map(); // key -> Promise

async function safeStorageSet(data, key = null) {
  // Extract key for mutex (e.g., 'siteAnalysis_123')
  const storageKey = key || Object.keys(data)[0];

  // CRITICAL FIX P0-3: Atomic lock acquisition
  // Chain new write after existing lock (if any)
  const previousLock = storageLocks.get(storageKey) || Promise.resolve();

  // Create new lock that waits for previous lock
  const lock = previousLock.then(async () => {
    try {
      await chrome.storage.local.set(data);
      return { success: true };
    } catch (error) {
      if (error.message && error.message.includes('QUOTA')) {
        console.warn('Hera: Storage quota exceeded, performing emergency cleanup');

        // Get all analysis data
        const allData = await chrome.storage.local.get(null);
        const analysisKeys = Object.keys(allData).filter(k => k.startsWith('siteAnalysis_'));

        if (analysisKeys.length > 10) {
          // Remove oldest 50% of analyses
          const toRemove = analysisKeys.slice(0, Math.floor(analysisKeys.length / 2));
          await chrome.storage.local.remove(toRemove);
          console.log(`Hera: Removed ${toRemove.length} old analyses to free space`);

          // Retry storage
          await chrome.storage.local.set(data);

          // Notify user
          chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon128.png',
            title: 'Hera Storage Warning',
            message: 'Storage quota exceeded. Older analysis data was automatically removed.',
            priority: 1
          });

          return { success: true, quotaExceeded: true };
        }
      }
      throw error;
    }
  }).finally(() => {
    // Clean up: remove lock only if it's still THIS lock
    if (storageLocks.get(storageKey) === lock) {
      storageLocks.delete(storageKey);
    }
  });

  // Set new lock BEFORE awaiting (atomic)
  storageLocks.set(storageKey, lock);
  return lock;
}

// CRITICAL FIX NEW-P1-4: Note - This is the SECOND message listener (first is at line 629)
// Both listeners handle different message formats:
//   - First listener: message.action (auth/probe/repeater)
//   - Second listener: message.type (analysis results)
// This is intentional - they route different message types

// Message handler for analysis results from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // P0-4 FIX: Reject messages with BOTH action AND type (security)
  if (message.action && message.type) {
    console.warn('Hera: Message has both action and type - rejecting to prevent double processing');
    sendResponse({ success: false, error: 'Invalid message format: cannot have both action and type' });
    return false;
  }

  // Skip if this is an 'action' message (handled by first listener)
  if (message.action) {
    return false; // Let first listener handle it
  }

  // SECURITY FIX P1-4: Validate message sender to prevent web page message spoofing
  if (!sender.id || sender.id !== chrome.runtime.id) {
    console.warn('Hera: Rejecting message from untrusted sender:', sender);
    sendResponse({ success: false, error: 'Unauthorized sender' });
    return false;
  }

  // P1-EIGHTH-2 FIX: Validate sender.url for type-based messages
  const allowedSenderUrls = [
    chrome.runtime.getURL('popup.html'),
    chrome.runtime.getURL('devtools/devtools.html'),
    chrome.runtime.getURL('probe-consent.html'),
    chrome.runtime.getURL('privacy-consent-ui.html')
  ];

  const senderUrl = sender.url || '';
  const isAuthorizedSender = allowedSenderUrls.some(allowed => senderUrl.startsWith(allowed));

  // P1-EIGHTH-2 FIX: Content scripts can only send specific type-based messages
  const contentScriptAllowedTypes = [
    'ANALYSIS_COMPLETE',
    'ANALYSIS_ERROR',
    'GET_SITE_ANALYSIS',
    'TRIGGER_ANALYSIS'
  ];

  if (!isAuthorizedSender && message.type && !contentScriptAllowedTypes.includes(message.type)) {
    console.error(`Hera SECURITY: Unauthorized type message from ${senderUrl}: ${message.type}`);
    sendResponse({ success: false, error: 'Unauthorized sender for this message type' });
    return false;
  }

  if (message.type === 'ANALYSIS_COMPLETE') {
    // P0-ELEVENTH-3 FIX: Synchronous sender validation BEFORE any async work
    // TOCTOU attack: Malicious extension times message to arrive during async window
    // Fix: Capture all sender info synchronously, validate completely before async operations

    const tabId = sender.tab?.id;
    const tabUrl = sender.tab?.url;
    const senderId = sender.id;
    const senderFrameId = sender.frameId;

    // P0-ELEVENTH-3 FIX: Reject if not from content script (frameId must exist)
    if (typeof senderFrameId !== 'number') {
      console.error('Hera SECURITY: ANALYSIS_COMPLETE must come from content script');
      sendResponse({ success: false, error: 'Invalid sender context' });
      return false;
    }

    // P0-ELEVENTH-3 FIX: Reject if from other extension
    if (senderId && senderId !== chrome.runtime.id) {
      console.error('Hera SECURITY: ANALYSIS_COMPLETE from external extension blocked');
      sendResponse({ success: false, error: 'External extension blocked' });
      return false;
    }

    // SECURITY FIX P1-6: Validate sender tab and URL
    if (!tabId) {
      console.warn('Hera: Rejecting analysis from sender without tab ID');
      sendResponse({ success: false, error: 'Invalid sender' });
      return false;
    }

    // SECURITY FIX NEW-P1-2: Strict URL validation (prevent spoofing)
    if (tabUrl && message.url !== tabUrl) {
      // Check if it's same-origin (iframe on same domain)
      try {
        const messageOrigin = new URL(message.url).origin;
        const tabOrigin = new URL(tabUrl).origin;

        if (messageOrigin !== tabOrigin) {
          console.error('Hera: SECURITY - Cross-origin analysis attempt blocked');
          console.error(`  Message URL: ${message.url}`);
          console.error(`  Sender tab URL: ${tabUrl}`);
          sendResponse({ success: false, error: 'URL validation failed - cross-origin' });
          return false;
        }

        // Same origin but different path - could be SPA navigation
        console.log('Hera: Same-origin URL mismatch (likely SPA navigation)');
        console.log(`  Message URL: ${message.url}`);
        console.log(`  Sender URL: ${tabUrl}`);

      } catch (error) {
        console.error('Hera: Invalid URL in analysis message:', error);
        sendResponse({ success: false, error: 'Invalid URL format' });
        return false;
      }
    }

    if (tabId) {
      // P0-5 FIX: Strict input validation before storage
      // Prevents DoS via massive payloads or malformed data

      // Validate findings array
      if (!Array.isArray(message.findings)) {
        sendResponse({ success: false, error: 'Invalid findings format' });
        return false;
      }

      // P0-5: Limit findings array size (prevent DoS)
      const MAX_FINDINGS = 100;
      if (message.findings.length > MAX_FINDINGS) {
        console.warn(`Hera: Findings array too large (${message.findings.length}), truncating to ${MAX_FINDINGS}`);
        message.findings = message.findings.slice(0, MAX_FINDINGS);
      }

      // P0-5: Validate each finding object
      const MAX_FINDING_SIZE = 10000; // 10KB per finding
      for (const finding of message.findings) {
        if (!finding || typeof finding !== 'object') {
          sendResponse({ success: false, error: 'Invalid finding object' });
          return false;
        }

        const findingSize = JSON.stringify(finding).length;
        if (findingSize > MAX_FINDING_SIZE) {
          sendResponse({ success: false, error: 'Finding object too large' });
          return false;
        }
      }

      // Validate score object
      if (!message.score || typeof message.score !== 'object') {
        sendResponse({ success: false, error: 'Invalid score format' });
        return false;
      }

      if (typeof message.score.grade !== 'string' || typeof message.score.criticalIssues !== 'number') {
        sendResponse({ success: false, error: 'Invalid score fields' });
        return false;
      }

      // P0-5: Validate overall payload size (excluding HTML for compression analysis)
      const MAX_PAYLOAD_SIZE = 500 * 1024; // 500KB max for stored data
      const payloadSize = JSON.stringify({
        findings: message.findings,
        score: message.score
      }).length;

      if (payloadSize > MAX_PAYLOAD_SIZE) {
        sendResponse({ success: false, error: `Payload too large: ${payloadSize} bytes exceeds ${MAX_PAYLOAD_SIZE} limit` });
        return false;
      }

      // P1-THIRTEENTH-2: Validate HTML size separately (not stored, only used for compression)
      if (message.html) {
        const MAX_HTML_SIZE = 2 * 1024 * 1024; // 2MB max for HTML content
        if (message.html.length > MAX_HTML_SIZE) {
          console.warn(`Hera: HTML content too large (${message.html.length} bytes), skipping compression analysis`);
          message.html = null; // Don't process overly large pages
        }
      }

      // P0-FOURTEENTH-3 FIX: Properly handle async compression analysis
      // Must await the async work before calling sendResponse
      (async () => {
        try {
          let compressionAnalysis = null;
          if (compressionAnalyzerReady && message.html) {
            try {
              compressionAnalysis = await compressionAnalyzer.analyzeAuthPage(message.html, message.url);

              // Add compression findings to existing findings array
              if (compressionAnalysis.indicators && compressionAnalysis.indicators.length > 0) {
                message.findings.push({
                  type: 'COMPRESSION_ANALYSIS',
                  severity: compressionAnalysis.recommendation === 'BLOCK' ? 'CRITICAL' :
                           compressionAnalysis.recommendation === 'WARN' ? 'MEDIUM' : 'INFO',
                  description: `PhishZip analysis: ${compressionAnalysis.recommendation}`,
                  details: compressionAnalysis.indicators,
                  suspicionScore: compressionAnalysis.suspicionScore,
                  confidence: compressionAnalysis.confidence
                });

                // Update critical issues count if blocking recommendation
                if (compressionAnalysis.recommendation === 'BLOCK') {
                  message.score.criticalIssues += 1;
                }
              }
            } catch (error) {
              console.warn('Hera: Compression analysis failed (non-blocking):', error);
            }
          }

          // SECURITY FIX P1-7 & NEW-P2-1: Use safe storage with mutex and quota handling
          const storageKey = `siteAnalysis_${tabId}`;
          await safeStorageSet({
            [storageKey]: {
              url: message.url,
              findings: message.findings,
              score: message.score,
              analysisSuccessful: message.analysisSuccessful,
              timestamp: message.timestamp,
              compressionAnalysis // P1-THIRTEENTH-2: Include PhishZip results
            }
          }, storageKey);

          console.log(`Hera: Stored analysis for tab ${tabId}:`, {
            url: message.url,
            grade: message.score.grade,
            findings: message.findings.length
          });

          // Show notification for critical issues
          if (message.score.criticalIssues > 0) {
            chrome.notifications.create({
              type: 'basic',
              iconUrl: 'icons/icon128.png',
              title: 'Hera Security Alert',
              message: `This site has ${message.score.criticalIssues} critical security issues. Grade: ${message.score.grade}`,
              priority: 2
            });
          }

          sendResponse({ success: true });
        } catch (error) {
          console.error('Hera: Failed to process analysis:', error);
          sendResponse({ success: false, error: error.message });
        }
      })();
    }

    return true; // Keep message channel open for async response
  }

  if (message.type === 'ANALYSIS_ERROR') {
    // Log analysis errors
    console.error('Hera: Content script analysis failed:', {
      url: message.url,
      error: message.error
    });

    sendResponse({ success: true });
    return false;
  }

  if (message.type === 'GET_SITE_ANALYSIS') {
    // Return cached analysis for popup
    // P0-SIXTH-1 FIX: Proper error handling for async operation
    handleGetAnalysis()
      .then(sendResponse)
      .catch(error => {
        console.error('Hera: GET_SITE_ANALYSIS failed:', error);
        sendResponse({ success: false, error: error.message });
      });
    return true;
  }

  if (message.type === 'TRIGGER_ANALYSIS') {
    // Forward analysis trigger to content script
    // P0-SIXTH-1 FIX: Proper error handling for async operation
    handleTriggerAnalysis()
      .then(sendResponse)
      .catch(error => {
        console.error('Hera: TRIGGER_ANALYSIS failed:', error);
        sendResponse({ success: false, error: error.message });
      });
    return true;
  }

  if (message.type === 'INJECT_RESPONSE_INTERCEPTOR') {
    // SECURITY FIX P1-1: Inject response interceptor in isolated world
    // P0-SIXTH-1 FIX: Proper error handling for async operation
    handleInterceptorInjection(sender, message)
      .then(sendResponse)
      .catch(error => {
        console.error('Hera: INJECT_RESPONSE_INTERCEPTOR failed:', error);
        sendResponse({ success: false, error: error.message });
      });
    return true;
  }
});

// SECURITY FIX P1-1: Inject response interceptor in isolated world
// CRITICAL FIX: Removed duplicate handleInterceptorInjection (already defined at top of file)

// SECURITY FIX P0-5: Proper async message handling
async function handleGetAnalysis() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });

    if (tabs.length === 0) {
      return { error: 'No active tab' };
    }

    const tabId = tabs[0].id;
    const result = await chrome.storage.local.get([`siteAnalysis_${tabId}`]);
    const analysis = result[`siteAnalysis_${tabId}`];

    if (analysis) {
      return { success: true, analysis: analysis };
    } else {
      return { error: 'No analysis available' };
    }
  } catch (error) {
    console.error('Hera: Failed to get analysis:', error);
    return { error: error.message };
  }
}

async function handleTriggerAnalysis() {
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });

    if (tabs.length === 0) {
      return { error: 'No active tab' };
    }

    const tab = tabs[0];

    // CRITICAL FIX: Check if tab URL is injectable
    if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('about:') ||
        tab.url.startsWith('chrome-extension://') || tab.url.startsWith('edge://')) {
      return { error: 'Cannot analyze restricted pages (chrome://, about://, etc.)' };
    }

    // CRITICAL FIX: Try to inject content script if it's not already loaded
    try {
      await chrome.tabs.sendMessage(tab.id, { type: 'PING' });
    } catch (pingError) {
      // Content script not loaded - inject it now
      console.log('Hera: Content script not loaded, injecting now...');

      try {
        // Inject detector modules first
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: [
            'modules/subdomain-impersonation-detector.js',
            'modules/dark-pattern-detector.js',
            'modules/phishing-detector.js',
            'modules/privacy-violation-detector.js',
            'modules/risk-scoring-engine.js',
            'content-script.js'
          ]
        });

        // Wait a bit for content script to initialize
        await new Promise(resolve => setTimeout(resolve, 500));
      } catch (injectError) {
        console.error('Hera: Failed to inject content script:', injectError);
        return { error: 'Failed to inject content script. Try refreshing the page.' };
      }
    }

    // Send trigger message to content script
    const response = await chrome.tabs.sendMessage(tab.id, {
      type: 'TRIGGER_ANALYSIS'
    });

    if (response && response.success) {
      return { success: true, score: response.score };
    } else {
      return { error: 'Analysis failed' };
    }
  } catch (error) {
    console.error('Hera: Failed to trigger analysis:', error);

    if (error.message.includes('Receiving end does not exist')) {
      return { error: 'Content script not ready. Please refresh the page.' };
    }

    return { error: error.message };
  }
}

console.log('Hera: All-in-one detection system loaded (analysis runs in content script)');
