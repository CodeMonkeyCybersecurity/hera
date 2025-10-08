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
 * ✅ PhishZip Compression Analysis - Visual clone detection
 *
 * Philosophy: HONEST, evidence-based, human-centric security
 * - Document what actually works (not marketing claims)
 * - Show users real findings with explanations
 * - Respect user agency - inform, don't patronize
 *
 * 📊 SECURITY REVIEW STATUS
 * - Reviews 10-17: Fixed 35+ critical issues
 * - Review 17: Modularized monolithic background.js (3260 lines → focused modules)
 */

// ==================== CORE MODULES ====================
import { HeraAuthProtocolDetector } from './hera-auth-detector.js';
import { HeraSecretScanner } from './hera-secret-scanner.js';
import { HeraMaliciousExtensionDetector } from './hera-extension-security.js';
import { HeraAuthSecurityAnalyzer } from './hera-auth-security-analyzer.js';
import { HeraPortAuthAnalyzer } from './hera-port-auth-analyzer.js';
import { EvidenceCollector } from './evidence-collector.js';
import { AlertManager } from './alert-manager.js';
import { HeraCompressionAnalyzer } from './modules/hera-compression-analyzer.js';

// ==================== INFRASTRUCTURE MODULES ====================
import { storageManager } from './modules/storage-manager.js';
import { memoryManager } from './modules/memory-manager.js';
import { sessionTracker } from './modules/session-tracker.js';
import { ipCacheManager } from './modules/ip-cache.js';
import { DebuggerManager } from './modules/debugger-manager.js';
import { EventHandlers } from './modules/event-handlers.js';
import { AlarmHandlers } from './modules/alarm-handlers.js';

// ==================== UTILITY MODULES ====================
import { SecurityValidation } from './modules/security-validation.js';

// ==================== GLOBAL CONFIGURATION ====================
const ALLOWED_SCRIPTS = new Set([
  'response-interceptor.js',
  'content-script.js'
]);

const isProduction = !chrome.runtime.getManifest().version.includes('dev');

// ==================== INITIALIZATION ====================
let heraReady = false;
let initializationPromise = null;

// Initialize core components
const evidenceCollector = new EvidenceCollector();
const alertManager = new AlertManager();
const compressionAnalyzer = new HeraCompressionAnalyzer();
let compressionAnalyzerReady = false;

// Initialize detectors
const heraAuthDetector = new HeraAuthProtocolDetector(evidenceCollector);
const heraSecretScanner = new HeraSecretScanner();
const heraExtensionDetector = new HeraMaliciousExtensionDetector();
const heraAuthSecurityAnalyzer = new HeraAuthSecurityAnalyzer();
const heraPortAuthAnalyzer = new HeraPortAuthAnalyzer();

// Initialize managers
const debuggerManager = new DebuggerManager(memoryManager);
const eventHandlers = new EventHandlers(debuggerManager, storageManager);
const alarmHandlers = new AlarmHandlers(
  memoryManager,
  alertManager,
  evidenceCollector,
  sessionTracker,
  storageManager
);

// Proxy wrappers for backward compatibility
const authRequestsWrapperCache = new Map();
const authRequests = new Proxy(memoryManager.authRequests, {
  get(target, prop) {
    if (!memoryManager.initialized) {
      console.warn(`Hera RACE: authRequests.${String(prop)} accessed before initialization`);
    }
    const value = target[prop];
    if (typeof value === 'function') {
      if (!authRequestsWrapperCache.has(prop)) {
        authRequestsWrapperCache.set(prop, function(...args) {
          const result = value.apply(target, args);
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

const debugTargetsWrapperCache = new Map();
const debugTargets = new Proxy(memoryManager.debugTargets, {
  get(target, prop) {
    if (!memoryManager.initialized) {
      console.warn(`Hera RACE: debugTargets.${String(prop)} accessed before initialization`);
    }
    const value = target[prop];
    if (typeof value === 'function') {
      if (!debugTargetsWrapperCache.has(prop)) {
        debugTargetsWrapperCache.set(prop, function(...args) {
          const result = value.apply(target, args);
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

/**
 * Master initialization function
 * P0-SEVENTEENTH-3: Coordinates all module initialization
 */
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

    // Initialize compression analyzer
    try {
      await compressionAnalyzer.initialize();
      compressionAnalyzerReady = true;
      console.log('Hera: Compression analyzer initialized (PhishZip enabled)');
    } catch (error) {
      console.warn('Hera: Compression analyzer initialization failed - PhishZip disabled:', error);
      compressionAnalyzerReady = false;
    }

    // Run startup cleanup
    try {
      await memoryManager.cleanupStaleRequests();
      await alertManager.cleanupAlertHistory();
      const bytesInUse = await chrome.storage.local.getBytesInUse();
      const quota = chrome.storage.local.QUOTA_BYTES || 10485760;
      console.log(`Hera: Storage quota ${(bytesInUse / 1024).toFixed(0)}KB / ${(quota / 1024).toFixed(0)}KB (${((bytesInUse / quota) * 100).toFixed(1)}%)`);
    } catch (error) {
      console.error('Hera: Startup cleanup failed:', error);
    }

    heraReady = true;
    const duration = Date.now() - startTime;
    console.log(`Hera: All modules initialized in ${duration}ms`);

    // Initialize webRequest listeners AFTER all modules ready
    await initializeWebRequestListeners();

  } catch (error) {
    console.error('Hera: Initialization failed:', error);
    heraReady = true; // Mark as ready anyway to prevent permanent blocking
  }
}

// Start initialization immediately
initializationPromise = initializeHera();

// ==================== EVENT REGISTRATION ====================
eventHandlers.registerListeners(initializeWebRequestListeners);
alarmHandlers.registerListener(initializationPromise);
alarmHandlers.initializeAlarms();

// ==================== PLACEHOLDER FOR WEBREQUEST LISTENERS ====================
// TODO: Extract webRequest listeners to separate module
async function initializeWebRequestListeners() {
  // This will be modularized in the next step
  console.log('Hera: webRequest listeners initialization (to be modularized)');
}

console.log('Hera: Modular background script loaded');
