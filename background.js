/**
 * HERA - Authentication & Authorization Security Monitor
 * Code Monkey Cybersecurity - "Cybersecurity. With humans."
 *
 * 🛡️ ACTIVE DETECTION LAYERS (Auth-Focused)
 *
 * ✅ OAuth/OIDC/SAML Flow Security - CSRF, PKCE, state parameter validation
 * ✅ SCIM Protocol Analysis - Provisioning security
 * ✅ JWT Security - Token validation, signature verification
 * ✅ Session Security - Fixation, hijacking, replay detection
 * ✅ Certificate Analysis - HTTPS/TLS integrity, domain matching
 * ✅ Password Security - Entropy analysis, common patterns
 * ✅ MFA Detection - TOTP, HOTP, WebAuthn, passkeys
 * ✅ Port/Service Auth - Default credentials, LDAP, Kerberos, RADIUS
 * ✅ Authorization Analysis - Scope validation, permission checks
 *
 * Philosophy: HONEST, evidence-based, human-centric security
 * - Focus on authentication vulnerabilities only
 * - Show users real findings with explanations
 * - Respect user agency - inform, don't patronize
 *
 * 📊 SIMPLIFIED & REFOCUSED (2025)
 * - Disabled non-auth features (phishing, dark patterns, privacy, compression)
 * - Streamlined to auth vulnerability detection only
 */

// ==================== CORE MODULES (AUTH-FOCUSED) ====================
import { HeraAuthProtocolDetector } from './hera-auth-detector.js';
// import { HeraSecretScanner } from './hera-secret-scanner.js'; // DISABLED - Non-essential
// import { HeraMaliciousExtensionDetector } from './hera-extension-security.js'; // DISABLED - Non-auth
import { HeraAuthSecurityAnalyzer } from './hera-auth-security-analyzer.js';
import { HeraPortAuthAnalyzer } from './hera-port-auth-analyzer.js';
import { EvidenceCollector } from './evidence-collector.js';
import { AlertManager } from './alert-manager.js';
// import { HeraCompressionAnalyzer } from './modules/hera-compression-analyzer.js'; // DISABLED - PhishZip (non-auth)

// ==================== NEW AUTH ANALYZERS ====================
import { JWTValidator } from './modules/auth/jwt-validator.js';
import { SessionSecurityAnalyzer } from './modules/auth/session-security-analyzer.js';
import { SCIMAnalyzer } from './modules/auth/scim-analyzer.js';

// ==================== INFRASTRUCTURE MODULES ====================
import { storageManager } from './modules/storage-manager.js';
import { memoryManager } from './modules/memory-manager.js';
import { sessionTracker } from './modules/session-tracker.js';
// import { ipCacheManager } from './modules/ip-cache.js'; // DISABLED - IP cache feature commented out
import { DebuggerManager } from './modules/debugger-manager.js';
import { EventHandlers } from './modules/event-handlers.js';
import { AlarmHandlers } from './modules/alarm-handlers.js';

// ==================== REQUEST/RESPONSE HANDLING ====================
import { WebRequestListeners } from './modules/webrequest-listeners.js';
import { DebuggerEvents } from './modules/debugger-events.js';
import { MessageRouter } from './modules/message-router.js';
import { decodeRequestBody, generateSessionId } from './modules/request-decoder.js';

// ==================== UTILITY MODULES ====================
import { SecurityValidation } from './modules/security-validation.js';
import { errorCollector } from './modules/error-collector.js';

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
// const compressionAnalyzer = new HeraCompressionAnalyzer(); // DISABLED - PhishZip
// let compressionAnalyzerReady = false; // DISABLED

// Initialize detectors (AUTH-ONLY)
const heraAuthDetector = new HeraAuthProtocolDetector(evidenceCollector);
// const heraSecretScanner = new HeraSecretScanner(); // DISABLED - Already commented out in file
// const heraExtensionDetector = new HeraMaliciousExtensionDetector(); // DISABLED - Non-auth
const heraAuthSecurityAnalyzer = new HeraAuthSecurityAnalyzer();
const heraPortAuthAnalyzer = new HeraPortAuthAnalyzer();

// Initialize new auth analyzers (2025)
const jwtValidator = new JWTValidator();
const sessionSecurityAnalyzer = new SessionSecurityAnalyzer();
const scimAnalyzer = new SCIMAnalyzer();

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

// Storage helper (backward compatibility)
const heraStore = {
  async storeAuthEvent(eventData) {
    return storageManager.storeAuthEvent(eventData);
  },
  async storeSession(sessionData) {
    return storageManager.storeSession(sessionData);
  }
};

// Badge update helper
const updateBadge = () => storageManager.updateBadge();

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
  console.log('Hera: Error collector active - runtime errors will be captured and exportable');
  const startTime = Date.now();

  try {
    // Initialize all persistent storage modules in parallel
    await Promise.all([
      memoryManager.initPromise,
      sessionTracker.initPromise,
      evidenceCollector.initPromise,
      alertManager.initPromise
      // ipCacheManager.initPromise // DISABLED - IP cache removed
    ]);

    // Initialize compression analyzer - DISABLED (non-auth feature)
    // try {
    //   await compressionAnalyzer.initialize();
    //   compressionAnalyzerReady = true;
    //   console.log('Hera: Compression analyzer initialized (PhishZip enabled)');
    // } catch (error) {
    //   console.warn('Hera: Compression analyzer initialization failed - PhishZip disabled:', error);
    //   compressionAnalyzerReady = false;
    // }

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

// ==================== REQUEST/RESPONSE HANDLING INITIALIZATION ====================

// Initialize webRequest listeners
const webRequestListeners = new WebRequestListeners(
  () => heraReady,
  authRequests,
  heraAuthDetector,
  heraPortAuthAnalyzer,
  evidenceCollector,
  storageManager,
  sessionTracker,
  decodeRequestBody,
  jwtValidator,
  sessionSecurityAnalyzer,
  scimAnalyzer
);

// Initialize debugger events
const debuggerEvents = new DebuggerEvents(
  () => heraReady,
  authRequests,
  debugTargets,
  heraAuthDetector,
  // heraSecretScanner,
  storageManager,
  updateBadge
);

// Initialize message router
const messageRouter = new MessageRouter(
  authRequests,
  debugTargets,
  heraAuthDetector,
  storageManager,
  memoryManager,
  updateBadge,
  null, // handleInterceptorInjection - will be added in Phase 3
  generateSessionId,
  heraStore,
  errorCollector
);

// Register all handlers
debuggerEvents.register();
messageRouter.register();

async function initializeWebRequestListeners() {
  return await webRequestListeners.initialize();
}

console.log('Hera: Modular background script loaded (Phase 2 complete)');
