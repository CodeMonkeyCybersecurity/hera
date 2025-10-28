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

// ==================== P0 PREREQUISITE MODULES ====================
import { ResponseBodyCapturer } from './modules/response-body-capturer.js';
import { RefreshTokenTracker } from './modules/auth/refresh-token-tracker.js';

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

/**
 * Handle response interceptor injection
 * Injects response-interceptor.js into the content script's tab
 * @param {Object} sender - Chrome message sender
 * @param {Object} message - Message with injection request
 * @returns {Promise<Object>} Injection result
 */
async function handleInterceptorInjection(sender, message) {
  try {
    const tabId = sender.tab?.id;
    let url = sender.tab?.url;

    if (!tabId) {
      return { success: false, error: 'No tab ID available' };
    }

    // Get latest tab URL to prevent race condition
    const tab = await chrome.tabs.get(tabId);
    url = tab.url;

    // Enhanced URL validation
    if (!url || url.startsWith('chrome://') || url.startsWith('about:') ||
        url.startsWith('chrome-extension://') || url.startsWith('edge://') ||
        url.startsWith('chrome-devtools://') || url.startsWith('view-source:')) {
      console.debug(`Hera: Skipping interceptor injection on restricted page: ${url}`);
      return { success: false, error: 'Cannot inject on restricted pages' };
    }

    // Validate URL is HTTP/HTTPS only
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      console.debug(`Hera: Skipping injection on non-HTTP(S) page: ${url}`);
      return { success: false, error: 'Only HTTP(S) pages supported' };
    }

    // Check if chrome.scripting API is available
    if (!chrome.scripting || !chrome.scripting.executeScript) {
      console.error('Hera: chrome.scripting API not available');
      return { success: false, error: 'Scripting permission not available' };
    }

    // Check if we have permission for this URL
    const hasPermission = await chrome.permissions.contains({
      origins: [new URL(url).origin + '/*']
    });

    if (!hasPermission) {
      console.debug(`Hera: No permission for ${url}`);
      return { success: false, error: 'Host permission not granted for this site' };
    }

    // Double-check permission right before injection
    const hasPermissionNow = await chrome.permissions.contains({
      origins: [new URL(url).origin + '/*']
    });

    if (!hasPermissionNow) {
      console.warn('Hera: Permission revoked between check and injection');
      return { success: false, error: 'Permission no longer available' };
    }

    // Validate script path against whitelist
    const scriptFile = 'response-interceptor.js';

    if (!ALLOWED_SCRIPTS.has(scriptFile)) {
      console.error(`Hera: Attempted to inject non-whitelisted script: ${scriptFile}`);
      return { success: false, error: 'Invalid script path' };
    }

    // Third check right before injection (TOCTOU protection)
    const latestTab = await chrome.tabs.get(tabId);
    if (latestTab.url !== url) {
      console.warn(`Hera SECURITY: Tab URL changed during injection (TOCTOU blocked)`);
      return { success: false, error: 'Tab URL changed during injection (security block)' };
    }

    // Wrap injection in try-catch to handle permission revocation
    try {
      const result = await chrome.scripting.executeScript({
        target: { tabId: tabId },
        world: 'ISOLATED',
        files: [scriptFile]
      });

      // Check for Chrome runtime errors
      if (chrome.runtime.lastError) {
        console.error('Hera: Injection failed:', chrome.runtime.lastError);
        return { success: false, error: chrome.runtime.lastError.message };
      }

      console.log(`Hera: Response interceptor injected in isolated world for tab ${tabId}`);
      return { success: true };

    } catch (injectionError) {
      // Catch errors from permission revocation mid-flight
      if (injectionError.message?.includes('permission') ||
          injectionError.message?.includes('Cannot access')) {
        console.debug('Hera: Injection blocked - permission revoked');
        return { success: false, error: 'Permission revoked during injection' };
      }
      throw injectionError;
    }
  } catch (error) {
    console.error('Hera: Failed to inject response interceptor:', error.message);
    return { success: false, error: error.message || 'Unknown error' };
  }
}

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

// P0 PREREQUISITE MODULES: Initialize after authRequests is available
// CRITICAL FIX: Create refreshTokenTracker first, then pass to responseBodyCapturer
const refreshTokenTracker = new RefreshTokenTracker();
const responseBodyCapturer = new ResponseBodyCapturer(authRequests, evidenceCollector, refreshTokenTracker);

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
  scimAnalyzer,
  responseBodyCapturer,
  refreshTokenTracker
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
  handleInterceptorInjection,
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
