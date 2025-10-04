// Hera Background Service Worker - Modular Architecture
// Main coordinator that orchestrates all modules

// Import core modules
import { SecurityValidation } from './modules/security-validation.js';
import { storageManager } from './modules/storage-manager.js';
import { memoryManager } from './modules/memory-manager.js';
import { RequestProcessor } from './modules/request-processor.js';
import { MessageHandler } from './modules/message-handler.js';

// Import analysis engines
import { HeraAuthProtocolDetector } from './hera-auth-detector.js';
import { HeraSecretScanner } from './hera-secret-scanner.js';
import { HeraMaliciousExtensionDetector } from './hera-extension-security.js';
import { HeraAuthSecurityAnalyzer } from './hera-auth-security-analyzer.js';
import { HeraPortAuthAnalyzer } from './hera-port-auth-analyzer.js';
import { EvidenceCollector } from './evidence-collector.js';
import { AlertManager } from './alert-manager.js';

// --- Initialization ---

// Initialize evidence collection and analysis engines
const evidenceCollector = new EvidenceCollector();
const alertManager = new AlertManager();

const heraAuthDetector = new HeraAuthProtocolDetector(evidenceCollector);
const heraSecretScanner = new HeraSecretScanner();
const heraExtensionDetector = new HeraMaliciousExtensionDetector();
const heraAuthSecurityAnalyzer = new HeraAuthSecurityAnalyzer();
const heraPortAuthAnalyzer = new HeraPortAuthAnalyzer();

// Add wrapper methods for HeraAuthProtocolDetector
heraAuthDetector.isAuthRequest = function(url, options) {
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

// Initialize processors
const requestProcessor = new RequestProcessor(
  heraAuthDetector,
  heraSecretScanner,
  heraPortAuthAnalyzer,
  alertManager
);

const messageHandler = new MessageHandler(requestProcessor, null);

// --- Alarm Setup (Periodic Tasks) ---

// Setup periodic cleanup and monitoring
chrome.alarms.create('cleanupAuthRequests', { periodInMinutes: 2 });
chrome.alarms.create('checkStorageQuota', { periodInMinutes: 10 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'cleanupAuthRequests') {
    memoryManager.cleanupStaleRequests();
    alertManager.cleanupAlertHistory();
  } else if (alarm.name === 'checkStorageQuota') {
    storageManager.checkStorageQuota();
  }
});

// --- WebRequest Listeners ---

// 1. Capture request details
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    requestProcessor.handleBeforeRequest(details);
  },
  { urls: ["<all_urls>"] },
  ["requestBody"]
);

// 2. Capture request headers and perform initial analysis
chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    requestProcessor.handleBeforeSendHeaders(details);
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

// 3. Capture response headers and status
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    requestProcessor.handleHeadersReceived(details);
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// --- Message Listener ---

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  messageHandler.handleMessage(message, sender, sendResponse);
  return true; // Keep channel open for async responses
});

// --- Extension Lifecycle ---

chrome.runtime.onInstalled.addListener(() => {
  console.log('Hera extension installed/updated (modular architecture).');
  storageManager.updateBadge();
});

chrome.runtime.onStartup.addListener(() => {
  console.log('Hera starting up (modular architecture)...');
  storageManager.updateBadge();
});

// --- Utility Functions for Alert Display ---

function showAuthSecurityAlert(finding, url) {
  try {
    const enrichedFinding = {
      ...finding,
      url: url,
      evidence: finding.evidence || {}
    };

    alertManager.processFinding(enrichedFinding);
  } catch (error) {
    console.error('Failed to show auth security alert:', error);
  }
}

function showExtensionSecurityAlert(finding) {
  try {
    const enrichedFinding = {
      ...finding,
      severity: 'CRITICAL',
      url: 'chrome://extensions/',
      evidence: {
        verification: finding.details?.extensionId
          ? `chrome://extensions/?id=${finding.details.extensionId}`
          : null
      }
    };

    alertManager.processFinding(enrichedFinding);
  } catch (error) {
    console.error('Failed to show extension security alert:', error);
  }
}

// Export for debugger manager (if needed)
globalThis.showAuthSecurityAlert = showAuthSecurityAlert;
globalThis.showExtensionSecurityAlert = showExtensionSecurityAlert;

console.log('✅ Hera modular background service worker initialized');
