// Hera Content Script - Modularized Coordinator
// Prevents users from submitting data to insecure backends

// CRITICAL FIX P0-1: Chrome MV3 does NOT support static ES6 imports in content scripts
// Using dynamic imports instead (supported in content scripts)
// Note: Static imports work in background.js but NOT here due to injection mechanism

console.log('Hera: Content script coordinator loading...');

// ==================== INITIALIZE MODULES ====================

let formProtector = null;
let analysisRunner = null;
let detectorLoader = null;

/**
 * Initialize all content script modules using dynamic imports
 */
async function initializeModules() {
  try {
    // CRITICAL FIX P0-1: Use dynamic imports for Chrome MV3 content scripts
    const contentUtilsModule = await import(chrome.runtime.getURL('modules/content/content-utils.js'));
    const detectorLoaderModule = await import(chrome.runtime.getURL('modules/content/detector-loader.js'));
    const formProtectorModule = await import(chrome.runtime.getURL('modules/content/form-protector.js'));
    const messageQueueModule = await import(chrome.runtime.getURL('modules/content/message-queue.js'));
    const analysisRunnerModule = await import(chrome.runtime.getURL('modules/content/analysis-runner.js'));

    console.log('Hera: All modules loaded successfully');

    // SECURITY FIX P1-1: Request isolated world injection from background script
    detectorLoaderModule.requestInterceptorInjection();

    // Initialize form protector
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        formProtector = new formProtectorModule.HeraFormProtector();
        window.heraFormProtector = formProtector;
      });
    } else {
      formProtector = new formProtectorModule.HeraFormProtector();
      window.heraFormProtector = formProtector;
    }

    // Set up message listener for analysis
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      return analysisRunnerModule.handleAnalysisMessage(message, sender, sendResponse);
    });

    // Auto-run analysis on page load
    analysisRunnerModule.autoRunAnalysis();

    // Store module references for global access
    analysisRunner = analysisRunnerModule;
    detectorLoader = detectorLoaderModule;

    console.log('Hera: Content script with modular detection system loaded');

  } catch (error) {
    console.error('Hera: Failed to initialize modules:', error);
    console.error('Hera: Content script functionality may be limited');
  }
}

// ==================== GLOBAL FUNCTIONS ====================

// Global functions for extension integration
window.hera = window.hera || {};

window.hera.openExtension = function() {
  chrome.runtime.sendMessage({ action: 'openPopup' });
};

window.hera.showTechnicalDetails = function() {
  chrome.runtime.sendMessage({ action: 'showTechnicalDetails' });
};

// Test function for the new branded alert system
window.hera.testBrandedAlert = function(severity = 'warning') {
  const testData = {
    title: '🧪 Test Security Alert',
    details: `This is a test of the new Hera branded alert system. Severity: <strong>${severity}</strong><br><br>The alert appears on the website but is clearly branded as coming from your Hera extension, so you know it's legitimate security monitoring.`,
    severity: severity,
    verification: severity === 'critical' ? 'https://example.com/.git/config' : null
  };

  if (window.heraFormProtector) {
    window.heraFormProtector.showBrandedAlert(testData);
  }
};

// ==================== START INITIALIZATION ====================

// Start module initialization
initializeModules();
