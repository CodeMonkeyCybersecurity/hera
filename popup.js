// P1-NINTH-4 FIX: Validate extension context to prevent clickjacking
(function() {
  'use strict';

  // Detect if popup.html was opened in invalid context (not via extension icon)
  if (window.opener || window.location !== window.parent.location) {
    // Opened by another window or iframed (shouldn't be possible but check anyway)
    document.body.innerHTML = `
      <div style="padding: 20px; text-align: center; font-family: system-ui, -apple-system, sans-serif;">
        <h1>⚠️ Invalid Context</h1>
        <p>This page must be opened via the extension icon.</p>
        <p>Please close this window and click the Hera icon in your browser toolbar.</p>
      </div>
    `;
    throw new Error('Popup opened in invalid context');
  }
})();

// Import simplified modules
import { DOMSecurity } from './modules/ui/dom-security.js';
import { ExportManager } from './modules/ui/export-manager.js';
import { HeraDashboard } from './modules/ui/dashboard.js';
import { DebugTimeline } from './modules/ui/debug-timeline.js';

// Make DOMSecurity globally available for backward compatibility
window.DOMSecurity = DOMSecurity;

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  console.log('Hera Popup: Initializing simplified UI...');

  // Initialize components
  const exportManager = new ExportManager();
  const dashboard = new HeraDashboard();
  const debugTimeline = new DebugTimeline();

  // Initialize dashboard
  dashboard.initialize();

  // Wire up buttons
  const exportBtn = document.getElementById('exportBtn');
  const clearBtn = document.getElementById('clearBtn');
  const debugModeToggle = document.getElementById('debugModeToggle');

  // Debug Mode Toggle
  if (debugModeToggle) {
    // Load current debug mode state
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      if (tabs[0]?.url) {
        try {
          const url = new URL(tabs[0].url);
          const domain = url.hostname;

          // Check if debug mode is enabled for this domain
          const result = await chrome.storage.local.get(['debugModeEnabled']);
          const enabledDomains = result.debugModeEnabled || [];
          debugModeToggle.checked = enabledDomains.includes(domain);
        } catch (error) {
          console.debug('Could not parse tab URL:', error);
        }
      }
    });

    // Handle toggle changes
    debugModeToggle.addEventListener('change', async () => {
      chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
        if (!tabs[0]?.url) {
          alert('Cannot enable debug mode: no active tab');
          debugModeToggle.checked = false;
          return;
        }

        try {
          const url = new URL(tabs[0].url);
          const domain = url.hostname;
          const tabId = tabs[0].id;

          // Send message to background to toggle debug mode
          chrome.runtime.sendMessage({
            action: debugModeToggle.checked ? 'enableDebugMode' : 'disableDebugMode',
            domain: domain,
            tabId: tabId
          }, (response) => {
            if (response?.success) {
              console.log(`Debug mode ${debugModeToggle.checked ? 'enabled' : 'disabled'} for ${domain}`);

              // Show debug timeline if enabled
              if (debugModeToggle.checked) {
                showDebugTimeline(domain);
              } else {
                dashboard.loadDashboard(); // Back to normal dashboard
              }
            } else {
              console.error('Failed to toggle debug mode:', response?.error);
              alert('Failed to toggle debug mode. See console for details.');
              debugModeToggle.checked = !debugModeToggle.checked; // Revert
            }
          });
        } catch (error) {
          console.error('Error toggling debug mode:', error);
          alert('Invalid URL - cannot enable debug mode for this page');
          debugModeToggle.checked = false;
        }
      });
    });
  }

  // Show debug timeline for a domain
  async function showDebugTimeline(domain) {
    const dashboardContent = document.getElementById('dashboardContent');
    if (!dashboardContent) return;

    // Request debug session data from background
    chrome.runtime.sendMessage({
      action: 'getDebugSession',
      domain: domain
    }, (response) => {
      if (response?.session) {
        debugTimeline.render(response.session, dashboardContent);
      } else {
        debugTimeline.render({ domain, startTime: Date.now(), requests: [], consoleLogs: [] }, dashboardContent);
      }
    });

    // Refresh timeline every 2 seconds while debug mode is active
    const refreshInterval = setInterval(() => {
      if (!debugModeToggle.checked) {
        clearInterval(refreshInterval);
        return;
      }

      chrome.runtime.sendMessage({
        action: 'getDebugSession',
        domain: domain
      }, (response) => {
        if (response?.session) {
          debugTimeline.render(response.session, dashboardContent);
        }
      });
    }, 2000);
  }

  if (exportBtn) {
    exportBtn.addEventListener('click', async () => {
      console.log('Export button clicked');

      // Check if debug mode is active
      if (debugModeToggle && debugModeToggle.checked) {
        // Export debug session
        chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
          if (tabs[0]?.url) {
            try {
              const url = new URL(tabs[0].url);
              const domain = url.hostname;

              chrome.runtime.sendMessage({
                action: 'exportDebugSession',
                domain: domain,
                format: 'enhanced' // or 'har'
              }, (response) => {
                if (response?.data) {
                  // Download the export
                  const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `hera-debug-${domain}-${new Date().toISOString().slice(0, 10)}.json`;
                  a.click();
                  URL.revokeObjectURL(url);
                } else {
                  alert('No debug data to export');
                }
              });
            } catch (error) {
              console.error('Export error:', error);
            }
          }
        });
      } else {
        // Normal export
        const result = await chrome.storage.local.get(['heraSessions']);
        const sessions = result.heraSessions || [];
        exportManager.showExportModal(sessions, 'current');
      }
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      console.log('Clear button clicked');
      if (confirm('Clear all captured auth data?')) {
        chrome.storage.local.clear(() => {
          console.log('Storage cleared');
          dashboard.loadDashboard();
        });
      }
    });
  }

  console.log('Hera Popup: Initialization complete');
});
