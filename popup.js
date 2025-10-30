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
// Note: DebugTimeline no longer imported - debug mode uses separate window (debug-window.html)

// Make DOMSecurity globally available for backward compatibility
window.DOMSecurity = DOMSecurity;

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  console.log('Hera Popup: Initializing simplified UI...');

  // Initialize components
  const exportManager = new ExportManager();
  const dashboard = new HeraDashboard();
  // Note: DebugTimeline no longer used - debug mode opens separate window

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

          // FIX: Check debug mode via message to background (session-only, not chrome.storage)
          const response = await chrome.runtime.sendMessage({
            action: 'isDebugModeEnabled',
            domain: domain
          });

          const isEnabled = response?.enabled || false;
          debugModeToggle.checked = isEnabled;

          // If debug mode is enabled, could open debug window (but don't auto-open on every popup load)
          // User can click toggle to open window if needed
        } catch (error) {
          console.debug('Could not parse tab URL or check debug mode:', error);
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
            // Check for runtime errors
            if (chrome.runtime.lastError) {
              console.error('Runtime error:', chrome.runtime.lastError.message);
              alert('Failed to toggle debug mode: ' + chrome.runtime.lastError.message);
              debugModeToggle.checked = !debugModeToggle.checked;
              return;
            }

            if (response?.success) {
              console.log(`Debug mode ${debugModeToggle.checked ? 'enabled' : 'disabled'} for ${domain}`);

              // Open debug window if enabled
              if (debugModeToggle.checked) {
                chrome.runtime.sendMessage({
                  action: 'openDebugWindow',
                  domain: domain
                }, (windowResponse) => {
                  if (chrome.runtime.lastError) {
                    console.error('Failed to open debug window:', chrome.runtime.lastError.message);
                    alert('Failed to open debug window: ' + chrome.runtime.lastError.message);
                  } else if (windowResponse?.success) {
                    console.log('Debug window opened');
                  }
                });
              }
            } else {
              console.error('Failed to toggle debug mode:', response?.error);
              alert('Failed to toggle debug mode: ' + (response?.error || 'Unknown error'));
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

  // Note: Debug mode now opens a separate window instead of inline timeline
  // The DebugTimeline component is kept for potential future use

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
                if (chrome.runtime.lastError) {
                  console.error('Export error:', chrome.runtime.lastError.message);
                  alert('Export failed: ' + chrome.runtime.lastError.message);
                  return;
                }
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
