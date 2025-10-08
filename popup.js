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

// Import all modules
import { DOMSecurity } from './modules/ui/dom-security.js';
import { JWTSecurity } from './modules/ui/jwt-security.js';
import { TimeUtils } from './modules/ui/time-utils.js';
import { ExportManager } from './modules/ui/export-manager.js';
import { CookieParser } from './modules/ui/cookie-parser.js';
import { SettingsPanel } from './modules/ui/settings-panel.js';
import { SessionRenderer } from './modules/ui/session-renderer.js';
import { RequestDetails } from './modules/ui/request-details.js';
import { HeraDashboard } from './modules/ui/dashboard.js';
import { RepeaterTool } from './modules/ui/repeater-tool.js';

// Global state (shared between modules)
let requests = [];
let selectedRequest = null;

// Make utilities globally available for backward compatibility
window.DOMSecurity = DOMSecurity;
window.JWTSecurity = JWTSecurity;
window.TimeUtils = TimeUtils;

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  console.log('Hera Popup: Initializing...');

  // Initialize all components
  const exportManager = new ExportManager();
  const settingsPanel = new SettingsPanel();
  const sessionRenderer = new SessionRenderer();
  const requestDetails = new RequestDetails();
  const dashboard = new HeraDashboard();
  const repeaterTool = new RepeaterTool();

  // Initialize each component
  settingsPanel.initialize();
  sessionRenderer.initialize();
  requestDetails.initialize();
  dashboard.initialize();
  repeaterTool.initialize();

  // Wire up export buttons
  const exportBtn = document.getElementById('exportBtn');
  const exportAllBtn = document.getElementById('exportAllBtn');
  const clearBtn = document.getElementById('clearBtn');
  const viewStorageBtn = document.getElementById('viewStorageBtn');

  if (exportBtn) {
    exportBtn.addEventListener('click', () => {
      console.log('Export button clicked');
      exportManager.showExportModal(requests, 'current');
    });
  }

  if (exportAllBtn) {
    exportAllBtn.addEventListener('click', () => {
      console.log('Export all button clicked');
      exportAllSessions(exportManager);
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      console.log('Clear button clicked');
      clearRequests();
    });
  }

  if (viewStorageBtn) {
    viewStorageBtn.addEventListener('click', () => {
      console.log('View storage button clicked');
      viewStorageStats(exportManager);
    });
  }

  // Make requests available globally for modules
  window.heraRequests = requests;

  // Listen for request updates from session renderer
  window.addEventListener('requestsUpdated', (e) => {
    requests = e.detail;
    window.heraRequests = requests;
  });

  // Listen for request selection
  window.addEventListener('showRequestDetails', (e) => {
    const requestId = e.detail;
    selectedRequest = requests.find(r => r.id === requestId);
    if (selectedRequest && repeaterTool.sendToRepeaterBtn) {
      repeaterTool.sendToRepeaterBtn.style.display = 'block';
    }
    // Dispatch event for repeater tool
    window.dispatchEvent(new CustomEvent('requestSelected', { detail: selectedRequest }));
  });

  console.log('Hera Popup: Initialization complete');
});

// Helper functions that need to remain in popup.js

/**
 * Export all stored sessions
 */
function exportAllSessions(exportManager) {
  console.log('exportAllSessions function called');
  try {
    chrome.storage.local.get(['heraSessions'], (result) => {
      console.log('Retrieved sessions for export:', result);

      if (chrome.runtime.lastError) {
        console.error('Chrome runtime error:', chrome.runtime.lastError);
        alert('Error accessing storage: ' + chrome.runtime.lastError.message);
        return;
      }

      const allSessions = result.heraSessions || [];

      const data = {
        exportType: 'all_sessions',
        timestamp: new Date().toISOString(),
        totalSessions: allSessions.length,
        sessions: allSessions,
        metadata: {
          exportedBy: 'Hera Browser Extension',
          version: '1.0.0',
          description: 'Complete authentication security analysis data'
        }
      };

      // Show export format selection modal for all sessions
      exportManager.showExportModal(data, 'all');
    });
  } catch (error) {
    console.error('Error in exportAllSessions:', error);
    alert('Error exporting sessions: ' + error.message);
  }
}

/**
 * View storage statistics
 */
function viewStorageStats(exportManager) {
  console.log('viewStorageStats function called');
  try {
    chrome.storage.local.get(null, (allData) => {
      console.log('Storage data retrieved:', allData);
      const stats = {
        heraSessions: allData.heraSessions?.length || 0,
        syncQueue: allData.syncQueue?.length || 0,
        heraConfig: allData.heraConfig ? 'Configured' : 'Not configured',
        totalStorageKeys: Object.keys(allData).length,
        estimatedSize: JSON.stringify(allData).length
      };

      // Create stats modal
      const modal = document.createElement('div');
      modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0,0,0,0.8);
        z-index: 10000;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: -apple-system, sans-serif;
      `;

      modal.innerHTML = `
        <div style="
          background: white;
          padding: 30px;
          border-radius: 12px;
          max-width: 500px;
          width: 90%;
        ">
          <h2 style="margin: 0 0 20px 0; color: #333;">Hera Storage Statistics</h2>
          
          <div style="margin-bottom: 15px;">
            <strong>Total Sessions Stored:</strong> ${stats.heraSessions.toLocaleString()}
          </div>
          
          <div style="margin-bottom: 15px;">
            <strong>Pending Sync Events:</strong> ${stats.syncQueue}
          </div>
          
          <div style="margin-bottom: 15px;">
            <strong>Configuration:</strong> ${stats.heraConfig}
          </div>
          
          <div style="margin-bottom: 15px;">
            <strong>Total Storage Keys:</strong> ${stats.totalStorageKeys}
          </div>
          
          <div style="margin-bottom: 30px;">
            <strong>Estimated Size:</strong> ${(stats.estimatedSize / 1024).toFixed(2)} KB
          </div>
          
          <div style="display: flex; gap: 10px; justify-content: flex-end;">
            <button id="closeStatsModal" style="
              background: #666;
              color: white;
              border: none;
              padding: 10px 20px;
              border-radius: 6px;
              cursor: pointer;
            ">
              Close
            </button>
            <button id="exportAllFromStats" style="
              background: #4CAF50;
              color: white;
              border: none;
              padding: 10px 20px;
              border-radius: 6px;
              cursor: pointer;
            ">
              Export All Data
            </button>
          </div>
        </div>
      `;

      document.body.appendChild(modal);

      // Close button
      modal.querySelector('#closeStatsModal').addEventListener('click', () => {
        modal.remove();
      });

      // Export all button
      modal.querySelector('#exportAllFromStats').addEventListener('click', () => {
        exportAllSessions(exportManager);
        modal.remove();
      });
    });
  } catch (error) {
    console.error('Error in viewStorageStats:', error);
    alert('Error viewing storage stats: ' + error.message);
  }
}

/**
 * Clear all requests
 */
function clearRequests() {
  if (confirm('Are you sure you want to clear all captured requests?')) {
    chrome.runtime.sendMessage({ action: 'clearRequests' }, response => {
      if (response && response.success) {
        requests = [];
        window.heraRequests = [];
        // Trigger re-render
        window.dispatchEvent(new CustomEvent('requestsCleared'));
        // Reload the session renderer
        window.location.reload();
      }
    });
  }
}

// Make functions globally available for debugging
window.hera = window.hera || {};
window.hera.exportAllData = exportAllSessions;
window.hera.viewStorage = viewStorageStats;
window.hera.clearRequests = clearRequests;

// Make dismissAlert globally available
window.dismissAlert = function() {
  const alertsEl = document.getElementById('consentAlerts');
  if (alertsEl) alertsEl.style.display = 'none';
};
