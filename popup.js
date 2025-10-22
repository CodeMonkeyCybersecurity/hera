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

// Make DOMSecurity globally available for backward compatibility
window.DOMSecurity = DOMSecurity;

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  console.log('Hera Popup: Initializing simplified UI...');

  // Initialize components
  const exportManager = new ExportManager();
  const dashboard = new HeraDashboard();

  // Initialize dashboard
  dashboard.initialize();

  // Wire up buttons
  const exportBtn = document.getElementById('exportBtn');
  const clearBtn = document.getElementById('clearBtn');

  if (exportBtn) {
    exportBtn.addEventListener('click', async () => {
      console.log('Export button clicked');
      const result = await chrome.storage.local.get(['heraSessions']);
      const sessions = result.heraSessions || [];
      exportManager.showExportModal(sessions, 'current');
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
