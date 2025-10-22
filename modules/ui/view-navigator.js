/**
 * View Navigator
 * Handles navigation between different panels in the popup UI
 */

export class ViewNavigator {
  constructor() {
    this.currentView = 'dashboard';
    this.views = {
      dashboard: 'dashboardPanel',
      requests: 'requestsList',
      vulnerabilities: 'vulnerabilitiesPanel'
      // ports and extensions removed - auth-only mode
    };
    this.buttons = {};
    this.panels = {};
  }

  /**
   * Initialize view navigator
   */
  initialize() {
    // Get all buttons (auth-only mode)
    this.buttons = {
      dashboard: document.getElementById('dashboardBtn'),
      requests: document.getElementById('requestsBtn'),
      vulnerabilities: document.getElementById('vulnerabilitiesBtn')
      // ports and extensions removed - auth-only mode
    };

    // Get all panels (auth-only mode)
    this.panels = {
      dashboard: document.getElementById('dashboardPanel'),
      requests: document.getElementById('requestsList'),
      vulnerabilities: document.getElementById('vulnerabilitiesPanel')
      // ports and extensions removed - auth-only mode
    };

    // Set up button click handlers
    Object.entries(this.buttons).forEach(([viewName, button]) => {
      if (button) {
        button.addEventListener('click', () => {
          console.log(`Navigation: Switching to ${viewName} view`);
          this.switchView(viewName);
        });
      } else {
        console.warn(`Navigation: Button for ${viewName} not found`);
      }
    });

    // Set up refresh buttons for ports and extensions
    const refreshPortsBtn = document.getElementById('refreshPortsBtn');
    if (refreshPortsBtn) {
      refreshPortsBtn.addEventListener('click', () => {
        console.log('Navigation: Refreshing ports analysis');
        this.loadPortsAnalysis();
      });
    }

    const refreshExtensionsBtn = document.getElementById('refreshExtensionsBtn');
    if (refreshExtensionsBtn) {
      refreshExtensionsBtn.addEventListener('click', async () => {
        console.log('Navigation: Refresh button clicked - reloading extensions analysis');
        await this.loadExtensionsAnalysis();
        console.log('Navigation: Extensions analysis reload complete');
      });
    }

    // Initialize with dashboard view
    this.switchView('dashboard');
  }

  /**
   * Switch to a specific view
   * @param {string} viewName - Name of the view to switch to
   */
  switchView(viewName) {
    if (!this.views[viewName]) {
      console.error(`Navigation: Unknown view: ${viewName}`);
      return;
    }

    // Hide all panels
    Object.entries(this.panels).forEach(([name, panel]) => {
      if (panel) {
        panel.style.display = 'none';
      }
    });

    // Remove active class from all buttons
    Object.entries(this.buttons).forEach(([name, button]) => {
      if (button) {
        button.classList.remove('active');
      }
    });

    // Show selected panel
    const selectedPanel = this.panels[viewName];
    if (selectedPanel) {
      selectedPanel.style.display = 'block';
      console.log(`Navigation: Showing ${viewName} panel`);
    } else {
      console.error(`Navigation: Panel for ${viewName} not found`);
    }

    // Activate selected button
    const selectedButton = this.buttons[viewName];
    if (selectedButton) {
      selectedButton.classList.add('active');
    }

    // Update current view
    this.currentView = viewName;

    // Dispatch event for view change (other modules can listen)
    window.dispatchEvent(new CustomEvent('viewChanged', {
      detail: {
        view: viewName,
        previousView: this.currentView
      }
    }));

    // Trigger data loading for specific views
    this.loadViewData(viewName);
  }

  /**
   * Load data for a specific view
   * @param {string} viewName - Name of the view
   */
  loadViewData(viewName) {
    switch (viewName) {
      case 'ports':
        this.loadPortsAnalysis();
        break;
      case 'extensions':
        this.loadExtensionsAnalysis();
        break;
      case 'findings':
        // Findings are rendered by SessionRenderer, trigger refresh
        window.dispatchEvent(new CustomEvent('refreshFindings'));
        break;
      default:
        // Other views auto-load
        break;
    }
  }

  /**
   * Load ports and authentication analysis
   */
  async loadPortsAnalysis() {
    const portsContent = document.getElementById('portsContent');
    const portDistribution = document.getElementById('portDistribution');
    const authTypes = document.getElementById('authTypes');
    const portRisks = document.getElementById('portRisks');

    if (!portsContent) return;

    try {
      // Show loading state
      portsContent.innerHTML = '<div class="loading-state"><p>Loading port and authentication analysis...</p></div>';

      // Request port analysis from background script
      const response = await chrome.runtime.sendMessage({ action: 'getPortAnalysis' });

      if (!response || !response.success) {
        portsContent.innerHTML = '<div class="empty-state"><p>No port analysis data available.</p></div>';
        return;
      }

      const { ports, authTypes: authTypeData, risks } = response.data;

      // Render port distribution
      if (portDistribution) {
        portDistribution.innerHTML = this.renderPortDistribution(ports);
      }

      // Render auth types
      if (authTypes) {
        authTypes.innerHTML = this.renderAuthTypes(authTypeData);
      }

      // Render risks
      if (portRisks) {
        portRisks.innerHTML = this.renderPortRisks(risks);
      }

      // Clear loading state
      portsContent.innerHTML = '<div class="empty-state"><p>Port analysis complete. See summary above.</p></div>';

    } catch (error) {
      console.error('Failed to load port analysis:', error);
      portsContent.innerHTML = `<div class="error-state"><p>Error loading port analysis: ${error.message}</p></div>`;
    }
  }

  /**
   * Render port distribution
   */
  renderPortDistribution(ports) {
    if (!ports || Object.keys(ports).length === 0) {
      return '<p>No ports detected</p>';
    }

    let html = '<ul class="port-list">';
    Object.entries(ports).forEach(([port, count]) => {
      const portName = this.getPortName(port);
      html += `<li><strong>Port ${port}</strong> (${portName}): ${count} request(s)</li>`;
    });
    html += '</ul>';
    return html;
  }

  /**
   * Render authentication types
   */
  renderAuthTypes(authTypes) {
    if (!authTypes || Object.keys(authTypes).length === 0) {
      return '<p>No authentication types detected</p>';
    }

    let html = '<ul class="auth-type-list">';
    Object.entries(authTypes).forEach(([type, count]) => {
      html += `<li><strong>${type}</strong>: ${count} request(s)</li>`;
    });
    html += '</ul>';
    return html;
  }

  /**
   * Render port security risks
   */
  renderPortRisks(risks) {
    if (!risks || risks.length === 0) {
      return '<p class="success">No port-related security risks detected</p>';
    }

    let html = '<ul class="risk-list">';
    risks.forEach(risk => {
      html += `<li class="risk-${risk.severity}"><strong>${risk.title}</strong>: ${risk.description}</li>`;
    });
    html += '</ul>';
    return html;
  }

  /**
   * Get friendly port name
   */
  getPortName(port) {
    const portNames = {
      '80': 'HTTP',
      '443': 'HTTPS',
      '8080': 'HTTP-Alt',
      '8443': 'HTTPS-Alt',
      '3000': 'Development',
      '5000': 'Development',
      '8000': 'Development'
    };
    return portNames[port] || 'Unknown';
  }

  /**
   * Load extensions security analysis
   */
  async loadExtensionsAnalysis() {
    const extensionsContent = document.getElementById('extensionsContent');

    if (!extensionsContent) {
      console.error('Navigation: extensionsContent element not found');
      return;
    }

    console.log('Navigation: Loading extensions analysis...');

    try {
      // Show loading state
      extensionsContent.innerHTML = '<div class="loading-state"><p>Loading extension security assessments...</p></div>';

      // Request extensions analysis from background script
      console.log('Navigation: Sending getExtensionsAnalysis message to background');
      const response = await chrome.runtime.sendMessage({ action: 'getExtensionsAnalysis' });
      console.log('Navigation: Received response from background:', response);

      if (!response || !response.success) {
        console.warn('Navigation: Extensions analysis failed or returned no data');
        extensionsContent.innerHTML = '<div class="empty-state"><p>No extensions analysis data available.</p></div>';
        return;
      }

      const { extensions } = response.data;
      console.log(`Navigation: Found ${extensions?.length || 0} extensions`);

      if (!extensions || extensions.length === 0) {
        extensionsContent.innerHTML = '<div class="empty-state"><p>No extensions detected.</p></div>';
        return;
      }

      // Render extensions
      console.log('Navigation: Rendering extensions...');
      extensionsContent.innerHTML = this.renderExtensions(extensions);
      console.log('Navigation: Extensions rendered successfully');

    } catch (error) {
      console.error('Failed to load extensions analysis:', error);
      extensionsContent.innerHTML = `<div class="error-state"><p>Error loading extensions: ${error.message}</p></div>`;
    }
  }

  /**
   * Render extensions list
   */
  renderExtensions(extensions) {
    let html = '<div class="extensions-grid">';

    extensions.forEach(ext => {
      const riskClass = ext.riskLevel || 'low';
      html += `
        <div class="extension-card risk-${riskClass}">
          <div class="extension-header">
            <h4>${this.escapeHtml(ext.name)}</h4>
            <span class="risk-badge ${riskClass}">${riskClass.toUpperCase()}</span>
          </div>
          <div class="extension-details">
            <p><strong>Version:</strong> ${this.escapeHtml(ext.version)}</p>
            <p><strong>Permissions:</strong> ${ext.permissions ? ext.permissions.length : 0}</p>
            ${ext.issues && ext.issues.length > 0 ? `
              <div class="extension-issues">
                <strong>Issues:</strong>
                <ul>
                  ${ext.issues.map(issue => `<li>${this.escapeHtml(issue)}</li>`).join('')}
                </ul>
              </div>
            ` : ''}
          </div>
        </div>
      `;
    });

    html += '</div>';
    return html;
  }

  /**
   * Escape HTML to prevent XSS
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  /**
   * Get current view
   */
  getCurrentView() {
    return this.currentView;
  }
}
