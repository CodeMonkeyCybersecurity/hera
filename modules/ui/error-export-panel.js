// Error Export Panel UI
// Displays errors and allows export

export class ErrorExportPanel {
  constructor(errorCollector) {
    this.errorCollector = errorCollector;
  }

  /**
   * Render error panel in popup
   */
  render(container) {
    const stats = this.errorCollector.getStats();

    const html = `
      <div class="error-export-panel">
        <div class="error-stats">
          <h3>🐛 Error Log</h3>
          <div class="stats-summary">
            <span class="stat-badge error">${stats.total} errors</span>
            <span class="stat-badge warning">${stats.warnings} warnings</span>
          </div>
        </div>

        <div class="error-actions">
          <button id="exportErrorsJSON" class="btn btn-primary">
            📥 Export JSON
          </button>
          <button id="exportErrorsTXT" class="btn btn-secondary">
            📄 Export Text
          </button>
          <button id="copyErrors" class="btn btn-secondary">
            📋 Copy to Clipboard
          </button>
          <button id="clearErrors" class="btn btn-danger">
            🗑️ Clear Errors
          </button>
        </div>

        <div class="error-list" id="errorList">
          ${this.renderErrorList()}
        </div>
      </div>
    `;

    container.innerHTML = html;
    this.attachEventListeners();
  }

  /**
   * Render error list
   */
  renderErrorList() {
    const { errors, warnings } = this.errorCollector.getErrors();

    if (errors.length === 0 && warnings.length === 0) {
      return '<div class="empty-state">✅ No errors or warnings</div>';
    }

    let html = '';

    // Show last 20 errors
    const recentErrors = errors.slice(-20).reverse();
    for (const err of recentErrors) {
      html += `
        <div class="error-item error-level-error">
          <div class="error-header">
            <span class="error-type">${err.type}</span>
            <span class="error-time">${new Date(err.timestamp).toLocaleTimeString()}</span>
          </div>
          <div class="error-message">${this.escapeHtml(err.message)}</div>
          ${err.filename ? `<div class="error-location">${err.filename}:${err.lineno}</div>` : ''}
        </div>
      `;
    }

    return html;
  }

  /**
   * Attach event listeners
   */
  attachEventListeners() {
    document.getElementById('exportErrorsJSON')?.addEventListener('click', () => {
      this.errorCollector.downloadErrors('json');
    });

    document.getElementById('exportErrorsTXT')?.addEventListener('click', () => {
      this.errorCollector.downloadErrors('txt');
    });

    document.getElementById('copyErrors')?.addEventListener('click', async () => {
      const text = this.errorCollector.exportText();
      try {
        await navigator.clipboard.writeText(text);
        alert('✅ Errors copied to clipboard!');
      } catch (err) {
        alert('❌ Failed to copy to clipboard');
      }
    });

    document.getElementById('clearErrors')?.addEventListener('click', async () => {
      if (confirm('Clear all errors?')) {
        await this.errorCollector.clearErrors();
        this.render(document.querySelector('.error-export-panel').parentElement);
      }
    });
  }

  /**
   * Escape HTML
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}
