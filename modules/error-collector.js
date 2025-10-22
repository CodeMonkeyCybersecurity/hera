// Error Collector Module
// Collects all extension errors and warnings for easy export

class ErrorCollector {
  constructor() {
    this.errors = [];
    this.warnings = [];
    this.infos = [];
    this.maxEntries = 1000; // Prevent memory overflow

    // Intercept console errors
    this.setupErrorHandlers();
  }

  /**
   * Setup global error handlers
   */
  setupErrorHandlers() {
    // Capture unhandled errors
    if (typeof self !== 'undefined') {
      self.addEventListener('error', (event) => {
        this.logError({
          type: 'UNHANDLED_ERROR',
          message: event.message || 'Unknown error',
          stack: event.error?.stack,
          filename: event.filename,
          lineno: event.lineno,
          colno: event.colno,
          timestamp: new Date().toISOString()
        });
      });

      // Capture unhandled promise rejections
      self.addEventListener('unhandledrejection', (event) => {
        this.logError({
          type: 'UNHANDLED_REJECTION',
          message: event.reason?.message || String(event.reason),
          stack: event.reason?.stack,
          timestamp: new Date().toISOString()
        });
      });
    }

    // Wrap console methods
    this.wrapConsole();
  }

  /**
   * Wrap console methods to capture errors
   */
  wrapConsole() {
    const originalError = console.error;
    const originalWarn = console.warn;
    const originalLog = console.log;

    console.error = (...args) => {
      this.logError({
        type: 'CONSOLE_ERROR',
        message: args.map(a => String(a)).join(' '),
        args: args,
        stack: new Error().stack,
        timestamp: new Date().toISOString()
      });
      originalError.apply(console, args);
    };

    console.warn = (...args) => {
      this.logWarning({
        type: 'CONSOLE_WARN',
        message: args.map(a => String(a)).join(' '),
        args: args,
        timestamp: new Date().toISOString()
      });
      originalWarn.apply(console, args);
    };

    // Optionally capture logs for debugging
    if (this.captureDebugLogs) {
      console.log = (...args) => {
        this.logInfo({
          type: 'CONSOLE_LOG',
          message: args.map(a => String(a)).join(' '),
          args: args,
          timestamp: new Date().toISOString()
        });
        originalLog.apply(console, args);
      };
    }
  }

  /**
   * Log an error
   */
  logError(error) {
    this.errors.push(error);
    if (this.errors.length > this.maxEntries) {
      this.errors.shift(); // Remove oldest
    }

    // Store in chrome.storage for persistence
    this.persistErrors();
  }

  /**
   * Log a warning
   */
  logWarning(warning) {
    this.warnings.push(warning);
    if (this.warnings.length > this.maxEntries) {
      this.warnings.shift();
    }
  }

  /**
   * Log info
   */
  logInfo(info) {
    this.infos.push(info);
    if (this.infos.length > this.maxEntries) {
      this.infos.shift();
    }
  }

  /**
   * Get all errors
   */
  getErrors() {
    return {
      errors: this.errors,
      warnings: this.warnings,
      infos: this.infos,
      summary: {
        errorCount: this.errors.length,
        warningCount: this.warnings.length,
        infoCount: this.infos.length
      }
    };
  }

  /**
   * Export errors as JSON
   */
  exportJSON() {
    const data = {
      exportedAt: new Date().toISOString(),
      extensionVersion: chrome.runtime.getManifest().version,
      ...this.getErrors()
    };

    return JSON.stringify(data, null, 2);
  }

  /**
   * Export errors as formatted text
   */
  exportText() {
    const lines = [];
    lines.push('='.repeat(80));
    lines.push('HERA ERROR REPORT');
    lines.push('='.repeat(80));
    lines.push(`Exported: ${new Date().toISOString()}`);
    lines.push(`Extension Version: ${chrome.runtime.getManifest().version}`);
    lines.push('');

    // Errors
    if (this.errors.length > 0) {
      lines.push(`ERRORS (${this.errors.length}):`);
      lines.push('-'.repeat(80));
      for (const err of this.errors) {
        lines.push(`[${err.timestamp}] ${err.type}: ${err.message}`);
        if (err.filename) {
          lines.push(`  File: ${err.filename}:${err.lineno}:${err.colno}`);
        }
        if (err.stack) {
          lines.push(`  Stack: ${err.stack.split('\n')[0]}`);
        }
        lines.push('');
      }
    }

    // Warnings
    if (this.warnings.length > 0) {
      lines.push(`WARNINGS (${this.warnings.length}):`);
      lines.push('-'.repeat(80));
      for (const warn of this.warnings) {
        lines.push(`[${warn.timestamp}] ${warn.type}: ${warn.message}`);
        lines.push('');
      }
    }

    return lines.join('\n');
  }

  /**
   * Download errors as file
   */
  async downloadErrors(format = 'json') {
    const content = format === 'json' ? this.exportJSON() : this.exportText();
    const filename = `hera-errors-${Date.now()}.${format === 'json' ? 'json' : 'txt'}`;

    const blob = new Blob([content], { type: format === 'json' ? 'application/json' : 'text/plain' });
    const url = URL.createObjectURL(blob);

    try {
      await chrome.downloads.download({
        url: url,
        filename: filename,
        saveAs: true
      });
      console.log(`✅ Errors exported to ${filename}`);
    } catch (err) {
      console.error('Failed to download errors:', err);
    }
  }

  /**
   * Persist errors to storage
   */
  async persistErrors() {
    try {
      await chrome.storage.local.set({
        heraErrors: {
          errors: this.errors.slice(-100), // Keep last 100
          warnings: this.warnings.slice(-100),
          lastUpdated: new Date().toISOString()
        }
      });
    } catch (err) {
      // Ignore storage errors to prevent infinite loop
    }
  }

  /**
   * Load persisted errors
   */
  async loadPersistedErrors() {
    try {
      const result = await chrome.storage.local.get('heraErrors');
      if (result.heraErrors) {
        this.errors = result.heraErrors.errors || [];
        this.warnings = result.heraErrors.warnings || [];
      }
    } catch (err) {
      console.warn('Failed to load persisted errors:', err);
    }
  }

  /**
   * Clear all errors
   */
  async clearErrors() {
    this.errors = [];
    this.warnings = [];
    this.infos = [];

    try {
      await chrome.storage.local.remove('heraErrors');
    } catch (err) {
      console.warn('Failed to clear stored errors:', err);
    }
  }

  /**
   * Get error statistics
   */
  getStats() {
    const errorTypes = {};
    for (const err of this.errors) {
      errorTypes[err.type] = (errorTypes[err.type] || 0) + 1;
    }

    return {
      total: this.errors.length,
      warnings: this.warnings.length,
      byType: errorTypes,
      oldest: this.errors[0]?.timestamp,
      newest: this.errors[this.errors.length - 1]?.timestamp
    };
  }
}

// Create singleton instance
const errorCollector = new ErrorCollector();

// Load persisted errors on startup
errorCollector.loadPersistedErrors();

export { errorCollector, ErrorCollector };
