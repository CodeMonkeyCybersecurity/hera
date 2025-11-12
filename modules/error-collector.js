// Error Collector Module
// Collects all extension errors and warnings for easy export

// Size limits to prevent storage bloat
const MAX_ENTRY_BYTES = 50000; // 50 KB per entry
const MAX_ARGS_PREVIEW = 5000; // 5 KB for args preview
const DEDUPE_WINDOW_MS = 5000; // 5 seconds

class ErrorCollector {
  constructor() {
    this.errors = [];
    this.warnings = [];
    this.infos = [];
    this.maxEntries = 100; // Reduced from 1000 to prevent storage bloat

    // Dedupe cache for noisy repeats
    this._lastSeen = new Map(); // key -> timestamp

    // OFF by default; can be toggled by message or storage
    this.captureDebugLogs = false;

    // FIX: Debounce timer for persistence (prevent rate limit violations)
    this._persistTimer = null;
    this._PERSIST_DELAY = 1000; // 1 second

    // Intercept console errors
    this.setupErrorHandlers();
  }

  /**
   * Generate dedupe key for an error/warning
   */
  _dedupeKey(obj) {
    const type = obj?.type ?? 'UNKNOWN';
    const msg = (obj?.message || '').slice(0, 160);
    return `${type}|${msg}`;
  }

  /**
   * Check if we should log this error (de-dupe check)
   */
  _shouldLog(obj) {
    const key = this._dedupeKey(obj);
    const last = this._lastSeen.get(key) || 0;
    const now = Date.now();
    if (now - last < DEDUPE_WINDOW_MS) return false; // suppress burst
    this._lastSeen.set(key, now);
    return true;
  }

  /**
   * Safely stringify a value with size limit
   */
  _safeStringify(value, byteLimit) {
    const seen = new WeakSet();
    let bytes = 0;
    const replacer = (_k, v) => {
      if (typeof v === 'object' && v !== null) {
        if (seen.has(v)) return '[Circular]';
        seen.add(v);

        // Skip huge types outright
        if (v instanceof Blob) return `[Blob ${v.type || ''} ${v.size || '?'} bytes]`;
        if (v instanceof ArrayBuffer) return `[ArrayBuffer ${v.byteLength} bytes]`;
        if (ArrayBuffer.isView(v)) return `[TypedArray ${v.byteLength} bytes]`;
      }

      // FIX: Properly convert to string for size calculation
      let str;
      if (typeof v === 'string') {
        str = v;
      } else {
        try {
          str = JSON.stringify(v);
        } catch {
          str = String(v);
        }
      }

      bytes += str.length; // rough count
      if (bytes > byteLimit) return '[TRUNCATED]';

      // Trim very long strings
      if (typeof v === 'string' && v.length > 4000) {
        return v.slice(0, 4000) + '… [truncated]';
      }
      return v; // Return original value - JSON.stringify handles conversion
    };

    try {
      const s = JSON.stringify(value, replacer);
      if (new Blob([s]).size > byteLimit) return '[TRUNCATED_OBJECT]';
      return s;
    } catch {
      return '[UNSERIALIZABLE]';
    }
  }

  /**
   * Shrink entry to stay under size limits
   */
  _shrink(entry) {
    const e = { ...entry };

    // Limit args preview
    if (Array.isArray(e.args)) {
      e.argsPreview = this._safeStringify(e.args, MAX_ARGS_PREVIEW);
      delete e.args; // don't persist full args
    }

    // Trim stack to first line + ~2KB tail
    if (typeof e.stack === 'string' && e.stack.length > 2000) {
      const first = e.stack.split('\n')[0];
      e.stack = `${first}\n… [stack truncated]`;
    }

    // Final size check
    const blob = new Blob([JSON.stringify(e)]);
    if (blob.size > MAX_ENTRY_BYTES) {
      // Keep only a minimal summary
      return {
        type: e.type,
        message: (e.message || '').slice(0, 500),
        timestamp: e.timestamp,
        note: `Entry truncated to stay under ${Math.round(MAX_ENTRY_BYTES/1024)}KB.`,
      };
    }
    return e;
  }

  /**
   * Setup global error handlers
   */
  setupErrorHandlers() {
    // Capture unhandled errors
    if (typeof self !== 'undefined') {
      self.addEventListener('error', (event) => {
        const entry = {
          type: 'UNHANDLED_ERROR',
          message: event.message || 'Unknown error',
          stack: event.error?.stack,
          filename: event.filename,
          lineno: event.lineno,
          colno: event.colno,
          timestamp: new Date().toISOString()
        };
        // FIX: Add de-dupe check to prevent error bursts
        if (this._shouldLog(entry)) {
          this.logError(entry);
        }
      });

      // Capture unhandled promise rejections
      self.addEventListener('unhandledrejection', (event) => {
        const entry = {
          type: 'UNHANDLED_REJECTION',
          message: event.reason?.message || String(event.reason),
          stack: event.reason?.stack,
          timestamp: new Date().toISOString()
        };
        // FIX: Add de-dupe check to prevent rejection bursts
        if (this._shouldLog(entry)) {
          this.logError(entry);
        }
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
      // BUGFIX: Don't log storage quota errors to prevent infinite loop
      const message = args.map(a => String(a)).join(' ');
      if (!message.includes('Storage rate limit') && !message.includes('QUOTA_BYTES')) {
        const entry = {
          type: 'CONSOLE_ERROR',
          message: message,
          args: args,
          stack: new Error().stack,
          timestamp: new Date().toISOString()
        };
        if (this._shouldLog(entry)) {
          this.logError(entry);
        }
      }
      originalError.apply(console, args);
    };

    console.warn = (...args) => {
      const entry = {
        type: 'CONSOLE_WARN',
        message: args.map(a => String(a)).join(' '),
        args: args,
        timestamp: new Date().toISOString()
      };
      if (this._shouldLog(entry)) {
        this.logWarning(entry);
      }
      originalWarn.apply(console, args);
    };

    // Optionally capture logs for debugging
    if (this.captureDebugLogs) {
      console.log = (...args) => {
        const entry = {
          type: 'CONSOLE_LOG',
          message: args.map(a => String(a)).join(' '),
          args: args,
          timestamp: new Date().toISOString()
        };
        if (this._shouldLog(entry)) {
          this.logInfo(entry);
        }
        originalLog.apply(console, args);
      };
    }
  }

  /**
   * Schedule debounced persistence
   */
  _schedulePersist() {
    // Clear existing timer
    if (this._persistTimer) {
      clearTimeout(this._persistTimer);
    }

    // Schedule new write (debounced)
    this._persistTimer = setTimeout(() => {
      this.persistErrors();
      this._persistTimer = null;
    }, this._PERSIST_DELAY);
  }

  /**
   * Log an error
   */
  logError(error) {
    const safe = this._shrink(error);
    this.errors.push(safe);
    if (this.errors.length > this.maxEntries) {
      this.errors.shift(); // Remove oldest
    }

    // FIX: Debounce persistence to prevent storage rate limit violations
    this._schedulePersist();
  }

  /**
   * Log a warning
   */
  logWarning(warning) {
    const safe = this._shrink(warning);
    this.warnings.push(safe);
    if (this.warnings.length > this.maxEntries) {
      this.warnings.shift();
    }
    // Do NOT persist on every warning to reduce write pressure
  }

  /**
   * Log info
   */
  logInfo(info) {
    const safe = this._shrink(info);
    this.infos.push(safe);
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
   * Persist errors to storage immediately (cancels debounce timer)
   */
  async persistErrorsNow() {
    // Cancel pending debounced write
    if (this._persistTimer) {
      clearTimeout(this._persistTimer);
      this._persistTimer = null;
    }
    await this.persistErrors();
  }

  /**
   * Persist errors to storage (internal - called by debounce timer)
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
      // BUGFIX: Silently ignore storage errors to prevent infinite loop
      // Don't log this error as it would cause recursion
      // Storage quota errors are expected when monitoring high-traffic sites
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
