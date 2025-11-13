/**
 * Batch Logger Utility
 *
 * PURPOSE: Reduce console spam by batching similar log messages
 * - Aggregates frequent log messages
 * - Outputs periodic summaries
 * - Reduces CPU usage from excessive logging
 *
 * IMPLEMENTATION: P1-3 (Batch Log Updates)
 * @see ROADMAP.md P1-3: Batch Log Updates
 */

export class BatchLogger {
  constructor(options = {}) {
    this.LOG_INTERVAL_MS = options.interval || 10000; // 10 seconds default
    this.lastLogTime = 0;
    this.batchedLogs = new Map(); // category → { count, lastMessage, firstSeen }
    this.immediateCategories = new Set(options.immediate || ['error', 'warn']);

    // Start periodic flush
    if (options.autoFlush !== false) {
      this.flushInterval = setInterval(() => this.flush(), this.LOG_INTERVAL_MS);
    }
  }

  /**
   * Log a message with batching
   *
   * @param {string} category - Log category for batching (e.g., 'evidence-capture', 'cleanup')
   * @param {string} message - Log message
   * @param {string} level - Log level ('log', 'debug', 'info', 'warn', 'error')
   * @param {Object} data - Optional data to log
   */
  log(category, message, level = 'log', data = null) {
    // Immediate logging for errors/warnings
    if (this.immediateCategories.has(level) || this.immediateCategories.has(category)) {
      console[level](`[${category}] ${message}`, data || '');
      return;
    }

    // Batch normal logs
    if (!this.batchedLogs.has(category)) {
      this.batchedLogs.set(category, {
        count: 0,
        lastMessage: message,
        level: level,
        firstSeen: Date.now(),
        data: []
      });
    }

    const batch = this.batchedLogs.get(category);
    batch.count++;
    batch.lastMessage = message;
    if (data) {
      batch.data.push(data);
    }

    // Note: Flushing is handled by the interval timer, not here
    // This prevents auto-flushing from interfering with batching
  }

  /**
   * Log debug message with batching
   */
  debug(category, message, data = null) {
    this.log(category, message, 'debug', data);
  }

  /**
   * Log info message with batching
   */
  info(category, message, data = null) {
    this.log(category, message, 'info', data);
  }

  /**
   * Log warning immediately (no batching)
   */
  warn(category, message, data = null) {
    console.warn(`[${category}] ${message}`, data || '');
  }

  /**
   * Log error immediately (no batching)
   */
  error(category, message, error = null) {
    console.error(`[${category}] ${message}`, error || '');
  }

  /**
   * Flush batched logs to console
   */
  flush() {
    if (this.batchedLogs.size === 0) {
      return;
    }

    const now = Date.now();
    const elapsed = Math.round((now - this.lastLogTime) / 1000);
    this.lastLogTime = now;

    console.groupCollapsed(`[Hera] Batched logs (${elapsed}s, ${this.batchedLogs.size} categories)`);

    for (const [category, batch] of this.batchedLogs.entries()) {
      const duration = Math.round((now - batch.firstSeen) / 1000);
      const logFn = console[batch.level] || console.log;

      if (batch.count === 1) {
        // Single occurrence - log normally
        logFn(`[${category}] ${batch.lastMessage}`);
      } else {
        // Multiple occurrences - show summary
        logFn(`[${category}] ${batch.count}× operations in ${duration}s`);
        if (batch.lastMessage) {
          console.log(`  Last: ${batch.lastMessage}`);
        }
        if (batch.data.length > 0 && batch.data.length <= 3) {
          // Show data for small batches
          batch.data.forEach((d, i) => {
            console.log(`  [${i + 1}]`, d);
          });
        } else if (batch.data.length > 3) {
          console.log(`  (${batch.data.length} data entries - use detailed logging to see all)`);
        }
      }
    }

    console.groupEnd();

    // Clear batched logs
    this.batchedLogs.clear();
  }

  /**
   * Force immediate flush
   */
  flushNow() {
    this.flush();
  }

  /**
   * Destroy logger and stop auto-flush
   */
  destroy() {
    if (this.flushInterval) {
      clearInterval(this.flushInterval);
      this.flushInterval = null;
    }
    this.flush(); // Final flush
  }

  /**
   * Get current batch statistics
   */
  getStats() {
    const stats = {
      categoriesBuffered: this.batchedLogs.size,
      totalMessages: 0,
      oldestBatch: null,
      categories: []
    };

    let oldestTime = Infinity;

    for (const [category, batch] of this.batchedLogs.entries()) {
      stats.totalMessages += batch.count;
      stats.categories.push({
        name: category,
        count: batch.count,
        age: Date.now() - batch.firstSeen
      });

      if (batch.firstSeen < oldestTime) {
        oldestTime = batch.firstSeen;
        stats.oldestBatch = category;
      }
    }

    return stats;
  }
}
