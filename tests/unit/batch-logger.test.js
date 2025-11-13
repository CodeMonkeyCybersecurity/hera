/**
 * Tests for BatchLogger
 *
 * PURPOSE: Verify batched logging functionality
 * - Log batching and aggregation
 * - Periodic flushing
 * - Immediate logging for errors/warnings
 * - Statistics tracking
 *
 * @see modules/utils/batch-logger.js
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { BatchLogger } from '../../modules/utils/batch-logger.js';

describe('BatchLogger', () => {
  let logger;
  let consoleLogSpy;
  let consoleDebugSpy;
  let consoleWarnSpy;
  let consoleErrorSpy;
  let consoleGroupCollapsedSpy;
  let consoleGroupEndSpy;

  beforeEach(() => {
    // Mock console methods
    consoleLogSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
    consoleDebugSpy = vi.spyOn(console, 'debug').mockImplementation(() => {});
    consoleWarnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    consoleGroupCollapsedSpy = vi.spyOn(console, 'groupCollapsed').mockImplementation(() => {});
    consoleGroupEndSpy = vi.spyOn(console, 'groupEnd').mockImplementation(() => {});

    // Create logger with no auto-flush for manual control
    logger = new BatchLogger({ autoFlush: false, interval: 10000 });
  });

  afterEach(() => {
    logger.destroy();
    vi.restoreAllMocks();
  });

  describe('initialization', () => {
    it('should initialize with default options', () => {
      const defaultLogger = new BatchLogger({ autoFlush: false });

      expect(defaultLogger.LOG_INTERVAL_MS).toBe(10000);
      expect(defaultLogger.batchedLogs.size).toBe(0);
      expect(defaultLogger.immediateCategories.has('error')).toBe(true);
      expect(defaultLogger.immediateCategories.has('warn')).toBe(true);

      defaultLogger.destroy();
    });

    it('should initialize with custom interval', () => {
      const customLogger = new BatchLogger({ interval: 5000, autoFlush: false });

      expect(customLogger.LOG_INTERVAL_MS).toBe(5000);

      customLogger.destroy();
    });

    it('should initialize with custom immediate categories', () => {
      const customLogger = new BatchLogger({
        immediate: ['critical', 'alert'],
        autoFlush: false
      });

      expect(customLogger.immediateCategories.has('critical')).toBe(true);
      expect(customLogger.immediateCategories.has('alert')).toBe(true);

      customLogger.destroy();
    });
  });

  describe('log batching', () => {
    it('should batch single log message', () => {
      logger.log('test-category', 'Test message');

      expect(logger.batchedLogs.size).toBe(1);
      expect(logger.batchedLogs.has('test-category')).toBe(true);

      const batch = logger.batchedLogs.get('test-category');
      expect(batch.count).toBe(1);
      expect(batch.lastMessage).toBe('Test message');
    });

    it('should batch multiple log messages in same category', () => {
      logger.log('test-category', 'Message 1');
      logger.log('test-category', 'Message 2');
      logger.log('test-category', 'Message 3');

      expect(logger.batchedLogs.size).toBe(1);

      const batch = logger.batchedLogs.get('test-category');
      expect(batch.count).toBe(3);
      expect(batch.lastMessage).toBe('Message 3');
    });

    it('should batch messages in different categories separately', () => {
      logger.log('category-a', 'Message A1');
      logger.log('category-b', 'Message B1');
      logger.log('category-a', 'Message A2');

      expect(logger.batchedLogs.size).toBe(2);
      expect(logger.batchedLogs.get('category-a').count).toBe(2);
      expect(logger.batchedLogs.get('category-b').count).toBe(1);
    });

    it('should store optional data with batched logs', () => {
      logger.log('test-category', 'Message 1', 'log', { id: 1 });
      logger.log('test-category', 'Message 2', 'log', { id: 2 });

      const batch = logger.batchedLogs.get('test-category');
      expect(batch.data).toHaveLength(2);
      expect(batch.data[0]).toEqual({ id: 1 });
      expect(batch.data[1]).toEqual({ id: 2 });
    });
  });

  describe('immediate logging', () => {
    it('should log errors immediately without batching', () => {
      logger.error('test-error', 'Error message', new Error('Test error'));

      expect(consoleErrorSpy).toHaveBeenCalledWith(
        '[test-error] Error message',
        expect.any(Error)
      );
      expect(logger.batchedLogs.size).toBe(0);
    });

    it('should log warnings immediately without batching', () => {
      logger.warn('test-warn', 'Warning message', { data: 'test' });

      expect(consoleWarnSpy).toHaveBeenCalledWith(
        '[test-warn] Warning message',
        { data: 'test' }
      );
      expect(logger.batchedLogs.size).toBe(0);
    });

    it('should log immediate category messages without batching', () => {
      logger.log('error', 'Critical message', 'log');

      expect(consoleLogSpy).toHaveBeenCalledWith(
        '[error] Critical message',
        ''
      );
      expect(logger.batchedLogs.size).toBe(0);
    });
  });

  describe('flush functionality', () => {
    it('should flush empty batch without error', () => {
      logger.flush();

      expect(consoleGroupCollapsedSpy).not.toHaveBeenCalled();
    });

    it('should flush single batched message', () => {
      logger.log('test-category', 'Test message');
      logger.flush();

      expect(consoleGroupCollapsedSpy).toHaveBeenCalled();
      expect(consoleLogSpy).toHaveBeenCalledWith(
        '[test-category] Test message'
      );
      expect(consoleGroupEndSpy).toHaveBeenCalled();
      expect(logger.batchedLogs.size).toBe(0);
    });

    it('should flush multiple batched messages with summary', () => {
      logger.log('test-category', 'Message 1');
      logger.log('test-category', 'Message 2');
      logger.log('test-category', 'Message 3');
      logger.flush();

      expect(consoleGroupCollapsedSpy).toHaveBeenCalled();
      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining('3× operations')
      );
      expect(consoleGroupEndSpy).toHaveBeenCalled();
    });

    it('should flush multiple categories', () => {
      logger.log('category-a', 'Message A');
      logger.log('category-b', 'Message B1');
      logger.log('category-b', 'Message B2');
      logger.flush();

      expect(consoleGroupCollapsedSpy).toHaveBeenCalledWith(
        expect.stringContaining('2 categories')
      );
      expect(logger.batchedLogs.size).toBe(0);
    });

    it('should clear batched logs after flush', () => {
      logger.log('test-category', 'Message 1');
      logger.log('test-category', 'Message 2');

      expect(logger.batchedLogs.size).toBe(1);

      logger.flush();

      expect(logger.batchedLogs.size).toBe(0);
    });

    it('should show data for small batches', () => {
      logger.log('test-category', 'Message 1', 'log', { id: 1 });
      logger.log('test-category', 'Message 2', 'log', { id: 2 });
      logger.flush();

      expect(consoleLogSpy).toHaveBeenCalledWith('  [1]', { id: 1 });
      expect(consoleLogSpy).toHaveBeenCalledWith('  [2]', { id: 2 });
    });

    it('should show summary for large batches', () => {
      for (let i = 0; i < 10; i++) {
        logger.log('test-category', `Message ${i}`, 'log', { id: i });
      }
      logger.flush();

      expect(consoleLogSpy).toHaveBeenCalledWith(
        expect.stringContaining('10 data entries')
      );
    });
  });

  describe('helper methods', () => {
    it('should log debug messages with batching', () => {
      logger.debug('test-category', 'Debug message');

      expect(logger.batchedLogs.size).toBe(1);

      const batch = logger.batchedLogs.get('test-category');
      expect(batch.level).toBe('debug');
    });

    it('should log info messages with batching', () => {
      logger.info('test-category', 'Info message');

      expect(logger.batchedLogs.size).toBe(1);

      const batch = logger.batchedLogs.get('test-category');
      expect(batch.level).toBe('info');
    });

    it('should use correct console method for level', () => {
      logger.debug('test-category', 'Debug message');
      logger.flush();

      expect(consoleDebugSpy).toHaveBeenCalled();
    });
  });

  describe('flushNow method', () => {
    it('should immediately flush batched logs', () => {
      logger.log('test-category', 'Message 1');
      logger.log('test-category', 'Message 2');

      logger.flushNow();

      expect(consoleGroupCollapsedSpy).toHaveBeenCalled();
      expect(logger.batchedLogs.size).toBe(0);
    });
  });

  describe('getStats method', () => {
    it('should return empty stats for no batched logs', () => {
      const stats = logger.getStats();

      expect(stats.categoriesBuffered).toBe(0);
      expect(stats.totalMessages).toBe(0);
      expect(stats.oldestBatch).toBeNull();
      expect(stats.categories).toHaveLength(0);
    });

    it('should return correct stats for batched logs', () => {
      logger.log('category-a', 'Message A1');
      logger.log('category-a', 'Message A2');
      logger.log('category-b', 'Message B1');

      const stats = logger.getStats();

      expect(stats.categoriesBuffered).toBe(2);
      expect(stats.totalMessages).toBe(3);
      expect(stats.categories).toHaveLength(2);
      expect(stats.oldestBatch).toBeDefined();
    });

    it('should track age of batches', () => {
      logger.log('test-category', 'Message 1');

      const stats = logger.getStats();
      const categoryStats = stats.categories.find(c => c.name === 'test-category');

      expect(categoryStats.age).toBeGreaterThanOrEqual(0);
    });
  });

  describe('destroy method', () => {
    it('should flush logs before destroying', () => {
      logger.log('test-category', 'Message 1');

      logger.destroy();

      expect(consoleGroupCollapsedSpy).toHaveBeenCalled();
    });

    it('should clear interval timer', () => {
      const autoFlushLogger = new BatchLogger({ interval: 10000 });

      expect(autoFlushLogger.flushInterval).toBeDefined();

      autoFlushLogger.destroy();

      expect(autoFlushLogger.flushInterval).toBeNull();
    });
  });

  describe('auto-flush', () => {
    it('should auto-flush after interval elapsed', () => {
      vi.useFakeTimers();

      const autoLogger = new BatchLogger({ interval: 1000 });
      autoLogger.log('test-category', 'Message 1');

      vi.advanceTimersByTime(1000);

      expect(consoleGroupCollapsedSpy).toHaveBeenCalled();

      autoLogger.destroy();
      vi.useRealTimers();
    });
  });

  describe('edge cases', () => {
    it('should handle null data gracefully', () => {
      logger.log('test-category', 'Message 1', 'log', null);

      const batch = logger.batchedLogs.get('test-category');
      expect(batch.data).toHaveLength(0);
    });

    it('should handle undefined data gracefully', () => {
      logger.log('test-category', 'Message 1', 'log', undefined);

      const batch = logger.batchedLogs.get('test-category');
      expect(batch.data).toHaveLength(0);
    });

    it('should handle empty message', () => {
      logger.log('test-category', '');

      const batch = logger.batchedLogs.get('test-category');
      expect(batch.lastMessage).toBe('');
    });

    it('should handle special characters in category', () => {
      logger.log('test/category:with:special-chars', 'Message');

      expect(logger.batchedLogs.has('test/category:with:special-chars')).toBe(true);
    });

    it('should handle invalid log level gracefully', () => {
      logger.log('test-category', 'Message', 'invalid-level');
      logger.flush();

      // Should fall back to console.log
      expect(consoleLogSpy).toHaveBeenCalled();
    });
  });
});
