/**
 * Tests for NotificationManager
 *
 * PURPOSE: Verify notification functionality for security findings
 * - Notification thresholds (confidence + severity)
 * - Badge updates
 * - Notification deduplication
 * - Statistics tracking
 *
 * @see modules/notification-manager.js
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { NotificationManager } from '../../modules/notification-manager.js';

// Mock chrome APIs
global.chrome = {
  notifications: {
    create: vi.fn((options, callback) => {
      const id = `notif-${Date.now()}`;
      callback(id);
      return id;
    }),
    onClicked: { addListener: vi.fn() },
    onButtonClicked: { addListener: vi.fn() }
  },
  action: {
    setBadgeText: vi.fn((options) => Promise.resolve()),
    setBadgeBackgroundColor: vi.fn((options) => Promise.resolve()),
    openPopup: vi.fn()
  },
  runtime: {
    sendMessage: vi.fn((message) => Promise.resolve({ success: true })),
    lastError: null
  }
};

describe('NotificationManager', () => {
  let manager;

  beforeEach(() => {
    manager = new NotificationManager();
    vi.clearAllMocks();
  });

  afterEach(() => {
    manager.clearAll();
  });

  describe('initialization', () => {
    it('should initialize with correct defaults', () => {
      expect(manager.MIN_CONFIDENCE).toBe('MEDIUM');
      expect(manager.MIN_SEVERITY).toBe('MEDIUM');
      expect(manager.notifiedFindings.size).toBe(0);
      expect(manager.findingCounts.size).toBe(0);
    });
  });

  describe('_shouldNotify', () => {
    it('should notify for HIGH confidence and MEDIUM severity', () => {
      const finding = { confidence: 'HIGH', severity: 'MEDIUM' };
      expect(manager._shouldNotify(finding)).toBe(true);
    });

    it('should notify for HIGH confidence and HIGH severity', () => {
      const finding = { confidence: 'HIGH', severity: 'HIGH' };
      expect(manager._shouldNotify(finding)).toBe(true);
    });

    it('should not notify for LOW confidence', () => {
      const finding = { confidence: 'LOW', severity: 'HIGH' };
      expect(manager._shouldNotify(finding)).toBe(false);
    });

    it('should not notify for LOW severity', () => {
      const finding = { confidence: 'HIGH', severity: 'LOW' };
      expect(manager._shouldNotify(finding)).toBe(false);
    });

    it('should notify for CRITICAL severity', () => {
      const finding = { confidence: 'MEDIUM', severity: 'CRITICAL' };
      expect(manager._shouldNotify(finding)).toBe(true);
    });
  });

  describe('notifyFinding', () => {
    it('should create notification for qualifying finding', async () => {
      const finding = {
        type: 'MISSING_STATE_PARAMETER',
        confidence: 'HIGH',
        severity: 'HIGH'
      };

      const notifId = await manager.notifyFinding(finding, 'auth.example.com');

      expect(notifId).toBeDefined();
      expect(chrome.notifications.create).toHaveBeenCalled();
      expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ text: '1' });
    });

    it('should not create notification for low confidence finding', async () => {
      const finding = {
        type: 'MISSING_STATE_PARAMETER',
        confidence: 'LOW',
        severity: 'HIGH'
      };

      const notifId = await manager.notifyFinding(finding, 'auth.example.com');

      expect(notifId).toBeNull();
      expect(chrome.notifications.create).not.toHaveBeenCalled();
    });

    it('should not create duplicate notifications', async () => {
      const finding = {
        type: 'MISSING_PKCE',
        confidence: 'HIGH',
        severity: 'MEDIUM'
      };

      await manager.notifyFinding(finding, 'auth.example.com');
      await manager.notifyFinding(finding, 'auth.example.com');

      expect(chrome.notifications.create).toHaveBeenCalledTimes(1);
    });

    it('should track finding counts by domain', async () => {
      const finding1 = { type: 'MISSING_STATE_PARAMETER', confidence: 'HIGH', severity: 'HIGH' };
      const finding2 = { type: 'MISSING_PKCE', confidence: 'HIGH', severity: 'MEDIUM' };

      await manager.notifyFinding(finding1, 'auth.example.com');
      await manager.notifyFinding(finding2, 'auth.example.com');

      expect(manager.findingCounts.get('auth.example.com')).toBe(2);
    });
  });

  describe('_formatFindingMessage', () => {
    it('should format known finding types', () => {
      const finding = { type: 'MISSING_STATE_PARAMETER' };
      const message = manager._formatFindingMessage(finding);

      expect(message).toBe('Missing CSRF protection (state parameter)');
    });

    it('should format unknown finding types', () => {
      const finding = { type: 'UNKNOWN_VULNERABILITY_TYPE' };
      const message = manager._formatFindingMessage(finding);

      expect(message).toBe('unknown vulnerability type');
    });
  });

  describe('badge management', () => {
    it('should set badge with finding count', async () => {
      const finding = {
        type: 'MISSING_STATE_PARAMETER',
        confidence: 'HIGH',
        severity: 'HIGH'
      };

      await manager.notifyFinding(finding, 'auth.example.com');

      expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ text: '1' });
      expect(chrome.action.setBadgeBackgroundColor).toHaveBeenCalled();
    });

    it('should show 99+ for counts over 99', async () => {
      manager.findingCounts.set('auth.example.com', 150);
      await manager._updateBadge('auth.example.com');

      expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ text: '99+' });
    });

    it('should clear badge when count is 0', async () => {
      await manager._updateBadge('auth.example.com');

      expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ text: '' });
    });
  });

  describe('_getBadgeColor', () => {
    it('should return red for 5+ findings', () => {
      const color = manager._getBadgeColor(5);
      expect(color).toBe('#DC2626');
    });

    it('should return orange for 3-4 findings', () => {
      const color = manager._getBadgeColor(3);
      expect(color).toBe('#F59E0B');
    });

    it('should return yellow for 1-2 findings', () => {
      const color = manager._getBadgeColor(1);
      expect(color).toBe('#FBBF24');
    });
  });

  describe('clearDomain', () => {
    it('should clear findings for specific domain', async () => {
      const finding = {
        type: 'MISSING_STATE_PARAMETER',
        confidence: 'HIGH',
        severity: 'HIGH'
      };

      await manager.notifyFinding(finding, 'auth.example.com');
      manager.clearDomain('auth.example.com');

      expect(manager.findingCounts.has('auth.example.com')).toBe(false);
    });
  });

  describe('clearAll', () => {
    it('should clear all notifications', async () => {
      const finding = {
        type: 'MISSING_STATE_PARAMETER',
        confidence: 'HIGH',
        severity: 'HIGH'
      };

      await manager.notifyFinding(finding, 'auth.example.com');
      await manager.notifyFinding(finding, 'oauth.test.com');

      manager.clearAll();

      expect(manager.notifiedFindings.size).toBe(0);
      expect(manager.findingCounts.size).toBe(0);
      expect(chrome.action.setBadgeText).toHaveBeenCalledWith({ text: '' });
    });
  });

  describe('getStats', () => {
    it('should return correct statistics', async () => {
      const finding1 = { type: 'MISSING_STATE_PARAMETER', confidence: 'HIGH', severity: 'HIGH' };
      const finding2 = { type: 'MISSING_PKCE', confidence: 'HIGH', severity: 'MEDIUM' };

      await manager.notifyFinding(finding1, 'auth.example.com');
      await manager.notifyFinding(finding2, 'oauth.test.com');

      const stats = manager.getStats();

      expect(stats.totalNotified).toBe(2);
      expect(stats.domains).toContain('auth.example.com');
      expect(stats.domains).toContain('oauth.test.com');
      expect(stats.findingsByDomain['auth.example.com']).toBe(1);
      expect(stats.findingsByDomain['oauth.test.com']).toBe(1);
    });
  });

  describe('_getSeverityEmoji', () => {
    it('should return correct emojis for severities', () => {
      expect(manager._getSeverityEmoji('CRITICAL')).toBe('🔴');
      expect(manager._getSeverityEmoji('HIGH')).toBe('🟠');
      expect(manager._getSeverityEmoji('MEDIUM')).toBe('🟡');
      expect(manager._getSeverityEmoji('LOW')).toBe('🔵');
    });
  });

  describe('_getConfidenceBadge', () => {
    it('should return correct badges for confidence levels', () => {
      expect(manager._getConfidenceBadge('HIGH')).toBe('[✓ High Confidence]');
      expect(manager._getConfidenceBadge('MEDIUM')).toBe('[~ Medium Confidence]');
      expect(manager._getConfidenceBadge('LOW')).toBe('[? Low Confidence]');
    });
  });

  describe('_getPriority', () => {
    it('should return correct priorities', () => {
      expect(manager._getPriority('CRITICAL')).toBe(2);
      expect(manager._getPriority('HIGH')).toBe(2);
      expect(manager._getPriority('MEDIUM')).toBe(1);
      expect(manager._getPriority('LOW')).toBe(0);
    });
  });
});
