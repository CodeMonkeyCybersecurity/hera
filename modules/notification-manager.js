/**
 * Notification Manager
 *
 * PURPOSE: Notify users when high-confidence security findings are detected
 * - Chrome notifications for immediate awareness
 * - Badge updates with finding counts
 * - Configurable notification thresholds
 *
 * IMPLEMENTATION: P1-1 (Evidence Export Notifications)
 * @see ROADMAP.md P1-1: Evidence Export Notifications
 */

export class NotificationManager {
  constructor() {
    this.notifiedFindings = new Set(); // Track notified findings to avoid duplicates
    this.findingCounts = new Map(); // domain → count

    // Notification thresholds
    this.MIN_CONFIDENCE = 'MEDIUM'; // Minimum confidence for notifications
    this.MIN_SEVERITY = 'MEDIUM'; // Minimum severity for notifications

    // Confidence levels (for comparison)
    this.confidenceLevels = {
      'SPECULATIVE': 0,
      'LOW': 1,
      'MEDIUM': 2,
      'HIGH': 3
    };

    // Severity levels (for comparison)
    this.severityLevels = {
      'INFO': 0,
      'LOW': 1,
      'MEDIUM': 2,
      'HIGH': 3,
      'CRITICAL': 4
    };
  }

  /**
   * Notify user of a high-confidence security finding
   *
   * @param {Object} finding - Security finding object
   * @param {string} domain - Domain where finding was detected
   * @returns {Promise<string|null>} Notification ID or null if not notified
   */
  async notifyFinding(finding, domain) {
    // Check if we should notify
    if (!this._shouldNotify(finding)) {
      return null;
    }

    // Check if already notified
    const findingKey = `${domain}:${finding.type}`;
    if (this.notifiedFindings.has(findingKey)) {
      return null;
    }

    // Mark as notified
    this.notifiedFindings.add(findingKey);

    // Update finding count
    const currentCount = this.findingCounts.get(domain) || 0;
    this.findingCounts.set(domain, currentCount + 1);

    // Create notification
    try {
      const notificationId = await this._createNotification(finding, domain);

      // Update badge
      await this._updateBadge(domain);

      return notificationId;
    } catch (error) {
      console.error('[NotificationManager] Failed to create notification:', error);
      return null;
    }
  }

  /**
   * Check if finding meets notification criteria
   *
   * @param {Object} finding - Security finding
   * @returns {boolean} True if should notify
   * @private
   */
  _shouldNotify(finding) {
    // Check confidence level
    const confidenceLevel = this.confidenceLevels[finding.confidence] || 0;
    const minConfidenceLevel = this.confidenceLevels[this.MIN_CONFIDENCE];

    if (confidenceLevel < minConfidenceLevel) {
      return false;
    }

    // Check severity level
    const severityLevel = this.severityLevels[finding.severity] || 0;
    const minSeverityLevel = this.severityLevels[this.MIN_SEVERITY];

    if (severityLevel < minSeverityLevel) {
      return false;
    }

    return true;
  }

  /**
   * Create Chrome notification
   *
   * @param {Object} finding - Security finding
   * @param {string} domain - Domain
   * @returns {Promise<string>} Notification ID
   * @private
   */
  async _createNotification(finding, domain) {
    const severityEmoji = this._getSeverityEmoji(finding.severity);
    const confidenceBadge = this._getConfidenceBadge(finding.confidence);

    const notificationOptions = {
      type: 'basic',
      iconUrl: this._getIconUrl(finding.severity),
      title: `Hera: ${severityEmoji} ${finding.severity} Finding`,
      message: `${confidenceBadge} ${this._formatFindingMessage(finding)} on ${domain}`,
      priority: this._getPriority(finding.severity),
      requireInteraction: finding.severity === 'CRITICAL',
      buttons: [
        { title: 'View Evidence' },
        { title: 'Export Report' }
      ]
    };

    return new Promise((resolve, reject) => {
      chrome.notifications.create(notificationOptions, (notificationId) => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError);
        } else {
          // Register notification click handler
          this._registerClickHandler(notificationId, domain);
          resolve(notificationId);
        }
      });
    });
  }

  /**
   * Format finding message for notification
   *
   * @param {Object} finding - Security finding
   * @returns {string} Formatted message
   * @private
   */
  _formatFindingMessage(finding) {
    // Convert finding type to human-readable message
    const messages = {
      'MISSING_STATE_PARAMETER': 'Missing CSRF protection (state parameter)',
      'WEAK_STATE_PARAMETER': 'Weak CSRF protection (predictable state)',
      'MISSING_PKCE': 'Missing PKCE (authorization code interception risk)',
      'MISSING_SECURE_FLAG': 'Missing Secure flag on auth cookie',
      'MISSING_HTTPONLY_FLAG': 'Missing HttpOnly flag on auth cookie',
      'SESSION_FIXATION': 'Session fixation vulnerability',
      'ALG_NONE_VULNERABILITY': 'JWT algorithm confusion (alg=none)',
      'WEAK_JWT_SECRET': 'Weak JWT secret detected',
      'TOKEN_IN_URL': 'Token leaked in URL',
      'CREDENTIALS_IN_URL': 'Credentials leaked in URL',
      'NO_HSTS': 'Missing HSTS header',
      'REFRESH_TOKEN_NOT_ROTATED': 'Refresh token not rotated'
    };

    return messages[finding.type] || finding.type.replace(/_/g, ' ').toLowerCase();
  }

  /**
   * Get icon URL based on severity
   *
   * @param {string} severity - Finding severity
   * @returns {string} Icon URL
   * @private
   */
  _getIconUrl(severity) {
    const icons = {
      'CRITICAL': 'icons/icon-critical-128.png',
      'HIGH': 'icons/icon-warning-128.png',
      'MEDIUM': 'icons/icon-info-128.png',
      'LOW': 'icons/icon-info-128.png'
    };

    return icons[severity] || 'icons/icon-128.png';
  }

  /**
   * Get severity emoji
   *
   * @param {string} severity - Finding severity
   * @returns {string} Emoji
   * @private
   */
  _getSeverityEmoji(severity) {
    const emojis = {
      'CRITICAL': '🔴',
      'HIGH': '🟠',
      'MEDIUM': '🟡',
      'LOW': '🔵',
      'INFO': 'ℹ️'
    };

    return emojis[severity] || '⚠️';
  }

  /**
   * Get confidence badge
   *
   * @param {string} confidence - Finding confidence
   * @returns {string} Badge text
   * @private
   */
  _getConfidenceBadge(confidence) {
    const badges = {
      'HIGH': '[✓ High Confidence]',
      'MEDIUM': '[~ Medium Confidence]',
      'LOW': '[? Low Confidence]',
      'SPECULATIVE': '[! Speculative]'
    };

    return badges[confidence] || '';
  }

  /**
   * Get notification priority
   *
   * @param {string} severity - Finding severity
   * @returns {number} Priority (0-2)
   * @private
   */
  _getPriority(severity) {
    const priorities = {
      'CRITICAL': 2,
      'HIGH': 2,
      'MEDIUM': 1,
      'LOW': 0
    };

    return priorities[severity] || 0;
  }

  /**
   * Update extension badge with finding count
   *
   * @param {string} domain - Domain
   * @private
   */
  async _updateBadge(domain) {
    const count = this.findingCounts.get(domain) || 0;

    if (count === 0) {
      // Clear badge
      await chrome.action.setBadgeText({ text: '' });
      return;
    }

    // Set badge text
    const badgeText = count > 99 ? '99+' : count.toString();
    await chrome.action.setBadgeText({ text: badgeText });

    // Set badge color based on highest severity
    const color = this._getBadgeColor(count);
    await chrome.action.setBadgeBackgroundColor({ color: color });
  }

  /**
   * Get badge background color
   *
   * @param {number} count - Finding count
   * @returns {string} Color hex code
   * @private
   */
  _getBadgeColor(count) {
    if (count >= 5) return '#DC2626'; // Red (Critical)
    if (count >= 3) return '#F59E0B'; // Orange (High)
    if (count >= 1) return '#FBBF24'; // Yellow (Medium)
    return '#60A5FA'; // Blue (Low)
  }

  /**
   * Register notification click handler
   *
   * @param {string} notificationId - Notification ID
   * @param {string} domain - Domain
   * @private
   */
  _registerClickHandler(notificationId, domain) {
    chrome.notifications.onClicked.addListener((clickedId) => {
      if (clickedId === notificationId) {
        // Open popup to view evidence
        chrome.action.openPopup();
      }
    });

    chrome.notifications.onButtonClicked.addListener((clickedId, buttonIndex) => {
      if (clickedId === notificationId) {
        if (buttonIndex === 0) {
          // View Evidence button
          chrome.action.openPopup();
        } else if (buttonIndex === 1) {
          // Export Report button
          this._triggerExport(domain);
        }
      }
    });
  }

  /**
   * Trigger evidence export
   *
   * @param {string} domain - Domain
   * @private
   */
  async _triggerExport(domain) {
    // Send message to background to trigger export
    try {
      await chrome.runtime.sendMessage({
        action: 'exportEvidence',
        domain: domain,
        format: 'enhanced'
      });
    } catch (error) {
      console.error('[NotificationManager] Failed to trigger export:', error);
    }
  }

  /**
   * Clear notifications for a domain
   *
   * @param {string} domain - Domain
   */
  clearDomain(domain) {
    // Clear notified findings for domain
    for (const key of this.notifiedFindings) {
      if (key.startsWith(`${domain}:`)) {
        this.notifiedFindings.delete(key);
      }
    }

    // Reset count
    this.findingCounts.delete(domain);

    // Update badge
    this._updateBadge(domain);
  }

  /**
   * Clear all notifications
   */
  clearAll() {
    this.notifiedFindings.clear();
    this.findingCounts.clear();
    chrome.action.setBadgeText({ text: '' });
  }

  /**
   * Get notification statistics
   *
   * @returns {Object} Statistics
   */
  getStats() {
    return {
      totalNotified: this.notifiedFindings.size,
      domains: Array.from(this.findingCounts.keys()),
      findingsByDomain: Object.fromEntries(this.findingCounts)
    };
  }
}
