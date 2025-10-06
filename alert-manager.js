// Hera Alert Manager - Tiered Alerting with Confidence Scoring
// Prevents alert fatigue by showing only high-confidence, high-severity findings

class AlertManager {
  constructor() {
    this.alertThresholds = {
      CRITICAL: { minConfidence: 70, action: 'PAGE_OVERLAY' },
      HIGH: { minConfidence: 60, action: 'NOTIFICATION' },
      MEDIUM: { minConfidence: 50, action: 'BADGE' },
      LOW: { minConfidence: 40, action: 'POPUP_ONLY' },
      INFO: { minConfidence: 0, action: 'LOG_ONLY' }
    };

    // CRITICAL FIX P0: Persistent storage for alert deduplication
    this._alertHistory = new Map();
    this.initialized = false;
    this.initPromise = this.initialize();

    // P0-SEVENTH-1 FIX: Maximum alert history size to prevent storage quota exhaustion
    this.MAX_ALERT_HISTORY_SIZE = 1000;
    this.ALERT_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours
  }

  async initialize() {
    if (this.initialized) return;

    try {
      // CRITICAL FIX P0: Use chrome.storage.local for alert history (survives browser restart)
      // Alert deduplication must persist across browser sessions
      const data = await chrome.storage.local.get(['heraAlertHistory']);
      if (data.heraAlertHistory) {
        for (const [key, value] of Object.entries(data.heraAlertHistory)) {
          this._alertHistory.set(key, value);
        }
        console.log(`Hera: Restored ${this._alertHistory.size} alert history entries`);
      }
      this.initialized = true;
    } catch (error) {
      console.error('Hera: Failed to initialize alert manager:', error);
      this.initialized = true;
    }
  }

  async _syncToStorage() {
    try {
      await this.initPromise;

      // P0-SIXTEENTH-2 FIX: Check quota before writing
      const bytesInUse = await chrome.storage.local.getBytesInUse();
      const quota = chrome.storage.local.QUOTA_BYTES || 10485760;
      if (bytesInUse / quota > 0.90) {
        console.warn('Hera: Alert history sync skipped - quota >90%');
        return;
      }

      const historyObj = Object.fromEntries(this._alertHistory.entries());
      // CRITICAL FIX P0: Use chrome.storage.local (survives browser restart)
      await chrome.storage.local.set({ heraAlertHistory: historyObj });
    } catch (error) {
      if (error.message?.includes('QUOTA')) {
        console.error('Hera: Alert history quota exceeded, forcing cleanup');
        this.cleanupAlertHistory();
      } else {
        console.error('Hera: Failed to sync alert history:', error);
      }
    }
  }

  _debouncedSync() {
    // P3-SIXTEENTH-2: DEBOUNCE TIMING - 1000ms (vs memory-manager's 100ms)
    // Alert history is low-priority data (used only for deduplication)
    // Longer debounce reduces storage quota pressure
    // Acceptable data loss: Worst case = duplicate alerts shown after browser restart
    if (this._syncTimeout) clearTimeout(this._syncTimeout);
    this._syncTimeout = setTimeout(() => {
      this._syncToStorage().catch(err => console.error('Alert history sync failed:', err));
    }, 1000); // 1 second debounce - see rationale above
  }

  get alertHistory() {
    return this._alertHistory;
  }

  /**
   * Calculate confidence score for a security finding
   * @param {Object} finding - Security finding with evidence
   * @returns {number} Confidence score 0-100
   */
  calculateConfidence(finding) {
    let confidence = 50; // Base confidence

    // Evidence-based confidence boosters
    if (finding.evidence) {
      // Direct evidence (response body, headers)
      if (finding.evidence.responseBody) confidence += 20;
      if (finding.evidence.verification) confidence += 15;

      // Known provider reduces confidence of false positives
      if (finding.evidence.isKnownProvider) confidence -= 10;

      // Multiple corroborating indicators
      if (finding.evidence.correlatedFindings > 1) {
        confidence += finding.evidence.correlatedFindings * 5;
      }
    }

    // Severity-based adjustments
    if (finding.severity === 'CRITICAL') {
      confidence += 10; // Critical findings need high bar
    }

    // Protocol-specific confidence
    if (finding.protocol) {
      if (['OAuth2', 'OIDC'].includes(finding.protocol)) {
        confidence += 5; // Well-understood protocols
      }
    }

    // Pattern matching confidence
    if (finding.patternMatches > 2) {
      confidence += 10; // Multiple patterns matched
    }

    // Entropy-based confidence (for state parameters)
    if (finding.entropyPerChar !== undefined) {
      if (finding.entropyPerChar < 1) confidence += 20; // Very low entropy = high confidence
      else if (finding.entropyPerChar < 2) confidence += 10;
    }

    // Cap at 0-100
    return Math.max(0, Math.min(100, confidence));
  }

  /**
   * Determine if an alert should be shown based on severity and confidence
   * @param {Object} finding - Security finding
   * @returns {Object} Alert decision { show, action, reason }
   */
  shouldShowAlert(finding) {
    const confidence = this.calculateConfidence(finding);
    finding.confidence = confidence; // Attach confidence to finding

    const threshold = this.alertThresholds[finding.severity];
    if (!threshold) {
      return { show: false, action: 'UNKNOWN_SEVERITY', reason: 'Unknown severity level' };
    }

    // Check confidence threshold
    if (confidence < threshold.minConfidence) {
      return {
        show: false,
        action: 'BELOW_THRESHOLD',
        reason: `Confidence ${confidence}% below threshold ${threshold.minConfidence}%`
      };
    }

    // Check for duplicate alerts (same finding on same domain within 1 hour)
    const alertKey = `${finding.type}_${finding.url}_${finding.severity}`;
    const lastShown = this.alertHistory.get(alertKey);
    if (lastShown && (Date.now() - lastShown) < 60 * 60 * 1000) {
      return {
        show: false,
        action: 'DUPLICATE',
        reason: 'Same alert shown within last hour'
      };
    }

    // Show the alert
    this.alertHistory.set(alertKey, Date.now());

    // CRITICAL FIX: Persist to storage.session
    this._debouncedSync();

    return {
      show: true,
      action: threshold.action,
      confidence: confidence,
      reason: `Severity ${finding.severity}, confidence ${confidence}%`
    };
  }

  /**
   * Execute the appropriate alert action
   * @param {Object} finding - Security finding with confidence
   * @param {string} action - Alert action type
   */
  async executeAlert(finding, action) {
    switch (action) {
      case 'PAGE_OVERLAY':
        // Send to content script for branded alert
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          if (tabs[0]) {
            chrome.tabs.sendMessage(tabs[0].id, {
              action: 'showPageAlert',
              finding: finding
            });
          }
        });
        break;

      case 'NOTIFICATION':
        // Chrome notification
        chrome.notifications.create({
          type: 'basic',
          iconUrl: 'icons/icon48.png',
          title: `🔒 Hera Security Alert (${finding.confidence}% confident)`,
          message: `${finding.type}: ${finding.message}`,
          priority: 2
        });
        break;

      case 'BADGE':
        // Update badge with severity indicator
        const badgeColors = {
          CRITICAL: '#dc3545',
          HIGH: '#fd7e14',
          MEDIUM: '#ffc107',
          LOW: '#6c757d'
        };
        chrome.action.setBadgeText({ text: '!' });
        chrome.action.setBadgeBackgroundColor({ color: badgeColors[finding.severity] || '#6c757d' });
        break;

      case 'POPUP_ONLY':
      case 'LOG_ONLY':
        // Just log for review in popup
        console.log(`Hera Finding (${finding.confidence}% confidence):`, finding);
        break;
    }
  }

  /**
   * Process a security finding with tiered alerting
   * @param {Object} finding - Raw security finding
   */
  processFinding(finding) {
    const decision = this.shouldShowAlert(finding);

    console.log(`Alert Decision for ${finding.type}:`, decision);

    if (decision.show) {
      this.executeAlert(finding, decision.action);
    }

    // Always store for popup display
    this.storeFindingForPopup(finding, decision);
  }

  /**
   * Store finding for display in popup
   * @param {Object} finding - Security finding
   * @param {Object} decision - Alert decision
   */
  storeFindingForPopup(finding, decision) {
    chrome.storage.local.get(['heraFindings'], (result) => {
      const findings = result.heraFindings || [];
      findings.push({
        ...finding,
        confidence: finding.confidence,
        alertAction: decision.action,
        timestamp: Date.now()
      });

      // Keep only last 500 findings
      if (findings.length > 500) {
        findings.splice(0, findings.length - 500);
      }

      chrome.storage.local.set({ heraFindings: findings });
    });
  }

  /**
   * Clear old alert history (run periodically)
   * P0-SEVENTH-1 FIX: Added LRU eviction to prevent unbounded growth
   */
  cleanupAlertHistory() {
    const now = Date.now();
    let cleaned = 0;

    // 1. Remove expired entries (older than 24 hours)
    for (const [key, timestamp] of this.alertHistory.entries()) {
      if (now - timestamp > this.ALERT_EXPIRY_MS) {
        this.alertHistory.delete(key);
        cleaned++;
      }
    }

    // 2. P0-SEVENTH-1 FIX: If still too large, LRU eviction
    if (this.alertHistory.size > this.MAX_ALERT_HISTORY_SIZE) {
      // Sort by timestamp (oldest first)
      const entries = Array.from(this.alertHistory.entries())
        .sort((a, b) => a[1] - b[1]);

      // Remove oldest entries until size is acceptable
      const toRemove = this.alertHistory.size - this.MAX_ALERT_HISTORY_SIZE;
      for (let i = 0; i < toRemove; i++) {
        this.alertHistory.delete(entries[i][0]);
        cleaned++;
      }

      console.log(`Hera: Alert history LRU eviction removed ${toRemove} oldest entries`);
    }

    if (cleaned > 0) {
      console.log(`Hera: Cleaned ${cleaned} total alert history entries (size now: ${this.alertHistory.size}/${this.MAX_ALERT_HISTORY_SIZE})`);
      // CRITICAL FIX: Persist deletion to storage.session
      this._debouncedSync();
    }
  }
}

// Export for ES modules
export { AlertManager };
