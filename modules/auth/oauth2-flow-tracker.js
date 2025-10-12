// OAuth2 Flow Tracking Module
// Tracks authorization requests, callbacks, and validates flows
// CRITICAL FIX P0: Persistent storage for service worker restarts

import { OAuth2Analyzer } from './oauth2-analyzer.js';

class OAuth2FlowTracker {
  constructor() {
    // CRITICAL FIX P0: Persistent storage for service worker restarts
    this._activeFlowsCache = new Map();
    this.cleanupInterval = 10 * 60 * 1000;
    this.initialized = false;
    this.initPromise = this.initialize();
  }

  // Initialize by loading from storage.session
  async initialize() {
    if (this.initialized) return;

    try {
      // CRITICAL FIX P0: Use chrome.storage.local for completed OAuth flows (survives browser restart)
      // Active flows need to persist for multi-day timing attack detection
      const data = await chrome.storage.local.get(['oauthFlows']);
      if (data.oauthFlows) {
        for (const [flowId, flow] of Object.entries(data.oauthFlows)) {
          this._activeFlowsCache.set(flowId, flow);
        }
        console.log(`Hera: Restored ${this._activeFlowsCache.size} OAuth flows from storage.local`);
      }
      this.initialized = true;
    } catch (error) {
      console.error('Hera: Failed to initialize OAuth2FlowTracker:', error);
      this.initialized = true;
    }
  }

  // Background sync to storage.local (CRITICAL FIX P0)
  async _syncToStorage() {
    try {
      await this.initPromise;
      const flowsObj = Object.fromEntries(this._activeFlowsCache.entries());
      // CRITICAL FIX P0: Use chrome.storage.local (survives browser restart)
      await chrome.storage.local.set({ oauthFlows: flowsObj });
    } catch (error) {
      console.error('Hera: Failed to sync OAuth flows:', error);
    }
  }

  // Debounced sync
  _debouncedSync() {
    if (this._syncTimeout) clearTimeout(this._syncTimeout);
    this._syncTimeout = setTimeout(() => {
      this._syncToStorage().catch(err => console.error('OAuth flow sync failed:', err));
    }, 100);
  }

  // Getter for activeFlows (backward compatibility)
  get activeFlows() {
    return this._activeFlowsCache;
  }

  /**
   * Track an authorization request
   */
  trackAuthRequest(request) {
    try {
      const url = new URL(request.url);
      const state = url.searchParams.get('state');
      const clientId = url.searchParams.get('client_id');

      if (state && clientId) {
        const flowId = `${clientId}_${state}`;

        // Check if this flow already exists (potential replay attack)
        if (this.activeFlows.has(flowId)) {
          const existingFlow = this.activeFlows.get(flowId);
          console.warn('Potential OAuth2 replay attack: state parameter reused', {
            clientId,
            state,
            originalTimestamp: existingFlow.authRequest.timestamp,
            newTimestamp: Date.now()
          });
          // Overwrite with warning - newer request takes precedence
        }

        this._activeFlowsCache.set(flowId, {
          authRequest: {
            url: request.url,
            timestamp: Date.now(),
            state: state,
            hasPKCE: url.searchParams.has('code_challenge'),
            hasNonce: url.searchParams.has('nonce'),
            clientId: clientId
          },
          callback: null,
          completed: false
        });

        // CRITICAL FIX: Persist to storage.session
        this._debouncedSync();

        // Schedule cleanup
        setTimeout(() => {
          this._activeFlowsCache.delete(flowId);
          this._debouncedSync(); // Persist deletion
        }, this.cleanupInterval);

        return flowId;
      }
    } catch (error) {
      console.warn('Error tracking OAuth2 auth request:', error);
    }
    return null;
  }

  /**
   * Track a callback/redirect
   */
  trackCallback(request) {
    try {
      const url = new URL(request.url);
      const state = url.searchParams.get('state');
      const code = url.searchParams.get('code');
      const error = url.searchParams.get('error');

      if (!state) {
        return {
          vulnerability: 'callbackWithoutState',
          message: 'OAuth2 callback missing state parameter',
          severity: 'HIGH'
        };
      }

      // Find matching flow
      for (const [flowId, flow] of this.activeFlows) {
        if (flow.authRequest.state === state) {
          // SECURITY: Check flow timing to prevent race attacks
          const flowAge = Date.now() - flow.authRequest.timestamp;

          if (flowAge < 2000) {
            // SECURITY FIX P2: Increased from 500ms to 2s (industry standard for human-initiated flows)
            // Callback arrived too quickly after request - likely race attack or automation
            console.warn('OAuth callback timing suspicious (< 2s) - possible CSRF race attack or automation');
            return {
              vulnerability: 'suspiciousTimingAnomaly',
              message: 'OAuth callback received too quickly after authorization request',
              severity: 'HIGH',
              details: `Flow age: ${flowAge}ms (expected > 2000ms for legitimate human interaction)`,
              evidence: {
                authRequestTime: flow.authRequest.timestamp,
                callbackTime: Date.now(),
                timeDifference: flowAge
              }
            };
          }

          if (flowAge > 600000) {
            // Callback too slow (>10 min) - state likely expired
            return {
              vulnerability: 'expiredState',
              message: 'OAuth state parameter expired (> 10 minutes)',
              severity: 'MEDIUM',
              details: `Flow age: ${Math.round(flowAge / 1000)}s`,
              evidence: {
                authRequestTime: flow.authRequest.timestamp,
                callbackTime: Date.now(),
                timeDifference: flowAge
              }
            };
          }

          flow.callback = {
            url: request.url,
            timestamp: Date.now(),
            hasCode: !!code,
            hasError: !!error,
            stateMatches: true
          };
          flow.completed = true;

          // CRITICAL FIX: Persist callback to storage.session
          this._debouncedSync();

          // Validate the complete flow
          return this.validateFlow(flow);
        }
      }

      // No matching flow found - potential attack
      return {
        vulnerability: 'orphanCallback',
        message: 'OAuth2 callback without matching authorization request',
        severity: 'HIGH'
      };
    } catch (error) {
      console.warn('Error tracking OAuth2 callback:', error);
      return null;
    }
  }

  /**
   * Validate a complete OAuth2 flow
   */
  validateFlow(flow) {
    const issues = [];
    const analyzer = new OAuth2Analyzer();

    // Check state parameter quality
    const stateQuality = analyzer.analyzeStateQuality(flow.authRequest.state);

    if (stateQuality.totalEntropy < 64 && !flow.authRequest.hasPKCE) {
      issues.push({
        type: 'weakStateInFlow',
        message: `State entropy too low: ${stateQuality.totalEntropy.toFixed(0)} bits total (${stateQuality.entropyPerChar.toFixed(1)} bits/char)`,
        severity: stateQuality.risk,
        exploitation: 'Predictable state allows CSRF attacks'
      });
    }

    // Check timing (callbacks should happen within reasonable time)
    const flowDuration = flow.callback.timestamp - flow.authRequest.timestamp;
    if (flowDuration > 5 * 60 * 1000) { // 5 minutes
      issues.push({
        type: 'suspiciousTiming',
        message: 'Unusually long delay between auth request and callback',
        severity: 'INFO',
        exploitation: 'Possible session fixation or replay attack'
      });
    }

    return issues;
  }

  /**
   * Get statistics about tracked flows
   */
  getFlowStats() {
    const stats = {
      activeFlows: this.activeFlows.size,
      completedFlows: 0,
      pendingFlows: 0
    };

    for (const flow of this.activeFlows.values()) {
      if (flow.completed) {
        stats.completedFlows++;
      } else {
        stats.pendingFlows++;
      }
    }

    return stats;
  }
}

export { OAuth2FlowTracker };
