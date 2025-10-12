/**
 * OAuth2 Verification Engine for Hera
 *
 * Main coordinator module that integrates CSRF, PKCE, and report generation.
 * Maintains persistent storage for multi-day vulnerability testing.
 */

import { OAuth2CSRFVerifier } from './oauth2-csrf-verifier.js';
import { OAuth2PKCEVerifier } from './oauth2-pkce-verifier.js';
import { OAuth2ReportGenerator } from './oauth2-report-generator.js';

class OAuth2VerificationEngine {
  constructor(evidenceCollector) {
    this.evidenceCollector = evidenceCollector;

    // Initialize sub-modules
    this.csrfVerifier = new OAuth2CSRFVerifier();
    this.pkceVerifier = new OAuth2PKCEVerifier();
    this.reportGenerator = new OAuth2ReportGenerator();

    // CRITICAL FIX P0: Persistent storage for verification state
    this._activeFlows = new Map();
    this._testResults = new Map();
    this.initialized = false;
    this.initPromise = this.initialize();
  }

  async initialize() {
    if (this.initialized) return;

    try {
      // CRITICAL FIX P0: Use chrome.storage.local for test results (survives browser restart)
      // Multi-day vulnerability testing must persist across sessions
      const data = await chrome.storage.local.get(['oauth2VerificationEngine']);
      if (data.oauth2VerificationEngine) {
        const engine = data.oauth2VerificationEngine;

        if (engine.activeFlows) {
          for (const [id, flow] of Object.entries(engine.activeFlows)) {
            this._activeFlows.set(id, flow);
          }
        }

        if (engine.testResults) {
          for (const [id, result] of Object.entries(engine.testResults)) {
            this._testResults.set(id, result);
          }
        }

        console.log(`Hera: Restored OAuth2 verification (${this._activeFlows.size} flows, ${this._testResults.size} results)`);
      }

      this.initialized = true;
    } catch (error) {
      console.error('Hera: Failed to initialize OAuth2VerificationEngine:', error);
      this.initialized = true;
    }
  }

  async _syncToStorage() {
    try {
      await this.initPromise;

      const engine = {
        activeFlows: Object.fromEntries(this._activeFlows.entries()),
        testResults: Object.fromEntries(this._testResults.entries())
      };

      // CRITICAL FIX P0: Use chrome.storage.local (survives browser restart)
      await chrome.storage.local.set({ oauth2VerificationEngine: engine });
    } catch (error) {
      console.error('Hera: Failed to sync OAuth2VerificationEngine:', error);
    }
  }

  _debouncedSync() {
    if (this._syncTimeout) clearTimeout(this._syncTimeout);
    this._syncTimeout = setTimeout(() => {
      this._syncToStorage().catch(err => console.error('OAuth2 verification sync failed:', err));
    }, 200);
  }

  // Getters for backward compatibility
  get activeFlows() {
    return this._activeFlows;
  }

  get testResults() {
    return this._testResults;
  }

  /**
   * Verify CSRF protection in OAuth2 authorization flow
   * @param {string} authorizationUrl - The OAuth2 authorization URL to test
   * @returns {Object} Evidence package with test results
   */
  async verifyCSRFProtection(authorizationUrl) {
    const context = {
      storeTestResult: (flowId, evidence) => {
        this.testResults.set(flowId, evidence);
        this._debouncedSync();
      }
    };

    return await this.csrfVerifier.verifyCSRFProtection(authorizationUrl, context);
  }

  /**
   * Verify PKCE implementation
   * @param {string} authorizationUrl - OAuth2 authorization URL
   * @returns {Object} PKCE verification results
   */
  async verifyPKCE(authorizationUrl) {
    return await this.pkceVerifier.verifyPKCE(authorizationUrl);
  }

  /**
   * Generate a comprehensive vulnerability report
   * @param {Object} evidence - Test evidence
   * @returns {Object} Bug bounty ready report
   */
  generateVulnerabilityReport(evidence) {
    return this.reportGenerator.generateVulnerabilityReport(evidence);
  }

  // Delegate helper methods to appropriate modules
  extractStateParameter(url) {
    return this.csrfVerifier.extractStateParameter(url);
  }

  extractCodeChallenge(url) {
    return this.pkceVerifier.extractCodeChallenge(url);
  }

  extractCodeChallengeMethod(url) {
    return this.pkceVerifier.extractCodeChallengeMethod(url);
  }

  analyzeCodeChallengeMethod(method) {
    return this.pkceVerifier.analyzeCodeChallengeMethod(method);
  }

  analyzeChallengeEntropy(challenge) {
    return this.pkceVerifier.analyzeChallengeEntropy(challenge);
  }

  generateSummary(vulnerabilities) {
    return this.reportGenerator.generateSummary(vulnerabilities);
  }

  getReproductionSteps(testType, evidence) {
    return this.reportGenerator.getReproductionSteps(testType, evidence);
  }

  getRecommendations(vulnerabilities) {
    return this.reportGenerator.getRecommendations(vulnerabilities);
  }
}

export { OAuth2VerificationEngine };
