// Hera Comprehensive Authentication Protocol Security Analysis Framework
// Coordinator module that integrates all authentication detection components
//
// This file replaces the monolithic hera-auth-detector.js with a modular architecture

import { OAuth2Analyzer } from './modules/auth/oauth2-analyzer.js';
import { OAuth2FlowTracker } from './modules/auth/oauth2-flow-tracker.js';
import { AuthIssueDatabase } from './modules/auth/auth-issue-database.js';
import { AuthUtilFunctions } from './modules/auth/auth-util-functions.js';
import { AuthRiskScorer } from './modules/auth/auth-risk-scorer.js';
import { AuthEvidenceManager } from './modules/auth/auth-evidence-manager.js';
import { HeraAuthIssueVisualizer } from './modules/auth/auth-issue-visualizer.js';
import { OAuth2VerificationEngine, HSTSVerificationEngine } from './oauth2-verification-engine.js';

/**
 * Main coordinator class for authentication protocol detection and analysis
 * Delegates to specialized modules for different responsibilities
 */
class HeraAuthProtocolDetector {
  constructor(evidenceCollector = null) {
    this.detectedProtocols = [];
    this.securityIssues = [];

    // Initialize modules
    this.issueDb = new AuthIssueDatabase();
    this.issueDatabase = this.issueDb.database; // Backward compatibility
    this.oauth2Analyzer = new OAuth2Analyzer();
    this.flowTracker = new OAuth2FlowTracker();
    this.utilFunctions = new AuthUtilFunctions();
    this.riskScorer = new AuthRiskScorer(this.utilFunctions);
    this.evidenceManager = new AuthEvidenceManager(this.utilFunctions);

    // Evidence-based verification engines
    this.evidenceCollector = evidenceCollector;
    this.oauth2Verifier = evidenceCollector ? new OAuth2VerificationEngine(evidenceCollector) : null;
    this.hstsVerifier = evidenceCollector ? new HSTSVerificationEngine(evidenceCollector) : null;
    this.verificationResults = new Map();
  }

  /**
   * Analyze a request for authentication security issues
   */
  analyzeRequest(request) {
    const issues = [];

    // Detect protocol type
    const protocol = this.detectProtocol(request);

    // Track OAuth2 flows if applicable
    if (protocol === 'OAuth2' && request.url.includes('authorize')) {
      this.flowTracker.trackAuthRequest(request);
    }

    // Run protocol-specific checks
    if (this.issueDatabase[protocol]) {
      issues.push(...this.checkProtocolSecurity(protocol, request));
    }

    // Run universal checks
    issues.push(...this.checkUniversalIssues(request));

    // Enhance issues with confidence levels and evidence
    const enhancedIssues = issues.map(issue => this.enhanceIssue(issue, request));

    // Calculate risk score
    const riskScore = this.riskScorer.calculateRiskScore(enhancedIssues);

    return {
      protocol,
      issues: enhancedIssues,
      riskScore,
      recommendation: this.riskScorer.getRecommendation(riskScore),
      timestamp: Date.now(),
      flowStats: protocol === 'OAuth2' ? this.flowTracker.getFlowStats() : null
    };
  }

  /**
   * Enhance an issue with confidence levels and evidence
   */
  enhanceIssue(issue, request) {
    const enhanced = {
      ...issue,
      confidence: this.evidenceManager.calculateConfidence(issue, request),
      evidence: this.evidenceManager.gatherEvidence(issue, request),
      recommendation: this.getIssueRecommendation(issue.type)
    };

    return enhanced;
  }

  /**
   * Get recommendation for a specific issue type
   */
  getIssueRecommendation(issueType) {
    const recommendations = {
      'missingState': 'Implement state parameter with cryptographically random values (minimum 128 bits entropy)',
      'weakState': 'Increase state parameter entropy to at least 128 bits using cryptographically secure random generation',
      'missingPKCE': 'Implement PKCE (Proof Key for Code Exchange) for public clients',
      'implicitFlow': 'Switch to Authorization Code flow with PKCE instead of Implicit flow',
      'clientSecretInURL': 'Move client secret to request body or use client authentication methods',
      'openRedirect': 'Validate redirect_uri against a whitelist of allowed URLs',
      'overlyBroadScopes': 'Request only the minimum required scopes for the application functionality',
      'orphanCallback': 'Investigate potential CSRF attack attempt',
      'callbackWithoutState': 'Ensure all OAuth2 callbacks include state parameter validation'
    };
    return recommendations[issueType] || 'Review OAuth2 implementation against security best practices';
  }

  /**
   * Check if a request is authentication-related
   * @param {string} url - Request URL
   * @param {Object} details - Request details (optional)
   * @returns {boolean} True if request is auth-related
   */
  isAuthRequest(url, details = {}) {
    try {
      // Quick URL-based checks for common auth patterns
      const authPatterns = [
        '/auth',
        '/login',
        '/oauth',
        '/saml',
        '/openid',
        '/authorize',
        '/token',
        '/connect',
        '/sso',
        '/signin',
        '/authenticate',
        '/.well-known',
        '/jwks'
      ];

      const lowerUrl = url.toLowerCase();
      if (authPatterns.some(pattern => lowerUrl.includes(pattern))) {
        return true;
      }

      // Check query parameters for auth indicators
      const params = this.parseParams(url);
      const authParams = [
        'response_type',
        'client_id',
        'redirect_uri',
        'scope',
        'state',
        'nonce',
        'code_challenge',
        'SAMLRequest',
        'SAMLResponse',
        'access_token',
        'id_token',
        'refresh_token'
      ];

      if (authParams.some(param => params[param])) {
        return true;
      }

      return false;
    } catch (error) {
      console.warn('Error in isAuthRequest:', error);
      return false;
    }
  }

  /**
   * Detect the authentication protocol used in a request
   */
  detectProtocol(request) {
    return this.utilFunctions.detectProtocol(request);
  }

  /**
   * Check for protocol-specific security issues
   */
  checkProtocolSecurity(protocol, request) {
    const issues = [];
    const protocolIssues = this.issueDatabase[protocol];

    for (const [issueType, issueData] of Object.entries(protocolIssues)) {
      if (issueData.detection && typeof issueData.detection === 'function') {
        try {
          if (issueData.detection(request, this)) {
            const severity = typeof issueData.severity === 'function'
              ? issueData.severity(request, this)
              : issueData.severity;

            issues.push({
              type: issueType,
              protocol: protocol,
              severity: severity,
              message: issueData.issue,
              exploitation: issueData.exploitation || 'See security documentation'
            });
          }
        } catch (error) {
          console.warn(`Error checking ${protocol}.${issueType}:`, error);
        }
      } else if (issueData.pattern) {
        const testString = request.url + ' ' + JSON.stringify(request.headers) + ' ' + (request.requestBody || '');
        if (issueData.pattern.test(testString)) {
          issues.push({
            type: issueType,
            protocol: protocol,
            severity: issueData.severity,
            message: issueData.issue,
            exploitation: issueData.exploitation || 'See security documentation'
          });
        }
      }
    }

    return issues;
  }

  /**
   * Check for universal security issues (TLS, HSTS, etc.)
   */
  checkUniversalIssues(request) {
    const issues = [];
    const headers = request.requestHeaders || request.headers || {};
    const url = request.url || '';

    // Check for HTTP
    if (!url.startsWith('https://')) {
      issues.push({
        type: 'NO_TLS',
        protocol: 'Universal',
        severity: 'CRITICAL',
        message: 'Authentication over unencrypted connection'
      });
    }

    // Check for credentials in URL - refined detection
    const credentialIssue = this.utilFunctions.detectCredentialsInUrl(url);
    if (credentialIssue) {
      issues.push(credentialIssue);
    }

    // Check for missing security headers with risk-based assessment
    const hstsIssue = this.riskScorer.assessHstsRisk(url, headers, request);
    if (hstsIssue) {
      issues.push(hstsIssue);
    }

    // Check for deprecated APIs
    const deprecatedApiHosts = [
      'graph.windows.net' // Azure AD Graph API
    ];
    try {
      const requestHost = new URL(url).hostname;
      if (deprecatedApiHosts.some(host => requestHost.endsWith(host))) {
        issues.push({
          type: 'DEPRECATED_API',
          protocol: 'Universal',
          severity: 'HIGH',
          message: 'Request uses a deprecated API (' + requestHost + '), which may have known vulnerabilities.'
        });
      }
    } catch (e) {
      // Ignore URL parsing errors
    }

    return issues;
  }

  /**
   * Perform evidence-based OAuth2 verification
   * @param {string} url - OAuth2 authorization URL to verify
   * @returns {Object} Verification results with evidence
   */
  async performEvidenceBasedOAuth2Verification(url) {
    return this.evidenceManager.performEvidenceBasedOAuth2Verification(
      url,
      this.oauth2Verifier,
      this.verificationResults
    );
  }

  /**
   * Perform evidence-based HSTS verification
   * @param {string} url - URL to verify HSTS implementation
   * @returns {Object} Verification results with evidence
   */
  async performEvidenceBasedHSTSVerification(url) {
    return this.evidenceManager.performEvidenceBasedHSTSVerification(
      url,
      this.hstsVerifier,
      this.verificationResults,
      this.riskScorer
    );
  }

  /**
   * Generate evidence-based report for a verification
   */
  generateEvidenceBasedReport(verificationId) {
    return this.evidenceManager.generateEvidenceBasedReport(
      verificationId,
      this.verificationResults
    );
  }

  /**
   * Analyze OAuth2 with evidence collection
   */
  async analyzeOAuth2WithEvidence(request) {
    return this.evidenceManager.analyzeOAuth2WithEvidence(
      request,
      this.oauth2Verifier,
      this
    );
  }

  /**
   * Calculate risk score for a set of issues
   */
  calculateRiskScore(issues) {
    return this.riskScorer.calculateRiskScore(issues);
  }

  /**
   * Get recommendation based on risk score
   */
  getRecommendation(riskScore) {
    return this.riskScorer.getRecommendation(riskScore);
  }

  /**
   * Get risk category for display
   */
  getRiskCategory(riskScore) {
    return this.riskScorer.getRiskCategory(riskScore);
  }

  /**
   * Parse URL parameters
   */
  parseParams(url) {
    return this.utilFunctions.parseParams(url);
  }

  /**
   * Get header value (case-insensitive)
   */
  getHeader(headers, name) {
    return this.utilFunctions.getHeader(headers, name);
  }

  /**
   * Extract session ID from response
   */
  extractSessionId(response) {
    return this.utilFunctions.extractSessionId(response);
  }

  /**
   * Verify JWT with HS256
   */
  verifyHS256(jwt, secret) {
    return this.utilFunctions.verifyHS256(jwt, secret);
  }

  /**
   * Check if string has repeating pattern
   */
  isRepeatingPattern(str) {
    return this.utilFunctions.isRepeatingPattern(str);
  }

  /**
   * Detect credentials in URL
   */
  detectCredentialsInUrl(url) {
    return this.utilFunctions.detectCredentialsInUrl(url);
  }

  /**
   * Calculate Shannon entropy
   */
  calculateEntropy(str) {
    return this.utilFunctions.calculateEntropy(str);
  }

  /**
   * Assess HSTS risk with context
   */
  assessHstsRisk(url, headers, request) {
    return this.riskScorer.assessHstsRisk(url, headers, request);
  }

  /**
   * Assess authentication risk
   */
  assessAuthenticationRisk(url, headers, request) {
    return this.riskScorer.assessAuthenticationRisk(url, headers, request);
  }

  /**
   * Assess data sensitivity
   */
  assessDataSensitivity(url, urlObj) {
    return this.riskScorer.assessDataSensitivity(url, urlObj);
  }

  /**
   * Assess application type
   */
  assessApplicationType(url, urlObj) {
    return this.riskScorer.assessApplicationType(url, urlObj);
  }

  /**
   * Assess edge protection
   */
  assessEdgeProtection(headers, urlObj) {
    return this.riskScorer.assessEdgeProtection(headers, urlObj);
  }

  /**
   * Get HSTS risk assessment
   */
  getHstsRiskAssessment(riskScore, riskFactors) {
    return this.riskScorer.getHstsRiskAssessment(riskScore, riskFactors);
  }

  /**
   * Analyze response body
   */
  analyzeResponseBody(body) {
    return this.utilFunctions.analyzeResponseBody(body);
  }

  /**
   * Generate verification ID
   */
  generateVerificationId() {
    return this.evidenceManager.generateVerificationId();
  }
}

// Export all classes for backward compatibility and external use
export {
  HeraAuthProtocolDetector,
  HeraAuthIssueVisualizer,
  OAuth2Analyzer,
  OAuth2FlowTracker
};
