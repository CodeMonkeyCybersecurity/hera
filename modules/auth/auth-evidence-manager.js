// Authentication Evidence Manager Module
// Evidence-based verification and issue enhancement

import { OAuth2Analyzer } from './oauth2-analyzer.js';

class AuthEvidenceManager {
  constructor(utilFunctions, oauth2Verifier = null, hstsVerifier = null) {
    this.utilFunctions = utilFunctions;
    this.oauth2Verifier = oauth2Verifier;
    this.hstsVerifier = hstsVerifier;
    this.verificationResults = new Map();
    this.oauth2Analyzer = new OAuth2Analyzer();
  }

  /**
   * Calculate confidence level for a security finding
   * @param {Object} issue - Security issue object
   * @param {Object} request - Request object
   * @returns {string} Confidence level (HIGH/MEDIUM/LOW)
   */
  calculateConfidence(issue, request) {
    try {
      const params = this.utilFunctions ? this.utilFunctions.parseParams(request.url) : {};
      const issueType = issue.type;
      const severity = issue.severity;

      // CRITICAL issues with clear evidence = HIGH confidence
      if (severity === 'CRITICAL') {
        const highConfidenceCritical = [
          'MISSING_STATE', 'MISSING_PKCE', 'TOKEN_IN_URL', 'TOKEN_LEAKED_VIA_REFERER',
          'NO_TLS', 'CREDENTIALS_IN_URL', 'MISSING_HTTPONLY_FLAG',
          'ALG_NONE_VULNERABILITY', 'ALGORITHM_CONFUSION_RISK',
          'WEBAUTHN_CHALLENGE_REUSE', 'WEBAUTHN_CROSS_ORIGIN_ATTEMPT',
          'MISSING_NONCE_IMPLICIT_FLOW', 'MISSING_NONCE_IN_ID_TOKEN',
          'NONCE_MISMATCH', 'AUDIENCE_MISMATCH', 'DISCOVERY_DOCUMENT_OVER_HTTP',
          'REDIRECT_URI_CREDENTIAL_INJECTION', 'MISSING_SUB_CLAIM', 'MISSING_ISSUER_CLAIM',
          'MISSING_AUDIENCE_CLAIM', 'WEBAUTHN_COUNTER_NOT_INCREMENTED'
        ];
        if (highConfidenceCritical.includes(issueType)) return 'HIGH';
      }

      // HIGH severity = MEDIUM-HIGH confidence
      if (severity === 'HIGH') {
        const highConfidenceHigh = [
          'WEAK_PKCE_METHOD', 'MISSING_SECURE_FLAG', 'TOKEN_IN_URL_FRAGMENT',
          'MISSING_AT_HASH', 'MISSING_C_HASH', 'WEAK_USER_VERIFICATION',
          'WEAK_WEBAUTHN_ALGORITHM', 'WEAK_WEBAUTHN_CHALLENGE',
          'MISSING_EXPIRATION_CLAIM', 'IAT_IN_FUTURE', 'MISSING_AZP_CLAIM'
        ];
        if (highConfidenceHigh.includes(issueType)) return 'HIGH';
        return 'MEDIUM';
      }

      // Binary checks (present or not) = HIGH confidence
      const binaryChecks = ['NO_HSTS', 'MISSING_CSRF_PROTECTION'];
      if (binaryChecks.includes(issueType)) return 'HIGH';

      // OAuth2 specific
      if (issueType === 'missingState' && !params.state) return 'HIGH';
      if (issueType === 'clientSecretInURL' || issueType === 'implicitFlow') return 'HIGH';
      if (issueType === 'DEPRECATED_IMPLICIT_FLOW') return 'HIGH';

      // Lower confidence with compensating controls
      if (issueType === 'weakState' && (params.code_challenge || params.nonce)) return 'LOW';

      // Known providers
      if (this.oauth2Analyzer && this.oauth2Analyzer.isKnownProvider(request.url)) {
        if (issueType === 'missingState' && (severity === 'HIGH' || severity === 'CRITICAL')) {
          return 'MEDIUM';
        }
      }

      // Default by severity
      if (severity === 'MEDIUM') return 'MEDIUM';
      if (severity === 'LOW') return 'LOW';
      return 'MEDIUM';
    } catch (error) {
      console.warn('Error calculating confidence:', error);
      return 'LOW';
    }
  }

  /**
   * Gather evidence for a security issue
   * @param {Object} issue - Security issue object
   * @param {Object} request - Request object
   * @returns {Object} Evidence object
   */
  gatherEvidence(issue, request) {
    try {
      const params = this.utilFunctions ? this.utilFunctions.parseParams(request.url) : {};
      const evidence = {
        hasState: !!params.state,
        stateLength: params.state ? params.state.length : 0,
        hasPKCE: !!params.code_challenge,
        hasNonce: !!params.nonce,
        isKnownProvider: this.oauth2Analyzer.isKnownProvider(request.url)
      };

      // Add state quality analysis for relevant issues
      if (issue.type === 'weakState' || issue.type === 'missingState') {
        if (params.state) {
          const stateQuality = this.oauth2Analyzer.analyzeStateQuality(params.state);
          evidence.stateEntropyPerChar = stateQuality.entropyPerChar;
          evidence.stateTotalEntropy = stateQuality.totalEntropy;
          evidence.stateAppearsRandom = stateQuality.appearsRandom;
        }
      }

      return evidence;
    } catch (error) {
      console.warn('Error gathering evidence:', error);
      return {};
    }
  }

  /**
   * Get recommendation for a specific issue type
   * @param {string} issueType - Issue type identifier
   * @returns {string} Recommendation text
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
   * Enhance an issue with confidence levels and evidence
   * @param {Object} issue - Base issue object
   * @param {Object} request - Request object
   * @returns {Object} Enhanced issue with evidence
   */
  enhanceIssue(issue, request) {
    const enhanced = {
      ...issue,
      confidence: this.calculateConfidence(issue, request),
      evidence: this.gatherEvidence(issue, request),
      recommendation: this.getIssueRecommendation(issue.type)
    };

    return enhanced;
  }

  /**
   * Perform evidence-based OAuth2 verification
   * @param {string} url - OAuth2 authorization URL to verify
   * @returns {Object} Verification results with evidence
   */
  async performEvidenceBasedOAuth2Verification(url) {
    if (!this.oauth2Verifier) {
      return {
        error: "Evidence-based verification not available",
        reason: "No evidence collector provided"
      };
    }

    try {
      // Perform comprehensive OAuth2 verification
      const csrfVerification = await this.oauth2Verifier.verifyCSRFProtection(url);
      const pkceVerification = await this.oauth2Verifier.verifyPKCE(url);

      const results = {
        url: url,
        timestamp: Date.now(),
        verificationId: this.generateVerificationId(),
        tests: {
          csrf: csrfVerification,
          pkce: pkceVerification
        },
        summary: this.summarizeOAuth2Verification(csrfVerification, pkceVerification)
      };

      // Store results for correlation
      this.verificationResults.set(results.verificationId, results);

      return results;
    } catch (error) {
      return {
        error: error.message,
        url: url,
        timestamp: Date.now()
      };
    }
  }

  /**
   * Perform evidence-based HSTS verification
   * @param {string} url - HTTPS URL to verify
   * @returns {Object} Verification results with evidence
   */
  async performEvidenceBasedHSTSVerification(url) {
    if (!this.hstsVerifier) {
      return {
        error: "Evidence-based verification not available",
        reason: "No evidence collector provided"
      };
    }

    try {
      const hstsVerification = await this.hstsVerifier.verifyHSTSImplementation(url);

      const results = {
        url: url,
        timestamp: Date.now(),
        verificationId: this.generateVerificationId(),
        tests: {
          hsts: hstsVerification
        },
        summary: this.summarizeHSTSVerification(hstsVerification)
      };

      // Store results for correlation
      this.verificationResults.set(results.verificationId, results);

      return results;
    } catch (error) {
      return {
        error: error.message,
        url: url,
        timestamp: Date.now()
      };
    }
  }

  /**
   * Generate vulnerability report based on evidence
   * @param {string} verificationId - Verification ID to generate report for
   * @returns {Object|null} Bug bounty ready vulnerability report
   */
  generateEvidenceBasedReport(verificationId) {
    const results = this.verificationResults.get(verificationId);
    if (!results) {
      return null;
    }

    // Generate OAuth2 vulnerability report
    if (results.tests.csrf && this.oauth2Verifier) {
      const oauth2Report = this.oauth2Verifier.generateVulnerabilityReport(results.tests.csrf);
      if (oauth2Report) {
        return {
          ...oauth2Report,
          verification_id: verificationId,
          hera_evidence_package: results
        };
      }
    }

    // Generate HSTS vulnerability report
    if (results.tests.hsts && this.hstsVerifier) {
      const hstsReport = this.generateHSTSVulnerabilityReport(results.tests.hsts);
      if (hstsReport) {
        return {
          ...hstsReport,
          verification_id: verificationId,
          hera_evidence_package: results
        };
      }
    }

    return null;
  }

  /**
   * Replace pattern-based OAuth2 state detection with evidence-based verification
   * @param {Object} request - Request object
   * @returns {Object|null} Evidence-based analysis results
   */
  async analyzeOAuth2WithEvidence(request) {
    const url = request.url;
    const params = this.utilFunctions ? this.utilFunctions.parseParams(url) : {};

    // Check if this is an OAuth2 authorization request
    if (!params?.client_id && !url.includes('oauth') && !url.includes('authorize')) {
      return null;
    }

    const analysis = {
      isOAuth2: true,
      parameters: params,
      evidenceBasedTests: null,
      recommendations: []
    };

    // Perform evidence-based verification if available
    if (this.oauth2Verifier) {
      try {
        analysis.evidenceBasedTests = await this.performEvidenceBasedOAuth2Verification(url);

        // Override pattern-based findings with evidence-based results
        if (analysis.evidenceBasedTests.tests?.csrf) {
          const csrfResults = analysis.evidenceBasedTests.tests.csrf;
          const vulnerableTests = csrfResults.testResults?.filter(test =>
            test.result === 'VULNERABLE' && test.severity === 'HIGH'
          );

          if (vulnerableTests?.length > 0) {
            analysis.vulnerabilities = vulnerableTests.map(test => ({
              type: test.test,
              severity: test.severity,
              evidence: test.evidence,
              verified: true
            }));
          }
        }
      } catch (error) {
        analysis.evidenceBasedTests = { error: error.message };
      }
    }

    return analysis;
  }

  /**
   * Summarize OAuth2 verification results
   * @param {Object} csrfVerification - CSRF verification results
   * @param {Object} pkceVerification - PKCE verification results
   * @returns {Object} Summary object
   */
  summarizeOAuth2Verification(csrfVerification, pkceVerification) {
    const summary = {
      vulnerabilities: [],
      strengths: [],
      overallRisk: 'LOW'
    };

    // Analyze CSRF verification results
    if (csrfVerification?.testResults) {
      const highRiskTests = csrfVerification.testResults.filter(test =>
        test.result === 'VULNERABLE' && test.severity === 'HIGH'
      );

      if (highRiskTests.length > 0) {
        summary.vulnerabilities.push(...highRiskTests.map(test => ({
          type: test.test,
          severity: test.severity,
          description: this.getTestDescription(test.test)
        })));
        summary.overallRisk = 'HIGH';
      }
    }

    // Analyze PKCE verification results
    if (pkceVerification?.testResults) {
      const pkceIssues = pkceVerification.testResults.filter(test =>
        test.result === 'VULNERABLE'
      );

      if (pkceIssues.length > 0) {
        summary.vulnerabilities.push(...pkceIssues.map(test => ({
          type: test.test,
          severity: test.severity,
          description: this.getTestDescription(test.test)
        })));

        if (summary.overallRisk !== 'HIGH') {
          summary.overallRisk = 'MEDIUM';
        }
      }
    }

    return summary;
  }

  /**
   * Summarize HSTS verification results
   * @param {Object} hstsVerification - HSTS verification results
   * @returns {Object} Summary object
   */
  summarizeHSTSVerification(hstsVerification) {
    const summary = {
      vulnerabilities: [],
      riskLevel: hstsVerification.riskLevel || 'LOW',
      hstsPresent: !!hstsVerification.evidence?.tests?.httpsHeaderCheck?.hstsHeader,
      recommendations: hstsVerification.recommendations || []
    };

    if (hstsVerification.vulnerabilities) {
      summary.vulnerabilities = hstsVerification.vulnerabilities;
    }

    return summary;
  }

  /**
   * Generate HSTS vulnerability report
   * @param {Object} hstsVerification - HSTS verification results
   * @returns {Object|null} Vulnerability report or null
   */
  generateHSTSVulnerabilityReport(hstsVerification) {
    const vulnerabilities = hstsVerification.vulnerabilities?.filter(v => v.severity === 'HIGH');

    if (!vulnerabilities || vulnerabilities.length === 0) {
      return null;
    }

    return {
      title: "Missing HSTS Protection Vulnerability",
      severity: "HIGH",
      confidence: "CONFIRMED",
      target: hstsVerification.evidence.targetUrl,

      summary: "HTTPS Strict Transport Security (HSTS) is not properly implemented, allowing downgrade attacks.",

      evidence: {
        target_url: hstsVerification.evidence.targetUrl,
        test_results: hstsVerification.evidence.tests,
        proof_of_vulnerability: {
          hsts_header_missing: !hstsVerification.evidence.tests.httpsHeaderCheck.hstsHeader,
          http_accessible: hstsVerification.evidence.tests.httpDowngradeTest?.httpAccessible,
          no_redirect_to_https: !hstsVerification.evidence.tests.httpDowngradeTest?.redirectsToHttps
        }
      },

      impact: "Attackers can downgrade HTTPS connections to HTTP, intercepting sensitive data in transit.",

      reproduction: [
        "1. Access the HTTP version of the target URL",
        "2. Observe that the connection is not automatically upgraded to HTTPS",
        "3. Verify that no HSTS header is sent in HTTPS responses",
        "4. Demonstrate successful HTTP connection to sensitive endpoints"
      ],

      recommendations: [
        "Implement HSTS header with appropriate max-age directive",
        "Redirect all HTTP traffic to HTTPS",
        "Consider HSTS preloading for enhanced security"
      ]
    };
  }

  /**
   * Get test description for OAuth2 verification
   * @param {string} testType - Test type identifier
   * @returns {string} Human-readable description
   */
  getTestDescription(testType) {
    const descriptions = {
      'csrf_no_state': 'OAuth2 authorization endpoint lacks CSRF protection via state parameter',
      'state_replay': 'OAuth2 state parameter can be reused, enabling CSRF attacks',
      'state_prediction': 'OAuth2 state parameter is predictable',
      'pkce_missing': 'OAuth2 flow lacks PKCE protection for public clients',
      'pkce_weak_method': 'OAuth2 PKCE uses weak challenge method'
    };

    return descriptions[testType] || `OAuth2 security issue: ${testType}`;
  }

  /**
   * Generate unique verification ID
   * @returns {string} Unique verification ID
   */
  generateVerificationId() {
    return `verification_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

export { AuthEvidenceManager };
