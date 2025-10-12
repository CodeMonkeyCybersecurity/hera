/**
 * OAuth2 Report Generator for Hera
 *
 * This module generates comprehensive vulnerability reports suitable for bug bounty submissions.
 * It provides detailed evidence, impact analysis, and reproduction steps.
 */

class OAuth2ReportGenerator {
  /**
   * Generate a comprehensive vulnerability report
   * @param {Object} evidence - Test evidence
   * @returns {Object} Bug bounty ready report
   */
  generateVulnerabilityReport(evidence) {
    const vulnerabilities = evidence.testResults.filter(test =>
      test.result === 'VULNERABLE' && test.severity === 'HIGH'
    );

    if (vulnerabilities.length === 0) {
      return null; // No high-severity vulnerabilities found
    }

    const report = {
      title: "OAuth2 Security Vulnerabilities",
      severity: "HIGH",
      confidence: "CONFIRMED",
      target: evidence.originalRequest,

      summary: this.generateSummary(vulnerabilities),

      vulnerabilities: vulnerabilities.map(vuln => ({
        type: vuln.test,
        description: this.getVulnerabilityDescription(vuln.test),
        evidence: vuln.evidence,
        impact: this.getImpact(vuln.test),
        reproduction: this.getReproductionSteps(vuln.test, vuln.evidence)
      })),

      recommendations: this.getRecommendations(vulnerabilities),

      evidence_package: {
        flow_id: evidence.flowId,
        timestamp: evidence.timestamp,
        complete_test_results: evidence.testResults
      }
    };

    return report;
  }

  /**
   * Generate executive summary of vulnerabilities
   * @param {Array} vulnerabilities - List of vulnerabilities
   * @returns {string} Summary text
   */
  generateSummary(vulnerabilities) {
    const types = vulnerabilities.map(v => v.test);
    if (types.includes('csrf_no_state')) {
      return "OAuth2 authorization endpoint lacks CSRF protection, allowing attackers to forge authorization requests.";
    }
    if (types.includes('state_replay')) {
      return "OAuth2 state parameter can be reused, enabling CSRF attacks.";
    }
    return "Multiple OAuth2 security vulnerabilities detected.";
  }

  /**
   * Get detailed vulnerability description
   * @param {string} testType - Type of vulnerability test
   * @returns {string} Description text
   */
  getVulnerabilityDescription(testType) {
    const descriptions = {
      csrf_no_state: "The OAuth2 authorization endpoint accepts requests without a state parameter, making it vulnerable to CSRF attacks.",
      state_replay: "The OAuth2 state parameter can be reused multiple times, defeating CSRF protection.",
      state_prediction: "The OAuth2 state parameter is predictable, allowing attackers to forge valid states."
    };
    return descriptions[testType] || "OAuth2 security vulnerability detected.";
  }

  /**
   * Get impact assessment for vulnerability
   * @param {string} testType - Type of vulnerability test
   * @returns {string} Impact description
   */
  getImpact(testType) {
    const impacts = {
      csrf_no_state: "Attackers can trick users into authorizing malicious applications, leading to account takeover.",
      state_replay: "Attackers can reuse captured state values to bypass CSRF protection.",
      state_prediction: "Attackers can predict valid state values to forge authorization requests."
    };
    return impacts[testType] || "Security vulnerability that may lead to unauthorized access.";
  }

  /**
   * Get step-by-step reproduction instructions
   * @param {string} testType - Type of vulnerability test
   * @param {Object} evidence - Test evidence
   * @returns {Array} List of reproduction steps
   */
  getReproductionSteps(testType, evidence) {
    if (testType === 'csrf_no_state') {
      return [
        "1. Create a malicious OAuth2 application",
        "2. Craft authorization URL without state parameter",
        "3. Social engineer victim to click malicious link",
        "4. Observe successful authorization without CSRF protection",
        "5. Attacker receives authorization code for victim's account"
      ];
    }
    return ["Detailed reproduction steps included in evidence package"];
  }

  /**
   * Get remediation recommendations
   * @param {Array} vulnerabilities - List of vulnerabilities
   * @returns {Array} List of recommendations
   */
  getRecommendations(vulnerabilities) {
    const recommendations = [];
    const types = vulnerabilities.map(v => v.test);

    if (types.includes('csrf_no_state')) {
      recommendations.push("Implement mandatory state parameter validation");
      recommendations.push("Generate cryptographically random state values");
      recommendations.push("Validate state parameter on callback");
    }

    if (types.includes('state_replay')) {
      recommendations.push("Implement one-time use state parameter validation");
      recommendations.push("Store and invalidate used state values");
    }

    if (types.includes('state_prediction')) {
      recommendations.push("Use cryptographically secure random number generator for state");
      recommendations.push("Ensure sufficient entropy in state parameter generation");
    }

    return recommendations;
  }
}

export { OAuth2ReportGenerator };
