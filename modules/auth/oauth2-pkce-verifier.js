/**
 * OAuth2 PKCE Verifier for Hera
 *
 * This module implements evidence-based PKCE (Proof Key for Code Exchange) verification.
 * It tests for PKCE implementation, code challenge method security, and entropy analysis.
 */

class OAuth2PKCEVerifier {
  /**
   * Verify PKCE implementation
   * @param {string} authorizationUrl - OAuth2 authorization URL
   * @returns {Object} PKCE verification results
   */
  async verifyPKCE(authorizationUrl) {
    const evidence = {
      originalRequest: authorizationUrl,
      codeChallenge: this.extractCodeChallenge(authorizationUrl),
      codeChallengeMethod: this.extractCodeChallengeMethod(authorizationUrl),
      testResults: [],
      timestamp: Date.now()
    };

    // Test 1: Check if PKCE is implemented
    if (!evidence.codeChallenge) {
      evidence.testResults.push({
        test: "pkce_missing",
        result: "VULNERABLE",
        evidence: {
          description: "No code_challenge parameter found",
          recommendation: "Implement PKCE for public clients"
        },
        severity: "HIGH"
      });
    } else {
      // Test 2: Verify code challenge method
      const methodTest = this.analyzeCodeChallengeMethod(evidence.codeChallengeMethod);
      evidence.testResults.push({
        test: "pkce_method",
        result: methodTest.secure ? "SECURE" : "WEAK",
        evidence: methodTest,
        severity: methodTest.secure ? "SECURE" : "MEDIUM"
      });

      // Test 3: Analyze code challenge entropy
      const challengeTest = this.analyzeChallengeEntropy(evidence.codeChallenge);
      evidence.testResults.push({
        test: "pkce_entropy",
        result: challengeTest.sufficient ? "SECURE" : "WEAK",
        evidence: challengeTest,
        severity: challengeTest.sufficient ? "SECURE" : "MEDIUM"
      });
    }

    return evidence;
  }

  /**
   * Extract code_challenge parameter
   * @param {string} url - OAuth2 authorization URL
   * @returns {string|null} Code challenge value
   */
  extractCodeChallenge(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.searchParams.get('code_challenge');
    } catch (error) {
      return null;
    }
  }

  /**
   * Extract code_challenge_method parameter
   * @param {string} url - OAuth2 authorization URL
   * @returns {string|null} Code challenge method
   */
  extractCodeChallengeMethod(url) {
    try {
      const urlObj = new URL(url);
      return urlObj.searchParams.get('code_challenge_method');
    } catch (error) {
      return null;
    }
  }

  /**
   * Analyze code challenge method security
   * @param {string} method - Code challenge method
   * @returns {Object} Method analysis
   */
  analyzeCodeChallengeMethod(method) {
    if (!method || method === 'plain') {
      return {
        secure: false,
        method: method || 'none',
        reason: 'Plain text method is insecure',
        recommendation: 'Use S256 method instead'
      };
    }

    if (method === 'S256') {
      return {
        secure: true,
        method: method,
        reason: 'SHA256 method is secure'
      };
    }

    return {
      secure: false,
      method: method,
      reason: 'Unknown or insecure method',
      recommendation: 'Use S256 method'
    };
  }

  /**
   * Analyze code challenge entropy
   * @param {string} challenge - Code challenge value
   * @returns {Object} Challenge analysis
   */
  analyzeChallengeEntropy(challenge) {
    if (!challenge) {
      return {
        sufficient: false,
        reason: 'No challenge provided'
      };
    }

    const entropy = this.calculateEntropy(challenge);
    const length = challenge.length;
    const minEntropy = 128; // bits total
    const actualEntropy = entropy * length;

    return {
      sufficient: actualEntropy >= minEntropy,
      challenge: challenge,
      length: length,
      entropy: entropy,
      totalEntropy: actualEntropy,
      minimumRequired: minEntropy
    };
  }

  /**
   * Calculate Shannon entropy of a string
   * @param {string} str - String to analyze
   * @returns {number} Shannon entropy
   */
  calculateEntropy(str) {
    if (!str || str.length === 0) return 0;

    const freq = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }
}

export { OAuth2PKCEVerifier };
