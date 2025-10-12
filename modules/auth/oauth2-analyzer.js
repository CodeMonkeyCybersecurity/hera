// OAuth2 Quality Analysis Module
// Analyzes state parameters, entropy, and known providers

class OAuth2Analyzer {
  /**
   * Calculate the entropy of a string
   * Returns both per-character entropy and total information content
   */
  calculateEntropy(str) {
    if (!str) return { perChar: 0, total: 0 };

    // Count character frequencies
    const freq = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    // Calculate Shannon entropy (bits per character)
    let entropyPerChar = 0;
    const len = str.length;
    for (const char in freq) {
      const p = freq[char] / len;
      entropyPerChar -= p * Math.log2(p);
    }

    return {
      perChar: entropyPerChar,
      total: entropyPerChar * len
    };
  }

  /**
   * Analyze the quality of a state parameter
   */
  analyzeStateQuality(state) {
    const entropyData = this.calculateEntropy(state);

    const analysis = {
      exists: !!state,
      length: state ? state.length : 0,
      entropyPerChar: entropyData.perChar,
      totalEntropy: entropyData.total,
      appearsRandom: false,
      risk: 'HIGH'
    };

    // Check entropy per character (should be >= 3 bits for decent randomness)
    // AND total entropy (should be >= 64 bits minimum for security)
    if (entropyData.perChar >= 3 && entropyData.total >= 128) {
      analysis.appearsRandom = true;
      analysis.risk = 'LOW';
    } else if (entropyData.perChar >= 2 && entropyData.total >= 64) {
      analysis.risk = 'MEDIUM';
    }

    return analysis;
  }

  /**
   * Check if this appears to be a legitimate OAuth2/OIDC provider
   */
  isKnownProvider(url) {
    const knownProviders = [
      'login.microsoftonline.com',
      'accounts.google.com',
      'github.com',
      'facebook.com',
      'auth0.com',
      'okta.com',
      'salesforce.com'
    ];

    try {
      const hostname = new URL(url).hostname;
      return knownProviders.some(provider => hostname.includes(provider));
    } catch {
      return false;
    }
  }
}

export { OAuth2Analyzer };
