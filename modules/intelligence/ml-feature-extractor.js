// Machine Learning Feature Extractor
// Extracts features for ML-based threat detection

class MLFeatureExtractor {
  async extractMLFeatures(domain, url) {
    const features = {
      domain: this.extractDomainFeatures(domain),
      url: this.extractURLFeatures(url),
      lexical: this.extractLexicalFeatures(domain),
      behavioral: await this.extractBehavioralFeatures(domain)
    };

    return features;
  }

  extractDomainFeatures(domain) {
    return {
      length: domain.length,
      entropy: this.calculateEntropy(domain),
      subdomainCount: domain.split('.').length - 2,
      dashCount: (domain.match(/-/g) || []).length,
      numberCount: (domain.match(/\d/g) || []).length,
      vowelRatio: this.calculateVowelRatio(domain),
      tld: domain.split('.').pop(),
      hasBrandName: this.checkBrandNames(domain),
      suspiciousKeywords: this.countSuspiciousKeywords(domain)
    };
  }

  extractURLFeatures(url) {
    return {
      length: url.length,
      hasHTTPS: url.startsWith('https:'),
      hasIP: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url),
      hasPunycode: url.includes('xn--'),
      pathDepth: url.split('/').length - 3,
      hasPhishingKeywords: this.hasPhishingKeywords(url)
    };
  }

  extractLexicalFeatures(domain) {
    const dictionary = ['secure', 'bank', 'pay', 'login', 'verify', 'update'];
    return {
      dictionaryWords: dictionary.filter(word => domain.includes(word)).length,
      repeatedChars: this.countRepeatedChars(domain),
      consonantClusters: this.countConsonantClusters(domain)
    };
  }

  async extractBehavioralFeatures(domain) {
    return {
      redirectCount: await this.countRedirects(domain),
      responseTime: await this.measureResponseTime(domain),
      availabilityScore: await this.checkAvailability(domain)
    };
  }

  // Utility functions for ML features
  calculateEntropy(str) {
    const freq = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  calculateVowelRatio(str) {
    const vowels = str.match(/[aeiou]/gi) || [];
    return vowels.length / str.length;
  }

  checkBrandNames(domain) {
    const brands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal'];
    return brands.some(brand => domain.includes(brand));
  }

  countSuspiciousKeywords(domain) {
    const keywords = ['secure', 'verify', 'update', 'suspended', 'urgent', 'action'];
    return keywords.filter(keyword => domain.includes(keyword)).length;
  }

  hasPhishingKeywords(url) {
    const phishingKeywords = ['signin', 'banking', 'paypal', 'ebay', 'amazon'];
    return phishingKeywords.some(keyword => url.toLowerCase().includes(keyword));
  }

  countRepeatedChars(str) {
    let count = 0;
    for (let i = 1; i < str.length; i++) {
      if (str[i] === str[i-1]) count++;
    }
    return count;
  }

  countConsonantClusters(str) {
    const consonants = str.replace(/[aeiou\d\-\.]/gi, '');
    let clusters = 0;
    let currentCluster = 0;

    for (const char of consonants) {
      if (/[bcdfghjklmnpqrstvwxyz]/i.test(char)) {
        currentCluster++;
      } else {
        if (currentCluster >= 3) clusters++;
        currentCluster = 0;
      }
    }

    return clusters;
  }

  async countRedirects(domain) {
    try {
      let redirects = 0;
      let currentUrl = `https://${domain}`;

      for (let i = 0; i < 5; i++) { // Max 5 redirects
        const response = await fetch(currentUrl, {
          method: 'HEAD',
          redirect: 'manual',
          signal: AbortSignal.timeout(3000)
        });

        if (response.type === 'opaqueredirect' ||
            response.status >= 300 && response.status < 400) {
          redirects++;
          const location = response.headers.get('location');
          if (!location) break;
          currentUrl = new URL(location, currentUrl).href;
        } else {
          break;
        }
      }

      return redirects;
    } catch (error) {
      return 0;
    }
  }

  async measureResponseTime(domain) {
    try {
      const start = performance.now();
      await fetch(`https://${domain}`, {
        method: 'HEAD',
        signal: AbortSignal.timeout(5000)
      });
      return performance.now() - start;
    } catch (error) {
      return 10000; // Timeout
    }
  }

  async checkAvailability(domain) {
    try {
      const response = await fetch(`https://${domain}`, {
        method: 'HEAD',
        signal: AbortSignal.timeout(5000)
      });
      return response.ok ? 1.0 : 0.5;
    } catch (error) {
      return 0.0;
    }
  }
}

export { MLFeatureExtractor };
