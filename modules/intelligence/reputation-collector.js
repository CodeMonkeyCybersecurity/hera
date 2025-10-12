// Performance & Reputation Data Collector
// Handles performance metrics and threat intelligence from various sources

class ReputationCollector {
  async collectPerformanceData(url) {
    const performanceData = {
      timing: {},
      resources: {},
      anomalies: []
    };

    try {
      const startTime = performance.now();

      const response = await fetch(url, {
        method: 'HEAD',
        signal: AbortSignal.timeout(10000)
      });

      const endTime = performance.now();
      const responseTime = endTime - startTime;

      performanceData.timing = {
        responseTime: responseTime,
        category: responseTime < 200 ? 'fast' : responseTime < 1000 ? 'normal' : 'slow'
      };

      if (responseTime > 5000) {
        performanceData.anomalies.push('very_slow_response');
      }

      if (response) {
        const contentLength = response.headers.get('content-length');
        if (contentLength) {
          performanceData.resources.totalSize = parseInt(contentLength);
        }
      }

    } catch (error) {
      performanceData.anomalies.push('connection_failed');
      console.error('Performance data collection failed:', error);
    }

    return performanceData;
  }

  async collectReputationData(domain) {
    const reputationData = {
      threatFeeds: {},
      historicalData: {},
      webOfTrust: {},
      anomalies: []
    };

    try {
      // Simulate threat feed checks
      reputationData.threatFeeds = {
        phishtank: await this.checkPhishTank(domain),
        urlhaus: await this.checkURLHaus(domain),
        safeBrowsing: await this.checkSafeBrowsing(domain)
      };

      // Historical analysis
      reputationData.historicalData = {
        domainAge: this.estimateDomainAge(domain),
        previouslyBlacklisted: Math.random() < 0.1, // 10% chance
        registrationPattern: this.analyzeRegistrationPattern(domain)
      };

    } catch (error) {
      console.error('Reputation data collection failed:', error);
    }

    return reputationData;
  }

  async checkPhishTank(domain) {
    // Simulate PhishTank API check
    const suspiciousPatterns = ['secure', 'verify', 'update', 'suspended'];
    const isListed = suspiciousPatterns.some(pattern => domain.includes(pattern));

    return {
      listed: isListed,
      verified: isListed,
      category: isListed ? 'phishing' : 'clean'
    };
  }

  async checkURLHaus(domain) {
    // Simulate URLhaus check
    return {
      listed: Math.random() < 0.05, // 5% chance
      category: 'malware'
    };
  }

  async checkSafeBrowsing(domain) {
    // Simulate Google Safe Browsing check
    const status = Math.random() < 0.95 ? 'SAFE' : 'POTENTIALLY_HARMFUL';
    return { status };
  }

  estimateDomainAge(domain) {
    // Heuristic domain age estimation
    const tld = domain.split('.').pop();
    const suspiciousTLDs = ['tk', 'ml', 'ga', 'cf'];

    if (suspiciousTLDs.includes(tld)) {
      return Math.random() * 90; // 0-90 days for suspicious TLDs
    }

    const hash = domain.split('').reduce((a, b) => a + b.charCodeAt(0), 0);
    return (hash % 3650) + 30; // 30 days to 10 years
  }

  analyzeRegistrationPattern(domain) {
    const patterns = {
      bulkRegistration: domain.length < 6 || /\d{4,}/.test(domain),
      randomPattern: /[a-z]{1}[0-9]{2,}[a-z]{1}/.test(domain),
      keywordStuffing: domain.split('-').length > 3
    };

    return patterns;
  }
}

export { ReputationCollector };
