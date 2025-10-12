// Intelligence Collection Coordinator
// Orchestrates parallel data collection from all intelligence modules

import { NetworkCollector } from './network-collector.js';
import { SecurityCollector } from './security-collector.js';
import { ContentCollector } from './content-collector.js';
import { ReputationCollector } from './reputation-collector.js';
import { MLFeatureExtractor } from './ml-feature-extractor.js';

class IntelligenceCoordinator {
  constructor() {
    this.cache = new Map(); // Cache results for performance
    this.rateLimiter = new Map(); // Rate limiting
    this.fingerprints = new Map(); // Site fingerprints

    // Initialize collectors
    this.networkCollector = new NetworkCollector();
    this.securityCollector = new SecurityCollector();
    this.contentCollector = new ContentCollector();
    this.reputationCollector = new ReputationCollector();
    this.mlExtractor = new MLFeatureExtractor();
  }

  async collectAllData(url) {
    const startTime = performance.now();
    const domain = new URL(url).hostname;

    console.log(`Starting comprehensive intelligence collection for ${domain}`);

    // Check cache first
    const cacheKey = `${domain}_${Date.now().toString().slice(0, -5)}`; // 5-minute cache
    if (this.cache.has(cacheKey)) {
      console.log(`Using cached data for ${domain}`);
      return this.cache.get(cacheKey);
    }

    try {
      // Parallel collection for speed
      const [
        networkData,
        securityData,
        contentData,
        performanceData,
        reputationData,
        mlFeatures
      ] = await Promise.allSettled([
        this.networkCollector.collectNetworkData(domain),
        this.securityCollector.collectSecurityData(domain),
        this.contentCollector.collectContentData(url),
        this.reputationCollector.collectPerformanceData(url),
        this.reputationCollector.collectReputationData(domain),
        this.mlExtractor.extractMLFeatures(domain, url)
      ]);

      // Merge successful results
      const data = {
        network: networkData.status === 'fulfilled' ? networkData.value : {},
        security: securityData.status === 'fulfilled' ? securityData.value : {},
        content: contentData.status === 'fulfilled' ? contentData.value : {},
        performance: performanceData.status === 'fulfilled' ? performanceData.value : {},
        reputation: reputationData.status === 'fulfilled' ? reputationData.value : {},
        ml: mlFeatures.status === 'fulfilled' ? mlFeatures.value : {}
      };

      // Calculate compound metrics
      const compoundMetrics = this.calculateCompoundMetrics(data);

      const fullProfile = {
        url,
        domain,
        timestamp: Date.now(),
        ...data,
        compound: compoundMetrics,
        fingerprint: await this.generateFingerprint(data),
        collectionTime: performance.now() - startTime
      };

      // Cache result
      this.cache.set(cacheKey, fullProfile);

      console.log(`Intelligence collection complete for ${domain} (${Math.round(fullProfile.collectionTime)}ms)`);
      return fullProfile;

    } catch (error) {
      console.error('Failed to collect comprehensive data:', error);
      return this.getMinimalProfile(url, domain);
    }
  }

  calculateCompoundMetrics(data) {
    const metrics = {
      overallRiskScore: 0,
      anomalyScore: 0,
      deceptionProbability: 0,
      infrastructureQuality: 0,
      trustScore: 0
    };

    try {
      // Overall risk score (0-100)
      let riskFactors = 0;
      let totalFactors = 0;

      // Security factors
      if (data.security?.headers?.score) {
        riskFactors += (100 - data.security.headers.score);
        totalFactors++;
      }

      // Reputation factors
      if (data.reputation?.threatFeeds?.phishtank?.listed) {
        riskFactors += 80;
        totalFactors++;
      }

      // Domain age factor
      if (data.reputation?.historicalData?.domainAge < 30) {
        riskFactors += 60;
        totalFactors++;
      }

      metrics.overallRiskScore = totalFactors > 0 ? riskFactors / totalFactors : 0;

      // Anomaly score based on ML features
      if (data.ml?.domain) {
        const domain = data.ml.domain;
        let anomalies = 0;

        if (domain.entropy > 4.5) anomalies += 20; // High entropy
        if (domain.numberCount > 3) anomalies += 15; // Many numbers
        if (domain.suspiciousKeywords > 0) anomalies += 25; // Suspicious words
        if (domain.hasBrandName && domain.length > 15) anomalies += 30; // Brand + long

        metrics.anomalyScore = Math.min(100, anomalies);
      }

      // Deception probability
      let deceptionFactors = 0;
      if (data.content?.textAnalysis?.similarity > 0.7) deceptionFactors += 40;
      if (data.ml?.domain?.hasBrandName && data.reputation?.historicalData?.domainAge < 90) {
        deceptionFactors += 50;
      }

      metrics.deceptionProbability = Math.min(100, deceptionFactors);

      // Infrastructure quality
      let infraScore = 50; // Base score
      if (data.security?.headers?.grade === 'A' || data.security?.headers?.grade === 'A+') {
        infraScore += 25;
      }
      if (data.security?.tls?.grade === 'A+') infraScore += 15;
      if (data.network?.cdn?.provider) infraScore += 10;

      metrics.infrastructureQuality = Math.min(100, infraScore);

      // Trust score (inverse of risk)
      metrics.trustScore = 100 - metrics.overallRiskScore;

    } catch (error) {
      console.error('Compound metrics calculation failed:', error);
    }

    return metrics;
  }

  async generateFingerprint(data) {
    try {
      const fingerprintComponents = [
        data.network?.dns?.aRecords?.join(',') || '',
        data.network?.hosting?.provider || '',
        data.content?.technology?.server || '',
        data.security?.certificates?.issuer || '',
        JSON.stringify(data.ml?.domain || {})
      ];

      const fingerprintString = fingerprintComponents.join('|');

      // Create a simple hash (in production, use crypto.subtle.digest)
      let hash = 0;
      for (let i = 0; i < fingerprintString.length; i++) {
        const char = fingerprintString.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32bit integer
      }

      return Math.abs(hash).toString(16);

    } catch (error) {
      console.error('Fingerprint generation failed:', error);
      return 'unknown';
    }
  }

  getMinimalProfile(url, domain) {
    return {
      url,
      domain,
      timestamp: Date.now(),
      network: {},
      security: {},
      content: {},
      performance: {},
      reputation: {},
      ml: {},
      compound: {
        overallRiskScore: 50,
        anomalyScore: 0,
        deceptionProbability: 0,
        infrastructureQuality: 50,
        trustScore: 50
      },
      fingerprint: 'minimal',
      collectionTime: 0,
      error: 'Limited data collection due to browser restrictions'
    };
  }

  // Clear old cache entries
  cleanCache() {
    const now = Date.now();
    const maxAge = 5 * 60 * 1000; // 5 minutes

    for (const [key, value] of this.cache.entries()) {
      if (now - value.timestamp > maxAge) {
        this.cache.delete(key);
      }
    }
  }
}

export { IntelligenceCoordinator };
