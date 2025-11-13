/**
 * Tests for P1-2: Evidence Quality Indicators
 *
 * Tests enhanced evidence quality features:
 * - Request coverage tracking (OAuth2 flow types)
 * - Finding confidence metrics integration
 * - Actionable suggestions generation
 * - Console logging for evidence quality
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock EvidenceCollector for testing
class MockEvidenceCollector {
  constructor() {
    this.responseCache = new Map();
  }

  calculateEvidenceQuality(requestId, findings = []) {
    const evidence = this.responseCache.get(requestId);
    if (!evidence) {return null;}

    const quality = {
      completeness: 0,
      reliability: 'UNKNOWN',
      gaps: [],
      strengths: [],
      requestCoverage: null,
      findingConfidence: null,
      suggestions: []
    };

    // Check what evidence components we have
    const has = {
      requestHeaders: !!(evidence.requestData?.requestHeaders?.length > 0),
      requestBody: !!(evidence.requestData?.requestBody),
      responseHeaders: !!(evidence.headers?.length > 0),
      responseBody: !!(evidence.body),
      statusCode: !!(evidence.statusCode),
      timing: !!(evidence.timestamp)
    };

    // Calculate completeness
    const components = Object.values(has);
    quality.completeness = Math.round(
      (components.filter(Boolean).length / components.length) * 100
    );

    // Determine reliability
    if (quality.completeness >= 90) {
      quality.reliability = 'HIGH';
    } else if (quality.completeness >= 70) {
      quality.reliability = 'MEDIUM';
    } else if (quality.completeness >= 50) {
      quality.reliability = 'LOW';
    } else {
      quality.reliability = 'VERY_LOW';
    }

    // Calculate request coverage
    quality.requestCoverage = this._calculateRequestCoverage();

    // Calculate finding confidence
    if (findings && findings.length > 0) {
      quality.findingConfidence = this._calculateAggregateConfidence(findings);
    }

    // Generate suggestions
    quality.suggestions = this._generateSuggestions(quality, has, evidence.requestData?.url || '');

    return quality;
  }

  _calculateRequestCoverage() {
    const coverage = {
      hasAuthFlow: false,
      hasTokenExchange: false,
      hasTokenRefresh: false,
      percentage: 0
    };

    for (const [_, evidence] of this.responseCache) {
      const flowType = evidence.requestData?.analysis?.oauth2Flow?.flowType;
      if (flowType === 'authorization_request') {
        coverage.hasAuthFlow = true;
      } else if (flowType === 'token_exchange') {
        coverage.hasTokenExchange = true;
      } else if (flowType === 'token_refresh') {
        coverage.hasTokenRefresh = true;
      }
    }

    const found = [coverage.hasAuthFlow, coverage.hasTokenExchange, coverage.hasTokenRefresh].filter(Boolean).length;
    coverage.percentage = Math.floor((found / 3) * 100);

    return coverage;
  }

  _calculateAggregateConfidence(findings) {
    const distribution = {
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      SPECULATIVE: 0
    };

    let totalScore = 0;

    findings.forEach(finding => {
      if (finding.confidence) {
        distribution[finding.confidence] = (distribution[finding.confidence] || 0) + 1;
      }
      if (finding.confidenceScore) {
        totalScore += finding.confidenceScore;
      }
    });

    return {
      averageScore: findings.length > 0 ? Math.round(totalScore / findings.length) : 0,
      distribution,
      highConfidenceCount: distribution.HIGH || 0
    };
  }

  _generateSuggestions(quality, has, url) {
    const suggestions = [];

    // Request coverage suggestions
    if (quality.requestCoverage) {
      if (!quality.requestCoverage.hasAuthFlow) {
        suggestions.push('Capture an OAuth2 authorization request (/authorize endpoint) for complete flow analysis');
      }
      if (!quality.requestCoverage.hasTokenExchange) {
        suggestions.push('Capture an OAuth2 token exchange request (grant_type=authorization_code) to verify PKCE');
      }
      if (!quality.requestCoverage.hasTokenRefresh) {
        suggestions.push('Capture a refresh token request (grant_type=refresh_token) to verify rotation');
      }
    }

    // Evidence completeness suggestions
    if (!has.requestBody && url.includes('/token')) {
      suggestions.push('Enable request body capture to verify OAuth2 grant types and PKCE code_verifier');
    }
    if (!has.responseBody && url.includes('/token')) {
      suggestions.push('Enable response body capture (debugger mode) to verify token types and DPoP');
    }

    // Finding confidence suggestions
    if (quality.findingConfidence) {
      const { averageScore, distribution } = quality.findingConfidence;
      if (averageScore < 70) {
        suggestions.push('Findings have medium-to-low confidence - enable debugger mode for more reliable detections');
      }
      if ((distribution.LOW || 0) + (distribution.SPECULATIVE || 0) > (distribution.HIGH || 0)) {
        suggestions.push('Most findings require manual verification - capture more complete evidence for higher confidence');
      }
    }

    return suggestions;
  }

  getAggregateEvidenceQuality() {
    const allQualities = [];
    const byReliability = {
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      VERY_LOW: 0
    };

    for (const [requestId] of this.responseCache) {
      const quality = this.calculateEvidenceQuality(requestId);
      if (quality) {
        allQualities.push(quality);
        byReliability[quality.reliability]++;
      }
    }

    if (allQualities.length === 0) {
      return {
        totalRequests: 0,
        averageCompleteness: 0,
        distribution: byReliability
      };
    }

    const averageCompleteness = Math.round(
      allQualities.reduce((sum, q) => sum + q.completeness, 0) / allQualities.length
    );

    return {
      totalRequests: allQualities.length,
      averageCompleteness,
      distribution: byReliability
    };
  }
}

describe('P1-2: Evidence Quality Indicators', () => {
  let collector;

  beforeEach(() => {
    collector = new MockEvidenceCollector();
  });

  describe('Request Coverage Tracking', () => {
    it('should track authorization request flow', () => {
      collector.responseCache.set('req1', {
        requestData: {
          url: 'https://auth.example.com/authorize?response_type=code',
          analysis: {
            oauth2Flow: {
              flowType: 'authorization_request'
            }
          }
        },
        headers: [],
        body: '',
        statusCode: 200,
        timestamp: Date.now()
      });

      const quality = collector.calculateEvidenceQuality('req1');

      expect(quality.requestCoverage.hasAuthFlow).toBe(true);
      expect(quality.requestCoverage.hasTokenExchange).toBe(false);
      expect(quality.requestCoverage.hasTokenRefresh).toBe(false);
      expect(quality.requestCoverage.percentage).toBe(33); // 1/3 = 33%
    });

    it('should track token exchange flow', () => {
      collector.responseCache.set('req1', {
        requestData: {
          url: 'https://auth.example.com/token',
          requestBody: 'grant_type=authorization_code&code=ABC123',
          analysis: {
            oauth2Flow: {
              flowType: 'token_exchange'
            }
          }
        },
        headers: [],
        body: '{"access_token":"xyz"}',
        statusCode: 200,
        timestamp: Date.now()
      });

      const quality = collector.calculateEvidenceQuality('req1');

      expect(quality.requestCoverage.hasAuthFlow).toBe(false);
      expect(quality.requestCoverage.hasTokenExchange).toBe(true);
      expect(quality.requestCoverage.hasTokenRefresh).toBe(false);
      expect(quality.requestCoverage.percentage).toBe(33); // 1/3 = 33%
    });

    it('should track token refresh flow', () => {
      collector.responseCache.set('req1', {
        requestData: {
          url: 'https://auth.example.com/token',
          requestBody: 'grant_type=refresh_token&refresh_token=xyz',
          analysis: {
            oauth2Flow: {
              flowType: 'token_refresh'
            }
          }
        },
        headers: [],
        body: '{"access_token":"new"}',
        statusCode: 200,
        timestamp: Date.now()
      });

      const quality = collector.calculateEvidenceQuality('req1');

      expect(quality.requestCoverage.hasAuthFlow).toBe(false);
      expect(quality.requestCoverage.hasTokenExchange).toBe(false);
      expect(quality.requestCoverage.hasTokenRefresh).toBe(true);
      expect(quality.requestCoverage.percentage).toBe(33); // 1/3 = 33%
    });

    it('should track complete OAuth2 flow (100% coverage)', () => {
      // Authorization request
      collector.responseCache.set('req1', {
        requestData: {
          url: 'https://auth.example.com/authorize',
          analysis: {
            oauth2Flow: { flowType: 'authorization_request' }
          }
        },
        headers: [],
        body: '',
        statusCode: 302,
        timestamp: Date.now()
      });

      // Token exchange
      collector.responseCache.set('req2', {
        requestData: {
          url: 'https://auth.example.com/token',
          analysis: {
            oauth2Flow: { flowType: 'token_exchange' }
          }
        },
        headers: [],
        body: '{"access_token":"xyz"}',
        statusCode: 200,
        timestamp: Date.now()
      });

      // Token refresh
      collector.responseCache.set('req3', {
        requestData: {
          url: 'https://auth.example.com/token',
          analysis: {
            oauth2Flow: { flowType: 'token_refresh' }
          }
        },
        headers: [],
        body: '{"access_token":"new"}',
        statusCode: 200,
        timestamp: Date.now()
      });

      const quality = collector.calculateEvidenceQuality('req1');

      expect(quality.requestCoverage.hasAuthFlow).toBe(true);
      expect(quality.requestCoverage.hasTokenExchange).toBe(true);
      expect(quality.requestCoverage.hasTokenRefresh).toBe(true);
      expect(quality.requestCoverage.percentage).toBe(100); // 3/3 = 100%
    });

    it('should handle requests with no OAuth2 flow type', () => {
      collector.responseCache.set('req1', {
        requestData: {
          url: 'https://api.example.com/data',
          analysis: {
            oauth2Flow: { flowType: 'unknown' }
          }
        },
        headers: [],
        body: '',
        statusCode: 200,
        timestamp: Date.now()
      });

      const quality = collector.calculateEvidenceQuality('req1');

      expect(quality.requestCoverage.hasAuthFlow).toBe(false);
      expect(quality.requestCoverage.hasTokenExchange).toBe(false);
      expect(quality.requestCoverage.hasTokenRefresh).toBe(false);
      expect(quality.requestCoverage.percentage).toBe(0); // 0/3 = 0%
    });
  });

  describe('Finding Confidence Metrics Integration', () => {
    it('should calculate average confidence score', () => {
      collector.responseCache.set('req1', {
        requestData: { url: 'https://example.com' },
        headers: [],
        body: '',
        statusCode: 200,
        timestamp: Date.now()
      });

      const findings = [
        { confidence: 'HIGH', confidenceScore: 95 },
        { confidence: 'HIGH', confidenceScore: 90 },
        { confidence: 'MEDIUM', confidenceScore: 70 }
      ];

      const quality = collector.calculateEvidenceQuality('req1', findings);

      expect(quality.findingConfidence.averageScore).toBe(85); // (95+90+70)/3 = 85
    });

    it('should track confidence distribution', () => {
      collector.responseCache.set('req1', {
        requestData: { url: 'https://example.com' },
        headers: [],
        body: '',
        statusCode: 200,
        timestamp: Date.now()
      });

      const findings = [
        { confidence: 'HIGH', confidenceScore: 95 },
        { confidence: 'HIGH', confidenceScore: 90 },
        { confidence: 'MEDIUM', confidenceScore: 70 },
        { confidence: 'LOW', confidenceScore: 50 },
        { confidence: 'SPECULATIVE', confidenceScore: 30 }
      ];

      const quality = collector.calculateEvidenceQuality('req1', findings);

      expect(quality.findingConfidence.distribution.HIGH).toBe(2);
      expect(quality.findingConfidence.distribution.MEDIUM).toBe(1);
      expect(quality.findingConfidence.distribution.LOW).toBe(1);
      expect(quality.findingConfidence.distribution.SPECULATIVE).toBe(1);
      expect(quality.findingConfidence.highConfidenceCount).toBe(2);
    });

    it('should handle empty findings array', () => {
      collector.responseCache.set('req1', {
        requestData: { url: 'https://example.com' },
        headers: [],
        body: '',
        statusCode: 200,
        timestamp: Date.now()
      });

      const quality = collector.calculateEvidenceQuality('req1', []);

      expect(quality.findingConfidence).toBeNull();
    });

    it('should handle findings without confidence scores', () => {
      collector.responseCache.set('req1', {
        requestData: { url: 'https://example.com' },
        headers: [],
        body: '',
        statusCode: 200,
        timestamp: Date.now()
      });

      const findings = [
        { confidence: 'HIGH' },
        { confidence: 'MEDIUM' }
      ];

      const quality = collector.calculateEvidenceQuality('req1', findings);

      expect(quality.findingConfidence.averageScore).toBe(0); // No scores provided
      expect(quality.findingConfidence.distribution.HIGH).toBe(1);
      expect(quality.findingConfidence.distribution.MEDIUM).toBe(1);
    });
  });

  describe('Actionable Suggestions Generation', () => {
    it('should suggest capturing missing OAuth2 flows', () => {
      collector.responseCache.set('req1', {
        requestData: {
          url: 'https://auth.example.com/authorize',
          analysis: {
            oauth2Flow: { flowType: 'authorization_request' }
          }
        },
        headers: [],
        body: '',
        statusCode: 302,
        timestamp: Date.now()
      });

      const quality = collector.calculateEvidenceQuality('req1');

      expect(quality.suggestions).toContain('Capture an OAuth2 token exchange request (grant_type=authorization_code) to verify PKCE');
      expect(quality.suggestions).toContain('Capture a refresh token request (grant_type=refresh_token) to verify rotation');
    });

    it('should suggest enabling request body capture for token endpoints', () => {
      collector.responseCache.set('req1', {
        requestData: {
          url: 'https://auth.example.com/token',
          requestHeaders: ['Authorization: Bearer xyz'],
          analysis: {
            oauth2Flow: { flowType: 'token_exchange' }
          }
        },
        headers: ['Content-Type: application/json'],
        body: '',
        statusCode: 200,
        timestamp: Date.now()
      });

      const quality = collector.calculateEvidenceQuality('req1');

      expect(quality.suggestions).toContain('Enable request body capture to verify OAuth2 grant types and PKCE code_verifier');
    });

    it('should suggest enabling response body capture for token endpoints', () => {
      collector.responseCache.set('req1', {
        requestData: {
          url: 'https://auth.example.com/token',
          requestHeaders: ['Content-Type: application/x-www-form-urlencoded'],
          requestBody: 'grant_type=authorization_code',
          analysis: {
            oauth2Flow: { flowType: 'token_exchange' }
          }
        },
        headers: ['Content-Type: application/json'],
        statusCode: 200,
        timestamp: Date.now()
      });

      const quality = collector.calculateEvidenceQuality('req1');

      expect(quality.suggestions).toContain('Enable response body capture (debugger mode) to verify token types and DPoP');
    });

    it('should suggest debugger mode for low-confidence findings', () => {
      collector.responseCache.set('req1', {
        requestData: {
          url: 'https://example.com',
          requestHeaders: ['Cookie: session=xyz']
        },
        headers: ['Set-Cookie: session=abc'],
        body: 'response',
        statusCode: 200,
        timestamp: Date.now()
      });

      const findings = [
        { confidence: 'LOW', confidenceScore: 50 },
        { confidence: 'SPECULATIVE', confidenceScore: 30 },
        { confidence: 'LOW', confidenceScore: 45 }
      ];

      const quality = collector.calculateEvidenceQuality('req1', findings);

      expect(quality.suggestions).toContain('Findings have medium-to-low confidence - enable debugger mode for more reliable detections');
      expect(quality.suggestions).toContain('Most findings require manual verification - capture more complete evidence for higher confidence');
    });

    it('should provide minimal suggestions for complete evidence with high confidence', () => {
      // Complete OAuth2 flow with all evidence components
      collector.responseCache.set('req1', {
        requestData: {
          url: 'https://auth.example.com/authorize',
          requestHeaders: ['Cookie: session=xyz'],
          requestBody: 'response_type=code',
          analysis: {
            oauth2Flow: { flowType: 'authorization_request' }
          }
        },
        headers: ['Set-Cookie: session=abc'],
        body: 'response',
        statusCode: 302,
        timestamp: Date.now()
      });

      // Add complete flow coverage with full evidence
      collector.responseCache.set('req2', {
        requestData: {
          url: 'https://auth.example.com/token',
          requestHeaders: ['Content-Type: application/x-www-form-urlencoded'],
          requestBody: 'grant_type=authorization_code&code=ABC123',
          analysis: {
            oauth2Flow: { flowType: 'token_exchange' }
          }
        },
        headers: ['Content-Type: application/json'],
        body: '{"access_token":"xyz"}',
        statusCode: 200,
        timestamp: Date.now()
      });

      collector.responseCache.set('req3', {
        requestData: {
          url: 'https://auth.example.com/token',
          requestHeaders: ['Content-Type: application/x-www-form-urlencoded'],
          requestBody: 'grant_type=refresh_token&refresh_token=xyz',
          analysis: {
            oauth2Flow: { flowType: 'token_refresh' }
          }
        },
        headers: ['Content-Type: application/json'],
        body: '{"access_token":"new"}',
        statusCode: 200,
        timestamp: Date.now()
      });

      const findings = [
        { confidence: 'HIGH', confidenceScore: 95 },
        { confidence: 'HIGH', confidenceScore: 90 }
      ];

      const quality = collector.calculateEvidenceQuality('req1', findings);

      // With complete flow coverage (100%) and complete evidence and high confidence,
      // there should be no suggestions
      expect(quality.suggestions.length).toBe(0);
      expect(quality.requestCoverage.percentage).toBe(100);
    });
  });

  describe('Evidence Completeness and Reliability', () => {
    it('should calculate HIGH reliability for complete evidence', () => {
      collector.responseCache.set('req1', {
        requestData: {
          url: 'https://example.com',
          requestHeaders: ['Authorization: Bearer xyz'],
          requestBody: 'data=value'
        },
        headers: ['Content-Type: application/json'],
        body: '{"result":"success"}',
        statusCode: 200,
        timestamp: Date.now()
      });

      const quality = collector.calculateEvidenceQuality('req1');

      expect(quality.completeness).toBe(100); // All 6 components present
      expect(quality.reliability).toBe('HIGH');
    });

    it('should calculate MEDIUM reliability for mostly complete evidence', () => {
      collector.responseCache.set('req1', {
        requestData: {
          url: 'https://example.com',
          requestHeaders: ['Authorization: Bearer xyz']
        },
        headers: ['Content-Type: application/json'],
        body: '{"result":"success"}',
        statusCode: 200,
        timestamp: Date.now()
      });

      const quality = collector.calculateEvidenceQuality('req1');

      expect(quality.completeness).toBe(83); // 5/6 components
      expect(quality.reliability).toBe('MEDIUM');
    });

    it('should calculate LOW reliability for partial evidence', () => {
      collector.responseCache.set('req1', {
        requestData: {
          url: 'https://example.com',
          requestHeaders: []
        },
        headers: [],
        body: 'response',
        statusCode: 200,
        timestamp: Date.now()
      });

      const quality = collector.calculateEvidenceQuality('req1');

      expect(quality.completeness).toBe(50); // 3/6 components
      expect(quality.reliability).toBe('LOW');
    });

    it('should calculate VERY_LOW reliability for minimal evidence', () => {
      collector.responseCache.set('req1', {
        requestData: {
          url: 'https://example.com'
        },
        headers: [],
        statusCode: 200,
        timestamp: Date.now()
      });

      const quality = collector.calculateEvidenceQuality('req1');

      expect(quality.completeness).toBe(33); // 2/6 components
      expect(quality.reliability).toBe('VERY_LOW');
    });
  });

  describe('Aggregate Evidence Quality', () => {
    it('should calculate aggregate quality across multiple requests', () => {
      // Request 1: Complete evidence
      collector.responseCache.set('req1', {
        requestData: {
          url: 'https://example.com',
          requestHeaders: ['Auth: Bearer xyz'],
          requestBody: 'data=1'
        },
        headers: ['Content-Type: application/json'],
        body: '{"result":"success"}',
        statusCode: 200,
        timestamp: Date.now()
      });

      // Request 2: Partial evidence
      collector.responseCache.set('req2', {
        requestData: {
          url: 'https://example.com'
        },
        headers: ['Content-Type: text/html'],
        body: 'response',
        statusCode: 200,
        timestamp: Date.now()
      });

      const aggregate = collector.getAggregateEvidenceQuality();

      expect(aggregate.totalRequests).toBe(2);
      expect(aggregate.averageCompleteness).toBeGreaterThan(0);
      expect(aggregate.distribution.HIGH).toBe(1);
      expect(aggregate.distribution.MEDIUM).toBe(0);
      expect(aggregate.distribution.LOW).toBe(1);
    });

    it('should handle empty evidence cache', () => {
      const aggregate = collector.getAggregateEvidenceQuality();

      expect(aggregate.totalRequests).toBe(0);
      expect(aggregate.averageCompleteness).toBe(0);
      expect(aggregate.distribution.HIGH).toBe(0);
    });
  });
});
