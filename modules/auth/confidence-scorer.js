/**
 * Confidence Scorer for Security Findings
 *
 * Provides confidence levels for security findings to help users prioritize
 * investigations and distinguish high-confidence issues from speculative ones.
 *
 * Confidence Levels:
 * - HIGH (90-100): Direct observation, binary checks
 * - MEDIUM (60-89): Requires parsing or analysis
 * - LOW (40-59): Context-dependent, potential false positives
 * - SPECULATIVE (0-39): Requires active testing to confirm
 *
 * @author Hera Security Team
 * @date 2025-11-12
 */

export class ConfidenceScorer {
  /**
   * Calculate confidence level for a security finding
   * @param {Object} issue - Security finding
   * @param {Object} request - Request data
   * @param {Object} response - Response data (optional)
   * @returns {Object} Confidence assessment
   */
  static calculateConfidence(issue, request, response = null) {
    const { type } = issue;

    // HIGH CONFIDENCE: Binary checks (present/absent)
    // These are directly observable and unambiguous
    const binaryChecks = [
      'NO_HSTS',
      'MISSING_HTTPONLY_FLAG',
      'MISSING_SECURE_FLAG',
      'MISSING_SAMESITE',
      'JWT_ALG_NONE',
      'TOKEN_IN_URL',
      'MISSING_X_FRAME_OPTIONS',
      'MISSING_X_CONTENT_TYPE_OPTIONS'
    ];

    if (binaryChecks.includes(type)) {
      return {
        level: 'HIGH',
        score: 95,
        reason: 'Direct observation of security control absence',
        falsePositiveLikelihood: 'VERY_LOW'
      };
    }

    // HIGH CONFIDENCE: Observable with direct evidence
    if (type === 'MISSING_PKCE') {
      const url = new URL(request.url);
      const hasCodeChallenge = url.searchParams.has('code_challenge');

      return {
        level: 'HIGH',
        score: 90,
        reason: 'Direct observation of authorization request parameters',
        evidence: {
          searchedFor: 'code_challenge',
          found: hasCodeChallenge,
          url: request.url
        },
        falsePositiveLikelihood: 'VERY_LOW'
      };
    }

    if (type === 'MISSING_STATE') {
      const url = new URL(request.url);
      const hasState = url.searchParams.has('state');

      return {
        level: 'HIGH',
        score: 92,
        reason: 'Direct observation of OAuth2 authorization parameters',
        evidence: {
          searchedFor: 'state',
          found: hasState
        },
        falsePositiveLikelihood: 'VERY_LOW'
      };
    }

    // MEDIUM CONFIDENCE: Requires parsing or analysis
    const analysisRequired = [
      'WEAK_STATE',
      'WEAK_WEBAUTHN_CHALLENGE',
      'JWT_WEAK_ALGORITHM',
      'SESSION_FIXATION_RISK',
      'WEAK_SESSION_ID',
      'PREDICTABLE_NONCE'
    ];

    if (analysisRequired.includes(type)) {
      return {
        level: 'MEDIUM',
        score: 70,
        reason: 'Based on entropy analysis or pattern matching',
        recommendation: 'Verify finding with manual inspection of actual values',
        falsePositiveLikelihood: 'LOW'
      };
    }

    // LOW-MEDIUM CONFIDENCE: Context-dependent CSRF detection
    if (type === 'MISSING_CSRF_PROTECTION') {
      // Check if this might be an OAuth2 token endpoint
      const potentiallyOAuth2 =
        request.url.includes('/token') ||
        request.url.includes('/oauth') ||
        request.url.includes('/auth/');

      // Check if OAuth2 grant type present in body
      const hasOAuth2Grant = request.body &&
        (request.body.includes('grant_type=') ||
         request.body.includes('code_verifier='));

      if (potentiallyOAuth2 && hasOAuth2Grant) {
        return {
          level: 'LOW',
          score: 30,
          reason: 'Likely OAuth2 token endpoint which does not require CSRF tokens per RFC 6749',
          falsePositiveLikelihood: 'VERY_HIGH',
          recommendation: 'Verify this is not an OAuth2 token endpoint before reporting. OAuth2 token endpoints are protected by authorization codes/PKCE, not CSRF tokens.',
          shouldBeFixed: 'This detection should use CSRFDetector class to exempt OAuth2 token endpoints'
        };
      }

      if (potentiallyOAuth2) {
        return {
          level: 'LOW',
          score: 50,
          reason: 'URL pattern suggests OAuth2 endpoint (may not require CSRF token)',
          falsePositiveLikelihood: 'HIGH',
          recommendation: 'Check if this is an OAuth2 token endpoint. If yes, CSRF protection is not required per RFC 6749.'
        };
      }

      // Regular POST endpoint
      return {
        level: 'MEDIUM',
        score: 75,
        reason: 'POST request without CSRF token or OAuth2 protection',
        falsePositiveLikelihood: 'LOW',
        recommendation: 'Verify CSRF protection is actually missing in production'
      };
    }

    // MEDIUM CONFIDENCE: DPoP/Refresh Token Findings
    if (type === 'MISSING_DPOP') {
      return {
        level: 'MEDIUM',
        score: 60,
        reason: 'DPoP is a SHOULD requirement per RFC 9449, not MUST',
        falsePositiveLikelihood: 'MEDIUM',
        recommendation: 'DPoP is optional but recommended for high-security applications. Not all OAuth2 providers implement it.'
      };
    }

    if (type === 'REFRESH_TOKEN_NOT_ROTATED') {
      // Check if DPoP or other sender-constraint is present
      const hasDPoP = response &&
        (response.token_type === 'DPoP' || response.token_type === 'dpop');

      if (hasDPoP) {
        return {
          level: 'LOW',
          score: 40,
          reason: 'Refresh token not rotated but protected by DPoP (acceptable per RFC 9700 Section 4.13.2)',
          falsePositiveLikelihood: 'HIGH',
          recommendation: 'RFC 9700 allows non-rotation if sender-constrained tokens (DPoP/mTLS) are used'
        };
      }

      return {
        level: 'MEDIUM',
        score: 75,
        reason: 'Refresh token reuse detected without observed compensating controls',
        falsePositiveLikelihood: 'LOW',
        recommendation: 'Verify that no sender-constraint (DPoP/mTLS) is in use'
      };
    }

    // HIGH CONFIDENCE: JWT Algorithm Issues
    if (type === 'JWT_ALG_CONFUSION_RISK') {
      return {
        level: 'HIGH',
        score: 85,
        reason: 'Algorithm mismatch between expected and actual JWT header',
        falsePositiveLikelihood: 'LOW',
        recommendation: 'High-confidence finding. Verify in production and report to bug bounty.'
      };
    }

    // SPECULATIVE: Requires active testing
    const speculativeChecks = [
      'OIDC_AUTHORIZATION_CODE_REUSE',
      'REFRESH_TOKEN_REPLAY',
      'STATE_REPLAY_ATTACK',
      'NONCE_REPLAY_ATTACK',
      'AUTHORIZATION_CODE_REPLAY'
    ];

    if (speculativeChecks.includes(type)) {
      return {
        level: 'SPECULATIVE',
        score: 35,
        reason: 'Passive monitoring cannot confirm this vulnerability. Requires active testing with replay attempts.',
        falsePositiveLikelihood: 'UNKNOWN',
        recommendation: 'Use Hera active testing mode (if available) or manual testing to confirm vulnerability',
        note: 'Many OAuth2 providers correctly prevent replay attacks. Do not report without confirmation.'
      };
    }

    // Default: MEDIUM confidence
    return {
      level: 'MEDIUM',
      score: 65,
      reason: 'Standard detection heuristic',
      falsePositiveLikelihood: 'MEDIUM'
    };
  }

  /**
   * Enhance finding with confidence metadata
   * @param {Object} finding - Original security finding
   * @param {Object} request - Request data
   * @param {Object} response - Response data (optional)
   * @returns {Object} Enhanced finding with confidence metadata
   */
  static enhanceFinding(finding, request, response = null) {
    const confidence = this.calculateConfidence(finding, request, response);

    return {
      ...finding,

      // Add confidence fields
      confidence: confidence.level,
      confidenceScore: confidence.score,
      confidenceReason: confidence.reason,

      // Optional fields
      ...(confidence.falsePositiveLikelihood && {
        falsePositiveLikelihood: confidence.falsePositiveLikelihood
      }),

      ...(confidence.recommendation && {
        confidenceRecommendation: confidence.recommendation
      }),

      ...(confidence.evidence && {
        confidenceEvidence: confidence.evidence
      }),

      ...(confidence.note && {
        confidenceNote: confidence.note
      }),

      ...(confidence.shouldBeFixed && {
        _internalNote: confidence.shouldBeFixed
      })
    };
  }

  /**
   * Calculate overall confidence for a set of findings
   * @param {Array} findings - Array of enhanced findings
   * @returns {Object} Aggregate confidence metrics
   */
  static calculateAggregateConfidence(findings) {
    if (!findings || findings.length === 0) {
      return {
        averageScore: 0,
        distribution: {},
        highConfidenceCount: 0,
        falsePositiveLikelyCount: 0
      };
    }

    const distribution = {
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      SPECULATIVE: 0
    };

    let totalScore = 0;
    let falsePositiveLikelyCount = 0;

    findings.forEach(finding => {
      if (finding.confidence) {
        distribution[finding.confidence] = (distribution[finding.confidence] || 0) + 1;
      }

      if (finding.confidenceScore) {
        totalScore += finding.confidenceScore;
      }

      if (finding.falsePositiveLikelihood === 'HIGH' ||
          finding.falsePositiveLikelihood === 'VERY_HIGH') {
        falsePositiveLikelyCount++;
      }
    });

    return {
      averageScore: Math.round(totalScore / findings.length),
      distribution,
      highConfidenceCount: distribution.HIGH || 0,
      falsePositiveLikelyCount,
      recommendation: this._getAggregateRecommendation(distribution, falsePositiveLikelyCount)
    };
  }

  /**
   * Get recommendation based on aggregate confidence
   * @private
   */
  static _getAggregateRecommendation(distribution, falsePositiveCount) {
    const total = Object.values(distribution).reduce((a, b) => a + b, 0);
    const highConfidenceRatio = (distribution.HIGH || 0) / total;

    if (highConfidenceRatio >= 0.8) {
      return 'High confidence findings - ready for bug bounty submission';
    } else if (highConfidenceRatio >= 0.5) {
      return 'Good mix of findings - prioritize HIGH confidence issues first';
    } else if (falsePositiveCount > total * 0.3) {
      return 'Many findings have high false positive likelihood - manual verification recommended';
    } else {
      return 'Mixed confidence levels - review each finding individually';
    }
  }

  /**
   * Prioritize findings by confidence and severity
   * @param {Array} findings - Array of enhanced findings
   * @returns {Object} Prioritized findings
   */
  static prioritizeFindings(findings) {
    const severityWeight = {
      CRITICAL: 4,
      HIGH: 3,
      MEDIUM: 2,
      LOW: 1,
      INFO: 0
    };

    const confidenceWeight = {
      HIGH: 3,
      MEDIUM: 2,
      LOW: 1,
      SPECULATIVE: 0
    };

    // Calculate priority score for each finding
    const scored = findings.map(finding => {
      const sevWeight = severityWeight[finding.severity] || 0;
      const confWeight = confidenceWeight[finding.confidence] || 0;

      // Priority = (Severity * 2) + Confidence
      const priorityScore = (sevWeight * 2) + confWeight;

      return {
        ...finding,
        priorityScore
      };
    });

    // Sort by priority score (descending)
    scored.sort((a, b) => b.priorityScore - a.priorityScore);

    // Group by priority tier
    return {
      critical: scored.filter(f => f.priorityScore >= 10), // CRITICAL + HIGH confidence
      high: scored.filter(f => f.priorityScore >= 7 && f.priorityScore < 10),
      medium: scored.filter(f => f.priorityScore >= 4 && f.priorityScore < 7),
      low: scored.filter(f => f.priorityScore < 4),
      allFindings: scored
    };
  }
}

// Export for use in hera-auth-detector.js
export default ConfidenceScorer;
