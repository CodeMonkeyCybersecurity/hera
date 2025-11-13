/**
 * RFC 9700 Compliance Checker - Dashboard & Scoring
 *
 * PURPOSE:
 * - Aggregate OAuth 2.1 security findings into a compliance dashboard
 * - Calculate RFC 9700 compliance score (0-100)
 * - Assign compliance grade (A+ to F)
 * - Provide actionable recommendations
 *
 * RFC 9700 KEY REQUIREMENTS:
 * - MUST: State parameter (authorization code flow)
 * - MUST: PKCE for public clients
 * - SHOULD: PKCE for all clients (including confidential)
 * - SHOULD: Refresh token rotation OR sender-constraint (DPoP/mTLS)
 * - MUST NOT: Implicit flow
 * - SHOULD: Resource indicators (RFC 8707)
 *
 * SCORING MODEL:
 * - MUST requirements: 30 points each (critical)
 * - SHOULD requirements: 15 points each (important)
 * - MAY/best practices: 5 points each (nice-to-have)
 * - Compensating controls: Full credit if present
 *
 * @see RFC 9700: OAuth 2.0 Security Best Current Practice
 * @see RFC 9449: OAuth 2.0 Demonstrating Proof-of-Possession (DPoP)
 * @see RFC 8707: Resource Indicators for OAuth 2.0
 * @see ROADMAP.md P1-5: RFC 9700 Compliance
 */

export class RFC9700ComplianceChecker {
  constructor() {
    // Compliance requirements with weights
    this.requirements = {
      // MUST requirements (30 points each)
      STATE_PARAMETER: {
        weight: 30,
        level: 'MUST',
        section: 'RFC 9700 Section 4.1.1',
        description: 'State parameter for CSRF protection'
      },
      PKCE_PUBLIC: {
        weight: 30,
        level: 'MUST',
        section: 'RFC 9700 Section 4.8.1',
        description: 'PKCE for public clients'
      },
      NO_IMPLICIT_FLOW: {
        weight: 30,
        level: 'MUST NOT',
        section: 'RFC 9700 Section 2.1.2',
        description: 'Implicit flow prohibited'
      },

      // SHOULD requirements (15 points each)
      PKCE_CONFIDENTIAL: {
        weight: 15,
        level: 'SHOULD',
        section: 'RFC 9700 Section 4.8.1',
        description: 'PKCE for confidential clients'
      },
      REFRESH_ROTATION: {
        weight: 15,
        level: 'SHOULD',
        section: 'RFC 9700 Section 4.13.2',
        description: 'Refresh token rotation OR sender-constraint'
      },

      // MAY/best practices (5 points each)
      RESOURCE_INDICATORS: {
        weight: 5,
        level: 'SHOULD',
        section: 'RFC 8707',
        description: 'Resource indicators for audience restriction'
      },
      DPOP_SENDER_CONSTRAINT: {
        weight: 5,
        level: 'MAY',
        section: 'RFC 9449',
        description: 'DPoP for sender-constrained tokens'
      }
    };

    // Maximum possible score
    this.maxScore = Object.values(this.requirements).reduce((sum, req) => sum + req.weight, 0);
  }

  /**
   * Calculate RFC 9700 compliance for a domain
   *
   * @param {Array<Object>} findings - All security findings for the domain
   * @param {Object} evidence - Evidence from auth requests/responses
   * @returns {Object} Compliance report with score, grade, and recommendations
   */
  checkCompliance(findings, evidence = {}) {
    const compliance = {
      domain: evidence.domain || 'unknown',
      timestamp: new Date().toISOString(),
      score: 0,
      maxScore: this.maxScore,
      percentage: 0,
      grade: 'F',
      requirements: {},
      violations: [],
      recommendations: [],
      compensatingControls: []
    };

    // Check each requirement
    compliance.requirements.STATE_PARAMETER = this._checkStateParameter(findings, evidence);
    compliance.requirements.PKCE_PUBLIC = this._checkPKCEPublic(findings, evidence);
    compliance.requirements.PKCE_CONFIDENTIAL = this._checkPKCEConfidential(findings, evidence);
    compliance.requirements.NO_IMPLICIT_FLOW = this._checkNoImplicitFlow(findings, evidence);
    compliance.requirements.REFRESH_ROTATION = this._checkRefreshRotation(findings, evidence);
    compliance.requirements.RESOURCE_INDICATORS = this._checkResourceIndicators(findings, evidence);
    compliance.requirements.DPOP_SENDER_CONSTRAINT = this._checkDPoPSenderConstraint(findings, evidence);

    // Calculate score
    for (const [reqName, reqResult] of Object.entries(compliance.requirements)) {
      if (reqResult.compliant) {
        compliance.score += this.requirements[reqName].weight;
      } else if (reqResult.partial) {
        // Partial credit for compensating controls
        compliance.score += Math.floor(this.requirements[reqName].weight * 0.7);
        compliance.compensatingControls.push({
          requirement: reqName,
          control: reqResult.compensatingControl,
          credit: 0.7
        });
      }

      if (!reqResult.compliant && !reqResult.partial) {
        compliance.violations.push({
          requirement: reqName,
          severity: this.requirements[reqName].level,
          description: this.requirements[reqName].description,
          section: this.requirements[reqName].section,
          recommendation: reqResult.recommendation
        });
      }
    }

    // Calculate percentage and grade
    compliance.percentage = Math.round((compliance.score / compliance.maxScore) * 100);
    compliance.grade = this._calculateGrade(compliance.percentage);

    // Generate recommendations
    compliance.recommendations = this._generateRecommendations(compliance);

    return compliance;
  }

  /**
   * Check STATE_PARAMETER requirement (MUST)
   * RFC 9700 Section 4.1.1: Authorization servers MUST use the state parameter
   */
  _checkStateParameter(findings, evidence) {
    const result = {
      compliant: false,
      checked: true,
      evidence: []
    };

    // Look for missing state findings
    const missingState = findings.find(f => f.type === 'MISSING_STATE_PARAMETER');
    if (missingState) {
      result.compliant = false;
      result.evidence.push('State parameter missing in authorization request');
      result.recommendation = 'Implement state parameter for CSRF protection per RFC 9700 Section 4.1.1';
      return result;
    }

    // Look for weak state findings
    const weakState = findings.find(f => f.type === 'WEAK_STATE_PARAMETER');
    if (weakState) {
      result.compliant = false;
      result.evidence.push(`State parameter weak: ${weakState.evidence?.weakness || 'insufficient entropy'}`);
      result.recommendation = 'Use cryptographically random state values (>=128 bits entropy)';
      return result;
    }

    // Check if state parameter exists in evidence
    if (evidence.authorizationRequest) {
      const url = new URL(evidence.authorizationRequest.url);
      const hasState = url.searchParams.has('state');
      if (hasState) {
        result.compliant = true;
        result.evidence.push('State parameter present in authorization request');
        return result;
      }
    }

    // Default: insufficient evidence
    result.compliant = false;
    result.checked = false;
    result.evidence.push('Insufficient evidence to determine state parameter usage');
    return result;
  }

  /**
   * Check PKCE_PUBLIC requirement (MUST)
   * RFC 9700 Section 4.8.1: Public clients MUST use PKCE
   */
  _checkPKCEPublic(findings, evidence) {
    const result = {
      compliant: false,
      checked: true,
      evidence: []
    };

    // Determine client type
    const clientType = this._inferClientType(findings, evidence);
    if (clientType !== 'public') {
      result.compliant = true;
      result.checked = false;
      result.evidence.push(`Not applicable (client type: ${clientType})`);
      return result;
    }

    // Look for missing PKCE on public client
    const missingPKCE = findings.find(f =>
      f.type === 'MISSING_PKCE' &&
      (f.evidence?.clientType === 'public' || f.severity === 'HIGH')
    );

    if (missingPKCE) {
      result.compliant = false;
      result.evidence.push('PKCE missing on public client (MUST requirement)');
      result.recommendation = 'Implement PKCE immediately - REQUIRED for public clients per RFC 9700 Section 4.8.1';
      return result;
    }

    // Check if PKCE exists in evidence
    if (evidence.authorizationRequest) {
      const url = new URL(evidence.authorizationRequest.url);
      const hasPKCE = url.searchParams.has('code_challenge');
      if (hasPKCE) {
        result.compliant = true;
        result.evidence.push('PKCE present (code_challenge parameter found)');
        return result;
      }
    }

    // Default: compliant if no negative findings
    result.compliant = true;
    result.evidence.push('No PKCE violations detected for public client');
    return result;
  }

  /**
   * Check PKCE_CONFIDENTIAL requirement (SHOULD)
   * RFC 9700 Section 4.8.1: PKCE SHOULD be used for all clients
   */
  _checkPKCEConfidential(findings, evidence) {
    const result = {
      compliant: false,
      checked: true,
      evidence: []
    };

    // Determine client type
    const clientType = this._inferClientType(findings, evidence);
    if (clientType !== 'confidential') {
      result.compliant = true;
      result.checked = false;
      result.evidence.push(`Not applicable (client type: ${clientType})`);
      return result;
    }

    // Look for missing PKCE on confidential client
    const missingPKCE = findings.find(f =>
      f.type === 'MISSING_PKCE_CONFIDENTIAL' ||
      (f.type === 'MISSING_PKCE' && f.severity === 'MEDIUM')
    );

    if (missingPKCE) {
      // Check for compensating control (client_secret)
      if (missingPKCE.evidence?.hasCompensatingControl === 'client_secret') {
        result.compliant = false;
        result.partial = true;
        result.compensatingControl = 'client_secret';
        result.evidence.push('PKCE not implemented, but client_secret provides some protection');
        result.recommendation = 'Consider implementing PKCE for defense-in-depth per RFC 9700 Section 4.8.1';
        return result;
      }

      result.compliant = false;
      result.evidence.push('PKCE not implemented on confidential client (SHOULD requirement)');
      result.recommendation = 'Implement PKCE for confidential clients per RFC 9700 Section 4.8.1';
      return result;
    }

    // Check if PKCE exists in evidence
    if (evidence.authorizationRequest) {
      const url = new URL(evidence.authorizationRequest.url);
      const hasPKCE = url.searchParams.has('code_challenge');
      if (hasPKCE) {
        result.compliant = true;
        result.evidence.push('PKCE present (code_challenge parameter found)');
        return result;
      }
    }

    // Default: compliant if no negative findings
    result.compliant = true;
    result.evidence.push('No PKCE violations detected for confidential client');
    return result;
  }

  /**
   * Check NO_IMPLICIT_FLOW requirement (MUST NOT)
   * RFC 9700 Section 2.1.2: Implicit flow is prohibited
   */
  _checkNoImplicitFlow(findings, evidence) {
    const result = {
      compliant: true,
      checked: true,
      evidence: []
    };

    // Look for implicit flow findings
    const implicitFlow = findings.find(f =>
      f.type === 'IMPLICIT_FLOW_DETECTED' ||
      f.type === 'IMPLICIT_GRANT_USED'
    );

    if (implicitFlow) {
      result.compliant = false;
      result.evidence.push('Implicit flow detected (response_type=token)');
      result.recommendation = 'Remove implicit flow and use authorization code flow with PKCE per RFC 9700 Section 2.1.2';
      return result;
    }

    // Check evidence for response_type=token
    if (evidence.authorizationRequest) {
      const url = new URL(evidence.authorizationRequest.url);
      const responseType = url.searchParams.get('response_type');
      if (responseType && (responseType.includes('token') && !responseType.includes('code'))) {
        result.compliant = false;
        result.evidence.push(`Implicit flow detected (response_type=${responseType})`);
        result.recommendation = 'Remove implicit flow and use authorization code flow per RFC 9700 Section 2.1.2';
        return result;
      }
    }

    result.compliant = true;
    result.evidence.push('No implicit flow detected');
    return result;
  }

  /**
   * Check REFRESH_ROTATION requirement (SHOULD)
   * RFC 9700 Section 4.13.2: Refresh tokens SHOULD rotate OR use sender-constraint
   */
  _checkRefreshRotation(findings, _evidence) {
    const result = {
      compliant: true,
      checked: true,
      evidence: []
    };

    // Look for refresh token not rotated findings
    const notRotated = findings.find(f => f.type === 'REFRESH_TOKEN_NOT_ROTATED');
    if (notRotated) {
      result.compliant = false;
      result.evidence.push(`Refresh token reused ${notRotated.evidence?.useCount || 2} times without rotation`);
      result.recommendation = 'Implement refresh token rotation OR use DPoP/mTLS per RFC 9700 Section 4.13.2';
      return result;
    }

    // Look for protected but not rotated (has DPoP/mTLS compensating control)
    const protectedButNotRotated = findings.find(f => f.type === 'REFRESH_TOKEN_NOT_ROTATED_BUT_PROTECTED');
    if (protectedButNotRotated) {
      result.compliant = true;
      result.partial = true;
      result.compensatingControl = protectedButNotRotated.evidence?.protection || 'DPoP';
      result.evidence.push(`Refresh token not rotated, but protected by ${result.compensatingControl}`);
      result.recommendation = 'RFC 9700 compliant: sender-constraint (DPoP/mTLS) compensates for non-rotation';
      return result;
    }

    result.compliant = true;
    result.evidence.push('No refresh token rotation violations detected');
    return result;
  }

  /**
   * Check RESOURCE_INDICATORS requirement (SHOULD)
   * RFC 8707: Resource indicators for audience restriction
   */
  _checkResourceIndicators(findings, evidence) {
    const result = {
      compliant: false,
      checked: true,
      evidence: []
    };

    // Look for missing resource indicator findings
    const missingResource = findings.find(f => f.type === 'MISSING_RESOURCE_INDICATOR');
    if (missingResource) {
      result.compliant = false;
      result.evidence.push('Token request without resource/audience parameter');
      result.recommendation = 'Use resource parameter per RFC 8707 for audience restriction';
      return result;
    }

    // Check if resource/audience exists in token request
    if (evidence.tokenRequest) {
      const body = evidence.tokenRequest.body || '';
      const hasResource = body.includes('resource=') || body.includes('audience=');
      if (hasResource) {
        result.compliant = true;
        result.evidence.push('Resource/audience parameter present in token request');
        return result;
      } else {
        result.compliant = false;
        result.evidence.push('No resource/audience parameter in token request');
        result.recommendation = 'Consider using resource parameter per RFC 8707';
        return result;
      }
    }

    // Default: insufficient evidence
    result.compliant = false;
    result.checked = false;
    result.evidence.push('Insufficient evidence to determine resource indicator usage');
    return result;
  }

  /**
   * Check DPOP_SENDER_CONSTRAINT requirement (MAY)
   * RFC 9449: DPoP for sender-constrained tokens
   */
  _checkDPoPSenderConstraint(findings, evidence) {
    const result = {
      compliant: false,
      checked: true,
      evidence: []
    };

    // Look for DPoP not implemented findings (INFO severity - optional)
    const noDPoP = findings.find(f => f.type === 'DPOP_NOT_IMPLEMENTED');
    if (noDPoP) {
      result.compliant = false;
      result.evidence.push('DPoP not implemented (optional enhancement)');
      result.recommendation = 'Consider implementing DPoP per RFC 9449 for enhanced security';
      return result;
    }

    // Check if DPoP is implemented
    if (evidence.tokenResponse) {
      const tokenType = evidence.tokenResponse.token_type?.toLowerCase();
      if (tokenType === 'dpop') {
        result.compliant = true;
        result.evidence.push('DPoP implemented (token_type=DPoP)');
        return result;
      }
    }

    // Check for DPoP header in request
    if (evidence.tokenRequest) {
      const hasDPoPHeader = evidence.tokenRequest.headers?.some(h => h.name.toLowerCase() === 'dpop');
      if (hasDPoPHeader) {
        result.compliant = true;
        result.evidence.push('DPoP header present in request');
        return result;
      }
    }

    // Default: not implemented (but optional)
    result.compliant = false;
    result.evidence.push('DPoP not detected (optional per RFC 9449)');
    return result;
  }

  /**
   * Calculate compliance grade based on percentage
   *
   * @param {number} percentage - Compliance percentage (0-100)
   * @returns {string} Grade (A+, A, B, C, D, F)
   */
  _calculateGrade(percentage) {
    if (percentage >= 95) {return 'A+';}
    if (percentage >= 90) {return 'A';}
    if (percentage >= 85) {return 'A-';}
    if (percentage >= 80) {return 'B+';}
    if (percentage >= 75) {return 'B';}
    if (percentage >= 70) {return 'B-';}
    if (percentage >= 65) {return 'C+';}
    if (percentage >= 60) {return 'C';}
    if (percentage >= 55) {return 'C-';}
    if (percentage >= 50) {return 'D';}
    return 'F';
  }

  /**
   * Generate prioritized recommendations
   *
   * @param {Object} compliance - Compliance report
   * @returns {Array<Object>} Prioritized recommendations
   */
  _generateRecommendations(compliance) {
    const recommendations = [];

    // Priority 1: MUST violations (critical)
    const mustViolations = compliance.violations.filter(v => v.severity === 'MUST' || v.severity === 'MUST NOT');
    for (const violation of mustViolations) {
      recommendations.push({
        priority: 'CRITICAL',
        requirement: violation.requirement,
        action: violation.recommendation,
        impact: 'RFC 9700 MUST requirement violation',
        effort: this._estimateEffort(violation.requirement)
      });
    }

    // Priority 2: SHOULD violations (important)
    const shouldViolations = compliance.violations.filter(v => v.severity === 'SHOULD');
    for (const violation of shouldViolations) {
      recommendations.push({
        priority: 'HIGH',
        requirement: violation.requirement,
        action: violation.recommendation,
        impact: 'RFC 9700 SHOULD requirement violation',
        effort: this._estimateEffort(violation.requirement)
      });
    }

    // Priority 3: MAY/best practices (nice-to-have)
    const mayViolations = compliance.violations.filter(v => v.severity === 'MAY');
    for (const violation of mayViolations) {
      recommendations.push({
        priority: 'MEDIUM',
        requirement: violation.requirement,
        action: violation.recommendation,
        impact: 'Optional security enhancement',
        effort: this._estimateEffort(violation.requirement)
      });
    }

    return recommendations;
  }

  /**
   * Estimate implementation effort
   *
   * @param {string} requirement - Requirement name
   * @returns {string} Effort estimate
   */
  _estimateEffort(requirement) {
    const efforts = {
      STATE_PARAMETER: '1-2 hours (add state parameter generation/validation)',
      PKCE_PUBLIC: '2-4 hours (implement PKCE flow)',
      PKCE_CONFIDENTIAL: '2-4 hours (implement PKCE flow)',
      NO_IMPLICIT_FLOW: '4-8 hours (migrate to authorization code flow)',
      REFRESH_ROTATION: '4-6 hours (implement token rotation logic)',
      RESOURCE_INDICATORS: '1-2 hours (add resource parameter)',
      DPOP_SENDER_CONSTRAINT: '8-16 hours (full DPoP implementation)'
    };

    return efforts[requirement] || 'Unknown';
  }

  /**
   * Infer client type from findings and evidence
   *
   * @param {Array<Object>} findings - Security findings
   * @param {Object} evidence - Request/response evidence
   * @returns {string} Client type ('public', 'confidential', 'unknown')
   */
  _inferClientType(findings, evidence) {
    // Check findings for explicit client type
    for (const finding of findings) {
      if (finding.evidence?.clientType) {
        return finding.evidence.clientType;
      }
    }

    // Check evidence for client_secret
    if (evidence.tokenRequest) {
      const body = evidence.tokenRequest.body || '';
      if (body.includes('client_secret=')) {
        return 'confidential';
      }
    }

    // Check for PKCE (typically indicates public client)
    if (evidence.authorizationRequest) {
      const url = new URL(evidence.authorizationRequest.url);
      const hasPKCE = url.searchParams.has('code_challenge');
      if (hasPKCE && !evidence.tokenRequest?.body?.includes('client_secret=')) {
        return 'public';
      }
    }

    return 'unknown';
  }

  /**
   * Generate compliance report summary (for UI display)
   *
   * @param {Object} compliance - Compliance report
   * @returns {string} Human-readable summary
   */
  generateSummary(compliance) {
    const lines = [];
    lines.push(`RFC 9700 Compliance Report`);
    lines.push(`Domain: ${compliance.domain}`);
    lines.push(`Score: ${compliance.score}/${compliance.maxScore} (${compliance.percentage}%)`);
    lines.push(`Grade: ${compliance.grade}`);
    lines.push('');

    if (compliance.violations.length > 0) {
      lines.push(`Violations (${compliance.violations.length}):`);
      for (const violation of compliance.violations) {
        lines.push(`  • [${violation.severity}] ${violation.description}`);
        lines.push(`    → ${violation.recommendation}`);
      }
      lines.push('');
    }

    if (compliance.compensatingControls.length > 0) {
      lines.push(`Compensating Controls (${compliance.compensatingControls.length}):`);
      for (const control of compliance.compensatingControls) {
        lines.push(`  • ${control.requirement}: ${control.control} (${Math.round(control.credit * 100)}% credit)`);
      }
      lines.push('');
    }

    if (compliance.recommendations.length > 0) {
      lines.push(`Recommendations (${compliance.recommendations.length}):`);
      for (const rec of compliance.recommendations) {
        lines.push(`  ${rec.priority === 'CRITICAL' ? '🔴' : rec.priority === 'HIGH' ? '🟠' : '🟡'} ${rec.requirement}`);
        lines.push(`    Action: ${rec.action}`);
        lines.push(`    Effort: ${rec.effort}`);
      }
    }

    return lines.join('\n');
  }
}
