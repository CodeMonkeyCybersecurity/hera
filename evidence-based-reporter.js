// /**
//  * Evidence-Based Vulnerability Reporter for Hera
//  *
//  * This module generates professional-grade vulnerability reports suitable for
//  * bug bounty submissions, based on concrete evidence rather than assumptions.
//  */

// class EvidenceBasedReporter {
//   constructor(evidenceCollector, oauth2Verifier, hstsVerifier) {
//     this.evidenceCollector = evidenceCollector;
//     this.oauth2Verifier = oauth2Verifier;
//     this.hstsVerifier = hstsVerifier;
//     this.reportCache = new Map();
//   }

//   /**
//    * Generate a comprehensive vulnerability report
//    * @param {Object} finding - Vulnerability finding
//    * @param {Object} evidence - Complete evidence package
//    * @param {Object} proofOfConcept - Proof of concept data
//    * @returns {Object} Professional vulnerability report
//    */
//   generateVulnerabilityReport(finding, evidence, proofOfConcept = null) {
//     const reportId = this.generateReportId();
//     const timestamp = Date.now();

//     const report = {
//       // Report metadata
//       metadata: {
//         id: reportId,
//         generated: new Date(timestamp).toISOString(),
//         tool: "Hera Security Extension",
//         version: "2.0-Evidence-Based",
//         purpose: "Bug Bounty Vulnerability Report"
//       },

//       // Finding details
//       finding: {
//         id: finding.id || this.generateFindingId(),
//         title: this.generateTitle(finding, evidence),
//         type: finding.type,
//         severity: this.calculateEvidenceBasedSeverity(evidence),
//         confidence: this.calculateConfidence(evidence),
//         status: evidence.verified ? "CONFIRMED" : "SUSPECTED",
//         cvss_score: this.calculateCVSS(finding, evidence)
//       },

//       // Target information
//       target: {
//         url: evidence.originalRequest || evidence.targetUrl,
//         domain: this.extractDomain(evidence.originalRequest || evidence.targetUrl),
//         protocol: this.extractProtocol(evidence.originalRequest || evidence.targetUrl),
//         tested_at: new Date(timestamp).toISOString()
//       },

//       // Executive summary
//       summary: this.generateExecutiveSummary(finding, evidence),

//       // Technical details
//       technical_details: {
//         vulnerability_description: this.getVulnerabilityDescription(finding.type),
//         affected_component: this.identifyAffectedComponent(evidence),
//         attack_vector: this.identifyAttackVector(finding.type),
//         impact_analysis: this.analyzeImpact(finding, evidence)
//       },

//       // Evidence package
//       evidence: {
//         captured: {
//           requests: this.extractRequestEvidence(evidence),
//           responses: this.extractResponseEvidence(evidence),
//           headers: this.extractHeaderEvidence(evidence),
//           timestamps: this.extractTimeline(evidence)
//         },

//         verification: {
//           tests: this.extractTestResults(evidence),
//           results: this.extractVerificationResults(evidence),
//           methodology: this.getTestMethodology(finding.type)
//         },

//         proof_of_vulnerability: this.generateProofOfVulnerability(finding, evidence)
//       },

//       // Proof of concept
//       proof_of_concept: proofOfConcept ? {
//         type: proofOfConcept.type,
//         description: proofOfConcept.description,
//         steps: proofOfConcept.reproduction || proofOfConcept.steps,
//         impact: proofOfConcept.impact,
//         exploit_code: proofOfConcept.exploitCode || proofOfConcept.exploit,
//         demonstration: proofOfConcept.demonstration
//       } : null,

//       // Reproduction steps
//       reproduction: {
//         prerequisites: this.getPrerequisites(finding.type),
//         steps: this.getDetailedReproductionSteps(finding, evidence),
//         expected_result: this.getExpectedResult(finding.type),
//         actual_result: this.getActualResult(evidence)
//       },

//       // Risk assessment
//       risk_assessment: {
//         likelihood: this.assessLikelihood(finding, evidence),
//         impact: this.assessImpact(finding, evidence),
//         risk_score: this.calculateRiskScore(finding, evidence),
//         business_impact: this.assessBusinessImpact(finding.type)
//       },

//       // Recommendations
//       recommendations: {
//         immediate: this.getImmediateActions(finding),
//         short_term: this.getShortTermActions(finding),
//         long_term: this.getLongTermActions(finding),
//         best_practices: this.getBestPractices(finding.type)
//       },

//       // References
//       references: {
//         standards: this.getSecurityStandards(finding.type),
//         documentation: this.getSecurityReferences(finding.type),
//         tools: this.getVerificationTools(finding.type)
//       },

//       // Quality assurance
//       quality_assurance: {
//         verified_by: "Hera Evidence-Based Testing Engine",
//         confidence_level: this.calculateConfidence(evidence),
//         false_positive_likelihood: this.assessFalsePositiveLikelihood(evidence),
//         verification_method: this.getVerificationMethod(finding.type)
//       }
//     };

//     // Cache the report
//     this.reportCache.set(reportId, report);

//     return report;
//   }

//   /**
//    * Generate bug bounty submission format
//    * @param {Object} report - Vulnerability report
//    * @returns {Object} Bug bounty formatted report
//    */
//   generateBugBountySubmission(report) {
//     return {
//       title: report.finding.title,
//       severity: report.finding.severity,
//       weakness: this.mapToOWASPCategory(report.finding.type),

//       summary: report.summary,

//       description: this.formatDescription(report),

//       steps_to_reproduce: report.reproduction.steps,

//       impact: report.technical_details.impact_analysis,

//       supporting_material: {
//         evidence_package: report.evidence,
//         proof_of_concept: report.proof_of_concept,
//         verification_results: report.evidence.verification
//       },

//       suggested_fix: report.recommendations.immediate,

//       // Additional fields for specific platforms
//       hackerone_fields: this.generateHackerOneFields(report),
//       bugcrowd_fields: this.generateBugcrowdFields(report),
//       intigriti_fields: this.generateIntigritiFields(report)
//     };
//   }

//   // Report generation helper methods

//   generateTitle(finding, evidence) {
//     const titles = {
//       'missingState': 'OAuth2 CSRF Vulnerability - Missing State Parameter Protection',
//       'csrf_no_state': 'OAuth2 CSRF Vulnerability - Missing State Parameter Protection',
//       'state_replay': 'OAuth2 CSRF Vulnerability - State Parameter Replay Attack',
//       'NO_HSTS': 'Missing HSTS Protection Allows Downgrade Attacks',
//       'HSTS_MISSING': 'Missing HSTS Protection Allows Downgrade Attacks',
//       'CREDENTIALS_IN_URL': 'Sensitive Credentials Exposed in URL Parameters'
//     };

//     const baseTitle = titles[finding.type] || `Authentication Security Vulnerability: ${finding.type}`;
//     const domain = this.extractDomain(evidence.originalRequest || evidence.targetUrl);

//     return `${baseTitle} in ${domain}`;
//   }

//   calculateEvidenceBasedSeverity(evidence) {
//     // Start with base severity from evidence
//     let severity = 'LOW';

//     // Check for high-impact vulnerabilities
//     if (evidence.testResults) {
//       const highSeverity = evidence.testResults.filter(test =>
//         test.result === 'VULNERABLE' && test.severity === 'HIGH'
//       );

//       if (highSeverity.length > 0) {
//         severity = 'HIGH';
//       } else {
//         const mediumSeverity = evidence.testResults.filter(test =>
//           test.result === 'VULNERABLE' && test.severity === 'MEDIUM'
//         );

//         if (mediumSeverity.length > 0) {
//           severity = 'MEDIUM';
//         }
//       }
//     }

//     // Check vulnerability types from evidence
//     if (evidence.vulnerabilities) {
//       const highVulns = evidence.vulnerabilities.filter(v => v.severity === 'HIGH');
//       if (highVulns.length > 0) {
//         severity = 'HIGH';
//       }
//     }

//     return severity;
//   }

//   calculateConfidence(evidence) {
//     let confidence = 50; // Base confidence

//     // Increase confidence for evidence-based verification
//     if (evidence.verified) confidence += 30;
//     if (evidence.testResults && evidence.testResults.length > 0) confidence += 20;
//     if (evidence.proof_of_vulnerability) confidence += 20;
//     if (evidence.evidence && evidence.evidence.captured) confidence += 10;

//     // Decrease confidence for errors or incomplete tests
//     if (evidence.error) confidence -= 20;
//     if (evidence.testResults && evidence.testResults.some(t => t.result === 'ERROR')) confidence -= 10;

//     return Math.min(100, Math.max(0, confidence));
//   }

//   generateExecutiveSummary(finding, evidence) {
//     const summaries = {
//       'missingState': this.generateOAuth2CSRFSummary(evidence),
//       'csrf_no_state': this.generateOAuth2CSRFSummary(evidence),
//       'NO_HSTS': this.generateHSTSSummary(evidence),
//       'HSTS_MISSING': this.generateHSTSSummary(evidence)
//     };

//     return summaries[finding.type] || this.generateGenericSummary(finding, evidence);
//   }

//   generateOAuth2CSRFSummary(evidence) {
//     return `The OAuth2 authorization endpoint fails to properly implement CSRF protection through state parameter validation. This vulnerability allows attackers to forge authorization requests, potentially leading to account takeover. Evidence-based testing confirmed that the endpoint accepts authorization requests without state parameters or with reusable state values, demonstrating a clear security flaw that violates OAuth2 security best practices.`;
//   }

//   generateHSTSSummary(evidence) {
//     return `The application lacks proper HTTP Strict Transport Security (HSTS) implementation, making it vulnerable to downgrade attacks. Evidence-based testing confirmed that the application is accessible over HTTP without proper redirects, and HTTPS responses do not include HSTS headers. This allows attackers to intercept sensitive communications by forcing connections to use unencrypted HTTP.`;
//   }

//   generateGenericSummary(finding, evidence) {
//     return `A security vulnerability has been identified and verified through evidence-based testing. The vulnerability poses a risk to application security and user data protection. Detailed evidence and reproduction steps are provided to demonstrate the security impact.`;
//   }

//   getVulnerabilityDescription(type) {
//     const descriptions = {
//       'missingState': `Cross-Site Request Forgery (CSRF) vulnerability in OAuth2 authorization flow. The authorization endpoint fails to validate the 'state' parameter, which is required for CSRF protection according to RFC 6749. This allows attackers to trick users into authorizing malicious applications.`,

//       'csrf_no_state': `Cross-Site Request Forgery (CSRF) vulnerability in OAuth2 authorization flow. The authorization endpoint fails to validate the 'state' parameter, which is required for CSRF protection according to RFC 6749. This allows attackers to trick users into authorizing malicious applications.`,

//       'state_replay': `OAuth2 state parameter replay vulnerability. The application accepts reused state parameters, defeating the CSRF protection mechanism. Attackers can capture and reuse state values to bypass security controls.`,

//       'NO_HSTS': `Missing HTTP Strict Transport Security (HSTS) protection. The application fails to implement HSTS headers, allowing attackers to perform downgrade attacks and intercept communications over unencrypted connections.`,

//       'HSTS_MISSING': `Missing HTTP Strict Transport Security (HSTS) protection. The application fails to implement HSTS headers, allowing attackers to perform downgrade attacks and intercept communications over unencrypted connections.`
//     };

//     return descriptions[type] || `Security vulnerability of type: ${type}`;
//   }

//   getDetailedReproductionSteps(finding, evidence) {
//     if (finding.type === 'missingState' || finding.type === 'csrf_no_state') {
//       return [
//         "1. Identify the OAuth2 authorization endpoint",
//         "2. Craft a malicious authorization URL without the state parameter",
//         "3. Host the malicious URL on an attacker-controlled domain",
//         "4. Social engineer the victim to visit the malicious URL",
//         "5. Observe that the authorization succeeds without CSRF protection",
//         "6. Capture the authorization code sent to the attacker's callback URL",
//         "7. Exchange the authorization code for access tokens",
//         "8. Demonstrate unauthorized access to the victim's account"
//       ];
//     }

//     if (finding.type === 'NO_HSTS' || finding.type === 'HSTS_MISSING') {
//       return [
//         "1. Access the application over HTTPS and verify no HSTS header is present",
//         "2. Attempt to access the application over HTTP",
//         "3. Confirm that HTTP connections are accepted without redirect",
//         "4. Demonstrate interception of sensitive data over HTTP",
//         "5. Show that browsers do not automatically upgrade to HTTPS"
//       ];
//     }

//     return ["Detailed reproduction steps provided in evidence package"];
//   }

//   extractRequestEvidence(evidence) {
//     if (evidence.originalRequest) {
//       return [{
//         url: evidence.originalRequest,
//         method: 'GET',
//         timestamp: evidence.timestamp
//       }];
//     }

//     if (evidence.evidence && evidence.evidence.captured && evidence.evidence.captured.requests) {
//       return evidence.evidence.captured.requests;
//     }

//     return [];
//   }

//   extractResponseEvidence(evidence) {
//     if (evidence.tests && evidence.tests.httpsHeaderCheck) {
//       return [{
//         status: evidence.tests.httpsHeaderCheck.status,
//         headers: evidence.tests.httpsHeaderCheck.evidence,
//         timestamp: evidence.timestamp
//       }];
//     }

//     if (evidence.evidence && evidence.evidence.captured && evidence.evidence.captured.responses) {
//       return evidence.evidence.captured.responses;
//     }

//     return [];
//   }

//   extractTestResults(evidence) {
//     if (evidence.testResults) {
//       return evidence.testResults;
//     }

//     if (evidence.tests) {
//       return evidence.tests;
//     }

//     return [];
//   }

//   generateProofOfVulnerability(finding, evidence) {
//     if (finding.type === 'missingState' || finding.type === 'csrf_no_state') {
//       return {
//         vulnerability_confirmed: true,
//         test_performed: "OAuth2 authorization without state parameter",
//         result: "Authorization succeeded without CSRF protection",
//         evidence_url: evidence.originalRequest,
//         state_parameter_present: !!this.extractStateFromUrl(evidence.originalRequest),
//         csrf_protection_bypassed: true
//       };
//     }

//     if (finding.type === 'NO_HSTS' || finding.type === 'HSTS_MISSING') {
//       return {
//         vulnerability_confirmed: true,
//         hsts_header_missing: true,
//         http_accessible: evidence.tests?.httpDowngradeTest?.httpAccessible || false,
//         https_redirect_missing: !evidence.tests?.httpDowngradeTest?.redirectsToHttps || false,
//         downgrade_attack_possible: true
//       };
//     }

//     return {
//       vulnerability_confirmed: evidence.verified || false,
//       test_completed: true,
//       evidence_collected: !!evidence.evidence
//     };
//   }

//   // Utility methods

//   extractDomain(url) {
//     try {
//       return new URL(url).hostname;
//     } catch {
//       return 'unknown';
//     }
//   }

//   extractProtocol(url) {
//     try {
//       return new URL(url).protocol;
//     } catch {
//       return 'unknown';
//     }
//   }

//   extractStateFromUrl(url) {
//     try {
//       return new URL(url).searchParams.get('state');
//     } catch {
//       return null;
//     }
//   }

//   calculateCVSS(finding, evidence) {
//     // Simplified CVSS calculation
//     const baseScores = {
//       'HIGH': 7.5,
//       'MEDIUM': 5.0,
//       'LOW': 2.5
//     };

//     const severity = this.calculateEvidenceBasedSeverity(evidence);
//     return baseScores[severity] || 0.0;
//   }

//   mapToOWASPCategory(findingType) {
//     const mapping = {
//       'missingState': 'A01:2021 – Broken Access Control',
//       'csrf_no_state': 'A01:2021 – Broken Access Control',
//       'state_replay': 'A01:2021 – Broken Access Control',
//       'NO_HSTS': 'A02:2021 – Cryptographic Failures',
//       'HSTS_MISSING': 'A02:2021 – Cryptographic Failures'
//     };

//     return mapping[findingType] || 'A06:2021 – Vulnerable and Outdated Components';
//   }

//   generateReportId() {
//     return `hera_report_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
//   }

//   generateFindingId() {
//     return `finding_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
//   }

//   // Platform-specific formatting

//   generateHackerOneFields(report) {
//     return {
//       weakness: this.mapToOWASPCategory(report.finding.type),
//       severity: report.finding.severity.toLowerCase(),
//       asset: report.target.domain
//     };
//   }

//   generateBugcrowdFields(report) {
//     return {
//       category: this.mapToBugcrowdCategory(report.finding.type),
//       priority: this.mapToBugcrowdPriority(report.finding.severity)
//     };
//   }

//   generateIntigritiFields(report) {
//     return {
//       impact: report.finding.severity,
//       category: this.mapToIntigritiCategory(report.finding.type)
//     };
//   }

//   // Additional helper methods for completeness

//   getPrerequisites(type) {
//     return ["Valid target application with authentication flow", "Network access to target", "Browser for testing"];
//   }

//   getExpectedResult(type) {
//     if (type.includes('State') || type.includes('csrf')) {
//       return "Authorization request should be rejected without proper state parameter";
//     }
//     if (type.includes('HSTS')) {
//       return "HTTP requests should be redirected to HTTPS with HSTS header";
//     }
//     return "Security controls should prevent the vulnerability";
//   }

//   getActualResult(evidence) {
//     return "Security controls failed, vulnerability confirmed through evidence-based testing";
//   }

//   assessLikelihood(finding, evidence) {
//     return evidence.verified ? "HIGH" : "MEDIUM";
//   }

//   assessImpact(finding, evidence) {
//     const severity = this.calculateEvidenceBasedSeverity(evidence);
//     return severity;
//   }

//   calculateRiskScore(finding, evidence) {
//     const severity = this.calculateEvidenceBasedSeverity(evidence);
//     const confidence = this.calculateConfidence(evidence);

//     const severityScores = { HIGH: 10, MEDIUM: 6, LOW: 3 };
//     const baseScore = severityScores[severity] || 1;

//     return Math.round(baseScore * (confidence / 100));
//   }

//   assessBusinessImpact(type) {
//     const impacts = {
//       'missingState': 'Account takeover, unauthorized access to user data',
//       'csrf_no_state': 'Account takeover, unauthorized access to user data',
//       'NO_HSTS': 'Data interception, man-in-the-middle attacks',
//       'HSTS_MISSING': 'Data interception, man-in-the-middle attacks'
//     };

//     return impacts[type] || 'Potential security compromise';
//   }

//   getImmediateActions(finding) {
//     const actions = {
//       'missingState': ['Implement mandatory state parameter validation', 'Generate cryptographically random state values'],
//       'csrf_no_state': ['Implement mandatory state parameter validation', 'Generate cryptographically random state values'],
//       'NO_HSTS': ['Add HSTS header to all HTTPS responses', 'Redirect HTTP traffic to HTTPS'],
//       'HSTS_MISSING': ['Add HSTS header to all HTTPS responses', 'Redirect HTTP traffic to HTTPS']
//     };

//     return actions[finding.type] || ['Review and fix identified security issue'];
//   }

//   getShortTermActions(finding) {
//     return ['Conduct security code review', 'Implement automated security testing', 'Update security documentation'];
//   }

//   getLongTermActions(finding) {
//     return ['Implement Security Development Lifecycle (SDL)', 'Regular penetration testing', 'Security awareness training'];
//   }

//   getBestPractices(type) {
//     return ['Follow OWASP security guidelines', 'Implement defense in depth', 'Regular security assessments'];
//   }

//   getSecurityStandards(type) {
//     const standards = {
//       'missingState': ['RFC 6749 - OAuth 2.0', 'RFC 6819 - OAuth 2.0 Security'],
//       'NO_HSTS': ['RFC 6797 - HSTS', 'OWASP HSTS Guidelines']
//     };

//     return standards[type] || ['OWASP Top 10', 'NIST Cybersecurity Framework'];
//   }

//   getSecurityReferences(type) {
//     return ['OWASP Authentication Cheat Sheet', 'OAuth 2.0 Security Best Practices', 'Web Application Security Guidelines'];
//   }

//   getVerificationTools(type) {
//     return ['Hera Security Extension', 'Browser Developer Tools', 'Security Testing Frameworks'];
//   }

//   assessFalsePositiveLikelihood(evidence) {
//     const confidence = this.calculateConfidence(evidence);
//     if (confidence >= 90) return 'VERY_LOW';
//     if (confidence >= 70) return 'LOW';
//     if (confidence >= 50) return 'MEDIUM';
//     return 'HIGH';
//   }

//   getVerificationMethod(type) {
//     return 'Evidence-based automated testing with manual verification';
//   }

//   getTestMethodology(type) {
//     if (type.includes('State') || type.includes('csrf')) {
//       return 'OAuth2 CSRF testing methodology including state parameter validation, replay testing, and entropy analysis';
//     }
//     if (type.includes('HSTS')) {
//       return 'HSTS implementation testing including HTTP/HTTPS behavior analysis and header verification';
//     }
//     return 'Evidence-based security testing methodology';
//   }

//   formatDescription(report) {
//     return `${report.technical_details.vulnerability_description}\n\nThis vulnerability was identified and verified using evidence-based testing methods, providing concrete proof of the security issue.`;
//   }

//   identifyAffectedComponent(evidence) {
//     if (evidence.originalRequest) {
//       const url = new URL(evidence.originalRequest);
//       return `${url.hostname}${url.pathname}`;
//     }
//     return 'Authentication system';
//   }

//   identifyAttackVector(type) {
//     const vectors = {
//       'missingState': 'Network - Social Engineering',
//       'csrf_no_state': 'Network - Social Engineering',
//       'NO_HSTS': 'Network - Man-in-the-Middle',
//       'HSTS_MISSING': 'Network - Man-in-the-Middle'
//     };

//     return vectors[type] || 'Network';
//   }

//   analyzeImpact(finding, evidence) {
//     const impacts = {
//       'missingState': 'Complete account takeover through CSRF attacks on OAuth2 authorization',
//       'csrf_no_state': 'Complete account takeover through CSRF attacks on OAuth2 authorization',
//       'NO_HSTS': 'Interception of sensitive data through HTTPS downgrade attacks',
//       'HSTS_MISSING': 'Interception of sensitive data through HTTPS downgrade attacks'
//     };

//     return impacts[finding.type] || 'Security compromise with potential data exposure';
//   }

//   extractHeaderEvidence(evidence) {
//     if (evidence.evidence && evidence.evidence.captured && evidence.evidence.captured.headers) {
//       return evidence.evidence.captured.headers;
//     }
//     return [];
//   }

//   extractTimeline(evidence) {
//     if (evidence.evidence && evidence.evidence.captured && evidence.evidence.captured.timestamps) {
//       return evidence.evidence.captured.timestamps;
//     }
//     return [{ event: 'vulnerability_detected', timestamp: evidence.timestamp || Date.now() }];
//   }

//   extractVerificationResults(evidence) {
//     if (evidence.evidence && evidence.evidence.verification) {
//       return evidence.evidence.verification;
//     }
//     return { verified: evidence.verified || false };
//   }

//   mapToBugcrowdCategory(type) {
//     // Placeholder for Bugcrowd-specific categories
//     return 'Authentication';
//   }

//   mapToBugcrowdPriority(severity) {
//     const mapping = { HIGH: 'P1', MEDIUM: 'P2', LOW: 'P3' };
//     return mapping[severity] || 'P4';
//   }

//   mapToIntigritiCategory(type) {
//     // Placeholder for Intigriti-specific categories
//     return 'Authentication';
//   }
// }

// export { EvidenceBasedReporter };
