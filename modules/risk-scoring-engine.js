// // Risk Scoring Engine - Unified risk scoring across all detection categories
// // Aggregates findings from all detectors and produces overall site grade

// class RiskScoringEngine {
//   constructor() {
//     // Scoring weights by category (accessibility removed - not a security issue)
//     this.categoryWeights = {
//       phishing: 40,           // Critical security threat
//       privacy_violation: 35,  // High user impact
//       dark_pattern: 15,       // Deceptive practices
//       auth_security: 10       // OAuth/OIDC/SAML issues (original Hera focus)
//     };

//     // Severity multipliers
//     this.severityMultipliers = {
//       critical: 10,
//       high: 7,
//       medium: 4,
//       low: 2,
//       info: 1
//     };

//     // Grade thresholds (score out of 100)
//     this.gradeThresholds = {
//       'A+': 95,
//       'A': 90,
//       'A-': 85,
//       'B+': 80,
//       'B': 75,
//       'B-': 70,
//       'C+': 65,
//       'C': 60,
//       'C-': 55,
//       'D+': 50,
//       'D': 45,
//       'D-': 40,
//       'F': 0
//     };

//     // Risk levels
//     this.riskLevels = {
//       SAFE: 'safe',
//       LOW: 'low',
//       MEDIUM: 'medium',
//       HIGH: 'high',
//       CRITICAL: 'critical'
//     };
//   }

//   // Main scoring method - processes all findings
//   calculateRiskScore(findings) {
//     // Group findings by category
//     const categorized = this.categorizeFindings(findings);

//     // Calculate category scores
//     const categoryScores = {};
//     let totalWeight = 0;
//     let weightedScore = 0;

//     for (const [category, weight] of Object.entries(this.categoryWeights)) {
//       const categoryFindings = categorized[category] || [];
//       const score = this.scoreCategoryFindings(categoryFindings);

//       categoryScores[category] = {
//         score: score,
//         weight: weight,
//         findingCount: categoryFindings.length,
//         findings: categoryFindings
//       };

//       weightedScore += score * weight;
//       totalWeight += weight;
//     }

//     // Calculate overall score (0-100)
//     const overallScore = totalWeight > 0 ? (weightedScore / totalWeight) : 100;

//     // Determine grade and risk level
//     const grade = this.calculateGrade(overallScore);
//     const riskLevel = this.calculateRiskLevel(categorized);

//     // Generate recommendations
//     const recommendations = this.generateRecommendations(categorized);

//     // Build detailed report
//     return {
//       overallScore: Math.round(overallScore * 10) / 10,
//       grade: grade,
//       riskLevel: riskLevel,
//       categoryScores: categoryScores,
//       totalFindings: findings.length,
//       criticalIssues: findings.filter(f => f.severity === 'critical').length,
//       highIssues: findings.filter(f => f.severity === 'high').length,
//       mediumIssues: findings.filter(f => f.severity === 'medium').length,
//       lowIssues: findings.filter(f => f.severity === 'low').length,
//       recommendations: recommendations,
//       summary: this.generateSummary(overallScore, categorized),
//       timestamp: new Date().toISOString()
//     };
//   }

//   // Categorize findings by type
//   categorizeFindings(findings) {
//     const categorized = {
//       phishing: [],
//       privacy_violation: [],
//       dark_pattern: [],
//       auth_security: []
//     };

//     for (const finding of findings) {
//       const type = finding.type || 'unknown';

//       if (type === 'phishing') {
//         categorized.phishing.push(finding);
//       } else if (type === 'privacy_violation') {
//         categorized.privacy_violation.push(finding);
//       } else if (type === 'dark_pattern') {
//         categorized.dark_pattern.push(finding);
//       } else if (type === 'auth_security' || type === 'oauth2' || type === 'oidc' || type === 'saml') {
//         categorized.auth_security.push(finding);
//       }
//       // Accessibility and unknown types are ignored
//     }

//     return categorized;
//   }

//   // Score findings within a single category (returns 0-100)
//   scoreCategoryFindings(findings) {
//     if (findings.length === 0) return 100; // Perfect score if no issues

//     // Calculate deductions based on severity
//     let totalDeduction = 0;

//     for (const finding of findings) {
//       const severity = finding.severity || 'low';
//       const multiplier = this.severityMultipliers[severity] || 1;
//       totalDeduction += multiplier;
//     }

//     // Apply diminishing returns (don't go below 0)
//     // Formula: 100 - (sqrt(totalDeduction) * 10)
//     const score = Math.max(0, 100 - (Math.sqrt(totalDeduction) * 10));

//     return score;
//   }

//   // Calculate letter grade from score
//   calculateGrade(score) {
//     for (const [grade, threshold] of Object.entries(this.gradeThresholds)) {
//       if (score >= threshold) {
//         return grade;
//       }
//     }
//     return 'F';
//   }

//   // Calculate risk level based on critical findings
//   calculateRiskLevel(categorized) {
//     // CRITICAL FIX: Only count security findings, not accessibility
//     const securityFindings = [
//       ...categorized.phishing,
//       ...categorized.privacy_violation,
//       ...categorized.dark_pattern,
//       ...categorized.auth_security
//     ];

//     const criticalCount = securityFindings.filter(f => f.severity === 'critical').length;
//     const highCount = securityFindings.filter(f => f.severity === 'high').length;

//     // CRITICAL FIX: Only check for critical/high phishing, not any phishing
//     const criticalPhishing = categorized.phishing.filter(f =>
//       f.severity === 'critical' || f.severity === 'high'
//     );
//     const hasCriticalPrivacy = categorized.privacy_violation.some(f => f.severity === 'critical');

//     if (criticalCount >= 3 || criticalPhishing.length > 0) {
//       return this.riskLevels.CRITICAL;
//     } else if (criticalCount >= 1 || hasCriticalPrivacy || highCount >= 5) {
//       return this.riskLevels.HIGH;
//     } else if (highCount >= 2 || securityFindings.length >= 10) {
//       return this.riskLevels.MEDIUM;
//     } else if (securityFindings.length > 0) {
//       return this.riskLevels.LOW;
//     } else {
//       return this.riskLevels.SAFE;
//     }
//   }

//   // Generate prioritized recommendations
//   generateRecommendations(categorized) {
//     const recommendations = [];

//     // CRITICAL FIX: Only show phishing warning if there are critical/high severity findings
//     // Don't panic users over low-confidence detections
//     const criticalPhishing = categorized.phishing.filter(f =>
//       f.severity === 'critical' || f.severity === 'high'
//     );

//     if (criticalPhishing.length > 0) {
//       recommendations.push({
//         priority: 1,
//         category: 'phishing',
//         title: 'Critical Security Threat Detected',
//         description: 'This site exhibits phishing characteristics. Do not enter credentials or personal information.',
//         action: 'Leave this site immediately and verify the URL',
//         findingCount: criticalPhishing.length
//       });
//     }

//     // Privacy violation recommendations
//     const cookieWalls = categorized.privacy_violation.filter(f => f.category === 'cookie_wall');
//     if (cookieWalls.length > 0) {
//       recommendations.push({
//         priority: 2,
//         category: 'privacy_violation',
//         title: 'GDPR Compliance Issues',
//         description: 'Site forces cookie acceptance without option to decline (GDPR violation)',
//         action: 'Report to data protection authority or use browser extensions to block',
//         findingCount: cookieWalls.length
//       });
//     }

//     const fingerprinting = categorized.privacy_violation.filter(f =>
//       f.category === 'canvas_fingerprinting' ||
//       f.category === 'webgl_fingerprinting' ||
//       f.category === 'audio_fingerprinting'
//     );
//     if (fingerprinting.length > 0) {
//       recommendations.push({
//         priority: 3,
//         category: 'privacy_violation',
//         title: 'Device Fingerprinting Detected',
//         description: 'Site attempts to uniquely identify your device without consent',
//         action: 'Use privacy-focused browser or fingerprinting protection',
//         findingCount: fingerprinting.length
//       });
//     }

//     // Dark pattern recommendations
//     const confirmshaming = categorized.dark_pattern.filter(f => f.category === 'confirmshaming');
//     if (confirmshaming.length > 0) {
//       recommendations.push({
//         priority: 4,
//         category: 'dark_pattern',
//         title: 'Manipulative UI Patterns',
//         description: 'Site uses guilt/shame to manipulate your decisions',
//         action: 'Be aware of manipulative language and make informed choices',
//         findingCount: confirmshaming.length
//       });
//     }

//     const sneaking = categorized.dark_pattern.filter(f => f.category === 'sneaking');
//     if (sneaking.length > 0) {
//       recommendations.push({
//         priority: 5,
//         category: 'dark_pattern',
//         title: 'Hidden Costs or Auto-Enrollment',
//         description: 'Site may hide additional charges or auto-enroll you in subscriptions',
//         action: 'Carefully review all charges and uncheck pre-selected options',
//         findingCount: sneaking.length
//       });
//     }

//     // Auth security recommendations (original Hera focus)
//     if (categorized.auth_security.length > 0) {
//       recommendations.push({
//         priority: 7,
//         category: 'auth_security',
//         title: 'Authentication Flow Issues',
//         description: 'OAuth/OIDC/SAML authentication may have security vulnerabilities',
//         action: 'Review authentication findings in Hera dashboard',
//         findingCount: categorized.auth_security.length
//       });
//     }

//     return recommendations.sort((a, b) => a.priority - b.priority);
//   }

//   // Generate human-readable summary
//   generateSummary(score, categorized) {
//     const allFindings = Object.values(categorized).flat();

//     if (allFindings.length === 0) {
//       return 'This site appears safe and well-designed with no major issues detected.';
//     }

//     const criticalCount = allFindings.filter(f => f.severity === 'critical').length;

//     // CRITICAL FIX: Only show DANGER for critical/high severity phishing, not any phishing finding
//     const criticalPhishing = categorized.phishing.filter(f =>
//       f.severity === 'critical' || f.severity === 'high'
//     );
//     const hasPrivacy = categorized.privacy_violation.length > 0;
//     const hasDarkPatterns = categorized.dark_pattern.length > 0;

//     if (criticalPhishing.length > 0) {
//       return 'DANGER: This site shows strong phishing indicators. Do not enter credentials or personal information.';
//     }

//     if (criticalCount >= 3) {
//       return `This site has ${criticalCount} critical security or privacy issues. Exercise extreme caution.`;
//     }

//     if (score >= 85) {
//       return `This site is generally trustworthy with ${allFindings.length} minor issues detected.`;
//     }

//     if (score >= 70) {
//       if (hasPrivacy && hasDarkPatterns) {
//         return 'This site has both privacy concerns and manipulative design patterns. Be cautious with your data.';
//       } else if (hasPrivacy) {
//         return 'This site has privacy concerns. Review what data is being collected.';
//       } else if (hasDarkPatterns) {
//         return 'This site uses manipulative design patterns. Be mindful of your choices.';
//       }
//       return `This site has ${allFindings.length} moderate issues. Review findings before proceeding.`;
//     }

//     if (score >= 50) {
//       return `This site has significant issues across multiple categories (${allFindings.length} findings). Consider using an alternative.`;
//     }

//     return `This site has major concerns (${allFindings.length} findings). Strongly consider avoiding this site.`;
//   }

//   // Get score interpretation
//   getScoreInterpretation(score) {
//     if (score >= 95) return 'Excellent';
//     if (score >= 90) return 'Very Good';
//     if (score >= 85) return 'Good';
//     if (score >= 80) return 'Above Average';
//     if (score >= 70) return 'Average';
//     if (score >= 60) return 'Below Average';
//     if (score >= 50) return 'Poor';
//     return 'Very Poor';
//   }

//   // Get risk color (for UI)
//   getRiskColor(riskLevel) {
//     switch (riskLevel) {
//       case this.riskLevels.SAFE:
//         return '#28a745'; // Green
//       case this.riskLevels.LOW:
//         return '#5bc0de'; // Light blue
//       case this.riskLevels.MEDIUM:
//         return '#ffc107'; // Yellow
//       case this.riskLevels.HIGH:
//         return '#fd7e14'; // Orange
//       case this.riskLevels.CRITICAL:
//         return '#dc3545'; // Red
//       default:
//         return '#6c757d'; // Gray
//     }
//   }

//   // Get grade color (for UI)
//   getGradeColor(grade) {
//     if (grade.startsWith('A')) return '#28a745'; // Green
//     if (grade.startsWith('B')) return '#5bc0de'; // Blue
//     if (grade.startsWith('C')) return '#ffc107'; // Yellow
//     if (grade.startsWith('D')) return '#fd7e14'; // Orange
//     return '#dc3545'; // Red
//   }

//   // Compare scores over time (for tracking improvements)
//   compareScores(currentScore, previousScore) {
//     if (!previousScore) {
//       return {
//         change: 0,
//         percentage: 0,
//         improved: false,
//         message: 'First scan'
//       };
//     }

//     const change = currentScore.overallScore - previousScore.overallScore;
//     const percentage = (change / previousScore.overallScore) * 100;

//     return {
//       change: Math.round(change * 10) / 10,
//       percentage: Math.round(percentage * 10) / 10,
//       improved: change > 0,
//       message: change > 0
//         ? `Improved by ${Math.abs(Math.round(change))} points`
//         : change < 0
//         ? `Declined by ${Math.abs(Math.round(change))} points`
//         : 'No change'
//     };
//   }

//   // Export report as JSON
//   exportReport(scoreData, url) {
//     return {
//       version: '1.0',
//       url: url,
//       scanDate: scoreData.timestamp,
//       score: scoreData.overallScore,
//       grade: scoreData.grade,
//       riskLevel: scoreData.riskLevel,
//       summary: scoreData.summary,
//       categories: Object.entries(scoreData.categoryScores).map(([name, data]) => ({
//         name: name,
//         score: data.score,
//         weight: data.weight,
//         findingCount: data.findingCount
//       })),
//       recommendations: scoreData.recommendations,
//       findings: Object.values(scoreData.categoryScores)
//         .flatMap(cat => cat.findings)
//         .map(f => ({
//           type: f.type,
//           category: f.category,
//           severity: f.severity,
//           title: f.title,
//           description: f.description
//         }))
//     };
//   }
// }

// // CRITICAL FIX P0-1: Assign to window instead of ES6 export
// window.riskScoringEngine = new RiskScoringEngine();
// console.log('Hera: Risk scoring engine loaded (no dynamic import needed)');
