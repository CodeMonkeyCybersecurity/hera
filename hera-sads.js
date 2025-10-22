// // Hera Statistical Anomaly Detection System (SADS)
// // Bayesian Website Security & Deception Analysis
// // Uses machine learning-inspired surprise scoring similar to Cylance

// class HeraAnomalyDetectionEngine {
//   constructor() {
//     // Baseline profiles for different website categories
//     this.baselineProfiles = {
//       'fortune500': {
//         expectedFeatures: {
//           hasGitExposed: 0.001,  // 0.1% chance
//           hasDevFiles: 0.005,
//           hasStaging: 0.01,
//           certIssuer: ['DigiCert', 'Entrust', 'GlobalSign'],
//           tlsVersion: ['1.3', '1.2'],
//           securityHeaders: 0.95,
//           cdnUsage: 0.90,
//           avgLoadTime: 800,
//           techStack: ['enterprise'],
//           domainAge: 7300  // 20+ years
//         },
//         variance: 0.1
//       },
//       'startup': {
//         expectedFeatures: {
//           hasGitExposed: 0.05,  // 5% chance
//           hasDevFiles: 0.10,
//           hasStaging: 0.20,
//           certIssuer: ['Let\'s Encrypt', 'Cloudflare'],
//           tlsVersion: ['1.3', '1.2'],
//           securityHeaders: 0.60,
//           cdnUsage: 0.70,
//           avgLoadTime: 1500,
//           techStack: ['modern'],
//           domainAge: 730  // 2 years
//         },
//         variance: 0.3
//       },
//       'personal': {
//         expectedFeatures: {
//           hasGitExposed: 0.15,  // 15% chance
//           hasDevFiles: 0.25,
//           hasStaging: 0.10,
//           certIssuer: ['Let\'s Encrypt'],
//           tlsVersion: ['1.2'],
//           securityHeaders: 0.30,
//           cdnUsage: 0.20,
//           avgLoadTime: 2500,
//           techStack: ['basic'],
//           domainAge: 365
//         },
//         variance: 0.5
//       },
//       'government': {
//         expectedFeatures: {
//           hasGitExposed: 0.0001,  // Should NEVER happen
//           hasDevFiles: 0.001,
//           hasStaging: 0.001,
//           certIssuer: ['DigiCert Gov', 'Entrust'],
//           tlsVersion: ['1.3'],
//           securityHeaders: 0.99,
//           cdnUsage: 0.50,
//           avgLoadTime: 1200,
//           techStack: ['legacy', 'enterprise'],
//           domainAge: 5475  // 15+ years
//         },
//         variance: 0.05
//       },
//       'financial': {
//         expectedFeatures: {
//           hasGitExposed: 0.0001,  // Critical if exposed
//           hasDevFiles: 0.001,
//           hasStaging: 0.005,
//           certIssuer: ['DigiCert', 'Entrust', 'GlobalSign'],
//           tlsVersion: ['1.3'],
//           securityHeaders: 0.98,
//           cdnUsage: 0.85,
//           avgLoadTime: 1000,
//           techStack: ['enterprise', 'banking'],
//           domainAge: 5475
//         },
//         variance: 0.05
//       },
//       'design_tool': {
//         expectedFeatures: {
//           hasGitExposed: 0.08,  // Higher tolerance for design tools
//           hasDevFiles: 0.15,
//           hasStaging: 0.25,
//           certIssuer: ['Let\'s Encrypt', 'Cloudflare'],
//           tlsVersion: ['1.3', '1.2'],
//           securityHeaders: 0.70,
//           cdnUsage: 0.80,
//           avgLoadTime: 1200,
//           techStack: ['modern', 'design'],
//           domainAge: 1095  // 3 years
//         },
//         variance: 0.4
//       }
//     };

//     // Feature weights based on security impact
//     this.featureWeights = {
//       gitExposed: 25,
//       envFileExposed: 100,
//       databaseExposed: 500,
//       devFilesPresent: 15,
//       weakCertificate: 30,
//       suspiciousCertEmail: 50,
//       domainAgeMismatch: 40,
//       techStackInconsistency: 35,
//       securityHeadersMissing: 20,
//       unusualLoadTime: 10,
//       homographDomain: 200,
//       typosquatting: 150,
//       contentMismatch: 80,
//       unusualDNS: 60,
//       strangeSubresources: 45
//     };

//     // Context multipliers
//     this.contextMultipliers = {
//       financial: 3.5,
//       healthcare: 2.8,
//       government: 4.0,
//       ecommerce: 2.5,
//       social: 2.0,
//       personal: 0.5,
//       design_tool: 0.6,
//       development: 0.3
//     };

//     // Domain classification patterns
//     this.domainPatterns = {
//       design_tools: [
//         'penpot.app', 'design.penpot.app', 'figma.com', 'sketch.com',
//         'canva.com', 'adobe.com', 'invisionapp.com', 'framer.com'
//       ],
//       financial: [
//         'bank', 'credit', 'payment', 'finance', 'invest', 'trading',
//         'paypal', 'stripe', 'square', 'visa', 'mastercard'
//       ],
//       government: ['.gov', '.gov.uk', '.gc.ca', '.gouv.fr'],
//       social: [
//         'facebook', 'twitter', 'linkedin', 'instagram', 'tiktok',
//         'reddit', 'discord', 'slack', 'zoom'
//       ]
//     };

//     // Machine learning model (simplified)
//     this.model = new HeraMLModel();
//     this.model.loadPretrainedWeights();
//   }

//   async analyzeWebsite(domain, signals) {
//     console.log(`SADS analyzing: ${domain}`);

//     // Step 1: Classify website type using multiple signals
//     const websiteType = this.classifyWebsite(domain, signals);
//     console.log(`Classified as: ${websiteType}`);

//     // Step 2: Get expected baseline for this type
//     const baseline = this.baselineProfiles[websiteType] || this.baselineProfiles['startup'];

//     // Step 3: Calculate surprise scores for each feature
//     const surpriseScores = this.calculateSurpriseScores(signals, baseline, websiteType);

//     // Step 4: Detect anomalous combinations
//     const anomalies = this.detectAnomalousCombinations(signals, websiteType);

//     // Step 5: Calculate aggregate S-Score
//     const sScore = this.calculateAggregateScore(surpriseScores, anomalies, websiteType);

//     // Step 6: Determine if deceptive or insecure
//     const assessment = this.assessThreat(sScore, signals, websiteType, anomalies);

//     const analysis = {
//       domain: domain,
//       websiteType: websiteType,
//       sScore: sScore,
//       assessment: assessment,
//       signals: signals,
//       surpriseScores: surpriseScores,
//       anomalies: anomalies,
//       recommendation: this.generateRecommendation(assessment, sScore),
//       confidence: this.calculateConfidence(surpriseScores, anomalies),
//       explanation: this.generateExplanation(surpriseScores, anomalies, websiteType)
//     };

//     console.log(`S-Score: ${sScore.normalized} (${sScore.category})`);
//     console.log(`Assessment: ${assessment.threatType || 'NORMAL'}`);

//     return analysis;
//   }

//   classifyWebsite(domain, signals) {
//     // Check design tools first (since Penpot was flagged incorrectly)
//     if (this.domainPatterns.design_tools.some(pattern =>
//         domain.includes(pattern) || pattern.includes(domain))) {
//       return 'design_tool';
//     }

//     // Check for government TLD
//     if (this.domainPatterns.government.some(tld => domain.endsWith(tld))) {
//       return 'government';
//     }

//     // Check financial keywords
//     if (this.domainPatterns.financial.some(keyword =>
//         domain.toLowerCase().includes(keyword))) {
//       return 'financial';
//     }

//     // Check social media
//     if (this.domainPatterns.social.some(pattern =>
//         domain.includes(pattern))) {
//       return 'social';
//     }

//     // Check domain age and other signals
//     if (signals.domainAge && signals.domainAge > 5475) { // 15+ years
//       return 'fortune500';
//     }

//     if (signals.domainAge && signals.domainAge < 365) {
//       return 'startup';
//     }

//     // Check hosting patterns
//     if (signals.hostingProvider &&
//         (signals.hostingProvider.includes('github') ||
//          signals.hostingProvider.includes('netlify') ||
//          signals.hostingProvider.includes('vercel'))) {
//       return 'personal';
//     }

//     return 'startup'; // Default
//   }

//   calculateSurpriseScores(signals, baseline, websiteType) {
//     const surpriseScores = {};

//     // Git exposure surprise (contextual)
//     if (signals.gitExposed && signals.gitExposed.exposed) {
//       const expectedProbability = baseline.expectedFeatures.hasGitExposed;
//       surpriseScores.gitExposure = -Math.log(expectedProbability) * 2;

//       // Apply context multiplier
//       const contextMultiplier = this.contextMultipliers[websiteType] || 1.0;
//       surpriseScores.gitExposure *= contextMultiplier;

//       // Adjust for severity
//       if (signals.gitExposed.sensitiveFiles && signals.gitExposed.sensitiveFiles.length > 0) {
//         surpriseScores.gitExposure *= 3;
//       }

//       console.log(`Git exposure surprise: ${surpriseScores.gitExposure.toFixed(2)} (expected: ${expectedProbability}, context: ${websiteType})`);
//     }

//     // Environment file exposure (very high surprise for any production site)
//     if (signals.envFileExposed && signals.envFileExposed.exposed) {
//       surpriseScores.envExposure = 50; // High base surprise
//       const contextMultiplier = this.contextMultipliers[websiteType] || 1.0;
//       surpriseScores.envExposure *= contextMultiplier;
//     }

//     // Certificate issuer surprise
//     if (signals.certificate && signals.certificate.issuer) {
//       const expectedIssuers = baseline.expectedFeatures.certIssuer;
//       const actualIssuer = signals.certificate.issuer;

//       if (!expectedIssuers.some(expected => actualIssuer.includes(expected))) {
//         surpriseScores.unexpectedCertIssuer = 8;

//         // Check for especially suspicious issuers
//         if (actualIssuer.toLowerCase().includes('free') ||
//             actualIssuer.toLowerCase().includes('test') ||
//             actualIssuer.toLowerCase().includes('staging')) {
//           surpriseScores.unexpectedCertIssuer = 25;
//         }
//       }
//     }

//     // Domain age surprise
//     if (signals.domainAge !== undefined) {
//       const expectedAge = baseline.expectedFeatures.domainAge;
//       const ageDifference = Math.abs(signals.domainAge - expectedAge);
//       const ageRatio = ageDifference / expectedAge;

//       if (ageRatio > baseline.variance) {
//         surpriseScores.domainAgeMismatch = ageRatio * 15;

//         // Very new domains are especially surprising for established site types
//         if (signals.domainAge < 90 && ['fortune500', 'government', 'financial'].includes(websiteType)) {
//           surpriseScores.domainAgeMismatch *= 3;
//         }
//       }
//     }

//     // Technology stack surprise
//     if (signals.techStack && signals.techStack.length > 0) {
//       const expectedStack = baseline.expectedFeatures.techStack;
//       const unexpectedTech = signals.techStack.filter(tech =>
//         !this.isExpectedTechnology(tech, expectedStack)
//       );

//       if (unexpectedTech.length > 0) {
//         surpriseScores.techStackMismatch = unexpectedTech.length * 12;
//       }
//     }

//     // Security headers surprise
//     if (signals.securityHeaders !== undefined) {
//       const expectedSecHeaders = baseline.expectedFeatures.securityHeaders;
//       const actualSecHeaders = signals.securityHeaders;

//       if (actualSecHeaders < expectedSecHeaders - baseline.variance) {
//         surpriseScores.weakSecurity = (expectedSecHeaders - actualSecHeaders) * 40;
//       }
//     }

//     // TLS version surprise
//     if (signals.tlsVersion) {
//       const expectedVersions = baseline.expectedFeatures.tlsVersion;
//       if (!expectedVersions.includes(signals.tlsVersion)) {
//         surpriseScores.weakTLS = 20;

//         // Very old TLS is extremely surprising
//         if (parseFloat(signals.tlsVersion) < 1.2) {
//           surpriseScores.weakTLS = 60;
//         }
//       }
//     }

//     return surpriseScores;
//   }

//   detectAnomalousCombinations(signals, websiteType) {
//     const anomalies = [];

//     // Pattern 1: Git + Login Form + New Domain = Likely Phishing Setup
//     if (signals.gitExposed?.exposed &&
//         signals.hasLoginForm &&
//         signals.domainAge && signals.domainAge < 60) {
//       anomalies.push({
//         type: 'PHISHING_DEVELOPMENT_PATTERN',
//         severity: 85,
//         description: 'Git repository exposed on new domain with login form',
//         confidence: 0.85,
//         reasoning: 'Attackers often leave development artifacts when rapidly deploying phishing sites'
//       });
//     }

//     // Pattern 2: High-value target + Development artifacts = Compromise or Test
//     if (['fortune500', 'financial', 'government'].includes(websiteType) &&
//         signals.gitExposed?.exposed) {
//       anomalies.push({
//         type: 'HIGH_VALUE_COMPROMISE_PATTERN',
//         severity: 95,
//         description: `${websiteType} site with exposed development files`,
//         confidence: 0.90,
//         reasoning: 'High-value targets should never have exposed development artifacts'
//       });
//     }

//     // Pattern 3: Government impersonation
//     if (websiteType === 'government' &&
//         signals.certificate?.issuer &&
//         !signals.certificate.issuer.toLowerCase().includes('gov') &&
//         signals.hostingProvider &&
//         !this.isDomesticHosting(signals.hostingProvider, signals.domainCountry)) {
//       anomalies.push({
//         type: 'GOVERNMENT_IMPERSONATION',
//         severity: 100,
//         description: 'Government site with non-government certificate and foreign hosting',
//         confidence: 0.95,
//         reasoning: 'Government sites should use government-issued certificates and domestic hosting'
//       });
//     }

//     // Pattern 4: Financial site with weak security
//     if (websiteType === 'financial' &&
//         (signals.tlsVersion < '1.2' || signals.securityHeaders < 0.8)) {
//       anomalies.push({
//         type: 'FINANCIAL_WEAK_SECURITY',
//         severity: 90,
//         description: 'Financial site with inadequate security configuration',
//         confidence: 0.88,
//         reasoning: 'Financial sites must maintain the highest security standards'
//       });
//     }

//     // Pattern 5: Typosquatting with copied content
//     if (signals.typosquattingScore > 0.7 &&
//         signals.contentSimilarity > 0.8 &&
//         signals.domainAge < 90) {
//       anomalies.push({
//         type: 'TYPOSQUATTING_CLONE',
//         severity: 85,
//         description: 'Typosquatting domain with copied content',
//         confidence: 0.85,
//         reasoning: 'Domain mimics legitimate site with stolen content'
//       });
//     }

//     // Pattern 6: Development + Production data mix
//     if ((signals.envFileExposed?.exposed || signals.stagingIndicators) &&
//         (signals.hasCreditCardForm || signals.hasLoginForm)) {
//       anomalies.push({
//         type: 'DEVELOPMENT_PRODUCTION_MIX',
//         severity: 75,
//         description: 'Development artifacts present with sensitive forms',
//         confidence: 0.80,
//         reasoning: 'Development files should never be present on production sites handling sensitive data'
//       });
//     }

//     // Pattern 7: Certificate email anomaly
//     if (signals.certificate?.email) {
//       const suspiciousEmails = [
//         /admin@(gmail|yahoo|hotmail)/i,
//         /test@/i,
//         /noreply@/i,
//         /[0-9]{5,}@/  // Numeric emails
//       ];

//       if (suspiciousEmails.some(pattern => pattern.test(signals.certificate.email))) {
//         anomalies.push({
//           type: 'SUSPICIOUS_CERTIFICATE_EMAIL',
//           severity: 40,
//           description: 'Certificate issued to suspicious email address',
//           confidence: 0.70,
//           reasoning: 'Professional organizations should use business email addresses for certificates'
//         });
//       }
//     }

//     return anomalies;
//   }

//   calculateAggregateScore(surpriseScores, anomalies, websiteType) {
//     let totalScore = 0;
//     let components = {
//       surprise: 0,
//       anomaly: 0,
//       context: 0
//     };

//     // Sum weighted surprise scores
//     for (const [feature, score] of Object.entries(surpriseScores)) {
//       const weight = this.featureWeights[feature] || 10;
//       const weightedScore = weight * score;
//       totalScore += weightedScore;
//       components.surprise += weightedScore;
//     }

//     // Add anomaly pattern scores
//     for (const anomaly of anomalies) {
//       const anomalyScore = anomaly.severity * anomaly.confidence;
//       totalScore += anomalyScore;
//       components.anomaly += anomalyScore;
//     }

//     // Apply context multiplier
//     const contextMultiplier = this.contextMultipliers[websiteType] || 1.0;
//     const contextBonus = totalScore * (contextMultiplier - 1);
//     totalScore *= contextMultiplier;
//     components.context = contextBonus;

//     // Normalize to 0-100 scale using logarithmic scaling for better distribution
//     const normalizedScore = Math.min(100,
//       100 * (1 - Math.exp(-totalScore / 500))
//     );

//     return {
//       raw: totalScore,
//       normalized: Math.round(normalizedScore * 10) / 10,
//       category: this.categorizeScore(normalizedScore),
//       components: components,
//       contextMultiplier: contextMultiplier
//     };
//   }

//   categorizeScore(score) {
//     if (score >= 80) return 'CRITICAL';
//     if (score >= 60) return 'HIGH';
//     if (score >= 40) return 'MEDIUM';
//     if (score >= 20) return 'LOW';
//     return 'NORMAL';
//   }

//   assessThreat(sScore, signals, websiteType, anomalies) {
//     const assessment = {
//       isDeceptive: false,
//       isInsecure: false,
//       isProbablyLegitimate: false,
//       threatType: null,
//       confidence: 0,
//       reasoning: [],
//       primaryConcerns: []
//     };

//     // Analyze anomaly patterns for threat classification
//     const deceptionPatterns = ['PHISHING_DEVELOPMENT_PATTERN', 'TYPOSQUATTING_CLONE', 'GOVERNMENT_IMPERSONATION'];
//     const securityPatterns = ['HIGH_VALUE_COMPROMISE_PATTERN', 'DEVELOPMENT_PRODUCTION_MIX', 'FINANCIAL_WEAK_SECURITY'];

//     const hasDeceptionAnomaly = anomalies.some(a => deceptionPatterns.includes(a.type));
//     const hasSecurityAnomaly = anomalies.some(a => securityPatterns.includes(a.type));

//     // High S-Score indicates something unusual
//     if (sScore.normalized >= 70) {
//       if (hasDeceptionAnomaly) {
//         assessment.isDeceptive = true;
//         assessment.threatType = 'DECEPTION';
//         assessment.confidence = Math.min(0.95, sScore.normalized / 100);
//         assessment.reasoning.push('Site exhibits patterns consistent with impersonation or phishing');
//         assessment.primaryConcerns.push('Potential phishing or impersonation attempt');
//       } else if (hasSecurityAnomaly || signals.gitExposed?.exposed || signals.envFileExposed?.exposed) {
//         assessment.isInsecure = true;
//         assessment.threatType = 'INSECURE_CONFIGURATION';
//         assessment.confidence = 0.85;
//         assessment.reasoning.push('Site has significant security configuration issues');
//         assessment.primaryConcerns.push('Exposed sensitive files or weak security');
//       } else {
//         assessment.isInsecure = true;
//         assessment.threatType = 'ANOMALOUS_BEHAVIOR';
//         assessment.confidence = 0.70;
//         assessment.reasoning.push('Site behavior deviates significantly from expected baseline');
//         assessment.primaryConcerns.push('Unusual configuration for site type');
//       }
//     }
//     // Medium S-Score requires context consideration
//     else if (sScore.normalized >= 40) {
//       if (['fortune500', 'government', 'financial'].includes(websiteType)) {
//         assessment.isInsecure = true;
//         assessment.threatType = 'UNEXPECTED_CONFIGURATION';
//         assessment.confidence = 0.60;
//         assessment.reasoning.push('High-value site with concerning configuration anomalies');
//         assessment.primaryConcerns.push('Security configuration below expected standards');
//       } else {
//         assessment.isProbablyLegitimate = true;
//         assessment.confidence = 0.70;
//         assessment.reasoning.push('Some configuration anomalies but within acceptable variance');
//         assessment.primaryConcerns.push('Minor security considerations');
//       }
//     }
//     // Low S-Score is generally normal
//     else {
//       assessment.isProbablyLegitimate = true;
//       assessment.confidence = 0.90;
//       assessment.reasoning.push('Site configuration matches expected baseline for category');

//       // But still flag if there are critical exposures
//       if (signals.gitExposed?.exposed && ['financial', 'government'].includes(websiteType)) {
//         assessment.primaryConcerns.push('Development files exposed (unusual but may be legitimate)');
//       }
//     }

//     return assessment;
//   }

//   calculateConfidence(surpriseScores, anomalies) {
//     let confidence = 0.5; // Base confidence

//     // Increase confidence with more surprise factors
//     const surpriseCount = Object.keys(surpriseScores).length;
//     confidence += surpriseCount * 0.05;

//     // Increase confidence with anomaly patterns
//     const highConfidenceAnomalies = anomalies.filter(a => a.confidence > 0.8);
//     confidence += highConfidenceAnomalies.length * 0.15;

//     // Decrease confidence if only weak signals
//     const maxSurprise = Math.max(...Object.values(surpriseScores), 0);
//     if (maxSurprise < 5) {
//       confidence -= 0.2;
//     }

//     return Math.min(0.95, Math.max(0.1, confidence));
//   }

//   generateExplanation(surpriseScores, anomalies, websiteType) {
//     const explanations = [];

//     // Explain surprise scores
//     const sortedSurprises = Object.entries(surpriseScores)
//       .sort((a, b) => b[1] - a[1])
//       .slice(0, 3);

//     if (sortedSurprises.length > 0) {
//       explanations.push(`Most unusual aspects:`);
//       sortedSurprises.forEach(([factor, score]) => {
//         explanations.push(`• ${this.humanizeFactor(factor)}: ${score.toFixed(1)}x more surprising than expected`);
//       });
//     }

//     // Explain anomalies
//     if (anomalies.length > 0) {
//       explanations.push(`\nPattern analysis:`);
//       anomalies.forEach(anomaly => {
//         explanations.push(`• ${anomaly.description} (${Math.round(anomaly.confidence * 100)}% confidence)`);
//       });
//     }

//     // Context explanation
//     explanations.push(`\nSite classified as: ${websiteType}`);
//     explanations.push(`Context multiplier: ${this.contextMultipliers[websiteType] || 1.0}x`);

//     return explanations.join('\n');
//   }

//   humanizeFactor(factor) {
//     const humanNames = {
//       gitExposure: 'Git repository exposure',
//       envExposure: 'Environment file exposure',
//       unexpectedCertIssuer: 'Unusual certificate issuer',
//       domainAgeMismatch: 'Domain age inconsistency',
//       techStackMismatch: 'Technology stack anomaly',
//       weakSecurity: 'Security header deficiency',
//       weakTLS: 'Outdated TLS configuration'
//     };

//     return humanNames[factor] || factor;
//   }

//   generateRecommendation(assessment, sScore) {
//     const recommendations = {
//       CRITICAL: {
//         action: 'BLOCK',
//         message: 'Critical security anomalies detected. Avoid entering any personal information.',
//         color: '#e45549',
//         icon: ''
//       },
//       HIGH: {
//         action: 'WARNING',
//         message: 'Significant security concerns detected. Exercise extreme caution.',
//         color: '#e45549',
//         icon: '⚠️'
//       },
//       MEDIUM: {
//         action: 'CAUTION',
//         message: 'Unusual site characteristics detected. Verify legitimacy before proceeding.',
//         color: '#FFD700',
//         icon: '⚡'
//       },
//       LOW: {
//         action: 'NOTICE',
//         message: 'Minor security considerations detected.',
//         color: '#FFD700',
//         icon: 'ℹ️'
//       },
//       NORMAL: {
//         action: 'OK',
//         message: 'Site configuration appears normal for its category.',
//         color: '#51a14f',
//         icon: ''
//       }
//     };

//     const baseRec = recommendations[sScore.category] || recommendations.NORMAL;

//     // Customize message based on assessment
//     if (assessment.isDeceptive) {
//       baseRec.message = `${baseRec.icon} Potential deception detected. This site may be impersonating another service.`;
//     } else if (assessment.isInsecure && assessment.primaryConcerns.length > 0) {
//       baseRec.message = `${baseRec.icon} Security issue: ${assessment.primaryConcerns[0]}`;
//     }

//     return baseRec;
//   }

//   // Helper methods
//   isExpectedTechnology(tech, expectedStacks) {
//     const techMappings = {
//       'enterprise': ['java', 'oracle', 'ibm', 'microsoft', 'sap'],
//       'modern': ['react', 'vue', 'angular', 'node', 'python', 'go'],
//       'basic': ['wordpress', 'php', 'apache', 'nginx'],
//       'design': ['javascript', 'css', 'svg', 'webgl'],
//       'banking': ['java', 'mainframe', 'cobol', 'db2'],
//       'legacy': ['asp', 'coldfusion', 'perl']
//     };

//     return expectedStacks.some(stack =>
//       techMappings[stack]?.some(pattern =>
//         tech.toLowerCase().includes(pattern)
//       )
//     );
//   }

//   isDomesticHosting(hostingProvider, domainCountry) {
//     // Simplified - in practice would use more sophisticated geo-matching
//     if (!hostingProvider || !domainCountry) return true;

//     const foreignIndicators = ['china', 'russia', 'offshore'];
//     return !foreignIndicators.some(indicator =>
//       hostingProvider.toLowerCase().includes(indicator)
//     );
//   }
// }

// // Simplified ML Model for scoring
// class HeraMLModel {
//   constructor() {
//     this.weights = {};
//     this.threshold = 0.5;
//   }

//   loadPretrainedWeights() {
//     // Simulate pre-trained weights based on security research
//     this.weights = {
//       gitExposure: 0.234,
//       certAnomalies: 0.456,
//       domainAge: -0.123,  // Older is generally less suspicious
//       techStackConsistency: -0.234,
//       securityHeaders: -0.345,
//       contentSimilarity: 0.567,
//       behavioralPatterns: 0.678
//     };
//   }

//   predict(features) {
//     let score = 0;

//     for (const [feature, value] of Object.entries(features)) {
//       if (this.weights[feature]) {
//         score += this.weights[feature] * value;
//       }
//     }

//     // Apply sigmoid activation
//     const probability = 1 / (1 + Math.exp(-score));

//     return {
//       probability: probability,
//       isSuspicious: probability > this.threshold,
//       confidence: Math.abs(probability - 0.5) * 2
//     };
//   }
// }

// export { HeraAnomalyDetectionEngine, HeraMLModel };
