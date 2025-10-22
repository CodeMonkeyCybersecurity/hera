// /**
//  * Hera Subdomain Brand Impersonation Detector
//  *
//  * Detects when a subdomain contains a brand name that doesn't match the actual domain
//  * Example: microsoft-login.verify-account.com (Microsoft in subdomain, not in domain)
//  *
//  * This is a CRITICAL layer because it's one of the most common phishing techniques
//  */

// class HeraSubdomainImpersonationDetector {
//   constructor() {
//     // Major brands commonly impersonated
//     // This list should be comprehensive and regularly updated
//     this.brandKeywords = {
//       // Tech companies
//       'microsoft': { legitimate: ['microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'office365.com', 'outlook.com', 'azure.com', 'windows.com'], weight: 10 },
//       'msft': { legitimate: ['microsoft.com', 'msft.com'], weight: 9 },
//       'azure': { legitimate: ['azure.com', 'azurewebsites.net', 'microsoft.com'], weight: 9 },
//       'office': { legitimate: ['office.com', 'office365.com', 'microsoft.com'], weight: 8 },
//       'outlook': { legitimate: ['outlook.com', 'live.com', 'microsoft.com'], weight: 8 },

//       'google': { legitimate: ['google.com', 'gmail.com', 'youtube.com', 'gstatic.com', 'googleapis.com', 'googleusercontent.com'], weight: 10 },
//       'gmail': { legitimate: ['gmail.com', 'google.com'], weight: 9 },
//       'goog': { legitimate: ['google.com', 'goog.com'], weight: 8 },

//       'apple': { legitimate: ['apple.com', 'icloud.com', 'me.com', 'mac.com'], weight: 10 },
//       'icloud': { legitimate: ['icloud.com', 'apple.com'], weight: 9 },
//       'appleid': { legitimate: ['apple.com', 'icloud.com'], weight: 9 },

//       'amazon': { legitimate: ['amazon.com', 'amazonaws.com', 'awsstatic.com'], weight: 10 },
//       'aws': { legitimate: ['aws.amazon.com', 'amazonaws.com', 'awsstatic.com'], weight: 10 },
//       'amzn': { legitimate: ['amazon.com', 'amzn.com'], weight: 8 },

//       'facebook': { legitimate: ['facebook.com', 'fb.com', 'fbcdn.net'], weight: 10 },
//       'meta': { legitimate: ['meta.com', 'facebook.com'], weight: 9 },

//       'paypal': { legitimate: ['paypal.com', 'paypal-worldwide.com'], weight: 10 },

//       'linkedin': { legitimate: ['linkedin.com', 'licdn.com'], weight: 9 },

//       'github': { legitimate: ['github.com', 'githubusercontent.com', 'github.io'], weight: 9 },

//       'dropbox': { legitimate: ['dropbox.com', 'dropboxusercontent.com'], weight: 9 },

//       'okta': { legitimate: ['okta.com', 'oktacdn.com'], weight: 9 },
//       'auth0': { legitimate: ['auth0.com', 'auth0cdn.com'], weight: 9 },

//       'salesforce': { legitimate: ['salesforce.com', 'force.com', 'salesforce-sites.com'], weight: 9 },

//       'slack': { legitimate: ['slack.com', 'slack-edge.com'], weight: 8 },

//       'zoom': { legitimate: ['zoom.us', 'zoom.com'], weight: 8 },

//       // Financial institutions
//       'bank': { legitimate: [], weight: 7 }, // Generic - any bank name is suspicious
//       'chase': { legitimate: ['chase.com', 'jpmorganchase.com'], weight: 9 },
//       'wellsfargo': { legitimate: ['wellsfargo.com'], weight: 9 },
//       'bofa': { legitimate: ['bankofamerica.com'], weight: 9 },
//       'citi': { legitimate: ['citi.com', 'citibank.com'], weight: 9 },

//       // Generic auth terms
//       'login': { legitimate: [], weight: 5 },
//       'signin': { legitimate: [], weight: 5 },
//       'auth': { legitimate: [], weight: 5 },
//       'sso': { legitimate: [], weight: 5 },
//       'portal': { legitimate: [], weight: 4 },
//       'account': { legitimate: [], weight: 4 },
//       'verify': { legitimate: [], weight: 6 },
//       'secure': { legitimate: [], weight: 6 },
//       'update': { legitimate: [], weight: 5 },
//     };

//     // Common typosquatting variations
//     this.typoVariations = {
//       'microsoft': ['microsfot', 'microsft', 'micosoft', 'micr0soft'],
//       'google': ['gogle', 'googel', 'gooogle', 'g00gle'],
//       'paypal': ['paypa1', 'paypai', 'paypall'],
//       'apple': ['appie', 'appl3'],
//       'amazon': ['amazom', 'arnazon', 'amaz0n'],
//     };
//   }

//   /**
//    * Main detection method for Hera integration
//    * Returns findings array compatible with Hera's finding format
//    */
//   async detectImpersonation(url) {
//     const findings = [];

//     try {
//       const analysis = this.analyzeURL(url);

//       // Only create findings if risk is detected
//       if (analysis.overallRiskScore >= 20) {

//         // Determine severity based on risk score
//         let severity = 'info';
//         if (analysis.overallRiskScore >= 80) severity = 'critical';
//         else if (analysis.overallRiskScore >= 60) severity = 'high';
//         else if (analysis.overallRiskScore >= 40) severity = 'medium';
//         else if (analysis.overallRiskScore >= 20) severity = 'low';

//         findings.push({
//           type: 'phishing',
//           category: 'subdomain_impersonation',
//           severity: severity,
//           title: analysis.brandImpersonation ?
//             `Brand Impersonation: ${analysis.brandImpersonation.brand.toUpperCase()} in Subdomain` :
//             'Suspicious Subdomain Pattern Detected',
//           description: analysis.explanation[0] || 'Subdomain contains suspicious patterns',
//           evidence: {
//             subdomain: analysis.subdomain,
//             domain: analysis.domain,
//             fullHost: analysis.fullHost,
//             riskScore: analysis.overallRiskScore,
//             verdict: analysis.verdict,
//             brandImpersonation: analysis.brandImpersonation,
//             typosquatting: analysis.typosquatting,
//             suspiciousPatterns: analysis.suspiciousPatterns,
//             allReasons: analysis.explanation
//           },
//           reasoning: this.generateReasoning(analysis),
//           recommendation: this.generateRecommendation(analysis),
//           timestamp: new Date().toISOString()
//         });
//       }

//     } catch (error) {
//       console.error('Hera: Subdomain impersonation detection error:', error);
//     }

//     return findings;
//   }

//   /**
//    * Generate human-readable reasoning
//    */
//   generateReasoning(analysis) {
//     let reasoning = '';

//     if (analysis.brandImpersonation) {
//       const brand = analysis.brandImpersonation.brand.toUpperCase();
//       reasoning = `The subdomain "${analysis.subdomain}" contains the brand name "${analysis.brandImpersonation.brand}", suggesting this is a ${brand} page. However, the actual domain "${analysis.domain}" does not match any legitimate ${brand} domains: ${analysis.brandImpersonation.brand ? this.brandKeywords[analysis.brandImpersonation.brand].legitimate.join(', ') : 'unknown'}. `;
//       reasoning += `This is a classic phishing technique where attackers use brand names in subdomains (e.g., "microsoft-login.evilsite.com") to create URLs that appear trustworthy at first glance. The domain itself is what matters for security - and this domain is NOT ${brand}. `;
//     }

//     if (analysis.typosquatting) {
//       reasoning += `Additionally, the domain uses typosquatting: "${analysis.typosquatting.typo}" is a deliberate misspelling of "${analysis.typosquatting.brand}". `;
//     }

//     if (analysis.suspiciousPatterns.length > 0) {
//       reasoning += `Suspicious patterns detected: ${analysis.suspiciousPatterns.map(p => p.reason).join('; ')}. `;
//     }

//     reasoning += `Overall risk score: ${analysis.overallRiskScore}/100 (${analysis.verdict}).`;

//     return reasoning;
//   }

//   /**
//    * Generate user-facing recommendation
//    */
//   generateRecommendation(analysis) {
//     if (analysis.overallRiskScore >= 80) {
//       return 'DO NOT enter credentials on this page. This appears to be a phishing attempt. Close this page immediately.';
//     } else if (analysis.overallRiskScore >= 60) {
//       return 'Exercise extreme caution. Verify the URL carefully before entering any information.';
//     } else if (analysis.overallRiskScore >= 40) {
//       return 'Be cautious. Double-check that this is the correct website before proceeding.';
//     } else {
//       return 'Verify the domain is correct before entering sensitive information.';
//     }
//   }

//   /**
//    * Main analysis function
//    * Returns detailed analysis of subdomain brand impersonation risk
//    */
//   analyzeURL(url) {
//     const parsed = this.parseURL(url);

//     if (!parsed) {
//       return {
//         error: 'Invalid URL',
//         riskScore: 0
//       };
//     }

//     const analysis = {
//       url,
//       domain: parsed.domain,
//       subdomain: parsed.subdomain,
//       fullHost: parsed.fullHost,

//       // Detection results
//       brandImpersonation: null,
//       typosquatting: null,
//       suspiciousPatterns: [],

//       // Scores
//       impersonationScore: 0,
//       typoScore: 0,
//       patternScore: 0,
//       overallRiskScore: 0,

//       // Verdict
//       verdict: 'SAFE',
//       confidence: 'LOW',
//       explanation: []
//     };

//     // Check 1: Brand keyword in subdomain
//     const brandCheck = this.checkBrandInSubdomain(parsed.subdomain, parsed.domain);
//     if (brandCheck.detected) {
//       analysis.brandImpersonation = brandCheck;
//       analysis.impersonationScore = brandCheck.score;
//       analysis.explanation.push(brandCheck.reason);
//     }

//     // Check 2: Typosquatting in domain
//     const typoCheck = this.checkTyposquatting(parsed.domain);
//     if (typoCheck.detected) {
//       analysis.typosquatting = typoCheck;
//       analysis.typoScore = typoCheck.score;
//       analysis.explanation.push(typoCheck.reason);
//     }

//     // Check 3: Suspicious patterns
//     const patternCheck = this.checkSuspiciousPatterns(parsed);
//     if (patternCheck.length > 0) {
//       analysis.suspiciousPatterns = patternCheck;
//       analysis.patternScore = patternCheck.reduce((sum, p) => sum + p.score, 0);
//       patternCheck.forEach(p => analysis.explanation.push(p.reason));
//     }

//     // Calculate overall risk score
//     analysis.overallRiskScore = Math.min(100,
//       analysis.impersonationScore * 1.0 +  // Brand impersonation is critical
//       analysis.typoScore * 0.8 +            // Typosquatting is very serious
//       analysis.patternScore * 0.5           // Patterns add to suspicion
//     );

//     // Determine verdict
//     if (analysis.overallRiskScore >= 80) {
//       analysis.verdict = 'CRITICAL';
//       analysis.confidence = 'HIGH';
//     } else if (analysis.overallRiskScore >= 60) {
//       analysis.verdict = 'HIGH';
//       analysis.confidence = 'HIGH';
//     } else if (analysis.overallRiskScore >= 40) {
//       analysis.verdict = 'MEDIUM';
//       analysis.confidence = 'MEDIUM';
//     } else if (analysis.overallRiskScore >= 20) {
//       analysis.verdict = 'LOW';
//       analysis.confidence = 'MEDIUM';
//     } else {
//       analysis.verdict = 'SAFE';
//       analysis.confidence = 'HIGH';
//     }

//     return analysis;
//   }

//   /**
//    * Parse URL into components
//    */
//   parseURL(url) {
//     try {
//       const urlObj = new URL(url);
//       const hostname = urlObj.hostname;

//       // Split into parts: subdomain.domain.tld
//       const parts = hostname.split('.');

//       if (parts.length < 2) {
//         return null; // Invalid
//       }

//       // Extract domain (last two parts typically: example.com)
//       // Handle special cases like .co.uk, .com.au
//       let domain, subdomain;

//       const specialTLDs = ['co.uk', 'com.au', 'co.nz', 'co.za', 'com.br'];
//       const lastTwoParts = parts.slice(-2).join('.');
//       const lastThreeParts = parts.slice(-3).join('.');

//       if (specialTLDs.includes(lastThreeParts)) {
//         // Handle .co.uk style domains
//         domain = parts.length > 3 ? lastThreeParts : lastThreeParts;
//         subdomain = parts.length > 3 ? parts.slice(0, -3).join('.') : '';
//       } else {
//         // Standard .com, .org, etc.
//         domain = lastTwoParts;
//         subdomain = parts.length > 2 ? parts.slice(0, -2).join('.') : '';
//       }

//       return {
//         fullHost: hostname,
//         domain: domain.toLowerCase(),
//         subdomain: subdomain.toLowerCase(),
//         protocol: urlObj.protocol,
//         path: urlObj.pathname
//       };
//     } catch (error) {
//       return null;
//     }
//   }

//   /**
//    * Check if subdomain contains a brand keyword that doesn't match the domain
//    */
//   checkBrandInSubdomain(subdomain, domain) {
//     if (!subdomain) {
//       return { detected: false };
//     }

//     const subdomainLower = subdomain.toLowerCase();

//     for (const [brand, config] of Object.entries(this.brandKeywords)) {
//       // Check if brand keyword is in subdomain
//       if (this.containsKeyword(subdomainLower, brand)) {

//         // Check if domain is legitimate for this brand
//         const isLegitimate = config.legitimate.some(legitDomain =>
//           domain === legitDomain || domain.endsWith('.' + legitDomain)
//         );

//         if (!isLegitimate) {
//           // BRAND IMPERSONATION DETECTED!
//           return {
//             detected: true,
//             brand: brand,
//             score: config.weight * 10, // Scale to 0-100
//             reason: `Subdomain contains '${brand}' but domain is '${domain}' (not a legitimate ${brand.toUpperCase()} domain)`,
//             type: 'BRAND_IMPERSONATION',
//             severity: 'CRITICAL'
//           };
//         }
//       }
//     }

//     return { detected: false };
//   }

//   /**
//    * Check if keyword is present in text (with word boundaries)
//    */
//   containsKeyword(text, keyword) {
//     // Match keyword as whole word or part of hyphenated/dotted domain
//     const pattern = new RegExp(`(^|[.-])${keyword}([.-]|$)`, 'i');
//     return pattern.test(text);
//   }

//   /**
//    * Check for typosquatting in the main domain
//    */
//   checkTyposquatting(domain) {
//     const domainBase = domain.split('.')[0]; // Get part before .com

//     for (const [brand, variations] of Object.entries(this.typoVariations)) {
//       for (const typo of variations) {
//         if (domainBase === typo || domainBase.includes(typo)) {
//           return {
//             detected: true,
//             brand: brand,
//             typo: typo,
//             score: 90, // Very high - typosquatting is deliberate deception
//             reason: `Domain contains typosquatting variation '${typo}' of '${brand}'`,
//             type: 'TYPOSQUATTING',
//             severity: 'CRITICAL'
//           };
//         }
//       }

//       // Check Levenshtein distance for similar spellings
//       const distance = this.levenshteinDistance(domainBase, brand);
//       if (distance > 0 && distance <= 2 && domainBase.length >= 5) {
//         return {
//           detected: true,
//           brand: brand,
//           typo: domainBase,
//           score: 80 - (distance * 10), // 80 for distance=1, 70 for distance=2
//           reason: `Domain '${domainBase}' is very similar to '${brand}' (edit distance: ${distance})`,
//           type: 'TYPOSQUATTING_SIMILAR',
//           severity: 'HIGH'
//         };
//       }
//     }

//     return { detected: false };
//   }

//   /**
//    * Check for other suspicious patterns
//    */
//   checkSuspiciousPatterns(parsed) {
//     const patterns = [];
//     const { subdomain, domain, fullHost } = parsed;

//     // Pattern 1: Multiple brand keywords
//     const brandsFound = [];
//     for (const brand of Object.keys(this.brandKeywords)) {
//       if (fullHost.includes(brand)) {
//         brandsFound.push(brand);
//       }
//     }

//     if (brandsFound.length >= 2) {
//       patterns.push({
//         type: 'MULTIPLE_BRANDS',
//         score: 30,
//         reason: `Domain contains multiple brand keywords: ${brandsFound.join(', ')}`,
//         severity: 'MEDIUM'
//       });
//     }

//     // Pattern 2: Suspicious auth-related subdomain
//     const suspiciousAuthSubdomains = [
//       'login', 'signin', 'auth', 'sso', 'account', 'verify',
//       'secure', 'update', 'confirm', 'validation'
//     ];

//     if (subdomain && suspiciousAuthSubdomains.some(s => subdomain.includes(s))) {
//       // Only suspicious if domain is NOT a known auth provider
//       const isKnownAuthProvider = this.isKnownAuthProvider(domain);

//       if (!isKnownAuthProvider) {
//         patterns.push({
//           type: 'SUSPICIOUS_AUTH_SUBDOMAIN',
//           score: 20,
//           reason: `Auth-related subdomain '${subdomain}' on unknown domain '${domain}'`,
//           severity: 'MEDIUM'
//         });
//       }
//     }

//     // Pattern 3: Excessive hyphens (common in phishing)
//     const hyphenCount = fullHost.split('-').length - 1;
//     if (hyphenCount >= 3) {
//       patterns.push({
//         type: 'EXCESSIVE_HYPHENS',
//         score: 15,
//         reason: `Domain contains ${hyphenCount} hyphens (common in phishing)`,
//         severity: 'LOW'
//       });
//     }

//     // Pattern 4: Numbers in suspicious positions
//     if (/\d/.test(subdomain) && subdomain.length > 0) {
//       patterns.push({
//         type: 'NUMBERS_IN_SUBDOMAIN',
//         score: 10,
//         reason: 'Subdomain contains numbers (sometimes used in phishing)',
//         severity: 'LOW'
//       });
//     }

//     // Pattern 5: Very long subdomain (> 30 chars)
//     if (subdomain.length > 30) {
//       patterns.push({
//         type: 'LONG_SUBDOMAIN',
//         score: 15,
//         reason: `Unusually long subdomain (${subdomain.length} characters)`,
//         severity: 'LOW'
//       });
//     }

//     return patterns;
//   }

//   /**
//    * Check if domain is a known auth provider
//    */
//   isKnownAuthProvider(domain) {
//     const knownProviders = [
//       'okta.com', 'auth0.com', 'onelogin.com', 'pingidentity.com',
//       'microsoft.com', 'microsoftonline.com', 'google.com', 'github.com',
//       'salesforce.com', 'apple.com', 'amazon.com', 'facebook.com'
//     ];

//     return knownProviders.some(provider =>
//       domain === provider || domain.endsWith('.' + provider)
//     );
//   }

//   /**
//    * Calculate Levenshtein distance between two strings
//    */
//   levenshteinDistance(str1, str2) {
//     const matrix = [];

//     for (let i = 0; i <= str2.length; i++) {
//       matrix[i] = [i];
//     }

//     for (let j = 0; j <= str1.length; j++) {
//       matrix[0][j] = j;
//     }

//     for (let i = 1; i <= str2.length; i++) {
//       for (let j = 1; j <= str1.length; j++) {
//         if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
//           matrix[i][j] = matrix[i - 1][j - 1];
//         } else {
//           matrix[i][j] = Math.min(
//             matrix[i - 1][j - 1] + 1,
//             matrix[i][j - 1] + 1,
//             matrix[i - 1][j] + 1
//           );
//         }
//       }
//     }

//     return matrix[str2.length][str1.length];
//   }

//   /**
//    * Enhanced analysis combining with other signals
//    */
//   enhancedAnalysis(url, additionalContext = {}) {
//     const basicAnalysis = this.analyzeURL(url);

//     // Enhance with additional context
//     if (additionalContext.domainAge !== undefined) {
//       // Very new domain + brand impersonation = EXTREMELY suspicious
//       if (basicAnalysis.impersonationScore > 0 && additionalContext.domainAge < 30) {
//         basicAnalysis.overallRiskScore += 20;
//         basicAnalysis.explanation.push(
//           `Domain is only ${additionalContext.domainAge} days old AND impersonating a brand - extremely suspicious`
//         );
//       }
//     }

//     if (additionalContext.hasSSL === false) {
//       // No HTTPS + brand impersonation = CRITICAL
//       if (basicAnalysis.impersonationScore > 0) {
//         basicAnalysis.overallRiskScore += 30;
//         basicAnalysis.explanation.push(
//           'No HTTPS encryption on a page impersonating a major brand - CRITICAL risk'
//         );
//       }
//     }

//     if (additionalContext.pageTitle) {
//       // Check if page title claims to be the brand
//       const titleLower = additionalContext.pageTitle.toLowerCase();
//       if (basicAnalysis.brandImpersonation) {
//         const brand = basicAnalysis.brandImpersonation.brand;
//         if (titleLower.includes(brand)) {
//           basicAnalysis.overallRiskScore += 15;
//           basicAnalysis.explanation.push(
//             `Page title claims to be ${brand.toUpperCase()} but domain is not legitimate ${brand.toUpperCase()} domain`
//           );
//         }
//       }
//     }

//     // Recalculate verdict after enhancements
//     basicAnalysis.overallRiskScore = Math.min(100, basicAnalysis.overallRiskScore);

//     if (basicAnalysis.overallRiskScore >= 80) {
//       basicAnalysis.verdict = 'CRITICAL';
//       basicAnalysis.confidence = 'HIGH';
//     } else if (basicAnalysis.overallRiskScore >= 60) {
//       basicAnalysis.verdict = 'HIGH';
//       basicAnalysis.confidence = 'HIGH';
//     }

//     return basicAnalysis;
//   }
// }

// // Make available globally for Hera extension
// if (typeof window !== 'undefined') {
//   window.HeraSubdomainImpersonationDetector = HeraSubdomainImpersonationDetector;
//   window.subdomainImpersonationDetector = new HeraSubdomainImpersonationDetector();
//   console.log('Hera: Enhanced subdomain impersonation detector loaded');
// }
