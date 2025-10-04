// Phishing Detector - Detects phishing and brand impersonation attempts
// Identifies homograph attacks, typosquatting, visual cloning, and credential theft

class PhishingDetector {
  constructor() {
    // Known legitimate domains for major brands
    this.trustedDomains = {
      'google': ['google.com', 'google.co.uk', 'google.ca', 'google.de', 'google.fr'],
      'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
      'apple': ['apple.com', 'icloud.com'],
      'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de'],
      'facebook': ['facebook.com', 'fb.com'],
      'paypal': ['paypal.com'],
      'netflix': ['netflix.com'],
      'dropbox': ['dropbox.com'],
      'github': ['github.com'],
      'twitter': ['twitter.com', 'x.com']
    };

    // Brand colors for visual cloning detection
    this.brandColors = {
      'paypal': { primary: '#003087', secondary: '#009cde' },
      'facebook': { primary: '#1877f2', secondary: '#ffffff' },
      'google': { primary: '#4285f4', secondary: '#ea4335' },
      'microsoft': { primary: '#00a4ef', secondary: '#f25022' },
      'amazon': { primary: '#ff9900', secondary: '#146eb4' },
      'apple': { primary: '#000000', secondary: '#ffffff' }
    };

    // Suspicious TLDs commonly used in phishing
    this.suspiciousTLDs = [
      '.tk', '.ml', '.ga', '.cf', '.gq', // Free TLDs
      '.xyz', '.top', '.win', '.review', '.date',
      '.loan', '.download', '.stream', '.science'
    ];
  }

  // PERFORMANCE FIX P1-2a: Helper to check if element is visible
  isElementVisible(element) {
    if (!element) return false;
    const style = window.getComputedStyle(element);
    return style.display !== 'none' &&
           style.visibility !== 'hidden' &&
           style.opacity !== '0' &&
           element.offsetWidth > 0 &&
           element.offsetHeight > 0;
  }

  // PERFORMANCE FIX P1-2a: Helper to filter visible elements
  filterVisible(elements) {
    return Array.from(elements).filter(el => this.isElementVisible(el));
  }

  // PERFORMANCE FIX P1-2b: Batch process elements with requestIdleCallback
  async processInBatches(elements, processFunc, batchSize = 50) {
    const results = [];
    const batches = [];

    for (let i = 0; i < elements.length; i += batchSize) {
      batches.push(elements.slice(i, i + batchSize));
    }

    for (const batch of batches) {
      await new Promise(resolve => {
        if (typeof requestIdleCallback !== 'undefined') {
          requestIdleCallback(() => {
            results.push(...batch.map(processFunc));
            resolve();
          }, { timeout: 1000 });
        } else {
          setTimeout(() => {
            results.push(...batch.map(processFunc));
            resolve();
          }, 0);
        }
      });
    }

    return results;
  }

  // Main detection method
  async detectPhishing(url, document) {
    const findings = [];

    // Run all detection methods
    findings.push(...await this.detectHomographAttack(url));
    findings.push(...await this.detectTyposquatting(url));
    findings.push(...await this.detectVisualCloning(url, document));
    findings.push(...await this.detectInsecureForms(document));
    findings.push(...await this.detectSuspiciousTLD(url));
    findings.push(...await this.detectCredentialFields(document));
    findings.push(...await this.detectBrandImpersonation(url, document));

    return findings;
  }

  // Detect homograph attacks (unicode characters that look like ASCII)
  async detectHomographAttack(url) {
    const findings = [];

    try {
      const hostname = new URL(url).hostname;

      // Check for non-ASCII characters in domain
      const hasNonASCII = /[^\x00-\x7F]/.test(hostname);

      if (hasNonASCII) {
        // Extract suspicious characters
        const suspiciousChars = hostname.match(/[^\x00-\x7F]/g);

        findings.push({
          type: 'phishing',
          category: 'homograph_attack',
          severity: 'critical',
          title: 'Homograph Attack Detected',
          description: 'Domain contains non-ASCII characters that may impersonate legitimate sites',
          evidence: {
            hostname: hostname,
            suspiciousCharacters: suspiciousChars,
            decodedHostname: decodeURIComponent(hostname),
            recommendation: 'This domain uses unicode characters to appear similar to trusted brands'
          },
          reasoning: `Domain "${hostname}" contains ${suspiciousChars.length} non-ASCII character(s): ${suspiciousChars.join(', ')}. Attackers use lookalike Unicode characters (e.g., Cyrillic 'а' vs Latin 'a') to create domains that visually mimic legitimate sites. This is a critical phishing indicator.`,
          recommendation: 'Immediately verify this is the correct domain before entering credentials',
          timestamp: new Date().toISOString()
        });
      }

      // Check for mixed scripts (e.g., Latin + Cyrillic)
      const scripts = this.detectMixedScripts(hostname);
      if (scripts.length > 1) {
        findings.push({
          type: 'phishing',
          category: 'mixed_script',
          severity: 'critical',
          title: 'Mixed Script Domain',
          description: 'Domain mixes multiple character scripts (e.g., Latin + Cyrillic)',
          evidence: {
            hostname: hostname,
            scripts: scripts,
            example: 'Characters like "а" (Cyrillic) look identical to "a" (Latin)'
          },
          reasoning: `Domain "${hostname}" mixes ${scripts.length} different character scripts: ${scripts.join(', ')}. Legitimate domains typically use a single script. Mixing scripts (e.g., Latin + Cyrillic) is a homograph attack technique used to create visually identical fake domains.`,
          recommendation: 'Verify domain authenticity - this is a common phishing technique',
          timestamp: new Date().toISOString()
        });
      }
    } catch (error) {
      // Invalid URL, skip
    }

    return findings;
  }

  // Detect typosquatting (domains similar to trusted brands)
  async detectTyposquatting(url) {
    const findings = [];

    try {
      const hostname = new URL(url).hostname;
      const domain = hostname.replace(/^www\./, '');

      // Check against known brands
      for (const [brand, trustedDomains] of Object.entries(this.trustedDomains)) {
        for (const trustedDomain of trustedDomains) {
          // Skip if exact match
          if (domain === trustedDomain) continue;

          // Calculate Levenshtein distance
          const distance = this.levenshteinDistance(domain, trustedDomain);

          // Flag if very similar (distance 1-3 characters)
          if (distance > 0 && distance <= 3) {
            findings.push({
              type: 'phishing',
              category: 'typosquatting',
              severity: distance === 1 ? 'critical' : 'high',
              title: 'Typosquatting Detected',
              description: `Domain is suspiciously similar to ${trustedDomain}`,
              evidence: {
                currentDomain: domain,
                legitimateDomain: trustedDomain,
                brand: brand,
                editDistance: distance,
                differences: this.findDifferences(domain, trustedDomain)
              },
              reasoning: `Domain "${domain}" differs from legitimate "${trustedDomain}" by only ${distance} character(s): ${this.findDifferences(domain, trustedDomain).join(', ')}. This minimal difference suggests intentional typosquatting to capture users who mistype the legitimate domain.`,
              recommendation: `Verify you meant to visit ${trustedDomain}, not ${domain}`,
              timestamp: new Date().toISOString()
            });
          }

          // CRITICAL FIX: Only check typosquatting patterns if domains are actually similar
          // Skip if edit distance is too high (e.g., gov.uk vs x.com = distance 6)
          if (distance <= 5) {
            const patterns = this.detectTyposquattingPatterns(domain, trustedDomain);
            if (patterns.length > 0) {
              findings.push({
                type: 'phishing',
                category: 'typosquatting_pattern',
                severity: 'high',
                title: 'Typosquatting Pattern Detected',
                description: `Domain uses common typosquatting technique`,
                evidence: {
                  currentDomain: domain,
                  legitimateDomain: trustedDomain,
                  brand: brand,
                  patterns: patterns,
                  editDistance: distance
                },
                reasoning: `Domain "${domain}" is similar to trusted domain "${trustedDomain}" (edit distance: ${distance}) and uses typosquatting patterns: ${patterns.join(', ')}. This suggests deliberate impersonation to deceive users.`,
                recommendation: `Be cautious - this domain mimics ${trustedDomain}`,
                timestamp: new Date().toISOString()
              });
            }
          }
        }
      }
    } catch (error) {
      // Invalid URL, skip
    }

    return findings;
  }

  // Detect visual brand cloning
  async detectVisualCloning(url, document) {
    const findings = [];

    try {
      const hostname = new URL(url).hostname;

      // Extract brand mentions from page content
      const bodyText = document.body.innerText.toLowerCase();
      const titleText = document.title.toLowerCase();

      for (const [brand, trustedDomains] of Object.entries(this.trustedDomains)) {
        // Check if page mentions brand but domain doesn't match
        const mentionsBrand = bodyText.includes(brand) || titleText.includes(brand);
        const isLegitDomain = trustedDomains.some(d => hostname.includes(d));

        if (mentionsBrand && !isLegitDomain) {
          // Check if page uses brand colors
          const usedBrandColors = this.detectBrandColors(document, brand);

          if (usedBrandColors.matches > 0) {
            findings.push({
              type: 'phishing',
              category: 'visual_cloning',
              severity: 'critical',
              title: 'Brand Impersonation Detected',
              description: `Page impersonates ${brand} but domain doesn't match`,
              evidence: {
                currentDomain: hostname,
                legitimateDomains: trustedDomains,
                brand: brand,
                colorMatches: usedBrandColors.matches,
                mentionsInText: this.countOccurrences(bodyText, brand)
              },
              reasoning: `Page mentions "${brand}" ${this.countOccurrences(bodyText, brand)} time(s) and uses ${usedBrandColors.matches} matching brand color(s), but domain "${hostname}" does not match legitimate domains: ${trustedDomains.join(', ')}. This visual impersonation is designed to trick users into thinking they're on the official ${brand} site.`,
              recommendation: `This is NOT an official ${brand} site - do not enter credentials`,
              timestamp: new Date().toISOString()
            });
          }
        }
      }

      // PERFORMANCE FIX P1-2a: Check for brand logos - filter visible images only
      const logos = this.filterVisible(document.querySelectorAll('img[src*="logo"], img[alt*="logo"], img[class*="logo"]'));
      for (const logo of logos) {
        const src = logo.src.toLowerCase();
        const alt = (logo.alt || '').toLowerCase();

        for (const [brand, trustedDomains] of Object.entries(this.trustedDomains)) {
          const hasBrandLogo = src.includes(brand) || alt.includes(brand);
          const isLegitDomain = trustedDomains.some(d => hostname.includes(d));

          if (hasBrandLogo && !isLegitDomain) {
            findings.push({
              type: 'phishing',
              category: 'logo_impersonation',
              severity: 'critical',
              title: 'Logo Impersonation',
              description: `Page displays ${brand} logo but is not hosted on ${brand} domain`,
              evidence: {
                currentDomain: hostname,
                legitimateDomains: trustedDomains,
                brand: brand,
                logoSrc: logo.src,
                logoAlt: logo.alt
              },
              reasoning: `Page displays ${brand} logo (alt text: "${logo.alt}", src: "${logo.src}") but domain "${hostname}" does not match any legitimate ${brand} domains: ${trustedDomains.join(', ')}. Attackers copy brand logos to create fake login pages that appear legitimate.`,
              recommendation: 'Verify domain authenticity - logos can be easily copied',
              timestamp: new Date().toISOString()
            });
          }
        }
      }
    } catch (error) {
      console.error('Visual cloning detection error:', error);
    }

    return findings;
  }

  // Detect insecure credential forms
  async detectInsecureForms(document) {
    const findings = [];

    // PERFORMANCE FIX P1-2a: Filter visible password inputs only
    const passwordInputs = this.filterVisible(document.querySelectorAll('input[type="password"]'));

    for (const passwordInput of passwordInputs) {
      const form = passwordInput.closest('form');
      if (!form) continue;

      // Check if form submits over HTTPS
      const formAction = form.action || window.location.href;
      const isHTTPS = formAction.startsWith('https://');

      if (!isHTTPS) {
        findings.push({
          type: 'phishing',
          category: 'insecure_form',
          severity: 'critical',
          title: 'Insecure Credential Form',
          description: 'Password form submits over insecure HTTP connection',
          evidence: {
            formAction: formAction,
            protocol: 'HTTP',
            formId: form.id,
            formName: form.name
          },
          reasoning: `Password form (id: "${form.id || 'none'}", name: "${form.name || 'none'}") submits to "${formAction}" using insecure HTTP protocol. This means credentials are transmitted in plaintext and can be intercepted by attackers. Legitimate sites always use HTTPS for credential forms.`,
          recommendation: 'NEVER enter passwords on non-HTTPS sites',
          timestamp: new Date().toISOString()
        });
      }

      // Check if form has autocomplete disabled (suspicious for credentials)
      const autocomplete = passwordInput.getAttribute('autocomplete');
      if (autocomplete === 'off') {
        findings.push({
          type: 'phishing',
          category: 'suspicious_form',
          severity: 'medium',
          title: 'Autocomplete Disabled on Password Field',
          description: 'Password field disables autocomplete (may bypass password managers)',
          evidence: {
            autocomplete: autocomplete,
            fieldId: passwordInput.id,
            fieldName: passwordInput.name
          },
          reasoning: `Password field (id: "${passwordInput.id || 'none'}", name: "${passwordInput.name || 'none'}") has autocomplete="${autocomplete}". Disabling autocomplete prevents password managers from detecting the field, which is a red flag. Legitimate sites allow autocomplete so users can use secure password managers.`,
          recommendation: 'Legitimate sites typically allow autocomplete for credential managers',
          timestamp: new Date().toISOString()
        });
      }
    }

    return findings;
  }

  // Detect suspicious TLDs
  async detectSuspiciousTLD(url) {
    const findings = [];

    try {
      const hostname = new URL(url).hostname;

      for (const tld of this.suspiciousTLDs) {
        if (hostname.endsWith(tld)) {
          findings.push({
            type: 'phishing',
            category: 'suspicious_tld',
            severity: 'high',
            title: 'Suspicious Top-Level Domain',
            description: `Site uses ${tld} which is commonly used in phishing campaigns`,
            evidence: {
              hostname: hostname,
              tld: tld,
              note: 'Free or low-cost TLDs are favored by phishers'
            },
            reasoning: `Domain "${hostname}" uses top-level domain "${tld}", which is frequently abused in phishing campaigns because it's free or low-cost and has minimal registration requirements. Attackers exploit these TLDs to create disposable phishing sites.`,
            recommendation: 'Exercise extreme caution with sites using this TLD',
            timestamp: new Date().toISOString()
          });
        }
      }
    } catch (error) {
      // Invalid URL, skip
    }

    return findings;
  }

  // Detect excessive credential field requests
  async detectCredentialFields(document) {
    const findings = [];

    // PERFORMANCE FIX P1-2a: Filter visible inputs only
    const passwordInputs = this.filterVisible(document.querySelectorAll('input[type="password"]'));
    const emailInputs = this.filterVisible(document.querySelectorAll('input[type="email"], input[name*="email"], input[id*="email"]'));
    const ssnInputs = this.filterVisible(document.querySelectorAll('input[name*="ssn"], input[name*="social"], input[id*="ssn"]'));
    const cardInputs = this.filterVisible(document.querySelectorAll('input[name*="card"], input[name*="credit"], input[autocomplete="cc-number"]'));

    // Count sensitive fields
    const sensitiveFieldCount = passwordInputs.length + ssnInputs.length + cardInputs.length;

    if (sensitiveFieldCount >= 3) {
      findings.push({
        type: 'phishing',
        category: 'excessive_credentials',
        severity: 'high',
        title: 'Excessive Credential Requests',
        description: 'Page requests multiple sensitive credential types simultaneously',
        evidence: {
          passwordFields: passwordInputs.length,
          ssnFields: ssnInputs.length,
          cardFields: cardInputs.length,
          totalSensitiveFields: sensitiveFieldCount
        },
        reasoning: `Page requests ${sensitiveFieldCount} different types of sensitive data simultaneously: ${passwordInputs.length} password field(s), ${ssnInputs.length} SSN field(s), and ${cardInputs.length} credit card field(s). Legitimate sites follow security best practices by collecting credentials in separate steps, not all at once. This pattern is common in credential harvesting attacks.`,
        recommendation: 'Legitimate sites rarely request multiple credential types on one page',
        timestamp: new Date().toISOString()
      });
    }

    return findings;
  }

  // Detect brand impersonation in URL
  async detectBrandImpersonation(url, document) {
    const findings = [];

    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname;
      const pathname = urlObj.pathname;
      const fullURL = hostname + pathname;

      // Check if URL contains brand name but doesn't use brand domain
      for (const [brand, trustedDomains] of Object.entries(this.trustedDomains)) {
        const containsBrandInURL = fullURL.toLowerCase().includes(brand);
        const isLegitDomain = trustedDomains.some(d => hostname.includes(d));

        if (containsBrandInURL && !isLegitDomain) {
          findings.push({
            type: 'phishing',
            category: 'url_impersonation',
            severity: 'critical',
            title: 'Brand Name in URL Path',
            description: `URL contains "${brand}" but is not hosted on ${brand} domain`,
            evidence: {
              url: url,
              hostname: hostname,
              legitimateDomains: trustedDomains,
              brand: brand
            },
            reasoning: `URL "${url}" contains the brand name "${brand}" in the path or subdomain, but the actual domain "${hostname}" does not match legitimate ${brand} domains: ${trustedDomains.join(', ')}. Attackers use this technique (e.g., "evilsite.com/paypal/login") to create URLs that appear trustworthy at first glance.`,
            recommendation: `Phishers often include brand names in URL paths (e.g., evil.com/paypal)`,
            timestamp: new Date().toISOString()
          });
        }
      }
    } catch (error) {
      // Invalid URL, skip
    }

    return findings;
  }

  // Helper: Detect mixed character scripts
  detectMixedScripts(text) {
    const scripts = [];

    // Check for different script ranges
    const hasLatin = /[\u0000-\u007F\u0080-\u00FF\u0100-\u017F]/.test(text);
    const hasCyrillic = /[\u0400-\u04FF]/.test(text);
    const hasGreek = /[\u0370-\u03FF]/.test(text);
    const hasArabic = /[\u0600-\u06FF]/.test(text);
    const hasChinese = /[\u4E00-\u9FFF]/.test(text);

    if (hasLatin) scripts.push('Latin');
    if (hasCyrillic) scripts.push('Cyrillic');
    if (hasGreek) scripts.push('Greek');
    if (hasArabic) scripts.push('Arabic');
    if (hasChinese) scripts.push('Chinese');

    return scripts;
  }

  // Helper: Levenshtein distance (edit distance between strings)
  levenshteinDistance(str1, str2) {
    const matrix = [];

    // Initialize matrix
    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    // Calculate distances
    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  // Helper: Find differences between strings
  findDifferences(str1, str2) {
    const diffs = [];

    for (let i = 0; i < Math.max(str1.length, str2.length); i++) {
      if (str1[i] !== str2[i]) {
        diffs.push({
          position: i,
          current: str1[i] || '(missing)',
          expected: str2[i] || '(extra)'
        });
      }
    }

    return diffs;
  }

  // Helper: Detect common typosquatting patterns
  detectTyposquattingPatterns(current, legitimate) {
    const patterns = [];

    // Character omission (e.g., gogle.com)
    if (current.length === legitimate.length - 1) {
      patterns.push('character_omission');
    }

    // Character addition (e.g., gooogle.com)
    if (current.length === legitimate.length + 1) {
      patterns.push('character_addition');
    }

    // Character substitution (e.g., goo0le.com - 0 instead of o)
    const substitutions = { 'o': '0', 'l': '1', 'i': '1', 'e': '3', 'a': '4', 's': '5' };
    for (const [letter, number] of Object.entries(substitutions)) {
      if (legitimate.includes(letter) && current.includes(number)) {
        patterns.push(`character_substitution_${letter}_to_${number}`);
      }
    }

    // Subdomain abuse (e.g., google.evil.com)
    if (current.includes(legitimate)) {
      patterns.push('subdomain_abuse');
    }

    // Hyphenation (e.g., goo-gle.com)
    if (current.includes('-') && !legitimate.includes('-')) {
      patterns.push('hyphenation');
    }

    return patterns;
  }

  // Helper: Detect brand colors on page
  detectBrandColors(document, brand) {
    const brandColor = this.brandColors[brand];
    if (!brandColor) return { matches: 0 };

    let matches = 0;

    // PERFORMANCE FIX P1-2a: Sample visible elements only to check colors
    const elements = this.filterVisible(document.querySelectorAll('header, nav, button, a, div[class*="logo"], div[class*="brand"]'));

    for (const element of elements) {
      const style = window.getComputedStyle(element);
      const bgColor = style.backgroundColor;
      const textColor = style.color;

      // Check if colors match brand palette (with tolerance)
      if (this.colorMatches(bgColor, brandColor.primary) ||
          this.colorMatches(bgColor, brandColor.secondary) ||
          this.colorMatches(textColor, brandColor.primary) ||
          this.colorMatches(textColor, brandColor.secondary)) {
        matches++;
      }
    }

    return { matches };
  }

  // Helper: Check if colors match (with tolerance)
  colorMatches(color1, color2) {
    const rgb1 = this.parseColor(color1);
    const rgb2 = this.parseColor(color2);

    if (!rgb1 || !rgb2) return false;

    // Allow 30-point tolerance per channel
    const tolerance = 30;
    return Math.abs(rgb1.r - rgb2.r) <= tolerance &&
           Math.abs(rgb1.g - rgb2.g) <= tolerance &&
           Math.abs(rgb1.b - rgb2.b) <= tolerance;
  }

  // Helper: Parse color string to RGB
  parseColor(color) {
    // Parse rgb() format
    const rgbMatch = color.match(/rgb\((\d+),\s*(\d+),\s*(\d+)\)/);
    if (rgbMatch) {
      return { r: parseInt(rgbMatch[1]), g: parseInt(rgbMatch[2]), b: parseInt(rgbMatch[3]) };
    }

    // Parse hex format
    const hexMatch = color.match(/#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})/i);
    if (hexMatch) {
      return { r: parseInt(hexMatch[1], 16), g: parseInt(hexMatch[2], 16), b: parseInt(hexMatch[3], 16) };
    }

    return null;
  }

  // Helper: Count occurrences
  countOccurrences(text, word) {
    const regex = new RegExp(word, 'gi');
    const matches = text.match(regex);
    return matches ? matches.length : 0;
  }
}

// CRITICAL FIX P0-1: Assign to window instead of ES6 export
window.phishingDetector = new PhishingDetector();
console.log('Hera: Phishing detector loaded (no dynamic import needed)');
