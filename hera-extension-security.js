// Hera Malicious Extension Detection System
// Detects credential theft, data exfiltration, and other malicious extension behaviors

class HeraMaliciousExtensionDetector {
  constructor() {
    this.suspiciousRequests = new Map(); // Track extension-initiated requests
    this.credentialPatterns = new Map(); // Track credential-like data flows
    this.extensionReputation = new Map(); // Cache extension reputation data
    this.homographPatterns = this.initializeHomographPatterns();
    this.legitimateDomains = this.initializeLegitimateDomainsSet();

    // Thresholds for detection
    this.CREDENTIAL_FORWARD_WINDOW = 10000; // 10 seconds
    this.TOKEN_EXFILTRATION_WINDOW = 30000; // 30 seconds
    this.MIN_CREDENTIAL_LENGTH = 3;
    this.MAX_CREDENTIAL_LENGTH = 100;
  }

  // Main detection entry point
  async analyzeRequest(requestDetails, requestBody = null) {
    const findings = [];

    try {
      // Check if request is extension-initiated
      const extensionInfo = this.identifyExtensionInitiator(requestDetails);
      if (!extensionInfo.isExtensionInitiated) {
        return findings; // Not an extension request
      }

      console.log(` Analyzing extension-initiated request from ${extensionInfo.extensionId}`);

      // Perform various malicious behavior checks
      const credentialTheft = await this.detectCredentialForwarding(requestDetails, requestBody, extensionInfo);
      const tokenExfiltration = await this.detectTokenExfiltration(requestDetails, requestBody, extensionInfo);
      const homographAttack = await this.detectHomographRedirect(requestDetails, extensionInfo);
      const dataExfiltration = await this.detectDataExfiltration(requestDetails, requestBody, extensionInfo);
      const reputationIssues = await this.checkExtensionReputation(extensionInfo.extensionId, requestDetails.url);

      // Collect all findings
      findings.push(...credentialTheft, ...tokenExfiltration, ...homographAttack, ...dataExfiltration, ...reputationIssues);

      // Store suspicious request for correlation
      if (findings.length > 0) {
        this.storeSuspiciousRequest(requestDetails, extensionInfo, findings);
      }

    } catch (error) {
      console.error('Extension analysis failed:', error);
    }

    return findings;
  }

  // Identify if request is extension-initiated and extract extension info
  identifyExtensionInitiator(requestDetails) {
    const result = {
      isExtensionInitiated: false,
      extensionId: null,
      extensionName: null,
      confidence: 0
    };

    try {
      // Check initiator URL for extension pattern
      if (requestDetails.initiator && requestDetails.initiator.startsWith('chrome-extension://')) {
        result.isExtensionInitiated = true;
        result.extensionId = requestDetails.initiator.split('/')[2];
        result.confidence = 1.0;
        return result;
      }

      // Check for other extension indicators in headers or request context
      if (requestDetails.requestHeaders) {
        const userAgent = requestDetails.requestHeaders.find(h => h.name.toLowerCase() === 'user-agent');
        if (userAgent && userAgent.value.includes('Extension')) {
          result.isExtensionInitiated = true;
          result.confidence = 0.7;
        }
      }

      // Check for programmatic request patterns (common in malicious extensions)
      if (requestDetails.type === 'xmlhttprequest' &&
          !requestDetails.initiator &&
          requestDetails.tabId === -1) {
        result.isExtensionInitiated = true;
        result.confidence = 0.6;
      }

    } catch (error) {
      console.error('Extension initiator identification failed:', error);
    }

    return result;
  }

  // Detect credential forwarding/theft
  async detectCredentialForwarding(requestDetails, requestBody, extensionInfo) {
    const findings = [];

    try {
      if (!requestBody || typeof requestBody !== 'string') {
        return findings;
      }

      // Look for credential-like data in request body
      const credentialData = this.extractCredentialData(requestBody);
      if (credentialData.length === 0) {
        return findings;
      }

      console.log(` Found ${credentialData.length} potential credentials in extension request`);

      // Check if this appears to be credential forwarding
      const destinationDomain = new URL(requestDetails.url).hostname;
      const isLegitimate = this.legitimateDomains.has(destinationDomain);

      // Check for recent legitimate login attempts
      const recentLogins = this.getRecentLoginAttempts();

      for (const credential of credentialData) {
        // Look for matching credentials sent to legitimate sites recently
        const matchingLogin = recentLogins.find(login =>
          this.credentialsMatch(credential, login.credentialData) &&
          (Date.now() - login.timestamp) < this.CREDENTIAL_FORWARD_WINDOW
        );

        if (matchingLogin && !isLegitimate) {
          findings.push({
            type: 'CREDENTIAL_THEFT',
            severity: 'CRITICAL',
            confidence: 0.9,
            message: `Extension ${extensionInfo.extensionId} forwarded credentials to suspicious domain ${destinationDomain}`,
            details: {
              extensionId: extensionInfo.extensionId,
              legitimateTarget: matchingLogin.domain,
              maliciousTarget: destinationDomain,
              credentialType: credential.type,
              timeGap: Date.now() - matchingLogin.timestamp
            },
            exploitation: `This extension appears to be stealing credentials entered on ${matchingLogin.domain}. Disable it immediately and change your passwords.`,
            mitigation: 'Disable the extension, scan for malware, and change all recently used passwords.'
          });
        }
      }

      // Store credential data for future correlation
      this.storeCredentialPattern(credentialData, requestDetails, extensionInfo);

    } catch (error) {
      console.error('Credential forwarding detection failed:', error);
    }

    return findings;
  }

  // Detect token exfiltration
  async detectTokenExfiltration(requestDetails, requestBody, extensionInfo) {
    const findings = [];

    try {
      // Check headers for stolen tokens
      const authHeaders = this.extractAuthTokens(requestDetails.requestHeaders || []);
      let bodyTokens = [];

      // Check body for tokens
      if (requestBody) {
        bodyTokens = this.extractTokensFromBody(requestBody);
      }

      const allTokens = [...authHeaders, ...bodyTokens];
      if (allTokens.length === 0) {
        return findings;
      }

      console.log(` Found ${allTokens.length} potential tokens in extension request`);

      const destinationDomain = new URL(requestDetails.url).hostname;

      for (const token of allTokens) {
        // Check if token belongs to a different service
        const tokenOrigin = this.identifyTokenOrigin(token);

        if (tokenOrigin && tokenOrigin.domain !== destinationDomain) {
          // This is a token being sent to a different domain than it originated from
          const confidence = this.calculateTokenTheftConfidence(token, tokenOrigin, destinationDomain);

          if (confidence > 0.7) {
            findings.push({
              type: 'TOKEN_EXFILTRATION',
              severity: 'CRITICAL',
              confidence: confidence,
              message: `Extension ${extensionInfo.extensionId} exfiltrated ${tokenOrigin.service} token to ${destinationDomain}`,
              details: {
                extensionId: extensionInfo.extensionId,
                tokenType: token.type,
                originalService: tokenOrigin.service,
                originalDomain: tokenOrigin.domain,
                exfiltrationTarget: destinationDomain,
                tokenPreview: token.value.substring(0, 20) + '...'
              },
              exploitation: `Your ${tokenOrigin.service} session token was stolen and sent to ${destinationDomain}. This could allow complete account takeover.`,
              mitigation: 'Immediately log out of all sessions, disable the extension, and check for unauthorized account activity.'
            });
          }
        }
      }

    } catch (error) {
      console.error('Token exfiltration detection failed:', error);
    }

    return findings;
  }

  // Detect homograph/typosquatting redirects
  async detectHomographRedirect(requestDetails, extensionInfo) {
    const findings = [];

    try {
      const targetDomain = new URL(requestDetails.url).hostname;

      // Check if domain is a homograph of a popular site
      const homographAnalysis = this.analyzeHomograph(targetDomain);

      if (homographAnalysis.isHomograph && homographAnalysis.confidence > 0.8) {
        findings.push({
          type: 'HOMOGRAPH_REDIRECT',
          severity: 'HIGH',
          confidence: homographAnalysis.confidence,
          message: `Extension ${extensionInfo.extensionId} redirected to homograph domain ${targetDomain}`,
          details: {
            extensionId: extensionInfo.extensionId,
            homographDomain: targetDomain,
            legitimateDomain: homographAnalysis.legitimateDomain,
            similarity: homographAnalysis.similarity,
            homographType: homographAnalysis.type
          },
          exploitation: `This looks like a phishing attempt. The domain ${targetDomain} is designed to look like ${homographAnalysis.legitimateDomain}.`,
          mitigation: 'Do not enter any credentials. Close the page and disable the extension.'
        });
      }

      // Check for suspicious TLD usage
      const tld = targetDomain.split('.').pop();
      const suspiciousTLDs = ['tk', 'ml', 'ga', 'cf', 'click', 'download', 'zip'];

      if (suspiciousTLDs.includes(tld) && homographAnalysis.containsBrandName) {
        findings.push({
          type: 'SUSPICIOUS_TLD_REDIRECT',
          severity: 'MEDIUM',
          confidence: 0.7,
          message: `Extension redirected to brand name domain with suspicious TLD: ${targetDomain}`,
          details: {
            extensionId: extensionInfo.extensionId,
            domain: targetDomain,
            suspiciousTLD: tld,
            brandName: homographAnalysis.brandName
          },
          exploitation: 'Suspicious domain with free TLD hosting often used for phishing.',
          mitigation: 'Verify the authentic website URL and avoid entering sensitive information.'
        });
      }

    } catch (error) {
      console.error('Homograph detection failed:', error);
    }

    return findings;
  }

  // Detect data exfiltration
  async detectDataExfiltration(requestDetails, requestBody, extensionInfo) {
    const findings = [];

    try {
      if (!requestBody || requestBody.length < 100) {
        return findings; // Not enough data to be exfiltration
      }

      const bodySize = requestBody.length;
      const destinationDomain = new URL(requestDetails.url).hostname;

      // Check if this is a large data transfer to a suspicious domain
      if (bodySize > 10000 && !this.legitimateDomains.has(destinationDomain)) {
        // Analyze content for sensitive data patterns
        const sensitiveDataFound = this.detectSensitiveDataPatterns(requestBody);

        if (sensitiveDataFound.length > 0) {
          findings.push({
            type: 'DATA_EXFILTRATION',
            severity: 'HIGH',
            confidence: 0.8,
            message: `Extension ${extensionInfo.extensionId} exfiltrated ${bodySize} bytes of potentially sensitive data`,
            details: {
              extensionId: extensionInfo.extensionId,
              destination: destinationDomain,
              dataSize: bodySize,
              sensitiveDataTypes: sensitiveDataFound,
              method: requestDetails.method
            },
            exploitation: 'Large amounts of data being sent to unknown domain, possibly including personal information.',
            mitigation: 'Disable the extension and check what data may have been compromised.'
          });
        }
      }

    } catch (error) {
      console.error('Data exfiltration detection failed:', error);
    }

    return findings;
  }

  // Check extension reputation
  async checkExtensionReputation(extensionId, targetUrl) {
    const findings = [];

    try {
      if (!extensionId) return findings;

      // Check cached reputation first
      let reputation = this.extensionReputation.get(extensionId);

      if (!reputation) {
        // Calculate reputation based on behavior patterns
        reputation = await this.calculateExtensionReputation(extensionId);
        this.extensionReputation.set(extensionId, reputation);
      }

      if (reputation.riskScore > 70) {
        findings.push({
          type: 'MALICIOUS_EXTENSION_DETECTED',
          severity: 'HIGH',
          confidence: reputation.confidence,
          message: `Extension ${extensionId} has high risk score: ${reputation.riskScore}/100`,
          details: {
            extensionId: extensionId,
            riskScore: reputation.riskScore,
            riskFactors: reputation.riskFactors,
            targetUrl: targetUrl
          },
          exploitation: 'This extension has exhibited multiple suspicious behaviors indicating malicious intent.',
          mitigation: 'Remove this extension immediately and scan for additional malware.'
        });
      }

    } catch (error) {
      console.error('Extension reputation check failed:', error);
    }

    return findings;
  }

  // Extract credential-like data from request body
  extractCredentialData(requestBody) {
    const credentials = [];

    try {
      // Try to parse as form data or JSON
      let data = {};

      if (requestBody.includes('=') && requestBody.includes('&')) {
        // Form data
        const params = new URLSearchParams(requestBody);
        for (const [key, value] of params) {
          data[key] = value;
        }
      } else {
        try {
          // JSON data
          data = JSON.parse(requestBody);
        } catch (e) {
          // Raw text search
          data = { body: requestBody };
        }
      }

      // Look for credential patterns
      for (const [key, value] of Object.entries(data)) {
        if (typeof value === 'string' &&
            value.length >= this.MIN_CREDENTIAL_LENGTH &&
            value.length <= this.MAX_CREDENTIAL_LENGTH) {

          const keyLower = key.toLowerCase();

          if (keyLower.includes('pass') || keyLower.includes('pwd')) {
            credentials.push({ type: 'password', key, value, confidence: 0.9 });
          } else if (keyLower.includes('user') || keyLower.includes('email') || keyLower.includes('login')) {
            credentials.push({ type: 'username', key, value, confidence: 0.8 });
          } else if (keyLower.includes('pin') || keyLower.includes('otp') || keyLower.includes('code')) {
            credentials.push({ type: 'code', key, value, confidence: 0.7 });
          }
        }
      }

    } catch (error) {
      console.error('Credential extraction failed:', error);
    }

    return credentials;
  }

  // Extract authentication tokens from headers
  extractAuthTokens(headers) {
    const tokens = [];

    try {
      for (const header of headers) {
        const name = header.name.toLowerCase();
        const value = header.value;

        if (name === 'authorization') {
          if (value.startsWith('Bearer ')) {
            tokens.push({ type: 'bearer', value: value.substring(7), header: name });
          } else if (value.startsWith('Basic ')) {
            tokens.push({ type: 'basic', value: value.substring(6), header: name });
          }
        } else if (name === 'cookie' && value.includes('token')) {
          // Extract token from cookies
          const tokenMatch = value.match(/(\w*token\w*=([^;]+))/gi);
          if (tokenMatch) {
            tokenMatch.forEach(match => {
              const [, , tokenValue] = match.match(/(\w*token\w*)=([^;]+)/i);
              tokens.push({ type: 'cookie', value: tokenValue, header: name });
            });
          }
        }
      }

    } catch (error) {
      console.error('Token extraction from headers failed:', error);
    }

    return tokens;
  }

  // Extract tokens from request body
  extractTokensFromBody(body) {
    const tokens = [];

    try {
      // Look for JWT patterns
      const jwtPattern = /eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g;
      const jwtMatches = body.match(jwtPattern);

      if (jwtMatches) {
        jwtMatches.forEach(jwt => {
          tokens.push({ type: 'jwt', value: jwt, source: 'body' });
        });
      }

      // Look for other token patterns
      const tokenPatterns = [
        /access_token["\s:=]+([A-Za-z0-9-_]+)/gi,
        /session["\s:=]+([A-Za-z0-9-_]+)/gi,
        /auth["\s:=]+([A-Za-z0-9-_]+)/gi
      ];

      tokenPatterns.forEach(pattern => {
        const matches = body.match(pattern);
        if (matches) {
          matches.forEach(match => {
            const tokenValue = match.split(/["\s:=]+/)[1];
            if (tokenValue && tokenValue.length > 10) {
              tokens.push({ type: 'access', value: tokenValue, source: 'body' });
            }
          });
        }
      });

    } catch (error) {
      console.error('Token extraction from body failed:', error);
    }

    return tokens;
  }

  // Analyze domain for homograph attacks
  analyzeHomograph(domain) {
    const result = {
      isHomograph: false,
      confidence: 0,
      legitimateDomain: null,
      similarity: 0,
      type: null,
      brandName: null,
      containsBrandName: false
    };

    try {
      // Check against known legitimate domains
      for (const [legitDomain, variations] of this.homographPatterns) {
        const similarity = this.calculateStringSimilarity(domain, legitDomain);

        if (similarity > 0.7 && similarity < 1.0) {
          result.isHomograph = true;
          result.confidence = similarity;
          result.legitimateDomain = legitDomain;
          result.similarity = similarity;
          result.type = 'typosquatting';
          break;
        }

        // Check for character substitution patterns
        if (this.hasHomographCharacters(domain, legitDomain)) {
          result.isHomograph = true;
          result.confidence = 0.85;
          result.legitimateDomain = legitDomain;
          result.type = 'homograph_characters';
          break;
        }
      }

      // Check for brand names
      const brands = ['google', 'facebook', 'amazon', 'microsoft', 'apple', 'paypal', 'github'];
      for (const brand of brands) {
        if (domain.includes(brand)) {
          result.containsBrandName = true;
          result.brandName = brand;
          break;
        }
      }

    } catch (error) {
      console.error('Homograph analysis failed:', error);
    }

    return result;
  }

  // Initialize homograph patterns for popular sites
  initializeHomographPatterns() {
    return new Map([
      ['google.com', ['g00gle.com', 'gooogle.com', 'googIe.com']],
      ['facebook.com', ['faceb00k.com', 'facebοοk.com']],
      ['amazon.com', ['amaz0n.com', 'amazοn.com']],
      ['microsoft.com', ['micr0soft.com', 'microsοft.com']],
      ['paypal.com', ['paypaI.com', 'ρaypal.com']],
      ['github.com', ['github.c0m', 'gìthub.com']],
      ['apple.com', ['appIe.com', 'αpple.com']]
    ]);
  }

  // Initialize set of legitimate domains
  initializeLegitimateDomainsSet() {
    return new Set([
      'google.com', 'googleapis.com', 'gstatic.com',
      'facebook.com', 'fbcdn.net',
      'amazon.com', 'amazonaws.com',
      'microsoft.com', 'microsoftonline.com',
      'apple.com', 'icloud.com',
      'github.com', 'githubusercontent.com',
      'paypal.com',
      'twitter.com', 'x.com',
      'linkedin.com',
      'dropbox.com',
      'zoom.us'
    ]);
  }

  // Calculate string similarity (Levenshtein-based)
  calculateStringSimilarity(str1, str2) {
    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;

    if (longer.length === 0) return 1.0;

    const distance = this.levenshteinDistance(longer, shorter);
    return (longer.length - distance) / longer.length;
  }

  // Levenshtein distance calculation
  levenshteinDistance(str1, str2) {
    const matrix = [];

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  // Check for homograph character substitutions
  hasHomographCharacters(domain, legitimate) {
    const homographMap = {
      'o': ['0', 'ο', 'ο'],
      'a': ['α', 'а'],
      'e': ['е'],
      'i': ['і', 'ι'],
      'l': ['I', '1', 'ǀ'],
      'm': ['м'],
      'n': ['и'],
      'p': ['ρ'],
      'r': ['г'],
      'y': ['у']
    };

    // Simple check for character substitution
    if (domain.length !== legitimate.length) return false;

    let substitutions = 0;
    for (let i = 0; i < domain.length; i++) {
      const domainChar = domain[i];
      const legitChar = legitimate[i];

      if (domainChar !== legitChar) {
        const possibleSubs = homographMap[legitChar];
        if (possibleSubs && possibleSubs.includes(domainChar)) {
          substitutions++;
        } else {
          return false; // Non-homograph difference
        }
      }
    }

    return substitutions > 0 && substitutions <= 3; // 1-3 character substitutions
  }

  // Detect sensitive data patterns in request body
  detectSensitiveDataPatterns(body) {
    const patterns = [];

    // Email patterns
    if (/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(body)) {
      patterns.push('email_addresses');
    }

    // Credit card patterns
    if (/\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/.test(body)) {
      patterns.push('credit_card_numbers');
    }

    // SSN patterns
    if (/\b\d{3}-\d{2}-\d{4}\b/.test(body)) {
      patterns.push('social_security_numbers');
    }

    // Phone number patterns
    if (/\b\d{3}[-.]?\d{3}[-.]?\d{4}\b/.test(body)) {
      patterns.push('phone_numbers');
    }

    // Large text blocks (potentially personal data)
    if (body.length > 5000) {
      patterns.push('large_text_content');
    }

    return patterns;
  }

  // Helper methods for data correlation and storage
  storeSuspiciousRequest(requestDetails, extensionInfo, findings) {
    const key = `${extensionInfo.extensionId}_${Date.now()}`;
    this.suspiciousRequests.set(key, {
      timestamp: Date.now(),
      requestDetails,
      extensionInfo,
      findings
    });
  }

  storeCredentialPattern(credentialData, requestDetails, extensionInfo) {
    const key = `${extensionInfo.extensionId}_${new URL(requestDetails.url).hostname}`;
    this.credentialPatterns.set(key, {
      timestamp: Date.now(),
      credentialData,
      domain: new URL(requestDetails.url).hostname,
      extensionInfo
    });
  }

  getRecentLoginAttempts() {
    // This would integrate with the main Hera system to get recent login attempts
    // For now, return empty array
    return [];
  }

  credentialsMatch(credential1, credential2) {
    // Simple credential matching logic
    return credential1.value === credential2.value ||
           (credential1.type === credential2.type &&
            this.calculateStringSimilarity(credential1.value, credential2.value) > 0.9);
  }

  identifyTokenOrigin(token) {
    // Analyze token to determine likely origin service
    if (token.type === 'jwt') {
      try {
        const payload = JSON.parse(atob(token.value.split('.')[1]));
        if (payload.iss) {
          const issuer = payload.iss;
          return {
            service: this.mapIssuerToService(issuer),
            domain: new URL(issuer).hostname
          };
        }
      } catch (e) {
        // Invalid JWT
      }
    }

    return null;
  }

  mapIssuerToService(issuer) {
    const serviceMap = {
      'accounts.google.com': 'Google',
      'login.microsoftonline.com': 'Microsoft',
      'www.facebook.com': 'Facebook',
      'github.com': 'GitHub'
    };

    for (const [domain, service] of Object.entries(serviceMap)) {
      if (issuer.includes(domain)) {
        return service;
      }
    }

    return 'Unknown Service';
  }

  calculateTokenTheftConfidence(token, tokenOrigin, destinationDomain) {
    let confidence = 0.5; // Base confidence

    // High confidence if token from major service going to unknown domain
    if (['Google', 'Microsoft', 'Facebook', 'GitHub'].includes(tokenOrigin.service)) {
      if (!this.legitimateDomains.has(destinationDomain)) {
        confidence += 0.3;
      }
    }

    // Increase confidence for JWT tokens (more valuable)
    if (token.type === 'jwt') {
      confidence += 0.2;
    }

    return Math.min(1.0, confidence);
  }

  async calculateExtensionReputation(extensionId) {
    // Calculate reputation based on observed behaviors
    let riskScore = 0;
    const riskFactors = [];

    // Check request patterns
    const extensionRequests = Array.from(this.suspiciousRequests.values())
      .filter(req => req.extensionInfo.extensionId === extensionId);

    if (extensionRequests.length > 10) {
      riskScore += 20;
      riskFactors.push('high_request_volume');
    }

    // Check for multiple suspicious domains
    const domains = new Set(extensionRequests.map(req => new URL(req.requestDetails.url).hostname));
    if (domains.size > 5) {
      riskScore += 30;
      riskFactors.push('multiple_suspicious_domains');
    }

    // Check for findings
    const totalFindings = extensionRequests.reduce((sum, req) => sum + req.findings.length, 0);
    if (totalFindings > 0) {
      riskScore += totalFindings * 15;
      riskFactors.push('security_violations_detected');
    }

    return {
      riskScore: Math.min(100, riskScore),
      confidence: 0.8,
      riskFactors,
      lastUpdated: Date.now()
    };
  }

  // Clean up old data
  cleanup() {
    const now = Date.now();
    const maxAge = 3600000; // 1 hour

    // Clean suspicious requests
    for (const [key, value] of this.suspiciousRequests.entries()) {
      if (now - value.timestamp > maxAge) {
        this.suspiciousRequests.delete(key);
      }
    }

    // Clean credential patterns
    for (const [key, value] of this.credentialPatterns.entries()) {
      if (now - value.timestamp > maxAge) {
        this.credentialPatterns.delete(key);
      }
    }
  }
}

export { HeraMaliciousExtensionDetector };