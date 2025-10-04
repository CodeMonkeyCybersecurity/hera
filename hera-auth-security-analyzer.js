// Hera Authentication Security Analyzer
// Analyzes passphrase strength, MFA usage, and passkey opportunities

class HeraAuthSecurityAnalyzer {
  constructor() {
    this.entropyThresholds = {
      weak: 30,      // < 30 bits: very weak
      poor: 40,      // 30-40 bits: poor
      fair: 50,      // 40-50 bits: fair
      good: 60,      // 50-60 bits: good
      strong: 70     // 60+ bits: strong
    };

    this.commonPasswords = new Set([
      'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
      'admin', 'letmein', 'welcome', 'monkey', '1234567890', 'dragon',
      'sunshine', 'princess', 'football', 'iloveyou', 'charlie', 'aa123456'
    ]);

    this.weakPatterns = [
      /^(.)\1{3,}$/,                    // Repeated characters (aaaa)
      /^(..)\1{2,}$/,                   // Repeated pairs (abab)
      /^(abc|123|qwe|asd|zxc)/i,        // Keyboard patterns
      /^(.+)\1$/,                       // Doubled patterns (passpass)
      /^(.*)(19|20)\d{2}$/,            // Ends with year
      /^[a-z]+\d{1,4}$/i,              // Word + numbers
      /^(password|pass|admin|user|login)/i // Common prefixes
    ];

    this.passwordlessSignals = [
      'webauthn', 'fido', 'passkey', 'biometric', 'fingerprint',
      'face-id', 'touch-id', 'platform-authenticator', 'security-key'
    ];

    this.mfaSignals = [
      'totp', 'hotp', 'sms', 'authenticator', 'google-authenticator',
      'authy', '2fa', 'mfa', 'two-factor', 'multi-factor', 'otp'
    ];
  }

  // Main analysis entry point
  analyzeAuthenticationSecurity(requestData, authFlow) {
    const findings = [];

    try {
      // Analyze password/passphrase strength
      const passphraseFindings = this.analyzePassphraseSecurity(requestData);
      findings.push(...passphraseFindings);

      // Analyze MFA usage
      const mfaFindings = this.analyzeMFASecurity(requestData, authFlow);
      findings.push(...mfaFindings);

      // Check for passkey opportunities
      const passkeyFindings = this.analyzePasskeyOpportunities(requestData, authFlow);
      findings.push(...passkeyFindings);

      // Analyze authentication flow security
      const flowFindings = this.analyzeAuthFlowSecurity(authFlow);
      findings.push(...flowFindings);

    } catch (error) {
      console.error('Auth security analysis failed:', error);
    }

    return findings;
  }

  // Analyze passphrase/password strength
  analyzePassphraseSecurity(requestData) {
    const findings = [];
    const body = requestData.requestBody || '';
    const url = requestData.url || '';

    // Extract potential passwords from various formats
    const passwords = this.extractPasswords(body, url);

    passwords.forEach(password => {
      const analysis = this.analyzePasswordStrength(password);

      if (analysis.entropy < this.entropyThresholds.weak) {
        findings.push({
          type: 'VERY_WEAK_PASSWORD',
          severity: 'CRITICAL',
          message: `Password has very low entropy (${Math.round(analysis.entropy)} bits). Extremely vulnerable to attacks.`,
          details: {
            entropy: analysis.entropy,
            length: password.length,
            issues: analysis.issues,
            recommendations: analysis.recommendations
          },
          category: 'password_security'
        });
      } else if (analysis.entropy < this.entropyThresholds.poor) {
        findings.push({
          type: 'WEAK_PASSWORD',
          severity: 'HIGH',
          message: `Password has low entropy (${Math.round(analysis.entropy)} bits). Vulnerable to brute force attacks.`,
          details: {
            entropy: analysis.entropy,
            length: password.length,
            issues: analysis.issues,
            recommendations: analysis.recommendations
          },
          category: 'password_security'
        });
      } else if (analysis.entropy < this.entropyThresholds.fair) {
        findings.push({
          type: 'POOR_PASSWORD',
          severity: 'MEDIUM',
          message: `Password has moderate entropy (${Math.round(analysis.entropy)} bits). Consider strengthening.`,
          details: {
            entropy: analysis.entropy,
            length: password.length,
            issues: analysis.issues,
            recommendations: analysis.recommendations
          },
          category: 'password_security'
        });
      }

      // Check for common password patterns
      if (this.isCommonPassword(password)) {
        findings.push({
          type: 'COMMON_PASSWORD',
          severity: 'CRITICAL',
          message: 'Using a commonly known password. This is extremely dangerous.',
          details: {
            recommendation: 'Use a unique, randomly generated password or passphrase'
          },
          category: 'password_security'
        });
      }

      // Check for weak patterns
      const weakPattern = this.checkWeakPatterns(password);
      if (weakPattern) {
        findings.push({
          type: 'WEAK_PASSWORD_PATTERN',
          severity: 'HIGH',
          message: `Password uses predictable pattern: ${weakPattern}`,
          details: {
            pattern: weakPattern,
            recommendation: 'Avoid predictable patterns, keyboard walks, and repeated elements'
          },
          category: 'password_security'
        });
      }
    });

    return findings;
  }

  // Analyze MFA implementation
  analyzeMFASecurity(requestData, authFlow) {
    const findings = [];
    const body = requestData.requestBody || '';
    const headers = requestData.requestHeaders || [];
    const url = requestData.url || '';

    // Check if MFA is being used
    const mfaDetected = this.detectMFAUsage(body, headers, url, authFlow);

    if (!mfaDetected.hasMFA) {
      // Check if this is a high-risk login (admin, sensitive service)
      const isHighRisk = this.isHighRiskLogin(url, authFlow);

      if (isHighRisk) {
        findings.push({
          type: 'MISSING_MFA_HIGH_RISK',
          severity: 'HIGH',
          message: 'High-risk authentication without multi-factor authentication detected.',
          details: {
            service: this.identifyService(url),
            recommendation: 'Enable MFA for administrative and sensitive accounts',
            mfaOptions: ['TOTP authenticator app', 'Hardware security key', 'SMS (less secure)', 'Email (least secure)']
          },
          category: 'mfa_security'
        });
      } else {
        findings.push({
          type: 'MISSING_MFA',
          severity: 'MEDIUM',
          message: 'Authentication without multi-factor authentication.',
          details: {
            recommendation: 'Consider enabling MFA for additional security',
            benefits: ['Protects against password breaches', 'Prevents account takeovers', 'Required for many compliance standards']
          },
          category: 'mfa_security'
        });
      }
    } else {
      // Analyze MFA quality
      const mfaQuality = this.analyzeMFAQuality(mfaDetected);

      if (mfaQuality.hasWeakMFA) {
        findings.push({
          type: 'WEAK_MFA_METHOD',
          severity: 'MEDIUM',
          message: `Weak MFA method detected: ${mfaQuality.method}`,
          details: {
            currentMethod: mfaQuality.method,
            issues: mfaQuality.issues,
            betterOptions: ['TOTP authenticator', 'Hardware security key', 'Biometric authentication']
          },
          category: 'mfa_security'
        });
      }
    }

    return findings;
  }

  // Analyze passkey opportunities
  analyzePasskeyOpportunities(requestData, authFlow) {
    const findings = [];
    const url = requestData.url || '';
    const userAgent = this.getUserAgent(requestData.requestHeaders);

    // Check if passkeys are supported but not used
    const supportsPasskeys = this.checkPasskeySupport(userAgent, url);
    const usesPasskeys = this.detectPasskeyUsage(requestData, authFlow);

    if (supportsPasskeys && !usesPasskeys) {
      const service = this.identifyService(url);
      const passkeySupport = this.checkServicePasskeySupport(service);

      if (passkeySupport.supported) {
        findings.push({
          type: 'PASSKEY_OPPORTUNITY',
          severity: 'LOW',
          message: `${service} supports passkeys but you're using password authentication.`,
          details: {
            service: service,
            benefits: [
              'No passwords to remember or steal',
              'Phishing resistant',
              'Faster authentication',
              'Works across devices'
            ],
            howToEnable: passkeySupport.instructions || 'Check account security settings for passkey options'
          },
          category: 'passkey_opportunity'
        });
      }
    }

    // Check for phishing-resistant authentication need
    if (this.isPhishingTarget(url) && !usesPasskeys) {
      findings.push({
        type: 'PHISHING_RISK_NO_PASSKEY',
        severity: 'MEDIUM',
        message: 'High-value target without phishing-resistant authentication.',
        details: {
          risk: 'This service is commonly targeted by phishing attacks',
          recommendation: 'Use passkeys or hardware security keys for phishing resistance',
          alternatives: ['Hardware security key', 'Platform authenticator (Face ID/Touch ID/Windows Hello)']
        },
        category: 'phishing_protection'
      });
    }

    return findings;
  }

  // Analyze overall authentication flow security
  analyzeAuthFlowSecurity(authFlow) {
    const findings = [];

    // Check for insecure flows
    if (authFlow.hasPasswordInURL) {
      findings.push({
        type: 'PASSWORD_IN_URL',
        severity: 'CRITICAL',
        message: 'Password transmitted in URL parameters.',
        details: {
          risk: 'URLs are logged and can expose passwords',
          recommendation: 'Use POST body for sensitive data'
        },
        category: 'flow_security'
      });
    }

    if (authFlow.hasUnencryptedTransmission) {
      findings.push({
        type: 'UNENCRYPTED_AUTH',
        severity: 'CRITICAL',
        message: 'Authentication data transmitted over unencrypted connection.',
        details: {
          risk: 'Credentials can be intercepted',
          recommendation: 'Always use HTTPS for authentication'
        },
        category: 'flow_security'
      });
    }

    return findings;
  }

  // Calculate password entropy
  calculateEntropy(password) {
    if (!password || password.length === 0) return 0;

    const charset = this.getCharsetSize(password);
    return Math.log2(Math.pow(charset, password.length));
  }

  // Get character set size for entropy calculation
  getCharsetSize(password) {
    let charset = 0;

    if (/[a-z]/.test(password)) charset += 26;      // lowercase
    if (/[A-Z]/.test(password)) charset += 26;      // uppercase
    if (/[0-9]/.test(password)) charset += 10;      // numbers
    if (/[^a-zA-Z0-9]/.test(password)) charset += 32; // symbols (estimated)

    return Math.max(charset, 1);
  }

  // Comprehensive password strength analysis
  analyzePasswordStrength(password) {
    const entropy = this.calculateEntropy(password);
    const issues = [];
    const recommendations = [];

    // Length analysis
    if (password.length < 8) {
      issues.push('Too short (< 8 characters)');
      recommendations.push('Use at least 12 characters');
    } else if (password.length < 12) {
      issues.push('Short length (< 12 characters)');
      recommendations.push('Consider using 15+ characters');
    }

    // Character diversity
    if (!/[a-z]/.test(password)) {
      issues.push('No lowercase letters');
      recommendations.push('Add lowercase letters');
    }
    if (!/[A-Z]/.test(password)) {
      issues.push('No uppercase letters');
      recommendations.push('Add uppercase letters');
    }
    if (!/[0-9]/.test(password)) {
      issues.push('No numbers');
      recommendations.push('Add numbers');
    }
    if (!/[^a-zA-Z0-9]/.test(password)) {
      issues.push('No special characters');
      recommendations.push('Add symbols (!@#$%^&*)');
    }

    // Pattern analysis
    if (/(.)\1{2,}/.test(password)) {
      issues.push('Contains repeated characters');
      recommendations.push('Avoid repeated characters');
    }

    if (/^[a-zA-Z]+$/.test(password)) {
      issues.push('Only contains letters');
      recommendations.push('Mix letters, numbers, and symbols');
    }

    if (/^\d+$/.test(password)) {
      issues.push('Only contains numbers');
      recommendations.push('Add letters and symbols');
    }

    return {
      entropy,
      issues,
      recommendations,
      strength: this.getStrengthLevel(entropy)
    };
  }

  // Extract passwords from request data
  extractPasswords(body, url) {
    const passwords = [];

    try {
      // Try to parse as JSON
      const jsonData = JSON.parse(body);
      this.extractPasswordsFromObject(jsonData, passwords);
    } catch {
      // Try form data
      const formData = new URLSearchParams(body);
      for (const [key, value] of formData) {
        if (this.isPasswordField(key) && value && value.length > 0) {
          passwords.push(value);
        }
      }
    }

    // Check URL parameters (should be flagged as insecure)
    const urlParams = new URL(url).searchParams;
    for (const [key, value] of urlParams) {
      if (this.isPasswordField(key) && value && value.length > 0) {
        passwords.push(value);
      }
    }

    return passwords;
  }

  // Extract passwords from nested object
  extractPasswordsFromObject(obj, passwords, depth = 0) {
    if (depth > 3) return; // Prevent deep recursion

    for (const [key, value] of Object.entries(obj)) {
      if (this.isPasswordField(key) && typeof value === 'string' && value.length > 0) {
        passwords.push(value);
      } else if (typeof value === 'object' && value !== null) {
        this.extractPasswordsFromObject(value, passwords, depth + 1);
      }
    }
  }

  // Check if field name indicates password
  isPasswordField(fieldName) {
    const passwordFields = [
      'password', 'pass', 'passwd', 'pwd', 'secret', 'pin',
      'passphrase', 'auth_password', 'user_password', 'login_password'
    ];

    return passwordFields.some(field =>
      fieldName.toLowerCase().includes(field)
    );
  }

  // Check for common passwords
  isCommonPassword(password) {
    return this.commonPasswords.has(password.toLowerCase());
  }

  // Check for weak patterns
  checkWeakPatterns(password) {
    for (const pattern of this.weakPatterns) {
      if (pattern.test(password)) {
        if (pattern.source.includes('(.)\\1{3,}')) return 'repeated characters';
        if (pattern.source.includes('(..)\\1{2,}')) return 'repeated pairs';
        if (pattern.source.includes('abc|123|qwe')) return 'keyboard pattern';
        if (pattern.source.includes('(.+)\\1')) return 'doubled pattern';
        if (pattern.source.includes('19|20')) return 'contains year';
        if (pattern.source.includes('[a-z]+\\d{1,4}')) return 'word + numbers';
        if (pattern.source.includes('password|pass|admin')) return 'common prefix';
      }
    }
    return null;
  }

  // Detect MFA usage
  detectMFAUsage(body, headers, url, authFlow) {
    const content = (body + ' ' + url + ' ' + JSON.stringify(headers)).toLowerCase();

    const hasMFA = this.mfaSignals.some(signal => content.includes(signal));

    let method = 'unknown';
    if (content.includes('sms')) method = 'SMS';
    else if (content.includes('totp') || content.includes('authenticator')) method = 'TOTP';
    else if (content.includes('email')) method = 'Email';
    else if (content.includes('push')) method = 'Push notification';

    return { hasMFA, method };
  }

  // Analyze MFA quality
  analyzeMFAQuality(mfaDetection) {
    const weakMethods = ['sms', 'email'];
    const hasWeakMFA = weakMethods.includes(mfaDetection.method.toLowerCase());

    const issues = [];
    if (mfaDetection.method.toLowerCase() === 'sms') {
      issues.push('SMS is vulnerable to SIM swapping attacks');
      issues.push('SMS can be intercepted');
    }
    if (mfaDetection.method.toLowerCase() === 'email') {
      issues.push('Email MFA is only as secure as the email account');
      issues.push('Email can be compromised separately');
    }

    return {
      hasWeakMFA,
      method: mfaDetection.method,
      issues
    };
  }

  // Check if login is high risk
  isHighRiskLogin(url, authFlow) {
    const highRiskPatterns = [
      'admin', 'administrator', 'root', 'sudo', 'management',
      'console', 'dashboard', 'control-panel', 'wp-admin',
      'cpanel', 'webmail', 'mail', 'email'
    ];

    const urlLower = url.toLowerCase();
    return highRiskPatterns.some(pattern => urlLower.includes(pattern));
  }

  // Identify service from URL
  identifyService(url) {
    try {
      const hostname = new URL(url).hostname.toLowerCase();

      // Common services
      if (hostname.includes('google')) return 'Google';
      if (hostname.includes('microsoft') || hostname.includes('live.com') || hostname.includes('outlook')) return 'Microsoft';
      if (hostname.includes('apple') || hostname.includes('icloud')) return 'Apple';
      if (hostname.includes('github')) return 'GitHub';
      if (hostname.includes('gitlab')) return 'GitLab';
      if (hostname.includes('aws') || hostname.includes('amazon')) return 'AWS';
      if (hostname.includes('facebook') || hostname.includes('meta')) return 'Facebook/Meta';
      if (hostname.includes('twitter') || hostname.includes('x.com')) return 'Twitter/X';
      if (hostname.includes('linkedin')) return 'LinkedIn';
      if (hostname.includes('dropbox')) return 'Dropbox';
      if (hostname.includes('slack')) return 'Slack';
      if (hostname.includes('zoom')) return 'Zoom';

      return hostname;
    } catch {
      return 'Unknown service';
    }
  }

  // Check passkey support
  checkPasskeySupport(userAgent, url) {
    // Modern browsers support WebAuthn/passkeys
    const supportsWebAuthn = userAgent && (
      userAgent.includes('Chrome') ||
      userAgent.includes('Firefox') ||
      userAgent.includes('Safari') ||
      userAgent.includes('Edge')
    );

    return supportsWebAuthn;
  }

  // Detect passkey usage
  detectPasskeyUsage(requestData, authFlow) {
    const content = (requestData.requestBody + ' ' + requestData.url).toLowerCase();
    return this.passwordlessSignals.some(signal => content.includes(signal));
  }

  // Check service passkey support
  checkServicePasskeySupport(service) {
    const supportedServices = {
      'Google': {
        supported: true,
        instructions: 'Go to myaccount.google.com → Security → 2-Step Verification → Security keys'
      },
      'Microsoft': {
        supported: true,
        instructions: 'Go to Security settings → More security options → Set up a security key'
      },
      'Apple': {
        supported: true,
        instructions: 'System Settings → Sign-In & Security → Two-Factor Authentication'
      },
      'GitHub': {
        supported: true,
        instructions: 'Settings → Password and authentication → Security keys'
      },
      'AWS': {
        supported: true,
        instructions: 'IAM → Users → Security credentials → Multi-factor authentication'
      }
    };

    return supportedServices[service] || { supported: false };
  }

  // Check if service is commonly phished
  isPhishingTarget(url) {
    const commonTargets = [
      'google', 'microsoft', 'apple', 'amazon', 'paypal', 'bank',
      'github', 'facebook', 'instagram', 'twitter', 'linkedin'
    ];

    const urlLower = url.toLowerCase();
    return commonTargets.some(target => urlLower.includes(target));
  }

  // Get user agent from headers
  getUserAgent(headers) {
    if (!headers) return '';

    const userAgentHeader = headers.find(h => h.name.toLowerCase() === 'user-agent');
    return userAgentHeader ? userAgentHeader.value : '';
  }

  // Get strength level from entropy
  getStrengthLevel(entropy) {
    if (entropy < this.entropyThresholds.weak) return 'very weak';
    if (entropy < this.entropyThresholds.poor) return 'weak';
    if (entropy < this.entropyThresholds.fair) return 'fair';
    if (entropy < this.entropyThresholds.good) return 'good';
    return 'strong';
  }
}

// Export for ES6 modules
export { HeraAuthSecurityAnalyzer };