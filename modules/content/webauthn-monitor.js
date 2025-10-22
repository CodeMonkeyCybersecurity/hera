// WebAuthn Monitor - Content Script
// Intercepts navigator.credentials.create() and .get() calls to detect WebAuthn vulnerabilities
// Reference: https://www.w3.org/TR/webauthn-2/

(function() {
  'use strict';

  // Track challenges to detect reuse
  const challengeHistory = new Map(); // challenge hash -> { timestamp, count }
  const credentialCounters = new Map(); // credentialId -> lastCounter

  // Store original methods
  const originalCreate = navigator.credentials.create;
  const originalGet = navigator.credentials.get;

  /**
   * Analyze WebAuthn registration (create) options for security issues
   */
  function analyzeCreateOptions(options) {
    const issues = [];

    if (!options || !options.publicKey) {
      return issues;
    }

    const publicKey = options.publicKey;

    // P0-1: Weak challenge entropy (< 16 bytes / 128 bits)
    if (publicKey.challenge) {
      const challengeLength = publicKey.challenge.byteLength || publicKey.challenge.length || 0;

      if (challengeLength < 16) {
        issues.push({
          severity: 'CRITICAL',
          type: 'WEAK_WEBAUTHN_CHALLENGE',
          message: `WebAuthn challenge too short: ${challengeLength} bytes (minimum 16 recommended)`,
          recommendation: 'Use cryptographically random challenge >= 128 bits (16 bytes)',
          cvss: 8.5,
          detail: 'Weak challenge allows brute force or collision attacks',
          reference: 'https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges',
          evidence: {
            challengeLength,
            minimumRecommended: 16,
            risk: 'Attacker can predict or brute force challenge'
          }
        });
      }

      // P0-2: Track challenge to detect reuse
      const challengeHash = hashChallenge(publicKey.challenge);
      const existing = challengeHistory.get(challengeHash);

      if (existing) {
        // Challenge reuse detected!
        issues.push({
          severity: 'CRITICAL',
          type: 'WEBAUTHN_CHALLENGE_REUSE',
          message: 'WebAuthn challenge reused (replay attack risk)',
          recommendation: 'Generate unique challenge for each authentication attempt',
          cvss: 9.0,
          detail: 'Challenge reuse allows replay attacks',
          reference: 'https://www.w3.org/TR/webauthn-2/#sctn-cryptographic-challenges',
          evidence: {
            challengeHash,
            firstSeen: new Date(existing.timestamp).toISOString(),
            reuseCount: existing.count + 1,
            risk: 'Attacker can capture and replay authentication response'
          }
        });
        existing.count++;
      } else {
        challengeHistory.set(challengeHash, { timestamp: Date.now(), count: 1 });
      }

      // Clean old challenges (older than 5 minutes)
      cleanOldChallenges();
    }

    // P0-3: Missing user verification (should be "required" for sensitive operations)
    const userVerification = publicKey.authenticatorSelection?.userVerification;
    if (userVerification === 'discouraged' || userVerification === 'preferred') {
      issues.push({
        severity: 'HIGH',
        type: 'WEAK_USER_VERIFICATION',
        message: `WebAuthn userVerification set to "${userVerification}" instead of "required"`,
        recommendation: 'Set userVerification: "required" for sensitive operations',
        cvss: 7.0,
        detail: 'Authenticator may not verify user presence (no PIN/biometric)',
        cve: 'CVE-2022-27262',
        reference: 'https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-userverification',
        evidence: {
          userVerification,
          risk: 'Stolen physical security key works without PIN/biometric',
          recommendation: 'Use "required" for banking, healthcare, admin access'
        }
      });
    }

    // P0-4: Missing timeout
    if (!publicKey.timeout || publicKey.timeout > 60000) {
      const severity = !publicKey.timeout ? 'MEDIUM' : 'LOW';
      issues.push({
        severity,
        type: 'WEBAUTHN_MISSING_TIMEOUT',
        message: publicKey.timeout ?
          `WebAuthn timeout too long: ${publicKey.timeout}ms` :
          'WebAuthn request has no timeout',
        recommendation: 'Set timeout between 30-60 seconds',
        cvss: 5.0,
        detail: 'Indefinite or excessive authentication window',
        evidence: {
          timeout: publicKey.timeout || 'none',
          recommended: '30000-60000ms',
          risk: 'Extended time for phishing/social engineering'
        }
      });
    }

    // P0-5: Cross-origin credential theft attempt
    const rpId = publicKey.rp?.id;
    const currentOrigin = window.location.hostname;

    if (rpId && !isValidRpId(rpId, currentOrigin)) {
      issues.push({
        severity: 'CRITICAL',
        type: 'WEBAUTHN_CROSS_ORIGIN_ATTEMPT',
        message: 'WebAuthn rpId does not match current origin',
        recommendation: 'Reject immediately - possible phishing attack',
        cvss: 9.0,
        detail: 'Attempting to create credentials for different origin',
        reference: 'https://www.w3.org/TR/webauthn-2/#relying-party-identifier',
        evidence: {
          rpId,
          currentOrigin,
          risk: 'evil.com trying to use credentials from bank.com'
        }
      });
    }

    // P0-6: Weak public key algorithm
    if (publicKey.pubKeyCredParams) {
      const weakAlgs = publicKey.pubKeyCredParams.filter(param =>
        param.alg === -257 || // RS256 deprecated
        param.alg === -37    // PS256 deprecated
      );

      if (weakAlgs.length > 0) {
        issues.push({
          severity: 'HIGH',
          type: 'WEAK_WEBAUTHN_ALGORITHM',
          message: 'WebAuthn accepting deprecated algorithms',
          recommendation: 'Use only ES256 (alg=-7) or EdDSA (alg=-8)',
          cvss: 7.0,
          detail: 'RS256 and PS256 deprecated for WebAuthn',
          evidence: {
            weakAlgorithms: weakAlgs.map(a => a.alg),
            recommended: 'ES256 (-7) or EdDSA (-8)'
          }
        });
      }
    }

    // MEDIUM: Resident key not required for passwordless
    if (publicKey.authenticatorSelection?.requireResidentKey === false) {
      issues.push({
        severity: 'MEDIUM',
        type: 'WEBAUTHN_NO_RESIDENT_KEY',
        message: 'WebAuthn not requiring resident keys for passwordless',
        recommendation: 'Set requireResidentKey: true for true passwordless authentication',
        cvss: 5.0,
        detail: 'User enumeration via username still possible',
        evidence: {
          requireResidentKey: false,
          impact: 'Not truly passwordless - username still required'
        }
      });
    }

    // MEDIUM: Backup eligibility warnings
    // (We can only check this in the response, not the request)

    return issues;
  }

  /**
   * Analyze WebAuthn authentication (get) options for security issues
   */
  function analyzeGetOptions(options) {
    const issues = [];

    if (!options || !options.publicKey) {
      return issues;
    }

    const publicKey = options.publicKey;

    // P0-1: Weak challenge entropy
    if (publicKey.challenge) {
      const challengeLength = publicKey.challenge.byteLength || publicKey.challenge.length || 0;

      if (challengeLength < 16) {
        issues.push({
          severity: 'CRITICAL',
          type: 'WEAK_WEBAUTHN_CHALLENGE',
          message: `WebAuthn challenge too short: ${challengeLength} bytes`,
          recommendation: 'Use cryptographically random challenge >= 128 bits',
          cvss: 8.5,
          evidence: { challengeLength, minimumRecommended: 16 }
        });
      }

      // P0-2: Challenge reuse detection
      const challengeHash = hashChallenge(publicKey.challenge);
      const existing = challengeHistory.get(challengeHash);

      if (existing) {
        issues.push({
          severity: 'CRITICAL',
          type: 'WEBAUTHN_CHALLENGE_REUSE',
          message: 'WebAuthn challenge reused',
          recommendation: 'Generate unique challenge for each authentication',
          cvss: 9.0,
          evidence: {
            challengeHash,
            reuseCount: existing.count + 1
          }
        });
        existing.count++;
      } else {
        challengeHistory.set(challengeHash, { timestamp: Date.now(), count: 1 });
      }

      cleanOldChallenges();
    }

    // P0-3: User verification
    const userVerification = publicKey.userVerification;
    if (userVerification === 'discouraged' || userVerification === 'preferred') {
      issues.push({
        severity: 'HIGH',
        type: 'WEAK_USER_VERIFICATION',
        message: `WebAuthn userVerification: "${userVerification}"`,
        recommendation: 'Use "required" for sensitive operations',
        cvss: 7.0,
        cve: 'CVE-2022-27262',
        evidence: { userVerification }
      });
    }

    // P0-4: Timeout check
    if (!publicKey.timeout || publicKey.timeout > 60000) {
      issues.push({
        severity: 'MEDIUM',
        type: 'WEBAUTHN_MISSING_TIMEOUT',
        message: publicKey.timeout ? `Timeout too long: ${publicKey.timeout}ms` : 'No timeout',
        recommendation: 'Set timeout 30-60 seconds',
        cvss: 5.0,
        evidence: { timeout: publicKey.timeout || 'none' }
      });
    }

    // P0-5: RP ID validation
    const rpId = publicKey.rpId;
    const currentOrigin = window.location.hostname;

    if (rpId && !isValidRpId(rpId, currentOrigin)) {
      issues.push({
        severity: 'CRITICAL',
        type: 'WEBAUTHN_CROSS_ORIGIN_ATTEMPT',
        message: 'WebAuthn rpId mismatch',
        recommendation: 'Reject - possible phishing',
        cvss: 9.0,
        evidence: { rpId, currentOrigin }
      });
    }

    return issues;
  }

  /**
   * Analyze WebAuthn response (authenticatorData) for security issues
   */
  function analyzeAuthenticatorResponse(response) {
    const issues = [];

    if (!response || !response.response) {
      return issues;
    }

    try {
      // P0-6: Credential counter validation (clone detection)
      const authenticatorData = response.response.authenticatorData;
      if (authenticatorData) {
        const counter = extractSignCount(authenticatorData);
        const credentialId = response.id || response.rawId;

        if (credentialId && counter !== null) {
          const lastCounter = credentialCounters.get(credentialId);

          if (lastCounter !== undefined) {
            if (counter <= lastCounter && counter !== 0 && lastCounter !== 0) {
              // Counter didn't increment - possible cloned authenticator!
              issues.push({
                severity: 'CRITICAL',
                type: 'WEBAUTHN_COUNTER_NOT_INCREMENTED',
                message: 'WebAuthn credential counter did not increment',
                recommendation: 'Reject authentication - possible cloned security key',
                cvss: 8.0,
                detail: 'Sign counter should strictly increase - clone detected',
                reference: 'https://www.w3.org/TR/webauthn-2/#sctn-sign-counter',
                evidence: {
                  currentCounter: counter,
                  expectedGreaterThan: lastCounter,
                  risk: 'Attacker cloned security key and using it in parallel'
                }
              });
            }
          }

          // Update stored counter
          credentialCounters.set(credentialId, counter);
        }
      }

      // Check for backup eligibility flag
      if (authenticatorData) {
        const flags = extractFlags(authenticatorData);
        if (flags && !flags.backupEligible) {
          issues.push({
            severity: 'MEDIUM',
            type: 'WEBAUTHN_NO_BACKUP',
            message: 'WebAuthn credential not backup eligible',
            recommendation: 'Warn user about single-device credential',
            cvss: 4.5,
            detail: 'User loses access if device lost',
            evidence: {
              backupEligible: false,
              risk: 'Account lockout if device lost or stolen'
            }
          });
        }
      }

    } catch (error) {
      console.warn('Hera: Error analyzing authenticator response:', error);
    }

    return issues;
  }

  // === HELPER FUNCTIONS ===

  function hashChallenge(challenge) {
    // Simple hash for challenge tracking (not cryptographic, just for deduplication)
    const arr = new Uint8Array(challenge);
    let hash = 0;
    for (let i = 0; i < arr.length; i++) {
      hash = ((hash << 5) - hash) + arr[i];
      hash = hash & hash; // Convert to 32-bit integer
    }
    return hash.toString(16);
  }

  function cleanOldChallenges() {
    const fiveMinutesAgo = Date.now() - (5 * 60 * 1000);
    for (const [hash, data] of challengeHistory.entries()) {
      if (data.timestamp < fiveMinutesAgo) {
        challengeHistory.delete(hash);
      }
    }
  }

  function isValidRpId(rpId, currentOrigin) {
    // RP ID must be a suffix of the current origin
    // Example: rpId="example.com" is valid for "login.example.com"
    return currentOrigin === rpId || currentOrigin.endsWith('.' + rpId);
  }

  function extractSignCount(authenticatorData) {
    try {
      // Sign counter is bytes 33-36 (4 bytes, big-endian uint32)
      const data = new Uint8Array(authenticatorData);
      if (data.length < 37) return null;

      const view = new DataView(data.buffer, data.byteOffset);
      return view.getUint32(33, false); // false = big-endian
    } catch {
      return null;
    }
  }

  function extractFlags(authenticatorData) {
    try {
      // Flags are at byte 32
      const data = new Uint8Array(authenticatorData);
      if (data.length < 33) return null;

      const flagsByte = data[32];
      return {
        userPresent: !!(flagsByte & 0x01),
        userVerified: !!(flagsByte & 0x04),
        backupEligible: !!(flagsByte & 0x08),
        backupState: !!(flagsByte & 0x10),
        attestedCredentialData: !!(flagsByte & 0x40),
        extensionData: !!(flagsByte & 0x80)
      };
    } catch {
      return null;
    }
  }

  function sendToBackground(type, data) {
    try {
      chrome.runtime.sendMessage({
        type: 'WEBAUTHN_DETECTION',
        subtype: type,
        url: window.location.href,
        timestamp: Date.now(),
        ...data
      });
    } catch (error) {
      console.warn('Hera: Failed to send WebAuthn detection to background:', error);
    }
  }

  // === INTERCEPT NAVIGATOR.CREDENTIALS.CREATE ===

  navigator.credentials.create = async function(options) {
    console.log('Hera: WebAuthn create() intercepted');

    // Analyze registration options
    const issues = analyzeCreateOptions(options);

    if (issues.length > 0) {
      console.log('Hera: WebAuthn create() issues detected:', issues);
      sendToBackground('CREATE_ISSUES', {
        issues,
        options: {
          rpId: options?.publicKey?.rp?.id,
          rpName: options?.publicKey?.rp?.name,
          userVerification: options?.publicKey?.authenticatorSelection?.userVerification,
          requireResidentKey: options?.publicKey?.authenticatorSelection?.requireResidentKey,
          challengeLength: options?.publicKey?.challenge?.byteLength
        }
      });
    }

    // Call original create
    try {
      const credential = await originalCreate.call(this, options);

      // Analyze response
      const responseIssues = analyzeAuthenticatorResponse(credential);
      if (responseIssues.length > 0) {
        console.log('Hera: WebAuthn create() response issues:', responseIssues);
        sendToBackground('CREATE_RESPONSE_ISSUES', {
          issues: responseIssues
        });
      }

      return credential;
    } catch (error) {
      console.log('Hera: WebAuthn create() failed:', error);
      throw error;
    }
  };

  // === INTERCEPT NAVIGATOR.CREDENTIALS.GET ===

  navigator.credentials.get = async function(options) {
    console.log('Hera: WebAuthn get() intercepted');

    // Analyze authentication options
    const issues = analyzeGetOptions(options);

    if (issues.length > 0) {
      console.log('Hera: WebAuthn get() issues detected:', issues);
      sendToBackground('GET_ISSUES', {
        issues,
        options: {
          rpId: options?.publicKey?.rpId,
          userVerification: options?.publicKey?.userVerification,
          challengeLength: options?.publicKey?.challenge?.byteLength,
          allowCredentialsCount: options?.publicKey?.allowCredentials?.length
        }
      });
    }

    // Call original get
    try {
      const assertion = await originalGet.call(this, options);

      // Analyze response for counter validation
      const responseIssues = analyzeAuthenticatorResponse(assertion);
      if (responseIssues.length > 0) {
        console.log('Hera: WebAuthn get() response issues:', responseIssues);
        sendToBackground('GET_RESPONSE_ISSUES', {
          issues: responseIssues
        });
      }

      return assertion;
    } catch (error) {
      console.log('Hera: WebAuthn get() failed:', error);
      throw error;
    }
  };

  console.log('Hera: WebAuthn monitor initialized');
})();
