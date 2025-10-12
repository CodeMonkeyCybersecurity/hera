// Hera Comprehensive Authentication Protocol Security Analysis Framework
// Advanced detection and analysis of authentication vulnerabilities across all protocols

import { OAuth2VerificationEngine, HSTSVerificationEngine } from './oauth2-verification-engine.js';

class OAuth2Analyzer {
  /**
   * Calculate the entropy of a string
   * Returns both per-character entropy and total information content
   */
  calculateEntropy(str) {
    if (!str) return { perChar: 0, total: 0 };

    // Count character frequencies
    const freq = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    // Calculate Shannon entropy (bits per character)
    let entropyPerChar = 0;
    const len = str.length;
    for (const char in freq) {
      const p = freq[char] / len;
      entropyPerChar -= p * Math.log2(p);
    }

    return {
      perChar: entropyPerChar,
      total: entropyPerChar * len
    };
  }

  /**
   * Analyze the quality of a state parameter
   */
  analyzeStateQuality(state) {
    const entropyData = this.calculateEntropy(state);

    const analysis = {
      exists: !!state,
      length: state ? state.length : 0,
      entropyPerChar: entropyData.perChar,
      totalEntropy: entropyData.total,
      appearsRandom: false,
      risk: 'HIGH'
    };

    // Check entropy per character (should be >= 3 bits for decent randomness)
    // AND total entropy (should be >= 64 bits minimum for security)
    if (entropyData.perChar >= 3 && entropyData.total >= 128) {
      analysis.appearsRandom = true;
      analysis.risk = 'LOW';
    } else if (entropyData.perChar >= 2 && entropyData.total >= 64) {
      analysis.risk = 'MEDIUM';
    }

    return analysis;
  }

  /**
   * Check if this appears to be a legitimate OAuth2/OIDC provider
   */
  isKnownProvider(url) {
    const knownProviders = [
      'login.microsoftonline.com',
      'accounts.google.com',
      'github.com',
      'facebook.com',
      'auth0.com',
      'okta.com',
      'salesforce.com'
    ];

    try {
      const hostname = new URL(url).hostname;
      return knownProviders.some(provider => hostname.includes(provider));
    } catch {
      return false;
    }
  }
}

class OAuth2FlowTracker {
  constructor() {
    // CRITICAL FIX P0: Persistent storage for service worker restarts
    this._activeFlowsCache = new Map();
    this.cleanupInterval = 10 * 60 * 1000;
    this.initialized = false;
    this.initPromise = this.initialize();
  }

  // Initialize by loading from storage.session
  async initialize() {
    if (this.initialized) return;

    try {
      // CRITICAL FIX P0: Use chrome.storage.local for completed OAuth flows (survives browser restart)
      // Active flows need to persist for multi-day timing attack detection
      const data = await chrome.storage.local.get(['oauthFlows']);
      if (data.oauthFlows) {
        for (const [flowId, flow] of Object.entries(data.oauthFlows)) {
          this._activeFlowsCache.set(flowId, flow);
        }
        console.log(`Hera: Restored ${this._activeFlowsCache.size} OAuth flows from storage.local`);
      }
      this.initialized = true;
    } catch (error) {
      console.error('Hera: Failed to initialize OAuth2FlowTracker:', error);
      this.initialized = true;
    }
  }

  // Background sync to storage.local (CRITICAL FIX P0)
  async _syncToStorage() {
    try {
      await this.initPromise;
      const flowsObj = Object.fromEntries(this._activeFlowsCache.entries());
      // CRITICAL FIX P0: Use chrome.storage.local (survives browser restart)
      await chrome.storage.local.set({ oauthFlows: flowsObj });
    } catch (error) {
      console.error('Hera: Failed to sync OAuth flows:', error);
    }
  }

  // Debounced sync
  _debouncedSync() {
    if (this._syncTimeout) clearTimeout(this._syncTimeout);
    this._syncTimeout = setTimeout(() => {
      this._syncToStorage().catch(err => console.error('OAuth flow sync failed:', err));
    }, 100);
  }

  // Getter for activeFlows (backward compatibility)
  get activeFlows() {
    return this._activeFlowsCache;
  }

  /**
   * Track an authorization request
   */
  trackAuthRequest(request) {
    try {
      const url = new URL(request.url);
      const state = url.searchParams.get('state');
      const clientId = url.searchParams.get('client_id');

      if (state && clientId) {
        const flowId = `${clientId}_${state}`;

        // Check if this flow already exists (potential replay attack)
        if (this.activeFlows.has(flowId)) {
          const existingFlow = this.activeFlows.get(flowId);
          console.warn('Potential OAuth2 replay attack: state parameter reused', {
            clientId,
            state,
            originalTimestamp: existingFlow.authRequest.timestamp,
            newTimestamp: Date.now()
          });
          // Overwrite with warning - newer request takes precedence
        }

        this._activeFlowsCache.set(flowId, {
          authRequest: {
            url: request.url,
            timestamp: Date.now(),
            state: state,
            hasPKCE: url.searchParams.has('code_challenge'),
            hasNonce: url.searchParams.has('nonce'),
            clientId: clientId
          },
          callback: null,
          completed: false
        });

        // CRITICAL FIX: Persist to storage.session
        this._debouncedSync();

        // Schedule cleanup
        setTimeout(() => {
          this._activeFlowsCache.delete(flowId);
          this._debouncedSync(); // Persist deletion
        }, this.cleanupInterval);

        return flowId;
      }
    } catch (error) {
      console.warn('Error tracking OAuth2 auth request:', error);
    }
    return null;
  }

  /**
   * Track a callback/redirect
   */
  trackCallback(request) {
    try {
      const url = new URL(request.url);
      const state = url.searchParams.get('state');
      const code = url.searchParams.get('code');
      const error = url.searchParams.get('error');

      if (!state) {
        return {
          vulnerability: 'callbackWithoutState',
          message: 'OAuth2 callback missing state parameter',
          severity: 'HIGH'
        };
      }

      // Find matching flow
      for (const [flowId, flow] of this.activeFlows) {
        if (flow.authRequest.state === state) {
          // SECURITY: Check flow timing to prevent race attacks
          const flowAge = Date.now() - flow.authRequest.timestamp;

          if (flowAge < 2000) {
            // SECURITY FIX P2: Increased from 500ms to 2s (industry standard for human-initiated flows)
            // Callback arrived too quickly after request - likely race attack or automation
            console.warn('OAuth callback timing suspicious (< 2s) - possible CSRF race attack or automation');
            return {
              vulnerability: 'suspiciousTimingAnomaly',
              message: 'OAuth callback received too quickly after authorization request',
              severity: 'HIGH',
              details: `Flow age: ${flowAge}ms (expected > 2000ms for legitimate human interaction)`,
              evidence: {
                authRequestTime: flow.authRequest.timestamp,
                callbackTime: Date.now(),
                timeDifference: flowAge
              }
            };
          }

          if (flowAge > 600000) {
            // Callback too slow (>10 min) - state likely expired
            return {
              vulnerability: 'expiredState',
              message: 'OAuth state parameter expired (> 10 minutes)',
              severity: 'MEDIUM',
              details: `Flow age: ${Math.round(flowAge / 1000)}s`,
              evidence: {
                authRequestTime: flow.authRequest.timestamp,
                callbackTime: Date.now(),
                timeDifference: flowAge
              }
            };
          }

          flow.callback = {
            url: request.url,
            timestamp: Date.now(),
            hasCode: !!code,
            hasError: !!error,
            stateMatches: true
          };
          flow.completed = true;

          // CRITICAL FIX: Persist callback to storage.session
          this._debouncedSync();

          // Validate the complete flow
          return this.validateFlow(flow);
        }
      }

      // No matching flow found - potential attack
      return {
        vulnerability: 'orphanCallback',
        message: 'OAuth2 callback without matching authorization request',
        severity: 'HIGH'
      };
    } catch (error) {
      console.warn('Error tracking OAuth2 callback:', error);
      return null;
    }
  }

  /**
   * Validate a complete OAuth2 flow
   */
  validateFlow(flow) {
    const issues = [];
    const analyzer = new OAuth2Analyzer();

    // Check state parameter quality
    const stateQuality = analyzer.analyzeStateQuality(flow.authRequest.state);

    if (stateQuality.totalEntropy < 64 && !flow.authRequest.hasPKCE) {
      issues.push({
        type: 'weakStateInFlow',
        message: `State entropy too low: ${stateQuality.totalEntropy.toFixed(0)} bits total (${stateQuality.entropyPerChar.toFixed(1)} bits/char)`,
        severity: stateQuality.risk,
        exploitation: 'Predictable state allows CSRF attacks'
      });
    }

    // Check timing (callbacks should happen within reasonable time)
    const flowDuration = flow.callback.timestamp - flow.authRequest.timestamp;
    if (flowDuration > 5 * 60 * 1000) { // 5 minutes
      issues.push({
        type: 'suspiciousTiming',
        message: 'Unusually long delay between auth request and callback',
        severity: 'INFO',
        exploitation: 'Possible session fixation or replay attack'
      });
    }

    return issues;
  }

  /**
   * Get statistics about tracked flows
   */
  getFlowStats() {
    const stats = {
      activeFlows: this.activeFlows.size,
      completedFlows: 0,
      pendingFlows: 0
    };

    for (const flow of this.activeFlows.values()) {
      if (flow.completed) {
        stats.completedFlows++;
      } else {
        stats.pendingFlows++;
      }
    }

    return stats;
  }
}

class HeraAuthProtocolDetector {
  constructor(evidenceCollector = null) {
    this.detectedProtocols = [];
    this.securityIssues = [];
    this.issueDatabase = this.initializeIssueDatabase();
    this.oauth2Analyzer = new OAuth2Analyzer();
    this.flowTracker = new OAuth2FlowTracker();

    // Evidence-based verification engines
    this.evidenceCollector = evidenceCollector;
    this.oauth2Verifier = evidenceCollector ? new OAuth2VerificationEngine(evidenceCollector) : null;
    this.hstsVerifier = evidenceCollector ? new HSTSVerificationEngine(evidenceCollector) : null;
    this.verificationResults = new Map();
  }

  initializeIssueDatabase() {
    return {
      OAuth2: {
        implicitFlow: {
          pattern: /response_type=token/,
          issue: "Access token exposed in URL fragment",
          severity: "CRITICAL",
          detection: (req, detector) => {
            const params = detector.parseParams(req.url);
            return params?.response_type === 'token';
          },
          exploitation: "Tokens visible in browser history, referrer headers, server logs"
        },
        missingPKCE: {
          pattern: /authorization_code.*(?!code_challenge)/,
          issue: "Authorization code interception attack possible",
          severity: "HIGH",
          detection: (req, detector) => {
            const params = detector.parseParams(req.url);
            return params?.response_type === 'code' && !params?.code_challenge;
          },
          exploitation: "Attacker can intercept authorization code and exchange for token"
        },
        missingState: {
          pattern: /authorize\?.*(?!state=)/,
          issue: "CSRF attack possible",
          severity: "HIGH",
          detection: (req, detector) => {
            const params = detector.parseParams(req.url);
            return !params?.state;
          },
          exploitation: "Attacker can forge authorization requests"
        },
        weakState: {
          pattern: /state=[a-z0-9]{1,8}$/,
          issue: "Predictable state parameter",
          severity: (req, detector) => {
            const params = detector.parseParams(req.url);
            const state = params?.state;
            const analyzer = new OAuth2Analyzer();
            const quality = analyzer.analyzeStateQuality(state);

            if (quality.totalEntropy < 32 || quality.entropyPerChar < 1) return 'CRITICAL';
            if (quality.totalEntropy < 64 || quality.entropyPerChar < 2) return 'HIGH';
            if (quality.totalEntropy < 128 && !params?.code_challenge) return 'MEDIUM';
            return 'INFO';
          },
          detection: (req, detector) => {
            const params = detector.parseParams(req.url);
            const state = params?.state;

            if (!state) return false; // Different vuln (missingState)

            // Check if this is actually an OAuth2 flow
            if (!req.url.includes('authorize') && !req.url.includes('oauth')) {
              return false;
            }

            const analyzer = new OAuth2Analyzer();
            const quality = analyzer.analyzeStateQuality(state);

            // Flag if entropy is too low AND no PKCE
            return quality.totalEntropy < 64 && !params?.code_challenge;
          },
          exploitation: "Predictable state allows CSRF attacks"
        },
        openRedirect: {
          pattern: /redirect_uri=(https?:)?\/\//,
          issue: "Potential open redirect vulnerability",
          severity: "HIGH",
          detection: (req, detector) => {
            const params = detector.parseParams(req.url);
            const uri = params?.redirect_uri;
            if (!uri) return false;
            // Detects common open redirect patterns like redirect_uri=@evil.com or redirect_uri=//evil.com
            try {
              const url = new URL(uri);
              return url.username || url.password;
            } catch (e) {
              return uri.startsWith('//') || uri.includes('@');
            }
          }
        },
        overlyBroadScopes: {
          pattern: /scope=.*(\*|all|full|admin)/,
          issue: "Requesting excessive permissions",
          severity: "MEDIUM",
          detection: (req, detector) => {
            const params = detector.parseParams(req.url);
            const scope = params?.scope;
            const dangerous = ['*', 'all', 'full_access', 'admin', 'write:org'];
            return dangerous.some(s => scope?.includes(s));
          }
        },
        clientSecretInURL: {
          pattern: /client_secret=[^&]+/,
          issue: "Client secret exposed in URL",
          severity: "CRITICAL",
          detection: (req, detector) => {
            const params = detector.parseParams(req.url);
            return req.method === 'GET' && params?.client_secret;
          }
        },
        longLivedTokens: {
          pattern: /expires_in=(\d{7,})/,
          issue: "Tokens valid for excessive duration",
          severity: "MEDIUM",
          detection: (res) => res.expires_in > 86400
        }
      },

      OIDC: {
        missingNonce: {
          pattern: /id_token.*(?!nonce)/,
          issue: "Replay attack possible",
          severity: "HIGH",
          detection: (req, detector) => {
            const params = detector.parseParams(req.url);
            return params?.response_type?.includes('id_token') && !params?.nonce;
          }
        },
        unvalidatedIDToken: {
          issue: "ID token signature not validated or weak algorithm",
          severity: "CRITICAL",
          detection: (idToken) => {
            try {
              const header = JSON.parse(atob(idToken.split('.')[0]));
              return header.alg === 'none' || header.alg === 'HS256';
            } catch { return false; }
          }
        },
        missingAudienceCheck: {
          issue: "Token meant for different client accepted",
          severity: "HIGH",
          detection: (idToken, expectedAud) => {
            try {
              const payload = JSON.parse(atob(idToken.split('.')[1]));
              return payload.aud !== expectedAud;
            } catch { return false; }
          }
        },
        expiredToken: {
          issue: "Expired tokens still accepted",
          severity: "HIGH",
          detection: (idToken) => {
            try {
              const payload = JSON.parse(atob(idToken.split('.')[1]));
              return payload.exp < Date.now() / 1000;
            } catch { return false; }
          }
        }
      },

      SAML: {
        unsignedAssertion: {
          pattern: /<saml:Assertion(?!.*<ds:Signature)/,
          issue: "SAML assertion not signed - can be forged",
          severity: "CRITICAL",
          detection: (samlResponse) => !samlResponse.includes('<ds:Signature')
        },
        unencryptedAssertion: {
          pattern: /<saml:Assertion(?!.*<xenc:EncryptedData)/,
          issue: "Sensitive data transmitted in plaintext",
          severity: "HIGH",
          detection: (samlResponse) => !samlResponse.includes('EncryptedAssertion')
        },
        noAudienceRestriction: {
          pattern: /<saml:Assertion(?!.*<saml:AudienceRestriction)/,
          issue: "Assertion can be replayed to different service",
          severity: "HIGH"
        },
        weakSignatureAlgorithm: {
          pattern: /SignatureMethod.*Algorithm=".*sha1"/,
          issue: "Using deprecated SHA1 for signatures",
          severity: "MEDIUM"
        },
        signatureWrapping: {
          issue: "XML signature wrapping attack possible",
          severity: "CRITICAL",
          detection: (samlResponse) => {
            const signatureIndex = samlResponse.indexOf('<ds:Signature');
            const assertionIndex = samlResponse.lastIndexOf('<saml:Assertion');
            return signatureIndex > 0 && signatureIndex < assertionIndex;
          }
        },
        missingExpiration: {
          pattern: /<saml:Conditions(?!.*NotOnOrAfter)/,
          issue: "Assertion never expires",
          severity: "HIGH"
        },
        xxeVulnerability: {
          pattern: /<!DOCTYPE.*SYSTEM/,
          issue: "XML External Entity attack possible",
          severity: "CRITICAL"
        }
      },

      JWT: {
        algorithmNone: {
          pattern: /eyJ.*alg.*none/,
          issue: "JWT signature verification bypassed",
          severity: "CRITICAL",
          detection: (jwt) => {
            try {
              const header = JSON.parse(atob(jwt.split('.')[0]));
              return header.alg === 'none' || header.alg === 'None';
            } catch { return false; }
          }
        },
        algorithmConfusion: {
          issue: "Algorithm confusion attack - using public key as HMAC secret",
          severity: "CRITICAL",
          detection: (jwt, expectedAlg) => {
            try {
              const header = JSON.parse(atob(jwt.split('.')[0]));
              return expectedAlg === 'RS256' && header.alg === 'HS256';
            } catch { return false; }
          }
        },
        weakSecret: {
          issue: "JWT signed with weak/guessable secret",
          severity: "HIGH",
          detection: (jwt) => {
            const commonSecrets = ['secret', '123456', 'password', 'admin'];
            return commonSecrets.some(secret => this.verifyHS256(jwt, secret));
          }
        },
        noExpiration: {
          issue: "JWT never expires",
          severity: "HIGH",
          detection: (jwt) => {
            try {
              const payload = JSON.parse(atob(jwt.split('.')[1]));
              return !payload.exp;
            } catch { return false; }
          }
        },
        longExpiration: {
          issue: "JWT valid for excessive duration",
          severity: "MEDIUM",
          detection: (jwt) => {
            try {
              const payload = JSON.parse(atob(jwt.split('.')[1]));
              const exp = payload.exp;
              const iat = payload.iat || (Date.now() / 1000);
              return (exp - iat) > 86400 * 30;
            } catch { return false; }
          }
        },
        sensitiveData: {
          issue: "Sensitive data exposed in JWT payload",
          severity: "HIGH",
          detection: (jwt) => {
            try {
              const payload = JSON.parse(atob(jwt.split('.')[1]));
              const sensitive = ['password', 'ssn', 'creditcard', 'secret'];
              return sensitive.some(s => JSON.stringify(payload).toLowerCase().includes(s));
            } catch { return false; }
          }
        },
        jwtInURL: {
          pattern: /[?&]token=eyJ/,
          issue: "JWT exposed in URL (logs, history, referrer)",
          severity: "HIGH"
        }
      },

      BasicAuth: {
        basicOverHTTP: {
          pattern: /^http:.*Authorization:\s*Basic/,
          issue: "Credentials sent in plaintext",
          severity: "CRITICAL"
        },
        noRateLimiting: {
          issue: "Brute force attacks possible",
          severity: "HIGH",
          detection: (responses) => {
            const failed401s = responses.filter(r => r.status === 401);
            return failed401s.length > 10 && !responses.some(r => r.status === 429);
          }
        },
        credentialsInURL: {
          pattern: /https?:\/\/[^:]+:[^@]+@/,
          issue: "Credentials exposed in URL",
          severity: "HIGH"
        }
      },

      APIKey: {
        apiKeyInURL: {
          pattern: /[?&](api_?key|apikey|key)=[^&]+/,
          issue: "API key exposed in URL",
          severity: "CRITICAL"
        },
        weakAPIKey: {
          issue: "API key has weak entropy",
          severity: "HIGH",
          detection: (apiKey) => {
            return apiKey.length < 32 ||
                   !/[A-Z]/.test(apiKey) ||
                   !/[!@#$%^&*]/.test(apiKey);
          }
        },
        sensitivePrefix: {
          pattern: /(sk_live|secret_|private_)/,
          issue: "Secret API key exposed in client-side code",
          severity: "CRITICAL",
          detection: (apiKey, context) => {
            return apiKey.startsWith('sk_live') && context === 'client_side';
          }
        }
      },

      Session: {
        sessionFixation: {
          issue: "Session ID not regenerated after authentication",
          severity: "CRITICAL",
          detection: (loginResponse, previousSessionId) => {
            const newSessionId = this.extractSessionId(loginResponse);
            return newSessionId === previousSessionId;
          }
        },
        insecureCookieFlags: {
          pattern: /Set-Cookie:.*(?!HttpOnly)/,
          issue: "Session cookie missing security flags",
          severity: "HIGH",
          detection: (setCookie) => {
            return !setCookie.includes('HttpOnly') ||
                   !setCookie.includes('Secure') ||
                   !setCookie.includes('SameSite');
          }
        },
        predictableSessionId: {
          issue: "Session IDs are predictable",
          severity: "HIGH",
          detection: (sessionIds) => {
            return sessionIds.every((id, i) =>
              parseInt(id) === parseInt(sessionIds[0]) + i
            );
          }
        },
        longSessionTimeout: {
          pattern: /Max-Age=(\d{6,})/,
          issue: "Session valid for excessive duration",
          severity: "MEDIUM"
        },
        sessionInURL: {
          pattern: /[?&](sid|sessionid|session)=/,
          issue: "Session ID exposed in URL",
          severity: "HIGH"
        }
      },

      WebAuthn: {
        weakChallenge: {
          issue: "Challenge not cryptographically random",
          severity: "HIGH",
          detection: (challenge) => {
            return challenge.length < 32 || this.isRepeatingPattern(challenge);
          }
        },
        noUserVerification: {
          pattern: /userVerification["']\s*:\s*["']discouraged/,
          issue: "User verification not required",
          severity: "HIGH",
          detection: (options) => options.userVerification === 'discouraged'
        },
        challengeReuse: {
          issue: "Same challenge used multiple times",
          severity: "HIGH",
          detection: (challenges) => new Set(challenges).size < challenges.length
        }
      },

      MFA: {
        weakOTP: {
          pattern: /^\d{4}$/,
          issue: "OTP too short or weak",
          severity: "HIGH",
          detection: (otp) => otp.length < 6 || !/\d/.test(otp)
        },
        otpInURL: {
          pattern: /[?&](code|otp|token)=\d{4,6}/,
          issue: "OTP exposed in URL",
          severity: "CRITICAL"
        },
        longOTPValidity: {
          issue: "OTP valid for too long",
          severity: "HIGH",
          detection: (otpLifetime) => otpLifetime > 600
        },
        smsOnly2FA: {
          issue: "SMS vulnerable to SIM swapping",
          severity: "CRITICAL",
          detection: (mfaMethods) => {
            return mfaMethods.length === 1 && mfaMethods[0] === 'sms';
          }
        },
        mfaBypass: {
          issue: "MFA can be bypassed",
          severity: "HIGH",
          detection: (response) => {
            return response.includes('skip_mfa') || response.includes('trust_device_permanently');
          }
        }
      },

      Custom: {
        homemadeCrypto: {
          pattern: /md5|sha1|base64.*password/i,
          issue: "Using weak/custom cryptography",
          severity: "CRITICAL",
          detection: (code) => {
            return code.includes('md5(password)') ||
                   code.includes('base64(password)') ||
                   code.includes('custom_encrypt');
          }
        },
        obscurity: {
          pattern: /X-Secret-Header|magic_token/,
          issue: "Relying on obscure headers/parameters",
          severity: "HIGH",
          detection: (headers) => {
            const suspicious = ['X-Secret', 'X-Magic', 'X-Special-Auth'];
            return suspicious.some(h => headers[h]);
          }
        },
        sqlInAuth: {
          pattern: /SELECT.*FROM.*users.*WHERE.*password/i,
          issue: "Plaintext password comparison in SQL",
          severity: "CRITICAL",
          detection: (query) => {
            return query.includes('password = ') && !query.includes('hash');
          }
        }
      }
    };
  }

  analyzeRequest(request) {
    const issues = [];

    // Detect protocol type
    const protocol = this.detectProtocol(request);

    // Track OAuth2 flows if applicable
    if (protocol === 'OAuth2' && request.url.includes('authorize')) {
      this.flowTracker.trackAuthRequest(request);
    }

    // Run protocol-specific checks
    if (this.issueDatabase[protocol]) {
      issues.push(...this.checkProtocolSecurity(protocol, request));
    }

    // Run universal checks
    issues.push(...this.checkUniversalIssues(request));

    // Enhance issues with confidence levels and evidence
    const enhancedIssues = issues.map(issue => this.enhanceIssue(issue, request));

    // Calculate risk score
    const riskScore = this.calculateRiskScore(enhancedIssues);

    return {
      protocol,
      issues: enhancedIssues,
      riskScore,
      recommendation: this.getRecommendation(riskScore),
      timestamp: Date.now(),
      flowStats: protocol === 'OAuth2' ? this.flowTracker.getFlowStats() : null
    };
  }

  /**
   * Enhance an issue with confidence levels and evidence
   */
  enhanceIssue(issue, request) {
    const enhanced = {
      ...issue,
      confidence: this.calculateConfidence(issue, request),
      evidence: this.gatherEvidence(issue, request),
      recommendation: this.getIssueRecommendation(issue.type)
    };

    return enhanced;
  }

  /**
   * Calculate confidence level for a finding
   */
  calculateConfidence(issue, request) {
    try {
      const params = this.parseParams(request.url);

      // High confidence if state is completely missing
      if (issue.type === 'missingState' && !params.state) {
        return 'HIGH';
      }

      // High confidence for known vulnerable patterns
      if (issue.type === 'clientSecretInURL' || issue.type === 'implicitFlow') {
        return 'HIGH';
      }

      // Lower confidence if compensating controls exist
      if (issue.type === 'weakState' && (params.code_challenge || params.nonce)) {
        return 'LOW';
      }

      // Check if this is a known provider (reduces false positive risk)
      if (this.oauth2Analyzer.isKnownProvider(request.url)) {
        if (issue.type === 'missingState' && (issue.severity === 'HIGH' || issue.severity === 'CRITICAL')) {
          return 'MEDIUM'; // Lower confidence for known providers with missing state
        }
      }

      return 'MEDIUM';
    } catch (error) {
      console.warn('Error calculating confidence:', error);
      return 'LOW';
    }
  }

  /**
   * Gather evidence for a security issue
   */
  gatherEvidence(issue, request) {
    try {
      const params = this.parseParams(request.url);
      const evidence = {
        hasState: !!params.state,
        stateLength: params.state ? params.state.length : 0,
        hasPKCE: !!params.code_challenge,
        hasNonce: !!params.nonce,
        isKnownProvider: this.oauth2Analyzer.isKnownProvider(request.url)
      };

      // Add state quality analysis for relevant issues
      if (issue.type === 'weakState' || issue.type === 'missingState') {
        if (params.state) {
          const stateQuality = this.oauth2Analyzer.analyzeStateQuality(params.state);
          evidence.stateEntropyPerChar = stateQuality.entropyPerChar;
          evidence.stateTotalEntropy = stateQuality.totalEntropy;
          evidence.stateAppearsRandom = stateQuality.appearsRandom;
        }
      }

      return evidence;
    } catch (error) {
      console.warn('Error gathering evidence:', error);
      return {};
    }
  }

  /**
   * Get recommendation for a specific issue type
   */
  getIssueRecommendation(issueType) {
    const recommendations = {
      'missingState': 'Implement state parameter with cryptographically random values (minimum 128 bits entropy)',
      'weakState': 'Increase state parameter entropy to at least 128 bits using cryptographically secure random generation',
      'missingPKCE': 'Implement PKCE (Proof Key for Code Exchange) for public clients',
      'implicitFlow': 'Switch to Authorization Code flow with PKCE instead of Implicit flow',
      'clientSecretInURL': 'Move client secret to request body or use client authentication methods',
      'openRedirect': 'Validate redirect_uri against a whitelist of allowed URLs',
      'overlyBroadScopes': 'Request only the minimum required scopes for the application functionality',
      'orphanCallback': 'Investigate potential CSRF attack attempt',
      'callbackWithoutState': 'Ensure all OAuth2 callbacks include state parameter validation'
    };
    return recommendations[issueType] || 'Review OAuth2 implementation against security best practices';
  }

  detectProtocol(request) {
    const url = request.url || '';
    const headers = request.requestHeaders || request.headers || {};
    const params = this.parseParams(url) || {};
    const body = (request.requestBody && typeof request.requestBody === 'string') ? request.requestBody : '';

    // OAuth 2.0
    if (url.includes('/authorize') && params.response_type) {
      return 'OAuth2';
    }

    // OIDC
    if (params.scope?.includes('openid')) {
      return 'OIDC';
    }

    // SAML
    if (body && (body.includes('SAMLRequest') || body.includes('SAMLResponse'))) {
      return 'SAML';
    }

    // JWT
    const authHeader = this.getHeader(headers, 'Authorization');
    if (authHeader?.startsWith('Bearer eyJ')) {
      return 'JWT';
    }

    // Basic Auth
    if (authHeader?.startsWith('Basic ')) {
      return 'BasicAuth';
    }

    // API Key
    if (this.getHeader(headers, 'X-API-Key') || params.api_key) {
      return 'APIKey';
    }

    // Session
    const cookie = this.getHeader(headers, 'Cookie');
    if (cookie?.includes('SESSIONID') || cookie?.includes('JSESSIONID')) {
      return 'Session';
    }

    // Kerberos
    if (authHeader?.startsWith('Negotiate ')) {
      return 'Kerberos';
    }

    // WebAuthn
    if (url.includes('webauthn') || (body && body.includes('publicKey'))) {
      return 'WebAuthn';
    }

    // MFA
    if (url.includes('2fa') || url.includes('mfa') || (body && body.includes('code'))) {
      return 'MFA';
    }

    // Certificate
    if (this.getHeader(headers, 'X-Client-Cert')) {
      return 'Certificate';
    }

    // ProtonMail API
    if (this.getHeader(headers, 'x-pm-uid') ||
        this.getHeader(headers, 'x-pm-appversion') ||
        (cookie && cookie.includes('AUTH-')) ||
        url.includes('/api/core/v4/') ||
        url.includes('/api/auth/v4/') ||
        url.includes('proton.me/api/')) {
      return 'ProtonMail API';
    }

    return 'Custom';
  }

  checkProtocolSecurity(protocol, request) {
    const issues = [];
    const protocolIssues = this.issueDatabase[protocol];

    for (const [issueType, issueData] of Object.entries(protocolIssues)) {
      if (issueData.detection && typeof issueData.detection === 'function') {
        try {
          if (issueData.detection(request, this)) {
            const severity = typeof issueData.severity === 'function'
              ? issueData.severity(request, this)
              : issueData.severity;

            issues.push({
              type: issueType,
              protocol: protocol,
              severity: severity,
              message: issueData.issue,
              exploitation: issueData.exploitation || 'See security documentation'
            });
          }
        } catch (error) {
          console.warn(`Error checking ${protocol}.${issueType}:`, error);
        }
      } else if (issueData.pattern) {
        const testString = request.url + ' ' + JSON.stringify(request.headers) + ' ' + (request.requestBody || '');
        if (issueData.pattern.test(testString)) {
          issues.push({
            type: issueType,
            protocol: protocol,
            severity: issueData.severity,
            message: issueData.issue,
            exploitation: issueData.exploitation || 'See security documentation'
          });
        }
      }
    }

    return issues;
  }

  checkUniversalIssues(request) {
    const issues = [];
    const headers = request.requestHeaders || request.headers || {};
    const url = request.url || '';

    // Check for HTTP
    if (!url.startsWith('https://')) {
      issues.push({
        type: 'NO_TLS',
        protocol: 'Universal',
        severity: 'CRITICAL',
        message: 'Authentication over unencrypted connection'
      });
    }

    // Check for credentials in URL - refined detection
    const credentialIssue = this.detectCredentialsInUrl(url);
    if (credentialIssue) {
      issues.push(credentialIssue);
    }

    // Check for missing security headers with risk-based assessment
    const hstsIssue = this.assessHstsRisk(url, headers, request);
    if (hstsIssue) {
      issues.push(hstsIssue);
    }

    // Check for deprecated APIs
    const deprecatedApiHosts = [
      'graph.windows.net' // Azure AD Graph API
    ];
    try {
      const requestHost = new URL(url).hostname;
      if (deprecatedApiHosts.some(host => requestHost.endsWith(host))) {
        issues.push({
          type: 'DEPRECATED_API',
          protocol: 'Universal',
          severity: 'HIGH',
          message: 'Request uses a deprecated API (' + requestHost + '), which may have known vulnerabilities.'
        });
      }
    } catch (e) {
      // Ignore URL parsing errors
    }

    return issues;
  }

  /**
   * Perform evidence-based OAuth2 verification
   * @param {string} url - OAuth2 authorization URL to verify
   * @returns {Object} Verification results with evidence
   */
  async performEvidenceBasedOAuth2Verification(url) {
    if (!this.oauth2Verifier) {
      return {
        error: "Evidence-based verification not available",
        reason: "No evidence collector provided"
      };
    }

    try {
      // Perform comprehensive OAuth2 verification
      const csrfVerification = await this.oauth2Verifier.verifyCSRFProtection(url);
      const pkceVerification = await this.oauth2Verifier.verifyPKCE(url);

      const results = {
        url: url,
        timestamp: Date.now(),
        verificationId: this.generateVerificationId(),
        tests: {
          csrf: csrfVerification,
          pkce: pkceVerification
        },
        summary: this.summarizeOAuth2Verification(csrfVerification, pkceVerification)
      };

      // Store results for correlation
      this.verificationResults.set(results.verificationId, results);

      return results;
    } catch (error) {
      return {
        error: error.message,
        url: url,
        timestamp: Date.now()
      };
    }
  }

  /**
   * Perform evidence-based HSTS verification
   * @param {string} url - HTTPS URL to verify
   * @returns {Object} Verification results with evidence
   */
  async performEvidenceBasedHSTSVerification(url) {
    if (!this.hstsVerifier) {
      return {
        error: "Evidence-based verification not available",
        reason: "No evidence collector provided"
      };
    }

    try {
      const hstsVerification = await this.hstsVerifier.verifyHSTSImplementation(url);

      const results = {
        url: url,
        timestamp: Date.now(),
        verificationId: this.generateVerificationId(),
        tests: {
          hsts: hstsVerification
        },
        summary: this.summarizeHSTSVerification(hstsVerification)
      };

      // Store results for correlation
      this.verificationResults.set(results.verificationId, results);

      return results;
    } catch (error) {
      return {
        error: error.message,
        url: url,
        timestamp: Date.now()
      };
    }
  }

  /**
   * Generate vulnerability report based on evidence
   * @param {string} verificationId - Verification ID to generate report for
   * @returns {Object} Bug bounty ready vulnerability report
   */
  generateEvidenceBasedReport(verificationId) {
    const results = this.verificationResults.get(verificationId);
    if (!results) {
      return null;
    }

    // Generate OAuth2 vulnerability report
    if (results.tests.csrf && this.oauth2Verifier) {
      const oauth2Report = this.oauth2Verifier.generateVulnerabilityReport(results.tests.csrf);
      if (oauth2Report) {
        return {
          ...oauth2Report,
          verification_id: verificationId,
          hera_evidence_package: results
        };
      }
    }

    // Generate HSTS vulnerability report
    if (results.tests.hsts && this.hstsVerifier) {
      const hstsReport = this.generateHSTSVulnerabilityReport(results.tests.hsts);
      if (hstsReport) {
        return {
          ...hstsReport,
          verification_id: verificationId,
          hera_evidence_package: results
        };
      }
    }

    return null;
  }

  /**
   * Replace pattern-based OAuth2 state detection with evidence-based verification
   * @param {Object} request - Request object
   * @returns {Object} Evidence-based analysis results
   */
  async analyzeOAuth2WithEvidence(request) {
    const url = request.url;
    const params = this.parseParams(url);

    // Check if this is an OAuth2 authorization request
    if (!params?.client_id && !url.includes('oauth') && !url.includes('authorize')) {
      return null;
    }

    const analysis = {
      isOAuth2: true,
      parameters: params,
      evidenceBasedTests: null,
      recommendations: []
    };

    // Perform evidence-based verification if available
    if (this.oauth2Verifier) {
      try {
        analysis.evidenceBasedTests = await this.performEvidenceBasedOAuth2Verification(url);

        // Override pattern-based findings with evidence-based results
        if (analysis.evidenceBasedTests.tests?.csrf) {
          const csrfResults = analysis.evidenceBasedTests.tests.csrf;
          const vulnerableTests = csrfResults.testResults?.filter(test =>
            test.result === 'VULNERABLE' && test.severity === 'HIGH'
          );

          if (vulnerableTests?.length > 0) {
            analysis.vulnerabilities = vulnerableTests.map(test => ({
              type: test.test,
              severity: test.severity,
              evidence: test.evidence,
              verified: true
            }));
          }
        }
      } catch (error) {
        analysis.evidenceBasedTests = { error: error.message };
      }
    }

    return analysis;
  }

  // Helper methods for evidence-based verification

  summarizeOAuth2Verification(csrfVerification, pkceVerification) {
    const summary = {
      vulnerabilities: [],
      strengths: [],
      overallRisk: 'LOW'
    };

    // Analyze CSRF verification results
    if (csrfVerification?.testResults) {
      const highRiskTests = csrfVerification.testResults.filter(test =>
        test.result === 'VULNERABLE' && test.severity === 'HIGH'
      );

      if (highRiskTests.length > 0) {
        summary.vulnerabilities.push(...highRiskTests.map(test => ({
          type: test.test,
          severity: test.severity,
          description: this.getTestDescription(test.test)
        })));
        summary.overallRisk = 'HIGH';
      }
    }

    // Analyze PKCE verification results
    if (pkceVerification?.testResults) {
      const pkceIssues = pkceVerification.testResults.filter(test =>
        test.result === 'VULNERABLE'
      );

      if (pkceIssues.length > 0) {
        summary.vulnerabilities.push(...pkceIssues.map(test => ({
          type: test.test,
          severity: test.severity,
          description: this.getTestDescription(test.test)
        })));

        if (summary.overallRisk !== 'HIGH') {
          summary.overallRisk = 'MEDIUM';
        }
      }
    }

    return summary;
  }

  summarizeHSTSVerification(hstsVerification) {
    const summary = {
      vulnerabilities: [],
      riskLevel: hstsVerification.riskLevel || 'LOW',
      hstsPresent: !!hstsVerification.evidence?.tests?.httpsHeaderCheck?.hstsHeader,
      recommendations: hstsVerification.recommendations || []
    };

    if (hstsVerification.vulnerabilities) {
      summary.vulnerabilities = hstsVerification.vulnerabilities;
    }

    return summary;
  }

  generateHSTSVulnerabilityReport(hstsVerification) {
    const vulnerabilities = hstsVerification.vulnerabilities?.filter(v => v.severity === 'HIGH');

    if (!vulnerabilities || vulnerabilities.length === 0) {
      return null;
    }

    return {
      title: "Missing HSTS Protection Vulnerability",
      severity: "HIGH",
      confidence: "CONFIRMED",
      target: hstsVerification.evidence.targetUrl,

      summary: "HTTPS Strict Transport Security (HSTS) is not properly implemented, allowing downgrade attacks.",

      evidence: {
        target_url: hstsVerification.evidence.targetUrl,
        test_results: hstsVerification.evidence.tests,
        proof_of_vulnerability: {
          hsts_header_missing: !hstsVerification.evidence.tests.httpsHeaderCheck.hstsHeader,
          http_accessible: hstsVerification.evidence.tests.httpDowngradeTest?.httpAccessible,
          no_redirect_to_https: !hstsVerification.evidence.tests.httpDowngradeTest?.redirectsToHttps
        }
      },

      impact: "Attackers can downgrade HTTPS connections to HTTP, intercepting sensitive data in transit.",

      reproduction: [
        "1. Access the HTTP version of the target URL",
        "2. Observe that the connection is not automatically upgraded to HTTPS",
        "3. Verify that no HSTS header is sent in HTTPS responses",
        "4. Demonstrate successful HTTP connection to sensitive endpoints"
      ],

      recommendations: [
        "Implement HSTS header with appropriate max-age directive",
        "Redirect all HTTP traffic to HTTPS",
        "Consider HSTS preloading for enhanced security"
      ]
    };
  }

  getTestDescription(testType) {
    const descriptions = {
      'csrf_no_state': 'OAuth2 authorization endpoint lacks CSRF protection via state parameter',
      'state_replay': 'OAuth2 state parameter can be reused, enabling CSRF attacks',
      'state_prediction': 'OAuth2 state parameter is predictable',
      'pkce_missing': 'OAuth2 flow lacks PKCE protection for public clients',
      'pkce_weak_method': 'OAuth2 PKCE uses weak challenge method'
    };

    return descriptions[testType] || `OAuth2 security issue: ${testType}`;
  }

  generateVerificationId() {
    return `verification_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  calculateRiskScore(issues) {
    const weights = {
      CRITICAL: 100,
      HIGH: 50,
      MEDIUM: 20,
      LOW: 5
    };

    let score = 0;
    for (const issue of issues) {
      score += weights[issue.severity] || 0;
    }

    return Math.min(100, score / 10);
  }

  getRecommendation(riskScore) {
    if (riskScore >= 80) return 'BLOCK - Critical security issues detected';
    if (riskScore >= 60) return 'WARN - Multiple security concerns identified';
    if (riskScore >= 30) return 'REVIEW - Some security improvements needed';
    return 'ACCEPT - Authentication appears secure';
  }

  getRiskCategory(riskScore) {
    if (riskScore >= 80) return 'insecure'; // Red
    if (riskScore >= 30) return 'moderate'; // Gold
    return 'secure'; // Green
  }

  // Helper methods
  parseParams(url) {
    try {
      const urlObj = new URL(url);
      const params = {};
      for (const [key, value] of urlObj.searchParams) {
        params[key] = value;
      }
      return params;
    } catch {
      return {};
    }
  }

  getHeader(headers, name) {
    if (Array.isArray(headers)) {
      const header = headers.find(h => h.name.toLowerCase() === name.toLowerCase());
      return header?.value;
    }
    return headers[name] || headers[name.toLowerCase()];
  }

  extractSessionId(response) {
    const setCookie = response.headers?.['Set-Cookie'] || '';
    const match = setCookie.match(/SESSIONID=([^;]+)/);
    return match ? match[1] : null;
  }

  verifyHS256(jwt, secret) {
    // Simplified verification - in real implementation would use crypto
    return false;
  }

  isRepeatingPattern(str) {
    return /(.)\1{3,}/.test(str) || str === str[0].repeat(str.length);
  }

  detectCredentialsInUrl(url) {
    try {
      const urlObj = new URL(url);
      const params = new URLSearchParams(urlObj.search);
      const fullUrl = url.toLowerCase();

      // Legitimate OAuth2 security parameters - these should NOT be flagged
      const oauthSecurityParams = ['state', 'nonce', 'code_challenge', 'code_verifier'];

      // Public API key patterns that are safe to expose
      const publicKeyPatterns = [
        /pk_[a-zA-Z0-9]+/, // Stripe public keys
        /pub_[a-zA-Z0-9]+/, // Generic public keys
        /public_[a-zA-Z0-9]+/ // Explicit public keys
      ];

      // Check for actual credential exposure in query parameters
      for (const [key, value] of params) {
        const lowerKey = key.toLowerCase();
        const lowerValue = value.toLowerCase();

        // Skip OAuth2 security parameters
        if (oauthSecurityParams.includes(lowerKey)) {
          continue;
        }

        // Skip public API keys
        if (publicKeyPatterns.some(pattern => pattern.test(value))) {
          continue;
        }

        // Look for actual credential patterns
        const credentialPatterns = [
          // Actual passwords
          { pattern: /^(password|passwd|pwd)$/i, paramKey: lowerKey },
          // Private API keys and tokens
          { pattern: /^(api_key|apikey|access_token|auth_token|bearer_token|secret_key|private_key)$/i, paramKey: lowerKey },
          // Database credentials
          { pattern: /^(db_password|database_password|mysql_password|postgres_password)$/i, paramKey: lowerKey },
          // AWS/Cloud credentials
          { pattern: /^(aws_secret_access_key|azure_client_secret|gcp_private_key)$/i, paramKey: lowerKey },
          // High-entropy secrets (likely actual credentials)
          { pattern: /^.{32,}$/, paramKey: lowerKey, value: value, entropyCheck: true }
        ];

        for (const credPattern of credentialPatterns) {
          if (credPattern.pattern.test(credPattern.paramKey)) {
            // For entropy check, ensure it's actually a credential parameter name and high entropy
            if (credPattern.entropyCheck) {
              if (/^(secret|key|token|password)$/i.test(lowerKey) && this.calculateEntropy(value) > 4.5) {
                return {
                  type: 'CREDENTIALS_IN_URL',
                  protocol: 'Universal',
                  severity: 'HIGH',
                  message: `High-entropy credential '${key}' exposed in URL parameters`
                };
              }
            } else {
              return {
                type: 'CREDENTIALS_IN_URL',
                protocol: 'Universal',
                severity: 'HIGH',
                message: `Credential parameter '${key}' exposed in URL`
              };
            }
          }
        }
      }

      // Check for credentials in URL path (rare but possible)
      const pathCredentialPatterns = [
        /\/password\/[^\/]+/i,
        /\/secret\/[^\/]+/i,
        /\/token\/[a-zA-Z0-9]{20,}/i // Long tokens in path
      ];

      for (const pattern of pathCredentialPatterns) {
        if (pattern.test(urlObj.pathname)) {
          // Exclude REST API patterns like /api/token/metadata
          if (!/\/(api|v[0-9]+|metadata|info|status|health)\//.test(urlObj.pathname)) {
            return {
              type: 'CREDENTIALS_IN_URL',
              protocol: 'Universal',
              severity: 'HIGH',
              message: 'Potential credential exposed in URL path'
            };
          }
        }
      }

      return null;
    } catch (error) {
      // Invalid URL, skip detection
      return null;
    }
  }

  calculateEntropy(str) {
    if (!str || str.length === 0) return 0;

    const freq = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  assessHstsRisk(url, headers, request) {
    // First check if HSTS header is present
    const hstsHeader = this.getHeader(headers, 'Strict-Transport-Security');
    if (hstsHeader) {
      return null; // HSTS is present, no issue
    }

    try {
      const urlObj = new URL(url);

      // Skip non-HTTPS URLs (HSTS only applies to HTTPS)
      if (urlObj.protocol !== 'https:') {
        return null;
      }

      // Risk factors assessment
      let riskScore = 10; // Baseline score for all HTTPS endpoints
      let riskFactors = ['HTTPS endpoint (baseline HSTS consideration)'];
      let severity = 'LOW';

      // 1. Authentication context assessment
      const authRisk = this.assessAuthenticationRisk(url, headers, request);
      if (authRisk.hasAuth) {
        riskScore += authRisk.score;
        riskFactors.push(...authRisk.factors);
      }

      // 2. Data sensitivity assessment
      const dataRisk = this.assessDataSensitivity(url, urlObj);
      if (dataRisk.isSensitive) {
        riskScore += dataRisk.score;
        riskFactors.push(...dataRisk.factors);
      }

      // 3. Application type assessment
      const appRisk = this.assessApplicationType(url, urlObj);
      riskScore += appRisk.score;
      riskFactors.push(...appRisk.factors);

      // 4. CDN/Edge protection assessment
      const edgeProtection = this.assessEdgeProtection(headers, urlObj);
      if (edgeProtection.hasProtection) {
        riskScore -= edgeProtection.reduction;
        riskFactors.push(edgeProtection.factor);
      }

      // Determine severity based on risk score
      if (riskScore >= 70) {
        severity = 'HIGH';
      } else if (riskScore >= 40) {
        severity = 'MEDIUM';
      } else if (riskScore >= 15) {
        severity = 'LOW';
      } else {
        // Very low risk - don't report
        return null;
      }

      return {
        type: 'NO_HSTS',
        protocol: 'Universal',
        severity: severity,
        message: `Missing HSTS header (Risk Score: ${riskScore})`,
        details: {
          riskScore: riskScore,
          riskFactors: riskFactors,
          assessment: this.getHstsRiskAssessment(riskScore, riskFactors)
        }
      };

    } catch (error) {
      // Invalid URL, skip assessment
      return null;
    }
  }

  assessAuthenticationRisk(url, headers, request) {
    let score = 0;
    let factors = [];
    let hasAuth = false;

    // Check for authentication headers
    const authHeader = this.getHeader(headers, 'Authorization');
    const cookieHeader = this.getHeader(headers, 'Cookie');

    if (authHeader) {
      hasAuth = true;
      if (authHeader.toLowerCase().includes('bearer')) {
        score += 30;
        factors.push('Bearer token authentication detected');
      } else if (authHeader.toLowerCase().includes('basic')) {
        score += 40;
        factors.push('Basic authentication detected (high risk)');
      } else {
        score += 25;
        factors.push('Custom authentication header detected');
      }
    }

    if (cookieHeader) {
      hasAuth = true;
      // Check for session/auth cookies
      const authCookiePatterns = [
        /sessionid|session_id|auth|token|login|jwt/i,
        /anthropic-device-id|session-key|user-token/i
      ];

      const hasAuthCookie = authCookiePatterns.some(pattern => pattern.test(cookieHeader));
      if (hasAuthCookie) {
        score += 25;
        factors.push('Authentication cookies detected');
      }
    }

    // Check URL patterns for auth endpoints
    const authUrlPatterns = [
      /\/auth\/|\/login\/|\/signin\/|\/oauth\/|\/sso\//i,
      /\/api\/.*\/auth|\/authentication|\/session/i,
      /\/chat_conversations\/|\/conversations\/|\/organizations\//i // AI/collaboration platforms
    ];

    if (authUrlPatterns.some(pattern => pattern.test(url))) {
      hasAuth = true;
      score += 20;
      factors.push('Authentication endpoint detected');
    }

    return { hasAuth, score, factors };
  }

  assessDataSensitivity(url, urlObj) {
    let score = 0;
    let factors = [];
    let isSensitive = false;

    // Financial/payment patterns
    const financialPatterns = [
      /payment|billing|invoice|transaction|financial/i,
      /stripe|paypal|square|checkout/i,
      /bank|secure\.bank|banking|credit|loan/i,
      /login.*bank|bank.*login/i
    ];

    // Healthcare patterns
    const healthcarePatterns = [
      /health|medical|patient|hipaa/i,
      /epic|cerner|allscripts/i
    ];

    // Personal data patterns
    const personalDataPatterns = [
      /profile|account|user|personal|private/i,
      /api\/.*\/(user|profile|account|personal)/i,
      /organizations\/.*\/|conversations\/|chat/i // AI/collaboration platforms
    ];

    // AI/ML service patterns (moderate risk)
    const aiServicePatterns = [
      /claude\.ai|anthropic\.com/i,
      /openai\.com|api\.openai\.com/i,
      /chat|conversation|assistant/i
    ];

    // Check URL for sensitive data indicators
    const urlString = url.toLowerCase();
    const hostname = urlObj.hostname.toLowerCase();

    if (financialPatterns.some(pattern => pattern.test(urlString) || pattern.test(hostname))) {
      isSensitive = true;
      score += 40;
      factors.push('Financial/payment data handling detected');
    }

    if (healthcarePatterns.some(pattern => pattern.test(urlString) || pattern.test(hostname))) {
      isSensitive = true;
      score += 45;
      factors.push('Healthcare data handling detected');
    }

    if (personalDataPatterns.some(pattern => pattern.test(urlString))) {
      isSensitive = true;
      score += 20;
      factors.push('Personal data handling detected');
    }

    if (aiServicePatterns.some(pattern => pattern.test(urlString) || pattern.test(hostname))) {
      isSensitive = true;
      score += 25;
      factors.push('AI/ML service with user data detected');
    }

    // Check for data modification endpoints
    const dataModificationPatterns = [
      /\/api\/.*\/(create|update|delete|modify|edit)/i,
      /\/admin\/|\/management\/|\/dashboard\//i
    ];

    if (dataModificationPatterns.some(pattern => pattern.test(urlString))) {
      isSensitive = true;
      score += 15;
      factors.push('Data modification endpoint detected');
    }

    return { isSensitive, score, factors };
  }

  assessApplicationType(url, urlObj) {
    let score = 0;
    let factors = [];

    const hostname = urlObj.hostname.toLowerCase();
    const path = urlObj.pathname.toLowerCase();

    // High-risk application types
    if (hostname.includes('admin') || path.includes('/admin')) {
      score += 25;
      factors.push('Administrative interface detected');
    }

    // API endpoints (lower browser exposure risk but still baseline concern)
    if (path.includes('/api/') || hostname.startsWith('api.')) {
      score += 5; // Baseline risk for API endpoints
      factors.push('API endpoint (baseline HSTS consideration)');
    }

    // Static content (very low risk)
    const staticPatterns = [
      /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2)$/i,
      /\/static\/|\/assets\/|\/cdn\//i
    ];

    if (staticPatterns.some(pattern => pattern.test(path))) {
      score -= 15;
      factors.push('Static content (very low risk)');
    }

    // Internal/development indicators
    if (hostname.includes('localhost') || hostname.includes('dev') || hostname.includes('staging')) {
      score -= 50;
      factors.push('Development/internal environment (HSTS not critical)');
    }

    return { score, factors };
  }

  assessEdgeProtection(headers, urlObj) {
    let reduction = 0;
    let hasProtection = false;
    let factor = null;

    // Check for CDN/edge service indicators
    const cdnHeaders = [
      'cf-ray', 'x-amz-cf-id', 'x-served-by', 'x-cache',
      'x-cloudflare-uid', 'x-akamai-transformed'
    ];

    const cdnIndicators = cdnHeaders.some(header =>
      Object.keys(headers).some(h => h.toLowerCase() === header)
    );

    if (cdnIndicators) {
      hasProtection = true;
      reduction = 15;
      factor = 'CDN/Edge service detected (may handle HTTPS redirects)';
    }

    // Check for security-focused headers that suggest good security posture
    const securityHeaders = [
      'content-security-policy', 'x-frame-options', 'x-content-type-options'
    ];

    const hasSecurityHeaders = securityHeaders.some(header =>
      Object.keys(headers).some(h => h.toLowerCase() === header)
    );

    if (hasSecurityHeaders) {
      hasProtection = true;
      reduction += 5;
      factor = factor ? `${factor}; Strong security headers present` : 'Strong security headers present';
    }

    return { hasProtection, reduction, factor };
  }

  getHstsRiskAssessment(riskScore, riskFactors) {
    if (riskScore >= 70) {
      return {
        level: 'HIGH',
        recommendation: 'Implement HSTS immediately. This application handles sensitive data and authentication.',
        priority: 'Critical'
      };
    } else if (riskScore >= 40) {
      return {
        level: 'MEDIUM',
        recommendation: 'Consider implementing HSTS to prevent downgrade attacks.',
        priority: 'Important'
      };
    } else if (riskScore >= 15) {
      return {
        level: 'LOW',
        recommendation: 'HSTS recommended but not critical for this application type.',
        priority: 'Optional'
      };
    } else {
      return {
        level: 'MINIMAL',
        recommendation: 'HSTS not critical for this use case.',
        priority: 'Low'
      };
    }
  }

  analyzeResponseBody(body) {
    const issues = [];
    if (!body || typeof body !== 'string') {
      return issues;
    }

    const lowerBody = body.toLowerCase();

    // Check for sensitive data exposure
    const sensitiveKeywords = ['password', 'secret', 'api_key', 'apikey', 'auth_token', 'ssn', 'credit_card'];
    sensitiveKeywords.forEach(keyword => {
      if (lowerBody.includes(keyword)) {
        issues.push({
          type: 'SENSITIVE_DATA_IN_RESPONSE',
          protocol: 'Universal',
          severity: 'HIGH',
          message: `Potential sensitive data exposure: found keyword '${keyword}' in response body.`,
          exploitation: 'Response body may contain secrets, PII, or credentials that should not be exposed to the client.'
        });
      }
    });

    // Check for verbose error messages
    const errorPatterns = ['stack trace', 'sql syntax', 'database error', 'exception', 'uncaught', 'internal server error'];
    errorPatterns.forEach(pattern => {
      if (lowerBody.includes(pattern)) {
        issues.push({
          type: 'VERBOSE_ERROR_MESSAGE',
          protocol: 'Universal',
          severity: 'MEDIUM',
          message: `Verbose error message detected: found keyword '${pattern}'.`,
          exploitation: 'Error messages can reveal server-side technologies, file paths, and application logic, aiding attackers.'
        });
      }
    });

    return issues;
  }
}

// Visual Issue Display
class HeraAuthIssueVisualizer {
  displayIssues(protocol, issues, riskScore) {
    const container = document.createElement('div');
    container.className = 'hera-auth-issues';

    // Risk score header
    const riskHeader = document.createElement('div');
    riskHeader.className = `hera-risk-header risk-${this.getRiskLevel(riskScore)}`;
    riskHeader.innerHTML = `
      <div class="hera-risk-score">Risk Score: ${Math.round(riskScore)}/100</div>
      <div class="hera-protocol-badge">${protocol}</div>
    `;

    // Issue list
    const issueList = document.createElement('div');
    issueList.className = 'hera-issue-list';

    if (issues.length === 0) {
      issueList.innerHTML = '<div class="hera-no-issues">No security issues detected</div>';
    } else {
      issues.forEach(issue => {
        const issueDiv = document.createElement('div');
        issueDiv.className = `hera-issue hera-issue-${issue.severity.toLowerCase()}`;
        issueDiv.innerHTML = `
          <div class="hera-issue-header">
            <span class="hera-issue-icon">${this.getSeverityIcon(issue.severity)}</span>
            <span class="hera-issue-type">${issue.type}</span>
            <span class="hera-issue-severity">${issue.severity}</span>
          </div>
          <div class="hera-issue-message">${issue.message}</div>
          ${issue.exploitation ? `<div class="hera-issue-exploitation">${issue.exploitation}</div>` : ''}
        `;
        issueList.appendChild(issueDiv);
      });
    }

    container.appendChild(riskHeader);
    container.appendChild(issueList);

    return container;
  }

  getSeverityIcon(severity) {
    const icons = {
      CRITICAL: '🔴',
      HIGH: '🟠',
      MEDIUM: '🟡',
      LOW: '🔵'
    };
    return icons[severity] || '⚪';
  }

  getRiskLevel(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 30) return 'medium';
    return 'low';
  }
}

export { HeraAuthProtocolDetector, HeraAuthIssueVisualizer, OAuth2Analyzer, OAuth2FlowTracker };