// Authentication Protocol Issue Database
// Comprehensive database of security issues across all auth protocols

class AuthIssueDatabase {
  constructor() {
    this.database = this.initializeIssueDatabase();
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
            const { OAuth2Analyzer } = require('./oauth2-analyzer.js');
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

            const { OAuth2Analyzer } = require('./oauth2-analyzer.js');
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

  getIssues(protocol) {
    return this.database[protocol] || {};
  }

  getAllProtocols() {
    return Object.keys(this.database);
  }
}

export { AuthIssueDatabase };
