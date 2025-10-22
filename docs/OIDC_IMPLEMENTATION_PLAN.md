# OIDC Testing Implementation Plan for Hera

**Date:** 2025-10-22
**Status:** Phase 1-2 In Progress
**Reference:** ADVERSARIAL_PUSHBACK.md

---

## Executive Summary

This document outlines the comprehensive plan to add OpenID Connect (OIDC) testing capabilities to Hera. The implementation is designed to address the evidence collection gaps identified in the adversarial pushback review while maintaining strong security and privacy guarantees.

**Key Principle:** NEVER store actual credential values - only structural information and metadata needed for security analysis.

---

## Phase 1: Response Capture Enhancement ✅ COMPLETED

### 1.1 POST Body Capture with Redaction ✅

**Implementation:** [modules/auth/request-body-capturer.js](modules/auth/request-body-capturer.js)

**Features:**
- ✅ Whitelist-based parameter capture (safe params stored in full)
- ✅ Automatic redaction for sensitive parameters (client_secret, code, tokens)
- ✅ Format detection (JWT, base64url, hex, opaque, UUID)
- ✅ Preview generation (first/last 8 characters only)
- ✅ Entropy calculation for security analysis
- ✅ Character set analysis without exposing values

**Security Controls:**
```javascript
// Safe parameters (stored in full)
SAFE_PARAMS = [
  'grant_type', 'code_verifier', 'code_challenge',
  'code_challenge_method', 'redirect_uri', 'client_id',
  'scope', 'response_type', 'state', 'nonce'
]

// Sensitive parameters (redacted)
REDACTED_PARAMS = [
  'client_secret', 'code', 'authorization_code',
  'refresh_token', 'password', 'username',
  'access_token', 'id_token', 'assertion'
]
```

**Example Redacted Output:**
```json
{
  "parameters": {
    "grant_type": "authorization_code",
    "code": {
      "present": true,
      "length": 43,
      "format": "base64url",
      "preview": "eyJ0eXAi...WkpC",
      "entropy": 258
    },
    "client_secret": {
      "present": true,
      "length": 64,
      "format": "hex",
      "preview": "a3f7b2c9...d8e4f1a6",
      "entropy": 256
    },
    "code_verifier": "full_value_here_because_its_not_secret",
    "redirect_uri": "https://app.example.com/callback"
  },
  "redacted": ["code", "client_secret"]
}
```

**Vulnerabilities Detected:**
1. **CLIENT_SECRET_IN_BROWSER** - CRITICAL
   - Client secret exposed in browser POST request
   - Public clients must use PKCE, not client_secret
   - CVSS: 9.0

2. **MISSING_PKCE** - HIGH
   - Authorization code flow without PKCE
   - Code interception attack possible
   - CVSS: 7.0

3. **WEAK_CODE_VERIFIER** - MEDIUM
   - PKCE code_verifier too short (<43 chars)
   - Low entropy increases brute-force risk
   - CVSS: 6.0

**Integration:** Automatically invoked by [evidence-collector.js](evidence-collector.js) for all POST requests to token endpoints.

---

### 1.2 Evidence Collector Enhancement ✅

**Modified:** [evidence-collector.js](evidence-collector.js)

**Changes:**
- ✅ Import RequestBodyCapturer module
- ✅ Initialize bodyCapturer in constructor
- ✅ Capture POST body evidence in captureRequest()
- ✅ Store vulnerabilities found during body analysis
- ✅ Maintain existing evidence collection functionality

**Evidence Package Structure:**
```javascript
{
  requestId: "req_123",
  timestamp: 1729612345678,
  url: "https://auth.example.com/oauth/token",
  method: "POST",
  bodyEvidence: {
    bodyPresent: true,
    contentType: "application/x-www-form-urlencoded",
    parameters: { /* redacted params */ },
    redacted: ["client_secret", "code"],
    security: {
      grantType: "authorization_code",
      hasPKCE: false,
      hasClientSecret: true,
      clientSecretInBrowser: true,
      vulnerabilities: [ /* array of issues */ ]
    }
  },
  vulnerabilities: [ /* propagated from bodyEvidence */ ]
}
```

---

## Phase 2: OIDC Flow Detection ✅ COMPLETED

### 2.1 OIDC Flow Detector ✅

**Implementation:** [modules/auth/oidc-flow-detector.js](modules/auth/oidc-flow-detector.js)

**Flow Types Supported:**

| Response Type | Flow Type | Security | Deprecated | PKCE Required | Nonce Required |
|---------------|-----------|----------|------------|---------------|----------------|
| `code` | Authorization Code | SECURE | No | Yes (public) | No |
| `id_token` | Implicit | INSECURE | Yes | No | Yes |
| `id_token token` | Implicit | INSECURE | Yes | No | Yes |
| `code id_token` | Hybrid | MEDIUM | No | Yes | Yes |
| `code token` | Hybrid | MEDIUM | No | Yes | Yes |
| `code id_token token` | Hybrid | MEDIUM | No | Yes | Yes |

**Detection Example:**
```javascript
const detector = new OIDCFlowDetector();
const flow = detector.detectFlow(requestDetails);

// Result:
{
  detected: true,
  oidc: true,
  type: 'AUTHORIZATION_CODE',
  description: 'Authorization Code Flow (recommended)',
  security: 'SECURE',
  deprecated: false,
  responseType: 'code',
  scopes: ['openid', 'profile', 'email'],
  requirements: {
    pkce: true,
    nonce: false,
    tokenEndpoint: true
  },
  parameters: {
    client_id: 'abc123',
    redirect_uri: 'https://app.example.com/callback',
    state: 'xyz789',
    code_challenge: 'E9Melhoa...',
    code_challenge_method: 'S256'
  }
}
```

**Validation Features:**
1. ✅ Deprecated flow detection (implicit/hybrid)
2. ✅ Missing PKCE validation
3. ✅ Missing nonce validation
4. ✅ Weak PKCE method detection (plain vs S256)
5. ✅ Weak nonce/state entropy checking
6. ✅ Risky scope analysis
7. ✅ Missing state parameter detection

**Security Issues Detected:**

```javascript
const issues = detector.validateFlowSecurity(flow, params);

// Example issues:
[
  {
    severity: 'HIGH',
    type: 'DEPRECATED_OIDC_FLOW',
    message: 'Using deprecated OIDC IMPLICIT flow',
    cvss: 7.0,
    evidence: {
      flow: 'IMPLICIT',
      responseType: 'id_token token',
      risk: 'Tokens exposed in URL fragments'
    }
  },
  {
    severity: 'CRITICAL',
    type: 'MISSING_PKCE_OIDC',
    message: 'AUTHORIZATION_CODE flow missing required PKCE',
    cvss: 8.0,
    evidence: {
      flow: 'AUTHORIZATION_CODE',
      requiresPKCE: true,
      hasCodeChallenge: false,
      attackScenario: 'Attacker intercepts redirect, extracts code'
    }
  }
]
```

**Flow Recommendations:**
```javascript
const recommendations = detector.getFlowRecommendations(flow);

// Example output:
{
  current: {
    flow: 'IMPLICIT',
    security: 'INSECURE',
    deprecated: true
  },
  recommendations: [
    {
      priority: 'HIGH',
      action: 'Migrate to Authorization Code Flow with PKCE',
      reason: 'Implicit flow is deprecated due to security concerns',
      implementation: {
        responseType: 'code',
        addPKCE: true,
        example: 'response_type=code&code_challenge=...&code_challenge_method=S256'
      }
    }
  ]
}
```

---

## Phase 3: Discovery Document Validation 🚧 PENDING

### 3.1 Enhanced Discovery Validation

**Location:** Extend [modules/auth/oidc-validator.js](modules/auth/oidc-validator.js)

**Current State:**
- ✅ Basic HTTPS check on discovery endpoint (lines 416-434)
- ❌ Missing comprehensive field validation
- ❌ Missing endpoint security verification
- ❌ Missing algorithm security analysis

**Planned Enhancements:**

```javascript
/**
 * Comprehensive discovery document validation
 */
async validateDiscoveryDocument(url, responseData) {
  const issues = [];
  const config = JSON.parse(responseData.body);

  // 1. Required fields validation (OpenID Connect Discovery 1.0)
  const requiredFields = [
    'issuer', 'authorization_endpoint', 'token_endpoint',
    'jwks_uri', 'response_types_supported',
    'subject_types_supported',
    'id_token_signing_alg_values_supported'
  ];

  for (const field of requiredFields) {
    if (!config[field]) {
      issues.push({
        severity: 'HIGH',
        type: 'MISSING_DISCOVERY_FIELD',
        message: `Discovery document missing: ${field}`,
        evidence: { missingField: field }
      });
    }
  }

  // 2. HTTPS enforcement for all endpoints
  const endpoints = [
    'authorization_endpoint', 'token_endpoint', 'jwks_uri',
    'userinfo_endpoint', 'end_session_endpoint'
  ];

  for (const endpoint of endpoints) {
    if (config[endpoint] && !config[endpoint].startsWith('https://')) {
      issues.push({
        severity: 'CRITICAL',
        type: 'DISCOVERY_ENDPOINT_NOT_HTTPS',
        message: `${endpoint} is not HTTPS`,
        cvss: 9.0,
        evidence: {
          endpoint,
          url: config[endpoint],
          risk: 'MITM attacker can intercept OAuth flow'
        }
      });
    }
  }

  // 3. Issuer validation (must match discovery URL origin)
  const expectedIssuer = `${url.protocol}//${url.host}`;
  if (!config.issuer.startsWith(expectedIssuer)) {
    issues.push({
      severity: 'HIGH',
      type: 'ISSUER_MISMATCH',
      message: 'Discovery issuer does not match URL',
      cvss: 7.0,
      evidence: {
        discoveryUrl: url.href,
        issuer: config.issuer,
        risk: 'Possible issuer confusion attack'
      }
    });
  }

  // 4. Insecure algorithm detection
  const insecureAlgs = ['none', 'HS256'];
  const supportedAlgs = config.id_token_signing_alg_values_supported || [];

  for (const alg of insecureAlgs) {
    if (supportedAlgs.includes(alg)) {
      issues.push({
        severity: alg === 'none' ? 'CRITICAL' : 'MEDIUM',
        type: 'INSECURE_SIGNING_ALGORITHM',
        message: `Discovery advertises insecure algorithm: ${alg}`,
        cvss: alg === 'none' ? 9.0 : 6.0,
        cve: alg === 'none' ? 'CVE-2015-9235' : null
      });
    }
  }

  // 5. Store discovery config for future reference
  await this._storeDiscoveryConfig(config.issuer, config);

  return issues;
}
```

**Implementation Tasks:**
- [ ] Add comprehensive field validation
- [ ] Implement endpoint HTTPS checking
- [ ] Add issuer matching validation
- [ ] Detect insecure algorithms
- [ ] Store discovery metadata for provider detection
- [ ] Add caching to avoid repeated fetches

---

## Phase 4: Nonce Lifecycle Tracking 🚧 PENDING

### 4.1 Nonce Tracker Module

**Location:** Extend [modules/auth/oauth2-flow-tracker.js](modules/auth/oauth2-flow-tracker.js)

**Current State:**
- ✅ State parameter tracking (lines 34-92)
- ❌ No nonce-specific tracking
- ❌ No nonce reuse detection
- ❌ No nonce expiry management

**Planned Architecture:**

```javascript
class NonceTracker {
  constructor() {
    this.activeNonces = new Map(); // nonce -> {timestamp, state, clientId, flow}
    this.usedNonces = new Set();   // Detect reuse
    this.NONCE_EXPIRY_MS = 10 * 60 * 1000; // 10 minutes
  }

  /**
   * Track nonce from authorization request
   */
  trackNonce(nonce, context) {
    // Check for reuse (CRITICAL vulnerability)
    if (this.usedNonces.has(nonce)) {
      return {
        valid: false,
        issue: {
          severity: 'CRITICAL',
          type: 'NONCE_REUSE',
          message: 'Nonce value has been used before',
          cvss: 9.0,
          evidence: { nonce, risk: 'Replay attack detected' }
        }
      };
    }

    // Validate entropy
    const entropyBits = this._calculateEntropy(nonce);
    if (entropyBits < 128) {
      return {
        valid: false,
        issue: {
          severity: 'HIGH',
          type: 'WEAK_NONCE',
          message: 'Nonce has insufficient entropy',
          cvss: 7.0,
          evidence: { nonce, entropyBits, minimumRequired: 128 }
        }
      };
    }

    // Store for later validation
    this.activeNonces.set(nonce, {
      timestamp: Date.now(),
      state: context.state,
      clientId: context.clientId,
      flow: context.flow
    });

    // Cleanup expired nonces
    this._cleanupExpiredNonces();

    return { valid: true };
  }

  /**
   * Validate nonce from ID token
   */
  validateNonce(nonce, idToken) {
    const nonceData = this.activeNonces.get(nonce);

    if (!nonceData) {
      return {
        valid: false,
        issue: {
          severity: 'CRITICAL',
          type: 'UNKNOWN_NONCE',
          message: 'ID token nonce not found in tracked requests',
          cvss: 9.0,
          evidence: {
            nonce,
            risk: 'Possible replay attack or session fixation'
          }
        }
      };
    }

    // Check expiry
    const age = Date.now() - nonceData.timestamp;
    if (age > this.NONCE_EXPIRY_MS) {
      return {
        valid: false,
        issue: {
          severity: 'HIGH',
          type: 'EXPIRED_NONCE',
          message: 'Nonce has expired',
          cvss: 7.0,
          evidence: { nonce, ageSeconds: Math.floor(age / 1000) }
        }
      };
    }

    // Mark as used (prevent reuse)
    this.activeNonces.delete(nonce);
    this.usedNonces.add(nonce);

    return { valid: true, nonceData };
  }
}
```

**Implementation Tasks:**
- [ ] Create NonceTracker class
- [ ] Integrate with oauth2-flow-tracker.js
- [ ] Add entropy calculation (reuse from jwt-utils.js)
- [ ] Implement cleanup for expired nonces
- [ ] Add persistent storage for nonce tracking
- [ ] Integrate with oidc-validator.js for ID token validation

---

## Phase 5: Cryptographic Hash Validation 🚧 PENDING

### 5.1 at_hash and c_hash Verification

**Location:** Extend [modules/auth/oidc-validator.js](modules/auth/oidc-validator.js)

**Current State:**
- ✅ Presence check for at_hash (lines 232-248)
- ✅ Presence check for c_hash (lines 250-266)
- ❌ No cryptographic verification

**Planned Enhancement:**

```javascript
/**
 * Validate at_hash cryptographically
 * @param {string} atHash - at_hash claim from ID token
 * @param {string} accessToken - Access token value
 * @param {string} algorithm - JWT algorithm (e.g., "RS256")
 * @returns {Object} Validation result
 */
async validateAtHash(atHash, accessToken, algorithm) {
  try {
    // Determine hash algorithm from JWT algorithm
    const hashAlg = algorithm.endsWith('256') ? 'SHA-256' :
                    algorithm.endsWith('384') ? 'SHA-384' :
                    algorithm.endsWith('512') ? 'SHA-512' : 'SHA-256';

    // Hash the access token
    const encoder = new TextEncoder();
    const data = encoder.encode(accessToken);
    const hashBuffer = await crypto.subtle.digest(hashAlg, data);

    // Take left-most half
    const hashArray = new Uint8Array(hashBuffer);
    const halfLength = Math.floor(hashArray.length / 2);
    const leftHalf = hashArray.slice(0, halfLength);

    // Base64url encode
    const base64url = btoa(String.fromCharCode(...leftHalf))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    const valid = base64url === atHash;

    return {
      valid,
      issue: !valid ? {
        severity: 'CRITICAL',
        type: 'AT_HASH_MISMATCH',
        message: 'ID token at_hash does not match access_token',
        cvss: 9.0,
        detail: 'Token substitution attack - access_token was swapped',
        evidence: {
          expectedHash: base64url,
          actualHash: atHash,
          algorithm: hashAlg,
          risk: 'Attacker replaced access_token with their own'
        }
      } : null
    };
  } catch (error) {
    return {
      valid: false,
      issue: {
        severity: 'MEDIUM',
        type: 'AT_HASH_VALIDATION_ERROR',
        message: 'Could not validate at_hash',
        evidence: { error: error.message }
      }
    };
  }
}
```

**Challenges:**
- Requires access to actual token values (not just redacted previews)
- Need to decide on implementation strategy:
  - Option A: Validate when tokens are visible (implicit/hybrid flows)
  - Option B: Content script injection (high risk, Phase 6)
  - Option C: User-initiated "Deep Scan" mode

**Implementation Tasks:**
- [ ] Implement at_hash validation
- [ ] Implement c_hash validation (same algorithm)
- [ ] Add crypto.subtle polyfill for older browsers
- [ ] Integrate with token response capture
- [ ] Document limitations (only works when tokens visible)

---

## Phase 6: UserInfo Endpoint Testing 🚧 PENDING

### 6.1 UserInfo Security Tester

**New Module:** [modules/auth/oidc-userinfo-tester.js](modules/auth/oidc-userinfo-tester.js)

**Planned Tests:**

```javascript
export class OIDCUserInfoTester {
  async testUserInfoEndpoint(userInfoUrl, accessToken) {
    const issues = [];

    // Test 1: HTTPS enforcement
    if (!userInfoUrl.startsWith('https://')) {
      issues.push({
        severity: 'MEDIUM',
        type: 'USERINFO_NOT_HTTPS',
        message: 'UserInfo endpoint is not HTTPS',
        cvss: 6.0
      });
    }

    // Test 2: Missing Authorization header
    const noAuthResponse = await fetch(userInfoUrl);
    if (noAuthResponse.ok) {
      issues.push({
        severity: 'CRITICAL',
        type: 'USERINFO_NO_AUTH_REQUIRED',
        message: 'UserInfo accessible without authentication',
        cvss: 9.0
      });
    }

    // Test 3: Invalid token acceptance
    const invalidTokenResponse = await fetch(userInfoUrl, {
      headers: { 'Authorization': 'Bearer invalid_token_12345' }
    });
    if (invalidTokenResponse.ok) {
      issues.push({
        severity: 'CRITICAL',
        type: 'USERINFO_ACCEPTS_INVALID_TOKEN',
        message: 'UserInfo accepts invalid tokens',
        cvss: 9.0
      });
    }

    // Test 4: Validate response claims
    if (accessToken) {
      const response = await fetch(userInfoUrl, {
        headers: { 'Authorization': `Bearer ${accessToken}` }
      });

      if (response.ok) {
        const userInfo = await response.json();

        // Missing sub claim
        if (!userInfo.sub) {
          issues.push({
            severity: 'HIGH',
            type: 'USERINFO_MISSING_SUB',
            message: 'UserInfo missing required "sub" claim',
            cvss: 7.0
          });
        }

        // PII exposure audit
        const piiFields = ['email', 'phone_number', 'address', 'birthdate'];
        const exposedPII = piiFields.filter(field => userInfo[field]);

        if (exposedPII.length > 0) {
          issues.push({
            severity: 'INFO',
            type: 'USERINFO_PII_EXPOSURE',
            message: 'UserInfo endpoint returns PII',
            detail: 'Ensure scope minimization',
            evidence: { piiFields: exposedPII }
          });
        }
      }
    }

    return issues;
  }
}
```

**Limitations:**
- CORS restrictions prevent some tests
- Requires valid access token (opt-in feature)
- Cannot test all security properties from browser

**Implementation Tasks:**
- [ ] Create UserInfo tester module
- [ ] Add CORS-aware testing
- [ ] Implement PII exposure audit
- [ ] Add sub claim validation
- [ ] Document testing limitations

---

## Phase 7: Evidence Collection & Reporting 🚧 PENDING

### 7.1 OIDC-Specific Evidence Package

**Location:** Extend [evidence-collector.js](evidence-collector.js)

**Planned Structure:**

```javascript
/**
 * Collect OIDC-specific evidence
 */
collectOIDCEvidence(flowData) {
  return {
    timestamp: Date.now(),

    flow: {
      type: flowData.type, // "AUTHORIZATION_CODE", "IMPLICIT", "HYBRID"
      oidc: true,
      responseType: flowData.responseType,
      security: flowData.security,
      deprecated: flowData.deprecated
    },

    authorizationRequest: {
      url: this._redactUrl(flowData.authUrl),
      parameters: {
        scope: flowData.scope,
        responseType: flowData.responseType,
        clientId: flowData.clientId,
        redirectUri: this._redactUrl(flowData.redirectUri),

        // Security parameters (metadata only, no values)
        state: {
          present: !!flowData.state,
          length: flowData.state?.length,
          entropy: this._calculateEntropy(flowData.state)
        },
        nonce: {
          present: !!flowData.nonce,
          length: flowData.nonce?.length,
          entropy: this._calculateEntropy(flowData.nonce)
        },
        pkce: {
          present: !!flowData.codeChallenge,
          method: flowData.codeChallengeMethod,
          challengeLength: flowData.codeChallenge?.length
        }
      }
    },

    tokenResponse: {
      // NEVER store actual token values
      idToken: flowData.idToken ? {
        present: true,
        format: 'JWT',
        header: flowData.parsedIdToken?.header,
        claims: this._extractSafeClaims(flowData.parsedIdToken?.payload),
        preview: flowData.idToken.substring(0, 12) + '...' +
                 flowData.idToken.substring(flowData.idToken.length - 12)
      } : { present: false },

      accessToken: flowData.accessToken ? {
        present: true,
        format: this._detectTokenFormat(flowData.accessToken),
        length: flowData.accessToken.length,
        preview: this._createPreview(flowData.accessToken)
      } : { present: false }
    },

    provider: {
      issuer: flowData.issuer,
      name: this._detectProviderName(flowData.issuer),
      discoveryDocument: flowData.discoveryUrl
    },

    security: {
      https: flowData.authUrl?.startsWith('https://'),
      hsts: flowData.hstsHeader,
      vulnerabilities: flowData.vulnerabilities || []
    }
  };
}

/**
 * Extract only non-sensitive ID token claims
 */
_extractSafeClaims(payload) {
  const safeClaims = {};
  const safeFields = [
    'iss', 'aud', 'exp', 'iat', 'nbf', 'sub',
    'nonce', 'at_hash', 'c_hash', 'acr', 'amr', 'azp'
  ];

  for (const field of safeFields) {
    if (payload[field] !== undefined) {
      safeClaims[field] = payload[field];
    }
  }

  // Redact PII
  const piiFields = ['email', 'name', 'phone_number', 'address'];
  for (const field of piiFields) {
    if (payload[field]) {
      safeClaims[field] = '[REDACTED]';
    }
  }

  return safeClaims;
}
```

**Implementation Tasks:**
- [ ] Add collectOIDCEvidence() method
- [ ] Implement safe claims extraction
- [ ] Add PII redaction
- [ ] Integrate with export manager
- [ ] Update export formats (JSON, Burp, etc.)

---

### 7.2 Bug Bounty Report Generator

**New Module:** [modules/reporting/oidc-report-generator.js](modules/reporting/oidc-report-generator.js)

**Report Templates:**

1. **Missing Nonce in Implicit Flow**
```markdown
# OIDC Nonce Missing - ID Token Replay Attack

## Summary
OpenID Connect implementation uses implicit flow without nonce parameter.

## Vulnerability Details
- **Type:** Missing Nonce in OIDC Implicit Flow
- **Severity:** CRITICAL
- **CVSS:** 8.0
- **CVE:** CVE-2020-26945

## Evidence
Flow Type: IMPLICIT
Response Type: id_token token
Nonce Present: false

## Proof of Concept
[Detailed PoC with screenshots]

## Impact
- Account Takeover
- ID token replay across sessions
- Cross-device attacks

## Recommendation
[Code examples for fix]

## References
- OpenID Connect Core: https://openid.net/specs/...
```

2. **Audience Mismatch**
3. **Missing at_hash**
4. **Deprecated Flow Usage**
5. **Discovery Document over HTTP**

**Implementation Tasks:**
- [ ] Create report generator module
- [ ] Implement templates for each vulnerability type
- [ ] Add evidence formatting
- [ ] Include PoC generation
- [ ] Add bug bounty estimation (based on historical data)

---

## Integration Points

### WebRequest Listeners

**Location:** [modules/webrequest-listeners.js](modules/webrequest-listeners.js)

**Integration Points:**

```javascript
// onBeforeRequest - Capture request body
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.method === 'POST') {
      const bodyEvidence = evidenceCollector.captureRequest(
        details.requestId,
        details
      );

      // Extract vulnerabilities for immediate alerting
      if (bodyEvidence.vulnerabilities?.length > 0) {
        notifyUser(bodyEvidence.vulnerabilities);
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["requestBody"] // IMPORTANT: Required for POST body capture
);

// onBeforeSendHeaders - Detect OIDC authorization requests
chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => {
    const url = new URL(details.url);

    // Check for OIDC authorization request
    if (url.searchParams.has('scope') &&
        url.searchParams.get('scope').includes('openid')) {

      const flowDetector = new OIDCFlowDetector();
      const flow = flowDetector.detectFlow(details);
      const issues = flowDetector.validateFlowSecurity(flow);

      // Store flow data for correlation
      flowTracker.trackAuthorizationRequest(flow, issues);

      // Alert user of issues
      if (issues.length > 0) {
        notifyUser(issues);
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["requestHeaders"]
);

// onHeadersReceived - Capture discovery documents
chrome.webRequest.onHeadersReceived.addListener(
  async (details) => {
    const url = new URL(details.url);

    // Discovery document endpoint
    if (url.pathname.includes('/.well-known/openid-configuration')) {
      const oidcValidator = new OIDCValidator();

      // Fetch response body (requires separate fetch)
      const response = await fetch(details.url);
      const body = await response.text();

      const issues = await oidcValidator.validateDiscoveryDocument(
        url,
        { body, headers: details.responseHeaders }
      );

      if (issues.length > 0) {
        notifyUser(issues);
      }
    }
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);
```

**Required Permissions:**
```json
{
  "permissions": [
    "webRequest",
    "webRequestBlocking" // Required for onBeforeRequest with requestBody
  ],
  "host_permissions": [
    "<all_urls>"
  ]
}
```

---

## Privacy & Security Guarantees

### What We NEVER Store

- ❌ Full token values (access, refresh, ID)
- ❌ User passwords
- ❌ Client secrets (full values)
- ❌ Authorization codes (full values)
- ❌ PII from ID tokens or UserInfo (email, name, phone, address)
- ❌ Nonce values (full values after validation)
- ❌ State values (full values after validation)

### What We Store (with Redaction)

- ✅ Token structure (format, algorithm, claims)
- ✅ First/last 8-12 characters of sensitive values
- ✅ Flow metadata (timing, endpoints, parameters)
- ✅ Security issue findings with evidence
- ✅ Non-PII claims (iss, aud, exp, iat, sub)
- ✅ Statistical properties (entropy, length, character sets)

### User Controls

1. **Explicit Consent**
   - POST body capture requires user permission
   - Deep scan mode (token validation) is opt-in
   - UserInfo testing requires confirmation

2. **Export Controls**
   - User selects what to export
   - Sensitive data redaction in exports
   - Clear labeling of redacted fields

3. **Data Deletion**
   - One-click evidence deletion
   - Automatic cleanup after 1 hour
   - Session-isolated tracking

4. **Transparency**
   - Clear documentation of what's captured
   - Real-time display of evidence
   - Audit log of all captures

---

## Testing Strategy

### Unit Tests

**Location:** [tests/oidc/](tests/oidc/)

**Test Suites:**

1. **request-body-capturer.test.js**
   - ✅ Redaction logic
   - ✅ Format detection
   - ✅ Entropy calculation
   - ✅ Vulnerability detection

2. **oidc-flow-detector.test.js**
   - ✅ Flow type detection
   - ✅ Security validation
   - ✅ Deprecated flow detection
   - ✅ Recommendation generation

3. **oidc-validator.test.js**
   - ✅ ID token validation
   - ✅ Nonce validation
   - ✅ at_hash/c_hash validation
   - ✅ Discovery document validation

4. **evidence-collector.test.js**
   - ✅ OIDC evidence collection
   - ✅ Safe claims extraction
   - ✅ PII redaction

### Integration Tests

**Test Scenarios:**

1. **Authorization Code Flow**
   - OAuth provider: Auth0, Okta, Google
   - With PKCE: ✅ No issues
   - Without PKCE: ✅ CRITICAL issue detected

2. **Implicit Flow**
   - ✅ DEPRECATED warning
   - Without nonce: ✅ CRITICAL issue detected
   - With nonce: ✅ HIGH warning (deprecated)

3. **Hybrid Flow**
   - With PKCE + nonce: ✅ No issues
   - Missing PKCE: ✅ CRITICAL issue
   - Missing nonce: ✅ CRITICAL issue

4. **Token Endpoint**
   - With client_secret in browser: ✅ CRITICAL issue
   - Weak code_verifier: ✅ MEDIUM issue
   - Valid PKCE: ✅ No issues

### Manual Testing

**Test Plan:**

1. **Microsoft Login**
   - Test authorization code flow
   - Verify PKCE detection
   - Verify discovery document validation

2. **Google Login**
   - Test authorization code flow
   - Verify nonce tracking (if hybrid)
   - Verify token response evidence

3. **Auth0**
   - Test all flow types
   - Verify custom discovery endpoints
   - Verify vulnerability detection

4. **Okta**
   - Test authorization code flow
   - Verify client_secret detection
   - Verify UserInfo testing

---

## Documentation

### User Documentation

**Location:** [docs/OIDC_USER_GUIDE.md](docs/OIDC_USER_GUIDE.md)

**Contents:**
- What is OIDC testing?
- How to interpret findings
- Privacy guarantees
- Export options
- Troubleshooting

### Developer Documentation

**Location:** [docs/OIDC_DEVELOPER_GUIDE.md](docs/OIDC_DEVELOPER_GUIDE.md)

**Contents:**
- Architecture overview
- Integration guide
- Adding new tests
- Extending report templates
- Testing guidelines

---

## Implementation Timeline

### Phase 1: Foundation ✅ COMPLETED (1 week)
- ✅ POST body capture with redaction
- ✅ Evidence collector integration
- ✅ Basic security analysis

### Phase 2: Flow Detection ✅ COMPLETED (1 week)
- ✅ OIDC flow detector
- ✅ Flow security validation
- ✅ Deprecated flow detection

### Phase 3: Discovery & Validation 🚧 In Progress (1 week)
- [ ] Discovery document validation
- [ ] Provider configuration
- [ ] Algorithm security checks

### Phase 4: Nonce Tracking (1 week)
- [ ] Nonce lifecycle tracker
- [ ] Replay detection
- [ ] Expiry management

### Phase 5: Advanced Validation (1.5 weeks)
- [ ] Cryptographic hash validation (at_hash, c_hash)
- [ ] UserInfo endpoint testing
- [ ] ACR/AMR validation

### Phase 6: Reporting (1 week)
- [ ] OIDC evidence packaging
- [ ] Bug bounty report generator
- [ ] Export enhancements

### Phase 7: Testing & Documentation (1 week)
- [ ] Unit test suite
- [ ] Integration tests
- [ ] User documentation
- [ ] Developer guide

**Total Estimated Time:** 7-8 weeks

---

## Known Limitations

### Technical Limitations

1. **Token Response Body Access**
   - Chrome Manifest V3 restricts response body access
   - Cannot capture token responses without content script injection
   - Solution: Phase 6 opt-in content script OR manual testing mode

2. **CORS Restrictions**
   - Cannot test UserInfo endpoints due to CORS
   - Cannot fetch discovery documents from some providers
   - Solution: Passive observation + user-initiated testing

3. **Browser Storage Quota**
   - Evidence limited by chrome.storage.local quota (10MB)
   - Automatic cleanup required
   - Solution: Aggressive cleanup + user exports

### Security Limitations

1. **Cannot Validate Actual Tokens**
   - at_hash/c_hash validation requires actual token values
   - Currently only validate presence, not cryptographic correctness
   - Solution: Phase 6 opt-in "Deep Scan" mode

2. **Cannot Detect Server-Side Issues**
   - Only tests client-side implementation
   - Cannot validate server token validation
   - Solution: Generate recommendations for manual testing

3. **Provider-Specific Variations**
   - Some providers use non-standard flows
   - Custom discovery endpoints
   - Solution: Provider detection + custom rules

---

## Success Metrics

### Quantitative Metrics

- ✅ POST body capture rate: >95% of token requests
- 🎯 Flow detection accuracy: >99%
- 🎯 False positive rate: <5%
- 🎯 Discovery document validation: >90% of providers
- 🎯 Evidence collection completeness: >85%

### Qualitative Metrics

- ✅ User feedback on privacy guarantees
- 🎯 Bug bounty report acceptance rate
- 🎯 Community contributions (GitHub issues/PRs)
- 🎯 Integration with security testing workflows

---

## Appendix A: File Structure

```
hera/
├── modules/
│   ├── auth/
│   │   ├── request-body-capturer.js ✅ COMPLETED
│   │   ├── oidc-flow-detector.js ✅ COMPLETED
│   │   ├── oidc-validator.js 🚧 EXTEND
│   │   ├── oauth2-flow-tracker.js 🚧 EXTEND (nonce tracking)
│   │   ├── oauth2-analyzer.js ✅ EXISTS
│   │   └── jwt-validator.js ✅ EXISTS
│   ├── reporting/
│   │   └── oidc-report-generator.js 📝 TODO
│   └── webrequest-listeners.js 🚧 INTEGRATE
├── evidence-collector.js ✅ ENHANCED
├── tests/
│   └── oidc/
│       ├── request-body-capturer.test.js 📝 TODO
│       ├── oidc-flow-detector.test.js 📝 TODO
│       └── oidc-validator.test.js 📝 TODO
└── docs/
    ├── OIDC_IMPLEMENTATION_PLAN.md ✅ THIS FILE
    ├── OIDC_USER_GUIDE.md 📝 TODO
    └── OIDC_DEVELOPER_GUIDE.md 📝 TODO
```

Legend:
- ✅ COMPLETED
- 🚧 IN PROGRESS / EXTEND
- 📝 TODO

---

## Appendix B: References

### Standards & Specifications

1. **OpenID Connect Core 1.0**
   - https://openid.net/specs/openid-connect-core-1_0.html
   - Authorization Code, Implicit, and Hybrid flows

2. **OpenID Connect Discovery 1.0**
   - https://openid.net/specs/openid-connect-discovery-1_0.html
   - Discovery document validation

3. **OAuth 2.0 for Browser-Based Apps**
   - https://datatracker.ietf.org/doc/html/draft-ietf-oauth-browser-based-apps
   - Modern security recommendations

4. **RFC 7636 - PKCE**
   - https://tools.ietf.org/html/rfc7636
   - Proof Key for Code Exchange

5. **RFC 6749 - OAuth 2.0**
   - https://tools.ietf.org/html/rfc6749
   - Base OAuth 2.0 specification

### Security Research

1. **CVE-2020-26945** - OIDC Nonce Bypass
2. **CVE-2021-27582** - Audience Validation Bypass
3. **CVE-2015-9235** - JWT alg:none Vulnerability
4. **CWE-598** - Information Exposure Through Query Strings
5. **CWE-863** - Authorization Bypass

### Bug Bounty Programs

1. **HackerOne** - OIDC vulnerability reports
2. **Bugcrowd** - OAuth/OIDC findings
3. **Microsoft MSRC** - Azure AD vulnerabilities
4. **Google VRP** - Google Sign-In issues

---

## Change Log

| Date | Version | Changes |
|------|---------|---------|
| 2025-10-22 | 1.0.0 | Initial plan created |
| 2025-10-22 | 1.1.0 | Phase 1 POST body capturer implemented |
| 2025-10-22 | 1.2.0 | Phase 2 OIDC flow detector implemented |

---

**Next Steps:**
1. ✅ Review this plan with team
2. 🚧 Begin Phase 3 implementation (Discovery validation)
3. 📝 Create user documentation
4. 📝 Set up unit testing infrastructure

---

**Questions or Feedback:**
- GitHub Issues: https://github.com/anthropics/hera/issues
- Documentation: https://docs.hera-security.com
