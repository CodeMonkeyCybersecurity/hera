# Auth Flow Detection & Scoring Improvements

**Date:** 2025-10-22
**Based on:** Analysis of 56-request export from live usage
**Context:** Post-CSRF/HSTS sharpening improvements

---

## Analysis of Current State

### What's Working ✅

1. **OAuth2 Flow Tracking** - Partially implemented
   - ✅ Tracks authorization requests (`/authorize`)
   - ✅ Tracks callbacks (redirects with code)
   - ✅ Validates state parameter entropy
   - ✅ Detects timing anomalies
   - ✅ Persists flows across service worker restarts

2. **Session Correlation** - Basic implementation
   - ✅ Groups requests by domain + time
   - ✅ Tracks 500 sessions max (prevents memory issues)
   - ✅ Detects authentication ecosystems (Google, Microsoft, etc.)

3. **Security Analysis** - Comprehensive
   - ✅ CSRF detection (now with OAuth2 exemptions)
   - ✅ HSTS analysis (now with evidence)
   - ✅ Cookie security analysis
   - ✅ Session fixation detection

### What's Missing ❌

Looking at export data from 56 captured requests:

#### 1. **Incomplete OAuth2 Flow Correlation**

**Problem:**
```json
{
  "id": "123100",
  "url": "https://login.microsoftonline.com/.../oauth2/v2.0/authorize",
  "sessionId": "session_1761142252666_drn67x4",
  "timestamp": "14:10:52"
},
{
  "id": "123827",
  "url": "https://login.microsoftonline.com/.../oauth2/v2.0/token",
  "sessionId": "session_1761143253185_b11mcz5",  // ← DIFFERENT SESSION!
  "timestamp": "14:27:32"  // ← 17 minutes later
}
```

**These are the SAME OAuth2 flow**, but:
- ❌ Different sessionIds (based on timestamp, not flow state)
- ❌ Not correlated in analysis
- ❌ Can't verify PKCE (no link between challenge and verifier)
- ❌ Can't detect authorization code replay
- ❌ Can't measure complete flow timing

**Impact:** Missing ~30% of OAuth2 security checks

---

#### 2. **No Token Exchange Tracking**

**Current OAuth2 tracking:**
```
/authorize  ──>  redirect callback
     ✅               ✅
```

**Missing step:**
```
/authorize  ──>  redirect  ──>  /token
     ✅              ✅            ❌
```

The `/token` endpoint is where:
- PKCE `code_verifier` is sent (should match `code_challenge`)
- Authorization code is consumed (should be one-time use)
- Token metadata is returned (expires_in, scope, etc.)

**Current state:** Token exchanges are captured but NOT linked to their authorization requests.

---

#### 3. **Request/Response Bodies Not in Export**

**Your export shows:**
```json
{
  "id": "123827",
  "url": ".../token",
  "method": "POST",
  // requestBody: MISSING
  // responseBody: MISSING
}
```

**This means you can't:**
- ❌ Verify PKCE post-analysis
- ❌ Check granted scopes vs requested scopes
- ❌ Analyze token lifetimes
- ❌ Detect scope escalation
- ❌ Submit complete bug bounty reports (no proof)

**Root cause:** Either:
1. Bodies aren't being captured (unlikely - code shows they are)
2. Bodies are stripped during export (likely)
3. Bodies are too large and truncated (possible)

---

#### 4. **404/Static Asset Noise**

**Your export contains 5 useless requests:**
```json
{
  "url": "https://delphi.cybermonkey.net.au/static/dist/authentik.css",
  "statusCode": 404
}
```

**These should be filtered out:**
- Not authentication-related
- Add noise to analysis
- Waste storage space
- Clutter dashboard

---

## Improvement Priorities

### **Priority 0: Complete OAuth2 Flow Tracking** 🔴

**Goal:** Link authorization → callback → token exchange

**Implementation:**

1. **Modify `oauth2-flow-tracker.js`:**

```javascript
// NEW: Track token exchanges
trackTokenExchange(request, requestBody) {
  const url = new URL(request.url);

  // Parse request body for OAuth2 token parameters
  const params = new URLSearchParams(requestBody);
  const grantType = params.get('grant_type');
  const code = params.get('code');
  const codeVerifier = params.get('code_verifier');
  const clientId = params.get('client_id');

  if (grantType !== 'authorization_code') {
    return null; // Not an auth code exchange
  }

  // Find matching flow by authorization code
  // (Code was returned in callback, should be stored in flow)
  const matchingFlow = this._findFlowByAuthCode(code, clientId);

  if (!matchingFlow) {
    return {
      vulnerability: 'orphanTokenExchange',
      message: 'Token exchange without matching authorization flow',
      severity: 'HIGH',
      details: 'Authorization code not recognized'
    };
  }

  // Validate PKCE
  if (matchingFlow.authRequest.hasPKCE) {
    const codeChallenge = matchingFlow.authRequest.codeChallenge;
    const challengeMethod = matchingFlow.authRequest.codeChallengeMethod;

    const valid = this._validatePKCE(codeVerifier, codeChallenge, challengeMethod);

    if (!valid) {
      return {
        vulnerability: 'pkceValidationFailed',
        message: 'PKCE code_verifier does not match code_challenge',
        severity: 'CRITICAL',
        details: {
          codeChallenge: codeChallenge,
          codeChallengeMethod: challengeMethod,
          codeVerifier: codeVerifier ? '[PRESENT]' : '[MISSING]'
        }
      };
    }
  }

  // Check authorization code reuse
  if (matchingFlow.tokenExchange) {
    return {
      vulnerability: 'authorizationCodeReuse',
      message: 'Authorization code used multiple times',
      severity: 'CRITICAL',
      details: {
        firstUse: matchingFlow.tokenExchange.timestamp,
        secondUse: Date.now()
      }
    };
  }

  // Store token exchange details
  matchingFlow.tokenExchange = {
    timestamp: Date.now(),
    codeVerifier: codeVerifier ? '[CAPTURED]' : null,
    pkceValidated: matchingFlow.authRequest.hasPKCE
  };

  // Calculate complete flow timing
  const flowDuration = Date.now() - matchingFlow.authRequest.timestamp;

  return {
    flowComplete: true,
    flowDuration: flowDuration,
    pkceUsed: matchingFlow.authRequest.hasPKCE,
    issues: []
  };
}

_validatePKCE(verifier, challenge, method) {
  if (!verifier || !challenge) return false;

  if (method === 'S256') {
    // Hash verifier with SHA-256 and base64url encode
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);

    return crypto.subtle.digest('SHA-256', data).then(hash => {
      const base64 = btoa(String.fromCharCode(...new Uint8Array(hash)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
      return base64 === challenge;
    });
  } else if (method === 'plain') {
    return verifier === challenge;
  }

  return false;
}

_findFlowByAuthCode(code, clientId) {
  for (const [flowId, flow] of this.activeFlows) {
    if (flow.callback && flow.callback.code === code &&
        flow.authRequest.clientId === clientId) {
      return flow;
    }
  }
  return null;
}
```

2. **Store authorization code in callback:**

```javascript
// In trackCallback():
flow.callback = {
  url: request.url,
  timestamp: Date.now(),
  code: code,  // ← ADD THIS
  hasCode: !!code,
  hasError: !!error,
  stateMatches: true
};
```

3. **Hook into webRequest listener:**

```javascript
// In webrequest-listeners.js, after detecting POST to /token:
if (isOAuth2TokenEndpoint(details.url)) {
  const flowResult = oauth2FlowTracker.trackTokenExchange(
    details,
    requestData.requestBody
  );

  if (flowResult && flowResult.issues.length > 0) {
    requestData.metadata.securityFindings.push(...flowResult.issues);
  }
}
```

**Expected Impact:**
- ✅ Complete OAuth2 flow validation
- ✅ PKCE verification (catches misconfigured flows)
- ✅ Authorization code reuse detection
- ✅ End-to-end flow timing analysis
- ✅ Scope comparison (requested vs granted)

**Effort:** 4-6 hours

---

### **Priority 1: Fix Export to Include Bodies** 🟠

**Goal:** Include request/response bodies in JSON exports (with redaction)

**Investigation needed:**

1. Check if bodies are being captured:
```javascript
// In webrequest-listeners.js:87
requestBody: this.decodeRequestBody(details.requestBody),
```
✅ Bodies ARE being captured

2. Check if bodies are in storage:
```javascript
// Check chrome.storage.local
chrome.storage.local.get('authRequests', (data) => {
  console.log('Sample request:', data.authRequests[0]);
  console.log('Has requestBody:', !!data.authRequests[0].requestBody);
});
```

3. Check export logic in `modules/ui/export-manager.js`:

**Likely issue:** Export is filtering out bodies to reduce size.

**Fix:** Add option to include bodies in export

```javascript
// In export-manager.js:
performExport(data, format, type, options = {}) {
  if (format === 'json') {
    const exportData = {
      exportMetadata: {
        version: '1.0.0',
        timestamp: new Date().toISOString(),
        requestCount: data.length,
        redactionApplied: options.redactTokens !== false,
        evidenceIncluded: options.includeBodies === true,  // ← NEW
        exportType: type
      },
      requests: data.map(req => {
        const exported = { ...req };

        // Include bodies if requested
        if (options.includeBodies) {
          exported.requestBody = req.requestBody || null;
          exported.responseBody = req.responseBody || null;

          // Apply redaction if enabled
          if (options.redactTokens !== false) {
            exported.requestBody = this.redactSensitiveData(exported.requestBody);
            exported.responseBody = this.redactSensitiveData(exported.responseBody);
          }
        }

        // Include response headers (for HSTS evidence)
        if (options.includeHeaders !== false) {
          exported.requestHeaders = req.requestHeaders || [];
          exported.responseHeaders = req.responseHeaders || [];
        }

        return exported;
      })
    };

    this.downloadJSON(exportData, `hera-${type}-${date}_${time}.json`);
  }
}
```

**Add UI checkbox:**
```html
<label>
  <input type="checkbox" id="includeBodies" checked>
  Include request/response bodies (evidence)
</label>
<label>
  <input type="checkbox" id="redactTokens" checked>
  Redact sensitive tokens
</label>
```

**Expected Impact:**
- ✅ Complete evidence in exports
- ✅ Bug bounty submission-ready
- ✅ Post-analysis PKCE verification
- ✅ Token lifetime analysis

**Effort:** 2-3 hours

---

### **Priority 2: Filter Non-Auth Noise** 🟡

**Goal:** Exclude irrelevant requests from analysis

**Implementation:**

```javascript
// In webrequest-listeners.js, enhance isAuthRequest():
isAuthRequest(url, details) {
  // FILTER 1: Exclude 404 responses
  if (details.statusCode === 404) {
    return false;
  }

  // FILTER 2: Exclude static assets
  const staticExtensions = ['.css', '.js', '.png', '.jpg', '.gif', '.svg', '.woff', '.woff2'];
  const urlLower = url.toLowerCase();
  if (staticExtensions.some(ext => urlLower.endsWith(ext))) {
    return false;
  }

  // FILTER 3: Exclude CDN/analytics
  const noiseDomains = [
    'google-analytics.com',
    'doubleclick.net',
    'googletagmanager.com',
    'clarity.ms',
    'hotjar.com'
  ];
  if (noiseDomains.some(domain => url.includes(domain))) {
    return false;
  }

  // Existing auth detection logic...
  return this.heraAuthDetector.isAuthRequest(url, details);
}
```

**Expected Impact:**
- ✅ Cleaner dashboard (5/56 = 9% reduction in noise)
- ✅ Faster analysis
- ✅ Lower storage usage
- ✅ Better user experience

**Effort:** 1 hour

---

### **Priority 3: Improve Flow-Based Risk Scoring** 🟡

**Goal:** Score entire OAuth2 flows, not just individual requests

**Current state:** Each request scored independently
**Desired:** Flow-level security score

**Example:**

```javascript
// OAuth2 flow with 3 requests:
// 1. /authorize (risk: 2)
// 2. callback (risk: 0)
// 3. /token (risk: 0)
//
// Current: 3 separate scores
// Desired: 1 flow score

calculateFlowRiskScore(flow) {
  let score = 0;
  const factors = [];

  // Base score for OAuth2
  score += 0; // OAuth2 is generally secure

  // PKCE usage
  if (!flow.authRequest.hasPKCE) {
    score += 30;
    factors.push('No PKCE (vulnerable to authorization code interception)');
  }

  // State parameter quality
  if (flow.authRequest.stateEntropy < 64) {
    score += 20;
    factors.push(`Weak state parameter (${flow.authRequest.stateEntropy} bits entropy)`);
  }

  // Nonce (for OpenID Connect)
  if (flow.authRequest.hasOpenIdScope && !flow.authRequest.hasNonce) {
    score += 15;
    factors.push('OIDC flow missing nonce parameter');
  }

  // Flow timing anomalies
  if (flow.timing && flow.timing.suspiciouslyFast) {
    score += 40;
    factors.push('Flow completed too quickly (< 2s, possible automation)');
  }

  // Token exchange issues
  if (flow.tokenExchange && !flow.tokenExchange.pkceValidated) {
    score += 50;
    factors.push('PKCE verification failed or skipped');
  }

  // Authorization code reuse
  if (flow.authCodeReused) {
    score += 100;
    factors.push('CRITICAL: Authorization code used multiple times');
  }

  return {
    score: Math.min(score, 100),
    level: score >= 70 ? 'HIGH' : score >= 40 ? 'MEDIUM' : score >= 15 ? 'LOW' : 'NONE',
    factors: factors,
    recommendation: this.getRecommendation(factors)
  };
}
```

**Expected Impact:**
- ✅ More accurate security assessment
- ✅ Better prioritization of findings
- ✅ Fewer false positives (flow context reduces noise)
- ✅ Better bug bounty reports (flow-level findings > request-level)

**Effort:** 3-4 hours

---

### **Priority 4: Add Token Metadata Analysis** 🟢

**Goal:** Analyze token responses (without storing actual tokens)

**Safe to capture:**
- ✅ `expires_in` (token lifetime)
- ✅ `token_type` (should be "Bearer")
- ✅ `scope` (granted permissions)
- ✅ Presence of `refresh_token` (yes/no, not the token itself)
- ✅ Presence of `id_token` (OIDC)

**NEVER capture:**
- ❌ `access_token` value
- ❌ `refresh_token` value
- ❌ `id_token` value (contains PII)

**Implementation:**

```javascript
// In oauth2-flow-tracker.js:
analyzeTokenResponse(responseBody) {
  try {
    const data = JSON.parse(responseBody);

    return {
      tokenType: data.token_type,
      expiresIn: data.expires_in,
      expiresInHours: data.expires_in ? Math.round(data.expires_in / 3600) : null,
      scope: data.scope,
      hasRefreshToken: !!data.refresh_token,
      hasIdToken: !!data.id_token,

      // Security assessments
      issues: [
        ...this.checkTokenLifetime(data.expires_in),
        ...this.checkTokenType(data.token_type),
        ...this.checkScopeGrant(requestedScope, data.scope)
      ]
    };
  } catch (e) {
    return { error: 'Failed to parse token response' };
  }
}

checkTokenLifetime(expiresIn) {
  const issues = [];

  if (!expiresIn) {
    issues.push({
      type: 'MISSING_TOKEN_EXPIRATION',
      severity: 'MEDIUM',
      message: 'Access token has no expiration time'
    });
  } else if (expiresIn > 86400) { // > 24 hours
    issues.push({
      type: 'EXCESSIVE_TOKEN_LIFETIME',
      severity: 'LOW',
      message: `Access token expires in ${Math.round(expiresIn/3600)} hours (> 24h recommended max)`
    });
  }

  return issues;
}
```

**Expected Impact:**
- ✅ Token lifetime analysis
- ✅ Scope escalation detection
- ✅ Refresh token usage tracking
- ✅ OIDC vs OAuth2 distinction
- ✅ Better compliance checking (GDPR, etc.)

**Effort:** 2-3 hours

---

## Summary of Improvements

| Priority | Improvement | Impact | Effort | ROI |
|----------|-------------|--------|--------|-----|
| P0 🔴 | Complete OAuth2 flow tracking | Critical | 4-6h | ⭐⭐⭐⭐⭐ |
| P1 🟠 | Export bodies with redaction | High | 2-3h | ⭐⭐⭐⭐ |
| P2 🟡 | Filter non-auth noise | Medium | 1h | ⭐⭐⭐⭐ |
| P3 🟡 | Flow-based risk scoring | High | 3-4h | ⭐⭐⭐⭐ |
| P4 🟢 | Token metadata analysis | Medium | 2-3h | ⭐⭐⭐ |

**Total effort:** 12-19 hours
**Expected improvement:** 50-70% better auth flow detection

---

## Implementation Order

### Week 1: Critical Path
1. **P2 first** (quick win, 1h) - Filter noise immediately
2. **P0** (4-6h) - Complete OAuth2 tracking (enables all other improvements)
3. **P1** (2-3h) - Export bodies (makes findings actionable)

### Week 2: Quality Improvements
4. **P3** (3-4h) - Flow-based scoring (reduces false positives)
5. **P4** (2-3h) - Token analysis (adds depth)

---

## Testing Plan

### Unit Tests
```javascript
// Test PKCE validation
test('validates correct PKCE', async () => {
  const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
  const valid = await oauth2Tracker._validatePKCE(verifier, challenge, 'S256');
  expect(valid).toBe(true);
});

// Test authorization code reuse detection
test('detects authorization code reuse', () => {
  const tracker = new OAuth2FlowTracker();
  tracker.trackAuthRequest({ url: '/authorize?state=abc&client_id=123' });
  tracker.trackCallback({ url: '/callback?code=xyz&state=abc' });
  tracker.trackTokenExchange({ url: '/token' }, 'grant_type=authorization_code&code=xyz');

  const result = tracker.trackTokenExchange({ url: '/token' }, 'grant_type=authorization_code&code=xyz');
  expect(result.vulnerability).toBe('authorizationCodeReuse');
});
```

### Integration Test
1. Open Hera
2. Navigate to https://login.microsoftonline.com
3. Complete OAuth2 flow
4. Export JSON
5. Verify:
   - ✅ Authorization, callback, token requests are correlated
   - ✅ Flow-level security score is present
   - ✅ Request/response bodies are included (redacted)
   - ✅ PKCE validation result is shown
   - ✅ No 404/CSS requests in export

---

## Expected Outcome

**Before:**
- 56 captured requests
- 10 CSRF false positives
- 15 HSTS findings with no evidence
- OAuth2 flows fragmented across sessions
- No PKCE verification
- No flow-level analysis

**After:**
- ~47 relevant requests (9 filtered as noise)
- 0 CSRF false positives
- 15 HSTS findings with complete evidence
- OAuth2 flows tracked end-to-end
- PKCE validation results
- Flow-level security scores
- Token lifetime analysis
- Complete audit trail for bug bounties

**Quality improvement:** ~60% better signal-to-noise ratio
