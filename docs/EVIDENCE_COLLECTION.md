# Evidence Collection in Hera

**Version:** 1.0.0
**Last Updated:** 2025-10-22
**Purpose:** Document what evidence Hera collects, why, and how it's used

---

## Overview

Hera collects comprehensive evidence for every authentication request to provide **proof-backed security findings** suitable for bug bounty submissions and security audits.

This document explains:
1. What data is collected
2. Why each piece of evidence matters
3. How sensitive data is protected
4. What gets included in exports

---

## Evidence Collection Architecture

### Request Lifecycle Evidence Collection

```
1. onBeforeRequest (Initial Capture)
   ├─ URL, method, request type
   ├─ Timestamp (ISO format)
   ├─ Request body (decoded, redacted)
   ├─ Request nonce (for correlation)
   └─ Tab ID

2. onBeforeSendHeaders (Header Analysis)
   ├─ All request headers
   ├─ Auth method detection
   ├─ Cookie analysis
   ├─ OAuth2 flow analysis
   └─ Credential detection

3. onHeadersReceived (Response Capture) ← KEY EVIDENCE
   ├─ All response headers
   ├─ Status code
   ├─ Security header analysis
   │  ├─ HSTS presence and configuration
   │  ├─ CSP, X-Frame-Options, X-Content-Type-Options
   │  └─ Cookie security attributes
   └─ Evidence package generation

4. onBeforeRedirect (Redirect Chain)
   ├─ Redirect URL
   ├─ IP address resolution
   └─ Network chain tracking

5. onCompleted (Final Analysis)
   ├─ Timing information
   ├─ JWT analysis (if applicable)
   ├─ Session security analysis
   └─ SCIM analysis (if applicable)
```

---

## What Evidence Is Collected

### 1. Request Evidence

**URL and Parameters:**
```javascript
{
  url: "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize",
  parsedParams: {
    client_id: "89bee1f7-5e6e-4d8a-9f3d-ecd601259da7",
    state: "eyJpZCI6IjVjZTgy...",
    code_challenge: "BH_wrhJSi9MRC3n3qX5KK3IUKA-Khiz6_orKdCFjmwk",
    code_challenge_method: "S256"
  }
}
```

**Why:** OAuth2 security analysis requires examining authorization parameters.

**Request Headers:**
```javascript
{
  requestHeaders: [
    { name: "Authorization", value: "Bearer eyJ0eXAi..." },
    { name: "Cookie", value: "session=abc; token=xyz" },
    { name: "User-Agent", value: "Mozilla/5.0..." }
  ],
  headerAnalysis: {
    hasAuthHeaders: true,
    authMethods: ["bearer_token"],
    cookieCount: 2
  }
}
```

**Why:** Detects authentication methods and cookie security.

**Request Body (POST/PUT):**
```javascript
{
  requestBody: "grant_type=authorization_code&code=AUTH_CODE&code_verifier=PKCE_VERIFIER...",
  _tokenMetadata: {
    redactionApplied: true,
    tokensFound: [
      {
        name: "code",
        riskLevel: "low",  // One-time use
        format: "base64url",
        originalLength: 128
      },
      {
        name: "code_verifier",
        riskLevel: "low",  // Useless without challenge
        format: "base64url",
        originalLength: 43
      }
    ]
  }
}
```

**Why:** Verifies PKCE implementation and detects client_secret leakage.

---

### 2. Response Evidence

**Response Headers (THE KEY EVIDENCE):**
```javascript
{
  responseHeaders: [
    { name: "Cache-Control", value: "no-store" },
    { name: "Pragma", value: "no-cache" },
    { name: "Content-Type", value: "application/json" }
    // Note: HSTS header ABSENT
  ],
  responseAnalysis: {
    securityHeaders: {
      // All present security headers
    },
    hasSecurityHeaders: false
  }
}
```

**Why:** Provides proof of missing security headers (HSTS, CSP, etc.).

**Evidence Package:**
```javascript
{
  evidencePackage: {
    hstsPresent: {
      present: false,
      reason: "header_missing",
      isHTTPS: true,
      evidence: [/* all response headers */]
    },
    securityHeaders: {
      count: 0,
      missing: ["strict-transport-security", "content-security-policy", ...],
      analysis: {
        score: 0,
        recommendations: [...]
      }
    },
    cookieFlags: {
      cookies: [...],
      vulnerabilities: [...]
    }
  }
}
```

**Why:** Bundles all evidence needed for bug bounty submissions.

---

### 3. Security Analysis Evidence

**OAuth2 Analysis:**
```javascript
{
  authAnalysis: {
    protocol: "OAuth2",
    issues: [
      {
        type: "MISSING_STATE",
        severity: "HIGH",
        confidence: "HIGH",  // ← Confidence score
        message: "Authorization request missing state parameter",
        evidence: {
          url: "...",
          params: {...},
          missingParam: "state"
        },
        recommendation: "Add state parameter for CSRF protection"
      }
    ],
    riskScore: 75,
    flowStats: {
      pkceDetected: true,
      stateEntropy: 4.2,
      stateLength: 150
    }
  }
}
```

**Why:** Provides context and confidence levels for findings.

---

## Token Redaction Strategy

Based on ADVERSARIAL_PUSHBACK.md analysis, Hera intelligently redacts tokens based on risk:

### Risk Levels

**HIGH RISK** (heavily redacted):
- `client_secret` - Long-lived credential
- `api_key` - Long-lived credential
- `refresh_token` - Valid for 90 days
- `password` - User credential

**Redaction:** Show only first 4 and last 4 characters
```
client_secret=AbCd...[REDACTED 64 chars]...XyZ9
```

**MEDIUM RISK** (moderately redacted):
- `access_token` - Short-lived but valuable
- `id_token` - Contains user claims
- `bearer` - Authorization token

**Redaction:** Show first 12 and last 8 characters
```
access_token=eyJ0eXAiOiJKV...[REDACTED 847 chars]...WkpC
```

**LOW RISK** (minimally redacted):
- `code` - One-time use authorization code (already consumed)
- `code_verifier` - Useless without matching challenge
- `state` - One-time use CSRF token
- `nonce` - One-time use replay protection

**Redaction:** Show first 16 and last 16 characters (or full if short)
```
code=M4gU9fYT3qK8xL2p...[48 chars]...9pL2xK8qT3Yf9UgM4
```

### Why This Strategy?

From ADVERSARIAL_PUSHBACK.md:

> Authorization codes in OAuth2 token requests:
> - ✅ One-time use
> - ✅ Expire in 10 minutes
> - ✅ Already consumed by export time
> - **Risk:** LOW

> Refresh tokens:
> - ❌ Valid for 90 days
> - ❌ Can generate new access tokens
> - ❌ If leaked, full account compromise
> - **Risk:** HIGH

---

## What Gets Exported

### Enhanced JSON Export Format

```json
{
  "exportMetadata": {
    "version": "1.0.0",
    "timestamp": "2025-10-22T10:30:00.000Z",
    "sessionCount": 42,
    "redactionApplied": true,
    "evidenceIncluded": true,
    "exportType": "all_sessions"
  },
  "sessions": [
    {
      "url": "https://login.microsoftonline.com/...",
      "method": "POST",
      "timestamp": "2025-10-22T10:15:00.000Z",

      "requestBody": "grant_type=authorization_code&code=M4gU...[REDACTED]...UgM4",

      "_tokenMetadata": {
        "redactionApplied": true,
        "tokensFound": [
          {
            "name": "code",
            "riskLevel": "low",
            "format": "base64url",
            "originalLength": 128
          }
        ]
      },

      "responseHeaders": [
        { "name": "Cache-Control", "value": "no-store" }
      ],

      "metadata": {
        "evidencePackage": {
          "hstsPresent": {
            "present": false,
            "isHTTPS": true,
            "evidence": [/* response headers */]
          }
        },
        "authAnalysis": {
          "issues": [
            {
              "type": "NO_HSTS",
              "severity": "MEDIUM",
              "confidence": "HIGH",
              "evidence": {...}
            }
          ]
        }
      },

      "_exportNotes": {
        "redactionInfo": "Sensitive tokens redacted. See _tokenMetadata for details.",
        "evidencePackage": "Response headers and security analysis included in metadata.evidencePackage",
        "confidenceScore": "Confidence scores included in each finding"
      }
    }
  ]
}
```

---

## Confidence Scoring

Every finding includes a confidence level based on evidence quality:

### HIGH Confidence
- Binary checks (header present/absent)
- Direct parameter observation
- Token inspection performed
- Cookie attributes verified

**Example:**
```json
{
  "type": "NO_HSTS",
  "severity": "MEDIUM",
  "confidence": "HIGH",
  "evidence": {
    "headerPresent": false,
    "isHTTPS": true,
    "allHeaders": [/* proof */]
  }
}
```

### MEDIUM Confidence
- Inferred issues (suspected but not confirmed)
- Pattern matching (might have false positives)
- Heuristic detection

### LOW Confidence
- Error during analysis
- Insufficient evidence
- Uncertain detection

---

## Privacy and Security Considerations

### What Is NOT Collected

❌ **User passwords** - Form submissions not monitored
❌ **Full token values** - Always redacted based on risk
❌ **Response bodies** - Not captured (token response capture deferred)
❌ **Non-auth requests** - Only auth-related endpoints monitored

### What IS Protected

✅ **Token redaction** - Automatic based on risk level
✅ **Storage quota management** - Auto-cleanup to prevent data loss
✅ **Per-origin rate limiting** - Prevents abuse
✅ **Deduplication** - Identical findings within 5 seconds skipped

### Export Controls

When you export data:
1. **Redacted tokens** are included (not full values)
2. **Evidence packages** are included (response headers, analysis)
3. **Confidence scores** are included (for analyst review)
4. **Export metadata** indicates redaction was applied

---

## Using Evidence for Bug Bounty Submissions

### Bug Bounty Template (Auto-Generated)

**For HSTS Missing Finding:**

```markdown
## Missing HSTS Header on Azure AD Authentication Endpoints

**Severity:** Medium
**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)

### Description
The Azure AD OAuth2 authentication endpoints do not implement HSTS headers,
potentially allowing SSL stripping attacks if a user accesses via HTTP.

### Affected Endpoints
- https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize
- https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token

### Proof of Concept

1. Navigate to affected endpoint
2. Inspect response headers
3. Observe missing Strict-Transport-Security header

**Evidence (captured 2025-10-22T10:15:00Z):**
```
Response Headers:
- Cache-Control: no-store
- Pragma: no-cache
- Content-Type: application/json
[No HSTS header present]
```

### Impact
- Potential SSL stripping attack on coffee shop WiFi
- Requires MitM position
- User must ignore browser warnings
- Defense-in-depth issue

### Recommendation
Add HSTS header:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### References
- RFC 6797: HTTP Strict Transport Security
- OWASP: Transport Layer Protection Cheat Sheet

**Confidence:** HIGH (binary check - header either present or absent)
```

---

## FAQ

### Q: Does Hera store full access tokens?

**A:** No. Hera redacts token values based on risk. Access tokens show only first 12 and last 8 characters.

### Q: Can I see the full POST body for debugging?

**A:** Yes, but redacted. The `_tokenMetadata` field shows what was found and redacted. Low-risk tokens (authorization codes) show more context.

### Q: Why doesn't Hera capture token response bodies?

**A:** Per ADVERSARIAL_PUSHBACK.md, this requires content script injection (security risk) and token redaction strategy. Deferred until separate design doc addresses security implications.

### Q: How do I verify Hera's findings manually?

**A:** Use the exported evidence:
1. Open JSON export
2. Find finding in `metadata.authAnalysis.issues`
3. Check `evidence` field for proof
4. Review `metadata.evidencePackage.hstsPresent.evidence` for response headers
5. Use `confidence` score to assess reliability

### Q: What if I need unredacted data for testing?

**A:** Hera prioritizes security. If you need full tokens:
1. Use your browser's DevTools Network tab (live capture)
2. Use Burp Suite proxy (intercepts before redaction)
3. Hera's purpose is evidence collection, not credential storage

---

## Technical References

**Evidence Collection Files:**
- `/modules/webrequest-listeners.js` - Request/response capture
- `/modules/header-utils.js` - Header analysis
- `/evidence-collector.js` - Evidence packaging
- `/modules/auth/token-redactor.js` - Token redaction
- `/modules/storage-manager.js` - Redaction application

**Evidence in Action:**
- `requestData.responseHeaders` - Raw response headers
- `requestData.metadata.evidencePackage` - Complete evidence bundle
- `requestData.metadata.responseAnalysis` - Analyzed security headers
- `requestData._tokenMetadata` - Redaction information

---

**Document Version:** 1.0.0
**Based on:** ADVERSARIAL_PUSHBACK.md recommendations
**Verified:** Source code analysis 2025-10-22
