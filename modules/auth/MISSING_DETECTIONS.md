# Missing Auth Vulnerability Detections

## Critical Gaps in Current Detection

### 1. Token Leakage via Referer Header ⚠️ CRITICAL
**What:** When OAuth tokens are in URL and user clicks external link
**Risk:** Token leaked to third-party site via Referer header
**Detection:** Check if access_token in URL + external links on page
**CVSS:** 8.0
**Fix:** Move tokens to Authorization header, never URL params

### 2. CORS Misconfiguration ⚠️ HIGH
**What:** `Access-Control-Allow-Origin: *` with credentials
**Risk:** Token theft from malicious origin
**Detection:** Check response headers for overly permissive CORS
**CVSS:** 7.5
**Current:** NOT DETECTED

### 3. Token Binding Missing ⚠️ HIGH
**What:** Tokens not bound to client TLS certificate or device
**Risk:** Stolen tokens work from any device/location
**Detection:** Check for DPoP header or certificate-bound tokens
**CVSS:** 7.0
**Current:** NOT DETECTED

### 4. Refresh Token Rotation Not Enforced ⚠️ MEDIUM
**What:** Refresh tokens can be reused multiple times
**Risk:** Stolen refresh token works indefinitely
**Detection:** Track refresh token reuse across requests
**CVSS:** 6.0
**Current:** NOT DETECTED

### 5. Missing Nonce in OIDC Implicit Flow ⚠️ HIGH
**What:** OIDC implicit/hybrid flow without nonce parameter
**Risk:** Token replay attacks
**Detection:** Check for nonce in id_token when response_type includes id_token
**CVSS:** 7.5
**Current:** NOT DETECTED

### 6. Redirect URI Bypass Techniques ⚠️ CRITICAL
**What:** Multiple bypass patterns we don't check:
- `https://evil.com@good.com` (credential injection)
- `https://good.com.evil.com` (subdomain spoofing)
- `https://good.com/../evil.com` (path traversal)
- `https://good.com?redirect=https://evil.com` (open redirect chain)
**Risk:** Authorization code theft
**CVSS:** 9.0
**Current:** PARTIAL - need stronger validation

### 7. JWT Algorithm Bypass Variants ⚠️ CRITICAL
**What:** Multiple "alg:none" bypass techniques:
- `"alg": "none\u0000"` (null byte)
- `"alg": "NoNe"` (case variation)
- `"alg": "none "` (trailing space)
- `"alg": ""` (empty string)
- Missing alg field entirely
**Risk:** Signature bypass
**CVSS:** 10.0
**Current:** PARTIAL - only checks lowercase "none"

### 8. Client Secret in JavaScript ⚠️ CRITICAL
**What:** OAuth client_secret exposed in JavaScript
**Risk:** Attacker can impersonate application
**Detection:** Check for client_secret in JS bundles
**CVSS:** 9.0
**Current:** NOT DETECTED

### 9. Account Enumeration via OAuth ⚠️ MEDIUM
**What:** Different error messages reveal if email exists
**Risk:** User enumeration attack
**Detection:** Compare error responses for valid/invalid users
**CVSS:** 5.0
**Current:** NOT DETECTED

### 10. Subdomain Takeover + Redirect URI ⚠️ HIGH
**What:** redirect_uri allows *.example.com but subdomain vulnerable to takeover
**Risk:** Code interception via subdomain takeover
**Detection:** Check for wildcard redirect_uri + DNS dangling
**CVSS:** 7.5
**Current:** NOT DETECTED

## Storage Issues

### What We're Storing That We Don't Need:
1. **Full request/response bodies** - stripped ✅
2. **All headers** - stripped ✅
3. **Browser context metadata** - stripped ✅

### What We're NOT Storing That We Need:
1. **Flow correlation** - Need to link authorize → token → refresh
2. **Timing data** - Detect suspiciously fast token generation
3. **Geolocation changes** - Token used from different location
4. **User agent switches** - Token used from different browser

## UX Issues

### What We're NOT Showing That We Should:
1. **Attack surface summary** - "3 auth protocols, 2 have critical issues"
2. **Flow visualization** - Timeline showing OAuth dance
3. **Comparative risk** - "This JWT is weaker than 90% of tokens we've seen"
4. **Remediation priority** - "Fix these 3 CRITICAL issues first"
5. **Evidence export** - One-click export for security team

### What We're Showing That Could Be Better:
1. **Individual findings** - Good ✅
2. **JSON highlighting** - Good ✅
3. **Severity badges** - Good ✅
4. **But missing:** Historical trends, flow timeline, attack scenarios

## Recommended Priority

### P0 (Implement Now):
1. Stronger redirect_uri validation (bypass techniques)
2. JWT alg:none bypass variants
3. Missing nonce in OIDC
4. CORS misconfiguration detection

### P1 (Next Sprint):
5. Token binding detection
6. Client secret in JavaScript
7. Flow correlation tracking
8. Attack surface summary in UX

### P2 (Future):
9. Refresh token rotation
10. Subdomain takeover detection
11. Account enumeration
12. Historical trend analysis
