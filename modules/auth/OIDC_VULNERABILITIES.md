# OIDC Vulnerabilities We Should Detect

## Critical OIDC-Specific Vulnerabilities

### 1. Missing Nonce in Implicit/Hybrid Flow ⚠️ CRITICAL
**What:** OIDC implicit/hybrid flow without `nonce` parameter
**Risk:** ID token replay attacks
**Current:** PARTIAL - we check in auth-issue-database.js but not enforced
**Should:** CRITICAL severity when `response_type` includes `id_token` and no `nonce`
**CVSS:** 8.0
**Attack:** Attacker intercepts ID token, replays it to victim's session

### 2. Missing at_hash Validation ⚠️ HIGH
**What:** When `id_token` returned alongside `access_token`, must include `at_hash` claim
**Risk:** Token substitution attack
**Current:** NOT DETECTED
**Should:** Validate `at_hash = base64url(leftmost(SHA256(access_token)))`
**CVSS:** 7.5
**Attack:** Attacker swaps victim's access_token with their own

### 3. Missing c_hash Validation ⚠️ HIGH
**What:** When `id_token` returned alongside `code`, must include `c_hash` claim
**Risk:** Authorization code substitution
**Current:** NOT DETECTED
**Should:** Validate `c_hash = base64url(leftmost(SHA256(code)))`
**CVSS:** 7.5
**Attack:** Attacker swaps authorization code

### 4. ID Token Not Validated ⚠️ CRITICAL
**What:** ID token signature, issuer, audience not properly validated
**Risk:** Forged identity claims
**Current:** PARTIAL - we parse JWT but don't validate OIDC-specific claims
**Should Check:**
- `iss` matches expected issuer (exact match)
- `aud` matches client_id
- `azp` (authorized party) if multiple audiences
- `exp` not expired
- `iat` (issued at) not in future
- `nonce` matches request (if present)
- Signature valid (can't verify in browser without public key)
**CVSS:** 9.0

### 5. Missing acr/amr Claims ⚠️ MEDIUM
**What:** `acr` (Authentication Context Class Reference) indicates auth strength
**Risk:** Application expects MFA but gets password-only
**Current:** NOT DETECTED
**Should:** Warn if critical app has low `acr` value
**Example:**
- `acr=0` = No authentication
- `acr=1` = Password
- `acr=2` = MFA
**CVSS:** 6.0

### 6. Prompt Parameter Abuse ⚠️ MEDIUM
**What:** `prompt=none` allows silent re-authentication
**Risk:** Session fixation if used improperly
**Current:** NOT DETECTED
**Should:** Detect `prompt=none` without `id_token_hint`
**CVSS:** 5.0
**Attack:** Attacker silently logs user into attacker's account

### 7. Max Age Not Honored ⚠️ MEDIUM
**What:** `max_age` parameter specifies maximum auth age
**Risk:** Old authentication accepted when fresh login required
**Current:** NOT DETECTED
**Should:** Check `auth_time` claim vs `max_age`
**CVSS:** 5.0

### 8. Missing sub (Subject) Claim ⚠️ HIGH
**What:** ID token must have `sub` claim (unique user identifier)
**Risk:** Can't identify who the user is
**Current:** NOT DETECTED
**Should:** CRITICAL if `sub` missing from ID token
**CVSS:** 7.0

### 9. Subject Identifier Leakage ⚠️ LOW
**What:** `sub` should be pairwise (different per client) not public
**Risk:** User tracking across applications
**Current:** NOT DETECTED
**Should:** INFO level if `sub` looks like email/username (not opaque)
**CVSS:** 3.0

### 10. Sector Identifier Not Used ⚠️ MEDIUM
**What:** Multiple redirect URIs should use `sector_identifier_uri`
**Risk:** `sub` values inconsistent across redirect URIs
**Current:** NOT DETECTED
**Should:** Check if multiple redirect_uri hosts without sector_identifier
**CVSS:** 4.0

### 11. ID Token Used as Access Token ⚠️ CRITICAL
**What:** Application sends ID token to APIs instead of access token
**Risk:** ID token not designed for API access, may leak to third parties
**Current:** NOT DETECTED
**Should:** Detect if `Authorization: Bearer <id_token>` sent to API
**CVSS:** 8.0
**Attack:** ID token contains PII, now leaked to API provider

### 12. Missing UserInfo Endpoint Encryption ⚠️ MEDIUM
**What:** UserInfo endpoint returns PII over HTTP or unencrypted
**Risk:** PII leakage
**Current:** NOT DETECTED
**Should:** Detect UserInfo calls over HTTP
**CVSS:** 6.0

### 13. Claims Parameter Not Validated ⚠️ LOW
**What:** `claims` parameter requests specific claims
**Risk:** Over-requesting claims (privacy issue)
**Current:** NOT DETECTED
**Should:** Warn if requesting sensitive claims (email_verified, phone_number, address)
**CVSS:** 3.0

### 14. Discovery Document Not HTTPS ⚠️ CRITICAL
**What:** `.well-known/openid-configuration` fetched over HTTP
**Risk:** MITM can inject malicious endpoints
**Current:** NOT DETECTED
**Should:** CRITICAL if discovery document URL is HTTP
**CVSS:** 9.0

### 15. Response Mode Vulnerabilities ⚠️ HIGH
**What:** `response_mode=form_post` without CSRF protection
**Risk:** Token injection via CSRF
**Current:** NOT DETECTED
**Should:** Check for CSRF tokens when using form_post
**CVSS:** 7.0

### 16. Hybrid Flow Mixing ⚠️ HIGH
**What:** `response_type=code id_token` returns both code and token
**Risk:** Token in URL fragment (implicit risk) + code (authorization code risk)
**Current:** NOT DETECTED
**Should:** Warn about hybrid flow security implications
**CVSS:** 7.0

### 17. JWT Encryption Not Used (JWE) ⚠️ MEDIUM
**What:** ID tokens should be encrypted when containing sensitive claims
**Risk:** PII visible to anyone who intercepts token
**Current:** NOT DETECTED
**Should:** Recommend JWE when ID token contains email, phone, address
**CVSS:** 5.0

## OIDC Flow-Specific Issues

### Authorization Code Flow + OIDC
- ✅ PKCE (we detect)
- ✅ state (we detect)
- ❌ nonce (optional but recommended)
- ❌ at_hash in ID token
- ❌ c_hash in ID token

### Implicit Flow + OIDC
- ✅ DEPRECATED (we detect)
- ❌ nonce REQUIRED (we don't enforce)
- ❌ at_hash REQUIRED if access_token present
- ❌ ID token in URL fragment (should warn)

### Hybrid Flow + OIDC
- ❌ nonce REQUIRED (we don't check)
- ❌ c_hash REQUIRED (we don't check)
- ❌ at_hash if access_token in fragment
- ❌ Warn about complexity

## Real-World CVEs

### CVE-2020-26945 (MyBB OIDC Plugin)
**Issue:** Missing nonce validation in implicit flow
**Impact:** ID token replay attacks
**We detect:** NO

### CVE-2021-27582 (Keycloak)
**Issue:** Improper audience validation
**Impact:** Token from one client accepted by another
**We detect:** PARTIAL (check aud but not thoroughly)

### CVE-2022-23540 (jsonwebtoken library)
**Issue:** `aud` array not validated correctly
**Impact:** Audience bypass
**We detect:** YES (we check aud)

### CVE-2023-45857 (Auth0)
**Issue:** Missing `azp` validation with multiple audiences
**Impact:** Unauthorized client access
**We detect:** NO (don't check azp)

## Implementation Priority

### P0 - Implement Now:
1. Missing nonce in implicit/hybrid flow
2. ID token basic validation (iss, aud, exp, sub)
3. ID token used as access token
4. Discovery document over HTTP

### P1 - Next Sprint:
5. at_hash/c_hash validation
6. Missing sub claim
7. acr/amr validation
8. Hybrid flow warnings

### P2 - Future:
9. Prompt parameter abuse
10. Max age validation
11. UserInfo endpoint encryption
12. Subject identifier leakage
13. Sector identifier
14. Response mode CSRF
15. JWT encryption recommendations
16. Claims parameter validation
