# WebAuthn / FIDO2 Vulnerabilities We Should Detect

## Critical WebAuthn/FIDO2 Vulnerabilities

### 1. Missing User Verification ⚠️ CRITICAL
**What:** `userVerification: "discouraged"` or `"preferred"` instead of `"required"`
**Risk:** Authenticator doesn't verify user presence (no PIN/biometric)
**Current:** NOT DETECTED
**Should:** CRITICAL if userVerification !== "required" for sensitive operations
**CVSS:** 8.0
**Attack:** Stolen physical security key works without PIN
**Detect:** Check `navigator.credentials.create/get` options

### 2. Attestation Not Validated ⚠️ HIGH
**What:** Server doesn't validate attestation statement
**Risk:** Malicious/cloned authenticator accepted
**Current:** NOT DETECTED
**Should:** Warn if attestation=none when enterprise expects hardware tokens
**CVSS:** 7.0
**Attack:** Software-based "security key" accepted instead of hardware FIDO2
**Detect:** Check attestation in registration response

### 3. Challenge Reuse ⚠️ CRITICAL
**What:** Same challenge used multiple times
**Risk:** Replay attacks
**Current:** NOT DETECTED
**Should:** Track challenges, warn if reused
**CVSS:** 9.0
**Attack:** Attacker captures authentication response, replays it
**Detect:** Hash and store challenges, check for duplicates

### 4. Weak Challenge Entropy ⚠️ CRITICAL
**What:** Challenge < 16 bytes (128 bits)
**Risk:** Challenge collision or brute force
**Current:** NOT DETECTED
**Should:** CRITICAL if challenge.byteLength < 16
**CVSS:** 8.5
**Attack:** Attacker generates same challenge, intercepts response
**Detect:** Check challenge length in create/get calls

### 5. Missing Timeout ⚠️ MEDIUM
**What:** No `timeout` parameter in credential request
**Risk:** Indefinite authentication window
**Current:** NOT DETECTED
**Should:** Warn if timeout > 60000ms (60 seconds)
**CVSS:** 5.0
**Attack:** Extended time for phishing/social engineering
**Detect:** Check timeout in navigator.credentials.get()

### 6. Cross-Origin Credential Theft ⚠️ CRITICAL
**What:** Credentials created for origin A, used on origin B
**Risk:** Phishing site uses victim's credentials
**Current:** NOT DETECTED (browser prevents, but we should detect attempt)
**Should:** Detect if rpId doesn't match current origin
**CVSS:** 9.0
**Attack:** evil.com tries to use credentials from bank.com
**Detect:** Check rpId in PublicKeyCredentialCreationOptions

### 7. Resident Key (Discoverable Credential) Not Used ⚠️ MEDIUM
**What:** `requireResidentKey: false` for passwordless scenario
**Risk:** User enumeration via username
**Current:** NOT DETECTED
**Should:** Recommend resident keys for true passwordless
**CVSS:** 5.0
**Impact:** Username/email still required (not truly passwordless)
**Detect:** Check requireResidentKey in create() options

### 8. Authenticator Selection Not Restricted ⚠️ HIGH
**What:** `authenticatorSelection` allows any authenticator type
**Risk:** Weak authenticators accepted (platform vs cross-platform)
**Current:** NOT DETECTED
**Should:** Warn if accepting platform authenticators for high-security
**CVSS:** 6.5
**Example:** Accepting Face ID when expecting hardware security key
**Detect:** Check authenticatorSelection.authenticatorAttachment

### 9. Credential ID Predictable ⚠️ MEDIUM
**What:** Credential ID not properly randomized
**Risk:** Credential enumeration
**Current:** NOT DETECTED
**Should:** Check if credentialId length < 16 bytes
**CVSS:** 4.0
**Detect:** Validate credential ID in registration response

### 10. Missing Extensions ⚠️ LOW
**What:** FIDO2 extensions not used (txAuthSimple, uvm, etc.)
**Risk:** Missing transaction confirmation or verification methods
**Current:** NOT DETECTED
**Should:** INFO level - suggest extensions for banking/finance
**CVSS:** 3.0
**Detect:** Check extensions in create/get options

### 11. Backup Eligibility Not Checked ⚠️ MEDIUM
**What:** `backupEligible` flag not validated
**Risk:** Single-device credentials without backup
**Current:** NOT DETECTED
**Should:** Warn if backupEligible=false (user loses access if device lost)
**CVSS:** 4.5
**Detect:** Check authenticatorData flags (ED flag bit 4)

### 12. User Handle Not Unique ⚠️ HIGH
**What:** `userHandle` (user.id) not unique per user
**Risk:** Credential confusion, account takeover
**Current:** NOT DETECTED
**Should:** Warn if userHandle looks like username/email (should be opaque)
**CVSS:** 7.5
**Attack:** Attacker uses same userHandle for different users
**Detect:** Check if user.id in create() is email/username

### 13. Phishing-Resistant Not Enforced ⚠️ HIGH
**What:** Accepting non-phishing-resistant authenticators
**Risk:** SMS OTP, TOTP accepted instead of FIDO2
**Current:** NOT DETECTED
**Should:** Detect if server accepts non-WebAuthn 2FA as fallback
**CVSS:** 7.0
**Attack:** Attacker bypasses WebAuthn with weaker SMS OTP
**Detect:** Check if other 2FA methods available

### 14. Conditional Mediation Misuse ⚠️ MEDIUM
**What:** `mediation: "conditional"` used incorrectly
**Risk:** Credential autofill not working or over-prompting
**Current:** NOT DETECTED
**Should:** Warn if conditional mediation without autocomplete="webauthn"
**CVSS:** 4.0
**Detect:** Check mediation parameter

### 15. CTAP2 Downgrade Attack ⚠️ HIGH
**What:** FIDO2 authenticator downgraded to U2F (CTAP1)
**Risk:** Loss of user verification, resident keys
**Current:** NOT DETECTED
**Should:** Detect U2F fallback when FIDO2 expected
**CVSS:** 6.5
**Detect:** Check attestation format (fido-u2f vs packed)

### 16. Credential Counter Not Validated ⚠️ HIGH
**What:** Sign counter not checked for cloning detection
**Risk:** Cloned authenticator not detected
**Current:** NOT DETECTED
**Should:** Warn if counter doesn't increment
**CVSS:** 7.0
**Attack:** Attacker clones security key, uses it in parallel
**Detect:** Track signCount in authenticatorData

### 17. Large Blob Not Encrypted ⚠️ MEDIUM
**What:** `largeBlob` extension stores sensitive data unencrypted
**Risk:** Data leakage if authenticator compromised
**Current:** NOT DETECTED
**Should:** Warn if largeBlob contains apparent PII
**CVSS:** 5.5
**Detect:** Check largeBlob extension data

### 18. AppID Extension Misuse (U2F Migration) ⚠️ MEDIUM
**What:** `appid` extension used for new registrations
**Risk:** Tying new credentials to legacy U2F app ID
**Current:** NOT DETECTED
**Should:** Warn if appid extension in create() vs get()
**CVSS:** 4.0
**Detect:** Check for appid in creation options

### 19. PRF Extension Without Encryption ⚠️ HIGH
**What:** PRF (Pseudo-Random Function) output not encrypted
**Risk:** Derived secrets leaked
**Current:** NOT DETECTED
**Should:** Warn if PRF used without proper key derivation
**CVSS:** 7.0
**Detect:** Check prf extension usage

### 20. Cross-Device Authentication Without QR ⚠️ LOW
**What:** Hybrid transport used insecurely
**Risk:** MITM in cross-device flow
**Current:** NOT DETECTED
**Should:** Info if hybrid transport without BLE/NFC verification
**CVSS:** 3.5
**Detect:** Check transports array

## WebAuthn Protocol-Level Issues

### 21. ClientDataJSON Tampering ⚠️ CRITICAL
**What:** clientDataJSON not properly validated
**Risk:** Attacker modifies challenge, origin, or type
**Current:** NOT DETECTED (browser validates, but server should too)
**Should:** Validate JSON structure and fields
**CVSS:** 9.0
**Detect:** Parse and validate clientDataJSON in response

### 22. AuthenticatorData Not Parsed ⚠️ HIGH
**What:** Server doesn't parse authenticatorData properly
**Risk:** Missing flags, credential data, extensions
**Current:** NOT DETECTED
**Should:** Validate RP ID hash, flags, counter
**CVSS:** 7.5
**Detect:** Parse authenticatorData bytes

### 23. AAGUID Leakage (Privacy) ⚠️ LOW
**What:** AAGUID reveals authenticator make/model
**Risk:** Device fingerprinting
**Current:** NOT DETECTED
**Should:** INFO level privacy warning
**CVSS:** 2.5
**Detect:** Extract AAGUID from authenticatorData

### 24. Attestation Format Unknown ⚠️ MEDIUM
**What:** Server accepts unknown attestation formats
**Risk:** Malicious/unvalidated attestation
**Current:** NOT DETECTED
**Should:** Warn if attestation format not in (packed, fido-u2f, android-key, android-safetynet, tpm, apple, none)
**CVSS:** 5.0
**Detect:** Check fmt in attestation object

### 25. Public Key Algorithm Weak ⚠️ HIGH
**What:** Accepting weak algorithms (RS1, ES256K with weak params)
**Risk:** Signature forgery
**Current:** NOT DETECTED
**Should:** CRITICAL if alg=-257 (RS256 deprecated for WebAuthn)
**CVSS:** 7.0
**Recommend:** ES256 (alg=-7) or EdDSA (alg=-8)
**Detect:** Check pubKeyCredParams in create() options

## Real-World WebAuthn CVEs

### CVE-2022-27262 (Duo)
**Issue:** Missing user verification validation
**Impact:** Authentication without biometric/PIN
**We detect:** NO

### CVE-2023-38038 (Keycloak)
**Issue:** Weak challenge generation
**Impact:** Challenge prediction attack
**We detect:** NO

### CVE-2021-41510 (Auth0)
**Issue:** Cross-origin credential theft attempt
**Impact:** Phishing via origin confusion
**We detect:** NO (browser blocks, but we should warn)

### CVE-2020-11022 (Generic)
**Issue:** Attestation validation bypass
**Impact:** Malicious authenticators accepted
**We detect:** NO

## Implementation Priority

### P0 - Implement Immediately:
1. Missing user verification (userVerification !== "required")
2. Weak challenge entropy (< 16 bytes)
3. Challenge reuse detection
4. Cross-origin credential theft attempts
5. Credential counter not incrementing (cloning detection)

### P1 - Next Sprint:
6. Attestation not validated
7. User handle not unique
8. rpId mismatch with origin
9. Authenticator selection not restricted
10. Public key algorithm weak

### P2 - Future:
11. Missing timeout
12. Resident key recommendations
13. Backup eligibility warnings
14. CTAP2 downgrade detection
15. Extensions validation
16. AAGUID privacy warnings

## Detection Implementation Notes

### Browser Context Limitations:
- We can see `navigator.credentials.create()` calls via content scripts
- We can intercept request/response to WebAuthn API
- We CAN'T see server-side validation (but can detect missing client-side checks)
- We CAN'T verify signatures (no access to public keys)

### What We Can Detect:
✅ Options passed to create/get (challenge, userVerification, etc.)
✅ Response structure (attestation, authenticatorData)
✅ Client-side JavaScript using WebAuthn API
✅ Missing or weak parameters
✅ Improper usage patterns

### What We Can't Detect:
❌ Server-side validation logic
❌ Actual signature verification
❌ Attestation chain validation
❌ Private key security in authenticator

## Recommended Approach

1. **Inject content script** to monitor `navigator.credentials.*` calls
2. **Intercept API calls** and validate options
3. **Parse responses** for credential data
4. **Track challenges** to detect reuse
5. **Validate fields** against FIDO2 specs
6. **Surface findings** in merged dashboard with JSON highlighting

Would show like:
```
microsoft.com  POST  /webauthn/register  200  [3 issues]

CRITICAL: userVerification set to "preferred" instead of "required"
HIGH: challenge only 12 bytes (minimum 16 recommended)
MEDIUM: attestation=none (can't verify authentic hardware key)

Request Data:
{
  "publicKey": {
    "challenge": "..." ← Only 12 bytes (weak)
    "userVerification": "preferred" ← Should be "required"
    "attestation": "none" ← Can't verify hardware
  }
}
```
