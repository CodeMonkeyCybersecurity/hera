# Hera Authentication Security Testing Roadmap

**Last Updated:** 2025-10-28
**Version:** 0.2.0
**Standards Compliance:** RFC 9700 (OAuth 2.1), OWASP WSTG 2025, CVSS 4.0, Bugcrowd VRT

---

## P0 Issues - COMPLETED ✅

### P0-1: Evidence Persistence (IndexedDB) ✅
**Problem:** Evidence cache showed "NOT synced" - all data lost on crash
**Solution:** Implemented IndexedDB auto-save every 60 seconds
**Status:** SHIPPED

### P0-4: Permissions Policy Violation (unload event) ✅
**Problem:** `unload` event blocked by Permissions Policy on modern sites (DuckDuckGo, etc.)
**Solution:** Replaced deprecated `unload` with modern `visibilitychange` + `pagehide` + auto-flush
**Status:** SHIPPED

**Error before:**
```
Permissions policy violation: unload is not allowed in this document.
Context: https://duckduckgo.com/
Stack Trace: modules/content/message-queue.js:23 (ThrottledMessageQueue)
```

**Why this happened:**
- `unload` event is deprecated (2020+)
- Modern sites block it via Permissions-Policy header
- Breaks back/forward cache (bfcache)
- Unreliable (fires only 50-70% of the time on mobile)

**Solution implemented:**
1. **visibilitychange** - Flush queue when page hidden (mobile-friendly)
2. **pagehide** - Final flush before page destroyed (more reliable)
3. **Auto-flush** - Periodic flush every 5 seconds (don't rely on events)

**New behavior:**
```javascript
[MessageQueue] Page hidden - flushing queue
[MessageQueue] Flushing 3 messages
[MessageQueue] Sent: ANALYSIS_COMPLETE
```

**Changes:**
- Auto-save to IndexedDB every 60 seconds
- Save on visibility change (tab hidden/closed)
- Persistent storage survives browser restart
- Migration from chrome.storage.local to IndexedDB
- No quota limits (vs 10MB chrome.storage limit)

**Log output before:**
```
Evidence cache (in-memory only, NOT synced): 161 responses, 0.17 MB
```

**Log output after:**
```
[Evidence] 161 responses, 161 events (0.17 MB) - ✓ Saved 3s ago
[Evidence] Auto-saved to IndexedDB (last sync: 60s ago)
```

---

### P0-2: Structured Logging ✅
**Problem:** Logs showed useless "Object, Object, Object"
**Solution:** Replaced with human-readable structured logs
**Status:** SHIPPED

**Changes:**
- `console.debug()` for routine messages
- `console.log()` for important events
- `console.error()` for failures
- Clear message categories: `[Evidence]`, `[Analysis]`, `[Message]`, `[Interceptor]`

**Log output before:**
```
MessageRouter: Message received (action handler): Object
MessageRouter: Message received (type handler): Object
MessageRouter: handleTypeMessage called with: Object
MessageRouter: Authorization check: Object
```

**Log output after:**
```
[Message] INJECT_RESPONSE_INTERCEPTOR from console.hetzner.com
[Interceptor] Injection successful for tab 54209604
```

---

### P0-3: Finding Summaries in Logs ✅
**Problem:** Analysis complete but no visibility into what was found
**Solution:** Log human-friendly summaries with findings breakdown
**Status:** SHIPPED

**Changes:**
- Show security score with rating (EXCELLENT/GOOD/FAIR/POOR/CRITICAL)
- Group findings by severity
- Display top 3 findings with icons
- Clear call-to-action ("Click Hera icon to view details")

**Log output before:**
```
MessageRouter: Analysis complete for: https://console.hetzner.com/...
MessageRouter: Score data: Object
MessageRouter: Analysis results stored successfully
```

**Log output after:**
```
[Analysis] console.hetzner.com - Score: 87/100 (GOOD)
  Findings: 2 (1 MEDIUM, 1 LOW)
  ⚠️  Cookie missing SameSite=Strict
  ⚠️  Response exposes server version
[Analysis] Results stored - Click Hera icon to view details
```

---

## Research Foundation: Industry Best Practices (2025)

This roadmap is informed by comprehensive research into current authentication security testing standards:

### 📋 Standards Reviewed
1. **RFC 9700** - OAuth 2.0 Security Best Current Practice (Jan 2025, IETF)
2. **OWASP WSTG** - Web Security Testing Guide 2025 (Authentication Testing)
3. **CVSS 4.0** - Common Vulnerability Scoring System (Nov 2023, FIRST.org)
4. **Bugcrowd VRT** - Vulnerability Rating Taxonomy (Industry standard P1-P5)
5. **NIST SP 800-63B** - Digital Identity Guidelines (Authentication & Lifecycle)

### 🔍 Key Industry Changes (2025)
- **PKCE now MANDATORY** for ALL OAuth 2.0 flows (public + confidential clients per RFC 9700)
- **Implicit grant MUST NOT be used** (deprecated in OAuth 2.1)
- **DPoP (Demonstration of Proof-of-Possession)** - New sender-constrained token standard
- **Refresh token rotation** required for security
- **CVSS 4.0** adds User Interaction (UI) and Privileges Required (PR) metrics
- **MFA detection** critical for bug bounty programs (99.9% attack prevention per Microsoft)

### ✅ Hera's Current Strengths
Based on adversarial codebase analysis (see [CLAUDE.md](CLAUDE.md)):
- ✅ 50+ vulnerability types across OAuth2/OIDC/JWT/Sessions/HSTS/CSRF/PKCE/WebAuthn
- ✅ Evidence-based confidence scoring (reduces false positives)
- ✅ Context-aware severity (HSTS risk varies by application type)
- ✅ RFC-compliant exemptions (OAuth2 token endpoints exempt from CSRF)
- ✅ Bug bounty ready (CWE/CVE references, CVSS 3.x scores)
- ✅ Smart 3-tier token redaction (high/medium/low risk)
- ✅ Persistent evidence (IndexedDB storage survives crashes)

### ❌ Critical Gaps Identified
1. **OAuth 2.1 / RFC 9700 compliance** - Missing DPoP, refresh rotation, PKCE for confidential clients
2. **CVSS 4.0 integration** - Still using hardcoded CVSS 3.x scores
3. **Bugcrowd VRT alignment** - No P1-P5 severity mapping
4. **Passive MFA detection** - WebAuthn module exists but incomplete
5. **Session lifecycle tracking** - No timeout/rotation testing
6. **Enhanced export formats** - Evidence collected but not user-friendly in exports

### ⚠️ ADVERSARIAL ANALYSIS FINDINGS (See CLAUDE.md Part 7)

**BLOCKERS identified before P1 can start:**
1. **Response body capture missing** - Required for DPoP validation and WebAuthn detection
2. **Token tracking conflicts with redaction** - Need secure hash-based tracking
3. **"Passive" session timeout requires active testing** - Contradiction with passive-first principle

**CORRECTIONS required:**
4. DPoP severity should be INFO (not MEDIUM) - RFC 9449 says it's optional
5. PKCE severity should remain context-dependent (HIGH for public, MEDIUM for confidential)
6. TOTP detection needs context checks (high false positive rate on numeric patterns)
7. Active testing "safe tests" are not safe (remove CSRF/refresh token tests)
8. CVSS 4.0 implementation should use existing library (not implement from scratch)

**See [CLAUDE.md](./CLAUDE.md#part-7-adversarial-analysis-of-roadmapmd-v020) for detailed analysis with evidence.**

---

## P0 Prerequisites - RFC 9700 & MFA Detection Blockers ✅

**Status:** COMPLETED (2025-10-28)

These modules were identified as BLOCKERS for P1-5 (RFC 9700) and P2-7 (MFA Detection) during adversarial analysis.

### P0-A: Response Body Capture Infrastructure ✅
**Status:** SHIPPED

**Problem:**
- DPoP detection requires reading `token_type` from response body
- WebAuthn detection requires reading challenge from response body
- Current implementation only captures response headers

**Solution:**
Implemented [modules/response-body-capturer.js](modules/response-body-capturer.js) using chrome.debugger API.

**Features:**
- Auto-attaches debugger to tabs when auth requests detected
- Captures response bodies for OAuth2 token endpoints
- Captures WebAuthn/FIDO2 challenges
- Captures MFA/OTP responses
- 3-tier redaction (HIGH/MEDIUM/LOW risk)
- User consent required (shows "DevTools is debugging" notification)

**Security:**
- Only captures auth-related responses (filtered by URL patterns)
- Full redaction of sensitive tokens (access_token, refresh_token, id_token)
- Partial redaction of challenges (WebAuthn, TOTP)
- No redaction of metadata (token_type, expires_in, scope)

**Integration:**
- [modules/webrequest-listeners.js](modules/webrequest-listeners.js#L103-106) - Auto-attach on auth request
- [evidence-collector.js](evidence-collector.js#L509-625) - Process response bodies

**Files:**
- `/modules/response-body-capturer.js` (new)
- `/modules/webrequest-listeners.js` (updated)
- `/evidence-collector.js` (added processResponseBody method)
- `/background.js` (initialized module)

---

### P0-B: Secure Hash-Based Token Tracking ✅
**Status:** SHIPPED

**Problem:**
- Refresh token rotation detection requires comparing tokens
- Current token redaction reduces to 4+4 chars (not enough for comparison)
- Cannot store plaintext tokens (security risk)

**Solution:**
Implemented [modules/auth/refresh-token-tracker.js](modules/auth/refresh-token-tracker.js) with SHA-256 hashing.

**Features:**
- One-way hashing (cannot recover token from hash)
- Stores only first 16 chars of hash (sufficient for collision detection)
- Automatic cleanup (7 day TTL)
- Memory-only storage (cleared on browser restart)
- No PII stored

**Detection:**
```javascript
{
  type: 'REFRESH_TOKEN_NOT_ROTATED',
  severity: 'HIGH',
  confidence: 'HIGH',
  message: 'Refresh token was not rotated on use (RFC 9700 violation)',
  evidence: {
    domain: 'login.microsoftonline.com',
    tokenHash: 'a3f2c8d1b5e9f7a4...', // Safe (one-way)
    useCount: 3,
    timeSinceFirstUse: 3600000 // 1 hour
  }
}
```

**Integration:**
- [modules/webrequest-listeners.js](modules/webrequest-listeners.js#L319-343) - Track on token response
- [modules/auth/refresh-token-tracker.js](modules/auth/refresh-token-tracker.js) - Secure hashing

**Files:**
- `/modules/auth/refresh-token-tracker.js` (new)
- `/modules/webrequest-listeners.js` (updated)
- `/background.js` (initialized module)

---

### P0-C: Critical Bug Fixes (Post-Adversarial Analysis) ✅
**Status:** SHIPPED (2025-10-28)

**Problem:**
Adversarial analysis revealed 3 critical bugs that prevented P0-A and P0-B from working:

**Critical Bugs Fixed:**

1. **❌ → ✅ ResponseCache vs AuthRequests Mismatch**
   - **Bug:** `processResponseBody()` looked in `this.responseCache`, but `ResponseBodyCapturer` stored in `authRequests`
   - **Impact:** NO response body analysis ever happened (silent failure)
   - **Fix:** Modified `processResponseBody()` to accept `authRequests` as parameter
   - **Files:** [evidence-collector.js:526](evidence-collector.js#L526), [response-body-capturer.js:222](modules/response-body-capturer.js#L222)

2. **❌ → ✅ Token Tracking After Redaction**
   - **Bug:** Tokens redacted BEFORE tracking, making rotation detection impossible
   - **Impact:** Refresh token tracking always returned null (broken by design)
   - **Fix:** Track tokens BEFORE redaction in `ResponseBodyCapturer._handleResponseReceived()`
   - **Files:** [response-body-capturer.js:215-230](modules/response-body-capturer.js#L215-230), [background.js:252-253](background.js#L252-253)

3. **❌ → ✅ Unhandled Promise Rejections**
   - **Bug:** `handleAuthRequest()` called without `.catch()` handler
   - **Impact:** Errors in debugger attachment caused uncaught exceptions
   - **Fix:** Added `.catch()` with proper error handling
   - **Files:** [webrequest-listeners.js:106-110](modules/webrequest-listeners.js#L106-110)

**Additional Improvements:**

4. **Response Size Limits**
   - Added 1MB size check before/after fetching response body
   - Prevents memory issues from large responses
   - **Files:** [response-body-capturer.js:184-209](modules/response-body-capturer.js#L184-209)

5. **Better Error Handling**
   - Specific handling for tab closure, DevTools conflicts, missing resources
   - No more uncaught exceptions
   - **Files:** [response-body-capturer.js:255-272](modules/response-body-capturer.js#L255-272)

6. **Improved RequestId Matching**
   - Best-match algorithm using timestamp proximity
   - Handles duplicate simultaneous requests to same URL
   - **Files:** [response-body-capturer.js:313-342](modules/response-body-capturer.js#L313-342)

7. **Debugger Lifecycle Safety**
   - Global `chrome.debugger.onDetach` listener registered once
   - Prevents per-tab listener leaks when analyzing many tabs
   - **Files:** [modules/response-body-capturer.js:72-78](modules/response-body-capturer.js#L72-L78)

8. **Capture Rate Limiting**
   - Per-domain rate limiting (10 captures/min, 1-minute window)
   - Mitigates malicious request flooding/DOS
   - **Files:** [modules/response-body-capturer.js:36-38](modules/response-body-capturer.js#L36-L38), [modules/response-body-capturer.js:359-388](modules/response-body-capturer.js#L359-L388)

**Testing:**
- See [P0_INTEGRATION_TESTS.md](P0_INTEGRATION_TESTS.md) for comprehensive test plan
- Manual tests: Microsoft OAuth2, Google OAuth2, GitHub OAuth2
- Edge cases: DevTools conflicts, tab closure, large responses, non-JSON, duplicates

---

**UNBLOCKED:** P1-5 (RFC 9700) and P2-7 (MFA Detection) can now proceed.

---

## P1 Issues - Standards Compliance & Core Enhancements (Weeks 1-4)

### P1-0: Message Queue Reliability Improvements
**Status:** PLANNED

**Goal:** Prevent message loss on page navigation/crash

**Current issues:**
1. Messages lost if user closes tab immediately
2. No persistence - queue is memory-only
3. No retry logic for failed sends
4. No expiration - messages can queue forever

**Implementation:**

```javascript
class ThrottledMessageQueue {
  constructor() {
    // ... existing code ...
    this.MAX_MESSAGE_AGE_MS = 5 * 60 * 1000; // 5 minutes
    this._restorePersistedQueue(); // Load from storage on init
  }

  // 1. Persist queue to chrome.storage.session
  async _persistQueue() {
    await chrome.storage.session.set({
      heraMessageQueue: this.queue.map(item => ({
        message: item.message,
        priority: item.priority,
        timestamp: item.timestamp,
        expiresAt: item.expiresAt
      }))
    });
  }

  // 2. Restore queue on initialization
  async _restorePersistedQueue() {
    const data = await chrome.storage.session.get('heraMessageQueue');
    if (data.heraMessageQueue) {
      this.queue = data.heraMessageQueue;
      this._removeExpiredMessages();
      console.log(`[MessageQueue] Restored ${this.queue.length} messages`);
      this._processQueue();
    }
  }

  // 3. Remove expired messages
  _removeExpiredMessages() {
    const now = Date.now();
    const before = this.queue.length;
    this.queue = this.queue.filter(item => item.expiresAt > now);
    const removed = before - this.queue.length;
    if (removed > 0) {
      console.warn(`[MessageQueue] Removed ${removed} expired messages`);
    }
  }

  // 4. Retry logic with exponential backoff
  async _sendMessage(message, retries = 3) {
    for (let attempt = 0; attempt < retries; attempt++) {
      try {
        await chrome.runtime.sendMessage(message);
        return true;
      } catch (error) {
        if (attempt < retries - 1) {
          const delay = Math.pow(2, attempt) * 100; // 100ms, 200ms, 400ms
          await new Promise(resolve => setTimeout(resolve, delay));
        } else {
          // Last resort: persist to failed message queue
          this._persistFailedMessage(message);
          return false;
        }
      }
    }
  }

  // 5. Failed message recovery
  _persistFailedMessage(message) {
    chrome.storage.local.get(['heraFailedMessages'], (result) => {
      const failed = result.heraFailedMessages || [];
      failed.push({
        message,
        failedAt: Date.now(),
        retries: 0
      });
      chrome.storage.local.set({
        heraFailedMessages: failed.slice(-50) // Keep last 50
      });
      console.error(`[MessageQueue] Message failed - stored for recovery`);
    });
  }
}
```

**User benefit:** No more lost security analysis results

---

### P1-1: Evidence Export Notifications
**Status:** PLANNED

**Goal:** Notify users when high-confidence findings are detected

**Implementation:**
```javascript
// When high-confidence finding detected
if (finding.confidence === 'HIGH' && finding.severity >= 'MEDIUM') {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon-warning.png',
    title: 'Hera: High-Confidence Finding',
    message: `${finding.type} detected on ${domain}`,
    buttons: [
      { title: 'View Evidence' },
      { title: 'Export Report' }
    ]
  });

  // Update badge with finding count
  chrome.action.setBadgeText({ text: findingCount.toString() });
  chrome.action.setBadgeBackgroundColor({ color: '#FF0000' });
}
```

**User benefit:** Immediate awareness when vulnerabilities are found

---

### P1-2: Evidence Quality Indicators
**Status:** PLANNED

**Goal:** Show users how complete their evidence is

**Implementation:**
```javascript
// Calculate evidence completeness
const quality = {
  requestCoverage: {
    hasAuthFlow: !!evidence.authorizationRequest,
    hasTokenExchange: !!evidence.tokenRequest,
    hasTokenRefresh: !!evidence.refreshRequest,
    percentage: Math.floor((found / total) * 100)
  },
  evidenceCompleteness: {
    hasRequestHeaders: !!evidence.requestHeaders,
    hasResponseHeaders: !!evidence.responseHeaders,
    hasRequestBody: !!evidence.requestBody,
    hasResponseBody: !!evidence.responseBody,
    hasTimingData: !!evidence.timing,
    percentage: Math.floor((fields / 5) * 100)
  },
  findingConfidence: {
    averageConfidence: avgConfidence,
    highConfidenceCount: highCount,
    suggestions: getSuggestions(evidence)
  }
};

console.log('[Evidence Quality] console.hetzner.com');
console.log(`  Request Coverage:  ${quality.requestCoverage.percentage}%`);
console.log(`  Evidence Complete: ${quality.evidenceCompleteness.percentage}%`);
console.log(`  Finding Confidence: ${quality.findingConfidence.averageConfidence}%`);

if (quality.findingConfidence.suggestions.length > 0) {
  console.log('  Suggestions:');
  quality.findingConfidence.suggestions.forEach(s => {
    console.log(`    • ${s}`);
  });
}
```

**User benefit:** Know when to stop testing (sufficient evidence collected)

---

### P1-3: Batch Log Updates (Reduce Spam)
**Status:** PLANNED

**Goal:** Reduce console spam from evidence collection

**Implementation:**
```javascript
class EvidenceCollector {
  constructor() {
    this.lastLogTime = 0;
    this.LOG_INTERVAL_MS = 10000; // Log every 10 seconds max
    this.pendingUpdates = 0;
  }

  _shouldLog() {
    const now = Date.now();
    if (now - this.lastLogTime > this.LOG_INTERVAL_MS) {
      this.lastLogTime = now;
      return true;
    }
    return false;
  }

  captureResponse(requestId, responseHeaders, responseBody, statusCode) {
    // ... existing code ...

    this.pendingUpdates++;

    if (this._shouldLog()) {
      console.log(`[Evidence] Captured ${this.pendingUpdates} responses in ${this.LOG_INTERVAL_MS / 1000}s`);
      this.pendingUpdates = 0;
    }
  }
}
```

**User benefit:** Clean console logs, no spam

---

### P1-4: Export Format Options
**Status:** PLANNED

**Goal:** Allow users to export evidence in multiple formats

**Formats:**
1. **PDF Report** - Human-readable bug bounty report
2. **JSON Evidence** - Machine-readable for tools
3. **HAR File** - Burp Suite / ZAP import
4. **Markdown Summary** - Documentation friendly

**Implementation:**
```javascript
class EvidenceExporter {
  async exportAsPDF(evidence, findings) {
    // Use jsPDF or similar
    const doc = new jsPDF();

    // Title page
    doc.setFontSize(20);
    doc.text('Security Assessment Report', 20, 20);
    doc.setFontSize(12);
    doc.text(`Target: ${evidence.domain}`, 20, 30);
    doc.text(`Date: ${new Date().toISOString()}`, 20, 40);

    // Executive summary
    doc.text('Executive Summary', 20, 60);
    doc.text(`Overall Score: ${evidence.score}/100`, 20, 70);
    doc.text(`Findings: ${findings.length}`, 20, 80);

    // Detailed findings
    findings.forEach((finding, i) => {
      doc.addPage();
      doc.setFontSize(16);
      doc.text(`Finding ${i + 1}: ${finding.title}`, 20, 20);
      doc.setFontSize(12);
      doc.text(`Severity: ${finding.severity}`, 20, 30);
      doc.text(`Confidence: ${finding.confidence}`, 20, 40);
      doc.text('Evidence:', 20, 50);
      doc.text(JSON.stringify(finding.evidence, null, 2), 20, 60);
    });

    return doc.output('blob');
  }

  async exportAsJSON(evidence, findings) {
    return JSON.stringify({
      version: '1.0',
      tool: 'Hera',
      timestamp: Date.now(),
      target: evidence.domain,
      score: evidence.score,
      findings: findings.map(f => ({
        ...f,
        evidence: f.evidence,
        cwe: f.cwe,
        cvss: f.cvss
      })),
      evidence: {
        requests: evidence.requests,
        responses: evidence.responses,
        timeline: evidence.timeline
      }
    }, null, 2);
  }

  async exportAsHAR(evidence) {
    return {
      log: {
        version: '1.2',
        creator: {
          name: 'Hera',
          version: chrome.runtime.getManifest().version
        },
        entries: evidence.requests.map(req => ({
          startedDateTime: new Date(req.timestamp).toISOString(),
          time: req.timing?.duration || 0,
          request: {
            method: req.method,
            url: req.url,
            headers: req.headers,
            postData: req.body ? { text: req.body } : undefined
          },
          response: {
            status: req.statusCode,
            headers: req.responseHeaders,
            content: req.responseBody ? { text: req.responseBody } : undefined
          }
        }))
      }
    };
  }
}
```

**User benefit:** Flexible export for different use cases

---

### P1-5: RFC 9700 (OAuth 2.1) Compliance ⭐ NEW
**Status:** PLANNED → **UNBLOCKED** ✅ (P0 prerequisites complete)
**Priority:** CRITICAL
**Timeline:** **4-6 weeks** (realistic estimate with testing and integration)
**Standards:** RFC 9700, RFC 9449 (DPoP), RFC 8707 (Resource Indicators)

**✅ PREREQUISITES COMPLETE (P0-A, P0-B):**
1. ✅ Response body capture implemented (chrome.debugger API)
2. ✅ Secure token tracking implemented (SHA-256 hashing)

**⚠️ IMPLEMENTATION CORRECTIONS REQUIRED:**
3. **DPoP severity** - Use INFO (optional per RFC 9449), not MEDIUM
4. **PKCE severity** - Context-dependent: HIGH for public clients, MEDIUM for confidential clients with client_secret

**Goal:** Align Hera with 2025 OAuth security best practices

**What's changing in OAuth 2.1:**
- PKCE **SHOULD be used** for ALL clients per RFC 9700 (REQUIRED for public, RECOMMENDED for confidential)
- Implicit grant completely removed (MUST NOT use)
- Refresh token rotation SHOULD be implemented
- DPoP for sender-constrained tokens (OPTIONAL enhancement)

**New Detections:**

1. **DPoP (Demonstration of Proof-of-Possession) - RFC 9449**

   **⚠️ CORRECTION REQUIRED:** DPoP is OPTIONAL per RFC 9449. Severity should be INFO, not MEDIUM.

   ```javascript
   // Detection logic (CORRECTED)
   checkDPoP(request, tokenRequest) {
     const hasDPoPHeader = request.headers.some(h => h.name.toLowerCase() === 'dpop');
     const hasDPoPProofJWT = hasDPoPHeader && this.validateDPoPJWT(request.headers);

     if (!hasDPoPHeader && this.isPublicClient(request)) {
       return {
         type: 'DPOP_NOT_IMPLEMENTED',
         severity: 'INFO',  // ← CORRECTED: Was MEDIUM
         message: 'DPoP not detected - tokens not sender-constrained',
         note: 'DPoP is optional per RFC 9449. Consider implementing for enhanced security.',
         cwe: 'CWE-319',
         evidence: {
           endpoint: request.url,
           clientType: 'public',
           recommendation: 'Implement DPoP per RFC 9449 for defense-in-depth'
         }
       };
     }
   }
   ```
   - **Finding:** "DPoP not implemented" (INFO)
   - **Impact:** Informational - tokens not sender-constrained but DPoP is optional
   - **Evidence:** DPoP header presence, token binding capability

2. **Refresh Token Rotation**

   **⚠️ BLOCKER:** Current token redaction reduces refresh_token to 4+4 chars. Cannot track equality.

   **Solution:** Secure hash-based tracking (no plaintext storage):

   ```javascript
   // Track refresh token reuse via secure hashes
   class RefreshTokenTracker {
     constructor() {
       this.seenHashes = new Map();  // Hash → metadata
     }

     async trackRefreshToken(tokenResponse) {
       const refreshToken = tokenResponse.refresh_token;

       // Hash token (never store plaintext)
       const hash = await crypto.subtle.digest(
         'SHA-256',
         new TextEncoder().encode(refreshToken)
       );
       const hashHex = Array.from(new Uint8Array(hash))
         .map(b => b.toString(16).padStart(2, '0'))
         .join('');

       if (this.seenHashes.has(hashHex)) {
         return {
           type: 'REFRESH_TOKEN_NOT_ROTATED',
           severity: 'HIGH',
           message: 'Refresh token reused - not rotated after exchange',
           cwe: 'CWE-326',
           cvss: 7.0,
           evidence: {
             firstSeen: this.seenHashes.get(hashHex).timestamp,
             reusedAt: Date.now(),
             tokenHash: hashHex.substring(0, 16) + '...',  // Partial hash for evidence
             recommendation: 'Rotate refresh tokens on every use per RFC 6749 Section 10.4'
           }
         };
       }

       this.seenHashes.set(hashHex, {
         timestamp: Date.now(),
         used: false
       });
     }
   }
   ```
   - **Finding:** "Refresh token not rotated after use" (HIGH)
   - **Impact:** Stolen refresh tokens have extended lifetime
   - **Evidence:** Hash collision detection (secure, no plaintext exposure)

3. **PKCE for ALL Clients (Not Just Public)**

   **✅ CORRECTED:** RFC 9700 says PKCE "SHOULD" be used (RFC 2119 = recommended, not required). Using context-dependent severity.

   ```javascript
   // Update existing oauth2-analyzer.js (CORRECTED - READY TO IMPLEMENT)
   detectMissingPKCE(request, clientType, hasClientSecret) {
     const params = this.parseParams(request.url);
     const hasPKCE = params.has('code_challenge');

     // RFC 9700 Section 2.1.1: PKCE SHOULD be used for ALL clients
     if (!hasPKCE) {
       // Context-dependent severity (CRITICAL DESIGN DECISION)
       if (clientType === 'public') {
         return {
           type: 'MISSING_PKCE',
           severity: 'HIGH',  // REQUIRED for public clients (no client_secret)
           message: 'PKCE missing on public client - authorization code interception possible',
           cwe: 'CWE-523',
           cvss: 7.5,
           rfcViolation: 'RFC 9700 Section 2.1.1 (MUST for public clients)',
           evidence: {
             clientType: 'public',
             authEndpoint: request.url,
             hasCompensatingControl: false,
             recommendation: 'Implement PKCE immediately - REQUIRED for public clients'
           }
         };
       } else if (clientType === 'confidential' && hasClientSecret) {
         return {
           type: 'MISSING_PKCE_CONFIDENTIAL',  // Separate finding type
           severity: 'MEDIUM',  // RECOMMENDED (has client_secret as fallback)
           message: 'PKCE not implemented on confidential client',
           note: 'RFC 9700 recommends PKCE for all clients. Confidential clients have client_secret as compensating control.',
           cwe: 'CWE-523',
           cvss: 5.0,
           rfcViolation: 'RFC 9700 Section 2.1.1 (SHOULD for confidential clients)',
           evidence: {
             clientType: 'confidential',
             hasCompensatingControl: 'client_secret',
             recommendation: 'Consider implementing PKCE for defense-in-depth per RFC 9700'
           }
         };
       }
     }
   }
   ```
   - **Severity Rationale:**
     - PUBLIC client: **HIGH** - PKCE is REQUIRED (no fallback protection)
     - CONFIDENTIAL client: **MEDIUM** - PKCE is RECOMMENDED (has client_secret)
   - **Evidence:** Absence of code_challenge parameter + client type inference
   - **Bug Bounty Alignment:** Context-dependent severity matches industry acceptance rates

4. **Resource Indicators (RFC 8707)**
   ```javascript
   checkResourceIndicators(tokenRequest) {
     const params = this.parseParams(tokenRequest.body);
     const hasResource = params.has('resource');
     const hasAudience = params.has('audience');

     if (!hasResource && !hasAudience) {
       return {
         type: 'MISSING_RESOURCE_INDICATOR',
         severity: 'LOW',
         message: 'Token request without resource/audience - broad scope',
         evidence: {
           recommendation: 'Use resource parameter per RFC 8707 for audience restriction'
         }
       };
     }
   }
   ```
   - **Finding:** "Missing resource indicator - tokens have broad scope" (LOW)

**Implementation Plan:**

**Phase 1 (Week 1-2): DPoP Detection Module**

Create `modules/auth/dpop-validator.js`:
```javascript
class DPoPValidator {
  // Check if DPoP is implemented (INFO severity - optional per RFC 9449)
  checkDPoPImplementation(request, responseBody) {
    const hasDPoPHeader = request.headers.some(h => h.name.toLowerCase() === 'dpop');
    const tokenType = responseBody?.token_type?.toLowerCase();
    const isDPoP = tokenType === 'dpop';

    if (!isDPoP && this._isPublicClient(request)) {
      return {
        type: 'DPOP_NOT_IMPLEMENTED',
        severity: 'INFO',  // Optional per RFC 9449
        message: 'DPoP not detected - tokens not sender-constrained',
        note: 'DPoP is optional. Consider for enhanced security.',
        evidence: { clientType: 'public', tokenType: tokenType || 'bearer' }
      };
    }
  }

  // Validate DPoP JWT if present
  validateDPoPJWT(dpopHeader) {
    // Check: alg, typ, jwk, jti, htm, htu, iat claims
  }
}
```

**Phase 2 (Week 2-3): Refresh Token Rotation**

Enhance `modules/auth/refresh-token-tracker.js` (already exists):
```javascript
async trackRefreshToken(tokenResponse, domain) {
  const hash = await this._hashToken(tokenResponse.refresh_token);

  if (this.seenHashes.has(hash)) {
    // FINDING: Token not rotated
    return {
      type: 'REFRESH_TOKEN_NOT_ROTATED',
      severity: 'HIGH',  // RFC 9700 violation
      message: 'Refresh token reused - not rotated after exchange',
      evidence: {
        tokenHash: hash.substring(0, 16) + '...',
        useCount: this.seenHashes.get(hash).count + 1
      }
    };
  }

  this.seenHashes.set(hash, { timestamp: Date.now(), count: 1 });
  return null; // No finding
}
```

**Phase 3 (Week 3): PKCE Context-Dependent Severity**

Update `modules/auth/oauth2-analyzer.js`:
```javascript
detectMissingPKCE(request) {
  const hasPKCE = this.parseParams(request.url).has('code_challenge');
  if (hasPKCE) return null;

  const clientType = this._inferClientType(request);

  if (clientType === 'public') {
    return {
      type: 'MISSING_PKCE',
      severity: 'HIGH',  // REQUIRED for public clients
      message: 'PKCE missing - authorization code interception possible'
    };
  } else if (clientType === 'confidential') {
    return {
      type: 'MISSING_PKCE_CONFIDENTIAL',
      severity: 'MEDIUM',  // RECOMMENDED (has client_secret)
      message: 'PKCE not implemented on confidential client',
      note: 'RFC 9700 recommends PKCE for all clients. Has client_secret as compensating control.'
    };
  }
}
```

**Files to Create:**
- `/modules/auth/dpop-validator.js` - DPoP detection and validation

**Files to Update:**
- `/modules/auth/refresh-token-tracker.js` - Add finding generation (exists, needs enhancement)
- `/modules/auth/oauth2-analyzer.js` - Context-dependent PKCE severity
- `/modules/auth/auth-issue-database.js` - Add new finding types
- `/modules/response-body-capturer.js` - Call DPoP validator after token response

**Success Metrics:**
- ✅ DPoP detection with INFO severity
- ✅ Refresh rotation detection (HIGH severity when missing)
- ✅ PKCE context-dependent (HIGH for public, MEDIUM for confidential)
- ✅ <5% false positive rate
- ✅ Bug bounty acceptance rate >85%

---

### P1-6: CVSS 4.0 Integration ⭐ NEW
**Status:** PLANNED
**Priority:** HIGH
**Timeline:** Week 3 (assumes library usage) or Week 3-5 (if implementing from scratch)
**Standards:** CVSS 4.0 Specification (FIRST.org)

**⚠️ IMPLEMENTATION DECISION REQUIRED:** Use existing CVSS 4.0 library vs. implement from scratch.
- **Option A (Recommended):** Use existing library (e.g., cvss4js) - 3-5 days
- **Option B:** Implement from scratch - 2-3 weeks (FIRST.org reference is 500+ lines, MacroVector scoring is complex)

**Goal:** Standardize severity scoring with industry-standard CVSS 4.0

**Current State:** Hera uses custom severity (CRITICAL/HIGH/MEDIUM/LOW) with hardcoded CVSS 3.x scores

**CVSS 4.0 Improvements:**
- **User Interaction (UI):** None vs. Required
- **Privileges Required (PR):** None/Low/High
- Better differentiation for auth vulnerabilities

**Implementation:**

```javascript
// New module: modules/cvss-calculator.js
class CVSSCalculator {
  /**
   * Calculate CVSS 4.0 score for a finding
   * @returns {Object} { score, severity, vector }
   */
  calculateCVSS4(finding) {
    // Base Metric Group
    const metrics = {
      AV: this.getAttackVector(finding),        // Attack Vector
      AC: this.getAttackComplexity(finding),    // Attack Complexity
      AT: this.getAttackRequirements(finding),  // Attack Requirements (NEW in 4.0)
      PR: this.getPrivilegesRequired(finding),  // Privileges Required
      UI: this.getUserInteraction(finding),     // User Interaction
      VC: this.getConfidentiality(finding),     // Vulnerability Confidentiality
      VI: this.getIntegrity(finding),           // Vulnerability Integrity
      VA: this.getAvailability(finding),        // Vulnerability Availability
      SC: this.getSubsequentConfidentiality(finding),  // Subsequent System Confidentiality
      SI: this.getSubsequentIntegrity(finding),        // Subsequent System Integrity
      SA: this.getSubsequentAvailability(finding)      // Subsequent System Availability
    };

    const vector = this.buildVector(metrics);
    const score = this.computeScore(metrics);
    const severity = this.getSeverityRating(score);

    return {
      version: '4.0',
      vector: vector,  // e.g., "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
      baseScore: score,
      baseSeverity: severity,
      exploitability: this.computeExploitability(metrics),
      impact: this.computeImpact(metrics)
    };
  }

  // Mapping examples for auth vulnerabilities
  getAttackVector(finding) {
    // All web auth issues = Network
    return 'N';
  }

  getAttackComplexity(finding) {
    const lowComplexity = [
      'MISSING_CSRF_PROTECTION',
      'MISSING_SECURE_FLAG',
      'TOKEN_IN_URL',
      'MISSING_HTTPONLY_FLAG'
    ];

    const highComplexity = [
      'ALGORITHM_CONFUSION_RISK',
      'TIMING_ATTACK_POSSIBLE',
      'SESSION_FIXATION'
    ];

    if (lowComplexity.includes(finding.type)) return 'L';  // Low
    if (highComplexity.includes(finding.type)) return 'H'; // High
    return 'L';  // Default
  }

  getPrivilegesRequired(finding) {
    // Does attacker need to be authenticated?
    const noAuthRequired = [
      'MISSING_STATE',
      'WEAK_STATE',
      'MISSING_PKCE',
      'NO_HSTS'
    ];

    if (noAuthRequired.includes(finding.type)) return 'N';  // None
    if (finding.requiresAuthentication) return 'L';  // Low
    return 'N';
  }

  getUserInteraction(finding) {
    // Does victim need to perform action?
    const requiresUserAction = [
      'MISSING_CSRF_PROTECTION',  // Victim must click malicious link
      'MISSING_STATE',             // Victim must authorize
      'OPEN_REDIRECT'              // Victim must follow redirect
    ];

    const noUserAction = [
      'MISSING_SECURE_FLAG',  // Passive network sniffing
      'MISSING_HTTPONLY_FLAG', // XSS (separate issue) exploits it
      'TOKEN_LEAKED_VIA_REFERER'  // Automatic header
    ];

    if (requiresUserAction.includes(finding.type)) return 'A';  // Active (NEW in 4.0)
    if (noUserAction.includes(finding.type)) return 'N';  // None
    return 'A';  // Default: assume user action required
  }

  getConfidentiality(finding) {
    // Impact on confidentiality
    const highImpact = [
      'TOKEN_IN_URL',
      'CREDENTIALS_IN_URL',
      'ALG_NONE_VULNERABILITY',
      'SESSION_FIXATION'
    ];

    if (highImpact.includes(finding.type)) return 'H';  // High
    if (finding.severity === 'MEDIUM') return 'L';  // Low
    return 'N';  // None
  }

  getIntegrity(finding) {
    const highImpact = [
      'MISSING_CSRF_PROTECTION',
      'ALG_NONE_VULNERABILITY',
      'ALGORITHM_CONFUSION_RISK'
    ];

    if (highImpact.includes(finding.type)) return 'H';
    return 'N';
  }
}

// Example outputs:
const examples = {
  missingCSRF: {
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:H/SA:N",
    score: 7.1,
    severity: "HIGH"
  },
  missingPKCE: {
    vector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    score: 6.8,
    severity: "MEDIUM"
  },
  algNone: {
    vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N",
    score: 9.3,
    severity: "CRITICAL"
  }
};
```

**Export Format Update:**
```json
{
  "finding": {
    "type": "MISSING_CSRF_PROTECTION",
    "heraSeverity": "HIGH",
    "cvss": {
      "version": "4.0",
      "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:H/SA:N",
      "baseScore": 7.1,
      "baseSeverity": "HIGH",
      "exploitability": 3.1,
      "impact": 5.2
    },
    "cwe": "CWE-352"
  }
}
```

**Files to Create:**
- `/modules/cvss-calculator.js` - CVSS 4.0 calculator
- `/data/cvss-mappings.json` - Finding type → CVSS metric mappings

**Files to Update:**
- `/modules/auth/auth-issue-database.js` - Add CVSS 4.0 vectors to all issues
- `/modules/ui/export-manager.js` - Include CVSS 4.0 in exports

**Success Metrics:**
- ✅ All findings have valid CVSS 4.0 scores
- ✅ CVSS vector strings in all exports
- ✅ Severity alignment: Hera ≈ CVSS (±1 level acceptable)

---

### P1-7: Bugcrowd VRT Alignment ⭐ NEW
**Status:** PLANNED
**Priority:** MEDIUM
**Timeline:** Week 3-4
**Standards:** Bugcrowd Vulnerability Rating Taxonomy

**Goal:** Map Hera findings to industry-standard bug bounty severity classifications

**Bugcrowd VRT Overview:**
- **Priority Levels:** P1 (Critical) → P5 (Informational)
- **Categories:** Broken Authentication, Broken Access Control, etc.
- **Used by:** Bugcrowd, many private programs

**Implementation:**

```javascript
// New module: modules/bugcrowd-vrt-mapper.js
class BugcrowdVRTMapper {
  constructor() {
    // Load VRT taxonomy from JSON
    this.vrtTaxonomy = this.loadTaxonomy();
  }

  /**
   * Map Hera finding to Bugcrowd VRT
   */
  mapToVRT(finding) {
    const mapping = this.vrtMappings[finding.type];

    if (!mapping) {
      return this.getDefaultMapping(finding.severity);
    }

    return {
      category: mapping.category,
      subcategory: mapping.subcategory,
      priority: this.heraSeverityToPriority(finding.severity, finding.confidence),
      vrtId: mapping.vrtId,
      url: `https://bugcrowd.com/vulnerability-rating-taxonomy#${mapping.vrtId}`,
      baselinePriority: mapping.baseline,
      notes: mapping.notes
    };
  }

  heraSeverityToPriority(severity, confidence) {
    // Hera severity + confidence → VRT priority
    const mapping = {
      'CRITICAL': { high: 'P1', medium: 'P2', low: 'P3' },
      'HIGH':     { high: 'P2', medium: 'P3', low: 'P4' },
      'MEDIUM':   { high: 'P3', medium: 'P4', low: 'P5' },
      'LOW':      { high: 'P4', medium: 'P5', low: 'P5' },
      'INFO':     { high: 'P5', medium: 'P5', low: 'P5' }
    };

    const confidenceLevel = confidence >= 80 ? 'high' : confidence >= 50 ? 'medium' : 'low';
    return mapping[severity][confidenceLevel];
  }

  // VRT mappings for Hera findings
  vrtMappings = {
    'MISSING_CSRF_PROTECTION': {
      category: 'Broken Authentication and Session Management',
      subcategory: 'Cross-Site Request Forgery (CSRF)',
      vrtId: 'broken_authentication_and_session_management.csrf',
      baseline: 'P2',
      notes: 'Priority varies based on endpoint sensitivity'
    },

    'SESSION_FIXATION': {
      category: 'Broken Authentication and Session Management',
      subcategory: 'Session Fixation',
      vrtId: 'broken_authentication_and_session_management.session_fixation',
      baseline: 'P1',
      notes: 'Critical - enables account takeover'
    },

    'MISSING_PKCE': {
      category: 'Broken Authentication and Session Management',
      subcategory: 'Weak Login Function',
      vrtId: 'broken_authentication_and_session_management.weak_login_function',
      baseline: 'P2',
      notes: 'Authorization code interception attack'
    },

    'ALG_NONE_VULNERABILITY': {
      category: 'Broken Authentication and Session Management',
      subcategory: 'Weak Login Function',
      vrtId: 'broken_authentication_and_session_management.weak_login_function',
      baseline: 'P1',
      notes: 'Complete authentication bypass'
    },

    'NO_HSTS': {
      category: 'Security Misconfiguration',
      subcategory: 'Missing Security Headers',
      vrtId: 'security_misconfiguration.missing_security_headers',
      baseline: 'P4',
      notes: 'Priority increases with auth endpoints (P2-P3)'
    },

    'MISSING_HTTPONLY_FLAG': {
      category: 'Broken Authentication and Session Management',
      subcategory: 'Weak Session Token',
      vrtId: 'broken_authentication_and_session_management.weak_session_token',
      baseline: 'P2',
      notes: 'Session hijacking via XSS'
    }
    // ... more mappings
  };
}

// Export format:
{
  "finding": {
    "type": "SESSION_FIXATION",
    "heraSeverity": "CRITICAL",
    "confidence": 85,
    "bugcrowdVRT": {
      "category": "Broken Authentication and Session Management",
      "subcategory": "Session Fixation",
      "priority": "P1",
      "vrtId": "broken_authentication_and_session_management.session_fixation",
      "url": "https://bugcrowd.com/vulnerability-rating-taxonomy#broken_authentication_and_session_management.session_fixation",
      "baselinePriority": "P1",
      "notes": "Critical - enables account takeover"
    }
  }
}
```

**Files to Create:**
- `/modules/bugcrowd-vrt-mapper.js` - VRT mapping logic
- `/data/vrt-mappings.json` - Complete VRT taxonomy data
- `/docs/VRT_ALIGNMENT.md` - Documentation of mappings

**Files to Update:**
- `/modules/ui/export-manager.js` - Include VRT in exports

**Success Metrics:**
- ✅ 90%+ of findings have VRT mappings
- ✅ VRT priority aligns with bug bounty acceptance rates
- ✅ Documented justification for all P1/P2 classifications

---

## P2 Issues - Enhanced Detection & User Experience (Weeks 4-8)

### P2-7: Passive MFA Detection ⭐ NEW
**Status:** PLANNED → **BLOCKED** ⚠️
**Priority:** HIGH
**Timeline:** Week 4-5 → **Week 5-7** (includes response body prerequisite)
**Standards:** OWASP WSTG 2025, NIST SP 800-63B

**⚠️ BLOCKERS:**
1. **Response body capture required** - WebAuthn challenges are in response bodies
2. **TOTP false positives** - Need context checks (6-8 digit pattern matches ZIP codes, order IDs, etc.)

**Goal:** Detect MFA implementation and identify bypass vulnerabilities

**Background:** Microsoft research shows MFA stops 99.9% of account compromises. Detecting weak/missing MFA is high-value for bug bounties.

**Detection Opportunities (Passive):**

1. **WebAuthn/FIDO2 Detection** (Enhance existing module)
   ```javascript
   // modules/auth/mfa-detector.js
   class MFADetector {
     detectWebAuthn(request, response) {
       // Detect WebAuthn API usage
       const hasWebAuthnChallenge = this.checkWebAuthnChallenge(response);
       const hasCredentialRequest = request.url.includes('/webauthn/');

       if (hasWebAuthnChallenge || hasCredentialRequest) {
         return {
           mfaType: 'WebAuthn',
           strength: 'STRONG',
           phishingResistant: true,
           evidence: {
             challengeDetected: hasWebAuthnChallenge,
             credentialRequestSeen: hasCredentialRequest
           }
         };
       }
     }
   }
   ```

2. **TOTP/Authenticator App Detection**

   **⚠️ CRITICAL: FALSE POSITIVE PREVENTION REQUIRED**

   **Problem:** 6-8 digit pattern matches many non-MFA codes:
   - ZIP codes (5-6 digits)
   - Order IDs (6-8 digits)
   - Confirmation codes (6 digits)
   - Verification codes (non-MFA)
   - Phone numbers (partial)

   **Solution (MANDATORY):** Require AT LEAST 2 of 3 context checks before reporting:

   ```javascript
   detectTOTP(request, flowContext) {
     const params = this.parseParams(request.url + '?' + request.body);

     // Common TOTP parameter names
     const totpParams = ['otp', 'totp', 'mfa_code', 'verification_code',
                        'authenticator_code', 'token', 'code'];

     for (const paramName of totpParams) {
       if (params.has(paramName)) {
         const value = params.get(paramName);

         // TOTP codes are typically 6-8 digits
         if (/^\d{6,8}$/.test(value)) {
           // ← ADD CONTEXT CHECKS to reduce false positives
           const hasAuthContext = flowContext.recentlyAuthenticated;
           const hasMFAEndpoint = /\/(mfa|2fa|otp|verify|authenticate)/.test(request.url);
           const hasMFAHeaders = request.headers.some(h =>
             h.name.toLowerCase().includes('x-mfa') ||
             h.name.toLowerCase().includes('x-otp')
           );

           // CRITICAL: Require at least 2 context checks to prevent false positives
           const contextScore = (hasAuthContext ? 1 : 0) +
                                (hasMFAEndpoint ? 1 : 0) +
                                (hasMFAHeaders ? 1 : 0);

           if (contextScore < 2) {
             // Insufficient context - likely false positive (ZIP, order ID, etc.)
             console.debug(`[MFA] Skipping potential TOTP (context score ${contextScore}/3): ${request.url}`);
             return null;
           }

           // CRITICAL: TOTP code in GET request = leaked via Referer
           if (request.method === 'GET') {
             return {
               type: 'MFA_CODE_IN_URL',
               severity: 'HIGH',
               message: 'MFA/TOTP code exposed in URL - leaked via Referer header',
               cwe: 'CWE-598',
               cvss: 7.5,
               confidence: hasAuthContext && hasMFAEndpoint ? 'HIGH' : 'MEDIUM',
               evidence: {
                 parameterName: paramName,
                 method: 'GET',
                 url: this.redactSensitiveParams(request.url),
                 contextChecks: { hasAuthContext, hasMFAEndpoint, hasMFAHeaders }
               }
             };
           }

           return {
             mfaType: 'TOTP',
             strength: 'MEDIUM',
             phishingResistant: false,
             confidence: hasAuthContext && hasMFAEndpoint ? 'HIGH' : 'MEDIUM',
             evidence: {
               parameterName: paramName,
               contextChecks: { hasAuthContext, hasMFAEndpoint, hasMFAHeaders }
             }
           };
         }
       }
     }
   }
   ```

3. **SMS OTP Detection**
   ```javascript
   detectSMSOTP(request, response) {
     const urlPatterns = [
       /\/sms\//,
       /\/verify[-_]?phone/,
       /\/send[-_]?code/,
       /\/otp/
     ];

     const isSMSEndpoint = urlPatterns.some(pattern => pattern.test(request.url));

     if (isSMSEndpoint) {
       return {
         type: 'SMS_BASED_MFA',
         severity: 'INFO',
         message: 'SMS-based MFA detected - vulnerable to SIM swapping',
         evidence: {
           endpoint: request.url,
           recommendation: 'Consider upgrading to TOTP or WebAuthn',
           weakness: 'SMS OTP susceptible to interception and SIM swap attacks'
         },
         mfaType: 'SMS',
         strength: 'WEAK',
         phishingResistant: false
       };
     }
   }
   ```

4. **MFA Bypass Detection (Remember Device)**
   ```javascript
   detectMFABypass(cookies) {
     const bypassPatterns = [
       'remember_device',
       'mfa_remember',
       'trust_device',
       'skip_mfa',
       'mfa_trusted'
     ];

     for (const [name, cookie] of Object.entries(cookies)) {
       if (bypassPatterns.some(pattern => name.toLowerCase().includes(pattern))) {
         // Check token lifetime
         const maxAge = this.getCookieMaxAge(cookie);

         if (maxAge > 30 * 24 * 60 * 60) {  // >30 days
           return {
             type: 'MFA_REMEMBER_TOKEN_EXCESSIVE_LIFETIME',
             severity: 'MEDIUM',
             message: 'MFA bypass token has excessive lifetime (>30 days)',
             evidence: {
               cookieName: name,
               maxAge: maxAge,
               maxAgeDays: Math.floor(maxAge / (24 * 60 * 60)),
               recommendation: 'Limit remember device tokens to 30 days or less'
             }
           };
         }
       }
     }
   }
   ```

5. **Missing MFA on Sensitive Endpoints**
   ```javascript
   detectMissingMFA(flowContext) {
     // Track if MFA was required during auth flow
     const hadMFAChallenge = flowContext.events.some(e =>
       e.type === 'webauthn' || e.type === 'totp' || e.type === 'sms_otp'
     );

     // Detect sensitive endpoints (admin, settings, financial)
     const sensitivePatterns = [
       /\/admin\//,
       /\/settings\//,
       /\/account\//,
       /\/payment/,
       /\/transfer/,
       /\/withdraw/
     ];

     const accessedSensitiveEndpoint = flowContext.events.some(e =>
       sensitivePatterns.some(pattern => pattern.test(e.url))
     );

     if (accessedSensitiveEndpoint && !hadMFAChallenge) {
       return {
         type: 'MFA_NOT_ENFORCED_SENSITIVE_ENDPOINT',
         severity: 'HIGH',
         message: 'MFA not enforced on sensitive endpoint access',
         evidence: {
           sensitiveEndpoints: flowContext.events
             .filter(e => sensitivePatterns.some(p => p.test(e.url)))
             .map(e => e.url),
           mfaChallengeObserved: false,
           recommendation: 'Enforce MFA for sensitive operations'
         }
       };
     }
   }
   ```

**New Findings:**
- "MFA/TOTP code in URL - leaked via Referer" (HIGH)
- "MFA not enforced on sensitive endpoint" (HIGH)
- "SMS-based MFA vulnerable to interception" (INFO - with recommendations)
- "MFA bypass token has excessive lifetime" (MEDIUM)
- "MFA challenge can be reused" (HIGH - leverage existing WebAuthn validator)

**Files to Create:**
- `/modules/auth/mfa-detector.js` - Main MFA detection coordinator
- `/modules/auth/totp-analyzer.js` - TOTP-specific detection

**Files to Update:**
- `/modules/auth/webauthn-validator.js` - Enhance with MFA context
- `/modules/auth/auth-issue-database.js` - Add MFA issue types

**Success Metrics:**
- ✅ Detect 90%+ of MFA implementations (WebAuthn/TOTP/SMS)
- ✅ Identify MFA bypass mechanisms
- ✅ Flag MFA code leakage in URLs

---

### P2-8: Session Lifetime Analysis ⭐ NEW (RENAMED)
**Status:** **SCOPE CORRECTED** ✅ (passive analysis only)
**Priority:** MEDIUM
**Timeline:** Week 9-10 (revised)
**Standards:** OWASP WSTG 2025 (Session Management Testing)

**✅ CORRECTED:** Renamed from "Session Lifecycle Tracking" to "Session Lifetime Analysis"

**Scope Decision:** **Option B selected** - Passive cookie attribute analysis ONLY

**What's Analyzed (Passive):**
- Cookie Max-Age/Expires attributes (absolute timeout)
- Remember-me token entropy and lifetime
- Concurrent session detection (via multiple cookie tracking)

**What's NOT Analyzed (Requires Active Testing):**
- ❌ Inactivity timeout behavior (requires waiting 30+ min + test request)
- ❌ Session rotation on privilege escalation (requires triggering escalation)
- ❌ Session validity after logout (requires POST /logout + test request)

**Goal:** Analyze session cookie configuration (passive) - NOT behavior testing

**Passive Analysis Only:**

1. **Session Lifetime Analysis (Passive Only)**

   **⚠️ CORRECTED:** Remove "inactivity timeout" testing (requires active testing). Only analyze cookie attributes.

   ```javascript
   // modules/auth/session-lifecycle-tracker.js (CORRECTED - passive only)
   class SessionLifecycleTracker {
     analyzeSessionLifetime(sessionCookie) {  // ← RENAMED: analyze, not test
       const maxAge = this.extractMaxAge(sessionCookie);
       const expires = this.extractExpires(sessionCookie);

       // Check for absolute timeout
       if (!maxAge && !expires) {
         return {
           type: 'SESSION_NO_ABSOLUTE_TIMEOUT',
           severity: 'MEDIUM',
           message: 'Session cookie has no Max-Age or Expires - no absolute timeout',
           note: 'Cannot verify inactivity timeout behavior passively',
           evidence: {
             cookieName: sessionCookie.name,
             maxAge: null,
             expires: null,
             recommendation: 'Set Max-Age or Expires for session cookies'
           }
         };
       }

       // Flag sessions >24 hours (absolute timeout)
       if (maxAge > 24 * 60 * 60) {
         return {
           type: 'SESSION_EXCESSIVE_LIFETIME',
           severity: 'MEDIUM',
           message: 'Session absolute lifetime exceeds 24 hours',
           evidence: {
             maxAge: maxAge,
             maxAgeHours: Math.floor(maxAge / 3600),
             isAbsoluteTimeout: true,  // ← This is absolute, not inactivity
             recommendation: 'OWASP recommends max 12-24 hour session lifetime'
           }
         };
       }

       return null;  // No issues
     }

     // ❌ REMOVED: trackSessionRefresh() - requires active testing
     // ❌ Cannot verify inactivity timeout behavior passively
     // ❌ Move to P3-6 (Active Testing) if needed
   }
   ```

2. **Concurrent Session Detection**
   ```javascript
   detectConcurrentSessions(domain) {
     const sessions = this.activeSessions.get(domain) || [];

     if (sessions.length > 1) {
       return {
         type: 'CONCURRENT_SESSIONS_ALLOWED',
         severity: 'LOW',
         message: 'Multiple concurrent sessions detected for same domain',
         evidence: {
           sessionCount: sessions.length,
           sessionIds: sessions.map(s => this.truncateSessionId(s.id)),
           recommendation: 'Consider limiting concurrent sessions for sensitive applications',
           note: 'May be acceptable for some applications'
         }
       };
     }
   }
   ```

3. **Remember Me Token Analysis**
   ```javascript
   analyzeRememberMeToken(cookie) {
     const rememberPatterns = ['remember', 'persistent', 'autologin', 'stay_logged_in'];

     if (rememberPatterns.some(p => cookie.name.toLowerCase().includes(p))) {
       const entropy = this.calculateEntropy(cookie.value);

       if (entropy < 128) {
         return {
           type: 'REMEMBER_ME_TOKEN_WEAK_ENTROPY',
           severity: 'MEDIUM',
           message: 'Remember me token has insufficient entropy',
           evidence: {
             cookieName: cookie.name,
             entropy: entropy,
             entropyBits: Math.floor(entropy),
             recommendation: 'Use at least 128 bits of entropy for remember me tokens'
           }
         };
       }

       const maxAge = this.extractMaxAge(cookie);
       if (maxAge > 90 * 24 * 60 * 60) {  // >90 days
         return {
           type: 'REMEMBER_ME_TOKEN_EXCESSIVE_LIFETIME',
           severity: 'LOW',
           message: 'Remember me token has excessive lifetime (>90 days)',
           evidence: {
             maxAgeDays: Math.floor(maxAge / (24 * 60 * 60)),
             recommendation: 'Limit remember me tokens to 90 days maximum'
           }
         };
       }
     }
   }
   ```

**Files to Create:**
- `/modules/auth/session-lifecycle-tracker.js` - Session lifecycle monitoring

**Files to Update:**
- `/modules/auth/session-security-analyzer.js` - Integrate lifecycle tracking

**Success Metrics:**
- ✅ Detect sessions without timeout
- ✅ Flag excessive session lifetimes
- ✅ Identify concurrent session issues

---

### P2-9: Password Policy Detection ⭐ NEW
**Status:** PLANNED
**Priority:** LOW
**Timeline:** Week 6-7
**Standards:** NIST SP 800-63B (Password Guidelines)

**Goal:** Passively detect and assess password policies

**Detection Strategy:**

```javascript
// modules/auth/password-policy-analyzer.js
class PasswordPolicyAnalyzer {
  detectPasswordEndpoints(request) {
    const passwordEndpoints = [
      /\/reset[-_]?password/,
      /\/change[-_]?password/,
      /\/signup/,
      /\/register/,
      /\/set[-_]?password/
    ];

    return passwordEndpoints.some(pattern => pattern.test(request.url));
  }

  extractPolicyFromError(errorResponse) {
    // Common error messages reveal policy
    const patterns = {
      minLength: /at least (\d+) characters?/i,
      maxLength: /no more than (\d+) characters?/i,
      requiresUppercase: /uppercase letter/i,
      requiresLowercase: /lowercase letter/i,
      requiresDigit: /number|digit/i,
      requiresSpecial: /special character/i
    };

    const policy = {};

    for (const [key, pattern] of Object.entries(patterns)) {
      const match = errorResponse.match(pattern);
      if (match) {
        policy[key] = match[1] ? parseInt(match[1]) : true;
      }
    }

    return policy;
  }

  assessPolicy(policy) {
    // NIST SP 800-63B guidelines (2025)
    const nistMinimum = 8;  // With MFA
    const nistRecommended = 15;  // Without MFA

    const findings = [];

    if (policy.minLength && policy.minLength < nistMinimum) {
      findings.push({
        type: 'WEAK_PASSWORD_POLICY',
        severity: 'MEDIUM',
        message: `Password minimum length (${policy.minLength}) below NIST recommendation`,
        evidence: {
          detectedMinLength: policy.minLength,
          nistRecommendation: nistMinimum,
          source: 'NIST SP 800-63B'
        }
      });
    }

    if (!policy.minLength) {
      findings.push({
        type: 'NO_PASSWORD_MINIMUM_LENGTH',
        severity: 'MEDIUM',
        message: 'No password minimum length detected',
        evidence: {
          recommendation: 'Enforce minimum 8 characters (with MFA) or 15 (without MFA)'
        }
      });
    }

    return findings;
  }
}
```

**Files to Create:**
- `/modules/auth/password-policy-analyzer.js` - Password policy detection

**Success Metrics:**
- ✅ Detect password policy from error messages
- ✅ Compare against NIST SP 800-63B
- ✅ Flag weak policies (MEDIUM severity)

---

### P2-1: Evidence Timeline Visualization
**Status:** PLANNED

**Goal:** Show chronological flow of authentication requests

**Mockup:**
```
[Timeline] console.hetzner.com OAuth2 session
  12:34:01 ━━ 🔵 Session started (OAuth2 login detected)
           │
  12:34:15 ━━ ✅ PKCE flow complete
           │   ├─ code_challenge sent (S256)
           │   └─ code_verifier verified
           │
  12:34:42 ━━ 📡 API calls monitored (142 requests)
           │
  12:35:08 ━━ ⚠️  Missing CSRF token
           │   └─ POST /api/dns/records
           │
  12:35:22 ━━ 💾 Evidence package ready
               └─ 0.17 MB, 161 requests
```

**Implementation:**
- Interactive HTML timeline
- Expandable events (click to see details)
- Color-coded by severity
- Exportable as SVG/PNG

---

### P2-2: Smart Evidence Summarization
**Status:** PLANNED

**Goal:** Reduce log noise with intelligent batching

**Example:**
```
// Instead of:
[Evidence] Captured 1 request
[Evidence] Captured 1 request
[Evidence] Captured 1 request
... (142 more)

// Show:
[Evidence] Captured 142 requests in 45 seconds
  - OAuth2 authorization flow (3 requests)
  - API calls (135 requests)
  - Static assets (4 requests)

  Notable: 2 security findings detected
  Storage: 0.17 MB (auto-saving every 60s)
```

---

### P2-3: Contextual User Notifications
**Status:** PLANNED

**Goal:** Browser notifications for important findings

**Implementation:**
```javascript
// When high-severity finding detected
if (finding.severity === 'HIGH' || finding.severity === 'CRITICAL') {
  const notification = chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon-alert.png',
    title: `Hera: ${finding.severity} Finding`,
    message: `${finding.title} on ${domain}`,
    contextMessage: `Confidence: ${finding.confidence}% - Click to view details`,
    buttons: [
      { title: 'View Evidence' },
      { title: 'Export Report' }
    ],
    requireInteraction: true
  });

  chrome.notifications.onButtonClicked.addListener((notifId, btnIdx) => {
    if (notifId === notification) {
      if (btnIdx === 0) {
        // Open popup with evidence
        chrome.action.openPopup();
      } else if (btnIdx === 1) {
        // Trigger export
        exportEvidence(finding);
      }
    }
  });
}
```

---

### P2-4: Evidence Export Preview
**Status:** PLANNED

**Goal:** Show users what they're exporting before download

**Mockup:**
```
┌─────────────────────────────────────────────────┐
│ Evidence Package: console.hetzner.com          │
├─────────────────────────────────────────────────┤
│                                                 │
│ Session Duration: 45 seconds                    │
│ Requests Captured: 161                          │
│ Findings: 2 (1 MEDIUM, 1 LOW)                   │
│                                                 │
│ Export Formats Available:                       │
│   📄 PDF Report (for bug bounties)             │
│   📊 JSON Evidence (for tools)                  │
│   📋 Markdown Summary (for docs)                │
│   🔗 HAR File (for Burp Suite)                  │
│                                                 │
│ Estimated Size: 2.3 MB                          │
│ Includes: Screenshots, request/response data    │
│                                                 │
│ [Export PDF] [Export JSON] [Export HAR] [❌]    │
└─────────────────────────────────────────────────┘
```

---

### P2-5: Real-Time Evidence Quality Indicators
**Status:** PLANNED

**Goal:** Live progress bars showing evidence completeness

**Mockup:**
```
[Evidence Quality] console.hetzner.com

  Request Coverage:  ████████░░ 80%
    ✅ Authorization flow captured
    ✅ Token exchange captured
    ⚠️  Token refresh not yet observed

  Evidence Completeness:  ██████████ 100%
    ✅ Request headers
    ✅ Response headers
    ✅ Request body
    ✅ Response body
    ✅ Timing data

  Finding Confidence:  ████████░░ 85%
    Suggestion: Capture 1 more CSRF-vulnerable request
                to increase confidence to 95%
```

---

### P2-6: Progressive Evidence Degradation
**Status:** PLANNED

**Goal:** Gracefully handle storage limits

**Implementation:**
```javascript
class EvidenceCollector {
  async handleStoragePressure() {
    const usage = await this.getStorageUsage();

    if (usage > 0.90) {
      console.warn('[Evidence] Storage at 90% - degrading evidence quality');

      // Strategy 1: Export high-confidence findings
      const highConfidence = this.findings.filter(f => f.confidence >= 90);
      if (highConfidence.length > 0) {
        await this.autoExport(highConfidence);
        console.log(`[Evidence] Auto-exported ${highConfidence.length} findings`);
      }

      // Strategy 2: Compress old requests
      const compressed = await this.compressOldEvidence();
      console.log(`[Evidence] Compressed ${compressed.sizeSaved} MB`);

      // Strategy 3: Archive to IndexedDB
      await this.archiveToIndexedDB();

      // Strategy 4: Warn user
      chrome.notifications.create({
        type: 'basic',
        title: 'Hera: Storage Almost Full',
        message: 'Export evidence now to prevent data loss?',
        buttons: [
          { title: 'Export Now' },
          { title: 'Increase Limit' }
        ]
      });
    }
  }
}
```

---

## P1 Optimizations - Performance & Code Quality (This Week)

### P1-OPT-1: Optimize Evidence Truncation (Shallow Clone)
**Priority:** MEDIUM
**Effort:** 30 minutes
**Impact:** Reduces memory allocation by ~50% for large requests

**Problem:** Current `_truncateEvidence()` uses `JSON.parse(JSON.stringify(evidence))` for deep cloning, which:
- Allocates memory for the entire stringified JSON
- Parses it back into objects
- Wasteful for objects that only need shallow truncation

**Solution:** Replace with efficient shallow clone:
```javascript
_truncateEvidence(evidence) {
  // Shallow clone instead of deep clone
  const truncated = { ...evidence };

  // Only deep clone the specific fields that need truncation
  if (evidence.request?.body?.length > this.MAX_BODY_SIZE) {
    truncated.request = { ...evidence.request };
    truncated.request.body = evidence.request.body.substring(0, this.MAX_BODY_SIZE) + '...';
  }

  if (evidence.response?.body?.length > this.MAX_BODY_SIZE) {
    truncated.response = { ...evidence.response };
    truncated.response.body = evidence.response.body.substring(0, this.MAX_BODY_SIZE) + '...';
  }

  return truncated;
}
```

**Files:** [evidence-collector.js:505-548](evidence-collector.js#L505-548)

---

### P1-OPT-2: Add Client Type Inference Confidence Levels
**Priority:** MEDIUM
**Effort:** 30 minutes
**Impact:** Reduces false positives in PKCE detection

**Problem:** Current `_inferClientType()` returns only the type string ('public', 'confidential', 'unknown'), but doesn't indicate confidence level. This can cause:
- False positives when guessing client type from weak signals
- Over-confident severity ratings based on uncertain inference

**Solution:** Return confidence tuple:
```javascript
_inferClientType(request) {
  const url = request.url;
  const body = request.requestBody || '';

  // HIGH confidence: Direct evidence
  if (body.includes('client_secret=')) {
    return { type: 'confidential', confidence: 'HIGH' };
  }

  // MEDIUM confidence: Indirect evidence
  const redirectUri = this._extractRedirectUri(url);
  if (redirectUri) {
    const isLocalhost = /^https?:\\/\\/(localhost|127\\.0\\.0\\.1|::1)/.test(redirectUri);
    if (isLocalhost) {
      return { type: 'public', confidence: 'MEDIUM' };
    }
  }

  // LOW confidence: Fallback
  if (url.includes('code_challenge=')) {
    return { type: 'public', confidence: 'LOW' };
  }

  return { type: 'unknown', confidence: 'LOW' };
}
```

**Usage:**
```javascript
const clientInfo = this._inferClientType(request);
if (clientInfo.type === 'public' && clientInfo.confidence === 'HIGH') {
  // HIGH severity PKCE missing
} else if (clientInfo.type === 'public' && clientInfo.confidence === 'MEDIUM') {
  // MEDIUM severity (not certain)
}
```

**Files:** [modules/auth/oauth2-analyzer.js](modules/auth/oauth2-analyzer.js), [modules/auth/dpop-validator.js:224-251](modules/auth/dpop-validator.js#L224-251)

---

## P2 Integration & Testing (Week 2-3)

### P2-INT-1: Integrate DPoP Validator
**Priority:** HIGH
**Effort:** 2-3 days
**Impact:** Implements RFC 9449 DPoP detection per P1-5

**Status:** Module created ✅ ([modules/auth/dpop-validator.js](modules/auth/dpop-validator.js)), but NOT integrated yet

**Integration Points:**

1. **Import in response-body-capturer.js:**
   ```javascript
   import { DPoPValidator } from './auth/dpop-validator.js';

   constructor() {
     this.dpopValidator = new DPoPValidator();
   }
   ```

2. **Check token responses for DPoP:**
   ```javascript
   async _captureResponseBody(tabId, webRequestId, url) {
     // ... existing code ...

     if (this._isTokenResponse(url)) {
       const parsedBody = JSON.parse(responseBody);

       // Check for DPoP implementation
       const dpopFinding = this.dpopValidator.checkDPoPImplementation(
         requestData.request,
         parsedBody
       );

       if (dpopFinding) {
         requestData.metadata.findings = requestData.metadata.findings || [];
         requestData.metadata.findings.push(dpopFinding);
       }
     }
   }
   ```

3. **Validate DPoP JWT headers in requests:**
   ```javascript
   // In webrequest-listeners.js onBeforeSendHeaders
   const dpopHeader = details.requestHeaders?.find(h => h.name.toLowerCase() === 'dpop');
   if (dpopHeader) {
     const dpopFinding = dpopValidator.validateDPoPJWT(dpopHeader.value, {
       method: details.method,
       url: details.url
     });

     if (dpopFinding) {
       // Add to findings
     }
   }
   ```

**Files to Modify:**
- [modules/response-body-capturer.js](modules/response-body-capturer.js)
- [modules/webrequest-listeners.js](modules/webrequest-listeners.js)
- [evidence-collector.js](evidence-collector.js) (add DPoP to evidence package)

**Testing:**
- Test with Microsoft OAuth2 (no DPoP) → INFO finding
- Test with DPoP-enabled server → no finding
- Test with malformed DPoP JWT → MEDIUM finding

---

### P2-INT-2: Update PKCE Detection (Context-Dependent Severity)
**Priority:** HIGH
**Effort:** 2-3 days
**Impact:** Corrects PKCE severity per RFC 9700 adversarial analysis

**Problem:** Current implementation flags missing PKCE as HIGH severity for all clients, but RFC 9700 says PKCE "SHOULD" be used (recommended, not required). Confidential clients have client_secret as compensating control.

**Solution:** Context-dependent severity:

```javascript
// In oauth2-analyzer.js or pkce-analyzer.js
detectMissingPKCE(request, clientInfo) {
  const hasPKCE = request.url.includes('code_challenge=') ||
                  request.requestBody?.includes('code_verifier=');

  if (hasPKCE) {
    return null; // No finding
  }

  const { type: clientType, confidence } = this._inferClientType(request);

  // Public client missing PKCE = HIGH (no other protection)
  if (clientType === 'public') {
    return {
      type: 'MISSING_PKCE',
      severity: 'HIGH',
      confidence: confidence, // Inherit confidence from client type inference
      message: 'Public client missing PKCE - authorization code vulnerable to interception',
      cwe: 'CWE-322',
      rfcReference: 'RFC 9700 Section 1 (PKCE required for public clients)'
    };
  }

  // Confidential client missing PKCE = MEDIUM (has client_secret)
  if (clientType === 'confidential') {
    return {
      type: 'MISSING_PKCE',
      severity: 'MEDIUM',
      confidence: confidence,
      message: 'Confidential client missing PKCE - consider implementing for defense-in-depth',
      note: 'Client secret provides protection, but PKCE is recommended per RFC 9700',
      cwe: 'CWE-322',
      rfcReference: 'RFC 9700 Section 1 (PKCE SHOULD be used)'
    };
  }

  // Unknown client type = MEDIUM (default to safe side)
  return {
    type: 'MISSING_PKCE',
    severity: 'MEDIUM',
    confidence: 'LOW',
    message: 'PKCE not detected - unable to determine client type',
    note: 'Cannot determine if public or confidential client',
    cwe: 'CWE-322'
  };
}
```

**Files to Modify:**
- [modules/auth/oauth2-analyzer.js](modules/auth/oauth2-analyzer.js) (or wherever PKCE detection lives)

**Testing:**
- Public client (localhost redirect) missing PKCE → HIGH
- Confidential client (has client_secret) missing PKCE → MEDIUM
- Unknown client missing PKCE → MEDIUM

---

### P2-TEST-1: Unit Tests for Truncation Logic
**Priority:** MEDIUM
**Effort:** 1 day
**Impact:** Prevents regression of evidence storage fixes

**Test Cases:**

1. **Pre-truncation of large response bodies:**
   ```javascript
   test('should truncate response body BEFORE analysis', () => {
     const largeBody = 'A'.repeat(200000); // 200KB
     const evidence = evidenceCollector.processResponseBody(requestId, largeBody, url);

     // Body should be truncated to MAX_BODY_SIZE (100KB)
     expect(evidence.response.body.length).toBeLessThanOrEqual(100000);
     expect(evidence.response.body).toContain('[TRUNCATED - original size: 200000 bytes]');
   });
   ```

2. **Per-request size limit enforcement:**
   ```javascript
   test('should enforce MAX_REQUEST_SIZE limit', () => {
     const largeRequest = {
       url: 'https://example.com/api',
       headers: Array(1000).fill({ name: 'X-Header', value: 'value' }), // Large headers
       body: 'A'.repeat(500000) // 500KB body
     };

     const evidence = evidenceCollector.addEvidence(largeRequest);
     const evidenceSize = JSON.stringify(evidence).length;

     expect(evidenceSize).toBeLessThanOrEqual(512000); // MAX_REQUEST_SIZE = 500KB
   });
   ```

3. **Session-only debug mode:**
   ```javascript
   test('debug mode should NOT persist to chrome.storage', async () => {
     await debugModeManager.enable('example.com');

     const stored = await chrome.storage.local.get(['debugModeEnabled']);
     expect(stored.debugModeEnabled).toBeUndefined(); // Should NOT be in storage

     const isEnabled = await debugModeManager.isEnabled('example.com');
     expect(isEnabled).toBe(true); // Should be in in-memory Set
   });
   ```

**Framework:** Jest or Mocha + Chrome extension test harness

**Files to Create:**
- `tests/evidence-collector.test.js`
- `tests/debug-mode-manager.test.js`

---

## P3 Issues - Advanced Features & Optional Enhancements (Months 2-3)

### P3-6: Active Testing Framework (Opt-In) ⭐ NEW
**Status:** **SCOPE CORRECTED** ✅ (unsafe tests removed)
**Priority:** LOW (opt-in feature)
**Timeline:** Month 3+
**⚠️ REQUIRES EXPLICIT USER CONSENT**

**✅ CORRECTED:** Unsafe tests (CSRF token reuse, refresh token rotation) have been REMOVED from scope.

**FINAL SCOPE:** Only truly safe read-only tests that cannot modify application state.

**Goal:** Optional active security testing with explicit user approval

**Philosophy:** Hera is passive-by-default. Active testing ONLY with clear user consent.

**Safe Tests (Read-Only GET Requests ONLY):**

1. **Session Timeout Testing**
   ```javascript
   // modules/auth/active-tester.js
   class ActiveTester {
     async testSessionTimeout(sessionCookie, userConsent) {
       if (!userConsent.sessionTimeoutTest) {
         return { skipped: true, reason: 'No user consent' };
       }

       // Wait 30 minutes, then test if session still valid
       await this.delay(30 * 60 * 1000);

       const stillValid = await this.checkSessionValidity(sessionCookie);

       return {
         type: 'SESSION_TIMEOUT_TEST',
         result: stillValid ? 'VULNERABLE' : 'SECURE',
         evidence: {
           inactivityPeriod: 30,  // minutes
           sessionStillValid: stillValid
         }
       };
     }
   }
   ```

**❌ REMOVED - NOT SAFE:**

2. ~~**CSRF Token Reuse Testing**~~ - **UNSAFE:** Making POST requests could create resources/modify state (e.g., POST /create-payment creates duplicate payment)

3. ~~**Refresh Token Rotation Testing**~~ - **UNSAFE:** Using old refresh token could trigger security alerts, invalidate all tokens, lock user out

**NEVER Test:**
- ❌ Password brute forcing
- ❌ Authentication bypass attempts
- ❌ Credential stuffing
- ❌ Account enumeration
- ❌ Any destructive actions
- ❌ Automated exploitation
- ❌ CSRF token reuse (could modify state) - **REMOVED FROM ROADMAP**
- ❌ Refresh token rotation (could invalidate tokens) - **REMOVED FROM ROADMAP**
- ❌ Any POST/PUT/DELETE/PATCH requests (state-modifying)

**SAFE Tests Only:**
- ✅ Session timeout (GET requests to read-only endpoints only)
- ✅ Read-only endpoints with expired/invalid tokens
- ✅ No state modification

**User Consent Flow (CORRECTED):**
```javascript
// UI consent dialog - ONLY safe tests
const consent = await showConsentDialog({
  title: 'Hera Active Testing (EXPERIMENTAL)',
  warning: 'Active testing will send additional GET requests to the target application.',
  tests: [
    {
      id: 'sessionTimeoutTest',
      name: 'Session Timeout Testing',
      description: 'Wait 30 minutes, then send GET request to test if session is still valid',
      risk: 'LOW - Read-only GET request to /userinfo or similar endpoint'
    }
    // REMOVED: csrfReuseTest (UNSAFE - could modify state)
    // REMOVED: refreshRotationTest (UNSAFE - could invalidate tokens)
  ],
  disclaimer: 'Only perform active testing on applications you have written authorization to test. Active testing is EXPERIMENTAL and opt-in only.'
});

if (consent.granted && consent.tests.length > 0) {
  // Run only safe, consented tests
  await activeTester.runSafeTests(consent);
}
```

**Files to Create:**
- `/modules/auth/active-tester.js` - Active testing coordinator
- `/modules/ui/consent-manager.js` - User consent management

**Success Metrics:**
- ✅ Zero active tests run without explicit consent
- ✅ Clear warnings about authorization requirements
- ✅ Safe tests only (no destructive actions)

---

### P3-1: Evidence Collaboration Features
**Status:** IDEA

**Goal:** Share evidence with team members

**Features:**
- Generate shareable link (read-only)
- Email evidence package
- Export to shared drive
- Encrypt for client delivery

---

### P3-2: Evidence-Based Learning
**Status:** IDEA

**Goal:** Track what evidence actually helps users

**Implementation:**
```javascript
class EvidenceAnalytics {
  trackExportUsage(finding, exportFormat) {
    // Track which evidence fields are actually used
    const analytics = {
      findingType: finding.type,
      exportFormat: exportFormat,
      evidenceFields: Object.keys(finding.evidence),
      timestamp: Date.now()
    };

    this.usageLog.push(analytics);
  }

  async generateInsights() {
    // After 30 days, show insights
    const insights = {
      mostUsedEvidence: this.getMostUsed(),
      leastUsedEvidence: this.getLeastUsed(),
      recommendations: this.getRecommendations()
    };

    console.log('[Insights] Evidence usage patterns');
    console.log(`  Most useful: ${insights.mostUsedEvidence.join(', ')}`);
    console.log(`  Least useful: ${insights.leastUsedEvidence.join(', ')}`);
    console.log('');
    console.log('  Recommendation:', insights.recommendations[0]);
  }
}
```

---

### P3-3: Machine Learning for False Positive Reduction
**Status:** IDEA

**Goal:** Learn from user feedback on findings

**Approach:**
- Track which findings users export vs dismiss
- Build classifier to predict false positives
- Adjust confidence scores based on historical accuracy

---

### P3-4: Integration with Bug Bounty Platforms
**Status:** IDEA

**Goal:** One-click submit to HackerOne, Bugcrowd, etc.

**Features:**
- Pre-filled vulnerability templates
- Automatic severity mapping (Hera → CVSS)
- Evidence attachment upload
- Draft submission creation

---

### P3-5: Compliance Reporting
**Status:** IDEA

**Goal:** Generate compliance reports (OWASP, PCI-DSS, SOC2)

**Example:**
```
OWASP Top 10 Compliance Report
Generated by Hera v0.1.0
Target: console.hetzner.com

A02:2021 - Cryptographic Failures
  ✅ PASS - HTTPS enforced with HSTS
  ⚠️  WARN - HSTS max-age could be longer (recommended: 31536000)

A05:2021 - Security Misconfiguration
  ❌ FAIL - Missing Content-Security-Policy header
  ⚠️  WARN - Server version exposed in headers

A07:2021 - Identification and Authentication Failures
  ✅ PASS - OAuth2 with PKCE implemented correctly
  ✅ PASS - No credentials in URLs

Overall Score: 8/10 controls passed
Risk Level: LOW
```

---

## Implementation Priority

### Phase 1: Standards Compliance (Weeks 1-6) - CRITICAL ⚠️ REVISED

**⚠️ TIMELINE REVISED:** +50% buffer added based on P0 implementation experience

| Item | Priority | Effort (Original) | Effort (Revised) | Impact | Timeline | Standards |
|------|----------|------------------|------------------|--------|----------|-----------|
| **P1-5: RFC 9700 Compliance** ⭐ | CRITICAL | 2 weeks | **4-6 weeks** | VERY HIGH | Week 1-6 | RFC 9700, RFC 9449 |
| **P1-6: CVSS 4.0 Integration** ⭐ | HIGH | 1 week | **1 week (with library)** | HIGH | Week 4 | CVSS 4.0 |
| **P1-7: Bugcrowd VRT Mapping** ⭐ | MEDIUM | 3 days | **1 week** | HIGH | Week 5 | Bugcrowd VRT |
| P1-4: Export Formats (PDF/MD) | HIGH | 1 week | **1.5 weeks** | HIGH | Week 6 | N/A |
| P1-1: Export Notifications | HIGH | 2 days | **3 days** | MEDIUM | Week 1 | N/A |
| P1-2: Quality Indicators | HIGH | 3 days | **1 week** | MEDIUM | Week 2 | N/A |
| P1-3: Batch Logs | LOW | 1 day | **2 days** | LOW | Week 1 | N/A |

**Rationale for Revisions:**
- P0 prerequisites took 2 weeks with 3 critical bugs discovered post-implementation
- Integration complexity consistently underestimated
- Testing and bug fixing requires additional time
- False positive tuning (especially for MFA detection) is iterative

**Phase 1 Deliverables:**
- ✅ Full RFC 9700 compliance (DPoP, refresh rotation, PKCE for all)
- ✅ CVSS 4.0 scores for all findings
- ✅ Bugcrowd VRT P1-P5 mappings
- ✅ Enhanced export formats (PDF, Markdown, Bug Bounty templates)

---

### Phase 2: Enhanced Detection (Weeks 6-12) - HIGH PRIORITY ⚠️ REVISED

**⚠️ TIMELINE REVISED:** +50% buffer, starts after Phase 1 completion

| Item | Priority | Effort (Original) | Effort (Revised) | Impact | Timeline | Standards |
|------|----------|------------------|------------------|--------|----------|-----------|
| **P2-7: Passive MFA Detection** ⭐ | HIGH | 2 weeks | **3-4 weeks** | VERY HIGH | Week 6-9 | OWASP WSTG, NIST 800-63B |
| **P2-8: Session Lifecycle** ⭐ | MEDIUM | 2 weeks | **2 weeks (passive only)** | MEDIUM | Week 9-10 | OWASP WSTG |
| **P2-9: Password Policy** ⭐ | LOW | 1 week | **1.5 weeks** | LOW | Week 10-11 | NIST SP 800-63B |
| P2-1: Timeline Visualization | LOW | 1 week | **1.5 weeks** | MEDIUM | Week 11 | N/A |
| P2-3: Notifications | MEDIUM | 3 days | **1 week** | MEDIUM | Week 6 | N/A |
| P2-4: Export Preview | LOW | 3 days | **1 week** | LOW | Week 11 | N/A |
| P2-5: Quality UI | LOW | 1 week | **1.5 weeks** | LOW | Week 12 | N/A |
| P2-6: Storage Degradation | LOW | 1 week | **1.5 weeks** | MEDIUM | Week 12 | N/A |

**Key Revision Notes:**
- **P2-7 (MFA Detection):** Extended to 3-4 weeks to include extensive false positive testing
- **P2-8 (Session):** Clarified as passive analysis only (no behavior testing)

**Phase 2 Deliverables:**
- ✅ MFA detection (WebAuthn/TOTP/SMS + bypass mechanisms)
- ✅ Session timeout/rotation tracking
- ✅ Password policy analysis
- ✅ Improved UX (notifications, previews, quality indicators)

---

### Phase 3: Advanced Features (Months 2-3) - OPTIONAL

| Item | Priority | Effort | Impact | Timeline | Notes |
|------|----------|--------|--------|----------|-------|
| **P3-6: Active Testing** ⭐ | LOW | 3 weeks | MEDIUM | Month 3 | **Opt-in only, requires consent** |
| P3-4: Bug Bounty Integration | MEDIUM | 2 weeks | HIGH | Q1 2026 | HackerOne/Bugcrowd API |
| P3-1: Collaboration | LOW | 2 weeks | LOW | Q1 2026 | Team features |
| P3-2: Learning Analytics | LOW | 2 weeks | MEDIUM | Q1 2026 | Usage tracking |
| P3-3: ML False Positives | LOW | 1 month | HIGH | Q2 2026 | Requires data |
| P3-5: Compliance Reports | LOW | 1 month | MEDIUM | Q3 2026 | OWASP/PCI-DSS |

**Phase 3 Notes:**
- Active testing is OPT-IN only (requires explicit user consent)
- Bug bounty integration depends on platform APIs
- ML features require sufficient usage data

---

### Quick Reference: New vs. Existing Items

**⭐ NEW (2025 Standards):**
- P1-5: RFC 9700 (OAuth 2.1) Compliance
- P1-6: CVSS 4.0 Integration
- P1-7: Bugcrowd VRT Mapping
- P2-7: Passive MFA Detection
- P2-8: Session Lifecycle Tracking
- P2-9: Password Policy Detection
- P3-6: Active Testing Framework (opt-in)

**Existing (From Original Roadmap):**
- P1-0 to P1-4: Message queue, notifications, quality, exports
- P2-1 to P2-6: Timeline viz, summaries, UI improvements
- P3-1 to P3-5: Collaboration, learning, ML, BB integration, compliance

---

## Success Metrics

### Standards Compliance Metrics ⭐ NEW

#### RFC 9700 (OAuth 2.1) Coverage
- **Goal:** 100% of RFC 9700 required checks implemented
- **Measure:** Automated test coverage
- **Checkpoints:**
  - ✅ DPoP detection for public clients
  - ✅ Refresh token rotation tracking
  - ✅ PKCE required for ALL client types (not just public)
  - ✅ Resource indicator recommendations

#### CVSS 4.0 Accuracy
- **Goal:** All findings have valid CVSS 4.0 scores
- **Measure:** Automated validation of CVSS vectors
- **Checkpoints:**
  - ✅ 100% of findings have CVSS 4.0 scores
  - ✅ CVSS vector strings validate per FIRST.org spec
  - ✅ Severity alignment: Hera ≈ CVSS (±1 level acceptable)

#### Bugcrowd VRT Alignment
- **Goal:** 90%+ of findings mapped to VRT categories
- **Measure:** VRT coverage percentage
- **Checkpoints:**
  - ✅ P1/P2 findings have documented justifications
  - ✅ VRT priority aligns with bug bounty acceptance rates
  - ✅ All critical findings mapped to VRT baseline

#### OWASP WSTG 2025 Coverage
- **Goal:** 80% coverage of Authentication Testing chapter
- **Measure:** Manual checklist validation
- **Categories:**
  - ✅ Credentials Transmitted Over Encrypted Channel
  - ✅ Default Credentials
  - ✅ Weak Lock Out Mechanism
  - ✅ Bypassing Authentication Schema
  - ✅ Remember Password Functionality
  - ✅ Browser Cache Weaknesses
  - ✅ Weak Password Policy
  - ✅ Weak Security Question/Answer
  - ✅ Weak Password Change/Reset
  - ✅ Weaker Authentication in Alternative Channel

---

### Detection Metrics ⭐ NEW

#### MFA Detection Rate
- **Goal:** Detect 90%+ of MFA implementations
- **Measure:** Manual verification on known MFA sites with documented test methodology

**✅ TEST METHODOLOGY (REQUIRED):**

**Test Site Selection (20 sites total):**

1. **WebAuthn/FIDO2 (5 sites):**
   - GitHub (https://github.com/settings/security)
   - Google (https://myaccount.google.com/security)
   - Microsoft (https://account.microsoft.com/security)
   - Duo (https://duo.com)
   - Yubico Demo (https://demo.yubico.com/webauthn-technical)

2. **TOTP/Authenticator Apps (10 sites):**
   - Auth0 Demo (https://auth0.com/learn/2fa-demo)
   - Okta (https://login.okta.com)
   - AWS Console (https://console.aws.amazon.com)
   - Twilio (https://www.twilio.com/login)
   - Stripe (https://dashboard.stripe.com)
   - Dropbox (https://www.dropbox.com/login)
   - Slack (https://slack.com/signin)
   - GitLab (https://gitlab.com/users/sign_in)
   - Bitwarden (https://vault.bitwarden.com)
   - 1Password (https://my.1password.com)

3. **SMS OTP (5 sites):**
   - Twitter/X (https://twitter.com/login)
   - Instagram (https://www.instagram.com/accounts/login/)
   - WhatsApp Web (https://web.whatsapp.com)
   - PayPal (https://www.paypal.com/signin)
   - Coinbase (https://www.coinbase.com/signin)

**Testing Procedure:**
1. Create test accounts on all 20 sites
2. Enable MFA on each account
3. Perform complete authentication flow with Hera monitoring
4. Record detection results (detected/not detected/false positive)
5. Calculate detection rate: (correctly detected / 20) × 100%

**False Positive Test (50 non-MFA codes):**
- 10 ZIP codes in address forms
- 10 order IDs in e-commerce checkouts
- 10 confirmation codes (non-auth)
- 10 phone number inputs (last 6-8 digits)
- 10 verification codes (email/phone, but not for MFA)

**Acceptance Criteria:**
- **Detection rate:** ≥90% (18/20 sites)
- **False positive rate:** ≤5% (≤2.5/50 tests)
- **Context score threshold:** Require ≥2/3 context checks

**Baseline:**
- Current: 0% (MFA detection not implemented)
- Target after P2-7: 90%+

**Breakdown:**
  - WebAuthn/FIDO2 detection: 95%+ (19/20)
  - TOTP/Authenticator app detection: 90%+ (18/20)
  - SMS OTP detection: 85%+ (17/20)
  - MFA bypass mechanism detection: 80%+ (16/20)

#### Session Management Coverage
- **Goal:** Detect 95% of session security issues
- **Measure:** Test against OWASP WSTG session checklist
- **Issues:**
  - Session fixation
  - Weak session IDs
  - Missing timeout
  - Concurrent sessions
  - Remember me token issues

#### Password Policy Detection
- **Goal:** Extract password policy from 70% of password endpoints
- **Measure:** Success rate on test suite
- **Extracted:**
  - Minimum length
  - Complexity requirements
  - Maximum length (if disclosed)

---

### User Experience Metrics

#### User Satisfaction
- **Goal:** 90% of users find evidence "useful" or "very useful"
- **Measure:** Post-export survey

#### Export Rate
- **Goal:** 50% of sessions with findings result in exports
- **Baseline:** Currently unknown (not tracked)
- **Target:** Increase by 20% after enhanced export formats

#### False Positive Rate
- **Goal:** <5% of exported findings are false positives
- **Baseline:** Currently <10%
- **Improvement:** 50% reduction via confidence scoring

#### Evidence Completeness
- **Goal:** 95% of exported evidence packages have all required fields
- **Measure:** Automated validation on export
- **Required Fields:**
  - Request/response data
  - CVSS 4.0 score
  - Bugcrowd VRT mapping
  - CWE/CVE references
  - Reproduction steps

#### Time to Export
- **Goal:** <2 minutes from detection to bug bounty submission
- **Baseline:** Currently unknown
- **Includes:** Finding detection → Evidence collection → PDF generation → Export

---

### Bug Bounty Success Metrics ⭐ NEW

#### Report Acceptance Rate
- **Goal:** Track % of Hera-generated reports accepted by bug bounty programs
- **Measure:** Optional user feedback form
- **Target:** 70%+ acceptance rate

#### Time to First Finding
- **Goal:** Average time to detect first security issue
- **Target:** <5 minutes after OAuth flow completion

#### Critical Finding Detection
- **Goal:** Detect at least 1 CRITICAL/HIGH finding per vulnerable application
- **Measure:** Success rate on intentionally vulnerable test apps

---

## Questions for Future Consideration

1. **Should Hera support collaborative pentesting?**
   - Multiple analysts sharing evidence in real-time
   - Team dashboards with aggregated findings

2. **Should Hera integrate with CI/CD pipelines?**
   - Automated security testing during development
   - Pre-deployment vulnerability scanning

3. **Should Hera support custom plugins?**
   - User-defined vulnerability detectors
   - Custom export formats
   - Third-party integrations

4. **Should Hera offer a hosted service?**
   - Cloud evidence storage
   - Team collaboration features
   - Historical trending

---

## Feedback

Have ideas for the roadmap? File an issue at:
https://github.com/anthropics/hera/issues

---

## Summary: Roadmap at a Glance

### What's New in Version 0.2.0 ⭐

This roadmap update integrates **2025 authentication security best practices** from leading standards organizations:

1. **RFC 9700 (OAuth 2.1)** - January 2025 security requirements
2. **CVSS 4.0** - Modern vulnerability scoring
3. **Bugcrowd VRT** - Industry-standard bug bounty severity
4. **OWASP WSTG 2025** - Comprehensive auth testing guide
5. **NIST SP 800-63B** - Password and MFA guidelines

### Implementation Timeline

- **Weeks 1-4 (P1):** Standards compliance (RFC 9700, CVSS 4.0, VRT)
- **Weeks 4-8 (P2):** Enhanced detection (MFA, session lifecycle, password policy)
- **Months 2-3 (P3):** Advanced features (active testing opt-in, bug bounty integration)

### Expected Outcomes

**After Phase 1 (Week 4):**
- ✅ Full OAuth 2.1 compliance
- ✅ CVSS 4.0 scores in all exports
- ✅ Bug bounty-ready reports (PDF, Markdown, templates)
- ✅ Bugcrowd P1-P5 severity mappings

**After Phase 2 (Week 8):**
- ✅ MFA implementation detection (WebAuthn/TOTP/SMS)
- ✅ MFA bypass vulnerability detection
- ✅ Session timeout and rotation tracking
- ✅ Password policy analysis
- ✅ 80% OWASP WSTG coverage

**After Phase 3 (Month 3):**
- ✅ Optional active testing (with explicit user consent)
- ✅ One-click bug bounty submission
- ✅ Compliance report generation

### Module Count

**New Modules:** 8
- `oauth2-2025-validator.js` - RFC 9700 compliance
- `dpop-validator.js` - DPoP header validation
- `cvss-calculator.js` - CVSS 4.0 scoring
- `bugcrowd-vrt-mapper.js` - VRT alignment
- `mfa-detector.js` - MFA detection
- `session-lifecycle-tracker.js` - Session management
- `password-policy-analyzer.js` - Password policy extraction
- `active-tester.js` - Opt-in active testing

**Enhanced Modules:** 5
- `oauth2-analyzer.js` - Updated PKCE severity
- `webauthn-validator.js` - MFA context
- `auth-issue-database.js` - New issue types
- `export-manager.js` - PDF/MD/BB templates
- `session-security-analyzer.js` - Lifecycle integration

### New Vulnerability Detections

**OAuth2/OIDC (RFC 9700):**
- Missing DPoP (MEDIUM)
- Refresh token not rotated (HIGH)
- PKCE missing on confidential clients (HIGH - severity increased)
- Missing resource indicators (LOW)

**MFA:**
- MFA code in URL (HIGH)
- MFA not enforced on sensitive endpoints (HIGH)
- MFA bypass token excessive lifetime (MEDIUM)
- SMS-based MFA detected (INFO with recommendations)

**Session Management:**
- Session no absolute timeout (MEDIUM)
- Session excessive lifetime >24h (MEDIUM)
- Inactivity timeout not enforced (LOW)
- Concurrent sessions allowed (LOW)
- Remember me token weak entropy (MEDIUM)

**Password Policy:**
- Weak password policy (MEDIUM)
- No password minimum length (MEDIUM)

### Standards Compliance Checklist

- ✅ RFC 9700 (OAuth 2.1 Security Best Current Practice)
- ✅ RFC 9449 (DPoP - Sender-Constrained Tokens)
- ✅ RFC 8707 (Resource Indicators)
- ✅ CVSS 4.0 (Common Vulnerability Scoring System)
- ✅ Bugcrowd VRT (P1-P5 severity taxonomy)
- ✅ OWASP WSTG 2025 (Authentication Testing - 80% coverage)
- ✅ NIST SP 800-63B (Digital Identity Guidelines)

### Key Principles Maintained

From CLAUDE.md adversarial design principles:

1. **Evidence-based detection** - Report facts, not guesses
2. **Context-aware severity** - HSTS risk varies by application type
3. **False positive avoidance** - Smart exemptions (OAuth2 token endpoints)
4. **RFC compliance** - No CSRF on token endpoints per RFC 6749/7636
5. **Privacy-first** - 3-tier token redaction (high/medium/low risk)
6. **Passive-by-default** - Active testing OPT-IN only with explicit consent

### Breaking Changes

**None.** All enhancements are backward-compatible:
- Existing detections continue to work
- New CVSS 4.0 scores complement existing severity
- Bugcrowd VRT mappings are additive
- Active testing is opt-in (disabled by default)

---

**Last Updated:** 2025-10-28
**Version:** 0.2.0
**Maintained by:** Hera Development Team
**Standards:** RFC 9700, CVSS 4.0, Bugcrowd VRT, OWASP WSTG 2025, NIST SP 800-63B
