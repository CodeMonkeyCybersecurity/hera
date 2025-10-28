# P0 Prerequisites - Integration Test Plan

**Date:** 2025-10-28
**Version:** 1.0
**Modules:** ResponseBodyCapturer, RefreshTokenTracker

---

## Critical Fixes Applied

Based on adversarial analysis, the following critical bugs were fixed:

### 1. ❌ → ✅ ResponseCache vs AuthRequests Mismatch
**Problem:** EvidenceCollector looked in `this.responseCache`, but ResponseBodyCapturer stored in `authRequests`
**Fix:** Modified `processResponseBody()` to accept `authRequests` Map as parameter
**Files:**
- [evidence-collector.js:526](evidence-collector.js#L526) - Added `authRequests` parameter
- [response-body-capturer.js:222](modules/response-body-capturer.js#L222) - Pass `authRequests` to processResponseBody

### 2. ❌ → ✅ Token Tracking After Redaction
**Problem:** Tokens were redacted BEFORE tracking, making rotation detection impossible
**Fix:** Track tokens BEFORE redaction in ResponseBodyCapturer
**Files:**
- [response-body-capturer.js:215-230](modules/response-body-capturer.js#L215-230) - Track before redact
- [background.js:252-253](background.js#L252-253) - Pass refreshTokenTracker to ResponseBodyCapturer

### 3. ❌ → ✅ Async Handler Not Awaiting
**Problem:** `handleAuthRequest()` was called without `.catch()`, causing unhandled promise rejections
**Fix:** Added `.catch()` error handler
**Files:**
- [webrequest-listeners.js:106-110](modules/webrequest-listeners.js#L106-110) - Added error handling

### 4. ❌ → ✅ No Response Size Limits
**Problem:** Large responses could cause memory issues
**Fix:** Added 1MB size limit with checks before and after fetching
**Files:**
- [response-body-capturer.js:184-209](modules/response-body-capturer.js#L184-209) - Size limits

### 5. ❌ → ✅ Poor RequestId Matching
**Problem:** Matched first URL, not necessarily the right request
**Fix:** Best-match algorithm using timestamp proximity
**Files:**
- [response-body-capturer.js:313-342](modules/response-body-capturer.js#L313-342) - Timestamp matching

---

## Test Scenarios

### Test 1: Microsoft OAuth2 Flow (DPoP Detection)

**Objective:** Verify DPoP token type detection from response body

**Prerequisites:**
- Microsoft account
- Test Azure AD application with OAuth2 configured
- Response body capture enabled

**Test Steps:**

1. **Navigate to Microsoft login**
   ```
   https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?...
   ```

2. **Complete authentication flow**
   - Enter credentials
   - Complete MFA if required
   - Wait for token endpoint request

3. **Verify token endpoint captured**
   - Check console for: `[ResponseCapture] Auth response detected: https://login.microsoftonline.com/.../token`
   - Verify no errors: `[ResponseCapture] Error capturing response body`

4. **Verify response body captured**
   - Check console for: `[ResponseCapture] Captured response body for https://...`
   - Open Hera popup/dashboard
   - Find token endpoint request
   - Verify `responseBodyCaptured: true` in metadata

5. **Verify DPoP or Bearer detection**
   - Check console for: `[Evidence] Found X security findings in response body`
   - Verify finding type:
     - If DPoP: `DPOP_DETECTED` (INFO severity)
     - If Bearer: `BEARER_TOKEN_USED` (INFO severity)

6. **Verify token redaction**
   - Inspect `requestData.responseBody`
   - Verify: `access_token: "[REDACTED_ACCESS_TOKEN length=XXX]"`
   - Verify: `refresh_token: "[REDACTED_REFRESH_TOKEN length=XXX]"`
   - Verify: `token_type: "Bearer"` (NOT redacted)
   - Verify: `expires_in: 3600` (NOT redacted)

**Expected Results:**
- ✅ Response body captured via debugger API
- ✅ Token type detected (DPoP or Bearer)
- ✅ Sensitive tokens redacted
- ✅ Metadata preserved for analysis
- ✅ Finding added to `metadata.responseBodyFindings`

**Debug Checklist:**
- [ ] Debugger attached successfully? (Check for "DevTools is debugging" notification)
- [ ] DevTools NOT already open? (Conflicts with debugger API)
- [ ] Request matched by URL pattern? (Check `_isAuthResponse()`)
- [ ] RequestId matched correctly? (Check `_findWebRequestId()` logs)
- [ ] Response body is JSON? (Non-JSON skipped)

---

### Test 2: Google OAuth2 Flow (Refresh Token Rotation)

**Objective:** Verify refresh token rotation detection

**Prerequisites:**
- Google account
- Test application with refresh token flow
- Response body capture enabled

**Test Steps:**

1. **Complete initial OAuth2 flow**
   - Authenticate with Google
   - Obtain refresh token
   - Verify token captured: Check console for `[ResponseCapture] Captured response body`

2. **Trigger refresh token usage (FIRST TIME)**
   - Use refresh token to get new access token
   - Check console for: `[RefreshTokenTracker] No existing hash` (implicit - no error)
   - Verify NO finding (rotation working correctly)

3. **Trigger refresh token usage (SECOND TIME - Same token)**
   - Use SAME refresh token again
   - Check console for: `[ResponseCapture] Refresh token rotation violation detected`
   - Verify finding added: `REFRESH_TOKEN_NOT_ROTATED` (HIGH severity)

4. **Verify token tracking without plaintext**
   - Inspect `requestData.responseBody`
   - Verify refresh_token is redacted: `[REDACTED_REFRESH_TOKEN...]`
   - Open browser console
   - Search memory for actual refresh token string
   - Should NOT find plaintext token (only hash stored)

5. **Verify finding evidence**
   - Check finding in `metadata.securityFindings`
   - Verify evidence includes:
     - `domain: "oauth2.googleapis.com"`
     - `tokenHash: "a3f2c8d1..."` (first 16 chars of SHA-256)
     - `useCount: 2` (or higher)
     - `timeSinceFirstUse: XXXXX` (milliseconds)

**Expected Results:**
- ✅ First use: Token tracked, no finding
- ✅ Second use: Rotation violation detected (HIGH severity)
- ✅ Token hash stored (NOT plaintext)
- ✅ Evidence includes use count and timing
- ✅ Redacted token in storage

**Debug Checklist:**
- [ ] Response body parsed as JSON?
- [ ] URL matched `_isTokenResponse()` pattern?
- [ ] RefreshTokenTracker received BEFORE redaction?
- [ ] Hash collision? (Extremely unlikely, but check `tokenHash`)
- [ ] Token different but detected as same? (Hash collision - report to dev)

---

### Test 3: GitHub OAuth2 Flow (Baseline Test)

**Objective:** Verify basic OAuth2 flow without DPoP or rotation issues

**Prerequisites:**
- GitHub account
- Test OAuth2 application
- Response body capture enabled

**Test Steps:**

1. **Complete GitHub OAuth2 flow**
   - Navigate to: `https://github.com/login/oauth/authorize?...`
   - Authorize application
   - Wait for token endpoint: `https://github.com/login/oauth/access_token`

2. **Verify basic capture**
   - Check console for: `[ResponseCapture] Auth response detected`
   - Verify response body captured
   - Verify no errors

3. **Verify token type detection**
   - Should detect: `BEARER_TOKEN_USED` (INFO severity)
   - GitHub does NOT use DPoP

4. **Verify NO false positives**
   - Should NOT detect: `REFRESH_TOKEN_NOT_ROTATED`
   - GitHub issues new token each time (rotation working)

5. **Verify redaction**
   - access_token: Redacted
   - token_type: Preserved ("bearer")
   - scope: Preserved

**Expected Results:**
- ✅ Response body captured
- ✅ Bearer token detected
- ✅ No false positives
- ✅ Proper redaction
- ✅ No errors in console

---

## Edge Case Tests

### Edge Case 1: DevTools Already Open

**Test:**
1. Open Chrome DevTools (F12)
2. Navigate to OAuth2 flow
3. Observe error: `[ResponseCapture] Failed to attach to tab: Another debugger is already attached`

**Expected:**
- ❌ Response body capture disabled for this tab
- ✅ No crashes or uncaught exceptions
- ✅ Other detections still work (PKCE, state, headers)

---

### Edge Case 2: Large Response Body (>1MB)

**Test:**
1. Configure server to return 2MB response
2. Trigger OAuth2 token endpoint
3. Observe warning: `[ResponseCapture] Response too large (2097152 bytes), skipping`

**Expected:**
- ✅ Request skipped (no memory issues)
- ✅ No capture attempted
- ✅ Other requests still captured normally

---

### Edge Case 3: Tab Closed Before Response

**Test:**
1. Start OAuth2 flow
2. Close tab immediately after request sent
3. Response arrives but tab is gone

**Expected:**
- ✅ Debug message: `[ResponseCapture] Tab closed before response captured`
- ✅ No errors thrown
- ✅ Debugger detached cleanly

---

### Edge Case 4: Non-JSON Response

**Test:**
1. Server returns HTML error page instead of JSON
2. Token endpoint returns 500 with HTML body

**Expected:**
- ✅ Debug message: `[ResponseCapture] Response body not JSON, skipping token tracking`
- ✅ No JSON parse errors
- ✅ No crash

---

### Edge Case 5: Duplicate Simultaneous Requests

**Test:**
1. Make 2 requests to same token endpoint simultaneously
2. Both responses arrive within 100ms

**Expected:**
- ✅ Both responses captured
- ✅ Matched to correct requests (timestamp-based)
- ✅ No response body swapping

---

## Performance Tests

### Performance Test 1: Memory Usage

**Test:**
1. Complete 100 OAuth2 flows in a row
2. Monitor extension memory usage

**Expected:**
- ✅ Memory stays under 50MB
- ✅ Old token hashes cleaned up (7 day TTL)
- ✅ No memory leaks

**How to check:**
1. Open `chrome://extensions/`
2. Enable Developer mode
3. Click "Inspect views: service worker"
4. Go to Memory tab
5. Take heap snapshot before/after 100 flows

---

### Performance Test 2: Response Time Impact

**Test:**
1. Measure token endpoint response time WITHOUT Hera
2. Measure token endpoint response time WITH Hera
3. Compare

**Expected:**
- ✅ Overhead < 50ms per request
- ✅ No visible slowdown to user

---

## Integration Test Checklist

Before shipping P0 prerequisites, verify:

- [ ] **Fix 1 (ResponseCache mismatch):** processResponseBody() finds requests in authRequests
- [ ] **Fix 2 (Track before redact):** Token rotation detection works with redacted storage
- [ ] **Fix 3 (Async error handling):** No unhandled promise rejections in console
- [ ] **Fix 4 (Error handling):** Tab closure handled gracefully
- [ ] **Fix 5 (Size limits):** Large responses (>1MB) skipped
- [ ] **Fix 6 (RequestId matching):** Duplicate URLs matched correctly
- [ ] **Microsoft OAuth2:** DPoP or Bearer detected
- [ ] **Google OAuth2:** Refresh token rotation violations detected
- [ ] **GitHub OAuth2:** Basic flow works, no false positives
- [ ] **Edge cases:** All 5 edge cases handled correctly
- [ ] **Performance:** Memory < 50MB, overhead < 50ms

---

## Debugging Tips

### Enable Verbose Logging

Add this to background.js:
```javascript
// Enable verbose logging for P0 modules
if (!isProduction) {
  window.DEBUG_RESPONSE_CAPTURE = true;
  window.DEBUG_TOKEN_TRACKING = true;
}
```

### Check Debugger Attachment

```javascript
// In browser console
chrome.runtime.sendMessage({action: 'GET_DEBUGGER_STATUS'}, (response) => {
  console.log('Debugger status:', response);
});
```

### Inspect Token Hashes

```javascript
// In Hera service worker console
refreshTokenTracker.getStats()
// Returns: { trackedTokens: 3, domains: ['oauth2.googleapis.com'], ... }
```

### View Response Bodies

```javascript
// In Hera service worker console
for (const [id, req] of authRequests.entries()) {
  if (req.responseBody) {
    console.log(id, req.url, req.responseBody);
  }
}
```

---

## Test Results Template

```markdown
## Test Results - [DATE]

**Tester:** [NAME]
**Browser:** Chrome [VERSION]
**Hera Version:** [VERSION]

### Test 1: Microsoft OAuth2
- [ ] Response body captured
- [ ] DPoP/Bearer detected
- [ ] Tokens redacted
- [ ] No errors
- **Notes:**

### Test 2: Google OAuth2
- [ ] First use: No finding
- [ ] Second use: Rotation violation
- [ ] Hash stored (not plaintext)
- [ ] No errors
- **Notes:**

### Test 3: GitHub OAuth2
- [ ] Response body captured
- [ ] Bearer detected
- [ ] No false positives
- [ ] No errors
- **Notes:**

### Edge Cases
- [ ] DevTools conflict handled
- [ ] Large response skipped
- [ ] Tab closure handled
- [ ] Non-JSON handled
- [ ] Duplicate requests matched
- **Notes:**

### Performance
- [ ] Memory < 50MB
- [ ] Overhead < 50ms
- **Notes:**

### Overall Status
- [ ] ✅ PASS - Ready for production
- [ ] ⚠️ PARTIAL - Minor issues found
- [ ] ❌ FAIL - Critical issues found

**Issues Found:**
1.
2.
3.

**Recommendations:**
```

---

## Manual Testing Instructions

### Quick Test (5 minutes)

1. Install Hera extension (load unpacked)
2. Navigate to: https://github.com/login
3. Click "Sign in with GitHub"
4. Complete authentication
5. Open browser console
6. Search for: `[ResponseCapture]`
7. Verify: "Captured response body"
8. Open Hera popup
9. Verify: Bearer token detected

### Full Test (30 minutes)

1. Run all 3 integration tests (Microsoft, Google, GitHub)
2. Run all 5 edge case tests
3. Run 2 performance tests
4. Fill out test results template
5. Report issues on GitHub

---

**Test Plan Version:** 1.0
**Last Updated:** 2025-10-28
**Status:** Ready for QA
