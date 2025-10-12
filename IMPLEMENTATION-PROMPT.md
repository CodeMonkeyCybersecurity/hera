# Prompt to Implement Security Fixes

Copy and paste this prompt to get Claude to implement the security fixes:

---

## 🔒 Security Fix Implementation Request

I need you to implement the security fixes identified in the adversarial audit. Please work through them systematically, starting with the CRITICAL issues.

### Context
- **Audit Report:** `docs/SECURITY-AUDIT-FINDINGS.md`
- **Quick Reference:** `SECURITY-PRIORITIES.md`
- **Codebase:** Hera Chrome Extension (recently modularized)
- **Total Issues:** 62 (focus on top 11 P0/P1 issues)

### Implementation Approach

Please follow this process for EACH fix:

1. **Read the issue details** from SECURITY-AUDIT-FINDINGS.md
2. **Read the affected file(s)** to understand current implementation
3. **Implement the fix** as specified in the audit report
4. **Preserve all existing P0/P1/P2 security annotations** in the code
5. **Add a comment** documenting the fix: `// SECURITY FIX: [Issue ID] - [Brief description]`
6. **Test the fix** (describe how you verified it works)
7. **Report completion** with summary of changes

### Priority Order

**Week 1 - CRITICAL Issues (Complete in order):**

1. **CRITICAL-01: Memory Manager Race Condition**
   - File: `modules/memory-manager.js:104-148`
   - Fix: Add blocking initialization check to authRequests/debugTargets getters
   - Expected change: ~5 lines added
   - Test: Verify accessing before init throws error

2. **CRITICAL-05: ReDoS in Secret Scanner** (Easiest - Start Here!)
   - File: `hera-secret-scanner.js:10`
   - Fix: Add word boundaries to GENERIC_API_KEY regex
   - Expected change: 1 line modified
   - Test: Verify no backtracking on malicious input

3. **CRITICAL-04: Broken Storage Mutex**
   - File: `modules/storage-manager.js:18, 48-134`
   - Fix: Implement proper AsyncMutex class
   - Expected change: New AsyncMutex class (~30 lines) + modify storeAuthEvent to use it
   - Test: Verify concurrent writes don't lose data

4. **CRITICAL-02: Circuit Breaker Data Destruction**
   - File: `modules/memory-manager.js:71-76, 116-125, 234-238`
   - Fix: Replace permanent circuit breaker with exponential backoff
   - Expected change: Modify _syncToStorage method (~40 lines)
   - Test: Verify data preserved after storage failures

5. **CRITICAL-03: Response Interceptor in MAIN World**
   - File: `response-interceptor.js` + `background.js`
   - Fix: Migrate to Chrome DevTools Protocol Network domain
   - Expected change: Rewrite interceptor to use chrome.debugger API (~100 lines)
   - Test: Verify OAuth tokens still captured, page can't intercept

**Week 2 - HIGH Priority Issues:**

6. **HIGH-05: javascript: URI XSS** (Quick Win!)
   - File: `modules/content/form-protector.js:838-841`
   - Fix: Validate URL protocol before setting href
   - Expected change: ~5 lines added
   - Test: Verify javascript: URIs rejected

7. **HIGH-04: Detector Loader Race**
   - File: `modules/content/detector-loader.js:8-57`
   - Fix: Actually use loadingPromise mutex
   - Expected change: ~3 lines modified
   - Test: Verify concurrent calls return same promise

8. **HIGH-03: XSS in DOMSecurity**
   - File: `modules/ui/dom-security.js:48-57`
   - Fix: Sanitize title attributes, validate className
   - Expected change: ~10 lines modified
   - Test: Verify XSS payloads in title/className blocked

9. **HIGH-02: Authorization Headers to Arbitrary Origins**
   - File: `modules/security-probes.js:85-96, 199-206`
   - Fix: Add 'authorization' to dangerousHeaders list
   - Expected change: ~2 lines added
   - Test: Verify auth headers not sent to probes

10. **HIGH-06: WebRequest Sender Validation**
    - File: `modules/webrequest-listeners.js:60-94`
    - Fix: Validate tab context exists before processing
    - Expected change: ~10 lines added (wrap in chrome.tabs.get)
    - Test: Verify invalid tab requests ignored

11. **HIGH-01: Message Router Auth Bypass**
    - File: `modules/message-router.js:91-101, 414-444`
    - Fix: Consolidate message handling with unified authorization
    - Expected change: ~30 lines (refactor two listeners into one)
    - Test: Verify type-based messages require authorization

### Additional Tasks (Optional - After P0/P1)

**Performance Fixes (Can do in parallel):**
- PERF-02: Rate limit session cleanup (2 hours)
- PERF-04: Fix origin count map leak (2 hours)
- PERF-03: Use WeakSet for form caching (2 hours)

### Requirements

**For Each Fix:**
- ✅ Read the relevant section in SECURITY-AUDIT-FINDINGS.md
- ✅ Read the affected file(s)
- ✅ Implement the fix exactly as specified
- ✅ Add security fix comment in code
- ✅ Preserve all existing security annotations
- ✅ Test the fix (describe test in your response)
- ✅ Report: file changed, lines modified, test results

**Code Quality:**
- Maintain existing code style
- Keep existing variable names where possible
- Don't break existing functionality
- Add JSDoc comments for new functions
- Use async/await consistently

**Testing:**
- Describe how you tested each fix
- Include example test code where applicable
- Verify no regressions in existing features

### Output Format

For each fix, provide:

```
## ✅ [Issue ID]: [Issue Name]

**Files Modified:**
- path/to/file.js (X lines changed)

**Changes Made:**
1. [Description of change 1]
2. [Description of change 2]

**Code Added/Modified:**
```javascript
// Show key code changes
```

**Testing:**
- [How you tested it]
- [Test results]

**Status:** ✅ COMPLETE / ⚠️ NEEDS REVIEW / ❌ BLOCKED
```

### Starting Instructions

Please start with **CRITICAL-05** (easiest, 1 line change) to build confidence, then proceed to **CRITICAL-01**, then continue through the list in order.

After completing each fix:
1. Verify the code compiles (no syntax errors)
2. Check that existing tests still pass (if any)
3. Add the fix to a running total summary
4. Ask if I want to continue to the next issue

### Example Starting Prompt

"I'll implement the security fixes from the audit report. Starting with CRITICAL-05 (ReDoS fix) as it's the quickest win..."

[Then Claude should read the file, implement the fix, test it, and report results]

### Important Notes

- **Don't skip the "read file first" step** - you need context
- **Follow the fix instructions exactly** - they were carefully designed
- **Test each fix** - describe what you tested
- **Preserve security comments** - they're critical for audit trail
- **Work incrementally** - one fix at a time with verification

### Ready?

Start with: **CRITICAL-05: ReDoS in Secret Scanner**

Begin by reading `hera-secret-scanner.js` and then implementing the fix.

---

## Alternative: Single Command

If you want me to implement ALL fixes in one go, use:

"Implement all 11 P0/P1 security fixes from SECURITY-AUDIT-FINDINGS.md in priority order. Start with CRITICAL-05 (ReDoS), then CRITICAL-01, 04, 02, 03, then HIGH-05 through HIGH-01. For each fix: read file, implement change, test, report. Work through them systematically and give me a summary after each one."

---

## If You Want Step-by-Step

Use this for interactive mode:

"Implement CRITICAL-05 from the security audit (ReDoS fix in hera-secret-scanner.js). Read the file first, apply the fix, test it, and report results. After completion, wait for my approval before moving to the next issue."

---

## Notes

- All backup files already exist (*.backup)
- Modularization is complete
- Focus on security fixes only (don't refactor other things)
- Preserve all existing P0/P1/P2/P3 annotations
- Add new "SECURITY FIX" comments for audit trail
