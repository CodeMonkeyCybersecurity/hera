# Hera Auth Monitor - Quick Start

## ✅ Import Error Fixed!

The error: `The requested module './probe-consent.js' does not provide an export named 'probeConsentManager'`

**Has been fixed** by disabling the probe imports in `modules/message-router.js`.

---

## 🚀 Loading the Extension

1. Open Chrome and go to `chrome://extensions/`
2. Enable **Developer mode** (toggle in top-right)
3. Click **Load unpacked**
4. Select the `/Users/henry/Dev/hera` folder
5. The extension should load successfully ✅

---

## 🧪 Testing Auth Detection

### Test 1: OAuth2 Flow (Google)
1. Go to https://accounts.google.com/
2. Start signing in to any Google service
3. Open Hera extension popup
4. Check Dashboard for OAuth2 flow detection

### Test 2: JWT in Response
1. Visit any site that uses JWTs (try https://jwt.io/)
2. Paste a sample JWT in the debugger
3. Extension should detect JWT in page

### Test 3: Session Cookies
1. Visit any site that sets cookies
2. Open Hera popup → Requests tab
3. Check for session cookie analysis

### Test 4: SCIM Endpoint (If you have access)
1. Visit your organization's SCIM endpoint (e.g., `/scim/v2/Users`)
2. Extension should flag SCIM requests

---

## 📊 What Works Now

✅ **Extension loads without errors**
✅ **Auth-only storage filtering** (only auth URLs saved)
✅ **7-day retention** (previously 24h)
✅ **Simplified UI** (6 buttons instead of 12)
✅ **New auth modules created** (JWT, Session, SCIM, enhanced OAuth2)

---

## ⚠️ What's NOT Wired Yet

❌ **New analyzers not integrated** - JWT/Session/SCIM analyzers created but not called from background.js
❌ **Popup doesn't display new findings** - UI needs JavaScript updates to show JWT/session/SCIM issues
❌ **No encryption** - Auth data stored in plaintext

---

## 🔧 Next Steps to Make It Fully Functional

### Step 1: Integrate Analyzers into background.js

Add these imports:
```javascript
import { JWTValidator } from './modules/auth/jwt-validator.js';
import { SessionSecurityAnalyzer } from './modules/auth/session-security-analyzer.js';
import { SCIMAnalyzer } from './modules/auth/scim-analyzer.js';
```

Initialize:
```javascript
const jwtValidator = new JWTValidator();
const sessionAnalyzer = new SessionSecurityAnalyzer();
const scimAnalyzer = new SCIMAnalyzer();
```

Call in webRequest listener:
```javascript
// In onHeadersReceived or onCompleted
if (jwtValidator._looksLikeJWT(responseBody)) {
  const jwtAnalysis = jwtValidator.validateJWT(token);
  // Store jwtAnalysis.issues
}

if (scimAnalyzer.isSCIMEndpoint(url)) {
  const scimAnalysis = scimAnalyzer.analyzeSCIMRequest(request, url);
  // Store scimAnalysis.issues
}

const sessionAnalysis = sessionAnalyzer.analyzeSessionCookies(cookies, url, isHttps);
// Store sessionAnalysis.issues
```

### Step 2: Update Popup JavaScript

Modify `popup.js` to handle new vulnerability types:
```javascript
// Display JWT vulnerabilities
if (finding.type === 'JWT_VULNERABILITY') {
  // Render JWT-specific UI
}

// Display session vulnerabilities
if (finding.type === 'SESSION_FIXATION' || finding.type === 'MISSING_HTTPONLY_FLAG') {
  // Render session-specific UI
}

// Display SCIM vulnerabilities
if (finding.type === 'SCIM_OVER_HTTP') {
  // Render SCIM-specific UI
}
```

### Step 3: Test End-to-End

1. Visit OAuth2 site → Check for grant type analysis
2. Find JWT in response → Check for `alg:none` detection
3. Check session cookies → Verify HttpOnly/Secure/SameSite analysis
4. Visit SCIM endpoint → Verify SCIM security analysis

---

## 📁 File Structure Overview

```
/hera/
├── background.js                    # Main service worker (auth modules disabled ✅)
├── manifest.json                    # Updated to v2.0, auth-only ✅
├── popup.html                       # Simplified UI ✅
├── popup.js                         # ⚠️ Needs updates for new findings
│
├── modules/
│   ├── auth/
│   │   ├── jwt-validator.js         # ✅ NEW - JWT security validation
│   │   ├── session-security-analyzer.js  # ✅ NEW - Session/CSRF detection
│   │   ├── scim-analyzer.js         # ✅ NEW - SCIM provisioning security
│   │   ├── oauth2-analyzer.js       # ✅ ENHANCED - Grant types, scopes, redirect URIs
│   │   └── [other auth modules]
│   │
│   ├── storage-manager.js           # ✅ Auth-only filtering, 7-day retention
│   ├── message-router.js            # ✅ FIXED - Probe imports disabled
│   ├── alarm-handlers.js            # ✅ FIXED - Consent imports disabled
│   └── content/
│       ├── analysis-runner.js       # ✅ All detectors disabled
│       └── detector-loader.js       # ✅ Returns empty (auth-only mode)
│
├── IMPLEMENTATION-COMPLETE.md       # Full implementation summary
├── AUTH-ONLY-REFACTOR-SUMMARY.md    # Original refactoring plan
└── QUICK-START.md                   # This file
```

---

## 🐛 Troubleshooting

**Error: "Service worker registration failed"**
- Fixed ✅ - probe-consent imports disabled

**Error: "Cannot find module"**
- Check all import paths are correct
- Ensure new files exist in `modules/auth/`

**Popup shows no data**
- Analyzers created but not called yet
- Need to integrate into background.js (Step 1 above)

**Storage still shows non-auth requests**
- Check storage-manager.js `_isAuthRelated()` function
- Should filter to only OAuth/SAML/SCIM/login URLs

---

## 💡 Tips

1. **Check browser console** - `chrome://extensions/` → Hera → Inspect views: background page
2. **Check storage** - DevTools → Application → Storage → chrome.storage.local
3. **Test on real sites** - Google login, GitHub OAuth, etc.
4. **Start simple** - Get OAuth2 working first, then JWT, then sessions

---

## 📞 What to Ask Next

- **"Wire up the analyzers"** - I'll integrate JWT/Session/SCIM into background.js
- **"Update the popup UI"** - I'll add JavaScript to display new findings
- **"Fix encryption"** - I'll implement Web Crypto API for sensitive data
- **"Test it"** - I'll create test scenarios and verification steps

---

**Status:** Extension loads ✅ | Auth modules created ✅ | Integration pending ⚠️

**Last Updated:** 2025-10-22
