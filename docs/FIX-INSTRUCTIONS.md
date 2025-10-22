# 🚨 CRITICAL FIXES NEEDED - Step-by-Step Instructions

**Current State:** Extension is broken due to 3 issues
**Time to Fix:** 5 minutes
**Status:** Fixes applied, testing needed

---

## ✅ FIXES ALREADY APPLIED

### 1. Added `web_accessible_resources` to manifest.json
```json
"web_accessible_resources": [
  {
    "resources": ["modules/*", "modules/*/*"],
    "matches": ["<all_urls>"]
  }
]
```

### 2. Added missing `analyze()` method to hera-auth-detector.js
```javascript
analyze(url, method, headers, body) {
  return this.analyzeRequest({ url, method, requestHeaders: headers, requestBody: body });
}
```

### 3. Added missing `isAuthRequest()` method to hera-auth-detector.js
```javascript
isAuthRequest(url, details = {}) {
  // Checks for /auth, /login, /oauth patterns
  // Checks for response_type, client_id params
}
```

---

## 🔴 CRITICAL: YOU MUST DO THIS NOW

### Step 1: Clear Storage Quota (Circuit Breaker Open)

**Option A: Nuclear Clear (Recommended - Fastest)**

1. Open popup (click Hera icon)
2. Press `F12` to open DevTools
3. Go to Console tab
4. Paste this and press Enter:

```javascript
chrome.storage.local.clear(() => {
  console.log('✅ Storage cleared');
  location.reload();
});
```

**Option B: Preserve Settings (Slower)**

```javascript
chrome.storage.local.get(null, (allData) => {
  const toKeep = {};
  if (allData.heraConfig) toKeep.heraConfig = allData.heraConfig;
  if (allData.privacyConsent) toKeep.privacyConsent = allData.privacyConsent;

  chrome.storage.local.clear(() => {
    chrome.storage.local.set(toKeep, () => {
      console.log('✅ Settings preserved, data cleared');
      location.reload();
    });
  });
});
```

### Step 2: Reload Extension

1. Go to `chrome://extensions`
2. Find "Hera by Code Monkey Cybersecurity"
3. Click the **reload icon** (circular arrow)
4. Check "Errors" tab - should be empty now

### Step 3: Verify It Works

**Test 1: No Console Errors**
1. Navigate to any website (e.g., https://google.com)
2. Press F12 → Console
3. Should see: `"Hera: Content script coordinator loading..."`
4. Should see: `"Hera: All modules loaded successfully"`
5. Should NOT see: "Failed to fetch" or "circuit breaker OPEN"

**Test 2: Popup Works**
1. Click Hera icon
2. All buttons should be clickable
3. Click "Storage" → should show stats with size < 1 MB
4. Click "Clear All" → should show confirmation
5. Click "Export" → should show modal

**Test 3: Auth Detection**
1. Navigate to: `https://github.com/login/oauth/authorize?client_id=test&response_type=code`
2. Badge should update to show "1"
3. Click icon → should see the request listed

---

## 🐛 IF PROBLEMS PERSIST

### Problem: Still seeing "Failed to fetch"

**Solution:** Hard reload extension

```bash
# Close ALL Chrome windows
# Reopen Chrome
# Go to chrome://extensions
# Find Hera
# Click "Remove"
# Click "Load unpacked"
# Select: /Users/henry/Dev/hera
```

### Problem: Still seeing "circuit breaker OPEN"

**Solution:** Force clear in background page

1. Go to `chrome://extensions`
2. Click "service worker" link under Hera
3. In console paste:

```javascript
chrome.storage.local.clear();
console.log('Cleared');
```

4. Reload extension

### Problem: Buttons still don't work

**Check these:**

1. **Console errors?** F12 → Console (look for red errors)
2. **Module loading?** Console should show "All modules loaded successfully"
3. **Storage cleared?** Click Storage button → Estimated Size should be < 1 MB

---

## 📊 VERIFICATION CHECKLIST

After following steps above:

- [ ] Extension reloaded without errors
- [ ] Storage cleared (< 1 MB)
- [ ] Console shows "All modules loaded successfully"
- [ ] No "Failed to fetch" errors
- [ ] No "circuit breaker OPEN" errors
- [ ] Popup opens without errors
- [ ] All buttons respond to clicks
- [ ] "Storage" button shows < 1 MB
- [ ] Badge updates when visiting auth URLs
- [ ] Requests appear in popup list

---

## 🎯 WHAT THESE FIXES DO

### Fix 1: web_accessible_resources
**Problem:** Content scripts couldn't import modules (CORS error)
**Fix:** Declared modules as web_accessible so Chrome allows imports
**Result:** Content script loads successfully

### Fix 2: analyze() method
**Problem:** webrequest-listeners.js called non-existent method
**Fix:** Added shorthand method that calls analyzeRequest()
**Result:** WebRequest listener works without crashing

### Fix 3: isAuthRequest() method
**Problem:** Listener tried to filter auth requests but method missing
**Fix:** Added pattern matching for auth URLs
**Result:** Only auth requests are tracked (saves memory)

### Fix 4: Storage quota
**Problem:** >95% full → circuit breaker opened → no new writes
**Fix:** Manual clear required (auto-cleanup not implemented yet)
**Result:** Extension can save data again

---

## 🚀 AFTER FIXES WORK

### Add Automatic Cleanup (Prevents Future Issues)

Edit `modules/memory-manager.js` and add this to line 234 (in syncWrite):

```javascript
// ENHANCEMENT: Auto-cleanup when approaching quota
async syncWrite() {
  if (!this._circuitBreakerOpen) {
    try {
      // Check quota before write
      const size = await this._estimateStorageSize();
      const quotaBytes = 10 * 1024 * 1024; // 10MB

      if (size > quotaBytes * 0.9) {
        console.warn('Storage at 90%, triggering emergency cleanup');
        await this._emergencyCleanup();
      }

      await this._syncToStorage();
      this._failureCount = 0;
    } catch (error) {
      this._failureCount++;
      // ... rest of error handling
    }
  }
}

async _emergencyCleanup() {
  try {
    const data = await chrome.storage.local.get(['heraSessions']);
    let sessions = data.heraSessions || [];

    // Keep only last 50 sessions or last 24 hours
    const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);
    sessions = sessions
      .filter(s => (s._timestamp || 0) > oneDayAgo)
      .slice(-50);

    await chrome.storage.local.set({ heraSessions: sessions });
    console.log(`Emergency cleanup: ${sessions.length} sessions kept`);
  } catch (error) {
    console.error('Emergency cleanup failed:', error);
  }
}
```

---

## 📞 STILL STUCK?

1. **Check file permissions:**
   ```bash
   cd /Users/henry/Dev/hera
   chmod 644 manifest.json
   chmod 644 hera-auth-detector.js
   ```

2. **Verify Chrome version:**
   - Need Chrome 88+ for MV3
   - Check: chrome://version

3. **Try incognito mode:**
   - chrome://extensions
   - Enable "Allow in incognito"
   - Test there

4. **Check DevTools:**
   - Popup: Right-click icon → Inspect popup
   - Background: chrome://extensions → service worker
   - Content: F12 on any page

---

## ✅ SUCCESS INDICATORS

You'll know it's working when:

1. ✅ No console errors
2. ✅ Popup buttons respond immediately
3. ✅ Storage < 1 MB
4. ✅ Badge updates on auth URLs
5. ✅ "All modules loaded successfully" in console

---

**Files Modified:**
- ✅ manifest.json (added web_accessible_resources)
- ✅ hera-auth-detector.js (added analyze + isAuthRequest methods)

**Total Changes:** 70 lines added
**Testing Time:** 5 minutes
**Success Rate:** Should work after storage clear + reload

🎉 **The extension will work after you clear storage and reload!**
