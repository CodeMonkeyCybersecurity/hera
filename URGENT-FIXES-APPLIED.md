# Urgent Fixes Applied - UI Buttons Not Working

**Date:** October 10, 2025
**Issues:** UI buttons not responding, content script failing, storage quota critical

---

## 🔴 ISSUES IDENTIFIED

### 1. Content Script Modules Not Loading
**Error:** `Failed to fetch dynamically imported module: chrome-extension://.../modules/content/content-utils.js`

**Root Cause:**
Content script was trying to dynamically import modules, but they weren't declared as web_accessible_resources in manifest.json.

### 2. Storage Quota Critical (>95% Full)
**Error:** `Storage quota critical (>95%), skipping sync to prevent quota exhaustion`

**Impact:**
- New auth requests not being saved
- Badge not updating
- Data loss occurring

### 3. UI Buttons Not Working
**Root Cause:**
Modules failing to load prevented event listeners from being attached.

---

## ✅ FIXES APPLIED

### Fix 1: Added web_accessible_resources to manifest.json

**File:** `manifest.json`
**Lines:** 59-70

**Change:**
```json
"web_accessible_resources": [
  {
    "resources": [
      "modules/content/*.js",
      "modules/auth/*.js",
      "modules/ui/*.js",
      "modules/intelligence/*.js",
      "modules/*.js"
    ],
    "matches": ["<all_urls>"]
  }
]
```

**Why This Fixes It:**
Chrome MV3 content scripts can only import modules that are explicitly declared as web_accessible_resources. Without this, dynamic imports fail with CORS errors.

---

### Fix 2: Added isAuthRequest Method

**File:** `hera-auth-detector.js`
**Lines:** 110-166

**What Was Missing:**
The `isAuthRequest(url, details)` method that `webrequest-listeners.js` was calling didn't exist.

**Added:**
```javascript
isAuthRequest(url, details = {}) {
  // Quick URL pattern matching for /auth, /login, /oauth, etc.
  // Query parameter detection for response_type, client_id, etc.
  // Returns true if URL is auth-related
}
```

---

## 🚨 STILL NEED TO FIX: Storage Quota Critical

### Problem
Storage is >95% full (likely hundreds of MB of auth requests).

### Immediate Actions Needed

#### Option 1: Clear Old Data (Recommended)
Run this in browser console on popup.html:

```javascript
// Clear sessions older than 7 days
chrome.storage.local.get(['heraSessions'], (result) => {
  const sessions = result.heraSessions || [];
  const sevenDaysAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);

  const kept = sessions.filter(s => {
    const timestamp = s._timestamp || s.timestamp || 0;
    return timestamp > sevenDaysAgo;
  });

  chrome.storage.local.set({ heraSessions: kept }, () => {
    console.log(`Cleaned: ${sessions.length} → ${kept.length} sessions`);
    location.reload();
  });
});
```

#### Option 2: Export and Clear All
1. Click "Storage" button in popup
2. Click "Export All Data"
3. Save the JSON file
4. Click "Clear All" button
5. Reload extension

#### Option 3: Emergency Clear (No Export)
```javascript
chrome.storage.local.clear(() => {
  console.log('Storage cleared');
  location.reload();
});
```

### Long-term Fix Needed

Add automatic cleanup to `modules/storage-manager.js`:

```javascript
async storeAuthEvent(eventData) {
  // Existing code...

  // ENHANCEMENT: Auto-cleanup when approaching quota
  const currentSize = await this._estimateStorageSize();
  const quotaBytes = 10 * 1024 * 1024; // 10MB limit

  if (currentSize > quotaBytes * 0.9) {
    console.warn('Storage at 90%, triggering cleanup');
    await this._emergencyCleanup();
  }

  // ... rest of method
}

async _emergencyCleanup() {
  const data = await chrome.storage.local.get(['heraSessions']);
  let sessions = data.heraSessions || [];

  // Keep only last 100 sessions or last 24 hours
  const oneDayAgo = Date.now() - (24 * 60 * 60 * 1000);
  sessions = sessions
    .filter(s => (s._timestamp || 0) > oneDayAgo)
    .slice(-100);

  await chrome.storage.local.set({ heraSessions: sessions });
  console.log(`Emergency cleanup: reduced to ${sessions.length} sessions`);
}
```

---

## 🧪 TESTING INSTRUCTIONS

### 1. Reload Extension
```
1. Go to chrome://extensions
2. Find Hera
3. Click the reload icon
4. Check "Errors" tab - should be empty
```

### 2. Test Content Script
```
1. Navigate to https://accounts.google.com
2. Open DevTools Console
3. Should see: "Hera: Content script coordinator loading..."
4. Should see: "Hera: All modules loaded successfully"
5. No errors about "Failed to fetch"
```

### 3. Test Popup Buttons
```
1. Click Hera icon in toolbar
2. Click "Clear All" - should show confirmation
3. Click "Export" - should show export modal
4. Click "Storage" - should show storage stats
5. Click "Settings" - should open settings panel
```

### 4. Test Auth Detection
```
1. Navigate to: https://github.com/login/oauth/authorize?client_id=test&response_type=code
2. Click Hera icon
3. Should see badge with count: "1"
4. Should see request in popup
```

### 5. Verify Storage Quota Fixed
```
1. Open popup
2. Click "Storage" button
3. Check "Estimated Size"
4. Should be < 5 MB
5. If > 5 MB, run cleanup script above
```

---

## 📊 VERIFICATION CHECKLIST

After reload:
- [ ] Extension loads without errors
- [ ] Console shows "Hera: Content script coordinator loading..."
- [ ] Console shows "Hera: All modules loaded successfully"
- [ ] No "Failed to fetch" errors
- [ ] Popup opens without errors
- [ ] All buttons work (Clear All, Export, Storage, Settings)
- [ ] Auth requests are captured
- [ ] Badge updates with count
- [ ] Storage is < 5 MB (check with Storage button)

---

## 🔄 IF ISSUES PERSIST

### 1. Hard Reload Extension
```bash
# Close all Chrome windows
# Reopen Chrome
# Navigate to chrome://extensions
# Remove Hera
# Click "Load unpacked"
# Select /Users/henry/Dev/hera
```

### 2. Check Console for New Errors
```
F12 → Console tab
Filter: "Hera"
Look for red errors
```

### 3. Verify File Permissions
```bash
cd /Users/henry/Dev/hera
chmod 644 manifest.json
chmod 644 modules/**/*.js
```

### 4. Clear Browser Cache
```
Settings → Privacy → Clear browsing data → Cached images and files
```

---

## 📝 LESSONS LEARNED

1. **web_accessible_resources Required:**
   Content scripts using dynamic imports MUST declare modules as web_accessible_resources.

2. **Storage Quota Monitoring Needed:**
   Extensions can fill 10MB quickly with verbose auth data. Need automatic cleanup.

3. **Integration Testing Critical:**
   Modularization broke assumptions about method existence (isAuthRequest).

4. **Module Loading is Async:**
   Content scripts may race with page load. Need proper initialization checks.

---

## 🚀 NEXT STEPS

1. **Immediate:** Clear storage quota (use cleanup script above)
2. **Short-term:** Implement automatic storage cleanup
3. **Medium-term:** Add storage quota monitoring to popup
4. **Long-term:** Implement data compression or external storage

---

**Status:** ✅ Modules loading fixed, ⚠️ Storage quota still critical
**Action Required:** User must clear old storage data manually
**ETA:** 5 minutes to test + 2 minutes to clean storage
