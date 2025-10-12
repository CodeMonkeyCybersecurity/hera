# Troubleshooting: Analysis Button Not Working

**Issue**: Clicking "Analyze Current Page" shows "Error: Analysis failed. Please try again." with no console logs.

## Step-by-Step Debugging Guide

### Step 1: Verify Extension Reload

1. Go to `chrome://extensions`
2. Find "Hera" extension
3. Click the **Refresh** icon (⟳)
4. You should see "Background script loaded" in the service worker console

**To check service worker console:**
- Click "service worker" link under the Hera extension
- You should see console logs from background.js

### Step 2: Verify Popup Console

1. Right-click the Hera extension icon
2. Select "Inspect popup"
3. This opens DevTools for the popup
4. Click "Console" tab

**When you click "Analyze Current Page"**, you should see:
```
Dashboard: Triggering manual analysis...
Dashboard: Sending TRIGGER_ANALYSIS message to background
Dashboard: Received response: {...}
```

### Step 3: Verify Content Script Console

1. Open the website you want to analyze (e.g., https://duckduckgo.com)
2. Press F12 to open DevTools for the PAGE (not the popup)
3. Click "Console" tab
4. You should see:
```
Hera: Content script coordinator loading...
Hera: All modules loaded successfully
```

**When you click "Analyze Current Page" in popup**, you should see:
```
Hera: Manual analysis trigger received
Hera: Starting comprehensive analysis in content script
Hera: Running subdomain impersonation detection...
Hera: Running dark pattern detection...
[etc...]
```

### Step 4: Common Issues

#### Issue: "No logs in popup console"
**Solution**: The popup console is NOT the same as the page console.
- Right-click extension icon → "Inspect popup" (NOT F12 on the page)

#### Issue: "Content script not loaded"
**Solution**: Content scripts only inject on page navigation
- Refresh the page (F5)
- OR wait for auto-injection (we added this feature)

#### Issue: "Service worker inactive"
**Solution**: Service workers sleep after inactivity
- Click "service worker" link to wake it up
- Send a message (click any button in popup)

#### Issue: "Still no logs anywhere"
**Solution**: Clear console filters
- In DevTools console, check that filter dropdown shows "All levels"
- Click the gear icon → ensure nothing is filtered

#### Issue: "Different console windows"
There are THREE separate console windows:
1. **Popup console** - Right-click icon → Inspect popup
2. **Content script console** - F12 on the webpage
3. **Background console** - chrome://extensions → click "service worker"

Logs appear in DIFFERENT consoles depending on where the code runs:
- `dashboard.js` logs → **Popup console**
- `content-script.js` logs → **Page console**
- `background.js` logs → **Service worker console**

### Step 5: Manual Test

Run this in the **popup console**:
```javascript
chrome.runtime.sendMessage({ type: 'TRIGGER_ANALYSIS' }).then(r => console.log('Response:', r))
```

Expected output:
```
Response: {success: true, score: {...}}
```

OR run this in the **page console**:
```javascript
chrome.runtime.sendMessage({ type: 'PING' }, r => console.log('Ping response:', r))
```

Expected output:
```
Ping response: {success: true, loaded: true}
```

### Step 6: Check Permissions

1. Go to `chrome://extensions`
2. Click "Details" on Hera
3. Scroll to "Permissions"
4. Verify these permissions exist:
   - ✅ Read and change all your data on all websites
   - ✅ Modify data you copy and paste
   - ✅ Manage your apps, extensions, and themes

If "scripting" permission is missing, the content script injection will fail.

---

## Recent Code Changes

### Added Debug Logging (2025-10-12)

**Files Modified:**
1. `modules/ui/dashboard.js` - Added console logs to `triggerManualAnalysis()`
2. `modules/ui/view-navigator.js` - Added console logs to `loadExtensionsAnalysis()`
3. `modules/message-router.js` - Added error details logging

**Expected Logs After Fix:**

**Popup Console:**
```
Dashboard: Triggering manual analysis...
Dashboard: Sending TRIGGER_ANALYSIS message to background
```

**Service Worker Console:**
```
Hera: Triggering analysis on tab: 12345 https://example.com
Hera: Content script already loaded, triggering analysis
```

**Page Console:**
```
Hera: Manual analysis trigger received
Hera: Starting comprehensive analysis in content script
Hera: Running subdomain impersonation detection...
Hera: Running dark pattern detection...
Hera: Running phishing detection...
[... more detectors ...]
Hera: Analysis complete
```

---

## If Still Not Working

### Check for Extension Conflicts

Some extensions can block Hera from working:
- **uBlock Origin** - May block content script injection
- **NoScript** - Blocks JavaScript on pages
- **Privacy Badger** - May interfere with webRequest listeners

**Test in incognito mode:**
1. Go to `chrome://extensions`
2. Click "Details" on Hera
3. Enable "Allow in incognito"
4. Open incognito window (Ctrl+Shift+N)
5. Try analysis button

### Check Browser Console for Errors

Press Ctrl+Shift+J (Windows) or Cmd+Option+J (Mac) to open browser console.
Look for errors like:
- `Uncaught TypeError: Cannot read property...`
- `Failed to load resource...`
- `Content Security Policy...`

### Reinstall Extension

If all else fails:
1. Go to `chrome://extensions`
2. Click "Remove" on Hera
3. Reload the extension directory
4. Test again

---

## Contact & Debugging

If you're still having issues after following this guide, provide:

1. **Screenshot of popup console** (Right-click icon → Inspect popup)
2. **Screenshot of page console** (F12 on the page)
3. **Screenshot of service worker console** (chrome://extensions → service worker)
4. **URL you're testing on** (e.g., https://duckduckgo.com)
5. **Chrome version** (chrome://version)

This will help diagnose the issue quickly.
