# Testing Instructions - UI Navigation Feature

## Quick Start

You now have a fully functional view navigation system! Here's how to test it:

## Step 1: Reload the Extension

```bash
# Navigate to chrome://extensions
# Find "Hera by Code Monkey Cybersecurity"
# Click the refresh icon 🔄
```

**Important**: You must reload the extension for the new code to take effect.

## Step 2: Open the Popup

Click the Hera icon in your browser toolbar to open the popup.

## Step 3: Test Navigation Buttons

You should see these buttons at the top:
- **Dashboard** (should be active/blue by default)
- **Requests**
- **Findings**
- **Ports/Auth**
- **Extensions**
- **Settings**

### Test Each Button:

1. **Click "Dashboard"**
   - Should show site safety analysis
   - Button should turn blue (active)
   - Other panels should hide

2. **Click "Requests"**
   - Should show list of captured authentication requests
   - Button should turn blue
   - Other panels should hide

3. **Click "Findings"** ✨ NEW
   - Should show aggregated security findings
   - Button should turn blue
   - If no auth requests captured yet, shows "No security findings yet"

4. **Click "Ports/Auth"** ✨ NEW
   - Should show:
     - Port Distribution (which ports are being used)
     - Authentication Types (OAuth2, SAML, etc.)
     - Security Risks (e.g., unencrypted HTTP)
   - Button should turn blue
   - If no auth requests captured yet, shows "No port analysis data available"

5. **Click "Extensions"** ✨ NEW
   - Should show list of installed extensions with security assessment
   - Each extension shows:
     - Name and version
     - Risk level (HIGH/MEDIUM/LOW)
     - Permissions
     - Security issues
   - Button should turn blue
   - **Note**: Requires "management" permission (Chrome will prompt on first use)

6. **Click "Settings"**
   - Should open settings overlay (modal)
   - Settings include:
     - Enable Response Body Capture
     - Enable DNS & IP Geolocation (GDPR consent)

## Step 4: Test Port Analysis (With Auth Requests)

To get meaningful port analysis data, you need to capture some authentication requests first:

1. Navigate to a website with OAuth/OIDC/SAML (e.g., login to GitHub, Google, Microsoft)
2. Open Hera popup
3. Click "Ports/Auth" button
4. You should see:
   - **Port Distribution**: "Port 443 (HTTPS): 10 request(s)"
   - **Authentication Types**: "OAuth2: 8 request(s)"
   - **Security Risks**: Any issues detected (or "No port-related security risks detected")

### Expected Port Analysis Output:

**Good Example** (secure):
```
Port Distribution:
  Port 443 (HTTPS): 25 requests

Authentication Types:
  OAuth2: 20 requests
  OIDC: 5 requests

Security Risks:
  ✅ No port-related security risks detected
```

**Warning Example** (insecure):
```
Port Distribution:
  Port 443 (HTTPS): 20 requests
  Port 80 (HTTP): 5 requests

Authentication Types:
  OAuth2: 15 requests
  Form Auth: 10 requests

Security Risks:
  🔴 CRITICAL: Unencrypted Authentication
      Authentication over HTTP on port 80 (insecure-site.com)
```

## Step 5: Test Extensions Analysis

1. Click "Extensions" button in Hera popup
2. Chrome may prompt: "Hera by Code Monkey Cybersecurity wants to manage your extensions"
   - Click "Allow" (this is safe - Hera only reads extension info, doesn't modify)
3. You should see a grid of your installed extensions

### Expected Extensions Output:

Each extension card shows:
- **Extension Name** (e.g., "uBlock Origin")
- **Version** (e.g., "1.50.0")
- **Risk Badge** (HIGH/MEDIUM/LOW)
- **Permissions Count** (e.g., "15 permissions")
- **Issues** (if any):
  - "Has broad permissions that could intercept authentication data"
  - "Can access cookies and network requests"
  - "Sideloaded extension (not from Chrome Web Store)"

### Risk Level Meanings:

- **🔴 HIGH**: Sideloaded/development extension (not from Chrome Web Store)
- **🟡 MEDIUM**: Has dangerous permissions (webRequest, debugger, cookies, <all_urls>)
- **🟢 LOW**: Regular web store extension with standard permissions

## Step 6: Test Refresh Buttons

1. Navigate to "Ports/Auth" view
2. Click "Refresh" button in top right
3. Data should reload and update

Same for "Extensions" view.

## Troubleshooting

### "Findings button doesn't work"
- ✅ **FIXED** - Should now switch to findings view
- If still not working, check browser console (F12) for errors

### "Ports/Auth button doesn't work"
- ✅ **FIXED** - Should now switch to port analysis view
- If still not working, check browser console (F12) for errors

### "Extensions button doesn't work"
- ✅ **FIXED** - Should now switch to extensions view
- If you see "Extension analysis requires management permission":
  - Chrome didn't prompt for permission (might have denied previously)
  - Go to chrome://extensions → Hera → Details → Permissions
  - Look for "Manage your extensions" permission

### "No port analysis data available"
This is expected if you haven't captured any authentication requests yet. To capture requests:
1. Navigate to a site with OAuth/OIDC/SAML login
2. Perform a login flow
3. Open Hera popup again
4. Click "Ports/Auth"

### "Module loading errors in console"
If you see errors like "Failed to fetch dynamically imported module":
- This is a separate issue related to content script modules
- It doesn't affect popup navigation (which should work fine)
- We'll address this in a future fix

## Known Issues (Not Related to Navigation)

These issues exist but **don't affect the new navigation features**:

1. **Storage Bloat**: 9.5 MB storage with only 4 sessions - investigating
2. **Content Script Module Loading**: web_accessible_resources CORS errors
3. **Circuit Breaker**: May trigger if storage quota hits 95%

## Expected Behavior Summary

| Button | Expected View | Data Source |
|--------|--------------|-------------|
| Dashboard | Site safety dashboard | Background script analysis |
| Requests | List of auth requests | chrome.storage.local (heraSessions) |
| Findings | Security findings | Aggregated from all requests |
| Ports/Auth | Port & auth analysis | Analyzed from captured requests |
| Extensions | Extension security | chrome.management.getAll() |
| Settings | Settings modal | chrome.storage.local (config) |

## Success Criteria

✅ All 6 buttons are clickable
✅ Clicking a button switches to the correct view
✅ Only one view visible at a time
✅ Active button has blue background
✅ Ports/Auth view shows port distribution
✅ Extensions view shows installed extensions
✅ Findings view shows security findings
✅ No JavaScript errors in console (F12)

## Reporting Issues

If you encounter issues, please report with:
1. Which button you clicked
2. What you expected to see
3. What actually happened
4. Any errors in browser console (F12)
5. Screenshot (if helpful)

## Next Steps After Testing

Once you've tested the navigation features:
1. ✅ Confirm all buttons work
2. ⏳ Address storage bloat issue (9.5 MB with 4 sessions)
3. ⏳ Fix content script module loading errors
4. ⏳ Implement security audit fixes (CRITICAL-01 through CRITICAL-05)

---

**Happy Testing!** 🎉
