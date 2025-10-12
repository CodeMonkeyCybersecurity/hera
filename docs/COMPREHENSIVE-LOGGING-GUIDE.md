# Comprehensive Logging Guide - Hera Extension

**Date**: 2025-10-12
**Purpose**: Complete logging coverage for debugging "Analyze Current Page" button and all analysis flows

---

## Overview

We've added extensive logging to every step of the analysis flow. This document explains:
1. **Where logs appear** (3 separate console windows)
2. **What logs to expect** at each step
3. **How to interpret the logs**
4. **Common error patterns**

---

## The Three Console Windows

**CRITICAL**: Chrome extensions have THREE separate JavaScript execution contexts, each with its own console:

### 1. Popup Console (UI)
**How to Access**: Right-click Hera icon → "Inspect popup"

**What Runs Here**:
- `popup.js`
- `modules/ui/dashboard.js`
- `modules/ui/view-navigator.js`
- All other UI modules

**Log Prefix**: `Dashboard:`, `Navigation:`

---

### 2. Service Worker Console (Background)
**How to Access**: `chrome://extensions` → Find Hera → Click "service worker"

**What Runs Here**:
- `background.js`
- `modules/message-router.js`
- `modules/storage-manager.js`
- All background modules

**Log Prefix**: `MessageRouter:`, `Hera:`, `StorageManager:`

---

### 3. Page Console (Content Script)
**How to Access**: Press F12 on the webpage you're analyzing

**What Runs Here**:
- `content-script.js`
- `modules/content/analysis-runner.js`
- All content script modules

**Log Prefix**: `AnalysisRunner:`, `Hera: Content script`

---

## Complete Analysis Flow with Expected Logs

### Step 1: User Clicks "Analyze Current Page"

**Popup Console**:
```
Dashboard: Triggering manual analysis...
Dashboard: Sending TRIGGER_ANALYSIS message to background
```

**What This Means**: The dashboard UI captured the button click and is sending a message to the background script.

---

### Step 2: Message Reaches Background Script

**Service Worker Console**:
```
MessageRouter: Message received (action handler): {action: undefined, type: "TRIGGER_ANALYSIS", senderUrl: "chrome-extension://[ID]/popup.html"}
MessageRouter: Skipping - has action property
MessageRouter: Message received (type handler): {action: undefined, type: "TRIGGER_ANALYSIS", senderUrl: "chrome-extension://[ID]/popup.html"}
MessageRouter: handleTypeMessage called with: {type: "TRIGGER_ANALYSIS", senderUrl: "chrome-extension://[ID]/popup.html"}
MessageRouter: Authorization check: {senderUrl: "chrome-extension://[ID]/popup.html", isAuthorizedSender: true, allowedUrls: [...]}
MessageRouter: Routing type-based message: TRIGGER_ANALYSIS
MessageRouter: Calling handleTriggerAnalysis
```

**What This Means**:
- Two listeners receive the message (action and type handlers)
- Action handler skips it (no `action` property)
- Type handler processes it
- Sender is authorized (popup is in allowed list)
- Routes to `handleTriggerAnalysis`

---

### Step 3: Background Gets Active Tab

**Service Worker Console**:
```
MessageRouter: handleTriggerAnalysis called
MessageRouter: Querying active tab...
MessageRouter: Found tabs: 1
MessageRouter: Active tab: {id: 12345, url: "https://example.com"}
MessageRouter: Triggering analysis on tab: 12345 https://example.com
MessageRouter: Pinging content script...
```

**What This Means**: Background script identified which tab to analyze and is checking if content script is loaded.

---

### Step 4A: Content Script Already Loaded (Normal Case)

**Service Worker Console**:
```
MessageRouter: Ping response: {success: true, loaded: true} Error: undefined
MessageRouter: Content script already loaded, triggering analysis
```

**Page Console**:
```
Hera: Manual analysis trigger received
AnalysisRunner: runComprehensiveAnalysis called
AnalysisRunner: State check - running: false, completed: false
AnalysisRunner: Starting analysis - setting analysisRunning = true
Hera: DOM snapshot captured: {url: "...", formCount: 3, ...}
Hera: Starting comprehensive analysis in content script
Hera: Running subdomain impersonation detection...
Hera: Running dark pattern detection...
Hera: Running phishing detection...
Hera: Running privacy violation detection...
[... more detectors ...]
Hera: Analysis complete
```

**What This Means**: Content script was already loaded, so analysis runs immediately.

---

### Step 4B: Content Script Not Loaded (First Analysis After Extension Reload)

**Service Worker Console**:
```
MessageRouter: Ping response: undefined Error: [Error object]
MessageRouter: Content script not found, injecting dynamically...
MessageRouter: Content script injected successfully
```

**Page Console**:
```
Hera: Content script coordinator loading...
Hera: All modules loaded successfully
[... then same as Step 4A ...]
```

**What This Means**: Background script detected missing content script and injected it automatically.

---

### Step 5: Analysis Completes in Content Script

**Page Console**:
```
Hera: Analysis complete
Hera: Reputation overlay not injected: Overlay injection blocked (likely by CSP)
Hera: Analysis complete but overlay unavailable. Results stored in extension.
```

**Service Worker Console**:
```
MessageRouter: Message received (type handler): {type: "ANALYSIS_COMPLETE", ...}
MessageRouter: handleAnalysisComplete called
MessageRouter: Message data: {url: "https://example.com", hasScore: true, findingsCount: 5}
MessageRouter: Analysis complete for: https://example.com
MessageRouter: Score data: {overall: 85, categories: {...}}
MessageRouter: Storing analysis data to chrome.storage.local...
MessageRouter: Analysis results stored successfully
```

**What This Means**: Content script finished analysis and sent results to background, which stored them.

---

### Step 6: Dashboard Receives Response

**Popup Console**:
```
Dashboard: Received response: {success: true, score: {...}}
Dashboard: Analysis successful, score: {overall: 85, ...}
```

**What This Means**: Dashboard received confirmation and will reload to show results.

---

## Common Error Patterns

### Error 1: Response is `undefined`

**Popup Console**:
```
Dashboard: Received response: undefined
Dashboard: Analysis failed with response: undefined
```

**Cause**: Message not reaching background OR background not calling `sendResponse()`

**Check Service Worker Console** - If you see NO logs at all:
- Message listener not registered
- Extension not loaded properly
- Background script crashed

**If you see logs up to "handleTriggerAnalysis called" then stops**:
- `sendResponse()` not being called
- Handler not returning `true` for async response

---

### Error 2: "Could not establish connection"

**Service Worker Console**:
```
MessageRouter: Ping response: undefined Error: {message: "Could not establish connection. Receiving end does not exist."}
MessageRouter: Content script not found, injecting dynamically...
```

**Cause**: Content script not loaded on page

**Solution**: Auto-injection should handle this. If it fails:
- Check if page allows content script injection (some Chrome internal pages don't)
- Check if scripting permission is present

---

### Error 3: "Analysis already completed"

**Page Console**:
```
AnalysisRunner: State check - running: false, completed: true
Hera: Analysis already completed for this page
```

**Cause**: Analysis runs once per page load, blocked on second attempt

**Solution**: Refresh the page OR the "Analyze Current Page" button should reset flags (check if TRIGGER_ANALYSIS handler resets flags)

---

### Error 4: Authorization Failed

**Service Worker Console**:
```
MessageRouter: Authorization check: {senderUrl: "...", isAuthorizedSender: false, ...}
Hera SECURITY: Unauthorized type message from ...: TRIGGER_ANALYSIS
```

**Cause**: Sender URL not in allowed list

**Solution**: Check `allowedSenderUrls` in `message-router.js` - popup.html should be included

---

## Debugging Checklist

When "Analyze Current Page" doesn't work:

### ✅ Step 1: Open All Three Consoles
- [ ] Popup console (Right-click icon → Inspect popup)
- [ ] Service worker console (chrome://extensions → service worker)
- [ ] Page console (F12 on webpage)

### ✅ Step 2: Click "Analyze Current Page"

### ✅ Step 3: Check Popup Console
- [ ] See "Dashboard: Triggering manual analysis..."?
  - **YES** → Proceed to Step 4
  - **NO** → Button click handler not attached

### ✅ Step 4: Check Service Worker Console
- [ ] See "MessageRouter: Message received..."?
  - **YES** → Proceed to Step 5
  - **NO** → Message not reaching background (check extension loaded)

- [ ] See "MessageRouter: Calling handleTriggerAnalysis"?
  - **YES** → Proceed to Step 6
  - **NO** → Check authorization logs (may be blocked)

- [ ] See "MessageRouter: Pinging content script..."?
  - **YES** → Proceed to Step 7
  - **NO** → handleTriggerAnalysis crashed (check error logs)

### ✅ Step 5: Check Page Console
- [ ] See "Hera: Manual analysis trigger received"?
  - **YES** → Content script working
  - **NO** → Content script not loaded or not receiving messages

- [ ] See "AnalysisRunner: Starting analysis..."?
  - **YES** → Analysis running
  - **NO** → Analysis blocked (check state: running/completed flags)

- [ ] See "Hera: Analysis complete"?
  - **YES** → Analysis finished successfully
  - **NO** → Analysis crashed (check error logs)

### ✅ Step 6: Check Service Worker Console Again
- [ ] See "MessageRouter: handleAnalysisComplete called"?
  - **YES** → Results being stored
  - **NO** → ANALYSIS_COMPLETE message not sent

- [ ] See "MessageRouter: Analysis results stored successfully"?
  - **YES** → Storage successful
  - **NO** → Storage failed (check quota, permissions)

### ✅ Step 7: Check Popup Console Again
- [ ] See "Dashboard: Received response: {success: true, ...}"?
  - **YES** → ✅ WORKING! Dashboard will reload
  - **NO** → Response not reaching popup (check Step 4-6 logs)

---

## Log Prefixes Reference

Quick reference for identifying which module is logging:

| Prefix | Module | Console |
|--------|--------|---------|
| `Dashboard:` | dashboard.js | Popup |
| `Navigation:` | view-navigator.js | Popup |
| `MessageRouter:` | message-router.js | Service Worker |
| `AnalysisRunner:` | analysis-runner.js | Page |
| `Hera: Content script` | content-script.js | Page |
| `Hera: Evidence` | evidence-collector.js | Service Worker |
| `Hera: Storage` | storage-manager.js | Service Worker |

---

## Files Modified with Logging

### High-Priority (Analysis Flow)
1. **modules/ui/dashboard.js** (lines 56-78)
   - `triggerManualAnalysis()` - full request/response logging

2. **modules/message-router.js** (lines 56-86, 606-720, 725-763, 773-838)
   - `register()` - listener registration logging
   - `handleTriggerAnalysis()` - complete flow logging
   - `handleAnalysisComplete()` - storage logging
   - `handleTypeMessage()` - routing and authorization logging

3. **modules/content/analysis-runner.js** (lines 47-63)
   - `runComprehensiveAnalysis()` - state and execution logging

### Medium-Priority (UI)
4. **modules/ui/view-navigator.js** (lines 65-69, 277-305)
   - Extensions refresh button and load logging

### Evidence Storage
5. **evidence-collector.js** (lines 104-134)
   - Stripped large fields before storing (9.18 MB → <1 MB)

---

## Testing the Logging

### Quick Test Commands

**Run in Popup Console**:
```javascript
chrome.runtime.sendMessage({ type: 'TRIGGER_ANALYSIS' }).then(r => console.log('Response:', r))
```

**Expected**: Should see full analysis flow in all three consoles

**Run in Page Console**:
```javascript
chrome.runtime.sendMessage({ type: 'PING' }, r => console.log('Ping:', r))
```

**Expected**: `Ping: {success: true, loaded: true}`

**Run in Service Worker Console**:
```javascript
console.log('Test log from service worker')
```

**Expected**: Should appear in service worker console

---

## Next Steps

1. **Reload extension** (chrome://extensions → refresh)
2. **Open all THREE consoles** (popup, service worker, page)
3. **Click "Analyze Current Page"**
4. **Follow the checklist** to see where flow breaks
5. **Report back** with logs from the step that fails

The logging is now comprehensive enough to identify the exact point of failure. Every critical function, message passing step, and state change is logged.

---

**Document Version**: 1.0
**Last Updated**: 2025-10-12
