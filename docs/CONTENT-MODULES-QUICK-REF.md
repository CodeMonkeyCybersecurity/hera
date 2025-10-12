# Content Script Modules - Quick Reference

## File Locations

```
hera/
├── content-script.js (1,571 lines) ← OLD monolithic version
├── content-script-new.js (94 lines) ← NEW coordinator
└── modules/content/
    ├── content-utils.js (151 lines)
    ├── detector-loader.js (105 lines)
    ├── form-protector.js (909 lines)
    ├── message-queue.js (159 lines)
    └── analysis-runner.js (311 lines)
```

## Module Quick Reference

### content-utils.js (151 lines)
**Purpose**: Shared utilities
**Exports**:
```javascript
export function debug(...args)
export function querySelectorAllDeep(selector, root = document)
export function sanitizeHTML(str)
export function createStubDetectors()
export function createStubDetector(name, method)
export function humanizeFactor(factor)
```
**When to use**: Need utility functions (logging, DOM queries, sanitization)

---

### detector-loader.js (105 lines)
**Purpose**: Detector initialization
**Exports**:
```javascript
export async function loadDetectors()
export function requestInterceptorInjection()
```
**When to use**: Loading detectors, setting up response interception

---

### form-protector.js (909 lines)
**Purpose**: Form protection and alerts
**Exports**:
```javascript
export class HeraFormProtector {
  constructor()
  async init()
  setupFormMonitoring()
  handleFormSubmission(e)
  showCriticalFormWarning(form)
  showPageWarning()
  showBrandedAlert(alertData)
  formatSADSAlertDOM(sadsAnalysis)
  formatAuthAnalysisDOM(authAnalysis)
  // ... more methods
}
```
**When to use**: Form monitoring, user-facing warnings, alerts

---

### message-queue.js (159 lines)
**Purpose**: Throttled messaging
**Exports**:
```javascript
export class ThrottledMessageQueue {
  constructor()
  send(message)
  cleanup()
}
export function getMessageQueue()
export function sendThrottledMessage(message)
```
**When to use**: Sending messages to background script

---

### analysis-runner.js (311 lines)
**Purpose**: Analysis orchestration
**Exports**:
```javascript
export function shouldRunAnalysis()
export async function runComprehensiveAnalysis()
export function handleAnalysisMessage(message, sender, sendResponse)
export function autoRunAnalysis()
```
**When to use**: Running analysis, checking if page should be analyzed

---

## Common Tasks

### Task 1: Add a new utility function
**File**: `modules/content/content-utils.js`
```javascript
export function myNewUtility() {
  // Implementation
}
```

### Task 2: Modify detector loading
**File**: `modules/content/detector-loader.js`
```javascript
export async function loadDetectors() {
  // Modify loading logic
}
```

### Task 3: Add new alert type
**File**: `modules/content/form-protector.js`
```javascript
class HeraFormProtector {
  showMyNewAlert(data) {
    // Create and display new alert
  }
}
```

### Task 4: Change throttle rates
**File**: `modules/content/message-queue.js`
```javascript
this.throttleRates = {
  'ANALYSIS_COMPLETE': 2000,
  'MY_NEW_MESSAGE': 1000, // Add new type
  'default': 500
};
```

### Task 5: Add new detector to analysis
**File**: `modules/content/analysis-runner.js`
```javascript
export async function runComprehensiveAnalysis() {
  // Add detector call
  const myResults = await detectors.myNewDetector.detect();
  allFindings.push(...myResults);
}
```

### Task 6: Modify URL filtering
**File**: `modules/content/analysis-runner.js`
```javascript
export function shouldRunAnalysis() {
  // Add new filtering logic
}
```

---

## Import Patterns

### In content-script-new.js (dynamic imports)
```javascript
const module = await import(chrome.runtime.getURL('modules/content/module-name.js'));
module.exportedFunction();
```

### Between modules (ES6 imports)
```javascript
import { functionName } from './other-module.js';
```

---

## Security Patterns

### XSS Prevention (use everywhere)
```javascript
// ❌ BAD - XSS vulnerable
element.innerHTML = userInput;

// ✅ GOOD - XSS safe
element.textContent = userInput;
// OR
const safeText = sanitizeHTML(userInput);
element.appendChild(document.createTextNode(safeText));
```

### DOM Construction (in form-protector.js)
```javascript
// ❌ BAD
const div = document.createElement('div');
div.innerHTML = `<strong>${userInput}</strong>`;

// ✅ GOOD
const div = document.createElement('div');
const strong = document.createElement('strong');
strong.textContent = userInput;
div.appendChild(strong);
```

### Message Sending (use throttled queue)
```javascript
// ❌ BAD - can overwhelm background
chrome.runtime.sendMessage(message);

// ✅ GOOD - throttled
import { sendThrottledMessage } from './message-queue.js';
sendThrottledMessage(message);
```

---

## Debugging Tips

### Enable debug logging
**File**: `modules/content/content-utils.js`
```javascript
const DEBUG = true; // Change from false
```

### Check module loading
**Console**: Look for these messages:
```
Hera: Content script coordinator loading...
Hera: All modules loaded successfully
Hera: All 5 detectors loaded from manifest
```

### Verify analysis runs
**Console**: Look for:
```
Hera: Starting comprehensive analysis in content script
Hera: Running subdomain impersonation detection...
Hera: Analysis complete - X findings, grade: Y
```

### Check message throttling
**Console**: Look for:
```
Hera: Message queued (priority X): MESSAGE_TYPE
Hera: Sent message: MESSAGE_TYPE
```

---

## Testing Checklist

### Module Loading
- [ ] All modules load without errors
- [ ] No import/export errors
- [ ] Dynamic imports work correctly

### Functionality
- [ ] Detectors load from manifest
- [ ] Form protector initializes
- [ ] Analysis runs automatically
- [ ] Manual analysis trigger works
- [ ] Alerts display correctly
- [ ] Form blocking works
- [ ] Message throttling works

### Security
- [ ] No XSS vulnerabilities
- [ ] All P0/P1/P2/P3 fixes present
- [ ] CSP errors handled gracefully
- [ ] No information leaks

### Performance
- [ ] No memory leaks
- [ ] No excessive CPU usage
- [ ] Message queue doesn't grow unbounded
- [ ] Analysis runs only once per page

---

## Line Count by Module

| Module | Lines | % of Total |
|--------|-------|------------|
| form-protector.js | 909 | 52.6% |
| analysis-runner.js | 311 | 18.0% |
| message-queue.js | 159 | 9.2% |
| content-utils.js | 151 | 8.7% |
| detector-loader.js | 105 | 6.1% |
| content-script-new.js | 94 | 5.4% |
| **Total** | **1,729** | **100%** |

---

## P0/P1/P2/P3 Fix Locations

### P0 Fixes (Critical)
- **P0-1**: detector-loader.js - CSP-safe manifest loading
- **P0-2**: analysis-runner.js - Deduplication flags
- **P0-3**: analysis-runner.js - Overlay injection error handling
- **P0-5**: content-utils.js - Stub detector fallbacks
- **P0-TENTH-4**: analysis-runner.js - DOM snapshot TOCTOU protection

### P1 Fixes (High Priority)
- **P1-1**: detector-loader.js - Isolated world injection
- **P1-4**: message-queue.js - Message throttling
- **P1-SIXTEENTH-1**: detector-loader.js, analysis-runner.js - CSP error handling

### P2 Fixes (Medium Priority)
- **P2-2**: content-utils.js - Shadow DOM support
- **P2-3**: message-queue.js - Per-type throttle rates
- **P2-6**: analysis-runner.js - URL filtering

### P3 Fixes (Low Priority)
- **P3-1**: content-utils.js - Conditional debug logging

### NEW Fixes
- **NEW-P0-2**: detector-loader.js - Loading mutex
- **NEW-P0-3**: message-queue.js - Cleanup on unload
- **NEW-P1-1**: content-utils.js - Error finding system
- **NEW-P2-2**: content-utils.js - Individual stub detectors
- **NEW-P2-3**: analysis-runner.js - Protocol/IP filtering

---

## Migration Checklist

### Before Migration
- [ ] Review all module code
- [ ] Run unit tests
- [ ] Test on multiple sites
- [ ] Verify all fixes present
- [ ] Check console for errors

### During Migration
- [ ] Update manifest.json
- [ ] Add modules to web_accessible_resources
- [ ] Test extension loading
- [ ] Verify analysis runs
- [ ] Check alerts display

### After Migration
- [ ] Monitor error logs
- [ ] Check performance metrics
- [ ] Verify no regressions
- [ ] Get user feedback
- [ ] Document any issues

---

## Common Issues

### Issue: "Failed to import module"
**Cause**: Module not in web_accessible_resources
**Fix**: Add to manifest.json:
```json
"web_accessible_resources": [{
  "resources": ["modules/content/*.js"],
  "matches": ["<all_urls>"]
}]
```

### Issue: "Cannot find export"
**Cause**: Export statement missing or incorrect
**Fix**: Check module exports:
```javascript
export function myFunction() { }  // Named export
export { myFunction };            // Named export
export default myFunction;        // Default export
```

### Issue: "Analysis runs multiple times"
**Cause**: Deduplication flags not working
**Fix**: Check analysis-runner.js flags:
```javascript
if (analysisRunning || analysisCompleted) {
  return;
}
```

### Issue: "Messages not throttled"
**Cause**: Not using sendThrottledMessage()
**Fix**: Import and use:
```javascript
import { sendThrottledMessage } from './message-queue.js';
sendThrottledMessage(message);
```

---

## Performance Optimization

### Module Loading
- Modules load in parallel (fast)
- Cached after first load
- ~10-20ms overhead vs monolithic

### Memory Usage
- Similar to monolithic version
- Modules garbage collected when not used
- Form protector uses MutationObserver efficiently

### Analysis Performance
- Same as before (no performance impact)
- Throttled messaging prevents background overload
- DOM snapshot cached (no repeated queries)

---

## Future Enhancements

### Potential Splits
If form-protector.js needs to be smaller:
- Split into alert-system.js (400-500 lines)
- Split into form-monitor.js (400-500 lines)
- Create result-formatter.js (200-300 lines)

### New Features
- Add more utility functions to content-utils.js
- Create detector-factory.js for dynamic detector loading
- Add telemetry.js for usage analytics
- Create dom-cache.js for optimized queries

---

## Getting Help

### Documentation
- Read CONTENT-SCRIPT-MODULARIZATION-COMPLETE.md
- Read CONTENT-SCRIPT-ARCHITECTURE.md
- Check inline comments in modules

### Debugging
- Enable DEBUG flag in content-utils.js
- Check browser console for errors
- Use Chrome DevTools to inspect modules

### Common Patterns
- Look at existing code in modules
- Follow security patterns (XSS prevention)
- Use throttled messaging always
- Build DOM elements safely

---

## Quick Start

### To modify existing functionality:
1. Find relevant module from table above
2. Locate function/method to modify
3. Make changes preserving security fixes
4. Test changes locally
5. Check console for errors

### To add new functionality:
1. Determine which module it belongs to
2. Add export to module
3. Import in coordinator if needed
4. Test new functionality
5. Update this documentation

### To debug issues:
1. Enable DEBUG flag
2. Check console logs
3. Verify module loading
4. Test on multiple sites
5. Review security patterns

---

## Contact

For questions or issues:
- Check existing documentation first
- Review inline comments in code
- Test changes thoroughly
- Follow security patterns
