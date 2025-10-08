# Hera Background.js Modularization Plan
**Date:** October 9, 2025  
**Status:** Phase 1 Complete (Infrastructure Modules)  
**Goal:** Break 3260-line monolith into focused, testable modules

## Executive Summary

The current `background.js` is a **3260-line monolith** that violates the Single Responsibility Principle. This plan breaks it into **focused modules** that each do one job well.

### Metrics
- **Before:** 1 file, 3260 lines, ~15 responsibilities
- **After (Target):** 12+ modules, <300 lines each, 1 responsibility per module
- **Phase 1 (Complete):** 3 infrastructure modules created
- **Phase 2-4 (Remaining):** 9+ modules to extract

---

## Phase 1: Infrastructure Modules ✅ COMPLETE

### Created Modules

#### 1. `modules/debugger-manager.js` (183 lines)
**Responsibility:** Chrome DevTools Protocol debugger lifecycle

**Exports:**
- `DebuggerManager` class

**Methods:**
- `attachDebugger(tabId)` - Attach with mutex
- `detachDebugger(tabId)` - Clean detach
- `initializeAllTabs()` - Bulk attach
- `detachAll()` - Cleanup on permission revoke
- `cleanupStaleEntries()` - Periodic garbage collection

**Dependencies:**
- `memoryManager` (for debugTargets storage)

**Fixes Preserved:**
- P0-NINTH-1: Mutex for concurrent operations
- P1-NINTH-1: Immediate cleanup on tab close

---

#### 2. `modules/event-handlers.js` (147 lines)
**Responsibility:** Chrome extension lifecycle events

**Exports:**
- `EventHandlers` class

**Methods:**
- `handleInstalled(details)` - First install + updates
- `handleStartup()` - Browser restart
- `handlePermissionAdded/Removed()` - Permission changes
- `handleTabCreated/Updated/Removed()` - Tab lifecycle
- `registerListeners()` - Wire up all events

**Dependencies:**
- `debuggerManager` (for tab events)
- `storageManager` (for badge updates)

**Fixes Preserved:**
- P0-SEVENTH-2: Graceful debugger permission revocation
- P1-NINTH-1: Immediate tab cleanup

---

#### 3. `modules/alarm-handlers.js` (71 lines)
**Responsibility:** Chrome alarms for periodic tasks

**Exports:**
- `AlarmHandlers` class

**Methods:**
- `initializeAlarms()` - Create all alarms
- `handleAlarm(alarm)` - Route alarm events
- `registerListener()` - Wire up handler

**Dependencies:**
- `memoryManager` (cleanup)
- `alertManager` (cleanup)
- `evidenceCollector` (cleanup)
- `sessionTracker` (cleanup)
- `storageManager` (quota checks)

**Fixes Preserved:**
- P1-TENTH-3: UUID-based probe consent alarms
- P0-ARCH-2: Auto-revoke consent on expiry

---

#### 4. `background-new.js` (206 lines)
**Responsibility:** Initialization coordinator

**Structure:**
- Module imports (organized by category)
- Global configuration
- Component initialization
- Event registration
- Placeholder for webRequest listeners (Phase 2)

**Reduction:** 3260 lines → 206 lines (93% reduction)

---

## Phase 2: Request/Response Handling (TODO)

### Modules to Create

#### 1. `modules/webrequest-listeners.js`
**Responsibility:** Chrome webRequest API listeners

**Exports:**
- `WebRequestListeners` class

**Methods:**
- `initializeListeners()` - Register all listeners
- `handleBeforeRequest(details)` - Capture request
- `handleBeforeSendHeaders(details)` - Capture headers
- `handleHeadersReceived(details)` - Capture response headers
- `handleBeforeRedirect(details)` - Track redirects
- `handleCompleted(details)` - Finalize request
- `handleErrorOccurred(details)` - Handle errors

**Lines:** ~500 (extracted from background.js:658-1300)

---

#### 2. `modules/debugger-events.js`
**Responsibility:** Chrome debugger protocol events

**Exports:**
- `DebuggerEvents` class

**Methods:**
- `handleResponseReceived(params)` - Store response metadata
- `handleLoadingFinished(params)` - Capture response body
- `registerListener()` - Wire up debugger events

**Lines:** ~200 (extracted from background.js:759-935)

---

#### 3. `modules/request-decoder.js`
**Responsibility:** Request/response body decoding

**Exports:**
- `decodeRequestBody(requestBody)` - Decode POST data
- `decodeResponseBody(response)` - Decode response (base64, gzip, etc.)

**Lines:** ~50 (extracted from background.js:614-630)

---

## Phase 3: Analysis & Detection (TODO)

### Modules to Create

#### 1. `modules/backend-scanner.js`
**Responsibility:** Exposed backend detection

**Exports:**
- `BackendScanner` class

**Methods:**
- `scanForExposedBackends(domain)` - Main scan
- `checkMongoDBExposure(domain)` - MongoDB check
- `checkS3Exposure(domain)` - S3 bucket check
- `checkGitExposure(domain)` - .git exposure
- `checkEnvFileExposure(domain)` - .env exposure
- `gatherSecuritySignals(domain)` - SADS signals

**Lines:** ~400 (extracted from background.js:1882-2300)

**Note:** Currently disabled due to CSP (P0-SEVENTEENTH-2)

---

#### 2. `modules/cdn-analyzer.js`
**Responsibility:** CDN and infrastructure analysis

**Exports:**
- `analyzeCDNFromHeaders(responseHeaders, url)` - Detect CDN
- `detectCDNMismatch(hostname, cdnProvider)` - Verify expected CDN

**Lines:** ~100 (extracted from background.js:1813-1878)

---

#### 3. `modules/risk-calculator.js`
**Responsibility:** Overall risk score calculation

**Exports:**
- `calculateOverallRiskScore(requestData)` - Aggregate risk
- `generateRiskFactors(requestData)` - Extract factors
- `generateVulnerabilities(requestData)` - Extract vulns

**Lines:** ~300 (extracted from background.js:2400-2700)

---

## Phase 4: Message Handling (TODO)

### Modules to Create

#### 1. `modules/message-router.js`
**Responsibility:** Route chrome.runtime.onMessage events

**Exports:**
- `MessageRouter` class

**Methods:**
- `routeMessage(message, sender, sendResponse)` - Main router
- `validateSender(sender, messageType)` - Authorization
- `handleActionMessage(message, sender)` - Action-based messages
- `handleTypeMessage(message, sender)` - Type-based messages

**Lines:** ~400 (extracted from background.js:1006-1400, 2764-3100)

**Fixes Preserved:**
- P0-EIGHTH-3: Sender validation
- P0-SIXTEENTH-1: Whitelist management
- P0-SEVENTEENTH-1: Correct whitelist routing

---

#### 2. `modules/devtools-port.js`
**Responsibility:** DevTools panel communication

**Exports:**
- `DevToolsPort` class

**Methods:**
- `handleConnection(port)` - Handle port connect
- `handleMessage(message, port)` - Route port messages
- `sendAuthRequest(session, port)` - Send to devtools

**Lines:** ~100 (extracted from background.js:950-1050)

---

## Migration Strategy

### Step 1: Create New Modules (Phase 1) ✅ COMPLETE
- [x] Create `modules/debugger-manager.js`
- [x] Create `modules/event-handlers.js`
- [x] Create `modules/alarm-handlers.js`
- [x] Create `background-new.js` (coordinator)

### Step 2: Test New Modules (Phase 1)
- [ ] Load extension with `background-new.js`
- [ ] Verify debugger attachment works
- [ ] Verify tab events work
- [ ] Verify alarms fire correctly
- [ ] Verify no regressions

### Step 3: Extract Request Handling (Phase 2)
- [ ] Create `modules/webrequest-listeners.js`
- [ ] Create `modules/debugger-events.js`
- [ ] Create `modules/request-decoder.js`
- [ ] Update `background-new.js` to use new modules
- [ ] Test request capture end-to-end

### Step 4: Extract Analysis (Phase 3)
- [ ] Create `modules/backend-scanner.js`
- [ ] Create `modules/cdn-analyzer.js`
- [ ] Create `modules/risk-calculator.js`
- [ ] Update `background-new.js` to use new modules
- [ ] Test analysis pipeline

### Step 5: Extract Message Handling (Phase 4)
- [ ] Create `modules/message-router.js`
- [ ] Create `modules/devtools-port.js`
- [ ] Update `background-new.js` to use new modules
- [ ] Test popup/devtools communication

### Step 6: Cutover
- [ ] Rename `background.js` → `background-monolithic-backup.js`
- [ ] Rename `background-new.js` → `background.js`
- [ ] Update `manifest.json` if needed
- [ ] Test full extension functionality
- [ ] Delete backup after 1 week of stable operation

---

## Benefits

### 1. **Testability**
- Each module can be unit tested in isolation
- Mock dependencies easily
- Test coverage increases from ~0% to >80%

### 2. **Maintainability**
- Find code faster (grep module name)
- Understand module purpose from filename
- Change one thing without breaking others

### 3. **Code Review**
- Review 200-line modules vs 3260-line monolith
- Easier to spot bugs in focused code
- Clear module boundaries

### 4. **Performance**
- Lazy load modules (import() only when needed)
- Tree-shaking removes unused code
- Smaller initial load time

### 5. **Collaboration**
- Multiple developers can work on different modules
- Less merge conflicts
- Clear ownership per module

---

## Risks & Mitigation

### Risk 1: Breaking Changes
**Mitigation:** Keep `background.js` as backup, test thoroughly before cutover

### Risk 2: Import Cycles
**Mitigation:** Use dependency injection, avoid circular imports

### Risk 3: Performance Regression
**Mitigation:** Benchmark before/after, use lazy imports

### Risk 4: Increased Complexity
**Mitigation:** Clear module boundaries, good documentation

---

## Success Criteria

- [x] Phase 1: Infrastructure modules created (3 modules, 401 lines)
- [ ] Phase 2: Request handling extracted (3 modules, ~750 lines)
- [ ] Phase 3: Analysis extracted (3 modules, ~800 lines)
- [ ] Phase 4: Message handling extracted (2 modules, ~500 lines)
- [ ] All tests pass
- [ ] No regressions in functionality
- [ ] Code review approval
- [ ] 1 week stable operation

---

## Timeline

- **Phase 1:** October 9, 2025 ✅ COMPLETE
- **Phase 2:** October 10-11, 2025 (2 days)
- **Phase 3:** October 12-13, 2025 (2 days)
- **Phase 4:** October 14-15, 2025 (2 days)
- **Testing:** October 16-17, 2025 (2 days)
- **Cutover:** October 18, 2025
- **Total:** 9 days

---

## Next Steps

1. **Test Phase 1 modules** - Load extension with `background-new.js`
2. **Fix any issues** - Ensure no regressions
3. **Start Phase 2** - Extract webRequest listeners
4. **Continue iteratively** - One phase at a time

---

**Status:** Phase 1 Complete, Ready for Testing  
**Next:** Test infrastructure modules, then proceed to Phase 2
