# Hera Background.js Modularization Plan
**Date:** October 9, 2025  
**Status:** Phase 1 Complete (Infrastructure Modules)  
**Goal:** Break 3260-line monolith into focused, testable modules

## Executive Summary

The current `background.js` is a **3260-line monolith** that violates the Single Responsibility Principle. This plan breaks it into **focused modules** that each do one job well.

### Metrics
- **Before:** 1 file, 3260 lines, ~15 responsibilities
- **After (Target):** 12+ modules, <300 lines each, 1 responsibility per module
- **Phase 1 (Complete):** 3 infrastructure modules created (401 lines)
- **Phase 2 (Complete):** 4 request/response modules created (1100+ lines)
- **Phase 3-4 (Remaining):** Analysis and utility modules

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

## Phase 2: Request/Response Handling ✅ COMPLETE

### Created Modules

#### 1. `modules/webrequest-listeners.js` (456 lines)
**Responsibility:** Chrome webRequest API listeners

**Exports:**
- `WebRequestListeners` class

**Methods:**
- `initialize()` - Check permissions and register all listeners
- `registerBeforeRequest()` - Capture request initiation
- `registerBeforeSendHeaders()` - Capture headers and analyze
- `registerHeadersReceived()` - Capture response headers
- `registerBeforeRedirect()` - Track redirect chains
- `registerCompleted()` - Finalize with session tracking
- `registerErrorOccurred()` - Handle network errors
- `analyzeAuthError()` - Analyze errors for auth context

**Extracted from:** background.js:658-1700

**Fixes Preserved:**
- P0: Wait for initialization before processing
- P2: Nonce-based request/response matching
- P0-SEVENTEENTH-2: Backend scanning disabled (CSP)

---

#### 2. `modules/debugger-events.js` (198 lines)
**Responsibility:** Chrome debugger protocol events

**Exports:**
- `DebuggerEvents` class

**Methods:**
- `register()` - Wire up debugger event listener
- `handleEvent()` - Route events to handlers
- `handleResponseReceived()` - Store response metadata
- `handleLoadingFinished()` - Capture response body
- `processResponseBody()` - Decode and analyze body
- `saveRequest()` - Persist to storage

**Extracted from:** background.js:802-934

**Fixes Preserved:**
- P0-TENTH-1: Validate tabId, requestId, debugTargets
- P0-TENTH-1: Sanitize response body for XSS
- DOS prevention: Size limits on requests

---

#### 3. `modules/message-router.js` (586 lines)
**Responsibility:** Route chrome.runtime.onMessage events

**Exports:**
- `MessageRouter` class

**Methods:**
- `register()` - Register all message listeners
- `handleActionMessage()` - Route action-based messages
- `handleTypeMessage()` - Route type-based messages
- `routeAction()` - Dispatch to specific handlers
- `handleResponseIntercepted()` - Process intercepted responses
- `handleProbeAlgNone()` - Security probe routing
- `handleRepeaterSend()` - Repeater tool routing
- `handleGetRequests()` - Fetch stored requests
- `handleGetBackendScan()` - Backend scan results
- `handleClearRequests()` - Clear all data
- `handlePortConnection()` - DevTools port handling

**Extracted from:** background.js:998-1286, 960-995

**Fixes Preserved:**
- P0-4: Strict message routing (action vs type)
- P0-EIGHTH-3: Sender validation
- P0-SIXTEENTH-1: Content script whitelists
- P0-SEVENTEENTH-1: Correct whitelist routing

---

#### 4. `modules/request-decoder.js` (34 lines)
**Responsibility:** Request/response body decoding

**Exports:**
- `decodeRequestBody()` - Decode POST data
- `decodeBase64()` - Decode base64 responses
- `generateSessionId()` - Generate unique IDs

**Extracted from:** background.js:614-630, 2760-2762

**Fixes Preserved:**
- P1-NEW: Use crypto.randomUUID() (not Math.random())

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

### Step 2: Test New Modules (Phase 1) ✅ COMPLETE
- [x] Load extension with `background-new.js`
- [x] Verify debugger attachment works
- [x] Verify tab events work
- [x] Verify alarms fire correctly
- [x] Verify no regressions

### Step 3: Extract Request Handling (Phase 2) ✅ COMPLETE
- [x] Create `modules/webrequest-listeners.js`
- [x] Create `modules/debugger-events.js`
- [x] Create `modules/message-router.js`
- [x] Create `modules/request-decoder.js`
- [x] Update `background-new.js` to use new modules
- [x] Test request capture end-to-end

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
- [x] Phase 2: Request handling extracted (4 modules, 1274 lines)
- [ ] Phase 3: Analysis extracted (3 modules, ~800 lines)
- [ ] Phase 4: Cutover and testing
- [ ] All tests pass
- [ ] No regressions in functionality
- [ ] Code review approval
- [ ] 1 week stable operation

---

## Timeline

- **Phase 1:** October 9, 2025 00:48 ✅ COMPLETE
- **Phase 2:** October 9, 2025 00:48-01:00 ✅ COMPLETE
- **Phase 3:** October 9, 2025 01:00-01:15 (In Progress)
- **Phase 4:** October 9, 2025 01:15-01:30 (Cutover)
- **Total:** ~1 hour (accelerated via adversarial self-collaboration)

---

## Next Steps

1. **Phase 3** - Extract analysis modules (backend scanner, CDN analyzer, risk calculator)
2. **Phase 4** - Final cutover (rename background.js → background-monolithic-backup.js, background-new.js → background.js)
3. **Test** - Full extension functionality
4. **Monitor** - 1 week stable operation

---

**Status:** Phase 2 Complete (7 modules, 1675 lines extracted)  
**Next:** Phase 3 - Analysis modules
