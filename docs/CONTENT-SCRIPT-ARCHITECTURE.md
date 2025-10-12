# Content Script Architecture Diagram

## Module Dependency Graph

```
┌─────────────────────────────────────────────────────────────────────┐
│                      content-script-new.js (94 lines)               │
│                         [Coordinator]                                │
│  - Dynamic module loading via import()                               │
│  - Initialize form protector                                         │
│  - Set up message listeners                                          │
│  - Auto-run analysis                                                 │
│  - Global API (window.hera)                                          │
└──────────────┬──────────────────────────────────────────────────────┘
               │ imports all modules
               │
    ┌──────────┼──────────┬──────────────┬──────────────┐
    ▼          ▼          ▼              ▼              ▼
┌────────┐ ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌──────────────┐
│content-│ │detector-│ │  form-  │ │ message- │ │  analysis-   │
│utils.js│ │loader.js│ │protector│ │ queue.js │ │  runner.js   │
│        │ │         │ │   .js   │ │          │ │              │
│151 lines│ │105 lines│ │909 lines│ │159 lines │ │  311 lines   │
└────────┘ └─────────┘ └─────────┘ └──────────┘ └──────────────┘
    ▲          ▲          ▲              ▲              ▲
    │          │          │              │              │
    │          └──────────┼──────────────┼──────────────┘
    │                     │              │
    └─────────────────────┴──────────────┘
         (utilities used by all modules)
```

## Module Responsibilities

### 1. content-script-new.js (Coordinator)
```
Role: Bootstrap and coordinate all modules
├── Load modules via dynamic import()
├── Initialize HeraFormProtector
├── Set up chrome.runtime.onMessage listener
├── Trigger auto-analysis
└── Expose global API (window.hera)
```

### 2. content-utils.js (Utilities)
```
Role: Shared utility functions
├── debug() - Conditional logging (P3-1)
├── querySelectorAllDeep() - Shadow DOM support (P2-2)
├── sanitizeHTML() - XSS prevention
├── createStubDetectors() - Fallback system (P0-5)
├── createStubDetector() - Individual stubs (NEW-P2-2)
└── humanizeFactor() - Display formatting
```

### 3. detector-loader.js (Initialization)
```
Role: Load and initialize detectors
├── loadDetectors() - Wait for manifest injection (P0-1)
│   ├── Poll for window.darkPatternDetector, etc.
│   ├── 5-second timeout with fallback to stubs
│   └── Return detector objects
└── requestInterceptorInjection() - Isolated world (P1-1)
    ├── Generate nonce
    ├── Send message to background
    └── Handle CSP failures gracefully (P1-SIXTEENTH-1)
```

### 4. form-protector.js (UI & Alerts)
```
Role: User-facing warnings and form protection
├── HeraFormProtector class
│   ├── init() - Get backend scan results
│   ├── setupFormMonitoring() - Event listeners
│   ├── handleFormSubmission() - Block if critical
│   ├── showCriticalFormWarning() - Blocking UI
│   ├── showPageWarning() - Page-level alerts
│   ├── showBrandedAlert() - Alert system
│   ├── formatSADSAlertDOM() - SADS display (XSS-safe)
│   ├── formatAuthAnalysisDOM() - Auth display (XSS-safe)
│   └── monitorForm() - Real-time monitoring
└── All DOM manipulation is XSS-safe (P0)
```

### 5. message-queue.js (Communication)
```
Role: Throttled messaging to background script
├── ThrottledMessageQueue class
│   ├── send() - Add to queue or send immediately
│   ├── _processQueue() - Priority-based processing
│   ├── _sendMessage() - chrome.runtime.sendMessage
│   └── cleanup() - Cleanup on unload (NEW-P0-3)
├── Throttle rates per message type (P2-3)
│   ├── ANALYSIS_COMPLETE: 2000ms
│   ├── ANALYSIS_ERROR: 5000ms
│   └── default: 500ms
└── Priority system (ANALYSIS_COMPLETE = highest)
```

### 6. analysis-runner.js (Orchestration)
```
Role: Run detection analysis
├── shouldRunAnalysis() - Filter URLs (P2-6, NEW-P2-3)
│   ├── Allow only http/https
│   └── Block localhost/private IPs
├── runComprehensiveAnalysis() - Main flow (P0-2)
│   ├── Check deduplication flags
│   ├── Capture DOM snapshot (P0-TENTH-4)
│   ├── Load detectors
│   ├── Run detectors sequentially
│   │   ├── Subdomain impersonation (fastest first)
│   │   ├── Dark patterns
│   │   ├── Phishing
│   │   └── Privacy violations
│   ├── Calculate risk score
│   ├── Send throttled message (P1-4)
│   ├── Inject overlay (with CSP handling)
│   └── Mark analysis complete
├── handleAnalysisMessage() - Message handler
│   ├── PING - Health check
│   ├── TRIGGER_ANALYSIS - Manual run
│   └── GET_ANALYSIS_STATUS - Status query
└── autoRunAnalysis() - Auto-run on page load
```

## Data Flow

### Initialization Flow
```
1. content-script-new.js loads
2. Dynamic imports load all modules
3. requestInterceptorInjection() called
4. HeraFormProtector initialized
   └── Gets backend scan results
   └── Sets up form monitoring
5. Message listener registered
6. autoRunAnalysis() triggers analysis
```

### Analysis Flow
```
1. shouldRunAnalysis() checks URL
   └── Skip if not http/https or localhost
2. runComprehensiveAnalysis() starts
   ├── Check flags (prevent duplicates)
   ├── Capture DOM snapshot (frozen)
   ├── loadDetectors() - wait for manifest
   ├── Run all detectors in sequence
   ├── Calculate risk score
   ├── sendThrottledMessage() to background
   │   └── ThrottledMessageQueue manages rate
   └── Inject overlay (CSP-safe)
3. Results displayed to user
```

### Form Protection Flow
```
1. User interacts with form
2. HeraFormProtector.handleFormSubmission()
   ├── Check if contains sensitive data
   ├── If critical risk → BLOCK
   │   └── showCriticalFormWarning()
   └── If high risk → WARN
       └── Show dismissible warning
3. Password fields get real-time warnings
   └── showPasswordWarning()
```

### Alert Flow
```
1. Backend scan finds issues
2. HeraFormProtector.showPageWarning()
   ├── Format results (DOM-safe)
   │   ├── formatSADSAlertDOM() if SADS available
   │   └── formatAuthAnalysisDOM() if auth issues
   └── showBrandedAlert()
       ├── Check if alert already showing
       ├── Create branded alert element
       ├── Add to queue if busy
       └── Display with animation
3. User dismisses or auto-dismisses after 15s
```

## Security Features by Module

### content-utils.js
- P3-1: Conditional debug logging
- P2-2: Shadow DOM recursive queries
- P0-5 & NEW-P1-1: Comprehensive stub system
- XSS prevention via sanitizeHTML()

### detector-loader.js
- P0-1: CSP-safe manifest loading
- P1-1: Isolated world injection
- P1-SIXTEENTH-1: Graceful CSP failure handling
- NEW-P0-2: Loading mutex

### form-protector.js
- P0: All DOM construction (no innerHTML)
- XSS-safe alert formatting
- Proper event cleanup
- Safe backend result handling

### message-queue.js
- P1-4: Message throttling
- P2-3: Per-type throttle rates
- NEW-P0-3: Unload cleanup
- Priority queue prevents DOS

### analysis-runner.js
- P0-2: Deduplication flags
- P0-TENTH-4: DOM snapshot TOCTOU protection
- P2-6 & NEW-P2-3: URL filtering
- P0-3: Overlay injection error handling
- P1-SIXTEENTH-1: CSP error suppression

## Chrome MV3 Compatibility

### Why Dynamic Imports?
```
❌ Static imports in content scripts:
   import { foo } from './module.js';
   → FAILS in Chrome MV3 content scripts

✅ Dynamic imports in content scripts:
   const module = await import(chrome.runtime.getURL('./module.js'));
   → WORKS in Chrome MV3 content scripts

Why? Content scripts are injected, not loaded like modules.
```

### Manifest Configuration
```json
{
  "content_scripts": [{
    "js": [
      "detectors/subdomain-impersonation.js",
      "detectors/dark-pattern.js",
      "detectors/phishing.js",
      "detectors/privacy.js",
      "detectors/risk-scoring.js",
      "content-script-new.js"
    ]
  }],
  "web_accessible_resources": [{
    "resources": [
      "modules/content/*.js",
      "site-reputation-overlay.js"
    ],
    "matches": ["<all_urls>"]
  }]
}
```

## Performance Characteristics

| Module | Load Time | Memory | Execution |
|--------|-----------|--------|-----------|
| content-utils.js | ~5ms | Minimal | On-demand |
| detector-loader.js | ~100-5000ms | Minimal | One-time |
| form-protector.js | ~20ms | Moderate | Continuous |
| message-queue.js | ~5ms | Minimal | Per-message |
| analysis-runner.js | ~2-5s | High | One-time |

### Optimization Notes
- Detector loading has 5s timeout (waits for manifest)
- Analysis runs once per page (deduplication)
- Form monitoring uses event delegation
- Message queue prevents background overload
- Overlay injection cached (no duplicates)

## Testing Strategy

### Unit Testing (per module)
```javascript
// content-utils.js
- Test querySelectorAllDeep with shadow DOM
- Test stub detector creation
- Test sanitizeHTML escaping

// detector-loader.js
- Test loadDetectors timeout
- Test stub fallback
- Test interceptor injection

// form-protector.js
- Test form submission blocking
- Test alert creation (no XSS)
- Test SADS formatting

// message-queue.js
- Test throttling rates
- Test priority queue
- Test cleanup

// analysis-runner.js
- Test URL filtering
- Test deduplication
- Test DOM snapshot
```

### Integration Testing
```javascript
// Test full flow
1. Load extension
2. Navigate to test site
3. Verify analysis runs
4. Check results displayed
5. Test form blocking
6. Verify message throttling
```

## Migration Path

### Step 1: Parallel Testing
```
Keep content-script.js (old)
Add content-script-new.js (new)
Test new version on subset of users
```

### Step 2: Switchover
```
Rename content-script.js → content-script-old.js
Rename content-script-new.js → content-script.js
Update manifest.json
```

### Step 3: Cleanup
```
After 1-2 releases, remove content-script-old.js
Keep modules in place
Monitor for issues
```

## Conclusion

The modular architecture provides:
- ✅ Clear separation of concerns
- ✅ Easier testing and debugging
- ✅ Better code organization
- ✅ Preserved security fixes
- ✅ Chrome MV3 compatible
- ✅ Maintainable codebase

Total: 1,729 lines across 6 files vs 1,571 lines in 1 file
Overhead: +158 lines (+10%) for better architecture
