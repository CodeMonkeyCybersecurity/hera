# Hera Evidence Collection & User Experience Roadmap

**Last Updated:** 2025-10-27
**Version:** 0.1.0

---

## P0 Issues - COMPLETED ✅

### P0-1: Evidence Persistence (IndexedDB) ✅
**Problem:** Evidence cache showed "NOT synced" - all data lost on crash
**Solution:** Implemented IndexedDB auto-save every 60 seconds
**Status:** SHIPPED

**Changes:**
- Auto-save to IndexedDB every 60 seconds
- Save on visibility change (tab hidden/closed)
- Persistent storage survives browser restart
- Migration from chrome.storage.local to IndexedDB
- No quota limits (vs 10MB chrome.storage limit)

**Log output before:**
```
Evidence cache (in-memory only, NOT synced): 161 responses, 0.17 MB
```

**Log output after:**
```
[Evidence] 161 responses, 161 events (0.17 MB) - ✓ Saved 3s ago
[Evidence] Auto-saved to IndexedDB (last sync: 60s ago)
```

---

### P0-2: Structured Logging ✅
**Problem:** Logs showed useless "Object, Object, Object"
**Solution:** Replaced with human-readable structured logs
**Status:** SHIPPED

**Changes:**
- `console.debug()` for routine messages
- `console.log()` for important events
- `console.error()` for failures
- Clear message categories: `[Evidence]`, `[Analysis]`, `[Message]`, `[Interceptor]`

**Log output before:**
```
MessageRouter: Message received (action handler): Object
MessageRouter: Message received (type handler): Object
MessageRouter: handleTypeMessage called with: Object
MessageRouter: Authorization check: Object
```

**Log output after:**
```
[Message] INJECT_RESPONSE_INTERCEPTOR from console.hetzner.com
[Interceptor] Injection successful for tab 54209604
```

---

### P0-3: Finding Summaries in Logs ✅
**Problem:** Analysis complete but no visibility into what was found
**Solution:** Log human-friendly summaries with findings breakdown
**Status:** SHIPPED

**Changes:**
- Show security score with rating (EXCELLENT/GOOD/FAIR/POOR/CRITICAL)
- Group findings by severity
- Display top 3 findings with icons
- Clear call-to-action ("Click Hera icon to view details")

**Log output before:**
```
MessageRouter: Analysis complete for: https://console.hetzner.com/...
MessageRouter: Score data: Object
MessageRouter: Analysis results stored successfully
```

**Log output after:**
```
[Analysis] console.hetzner.com - Score: 87/100 (GOOD)
  Findings: 2 (1 MEDIUM, 1 LOW)
  ⚠️  Cookie missing SameSite=Strict
  ⚠️  Response exposes server version
[Analysis] Results stored - Click Hera icon to view details
```

---

## P1 Issues - Short Term (1-2 weeks)

### P1-1: Evidence Export Notifications
**Status:** PLANNED

**Goal:** Notify users when high-confidence findings are detected

**Implementation:**
```javascript
// When high-confidence finding detected
if (finding.confidence === 'HIGH' && finding.severity >= 'MEDIUM') {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon-warning.png',
    title: 'Hera: High-Confidence Finding',
    message: `${finding.type} detected on ${domain}`,
    buttons: [
      { title: 'View Evidence' },
      { title: 'Export Report' }
    ]
  });

  // Update badge with finding count
  chrome.action.setBadgeText({ text: findingCount.toString() });
  chrome.action.setBadgeBackgroundColor({ color: '#FF0000' });
}
```

**User benefit:** Immediate awareness when vulnerabilities are found

---

### P1-2: Evidence Quality Indicators
**Status:** PLANNED

**Goal:** Show users how complete their evidence is

**Implementation:**
```javascript
// Calculate evidence completeness
const quality = {
  requestCoverage: {
    hasAuthFlow: !!evidence.authorizationRequest,
    hasTokenExchange: !!evidence.tokenRequest,
    hasTokenRefresh: !!evidence.refreshRequest,
    percentage: Math.floor((found / total) * 100)
  },
  evidenceCompleteness: {
    hasRequestHeaders: !!evidence.requestHeaders,
    hasResponseHeaders: !!evidence.responseHeaders,
    hasRequestBody: !!evidence.requestBody,
    hasResponseBody: !!evidence.responseBody,
    hasTimingData: !!evidence.timing,
    percentage: Math.floor((fields / 5) * 100)
  },
  findingConfidence: {
    averageConfidence: avgConfidence,
    highConfidenceCount: highCount,
    suggestions: getSuggestions(evidence)
  }
};

console.log('[Evidence Quality] console.hetzner.com');
console.log(`  Request Coverage:  ${quality.requestCoverage.percentage}%`);
console.log(`  Evidence Complete: ${quality.evidenceCompleteness.percentage}%`);
console.log(`  Finding Confidence: ${quality.findingConfidence.averageConfidence}%`);

if (quality.findingConfidence.suggestions.length > 0) {
  console.log('  Suggestions:');
  quality.findingConfidence.suggestions.forEach(s => {
    console.log(`    • ${s}`);
  });
}
```

**User benefit:** Know when to stop testing (sufficient evidence collected)

---

### P1-3: Batch Log Updates (Reduce Spam)
**Status:** PLANNED

**Goal:** Reduce console spam from evidence collection

**Implementation:**
```javascript
class EvidenceCollector {
  constructor() {
    this.lastLogTime = 0;
    this.LOG_INTERVAL_MS = 10000; // Log every 10 seconds max
    this.pendingUpdates = 0;
  }

  _shouldLog() {
    const now = Date.now();
    if (now - this.lastLogTime > this.LOG_INTERVAL_MS) {
      this.lastLogTime = now;
      return true;
    }
    return false;
  }

  captureResponse(requestId, responseHeaders, responseBody, statusCode) {
    // ... existing code ...

    this.pendingUpdates++;

    if (this._shouldLog()) {
      console.log(`[Evidence] Captured ${this.pendingUpdates} responses in ${this.LOG_INTERVAL_MS / 1000}s`);
      this.pendingUpdates = 0;
    }
  }
}
```

**User benefit:** Clean console logs, no spam

---

### P1-4: Export Format Options
**Status:** PLANNED

**Goal:** Allow users to export evidence in multiple formats

**Formats:**
1. **PDF Report** - Human-readable bug bounty report
2. **JSON Evidence** - Machine-readable for tools
3. **HAR File** - Burp Suite / ZAP import
4. **Markdown Summary** - Documentation friendly

**Implementation:**
```javascript
class EvidenceExporter {
  async exportAsPDF(evidence, findings) {
    // Use jsPDF or similar
    const doc = new jsPDF();

    // Title page
    doc.setFontSize(20);
    doc.text('Security Assessment Report', 20, 20);
    doc.setFontSize(12);
    doc.text(`Target: ${evidence.domain}`, 20, 30);
    doc.text(`Date: ${new Date().toISOString()}`, 20, 40);

    // Executive summary
    doc.text('Executive Summary', 20, 60);
    doc.text(`Overall Score: ${evidence.score}/100`, 20, 70);
    doc.text(`Findings: ${findings.length}`, 20, 80);

    // Detailed findings
    findings.forEach((finding, i) => {
      doc.addPage();
      doc.setFontSize(16);
      doc.text(`Finding ${i + 1}: ${finding.title}`, 20, 20);
      doc.setFontSize(12);
      doc.text(`Severity: ${finding.severity}`, 20, 30);
      doc.text(`Confidence: ${finding.confidence}`, 20, 40);
      doc.text('Evidence:', 20, 50);
      doc.text(JSON.stringify(finding.evidence, null, 2), 20, 60);
    });

    return doc.output('blob');
  }

  async exportAsJSON(evidence, findings) {
    return JSON.stringify({
      version: '1.0',
      tool: 'Hera',
      timestamp: Date.now(),
      target: evidence.domain,
      score: evidence.score,
      findings: findings.map(f => ({
        ...f,
        evidence: f.evidence,
        cwe: f.cwe,
        cvss: f.cvss
      })),
      evidence: {
        requests: evidence.requests,
        responses: evidence.responses,
        timeline: evidence.timeline
      }
    }, null, 2);
  }

  async exportAsHAR(evidence) {
    return {
      log: {
        version: '1.2',
        creator: {
          name: 'Hera',
          version: chrome.runtime.getManifest().version
        },
        entries: evidence.requests.map(req => ({
          startedDateTime: new Date(req.timestamp).toISOString(),
          time: req.timing?.duration || 0,
          request: {
            method: req.method,
            url: req.url,
            headers: req.headers,
            postData: req.body ? { text: req.body } : undefined
          },
          response: {
            status: req.statusCode,
            headers: req.responseHeaders,
            content: req.responseBody ? { text: req.responseBody } : undefined
          }
        }))
      }
    };
  }
}
```

**User benefit:** Flexible export for different use cases

---

## P2 Issues - Medium Term (1-2 months)

### P2-1: Evidence Timeline Visualization
**Status:** PLANNED

**Goal:** Show chronological flow of authentication requests

**Mockup:**
```
[Timeline] console.hetzner.com OAuth2 session
  12:34:01 ━━ 🔵 Session started (OAuth2 login detected)
           │
  12:34:15 ━━ ✅ PKCE flow complete
           │   ├─ code_challenge sent (S256)
           │   └─ code_verifier verified
           │
  12:34:42 ━━ 📡 API calls monitored (142 requests)
           │
  12:35:08 ━━ ⚠️  Missing CSRF token
           │   └─ POST /api/dns/records
           │
  12:35:22 ━━ 💾 Evidence package ready
               └─ 0.17 MB, 161 requests
```

**Implementation:**
- Interactive HTML timeline
- Expandable events (click to see details)
- Color-coded by severity
- Exportable as SVG/PNG

---

### P2-2: Smart Evidence Summarization
**Status:** PLANNED

**Goal:** Reduce log noise with intelligent batching

**Example:**
```
// Instead of:
[Evidence] Captured 1 request
[Evidence] Captured 1 request
[Evidence] Captured 1 request
... (142 more)

// Show:
[Evidence] Captured 142 requests in 45 seconds
  - OAuth2 authorization flow (3 requests)
  - API calls (135 requests)
  - Static assets (4 requests)

  Notable: 2 security findings detected
  Storage: 0.17 MB (auto-saving every 60s)
```

---

### P2-3: Contextual User Notifications
**Status:** PLANNED

**Goal:** Browser notifications for important findings

**Implementation:**
```javascript
// When high-severity finding detected
if (finding.severity === 'HIGH' || finding.severity === 'CRITICAL') {
  const notification = chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon-alert.png',
    title: `Hera: ${finding.severity} Finding`,
    message: `${finding.title} on ${domain}`,
    contextMessage: `Confidence: ${finding.confidence}% - Click to view details`,
    buttons: [
      { title: 'View Evidence' },
      { title: 'Export Report' }
    ],
    requireInteraction: true
  });

  chrome.notifications.onButtonClicked.addListener((notifId, btnIdx) => {
    if (notifId === notification) {
      if (btnIdx === 0) {
        // Open popup with evidence
        chrome.action.openPopup();
      } else if (btnIdx === 1) {
        // Trigger export
        exportEvidence(finding);
      }
    }
  });
}
```

---

### P2-4: Evidence Export Preview
**Status:** PLANNED

**Goal:** Show users what they're exporting before download

**Mockup:**
```
┌─────────────────────────────────────────────────┐
│ Evidence Package: console.hetzner.com          │
├─────────────────────────────────────────────────┤
│                                                 │
│ Session Duration: 45 seconds                    │
│ Requests Captured: 161                          │
│ Findings: 2 (1 MEDIUM, 1 LOW)                   │
│                                                 │
│ Export Formats Available:                       │
│   📄 PDF Report (for bug bounties)             │
│   📊 JSON Evidence (for tools)                  │
│   📋 Markdown Summary (for docs)                │
│   🔗 HAR File (for Burp Suite)                  │
│                                                 │
│ Estimated Size: 2.3 MB                          │
│ Includes: Screenshots, request/response data    │
│                                                 │
│ [Export PDF] [Export JSON] [Export HAR] [❌]    │
└─────────────────────────────────────────────────┘
```

---

### P2-5: Real-Time Evidence Quality Indicators
**Status:** PLANNED

**Goal:** Live progress bars showing evidence completeness

**Mockup:**
```
[Evidence Quality] console.hetzner.com

  Request Coverage:  ████████░░ 80%
    ✅ Authorization flow captured
    ✅ Token exchange captured
    ⚠️  Token refresh not yet observed

  Evidence Completeness:  ██████████ 100%
    ✅ Request headers
    ✅ Response headers
    ✅ Request body
    ✅ Response body
    ✅ Timing data

  Finding Confidence:  ████████░░ 85%
    Suggestion: Capture 1 more CSRF-vulnerable request
                to increase confidence to 95%
```

---

### P2-6: Progressive Evidence Degradation
**Status:** PLANNED

**Goal:** Gracefully handle storage limits

**Implementation:**
```javascript
class EvidenceCollector {
  async handleStoragePressure() {
    const usage = await this.getStorageUsage();

    if (usage > 0.90) {
      console.warn('[Evidence] Storage at 90% - degrading evidence quality');

      // Strategy 1: Export high-confidence findings
      const highConfidence = this.findings.filter(f => f.confidence >= 90);
      if (highConfidence.length > 0) {
        await this.autoExport(highConfidence);
        console.log(`[Evidence] Auto-exported ${highConfidence.length} findings`);
      }

      // Strategy 2: Compress old requests
      const compressed = await this.compressOldEvidence();
      console.log(`[Evidence] Compressed ${compressed.sizeSaved} MB`);

      // Strategy 3: Archive to IndexedDB
      await this.archiveToIndexedDB();

      // Strategy 4: Warn user
      chrome.notifications.create({
        type: 'basic',
        title: 'Hera: Storage Almost Full',
        message: 'Export evidence now to prevent data loss?',
        buttons: [
          { title: 'Export Now' },
          { title: 'Increase Limit' }
        ]
      });
    }
  }
}
```

---

## P3 Issues - Long Term (2+ months)

### P3-1: Evidence Collaboration Features
**Status:** IDEA

**Goal:** Share evidence with team members

**Features:**
- Generate shareable link (read-only)
- Email evidence package
- Export to shared drive
- Encrypt for client delivery

---

### P3-2: Evidence-Based Learning
**Status:** IDEA

**Goal:** Track what evidence actually helps users

**Implementation:**
```javascript
class EvidenceAnalytics {
  trackExportUsage(finding, exportFormat) {
    // Track which evidence fields are actually used
    const analytics = {
      findingType: finding.type,
      exportFormat: exportFormat,
      evidenceFields: Object.keys(finding.evidence),
      timestamp: Date.now()
    };

    this.usageLog.push(analytics);
  }

  async generateInsights() {
    // After 30 days, show insights
    const insights = {
      mostUsedEvidence: this.getMostUsed(),
      leastUsedEvidence: this.getLeastUsed(),
      recommendations: this.getRecommendations()
    };

    console.log('[Insights] Evidence usage patterns');
    console.log(`  Most useful: ${insights.mostUsedEvidence.join(', ')}`);
    console.log(`  Least useful: ${insights.leastUsedEvidence.join(', ')}`);
    console.log('');
    console.log('  Recommendation:', insights.recommendations[0]);
  }
}
```

---

### P3-3: Machine Learning for False Positive Reduction
**Status:** IDEA

**Goal:** Learn from user feedback on findings

**Approach:**
- Track which findings users export vs dismiss
- Build classifier to predict false positives
- Adjust confidence scores based on historical accuracy

---

### P3-4: Integration with Bug Bounty Platforms
**Status:** IDEA

**Goal:** One-click submit to HackerOne, Bugcrowd, etc.

**Features:**
- Pre-filled vulnerability templates
- Automatic severity mapping (Hera → CVSS)
- Evidence attachment upload
- Draft submission creation

---

### P3-5: Compliance Reporting
**Status:** IDEA

**Goal:** Generate compliance reports (OWASP, PCI-DSS, SOC2)

**Example:**
```
OWASP Top 10 Compliance Report
Generated by Hera v0.1.0
Target: console.hetzner.com

A02:2021 - Cryptographic Failures
  ✅ PASS - HTTPS enforced with HSTS
  ⚠️  WARN - HSTS max-age could be longer (recommended: 31536000)

A05:2021 - Security Misconfiguration
  ❌ FAIL - Missing Content-Security-Policy header
  ⚠️  WARN - Server version exposed in headers

A07:2021 - Identification and Authentication Failures
  ✅ PASS - OAuth2 with PKCE implemented correctly
  ✅ PASS - No credentials in URLs

Overall Score: 8/10 controls passed
Risk Level: LOW
```

---

## Implementation Priority

| Item | Priority | Effort | Impact | Timeline |
|------|----------|--------|--------|----------|
| P1-1: Export Notifications | HIGH | 2 days | HIGH | Week 1 |
| P1-2: Quality Indicators | HIGH | 3 days | HIGH | Week 1 |
| P1-3: Batch Logs | MEDIUM | 1 day | MEDIUM | Week 1 |
| P1-4: Export Formats | HIGH | 5 days | HIGH | Week 2 |
| P2-1: Timeline Viz | MEDIUM | 1 week | MEDIUM | Month 1 |
| P2-2: Smart Summary | LOW | 2 days | LOW | Month 1 |
| P2-3: Notifications | HIGH | 3 days | HIGH | Month 1 |
| P2-4: Export Preview | MEDIUM | 3 days | MEDIUM | Month 1 |
| P2-5: Quality UI | MEDIUM | 1 week | MEDIUM | Month 2 |
| P2-6: Degradation | LOW | 1 week | MEDIUM | Month 2 |
| P3-1: Collaboration | LOW | 2 weeks | LOW | Q1 2026 |
| P3-2: Learning | LOW | 2 weeks | MEDIUM | Q1 2026 |
| P3-3: ML | LOW | 1 month | HIGH | Q2 2026 |
| P3-4: BB Integration | MEDIUM | 2 weeks | HIGH | Q2 2026 |
| P3-5: Compliance | LOW | 1 month | MEDIUM | Q3 2026 |

---

## Success Metrics

### User Satisfaction
- **Goal:** 90% of users find evidence "useful" or "very useful"
- **Measure:** Post-export survey

### Export Rate
- **Goal:** 50% of sessions with findings result in exports
- **Baseline:** Currently unknown (not tracked)

### False Positive Rate
- **Goal:** <10% of exported findings are false positives
- **Measure:** User feedback on exports

### Evidence Completeness
- **Goal:** 95% of exported evidence packages have all required fields
- **Measure:** Automated validation on export

### Time to Export
- **Goal:** <30 seconds from finding detection to PDF export
- **Baseline:** Currently unknown

---

## Questions for Future Consideration

1. **Should Hera support collaborative pentesting?**
   - Multiple analysts sharing evidence in real-time
   - Team dashboards with aggregated findings

2. **Should Hera integrate with CI/CD pipelines?**
   - Automated security testing during development
   - Pre-deployment vulnerability scanning

3. **Should Hera support custom plugins?**
   - User-defined vulnerability detectors
   - Custom export formats
   - Third-party integrations

4. **Should Hera offer a hosted service?**
   - Cloud evidence storage
   - Team collaboration features
   - Historical trending

---

## Feedback

Have ideas for the roadmap? File an issue at:
https://github.com/anthropics/hera/issues

---

**Last Updated:** 2025-10-27
**Maintained by:** Hera Development Team
