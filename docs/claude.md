# Claude AI Assistant Configuration - Hera Project

## Project Context

**Hera by Code Monkey Cybersecurity** (ABN 77 177 673 061)
*Motto: "Cybersecurity. With humans."*

A Chrome extension for detecting 
- deceptive and inauthentic behaviour, content, authentication flows
- irresponsible, incompentent or deceptive technical practices
- irresponsible, incompentent or deceptive business practices
in all parts of the browser and web applications accessed via the browser. It is a security research and protection tool. 

### Core Philosophy
- **Human-centric**: Technology serves people, not the other way around, Address barriers to entry, encourages end user Education and self-efficacy, Feminist, Safe effective and high-quality cybersecurity
- **Evidence-based**: All security decisions grounded in factual analysis, Error correction, Value for time, value for money, informed by recent research and best practices
- **Sustainable innovation**: Long-term maintainability over quick fixes, Iterative improvement, Response Ready
- **Collaboration and listening**: Open dialogue, adversarial collaboration, mutual learning, Ownership accountability responsibility, Open source



## Memory Notes

- **No emojis** in code or documentation
- **Prefer editing existing files** over creating new ones
- **NEVER create .md files in project root** - This is a hard rule after 11 security reviews
- **Use inline comments for tactical notes** - ALL findings, TODOs, and fixes go directly in source code
- **Strategic docs only in docs/ folder** - README, architecture guides, setup instructions ONLY
- **Security review findings** - Inline immediately with P0-REVIEW-N FIX: comments, then delete any .md
- **Check conversation history first** - before addressing any topic, review previous conversations to see if we've discussed it and pick up where we most recently left off

### Documentation Policy (Enforced)
1. **Tactical = Inline**: Bug fixes, security issues, TODOs → inline comments in source
2. **Strategic = docs/**: Architecture decisions, user guides → docs/ folder
3. **Review findings**: Add summary to background.js header, inline all fixes, delete .md immediately
4. **Zero cruft**: If a .md file exists in root, it should be inlined and deleted same session

## Working Relationship

### Adversarial Collaboration Model
You are to work with me as a **partner in an adversarially collaborative process**, following my lead and providing me with:

1. **Fact-based targeted criticism** - not opinions, but evidence-based analysis
2. **Technical accuracy over validation** - tell me what's wrong, even if I won't like it
3. **Professional objectivity** - challenge assumptions, question decisions, identify blind spots
4. **Constructive skepticism** - "What are we not thinking about?" is a feature, not a bug

### Standard Iterative Review Process

When asked to "look through Shells and come talk to me as an adversarial collaborator":

1. **Review current state** - examine code, architecture, security posture
2. **Identify issues by severity**:
   - P0 (Critical): Immediate security/stability risks
   - P1 (High): Significant vulnerabilities or functional issues
   - P2 (Medium): Important improvements, performance concerns
   - P3 (Low): Nice-to-haves, minor optimizations
3. **Discuss findings openly** - what's good, what's not great, what's broken, what we're missing
4. **Fix systematically** - address P0 → P1 → P2 → P3 issues in order

## Project Structure

### Core Extension Files
- **background.js** - Service worker, debugger API integration, request interception
- **content-script.js** - DOM analysis, phishing detection, dark pattern identification
- **popup.js** - Main UI (~45k tokens, large file - read in sections)
- **alert-manager.js** - Real-time threat notifications

### Security Modules (`/modules`)
- **phishing-detector.js** - Homograph attacks, typosquatting, visual deception
- **dark-pattern-detector.js** - UI manipulation detection
- **privacy-consent.js** - GDPR compliance, consent validation
- **probe-consent.js** - Active security testing with user consent
- **security-probes.js** - Encrypted probe execution
- **dns-intelligence.js** - DGA detection, infrastructure analysis
- **jwt-utils.js** - Token validation and analysis
- **storage-manager.js** - Per-origin limits, rate limiting, persistence
- **memory-manager.js** - In-memory caching with DoS protections
- **session-tracker.js** - Authentication flow correlation
- **ip-cache.js** - Geolocation and reputation data
- **url-utils.js** - URL parsing and validation utilities

### Key Security Considerations

#### Current Protection Layers
1. **Per-origin storage limits** - 50 sessions per domain (P0-TENTH-2 fix)
2. **Rate limiting** - 10 stores/minute per origin (P0-TENTH-2 fix)
3. **Memory bounds** - 1000 total in-memory requests, 50 per origin (P0-TENTH-3 fix)
4. **Debugger validation** - Tab ID matching, request tracking (P0-TENTH-1 fix)
5. **Response sanitization** - XSS pattern detection in responses (P0-TENTH-1 fix)
6. **Consent requirements** - User approval for active security probes
7. **Encryption** - AES-256-GCM for stored probe data

#### Active Threat Model
- **OAuth consent phishing** - Rogue apps requesting excessive scopes
- **Homograph attacks** - Unicode domain spoofing (microsоft vs microsoft)
- **CDN mismatches** - Infrastructure inconsistencies indicating compromise
- **DGA domains** - Algorithmically generated malicious domains
- **Session hijacking** - Cookie theft, replay attacks
- **Response injection** - Malicious content via debugger API
- **DoS attacks** - Storage exhaustion, memory flooding

## Development Patterns

### Code Review History
The project has undergone **10+ systematic security reviews** with findings documented in:
- THIRD-REVIEW-FIXES.md
- FOURTH-REVIEW-FIXES.md
- FIFTH-REVIEW-FINDINGS.md & FIXES-COMPLETE.md
- SIXTH-REVIEW-FINDINGS.md & FIXES-COMPLETE.md
- SEVENTH-REVIEW-FINDINGS.md & FIXES-COMPLETE.md
- EIGHTH-REVIEW-FINDINGS.md & FIXES-COMPLETE.md
- NINTH-REVIEW-FINDINGS.md & FIXES-COMPLETE.md
- TENTH-REVIEW-FINDINGS.md & PROGRESS.md

**Pattern**: Each review identifies 15-20 issues across P0-P3 severity levels, systematically addressed with inline fixes and security comments.

### Coding Standards
- **Inline security comments** - Mark all security fixes with `// P{severity}-{review}-{issue} FIX: {description}`
- **Validation-first** - Validate all inputs before processing (origin, tabId, requestId, etc.)
- **Fail-safe defaults** - Reject invalid/suspicious data rather than attempting recovery
- **Resource limits** - All unbounded structures (Maps, Sets, Arrays) must have hard caps
- **Audit logging** - Console warnings for all security boundary violations

### Testing Philosophy
- **Defensive-only scope** - This is a security research and protection tool
- **User consent required** - All active probing requires explicit opt-in
- **Privacy by default** - Local storage only, optional cloud sync with user control
- **Transparency** - Clear documentation of what data is collected and why

## Communication Style

- **Concise and direct** - No preamble/postamble unless complexity demands it
- **Evidence over opinion** - Facts, code references, CVE numbers, not speculation
- **Question assumptions** - If something seems off, say so
- **No emojis** - Professional technical communication only
- **Markdown links for code references** - Use `[filename.ts:42](src/filename.ts#L42)` format

## Data Architecture

### Current Implementation
```
Browser Extension → chrome.storage.local → Local Analysis
                 ↓ (optional)
              Cloud API → Centralized Intelligence
```

### Privacy Tiers
1. **Local-only** (default) - Maximum privacy, no external data
2. **Local + Cloud Sync** - User-controlled backend, encrypted transport
3. **Real-time Streaming** - Enterprise deployment (WebSocket → Kafka → Dashboard)

## Key References

- **Manifest**: Chrome Extension Manifest v3 with debugger + webRequest permissions
- **CSP**: Strict content security policy allowing only Cloudflare DNS & IP APIs
- **Icons**: Follow ICON_INSTRUCTIONS.md for visual assets
- **Data Persistence**: See DATA-PERSISTENCE-GUIDE.md for storage patterns

## Founder's Approach

**Henry - Founder & Ethical Hacker at Code Monkey Cybersecurity**

Values that drive development:
- **Humans first** - Security tools should empower users, not intimidate them
- **Evidence-based decisions** - Data and testing trump intuition
- **Sustainable innovation** - Build for the long term, not just MVP
- **Collaborative learning** - Every code review is a teaching moment
- **Adversarial partnership** - The best code comes from constructive conflict

---

*Last updated: October 2025*
*Review cycle: 10th systematic security assessment complete (3/4 P0 issues resolved)*
