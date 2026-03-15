---
title: OAuth2/OIDC monitoring patterns for hera
doc-type: reference
status: accepted
date: 2026-03-15
author: henry
related: [security-checks.md, test-fixtures.md, CLAUDE.md]
issue: 1
---

## Fundamental Constraint

**Hera passively monitors authentication flows — it never modifies, intercepts, or blocks requests.** All detection is read-only observation of network traffic and DOM state.

## RFC References (mandatory in findings)

All OAuth2/OIDC findings must cite the relevant RFC:

| Protocol | RFC |
|----------|-----|
| OAuth 2.0 | RFC 6749 |
| PKCE | RFC 7636 |
| JWT | RFC 7519 |
| DPoP | RFC 9449 |
| OAuth 2.0 Security BCP | RFC 9700 (BCP 225) |
| OIDC Core | OpenID Connect Core 1.0 |

## Auth Module Inventory

Located in `modules/auth/`:

| Module | Responsibility |
|--------|---------------|
| `oauth2-analyzer.js` | State entropy, grant type validation, dangerous scope detection |
| `oauth2-pkce-verifier.js` | PKCE (RFC 7636) compliance — code_challenge = BASE64URL(SHA-256(code_verifier)) |
| `oauth2-csrf-verifier.js` | CSRF state parameter validation per RFC 6749 §10.12 |
| `jwt-validator.js` | Algorithm analysis, weak algorithm detection (none, HS256 with RS key), expiry, claims |
| `oidc-validator.js` | Nonce verification, id_token validation, hybrid flow checks |
| `session-security-analyzer.js` | Session fixation, hijacking, replay attack detection |
| `refresh-token-tracker.js` | Token rotation monitoring (hashed tracking only) |
| `dpop-validator.js` | DPoP proof validation per RFC 9449 |
| `csrf-detector.js` | CSRF attack pattern detection |
| `hsts-verifier.js` | HSTS header compliance |
| `scim-analyzer.js` | SCIM provisioning vulnerability detection |
| `oauth2-flow-tracker.js` | Flow correlation and lifecycle tracking |
| `oidc-flow-detector.js` | OIDC flow variant detection (code, implicit, hybrid) |
| `auth-util-functions.js` | Shared auth utilities — **check here before reimplementing** |

## Finding Pipeline

Every security finding must pass through this pipeline in order:

1. **Detection** — auth analyzer module detects the issue
2. **Categorisation** — `auth-issue-database.js` maps to known issue type
3. **Risk scoring** — `auth-risk-scorer.js` calculates CVSS 4.0 score via `ae-cvss-calculator`; all required CVSS fields must be populated
4. **Confidence** — `confidence-scorer.js` assigns confidence; findings below threshold must not surface in UI
5. **Display** — `auth-issue-visualizer.js` renders to popup
6. **Evidence** — `auth-evidence-manager.js` persists evidence for export

### Pipeline error handling

Each stage can fail independently. Rules:

- **Detection throws**: catch at caller, log structured error, skip finding (do not crash flow)
- **CVSS fields missing**: log `WARN` with field name, surface finding with `severity: 'UNKNOWN'` rather than silently dropping
- **Confidence below threshold**: log `DEBUG` with finding type and score — not an error
- **Storage quota exceeded**: log `ERROR` with quota details, evict oldest evidence per `auth-evidence-manager.js` policy

Never let a single finding's failure crash the entire analysis. Wrap per-finding logic in `try/catch`:

```js
try {
  const finding = detector.analyze(request);
  if (finding) pipeline.push(finding);
} catch (err) {
  // Log structured, never swallow silently (OWASP A10:2025)
  console.error('[hera:detection]', { module: 'oauth2-analyzer', error: err.message, url: request?.url });
}
```

## Structured Logging

Use the `batch-logger.js` module (already wired in background.js) — never `console.log` directly in auth modules:

```js
// Good: structured, redacted, context-rich
logger.warn('[hera:pkce]', { issue: 'missing_code_challenge', flow: flowId });
logger.error('[hera:jwt]', { issue: 'weak_algorithm', alg: header.alg, url: redactedUrl });

// Bad: raw console, secrets exposed, no context
console.log('JWT error: ' + token);
```

Secret/token redaction: never log raw JWT payloads, `code_verifier`, or `access_token` values. Log hashed identifiers or the first 8 chars only.

## Token Handling

- **Never store raw tokens** — use hashed identifiers only
- Refresh token tracking uses `refresh-token-tracker.js` hashing pattern — do not replicate inline
- JWT parsing is read-only; do not reconstruct or re-sign tokens

## Execution Context Rules

| File | Context | Restrictions |
|------|---------|-------------|
| `background.js` | Service worker | No `window`, no `document`, no DOM APIs |
| `content-script.js` | ISOLATED world (page injection) | `document`/`window` are readonly; no chrome.storage direct writes |
| `popup.js` | Extension popup | Full `document`/`window` access |

Always check which context you are in before using browser globals.
