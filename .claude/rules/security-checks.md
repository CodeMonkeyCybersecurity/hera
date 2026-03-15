---
title: Security scanning patterns and code quality gates for hera
doc-type: reference
status: accepted
date: 2026-03-15
author: henry
related: [oauth-oidc.md, test-fixtures.md, CLAUDE.md]
issue: 1
---

## Linting (ESLint)

- Config: `.eslintrc.*` files (legacy config mode — `ESLINT_USE_FLAT_CONFIG=false` set in all npm scripts)
- **Note**: `eslint.config.mjs` exists but flat-config migration is incomplete (`fix/eslint-flat-config` branch). Do not switch until that PR merges.
- Run before committing: `npm run lint`; auto-fix: `npm run lint:fix`
- Pre-commit hook (Husky + lint-staged) runs ESLint --fix on staged files — **do not bypass with `--no-verify`**

### Security-critical rules (violations block commit)

| Rule | Reason |
|------|--------|
| `no-eval` | Arbitrary code execution |
| `no-new-func` | `Function()` constructor equivalent to eval |
| `no-script-url` | `javascript:` URL injection |

### Unused variable convention

ESLint enforces `no-unused-vars`. Intentionally unused function parameters MUST be prefixed with `_`:

```js
// Stub with planned-but-not-yet-implemented params
verifyHS256(_jwt, _secret) { return false; }

// Interface-mandated param not used in this implementation
_generateRecommendation(riskScore, _issues) { ... }
```

Never suppress warnings by disabling the rule. Fix them.

### Context-aware rules

| File | Restrictions |
|------|-------------|
| `background.js` (service worker) | `window` and `document` are not available — ESLint will flag accidental references |
| `content-script.js` | `document`/`window` are readonly — do not assign to them |
| `popup.js` / UI files | Full `document`/`window` access permitted |
| `tests/**` | Vitest/jest globals enabled; standard browser restrictions relaxed |

## Dependency Security

- `npm audit` runs in CI — do not add packages with known high/critical CVEs
- Pin exact versions for security-sensitive packages (`ae-cvss-calculator`)
- Review `package.json` changes for supply-chain risk before committing

## Token and Data Handling

- **Never store raw tokens** — use hashed identifiers; see `refresh-token-tracker.js` for the pattern
- All user-facing security findings must go through `auth-risk-scorer.js` — no hardcoded severity strings ("high", "critical") in UI code
- CVSS 4.0 scoring via `ae-cvss-calculator` — populate all required vector components

## Extension Permissions

- `manifest.json` permissions must follow **least-privilege** — do not add broad host permissions (`<all_urls>`) without explicit justification
- After adding/removing permissions, run `npm run validate` to verify extension structure integrity
- Host permission changes require a `docs/adr/` entry explaining the need

## Coverage as a Security Gate

Coverage thresholds are defined in `vitest.config.js` (single source of truth — do not duplicate here). Summary:

- **95%+** for `auth-issue-database.js`, `auth-util-functions.js`, `oauth2-analyzer.js` (security-critical)
- **30%** minimum for all other `modules/auth/**` files (ratchet strategy — raise as tests are added)
- **8%** global minimum (most non-auth modules are untested — tracked as P2)

Do not lower thresholds to make tests pass. Raise them when new tests increase coverage.

## CI Quality Gates

```
npm run lint       → ESLint full codebase (must pass, zero warnings in auth modules)
npm run validate   → Extension structure validation (must pass)
npm run test:coverage → Coverage with vitest.config.js thresholds (must meet minimums)
npm run ci         → Runs all three gates above (use this before opening a PR)
npm run test:summary → Compact test output for agent sessions (governance rule 59)
```

Run `npm run ci` before opening a PR. GitHub Actions enforces these on push.

## Error Handling Standards (OWASP A10:2025)

All code in `modules/auth/**` must follow structured error handling:

- **No silent failures**: every `catch` block must log or propagate — never `catch (e) {}`
- **No secrets in error messages**: redact tokens, keys, and passwords before logging
- **Graceful degradation**: a single finding failure must not crash the analysis loop
- **Structured errors**: use object context in log calls, not string concatenation

```js
// Good
try {
  const result = await analyzeFlow(request);
} catch (err) {
  console.error('[hera:analyzer]', { error: err.message, flow: flowId });
  // continue — don't re-throw unless unrecoverable
}

// Bad
try {
  analyzeFlow(request);
} catch (e) {} // silent swallow — OWASP A10 violation
```
