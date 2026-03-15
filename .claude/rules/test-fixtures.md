---
title: Test fixture management, mocking patterns, and coverage requirements for hera
doc-type: reference
status: accepted
date: 2026-03-15
author: henry
related: [oauth-oidc.md, security-checks.md, CLAUDE.md]
issue: 1
---

## Testing Stack

- **Framework**: Vitest (see `package.json` for pinned version) — import from `vitest`, not `jest`
- **Environment**: jsdom (not happy-dom — required for Chrome extension compatibility)
- **Coverage**: V8 provider (`--coverage.provider=v8`) — do not switch to Istanbul
- **Runner**: `npm test` (full suite), `npm run test:unit` (unit only, pre-commit), `npm run test:summary` (compact output for agent sessions)

## Chrome API Mocking

- **Always import `tests/mocks/chrome.js`** in any test that touches extension APIs (storage, runtime, tabs, webRequest, alarms)
- Do not re-mock `chrome.*` APIs inline — the shared mock maintains consistent behaviour across tests
- The mock is initialised in `tests/setup.js` (Vitest `setupFiles`) — it runs before every test file

## Test Helpers and Fixtures

- **`tests/utils/test-helpers.js`** — use factory functions from here; do not hand-craft raw JWT strings or flow objects
  - `createMockJWT(claims, options)` — generates test JWTs with controlled headers/claims
  - Other helpers: mock OAuth2 flow creators, PKCE pair generators, etc.
- For integration tests requiring correlated flows, build on `tests/integration/evidence-collection.test.js` patterns

## Test Naming Convention

```
test_<what>_<condition>_<expected>
```

Examples:
- `test_jwtValidator_expiredToken_returnsHighSeverityFinding`
- `test_pkceVerifier_missingChallenge_flagsViolation`
- Regression tests: `test_issue_42_regression_sessionFixationFalsePositive`

## Setup / Teardown Pattern

```js
beforeEach(() => {
  vi.clearAllMocks();        // reset call counts and return values
});

afterEach(() => {
  vi.restoreAllMocks();      // restore any spied-on originals
});
```

## Coverage Thresholds

Thresholds are defined and enforced in `vitest.config.js` — that file is the single source of truth. Do not duplicate threshold values here; they will drift.

Current state (as of 2026-03-15, branch `fix/1`):
- `auth-issue-database.js`, `auth-util-functions.js`, `oauth2-analyzer.js`: **95%+** (security-critical, ratchet in place)
- Other `modules/auth/**`: **30%** minimum (16 of 25 auth files still at 0% — P2 follow-up)
- Global: **8%** (most non-auth modules untested — P2, not a target state)

When you add tests that increase coverage above the current threshold, update `vitest.config.js` thresholds to lock in the gain (ratchet strategy).

## Anti-patterns to Avoid

- No `console.log` wrappers in test code — anti-pattern per UNIX Rule #8
  - To assert on console output: `vi.spyOn(console, 'error')` then assert on the spy
- Do not stub `chrome.*` inline — use the shared mock
- Do not write raw fixture strings (JWTs, OAuth codes) — use factory functions from `test-helpers.js`
- Do not use `setTimeout`/`setInterval` directly in tests — use `vi.useFakeTimers()`

## Integration vs Unit Tests

- **Unit tests** (`tests/unit/`) — isolate a single module; mock all dependencies
- **Integration tests** (`tests/integration/`) — use real Chrome mock; test multi-module flows (e.g., flow-tracker + evidence-collection)
- Prefer integration tests when testing OAuth2 flow correlation across multiple auth modules

## Token Output for Agent Sessions

Use `npm run test:summary` (compact dot reporter) for agent sessions — never read full verbose test output when all tests pass. Only read failure output (governance rule 59).
