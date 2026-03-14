# Hera

Chrome extension for authentication security testing and vulnerability detection.

## Dev environment

- Language: JavaScript (ES Modules)
- Runtime: Chrome Extension (Manifest V3)
- Testing: Vitest 4.x with jsdom
- Linting: ESLint (flat config)
- Node: >= 18.0.0

## Build and test

```bash
npm run lint            # ESLint
npm run lint:fix        # Auto-fix linting issues
npm run check           # Lint + validate extension structure
npm run test            # Run Vitest suite
npm run test:unit       # Unit tests only
npm run test:integration # Integration tests only
npm run test:coverage   # Coverage report (V8)
npm run test:all        # Full CI pipeline (check + coverage)
```

## Code style

- ES Modules throughout (no CommonJS)
- Chrome Extension Manifest V3 APIs only
- Conventional Commits: `<type>(<scope>): <description>`
- Branch naming: `<type>/<issue-number>-<slug>`

## Testing

- Coverage targets for auth modules: 70% lines, 69% functions, 64% branches
- Overall minimum: 10% (expanding towards 80%)
- Every code change MUST include tests for the changed behaviour
- Coverage must not decrease on any PR

## Architecture rules

- Modules are organised by function under `modules/`
- `background.js` is the service worker — orchestration only
- `evidence-collector.js` handles all persistence
- Token/secret data MUST be redacted before storage
- Auth-focused only: non-auth detectors remain disabled unless explicitly enabled

## PR guidelines

- Link every PR to an issue
- Max ~400 lines changed per PR
- Signed commits required
- Linear history only

## Security

- Secrets never hardcoded or committed
- All captured auth data auto-redacted (tokens, passwords, secrets)
- CSP enforced: no inline scripts
- Extension permissions are the minimum required set

## Multi-agent coordination

- One agent per issue, one branch per issue
- Push branch to origin within 1 hour

## Directory-specific notes

| Directory | What it contains |
|-----------|-----------------|
| `modules/auth/` | OAuth2, OIDC, JWT, PKCE, CSRF, session, SCIM, WebAuthn analysers |
| `modules/content/` | Content scripts — WebAuthn interceptor runs in MAIN world |
| `modules/intelligence/` | ML features, domain reputation, security metrics |
| `modules/ui/` | Popup and DevTools panel UI components |
| `tests/unit/` | Vitest unit tests |
| `tests/integration/` | Integration test suites |
