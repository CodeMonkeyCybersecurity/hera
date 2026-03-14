# Hera Auth Security Monitor

> *Like the goddess Hera, who could see through Zeus's disguises, this extension reveals the true nature of authentication requests.*

A Chrome extension for detecting authentication vulnerabilities, phishing attempts, and security misconfigurations across OAuth 2.0, OIDC, SAML, SCIM, and WebAuthn flows.

**Author:** Code Monkey Cybersecurity
**License:** Dual-licensed under AGPL v3 and Do No Harm License
**Manifest Version:** 3

## What It Does

Hera passively monitors authentication flows in your browser and flags security issues in real time. It analyses token entropy, validates PKCE compliance, checks JWT algorithms, detects session fixation patterns, and tracks refresh token rotation — all without modifying the requests themselves.

The extension is focused exclusively on authentication vulnerabilities. Non-auth detectors (phishing, dark patterns, privacy violations) exist in the codebase but are disabled by default.

## Quick Start

### Install from Source

```bash
git clone <repo-url>
cd hera
npm install
```

1. Open `chrome://extensions/` and enable Developer Mode
2. Click "Load unpacked" and select the `hera/` directory
3. The Hera icon will appear in your toolbar

### Development

```bash
npm run lint          # Run ESLint
npm run lint:fix      # Auto-fix linting issues
npm run test          # Run Vitest suite
npm run test:watch    # Watch mode
npm run test:coverage # Generate coverage report
npm run test:all      # Full CI pipeline (lint + validate + coverage)
npm run check         # Lint + validate extension structure
```

## Architecture

Hera is organised into ~94 JavaScript modules across several functional areas:

### Core Components

| Component | Description |
|-----------|-------------|
| `background.js` | Service worker — orchestrates all auth detection, manages storage and alarms |
| `content-script.js` | Injected into pages (ISOLATED world) — runs detectors on page content |
| `popup.js` / `popup.html` | Extension popup UI |
| `evidence-collector.js` | Central evidence persistence with POST body capture and auto-redaction |
| `devtools/` | Chrome DevTools panel integration |

### Module Categories

| Directory | Files | Purpose |
|-----------|-------|---------|
| `modules/auth/` | ~30 | OAuth 2.0, OIDC, JWT, PKCE, CSRF, session security, SCIM, WebAuthn analysis |
| `modules/content/` | ~8 | Page-level detection — WebAuthn interceptor, form protection, analysis runner |
| `modules/intelligence/` | 5 | ML feature extraction, domain reputation, security metrics |
| `modules/ui/` | ~15 | UI components for findings display |
| `modules/export/` | — | Export captured data (JSON, etc.) |
| `modules/security/` | — | Security-specific modules |
| `modules/utils/` | — | Shared utilities (JWT parsing, headers, strings) |

### Key Auth Modules

| Module | What It Checks |
|--------|---------------|
| `oauth2-analyzer.js` | State entropy, grant type validation, dangerous scope detection |
| `oauth2-pkce-verifier.js` | PKCE (RFC 7636) compliance — code challenge verification, replay prevention |
| `oauth2-csrf-verifier.js` | CSRF state parameter validation per RFC 6749 §10.12 |
| `jwt-validator.js` | Algorithm analysis, weak algorithm detection (none, HS256 with public key) |
| `oidc-validator.js` | Nonce verification, id_token validation, hybrid flow checks |
| `session-security-analyzer.js` | Session fixation, hijacking, and replay attack detection |
| `refresh-token-tracker.js` | Token rotation monitoring with hashed tracking |
| `scim-analyzer.js` | SCIM provisioning vulnerability detection |

### Infrastructure

| Module | Purpose |
|--------|---------|
| `storage-manager.js` | Centralized storage with schema versioning |
| `session-tracker.js` | Session lifecycle tracking |
| `message-router.js` | Message routing between extension contexts |
| `response-body-capturer.js` | HTTP response body capture with automatic token redaction |
| `dns-intelligence.js` | DGA detection, homograph analysis |

## Permissions

Hera requests the following Chrome permissions:

- `storage`, `activeTab`, `tabs` — Core extension functionality
- `webRequest`, `webRequestAuthProvider` — Monitor auth-related requests
- `debugger` — Debugger protocol for response body capture
- `scripting` — Content script injection
- `identity` — Chrome identity API access
- `downloads` — Export captured data
- `alarms`, `notifications` — Scheduled tasks and user alerts
- `management` — Extension management

Host permissions: `https://*/*` and `http://*/*` (monitors all URLs)

## Testing

**Framework:** Vitest 4.x with jsdom environment and V8 coverage

**Current coverage targets:**
- Auth modules (`modules/auth/**`): 70% lines, 69% functions, 64% branches
- Overall: 10% minimum (expanding)

**Actual coverage:** ~2.3% overall. `jwt-validator.js` and `oidc-validator.js` are at ~95%; most other modules are at 0%.

```bash
npm run test:unit         # Unit tests only
npm run test:integration  # Integration tests only
npm run test:coverage     # Full coverage report
```

### CI/CD

GitHub Actions workflow (`.github/workflows/test.yml`) runs on Node 18.x and 20.x:

1. Lint → Validate → Unit tests → Integration tests → Coverage → Codecov upload
2. Code quality: ESLint flat config + `npm audit`
3. Build: Manifest validation + extension archive

Pre-commit hooks via Husky enforce lint-staged ESLint checks.

## Evidence Collection

Hera captures authentication flow evidence with built-in privacy protections:

- POST body capture with automatic token/secret redaction
- Flow correlation tracking across requests
- IndexedDB persistence with 500KB per-request size limits
- Auto-save every 60 seconds
- Schema-versioned storage (SCHEMA_VERSION: 1)

## Project Structure

```
hera/
├── background.js              # Service worker entry point
├── content-script.js          # Content script entry point
├── popup.js / popup.html      # Extension popup
├── evidence-collector.js      # Evidence persistence
├── manifest.json              # Chrome extension manifest (MV3)
├── modules/                   # 94+ organised modules
│   ├── auth/                  # Authentication analysis (~30 files)
│   ├── content/               # Page-level detection (~8 files)
│   ├── intelligence/          # ML + reputation (5 files)
│   ├── ui/                    # UI components (~15 files)
│   ├── export/                # Data export
│   ├── security/              # Security modules
│   └── utils/                 # Shared utilities
├── tests/                     # Vitest test suite
│   ├── unit/                  # 9 unit test files
│   ├── integration/           # 2 integration suites
│   ├── mocks/                 # Test mocks
│   └── setup.js               # Test configuration
├── devtools/                  # Chrome DevTools panel
├── html/                      # UI HTML + assets
├── icons/                     # Extension icons (16, 48, 128px)
├── docs/                      # ADRs, runbooks, guides
│   ├── adr/                   # Architecture Decision Records
│   └── runbooks/              # Operational procedures
└── .github/workflows/         # CI/CD pipeline
```

## Documentation

| Document | Purpose |
|----------|---------|
| `docs/README.md` | Extension usage guide |
| `ADVERSARIAL_ANALYSIS.md` | Security assessment and coverage gaps |
| `P0_FIX_SUMMARY.md` | Critical bug fix history |
| `ACTION_PLAN.md` | Development priorities |
| `ROADMAP.md` | Feature roadmap |
| `TESTING.md` | Testing strategy |
| `DATA-PERSISTENCE-GUIDE.md` | Storage architecture |
| `docs/adr/` | Architecture Decision Records |
| `docs/runbooks/` | Operational procedures |

## Dependencies

**Runtime:** `ae-cvss-calculator` (CVSS scoring)

**Dev:** Vitest 4.x, ESLint (flat config), Husky, lint-staged, jsdom, happy-dom

**Node requirement:** >= 18.0.0

## License

Dual-licensed:

1. **GNU Affero General Public License (AGPL) v3** — see `LICENSE.agpl`
2. **Do No Harm License** — see `LICENSE.dnh`

Choose either license; honour the spirit of both.

## Part of the Cybermonkey Platform

Hera is one component of the Cybermonkey ethical technology platform. Related projects:

- **Contracts** — Canonical interface contracts for all services
- **Hecate** — Authentication gateway (Caddy + Authentik)
- **Moni** — Core platform and API
- **Eos** — Infrastructure CLI
- **Artemis** — Bug bounty automation
