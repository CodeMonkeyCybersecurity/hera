# HERA TESTING - ACTION PLAN
## Comprehensive Remediation & Prevention Strategy

**Date**: 2025-11-06
**Status**: Testing infrastructure at 2.3% coverage (CRITICAL RISK)
**Goal**: Achieve 70% coverage with security-first approach within 8 weeks

---

## Executive Summary

### Current State Assessment

**Critical Findings**:
- ✅ **Good**: 84 tests passing (JWT + OIDC validators well-tested)
- ❌ **Critical**: 11 security modules (PKCE, CSRF, session security) untested
- ❌ **High Risk**: 2.3% overall coverage vs. 80% industry standard
- ❌ **CI/CD Gaps**: Security gates disabled, failures allowed
- ❌ **Process Gaps**: No systematic test generation, manual effort only

**Risk Assessment**:
```
Current Risk Level: 🔴 CRITICAL

Attack Vectors Without Detection:
- Authorization code interception (PKCE)
- Cross-site request forgery (CSRF)
- Session hijacking (cookie security)
- Token leakage in exports (redaction)

Estimated Breach Probability: HIGH
Time to Production Bug: < 1 week (historical data)
```

**Required Investment**:
```
Time: 8 weeks (1-2 developers)
Phases: 6
Priority: P0 (Security critical)
Budget: Dev time only (no additional tooling costs)
```

---

## What Remains To Be Done

### Phase 1: Immediate Critical Fixes (Week 1)

**Status**: 🔴 NOT STARTED

**Objectives**:
1. Prevent further regression
2. Fix CI/CD security gates
3. Block untested code from merging

**Tasks**:

#### Task 1.1: Fix CI/CD Security Gates (4 hours)

**Files to Modify**:
- `.github/workflows/test.yml`
- `.github/workflows/security.yml`

**Changes Required**:

**File**: `.github/workflows/test.yml`
```yaml
# Line 45-52: BEFORE
- name: Upload coverage to Codecov
  uses: codecov/codecov-action@v4
  with:
    fail_ci_if_error: false  # ❌ REMOVE THIS

# AFTER
- name: Upload coverage to Codecov
  uses: codecov/codecov-action@v4
  with:
    fail_ci_if_error: true   # ✅ Block on failure

- name: Enforce coverage thresholds
  run: |
    npm run test:coverage
    if [ $? -ne 0 ]; then
      echo "❌ Coverage thresholds not met"
      exit 1
    fi
```

**File**: `.github/workflows/security.yml`
```yaml
# Line 28-40: BEFORE
- name: Run npm audit
  run: npm audit --audit-level=moderate
  continue-on-error: true  # ❌ REMOVE THIS

# AFTER
- name: Run npm audit (BLOCKING)
  run: npm audit --audit-level=moderate
  # No continue-on-error = failures block CI

- name: Report vulnerabilities
  if: failure()
  run: |
    echo "❌ Security vulnerabilities detected"
    npm audit --json > audit-report.json
    cat audit-report.json
    exit 1
```

**Verification**:
```bash
# Create PR to test
git checkout -b ci/enforce-security-gates
# Make changes above
git commit -m "ci: enforce security gates - block on coverage/vulnerability failures"
git push

# Verify CI blocks merge:
# 1. CI should fail if coverage < threshold
# 2. CI should fail if npm audit finds vulnerabilities
# 3. Cannot merge until fixed
```

**Acceptance Criteria**:
- [ ] CI fails when coverage decreases
- [ ] CI fails when vulnerabilities detected
- [ ] PR cannot merge while CI failing
- [ ] Team notified of process change

**Time**: 4 hours
**Owner**: [DevOps Lead]
**Due**: 2025-11-08 (Friday EOD)

---

#### Task 1.2: Update Coverage Thresholds (1 hour)

**File**: `vitest.config.js`

**Change**:
```javascript
// Lines 31-40: BEFORE
thresholds: {
  lines: 5,      // ❌ Too low
  functions: 5,
  branches: 5,
  statements: 5
},

// AFTER (Realistic but strict)
thresholds: {
  lines: 60,     // ✅ Industry minimum for security code
  functions: 60,
  branches: 50,
  statements: 60
},

// Per-file thresholds for critical modules
perFile: {
  'modules/auth/**/*.js': {
    lines: 80,
    functions: 80,
    branches: 75,
    statements: 80
  },
  'modules/security/**/*.js': {
    lines: 80,
    functions: 80,
    branches: 75,
    statements: 80
  }
}
```

**Note**: This will cause CI to fail immediately (current coverage 2.3%). This is intentional - forces immediate action on critical tests.

**Acceptance Criteria**:
- [ ] Coverage thresholds updated
- [ ] CI fails (expected) showing gap
- [ ] Team aware of temporary CI failure
- [ ] Plan communicated for fixing

**Time**: 1 hour
**Owner**: [Tech Lead]
**Due**: 2025-11-08 (Friday EOD)

---

#### Task 1.3: Configure Branch Protection (30 minutes)

**GitHub Repository Settings**:

**Navigation**: Settings → Branches → Branch protection rules → Add rule

**Configuration**:
```
Branch name pattern: main

☑ Require a pull request before merging
  ☑ Require approvals: 1
  ☑ Dismiss stale pull request approvals when new commits are pushed

☑ Require status checks to pass before merging
  ☑ Require branches to be up to date before merging
  Status checks required:
    - test / test (Node 20)
    - code-quality / code-quality
    - security-gate (add this check to workflow)

☑ Require conversation resolution before merging

☑ Require signed commits (optional but recommended)

☑ Require linear history (optional - cleaner git log)

☑ Do not allow bypassing the above settings
  (includes administrators)
```

**Create Security Gate Job** (add to `.github/workflows/test.yml`):
```yaml
security-gate:
  name: Security Gate
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4

    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: 20

    - name: Install dependencies
      run: npm ci

    - name: Security checks
      run: |
        # Fail if any check fails
        set -e

        echo "🔒 Running security gate..."

        # 1. Dependency vulnerabilities
        npm audit --audit-level=moderate

        # 2. Code security patterns
        npm run lint:security

        # 3. Coverage enforcement
        npm run test:coverage

        echo "✅ Security gate passed"
```

**Acceptance Criteria**:
- [ ] Branch protection active on main
- [ ] Cannot merge without approval
- [ ] Cannot merge with failing CI
- [ ] Cannot bypass (even admins)

**Time**: 30 minutes
**Owner**: [Tech Lead or DevOps]
**Due**: 2025-11-08 (Friday EOD)

---

#### Task 1.4: Install Pre-Commit Hooks (2 hours)

**Prevent untested code from being committed**

**Installation**:
```bash
npm install --save-dev husky lint-staged
npx husky install
npm set-script prepare "husky install"
```

**Create Hook**: `.husky/pre-commit`
```bash
#!/usr/bin/env sh
. "$(dirname -- "$0")/_/husky.sh"

echo "🔍 Running pre-commit checks..."

# 1. Lint staged files
npx lint-staged

# 2. Test changed files
echo "🧪 Testing changed files..."
npm run test:changed || {
  echo "❌ Tests failed for changed files"
  echo "💡 Fix tests before committing"
  exit 1
}

# 3. Coverage delta check
echo "📊 Checking coverage delta..."
npm run test:coverage-delta || {
  echo "❌ Coverage decreased (not allowed)"
  echo "💡 Add tests to restore coverage"
  exit 1
}

echo "✅ Pre-commit checks passed"
```

**Configuration**: `package.json`
```json
{
  "lint-staged": {
    "*.js": [
      "eslint --fix",
      "prettier --write"
    ],
    "modules/**/*.js": [
      "bash -c 'npm run test:related -- --run'"
    ]
  },
  "scripts": {
    "test:changed": "vitest related --run",
    "test:coverage-delta": "vitest --coverage --changed --reporter=json > coverage-new.json && node scripts/check-coverage-delta.js",
    "test:related": "vitest related"
  }
}
```

**Create Script**: `scripts/check-coverage-delta.js`
```javascript
#!/usr/bin/env node
const fs = require('fs');

// Read current coverage
const newCoverage = JSON.parse(fs.readFileSync('coverage-new.json'));

// Read baseline (from last commit)
let oldCoverage = { coverage: 2.3 };
try {
  oldCoverage = JSON.parse(fs.readFileSync('coverage-baseline.json'));
} catch (e) {
  console.log('No baseline found, creating...');
}

const delta = newCoverage.coverage - oldCoverage.coverage;

if (delta < 0) {
  console.error(`❌ Coverage decreased: ${oldCoverage.coverage}% → ${newCoverage.coverage}% (${delta.toFixed(2)}%)`);
  process.exit(1);
}

console.log(`✅ Coverage OK: ${oldCoverage.coverage}% → ${newCoverage.coverage}% (+${delta.toFixed(2)}%)`);

// Update baseline
fs.writeFileSync('coverage-baseline.json', JSON.stringify(newCoverage));
```

**Acceptance Criteria**:
- [ ] Pre-commit hook installed
- [ ] Blocks commits with failing tests
- [ ] Blocks commits that decrease coverage
- [ ] Team trained on workflow
- [ ] Documentation updated (CONTRIBUTING.md)

**Time**: 2 hours (including testing and docs)
**Owner**: [Developer 1]
**Due**: 2025-11-09 (Monday EOD)

---

### Phase 2: Critical Security Tests (Week 2-3)

**Status**: 🔴 NOT STARTED

**Objective**: Test Tier 1 critical security modules

**Priority Order** (by risk):
1. PKCE Validator (authorization code interception)
2. CSRF Verifier (cross-site request forgery)
3. Session Security (session hijacking)
4. Token Redactor (sensitive data leakage)

---

#### Task 2.1: PKCE Validator Tests (3 days)

**File to Create**: `tests/unit/oauth2-pkce-verifier.test.js`

**Source**: `modules/auth/oauth2-pkce-verifier.js` (169 LOC, 0% coverage)

**Test Requirements** (12 tests minimum):

**Security Attack Vectors**:
```javascript
describe('PKCE Validator - RFC 7636 Compliance', () => {
  // 1. Missing code_challenge detection
  it('should reject authorization without code_challenge', () => {
    const url = 'https://auth.example.com/authorize?client_id=abc';
    const result = validator.verifyPKCE(url);
    expect(result.issues).toContainEqual({
      type: 'MISSING_CODE_CHALLENGE',
      severity: 'CRITICAL',
      cvss: 9.1
    });
  });

  // 2. Weak method detection (plain not allowed per RFC 7636 §4.2)
  it('should reject plain code_challenge_method', () => {
    const url = 'https://auth.example.com/authorize?code_challenge=abc&code_challenge_method=plain';
    const result = validator.verifyPKCE(url);
    expect(result.issues).toContainEqual({
      type: 'WEAK_PKCE_METHOD',
      severity: 'HIGH',
      message: 'plain method is insecure per RFC 7636 §4.2'
    });
  });

  // 3. Entropy validation (must be >= 128 bits per RFC 7636 §4.1)
  it('should validate code_challenge entropy >= 128 bits', () => {
    const weakChallenge = 'abc123'; // < 128 bits
    const url = `https://auth.example.com/authorize?code_challenge=${weakChallenge}&code_challenge_method=S256`;
    const result = validator.verifyPKCE(url);
    expect(result.issues).toContainEqual({
      type: 'INSUFFICIENT_ENTROPY',
      severity: 'HIGH'
    });
  });

  // 4. Challenge/verifier mismatch
  it('should detect code_challenge mismatch', async () => {
    const challenge = 'correct-challenge';
    const wrongVerifier = 'wrong-verifier';

    const result = await validator.validateVerifier(challenge, wrongVerifier);
    expect(result.valid).toBe(false);
    expect(result.error).toBe('CODE_VERIFIER_MISMATCH');
  });
});

describe('Error Handling', () => {
  // 5. Null URL
  it('should handle null URL gracefully', () => {
    expect(() => validator.verifyPKCE(null)).not.toThrow();
    const result = validator.verifyPKCE(null);
    expect(result.valid).toBe(false);
  });

  // 6. Malformed URL
  it('should handle invalid URL format', () => {
    const result = validator.verifyPKCE('not-a-url');
    expect(result.valid).toBe(false);
    expect(result.error).toContain('INVALID_URL');
  });

  // 7. Missing parameters object
  it('should handle missing URL parameters', () => {
    const url = 'https://auth.example.com/authorize';
    const result = validator.verifyPKCE(url);
    expect(result.valid).toBe(false);
  });
});

describe('Edge Cases', () => {
  // 8. Maximum length challenge (128 chars per RFC)
  it('should accept maximum length challenge', () => {
    const maxChallenge = 'A'.repeat(128);
    const url = `https://auth.example.com/authorize?code_challenge=${maxChallenge}&code_challenge_method=S256`;
    const result = validator.verifyPKCE(url);
    expect(result.valid).toBe(true);
  });

  // 9. DoS protection (extremely long challenge)
  it('should reject extremely long challenge (DoS)', () => {
    const longChallenge = 'A'.repeat(1000000); // 1MB
    const url = `https://auth.example.com/authorize?code_challenge=${longChallenge}`;

    const startTime = Date.now();
    const result = validator.verifyPKCE(url);
    const duration = Date.now() - startTime;

    expect(duration).toBeLessThan(5000); // Should complete in <5s
    expect(result.issues).toContainEqual({
      type: 'CHALLENGE_TOO_LONG',
      severity: 'MEDIUM'
    });
  });

  // 10. Base64url encoding variations
  it('should accept valid base64url encoding', () => {
    const validChallenge = 'abc123-_'; // Valid base64url chars
    const url = `https://auth.example.com/authorize?code_challenge=${validChallenge}&code_challenge_method=S256`;
    const result = validator.verifyPKCE(url);
    expect(result.valid).toBe(true);
  });

  // 11. Invalid base64url characters
  it('should reject invalid base64url encoding', () => {
    const invalidChallenge = 'abc123+/='; // + / = not allowed in base64url
    const url = `https://auth.example.com/authorize?code_challenge=${invalidChallenge}`;
    const result = validator.verifyPKCE(url);
    expect(result.issues).toContainEqual({
      type: 'INVALID_BASE64URL',
      severity: 'MEDIUM'
    });
  });

  // 12. Code reuse detection (replay attack)
  it('should detect authorization code reuse', () => {
    const code = 'auth-code-123';
    validator.markCodeUsed(code);

    const result = validator.checkCodeReuse(code);
    expect(result.issues).toContainEqual({
      type: 'CODE_REUSE_DETECTED',
      severity: 'CRITICAL'
    });
  });
});
```

**Test Scaffolding** (use this pattern):
```bash
# Generate initial scaffold
cat > tests/unit/oauth2-pkce-verifier.test.js <<'EOF'
import { describe, it, expect, beforeEach } from 'vitest';
import { OAuth2PKCEVerifier } from '../../modules/auth/oauth2-pkce-verifier.js';

describe('OAuth2PKCEVerifier', () => {
  let validator;

  beforeEach(() => {
    validator = new OAuth2PKCEVerifier();
  });

  // [Add 12 tests above]
});
EOF

# Run tests
npm test tests/unit/oauth2-pkce-verifier.test.js

# Check coverage
npm run test:coverage -- tests/unit/oauth2-pkce-verifier.test.js

# Target: 90% coverage
```

**Acceptance Criteria**:
- [ ] 12 tests implemented and passing
- [ ] Coverage >= 90% for oauth2-pkce-verifier.js
- [ ] All attack vectors tested
- [ ] Error handling comprehensive
- [ ] Code review approved
- [ ] Merged to main

**Time**: 3 days (2 days dev + 1 day review)
**Owner**: [Developer 1 + Security Lead (pair)]
**Due**: 2025-11-13 (Wednesday)

---

#### Task 2.2: CSRF Verifier Tests (3 days)

**File to Create**: `tests/unit/oauth2-csrf-verifier.test.js`

**Source**: `modules/auth/oauth2-csrf-verifier.js` (343 LOC, 0% coverage)

**Test Requirements** (15 tests minimum):

**Focus Areas**:
1. Missing state parameter detection
2. State entropy validation (>= 128 bits)
3. State replay detection (one-time use)
4. State parameter tampering
5. Timing attack resistance
6. Error handling (null, malformed)

**Similar pattern to PKCE tests** (see Task 2.1 for structure)

**Acceptance Criteria**:
- [ ] 15 tests implemented and passing
- [ ] Coverage >= 90% for oauth2-csrf-verifier.js
- [ ] CSRF attack scenarios tested
- [ ] Replay attacks tested
- [ ] Code review approved

**Time**: 3 days
**Owner**: [Developer 2 + Security Lead (pair)]
**Due**: 2025-11-16 (Saturday) - or Nov 18 if weekend excluded

---

#### Task 2.3: Session Security Analyzer Tests (4 days)

**File to Create**: `tests/unit/session-security-analyzer.test.js`

**Source**: `modules/auth/session-security-analyzer.js` (652 LOC, 0% coverage)

**Test Requirements** (18 tests minimum):

**Focus Areas** (per OWASP ASVS 3.0):
```javascript
describe('Session Security Analyzer - Cookie Security', () => {
  // ASVS V3.4.1: Secure flag on HTTPS
  it('should require Secure flag on HTTPS cookies', () => {
    const cookie = { name: 'session', value: 'abc', secure: false };
    const url = 'https://example.com';

    const result = analyzer.analyzeCookie(cookie, url);

    expect(result.issues).toContainEqual({
      type: 'MISSING_SECURE_FLAG',
      severity: 'HIGH',
      cvss: 8.1,
      asvs: '3.4.1'
    });
  });

  // ASVS V3.4.2: HttpOnly flag (XSS protection)
  it('should require HttpOnly flag', () => {
    const cookie = { name: 'session', value: 'abc', httpOnly: false };

    const result = analyzer.analyzeCookie(cookie);

    expect(result.issues).toContainEqual({
      type: 'MISSING_HTTPONLY_FLAG',
      severity: 'CRITICAL',
      cvss: 9.1,
      attack: 'XSS can steal cookie via document.cookie',
      asvs: '3.4.2'
    });
  });

  // ASVS V3.4.3: SameSite attribute
  it('should require SameSite attribute', () => {
    const cookie = { name: 'session', value: 'abc' }; // No sameSite

    const result = analyzer.analyzeCookie(cookie);

    expect(result.issues).toContainEqual({
      type: 'MISSING_SAMESITE',
      severity: 'HIGH',
      recommendation: 'Set SameSite=Strict or SameSite=Lax',
      asvs: '3.4.3'
    });
  });

  // Additional tests: domain binding, path restriction, expiration, etc.
});

describe('Session Hijacking Scenarios', () => {
  it('should detect session fixation vulnerability', () => {
    // Test implementation
  });

  it('should detect concurrent session abuse', () => {
    // Test implementation
  });
});
```

**Acceptance Criteria**:
- [ ] 18 tests implemented and passing
- [ ] Coverage >= 85% for session-security-analyzer.js
- [ ] OWASP ASVS 3.x requirements tested
- [ ] Session hijacking scenarios covered
- [ ] Code review approved

**Time**: 4 days (complex module)
**Owner**: [Developer 3 + Security Lead (pair)]
**Due**: 2025-11-20 (Thursday)

---

#### Task 2.4: Token Redactor Tests (3 days)

**File to Create**: `tests/unit/token-redactor.test.js`

**Source**: `modules/auth/token-redactor.js` (348 LOC, 0% coverage)

**Test Requirements** (20 tests minimum):

**Critical Test**: Ensure tokens don't leak in exports

```javascript
describe('Token Redactor - Sensitive Data Protection', () => {
  // High-risk patterns (full redaction)
  it('should fully redact client_secret', () => {
    const data = { client_secret: 'super-secret-key-123' };
    const redacted = redactor.redact(data);
    expect(redacted.client_secret).toBe('[REDACTED]');
  });

  it('should fully redact refresh_token', () => {
    const data = { refresh_token: 'rt-long-lived-token-abc' };
    const redacted = redactor.redact(data);
    expect(redacted.refresh_token).toBe('[REDACTED]');
  });

  // Medium-risk patterns (partial redaction)
  it('should partially redact access_token', () => {
    const data = { access_token: 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...' };
    const redacted = redactor.redact(data);
    expect(redacted.access_token).toMatch(/^eyJh\.\.\.\[REDACTED\]$/);
  });

  // Nested structures
  it('should redact tokens in nested objects', () => {
    const data = {
      oauth: {
        tokens: {
          access_token: 'secret',
          refresh_token: 'secret'
        }
      }
    };
    const redacted = redactor.redact(data);
    expect(redacted.oauth.tokens.refresh_token).toBe('[REDACTED]');
  });

  // Arrays
  it('should redact tokens in arrays', () => {
    const data = {
      tokens: [
        { type: 'access', value: 'secret1' },
        { type: 'refresh', value: 'secret2' }
      ]
    };
    const redacted = redactor.redact(data);
    expect(redacted.tokens[1].value).toBe('[REDACTED]');
  });

  // Edge cases
  it('should handle null values', () => {
    const data = { client_secret: null };
    expect(() => redactor.redact(data)).not.toThrow();
  });

  it('should handle undefined values', () => {
    const data = { client_secret: undefined };
    expect(() => redactor.redact(data)).not.toThrow();
  });
});
```

**Acceptance Criteria**:
- [ ] 20 tests implemented and passing
- [ ] Coverage >= 95% for token-redactor.js (critical for data leakage)
- [ ] All sensitive patterns tested
- [ ] Nested and array structures tested
- [ ] No tokens leak in test output
- [ ] Code review approved

**Time**: 3 days
**Owner**: [Developer 1]
**Due**: 2025-11-23 (Sunday) - or Nov 25 if weekend excluded

---

### Phase 3: CI/CD Hardening (Week 3)

**Run in parallel with Phase 2**

**Objective**: Harden GitHub Actions workflows

---

#### Task 3.1: Pin Actions to Commit SHAs (2 hours)

**Security Risk**: GitHub Actions using tags can be compromised if repository taken over

**Fix**: Pin to immutable commit SHAs

**Tool**: https://app.stepsecurity.io/secureworkflow

**Example**:
```yaml
# BEFORE (vulnerable)
- uses: actions/checkout@v4
- uses: actions/setup-node@v4

# AFTER (hardened)
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
- uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8 # v4.0.2
```

**Process**:
```bash
# 1. Go to https://app.stepsecurity.io/secureworkflow
# 2. Upload .github/workflows/test.yml
# 3. Download secured version
# 4. Replace file
# 5. Commit: "ci: pin actions to commit SHAs for security"
```

**Files to Update**:
- `.github/workflows/test.yml`
- `.github/workflows/security.yml`

**Acceptance Criteria**:
- [ ] All actions pinned to SHAs
- [ ] Comments show version for readability
- [ ] Workflows still pass
- [ ] Dependabot configured to update pins

**Time**: 2 hours
**Owner**: [DevOps Lead]
**Due**: 2025-11-15 (Friday)

---

#### Task 3.2: Add SBOM Generation (3 hours)

**Purpose**: Track all dependencies for supply chain security

**Implementation**:

Add to `.github/workflows/security.yml`:
```yaml
- name: Generate SBOM
  run: |
    npm install -g @cyclonedx/cyclonedx-npm
    cyclonedx-npm --output-file sbom.json

- name: Upload SBOM
  uses: actions/upload-artifact@v4
  with:
    name: sbom-${{ github.sha }}
    path: sbom.json
    retention-days: 90

- name: Scan SBOM for vulnerabilities
  uses: anchore/scan-action@v3
  with:
    sbom: sbom.json
    fail-build: true
    severity-cutoff: high
```

**Acceptance Criteria**:
- [ ] SBOM generated on every build
- [ ] SBOM uploaded as artifact
- [ ] Vulnerability scanning enabled
- [ ] High-severity vulnerabilities block CI

**Time**: 3 hours
**Owner**: [DevOps Lead]
**Due**: 2025-11-16 (Saturday)

---

### Phase 4: Remaining Security Tests (Week 4-5)

**Status**: 🟡 PLANNED

**Objective**: Complete Tier 2 security module tests

**Modules**:
1. HSTS Verifier (10 tests)
2. DPoP Validator (14 tests)
3. Token Response Capturer (15 tests)

**Pattern**: Similar to Phase 2, pair programming with security lead

**Time**: 2 weeks
**Coverage Increase**: ~40% → ~60%

---

### Phase 5: Detection Modules (Week 6-7)

**Status**: 🟡 PLANNED

**Objective**: Test phishing, dark pattern, privacy detectors

**Modules**:
1. Phishing Detector
2. Dark Pattern Detector
3. Privacy Violation Detector

**Time**: 2 weeks
**Coverage Increase**: ~60% → ~70%

---

### Phase 6: Reach Target Coverage (Week 8)

**Status**: 🟡 PLANNED

**Objective**: Final push to 70% overall, 85% security modules

**Activities**:
1. Identify remaining gaps (coverage report analysis)
2. Write missing tests (prioritized by risk)
3. Refactor for testability (dependency injection)
4. Performance optimization (test suite < 60s)

**Time**: 1 week
**Final Coverage**: >= 70% overall

---

## Automation & Tooling

### EOS CLI Tool Implementation

**Priority**: Start in Week 2 (parallel with Phase 2)

**Initial Commands to Build**:
1. `eos test scaffold` - Auto-generate test scaffolds
2. `eos test missing` - Identify untested functions
3. `eos doctor` - Diagnose issues

**Implementation Plan**:
```
Week 2: Core framework + scaffold command
Week 3: Missing detection + doctor command
Week 4: Integration + CI/CD commands
Week 5: Polish + documentation
Week 6: Advanced features (AI completion)
```

**Benefits**:
- Prevents future test gaps
- Automates repetitive work
- Enforces best practices
- Reduces manual effort by 80%

---

## Metrics & Success Criteria

### Weekly Metrics

**Track Every Monday**:
```javascript
{
  "coverage": {
    "overall": "??%",
    "delta_week": "±?%",
    "auth_modules": "??%",
    "target": "70%"
  },
  "tests": {
    "total": ??,
    "added_week": ??,
    "passing": ??,
    "flaky": ??
  },
  "security": {
    "modules_tested": "?/11",
    "vulnerabilities": ?,
    "sbom_generated": true/false
  },
  "ci_health": {
    "blocking_on_coverage": true/false,
    "blocking_on_vulns": true/false,
    "branch_protection": true/false
  }
}
```

### Milestones

**Week 1 End** (2025-11-09):
- ✅ CI/CD security gates enabled
- ✅ Branch protection configured
- ✅ Pre-commit hooks installed
- ✅ Coverage thresholds raised (CI failing - expected)

**Week 2 End** (2025-11-16):
- ✅ PKCE + CSRF validators tested (2/11 critical modules)
- ✅ Coverage: ~15%
- ✅ Actions pinned to SHAs
- ✅ SBOM generation enabled

**Week 3 End** (2025-11-23):
- ✅ Session security + Token redactor tested (4/11 modules)
- ✅ Coverage: ~25%
- ✅ CI passing (no longer blocked)

**Week 4-5 End** (2025-12-07):
- ✅ Tier 2 modules tested (7/11 total)
- ✅ Coverage: ~40-60%

**Week 6-7 End** (2025-12-21):
- ✅ Detection modules tested
- ✅ Coverage: ~60-70%

**Week 8 End** (2025-12-28):
- ✅ Coverage: >= 70% overall, >= 85% security modules
- ✅ All 11 critical modules tested
- ✅ CI/CD fully hardened
- ✅ EOS CLI tool operational
- ✅ Team trained on new processes

---

## Risk Management

### Risks & Mitigations

**Risk 1**: Team capacity insufficient
- **Mitigation**: Pair programming reduces time, dedicate 2 devs full-time
- **Contingency**: Extend timeline to 12 weeks if needed

**Risk 2**: Tests reveal critical bugs
- **Mitigation**: Good! Fix before production. Prioritize fixes over coverage.
- **Contingency**: Pause new features, focus on quality

**Risk 3**: CI blocking slows development
- **Mitigation**: Pre-commit hooks catch issues earlier (shift-left)
- **Contingency**: Temporary relaxation with explicit approval process

**Risk 4**: Coverage targets too aggressive
- **Mitigation**: Realistic thresholds (60-70% not 90%)
- **Contingency**: Adjust thresholds based on weekly progress

**Risk 5**: EOS tool development delays
- **Mitigation**: Manual processes work while tool being built
- **Contingency**: Release tool in phases (MVP first)

---

## Communication Plan

### Daily Standup

**Agenda**:
- Test progress (coverage delta)
- Blockers (failing tests, unclear requirements)
- Pair programming schedule

### Weekly Review

**Every Friday 3pm**:
- Review weekly metrics
- Demo completed tests
- Adjust plan if needed
- Celebrate wins (coverage milestones)

### Team Training

**Week 1**: CI/CD changes training (30 min)
**Week 2**: TDD workshop (2 hours)
**Week 3**: Security testing patterns (1 hour)
**Week 4**: EOS CLI tool demo (30 min)

---

## Documentation Updates

### Files to Create/Update

**Immediate** (Week 1):
- [ ] Update `TESTING.md` with new processes
- [ ] Create `CONTRIBUTING.md` with test requirements
- [ ] Update `README.md` with testing quick start

**Ongoing**:
- [ ] Document test patterns in `TEST_PATTERNS.md`
- [ ] Create video tutorials (Loom) for common tasks
- [ ] Update PR template with test checklist

---

## Budget & Resources

### Time Investment

**Total Developer Time**: ~320 hours (8 weeks × 2 devs × 20 hours/week)

**Breakdown**:
- Phase 1: 8 hours (CI/CD fixes)
- Phase 2: 80 hours (Critical security tests)
- Phase 3: 10 hours (CI/CD hardening)
- Phase 4: 80 hours (Tier 2 tests)
- Phase 5: 80 hours (Detection tests)
- Phase 6: 40 hours (Final coverage push)
- EOS CLI: 40 hours (parallel development)

**Cost**: Developer time only (no additional tooling costs)

### Tooling Costs

**All Free/Open Source**:
- Vitest: Free
- GitHub Actions: Free (public repos)
- Codecov: Free (public repos)
- EOS CLI: Internal tool (free)

---

## Next Immediate Actions (Today)

### Action 1: Create Git Branch (5 min)
```bash
git checkout -b test/critical-coverage-initiative
```

### Action 2: Fix CI/CD Gates (1 hour)
```bash
# Edit .github/workflows/test.yml
# Edit .github/workflows/security.yml
# Commit and push
git add .github/workflows/
git commit -m "ci: enforce security gates - block on failures"
git push -u origin test/critical-coverage-initiative
```

### Action 3: Update Coverage Thresholds (15 min)
```bash
# Edit vitest.config.js
# Commit
git add vitest.config.js
git commit -m "test: increase coverage thresholds to industry standards"
git push
```

### Action 4: Create PR (5 min)
```bash
# Go to GitHub
# Create PR from test/critical-coverage-initiative to main
# Title: "CI/CD Security Hardening + Coverage Enforcement"
# Assign reviewers
# Merge ASAP (blocks all future merges on purpose)
```

### Action 5: Team Notification (10 min)
```markdown
Email to: engineering@example.com
Subject: 🚨 Important: Testing Infrastructure Changes

Team,

Starting today, we're implementing mandatory security testing:

**Changes Effective Immediately**:
1. ✅ Coverage must be >= 60% to merge (was 5%)
2. ✅ Security vulnerabilities block CI (no exceptions)
3. ✅ Branch protection enabled (1 approval required)
4. ✅ Pre-commit hooks check tests automatically

**Why**: Our testing infrastructure analysis revealed critical gaps:
- 11 security modules completely untested
- 2.3% coverage vs 80% industry standard
- CI/CD allowed security failures

**What This Means For You**:
- Write tests for new code (TDD encouraged)
- Pre-commit hook runs tests automatically
- CI will fail if coverage decreases
- Pair programming available for testing help

**Support**:
- Test-writing workshop: Friday 10am
- Office hours: Daily 3-4pm
- Questions: #testing-excellence Slack channel

**Timeline**: 8-week initiative to reach 70% coverage

Thanks for your patience as we improve our quality standards.

- [Your Name]
```

---

## Conclusion

This action plan provides a clear, evidence-based path from 2.3% coverage (critical risk) to 70% coverage (acceptable risk) in 8 weeks.

**Key Success Factors**:
1. **Immediate CI/CD fixes** prevent further regression
2. **Security-first approach** tackles highest-risk modules first
3. **Systematic automation** (EOS CLI) prevents future gaps
4. **Cultural shift** toward test-first development
5. **Clear metrics** track progress weekly

**Expected Outcome**:
- 70% coverage baseline (industry acceptable)
- 85% coverage on security modules (OWASP recommended)
- Zero critical security modules untested
- Automated prevention of test gaps
- Testing culture embedded in team

**Start Date**: 2025-11-07 (Today)
**Completion Date**: 2025-12-28 (8 weeks)
**Risk Reduction**: CRITICAL → LOW

Let's build a security tool we can trust. 🚀
