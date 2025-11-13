# Hera Testing Guide

This document describes the testing infrastructure, practices, and guidelines for the Hera Chrome extension.

## Table of Contents

- [Overview](#overview)
- [Test Infrastructure](#test-infrastructure)
- [Running Tests](#running-tests)
- [Test Coverage](#test-coverage)
- [Writing Tests](#writing-tests)
- [CI/CD Integration](#cicd-integration)
- [Testing Best Practices](#testing-best-practices)

## Overview

Hera uses a comprehensive testing strategy that includes:

- **Unit Tests**: Test individual modules and functions in isolation
- **Integration Tests**: Test how multiple components work together
- **Coverage Reporting**: Track test coverage and identify untested code
- **CI/CD Automation**: Automated testing on every commit and PR

### Current Test Statistics

- **Total Tests**: 84 passing
- **Unit Tests**: 70 tests covering JWT and OIDC validators
- **Integration Tests**: 14 tests covering evidence collection
- **Test Coverage**: ~9% for tested modules (JWT & OIDC validators have high coverage)

## Test Infrastructure

### Framework: Vitest

We use [Vitest](https://vitest.dev/) as our test framework because:

- Native ES Module (ESM) support
- Fast execution with parallel testing
- Built-in coverage reporting
- Excellent TypeScript/JavaScript support
- Modern testing API compatible with Jest

### Test Structure

```
tests/
├── setup.js              # Global test setup
├── mocks/
│   └── chrome.js         # Chrome Extension API mocks
├── utils/
│   └── test-helpers.js   # Testing utility functions
├── unit/
│   ├── jwt-validator.test.js
│   └── oidc-validator.test.js
└── integration/
    └── evidence-collection.test.js
```

### Configuration Files

- `vitest.config.js` - Main Vitest configuration
- `tests/setup.js` - Global test setup (mocks, polyfills)
- `.github/workflows/test.yml` - CI/CD test automation
- `.github/workflows/security.yml` - Security scanning automation

## Running Tests

### All Tests

```bash
npm test              # Run all tests once
npm run test:watch    # Run tests in watch mode
npm run test:ui       # Open Vitest UI in browser
```

### Specific Test Suites

```bash
npm run test:unit         # Run only unit tests
npm run test:integration  # Run only integration tests
```

### Coverage Reports

```bash
npm run test:coverage     # Generate coverage report
npm run test:all          # Run lint, validate, and coverage
```

Coverage reports are generated in:
- `coverage/` - Detailed coverage data
- `coverage/index.html` - Visual HTML coverage report

### Continuous Integration

Tests run automatically on:
- Every push to `main`, `develop`, or `claude/**` branches
- Every pull request to `main` or `develop`
- Multiple Node.js versions (18.x, 20.x)

## Test Coverage

### Current Coverage

| Module | Coverage | Tests |
|--------|----------|-------|
| jwt-validator.js | ~95% | 48 tests |
| oidc-validator.js | ~95% | 46 tests |
| Other modules | 0% | Pending |

### Coverage Goals

Our coverage targets (to be achieved as more tests are added):

- **Lines**: 70%
- **Functions**: 70%
- **Branches**: 65%
- **Statements**: 70%

### Viewing Coverage

1. Run tests with coverage:
   ```bash
   npm run test:coverage
   ```

2. Open the HTML report:
   ```bash
   open coverage/index.html
   ```

## Writing Tests

### Unit Test Example

```javascript
// tests/unit/my-module.test.js
import { describe, it, expect, beforeEach } from 'vitest';
import { MyModule } from '../../modules/my-module.js';

describe('MyModule', () => {
  let module;

  beforeEach(() => {
    module = new MyModule();
  });

  it('should perform expected behavior', () => {
    const result = module.doSomething('input');
    expect(result).toBe('expected');
  });

  it('should handle edge cases', () => {
    expect(() => module.doSomething(null)).toThrow();
  });
});
```

### Integration Test Example

```javascript
// tests/integration/workflow.test.js
import { describe, it, expect, beforeEach } from 'vitest';
import { setMockStorageData, resetChromeMocks } from '../mocks/chrome.js';

describe('OAuth2 Flow Integration', () => {
  beforeEach(() => {
    resetChromeMocks();
  });

  it('should track complete OAuth2 flow', async () => {
    // Test multi-component interaction
    const authRequest = { /* ... */ };
    const tokenRequest = { /* ... */ };

    // Verify flow correlation
    expect(authRequest).toBeDefined();
    expect(tokenRequest).toBeDefined();
  });
});
```

### Using Test Helpers

```javascript
import { createMockJWT, createMockOIDCTokenResponse } from '../utils/test-helpers.js';

// Create a mock JWT with custom claims
const jwt = createMockJWT(
  { alg: 'RS256' },  // header
  { sub: 'user-123', exp: Date.now() + 3600 }  // payload
);

// Create a mock OIDC token response
const tokenResponse = createMockOIDCTokenResponse({
  access_token: 'mock-access-token',
  idTokenPayload: { sub: 'user-123' }
});
```

### Mocking Chrome APIs

```javascript
import { chromeMock, setMockStorageData } from '../mocks/chrome.js';

// Mock storage data
setMockStorageData({
  heraEvidence: { /* test data */ }
});

// Use chrome API in tests
const result = await chrome.storage.local.get(['heraEvidence']);
expect(result.heraEvidence).toBeDefined();
```

## CI/CD Integration

### GitHub Actions Workflows

#### Test Workflow (`.github/workflows/test.yml`)

Runs on every push and PR:

1. **Install dependencies** - `npm ci`
2. **Run linter** - `npm run lint`
3. **Validate extension** - `npm run validate`
4. **Run unit tests** - `npm run test:unit`
5. **Run integration tests** - `npm run test:integration`
6. **Generate coverage** - `npm run test:coverage`
7. **Upload coverage to Codecov** (optional)
8. **Archive test results**

#### Security Workflow (`.github/workflows/security.yml`)

Runs daily and on main branch changes:

1. **npm audit** - Check for security vulnerabilities
2. **Dependency check** - Find outdated packages
3. **CodeQL analysis** - Static code analysis

### Build Artifacts

Test runs generate artifacts:
- `test-results-<node-version>` - Test execution results
- `coverage/` - Coverage reports
- `hera-extension` - Validated extension files

## Testing Best Practices

### 1. Test Naming

Use descriptive test names that explain what is being tested:

```javascript
// ❌ Bad
it('works', () => { /* ... */ });

// ✅ Good
it('should detect missing nonce in implicit flow', () => { /* ... */ });
```

### 2. Arrange-Act-Assert Pattern

Structure tests clearly:

```javascript
it('should validate JWT expiration', () => {
  // Arrange - Set up test data
  const expiredToken = createExpiredJWT();

  // Act - Perform the action
  const result = validator.validateJWT(expiredToken);

  // Assert - Verify the result
  expect(result.issues).toContainEqual(
    expect.objectContaining({ type: 'TOKEN_EXPIRED' })
  );
});
```

### 3. Test Isolation

Each test should be independent:

```javascript
beforeEach(() => {
  resetChromeMocks();  // Reset mocks before each test
  validator = new Validator();  // Create fresh instance
});

afterEach(() => {
  // Clean up if needed
});
```

### 4. Test Edge Cases

Always test boundary conditions:

```javascript
describe('JWT parsing', () => {
  it('should parse valid JWT', () => { /* ... */ });
  it('should reject token with <3 parts', () => { /* ... */ });
  it('should reject invalid base64', () => { /* ... */ });
  it('should handle URL-safe encoding', () => { /* ... */ });
  it('should reject null input', () => { /* ... */ });
});
```

### 5. Use Test Helpers

Avoid duplication with helper functions:

```javascript
// Good - reusable helper
function createTestJWT(claims = {}) {
  return createMockJWT(
    { alg: 'RS256' },
    { sub: 'test', ...claims }
  );
}

it('test 1', () => {
  const jwt = createTestJWT({ exp: futureTime });
  // ...
});

it('test 2', () => {
  const jwt = createTestJWT({ iss: 'issuer' });
  // ...
});
```

### 6. Test Security Vulnerabilities

For a security extension, always test vulnerability detection:

```javascript
it('should detect alg:none vulnerability', () => {
  const unsafeToken = createJWT({ alg: 'none' });
  const result = validator.validateJWT(unsafeToken);

  expect(result.issues).toContainEqual(
    expect.objectContaining({
      type: 'ALG_NONE_VULNERABILITY',
      severity: 'CRITICAL',
      cvss: 10.0
    })
  );
});
```

### 7. Performance Testing

Test with realistic data sizes:

```javascript
it('should handle large token responses', () => {
  const largeResponse = createResponseWithSize(500000); // 500KB
  expect(() => validator.analyze(largeResponse)).not.toThrow();
});

it('should limit cache size', () => {
  // Add 100 items to cache with max 25
  for (let i = 0; i < 100; i++) {
    cache.add(createCacheEntry(i));
  }

  expect(cache.size).toBeLessThanOrEqual(25);
});
```

## What to Test Next

To expand test coverage, prioritize these modules:

### High Priority
1. **oauth2-analyzer.js** - Core OAuth2 flow analysis
2. **pkce-validator.js** - PKCE implementation checking
3. **refresh-token-tracker.js** - Token rotation detection
4. **session-security-analyzer.js** - Session fixation & hijacking

### Medium Priority
5. **cookie-utils.js** - Cookie security validation
6. **request-body-capturer.js** - POST body capture & redaction
7. **flow-analyzer.js** - Authentication flow correlation

### Integration Tests Needed
- Complete OAuth2 authorization code flow
- OIDC implicit/hybrid flows
- PKCE end-to-end validation
- Token refresh rotation
- Evidence persistence across restarts

## Continuous Improvement

### Adding New Tests

1. Create test file: `tests/unit/module-name.test.js`
2. Import module and test utilities
3. Write descriptive test cases
4. Run tests: `npm test`
5. Check coverage: `npm run test:coverage`
6. Commit with clear message

### Increasing Coverage

1. Run coverage report: `npm run test:coverage`
2. Open HTML report: `open coverage/index.html`
3. Identify untested code (red/yellow highlights)
4. Add tests for uncovered lines
5. Verify coverage improvement

### Performance Optimization

- Keep tests fast (<100ms per test when possible)
- Use `beforeEach` for setup, not before each assertion
- Mock expensive operations (network, file I/O)
- Run tests in parallel (Vitest default)

## Troubleshooting

### Tests Failing in CI but Passing Locally

- Check Node.js version match
- Verify all dependencies in package.json
- Look for timing issues (use `vi.useFakeTimers()`)
- Check for environment-specific code

### Mock Issues

- Ensure `resetChromeMocks()` in `beforeEach`
- Verify mock implementations match real APIs
- Check for null/undefined mock values

### Coverage Not Generated

- Ensure source files are in include paths
- Check that tests actually import the modules
- Verify vitest.config.js coverage settings

## Resources

- [Vitest Documentation](https://vitest.dev/)
- [Chrome Extension APIs](https://developer.chrome.com/docs/extensions/reference/)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OIDC Specification](https://openid.net/specs/openid-connect-core-1_0.html)

## Support

For questions or issues with tests:

1. Check this documentation
2. Review existing test files for examples
3. Check test output and error messages
4. Open an issue with test failure details
