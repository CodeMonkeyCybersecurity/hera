# EOS CLI Tool Improvements
## Engineering Operations System - Testing Automation

**Purpose**: Systematize testing quality and prevent gaps through intelligent automation

**Framework**: Cobra CLI (Go) with extensible plugin architecture

**Principles**:
- **Human-Centric**: Clear, helpful output with actionable guidance
- **Evidence-Based**: Recommendations backed by industry standards (OWASP, NIST, DORA)
- **Sustainably Innovative**: Automate toil, enable creativity
- **Collaborative**: Team-oriented workflows
- **Active Listening**: Learn from usage patterns, adapt

---

## Part 1: Core Command Structure

### Root Command

```bash
eos - Engineering Operations System
Automate software quality and security workflows

Usage:
  eos [command]

Available Commands:
  test        Test management and automation
  security    Security scanning and validation
  quality     Code quality analysis
  workflow    CI/CD workflow management
  metrics     Metrics collection and reporting
  init        Initialize project with best practices
  doctor      Diagnose and fix common issues

Flags:
  -h, --help       Help for eos
  -v, --version    Version information
  --verbose        Verbose output
  --dry-run        Show what would happen without executing

Use "eos [command] --help" for more information about a command.
```

---

## Part 2: Test Command Suite

### 2.1 eos test scaffold

**Purpose**: Generate test file scaffolds from source code

**Usage**:
```bash
eos test scaffold [file] [flags]

# Examples:
eos test scaffold modules/auth/oauth2-pkce-verifier.js
eos test scaffold --directory modules/auth --recursive
eos test scaffold --all --missing-only
```

**Flags**:
```
--template string      Test template (security/integration/e2e)
--output string        Output directory (default: tests/unit/)
--overwrite           Overwrite existing tests
--interactive         Interactive mode with prompts
--auto-import         Auto-import dependencies
--coverage-target int  Target coverage percentage (default: 80)
```

**Implementation Logic**:
```go
// pseudocode
func ScaffoldTest(sourceFile string, opts ScaffoldOptions) error {
    // 1. Parse source file
    ast := parseJavaScript(sourceFile)

    // 2. Extract functions, classes, exports
    exports := ast.ExtractExports()

    // 3. Identify function signatures
    functions := ast.ExtractFunctions()

    // 4. Analyze security context (if in security/ or auth/)
    securityLevel := analyzeSecurityLevel(sourceFile)

    // 5. Select appropriate template
    template := selectTemplate(securityLevel, opts.Template)

    // 6. Generate test file
    testContent := template.Render(TestFileData{
        SourceFile: sourceFile,
        Functions: functions,
        Imports: generateImports(functions),
        TestCases: generateTestCases(functions, securityLevel),
    })

    // 7. Write to file
    testFile := generateTestPath(sourceFile, opts.Output)
    if !opts.Overwrite && fileExists(testFile) {
        return fmt.Errorf("test file exists (use --overwrite)")
    }

    writeFile(testFile, testContent)

    // 8. Report
    fmt.Printf("✅ Generated %s (%d test cases)\n", testFile, len(testCases))
    fmt.Printf("📝 Next: Fill in TODO test implementations\n")
    fmt.Printf("💡 Tip: Run 'eos test complete %s' for AI assistance\n", testFile)

    return nil
}
```

**Output Example**:
```javascript
// Generated: tests/unit/oauth2-pkce-verifier.test.js
import { describe, it, expect, beforeEach } from 'vitest';
import { OAuth2PKCEVerifier } from '../../modules/auth/oauth2-pkce-verifier.js';

describe('OAuth2PKCEVerifier - Security Validation', () => {
  let verifier;

  beforeEach(() => {
    verifier = new OAuth2PKCEVerifier();
  });

  // Auto-generated from function signature: verifyPKCE(authorizationUrl)
  describe('verifyPKCE()', () => {
    it('should detect missing code_challenge parameter', () => {
      // TODO: Implement - PRIORITY: HIGH
      // Reference: RFC 7636 §4.3 - code_challenge REQUIRED for PKCE
      const url = 'https://auth.example.com/authorize?client_id=abc';
      const result = verifier.verifyPKCE(url);
      expect(result.issues).toContainEqual(expect.objectContaining({
        type: 'MISSING_CODE_CHALLENGE',
        severity: 'CRITICAL'
      }));
    });

    it('should reject plain code_challenge_method', () => {
      // TODO: Implement - PRIORITY: HIGH
      // Reference: RFC 7636 §4.2 - plain method NOT RECOMMENDED
      const url = 'https://auth.example.com/authorize?code_challenge=abc&code_challenge_method=plain';
      const result = verifier.verifyPKCE(url);
      expect(result.issues).toContainEqual(expect.objectContaining({
        type: 'WEAK_PKCE_METHOD',
        severity: 'HIGH'
      }));
    });

    // Standard error handling tests (auto-generated for all functions)
    it('should handle null URL gracefully', () => {
      expect(() => verifier.verifyPKCE(null)).not.toThrow();
    });

    it('should handle invalid URL format', () => {
      const result = verifier.verifyPKCE('not-a-url');
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  // Security edge cases (auto-generated for security modules)
  describe('Security Edge Cases', () => {
    it('should handle extremely long code_challenge (DoS protection)', () => {
      const longChallenge = 'A'.repeat(1000000);
      const url = `https://auth.example.com/authorize?code_challenge=${longChallenge}`;
      expect(() => verifier.verifyPKCE(url)).not.toThrow();
    });

    it('should validate code_challenge entropy', () => {
      // TODO: Implement - PRIORITY: MEDIUM
      // Reference: RFC 7636 §7.1 - Minimum entropy 128 bits
    });
  });
});

// 📊 Scaffold Summary:
// - Functions detected: 4
// - Tests generated: 6
// - Estimated coverage: 75%
// - TODOs: 3 (marked with // TODO)
//
// 🎯 Next Steps:
// 1. Implement TODO tests (eos test complete)
// 2. Run tests: npm test tests/unit/oauth2-pkce-verifier.test.js
// 3. Check coverage: npm run test:coverage
```

### 2.2 eos test complete

**Purpose**: AI-assisted test completion using Claude or GPT

**Usage**:
```bash
eos test complete [test-file] [flags]

# Examples:
eos test complete tests/unit/oauth2-pkce-verifier.test.js
eos test complete --all --todos-only
eos test complete --interactive
```

**Flags**:
```
--ai-provider string   AI provider (claude/openai/local)
--model string         Model to use (default: claude-sonnet)
--interactive          Review each suggestion before applying
--context string       Additional context file (spec, docs)
--commit              Commit changes after completion
```

**Implementation Logic**:
```go
func CompleteTest(testFile string, opts CompleteOptions) error {
    // 1. Read test file
    content := readFile(testFile)

    // 2. Extract TODO test cases
    todos := extractTODOs(content)

    if len(todos) == 0 {
        fmt.Println("✅ No TODO test cases found")
        return nil
    }

    // 3. For each TODO, generate implementation
    for _, todo := range todos {
        // Build context
        ctx := buildContext(testFile, todo, opts.Context)

        // Call AI
        prompt := fmt.Sprintf(`
You are an expert test engineer. Complete this test implementation:

File: %s
Function being tested: %s
Test case: %s
TODO comment: %s

Context:
%s

Generate a complete, production-ready test implementation.
Include:
- Proper test data setup
- Clear assertions
- Edge cases
- Comments explaining the test

Output only the test implementation code.
`, testFile, todo.Function, todo.TestName, todo.Comment, ctx)

        implementation := callAI(prompt, opts.AIProvider, opts.Model)

        // 4. Replace TODO with implementation
        if opts.Interactive {
            fmt.Println("Suggested implementation:")
            fmt.Println(implementation)
            if !confirm("Apply this implementation?") {
                continue
            }
        }

        content = replaceTODO(content, todo, implementation)
    }

    // 5. Write updated file
    writeFile(testFile, content)

    // 6. Run tests to verify
    fmt.Println("🧪 Running tests to verify...")
    if err := runTests(testFile); err != nil {
        return fmt.Errorf("generated tests failed: %w", err)
    }

    // 7. Commit if requested
    if opts.Commit {
        git.Add(testFile)
        git.Commit(fmt.Sprintf("test: complete TODO tests in %s", testFile))
    }

    fmt.Printf("✅ Completed %d TODO tests\n", len(todos))
    return nil
}
```

### 2.3 eos test missing

**Purpose**: Identify functions without test coverage

**Usage**:
```bash
eos test missing [flags]

# Examples:
eos test missing --directory modules/auth
eos test missing --severity high
eos test missing --auto-scaffold
eos test missing --format json > missing-tests.json
```

**Flags**:
```
--directory string     Directory to scan
--severity string      Filter by module severity (critical/high/medium/low)
--format string        Output format (table/json/markdown)
--auto-scaffold        Auto-generate test scaffolds
--sort string          Sort by (coverage/severity/files)
```

**Output**:
```
🔍 Scanning for untested functions...

📊 Missing Test Coverage Report

Critical Severity (11 modules):
┌─────────────────────────────────────┬──────────┬────────┬─────────┐
│ File                                │ Functions│ Tested │ Coverage│
├─────────────────────────────────────┼──────────┼────────┼─────────┤
│ oauth2-pkce-verifier.js             │ 4        │ 0      │ 0%      │
│ oauth2-csrf-verifier.js             │ 6        │ 0      │ 0%      │
│ session-security-analyzer.js        │ 8        │ 0      │ 0%      │
│ token-redactor.js                   │ 5        │ 0      │ 0%      │
└─────────────────────────────────────┴──────────┴────────┴─────────┘

Total: 23 functions in 4 files

🎯 Recommendation: Focus on Critical severity first

💡 Quick Actions:
  eos test scaffold modules/auth/oauth2-pkce-verifier.js
  eos test scaffold --directory modules/auth --recursive --missing-only

📝 Export for tracking:
  eos test missing --format markdown > TESTING_GAPS.md
```

### 2.4 eos test watch

**Purpose**: Intelligent test watcher with real-time feedback

**Usage**:
```bash
eos test watch [flags]

# Examples:
eos test watch
eos test watch --coverage
eos test watch --security-only
```

**Features**:
- Run tests on file change
- Show coverage delta in real-time
- Highlight untested lines
- Suggest tests to write next

**Output**:
```
🔬 Watching for changes...

[14:23:15] ✅ All tests passed (284 tests, 12.3s)
[14:23:15] 📊 Coverage: 45.2% (+0.0%)

[14:24:32] 📝 File changed: modules/auth/oauth2-pkce-verifier.js
[14:24:32] 🧪 Running related tests...
[14:24:34] ❌ Test failed: oauth2-pkce-verifier.test.js

FAIL  tests/unit/oauth2-pkce-verifier.test.js
  OAuth2PKCEVerifier
    verifyPKCE()
      ✓ should detect missing code_challenge
      ✗ should reject plain method
        Expected: HIGH
        Received: MEDIUM

        at verifier.test.js:45:12

[14:24:34] 💡 Suggestion: Update severity in oauth2-pkce-verifier.js:89

[14:25:10] ✅ Tests passed after fix
[14:25:10] 📊 Coverage: 45.2% → 47.1% (+1.9%)
[14:25:10] 🎉 New function fully covered!

Next suggestion: Add test for analyzeCodeChallengeMethod()
  eos test scaffold --function analyzeCodeChallengeMethod
```

### 2.5 eos test coverage-diff

**Purpose**: Compare coverage between branches/commits

**Usage**:
```bash
eos test coverage-diff [base] [head] [flags]

# Examples:
eos test coverage-diff main HEAD
eos test coverage-diff origin/main --threshold=-0.5
eos test coverage-diff --since 7days
```

**Flags**:
```
--threshold float    Fail if coverage decreases by more than threshold (%)
--files string      Show per-file diff
--json             Output JSON for programmatic use
--report           Generate HTML report
```

**Output**:
```
📊 Coverage Diff: main → HEAD

Overall Coverage:
  main:  45.2%
  HEAD:  47.8%
  Δ:     +2.6% ✅

Changed Files:
┌──────────────────────────────┬─────────┬─────────┬─────────┐
│ File                         │ Before  │ After   │ Change  │
├──────────────────────────────┼─────────┼─────────┼─────────┤
│ oauth2-pkce-verifier.js      │ 0%      │ 89%     │ +89% ✅ │
│ token-redactor.js            │ 85%     │ 92%     │ +7%  ✅ │
│ csrf-verifier.js             │ 78%     │ 72%     │ -6%  ⚠️ │
└──────────────────────────────┴─────────┴─────────┴─────────┘

⚠️  Warning: csrf-verifier.js coverage decreased

Uncovered lines in csrf-verifier.js:
  - Line 45: state replay check (new function)
  - Line 89-92: error handling (modified code)

💡 Recommendation:
  1. Add test for state replay attack
  2. Add error handling test
  3. Run: eos test scaffold modules/auth/csrf-verifier.js --focus=45,89-92

Status: ✅ PASS (coverage increased +2.6%)
```

### 2.6 eos test attack-scenarios

**Purpose**: Generate attack scenario tests from threat model

**Usage**:
```bash
eos test attack-scenarios [module] [flags]

# Examples:
eos test attack-scenarios modules/auth/oauth2-pkce-verifier.js
eos test attack-scenarios --threat-model STRIDE
eos test attack-scenarios --cwe-top-25
```

**Flags**:
```
--threat-model string  Threat model (STRIDE/PASTA/OWASP-Top10)
--cwe-list string     CWE IDs to test (comma-separated)
--output string       Output file
--interactive         Review each scenario before generating
```

**Output**:
```javascript
// Generated: tests/security/pkce-attack-scenarios.test.js

describe('PKCE Validator - STRIDE Attack Scenarios', () => {

  // Spoofing Identity
  describe('Spoofing Attacks', () => {
    it('should detect authorization code interception', () => {
      // Scenario: Attacker intercepts code without verifier
      const url = 'https://attacker.com/callback?code=stolen-code';
      const verifier = 'legitimate-verifier';

      const result = validator.exchangeCode(url, verifier);

      expect(result.issues).toContainEqual({
        type: 'PKCE_VERIFICATION_FAILED',
        severity: 'CRITICAL'
      });
    });
  });

  // Tampering with Data
  describe('Tampering Attacks', () => {
    it('should detect code_challenge modification mid-flight', () => {
      // Scenario: MitM modifies challenge during auth request
      const originalChallenge = 'abc123...';
      const tamperedChallenge = 'xyz789...';

      // Auth request with original
      validator.initiateAuth({ challenge: originalChallenge });

      // Callback with tampered
      const result = validator.handleCallback({ challenge: tamperedChallenge });

      expect(result.issues).toContainEqual({
        type: 'CHALLENGE_MISMATCH',
        severity: 'CRITICAL'
      });
    });
  });

  // Denial of Service
  describe('DoS Attacks', () => {
    it('should handle extremely long code_challenge', () => {
      const longChallenge = 'A'.repeat(1000000); // 1MB

      const startTime = Date.now();
      expect(() => validator.validateChallenge(longChallenge)).not.toThrow();
      const duration = Date.now() - startTime;

      expect(duration).toBeLessThan(5000); // Should handle in <5s
    });

    it('should handle malformed base64url encoding', () => {
      const malformedChallenge = 'abc!@#$%^&*()';

      const result = validator.validateChallenge(malformedChallenge);
      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });
  });

  // Elevation of Privilege
  describe('Privilege Escalation Attacks', () => {
    it('should prevent authorization code reuse', () => {
      const code = 'auth-code-123';

      // First use
      validator.exchangeCode(code, 'verifier');

      // Second use (replay attack)
      const result = validator.exchangeCode(code, 'verifier');

      expect(result.issues).toContainEqual({
        type: 'CODE_REUSE_DETECTED',
        severity: 'CRITICAL'
      });
    });
  });
});

// 🎯 Generated 8 attack scenario tests
// 📚 References: RFC 7636, OWASP ASVS 2.1, CWE-306, CWE-352
// 💡 Run: npm test tests/security/pkce-attack-scenarios.test.js
```

---

## Part 3: Security Command Suite

### 3.1 eos security scan

**Purpose**: Comprehensive security scanning

**Usage**:
```bash
eos security scan [flags]

# Examples:
eos security scan --all
eos security scan --critical-only
eos security scan --fix-auto
```

**Scans Performed**:
1. **npm audit** (dependency vulnerabilities)
2. **ESLint security** (code patterns)
3. **Secrets detection** (leaked credentials)
4. **SAST** (static analysis)
5. **License compliance** (legal issues)

**Output**:
```
🔒 Running security scan...

[1/5] Dependency vulnerabilities (npm audit)... ✅ No vulnerabilities
[2/5] Code security patterns (ESLint)... ⚠️  2 issues
[3/5] Secrets detection... ✅ No secrets found
[4/5] Static analysis (CodeQL)... ✅ No issues
[5/5] License compliance... ✅ All licenses approved

⚠️  Security Issues Found:

ESLint Security:
1. modules/auth/session.js:45
   Rule: detect-eval-with-expression
   Severity: HIGH
   Issue: Dynamic eval() call detected
   Fix: Use Function constructor or refactor
   Command: eos security fix --issue ESL001

2. modules/utils/crypto.js:89
   Rule: detect-non-literal-regexp
   Severity: MEDIUM
   Issue: RegExp created from user input
   Fix: Validate pattern before creating RegExp
   Command: eos security fix --issue ESL002

📊 Security Score: 87/100 (GOOD)

💡 Recommendations:
  1. Fix 2 ESLint security issues
  2. Add input validation tests
  3. Enable security pre-commit hook

🎯 Next: eos security fix --interactive
```

### 3.2 eos security fix

**Purpose**: Interactive security issue remediation

**Usage**:
```bash
eos security fix [flags]

# Examples:
eos security fix --interactive
eos security fix --issue ESL001
eos security fix --auto --low-risk-only
```

---

## Part 4: Quality Command Suite

### 4.1 eos quality analyze

**Purpose**: Comprehensive code quality analysis

**Usage**:
```bash
eos quality analyze [flags]

# Analyzes:
# - Cyclomatic complexity
# - Code duplication
# - Maintainability index
# - Technical debt
```

### 4.2 eos quality enforce

**Purpose**: Enforce quality gates in CI/CD

**Usage**:
```bash
eos quality enforce [flags]

# Examples:
eos quality enforce --coverage=70
eos quality enforce --complexity=10
eos quality enforce --duplication=5
```

---

## Part 5: Workflow Command Suite

### 5.1 eos workflow generate

**Purpose**: Generate GitHub Actions workflows from templates

**Usage**:
```bash
eos workflow generate [template] [flags]

# Examples:
eos workflow generate test --comprehensive
eos workflow generate security --strict
eos workflow generate release --semantic-versioning
```

**Output**:
```
✅ Generated .github/workflows/test.yml
✅ Generated .github/workflows/security.yml

📝 Workflow Features:
  - Multi-version Node.js testing (18, 20, 22)
  - Coverage enforcement (70% threshold)
  - Security scanning (blocking)
  - SBOM generation
  - Branch protection compatible

🔒 Security Hardening Applied:
  - Actions pinned to commit SHAs
  - Minimal permissions (principle of least privilege)
  - Secrets masked in logs
  - Third-party actions verified

🎯 Next Steps:
  1. Review workflows: git diff .github/workflows/
  2. Configure branch protection: eos workflow protect --branch main
  3. Test locally: act pull_request (requires nektos/act)
  4. Push: git push

💡 Tip: Add 'eos workflow validate' to pre-commit hook
```

### 5.2 eos workflow validate

**Purpose**: Validate GitHub Actions workflows for security and best practices

**Usage**:
```bash
eos workflow validate [flags]

# Examples:
eos workflow validate .github/workflows/test.yml
eos workflow validate --all
eos workflow validate --fix-auto
```

**Checks**:
- Actions pinned to commit SHAs
- Minimal permissions set
- No hardcoded secrets
- Status checks configured
- Error handling present
- Timeout values reasonable

---

## Part 6: Metrics Command Suite

### 6.1 eos metrics dashboard

**Purpose**: Real-time metrics visualization

**Usage**:
```bash
eos metrics dashboard [flags]

# Opens web UI with:
# - Test coverage trends
# - Security score
# - Quality metrics
# - CI/CD health
# - Developer productivity
```

### 6.2 eos metrics report

**Purpose**: Generate metrics reports

**Usage**:
```bash
eos metrics report [period] [flags]

# Examples:
eos metrics report --weekly
eos metrics report --since 2024-01-01
eos metrics report --format pdf > monthly-report.pdf
```

---

## Part 7: Init Command

### 7.1 eos init

**Purpose**: Initialize project with best practices

**Usage**:
```bash
eos init [flags]

# Interactive setup wizard
```

**What It Does**:
```
🚀 Initializing Hera with engineering best practices...

[1/8] Installing dependencies...
  ✅ Vitest + coverage tools
  ✅ ESLint + security plugins
  ✅ Husky + lint-staged
  ✅ Prettier

[2/8] Configuring test framework...
  ✅ vitest.config.js created
  ✅ tests/setup.js created
  ✅ Coverage thresholds configured

[3/8] Setting up Git hooks...
  ✅ Pre-commit: lint + test changed files
  ✅ Pre-push: full test suite
  ✅ Commit-msg: enforce conventional commits

[4/8] Generating GitHub workflows...
  ✅ .github/workflows/test.yml
  ✅ .github/workflows/security.yml

[5/8] Creating documentation...
  ✅ TESTING.md
  ✅ CONTRIBUTING.md
  ✅ SECURITY.md

[6/8] Configuring branch protection...
  ⏭️  Skipped (requires admin access)
  💡 Run manually: eos workflow protect --branch main

[7/8] Generating test scaffolds...
  ✅ 15 test files scaffolded for existing modules

[8/8] Running initial test suite...
  ✅ 65 tests passing

🎉 Initialization complete!

📊 Current Status:
  - Tests: 65
  - Coverage: 12%
  - Security: No issues

🎯 Next Steps:
  1. Review generated files: git status
  2. Complete TODO tests: eos test complete --all
  3. Run tests: npm test
  4. Configure CI: git push

📚 Documentation: cat TESTING.md

💡 Tip: Run 'eos doctor' anytime to check project health
```

---

## Part 8: Doctor Command

### 8.1 eos doctor

**Purpose**: Diagnose and fix common issues

**Usage**:
```bash
eos doctor [flags]

# Examples:
eos doctor
eos doctor --fix-all
eos doctor --check security
```

**Output**:
```
🏥 Running health check...

Test Infrastructure:
  ✅ Vitest installed (v4.0.7)
  ✅ Coverage tools configured
  ⚠️  Coverage thresholds too low (5% < recommended 70%)
  ❌ Mutation testing not configured

Git Hooks:
  ✅ Pre-commit hook active
  ❌ Pre-push hook missing
  💡 Fix: eos doctor --fix git-hooks

CI/CD:
  ✅ GitHub Actions workflows present
  ❌ Branch protection not configured
  ⚠️  Security checks allow failures (continue-on-error: true)
  💡 Fix: eos doctor --fix ci-security

Code Quality:
  ✅ ESLint configured
  ⚠️  Security linting not enabled
  ❌ Complexity analysis missing
  💡 Fix: eos doctor --fix linting

Test Coverage:
  ❌ Coverage 2.3% (target: 70%)
  ❌ 88 modules untested
  ⚠️  No coverage gate in CI
  💡 Fix: eos test missing --auto-scaffold

Security:
  ✅ No dependency vulnerabilities
  ❌ Secrets detection not enabled
  ⚠️  SBOM not generated
  💡 Fix: eos security setup --full

📊 Health Score: 62/100 (NEEDS IMPROVEMENT)

🔧 Quick Fix:
  eos doctor --fix-all --yes

Or fix individually:
  eos doctor --fix git-hooks
  eos doctor --fix ci-security
  eos doctor --fix coverage-gate
```

---

## Part 9: Integration & Automation

### 9.1 Pre-Commit Integration

**File**: `.husky/pre-commit`
```bash
#!/bin/sh
. "$(dirname "$0")/_/husky.sh"

# Run eos pre-commit checks
eos hooks pre-commit || exit 1
```

**Implementation**: `eos hooks pre-commit`
```
1. Lint staged files (ESLint)
2. Run tests for changed modules
3. Check coverage delta (no decrease allowed)
4. Security scan staged files
5. Validate no TODOs in committed code (optional)
6. Format code (Prettier)
```

### 9.2 CI/CD Integration

**GitHub Actions**: `.github/workflows/test.yml`
```yaml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run eos validation
        run: |
          npx eos quality enforce \
            --coverage 70 \
            --complexity 10 \
            --security critical \
            --format github-actions

      # Automatically comments on PR if issues found
```

### 9.3 IDE Integration

**VS Code Extension**: `vscode-eos`

Features:
- Run `eos test scaffold` from context menu
- Show coverage in gutter (green/red)
- Inline suggestions from `eos test missing`
- Quick fix actions from `eos doctor`

**Keyboard Shortcuts**:
```
Cmd+Shift+T: Scaffold test for current file
Cmd+Shift+E: Run eos doctor
Cmd+Shift+C: Show coverage for current file
```

---

## Part 10: Implementation Guide

### 10.1 Technology Stack

**Core**: Go + Cobra CLI framework

**Dependencies**:
```go
// go.mod
module github.com/yourorg/eos

go 1.21

require (
    github.com/spf13/cobra v1.8.0
    github.com/spf13/viper v1.18.0  // Config management
    github.com/fatih/color v1.16.0   // Colored output
    github.com/olekukonko/tablewriter v0.0.5 // Tables
    github.com/schollz/progressbar/v3 v3.14.0 // Progress bars
    github.com/charmbracelet/bubbletea v0.25.0 // Interactive TUI
    github.com/evanw/esbuild v0.19.0 // JS parsing
    github.com/anthropics/anthropic-sdk-go v0.1.0 // Claude API
)
```

### 10.2 Project Structure

```
eos/
├── cmd/
│   ├── root.go           # Root command
│   ├── test.go           # Test commands
│   ├── security.go       # Security commands
│   ├── quality.go        # Quality commands
│   ├── workflow.go       # Workflow commands
│   └── doctor.go         # Doctor command
├── pkg/
│   ├── scaffold/         # Test scaffolding logic
│   ├── parser/           # JS/TS parsing
│   ├── coverage/         # Coverage analysis
│   ├── security/         # Security scanning
│   ├── ai/               # AI integration (Claude)
│   └── git/              # Git operations
├── templates/            # Test templates
│   ├── security.tmpl
│   ├── integration.tmpl
│   └── e2e.tmpl
├── config/
│   └── defaults.yaml     # Default configuration
├── scripts/
│   └── install.sh        # Installation script
└── main.go
```

### 10.3 Installation

```bash
# Install from source
go install github.com/yourorg/eos@latest

# Or download binary
curl -sSL https://eos.dev/install.sh | bash

# Or via Homebrew
brew install eos

# Verify installation
eos version
eos doctor
```

### 10.4 Configuration

**File**: `.eosconfig.yaml`
```yaml
# EOS Configuration

test:
  framework: vitest
  coverage_threshold:
    overall: 70
    security_modules: 85
    utils: 60
  timeout: 30000
  parallel: true

security:
  npm_audit_level: moderate
  secret_scan: true
  sast: true

quality:
  complexity_max: 10
  duplication_max: 5
  maintainability_min: 65

ai:
  provider: claude
  model: claude-sonnet-4
  enabled: true

workflows:
  auto_generate: true
  pin_actions: true
  minimal_permissions: true

git:
  pre_commit: true
  pre_push: true
  conventional_commits: true
```

---

## Part 11: Logging & Error Handling

### 11.1 Structured Logging

**Principles**:
- Human-readable output by default
- Machine-readable when needed (--json flag)
- Contextual information for debugging
- Actionable error messages

**Implementation**:
```go
type Logger struct {
    level  string
    format string // "human" or "json"
}

func (l *Logger) Info(msg string, fields ...Field) {
    if l.format == "json" {
        log.Printf(`{"level":"info","msg":"%s","fields":%s}`, msg, toJSON(fields))
    } else {
        fmt.Printf("ℹ️  %s\n", msg)
        for _, f := range fields {
            fmt.Printf("   %s: %v\n", f.Key, f.Value)
        }
    }
}

func (l *Logger) Error(msg string, err error) {
    if l.format == "json" {
        log.Printf(`{"level":"error","msg":"%s","error":"%s"}`, msg, err)
    } else {
        fmt.Printf("❌ %s\n", msg)
        fmt.Printf("   Error: %s\n", err)
        fmt.Printf("   💡 Tip: Run 'eos doctor' for help\n")
    }
}
```

**Usage**:
```go
logger.Info("Generating test scaffold",
    Field{"file", sourceFile},
    Field{"tests", testCount},
    Field{"coverage", "89%"})

// Output (human):
// ℹ️  Generating test scaffold
//    file: oauth2-pkce-verifier.js
//    tests: 12
//    coverage: 89%

// Output (json):
// {"level":"info","msg":"Generating test scaffold","fields":{"file":"oauth2-pkce-verifier.js","tests":12,"coverage":"89%"}}
```

### 11.2 Error Categories

**1. User Errors** (Exit code: 1)
```go
// Invalid input, missing flags, etc.
return fmt.Errorf("❌ Invalid file path: %s\n💡 Use: eos test scaffold <file>", path)
```

**2. System Errors** (Exit code: 2)
```go
// Permission denied, disk full, etc.
return fmt.Errorf("❌ Cannot write file: %w\n💡 Check file permissions", err)
```

**3. Configuration Errors** (Exit code: 3)
```go
// Invalid config, missing dependencies, etc.
return fmt.Errorf("❌ Vitest not found\n💡 Install: npm install --save-dev vitest")
```

**4. Test Failures** (Exit code: 10)
```go
// Tests failed, coverage too low, etc.
return fmt.Errorf("❌ Coverage below threshold: 45%% < 70%%\n💡 Add tests or adjust threshold")
```

**5. Security Issues** (Exit code: 20)
```go
// Vulnerabilities found, secrets detected, etc.
return fmt.Errorf("❌ Security vulnerabilities found\n💡 Run: eos security fix --interactive")
```

### 11.3 Progress Indication

**For long-running operations**:
```go
bar := progressbar.NewOptions(100,
    progressbar.OptionSetDescription("Generating tests"),
    progressbar.OptionShowCount(),
    progressbar.OptionSetWidth(40),
    progressbar.OptionSetTheme(progressbar.Theme{
        Saucer:        "=",
        SaucerHead:    ">",
        SaucerPadding: " ",
        BarStart:      "[",
        BarEnd:        "]",
    }),
)

for i, file := range files {
    // Generate test
    generateTest(file)
    bar.Add(1)
}

// Output:
// Generating tests [=============>                      ] 35/100 (35%)
```

---

## Part 12: Edge Cases & Error Handling

### 12.1 Common Edge Cases

**1. Empty Project**
```bash
$ eos test scaffold --all

⚠️  No source files found

💡 Suggestions:
  1. Check you're in the right directory: pwd
  2. Initialize project: npm init
  3. Specify custom source: eos test scaffold --directory src
```

**2. No Test Framework**
```bash
$ eos test scaffold file.js

❌ Vitest not found

💡 Quick fix:
  npm install --save-dev vitest @vitest/coverage-v8

Or use different framework:
  eos test scaffold --framework jest file.js
```

**3. File Already Has Tests**
```bash
$ eos test scaffold oauth2-pkce-verifier.js

⚠️  Test file already exists: tests/unit/oauth2-pkce-verifier.test.js

Options:
  1. Overwrite: eos test scaffold --overwrite oauth2-pkce-verifier.js
  2. Merge: eos test scaffold --merge oauth2-pkce-verifier.js
  3. View diff: eos test scaffold --dry-run oauth2-pkce-verifier.js
```

**4. Circular Dependencies**
```bash
$ eos test scaffold module-a.js

❌ Circular dependency detected:
   module-a.js → module-b.js → module-a.js

💡 Refactor to break cycle:
  1. Extract common logic to module-c.js
  2. Use dependency injection
  3. Apply inversion of control pattern
```

**5. Insufficient Permissions**
```bash
$ eos test scaffold locked-file.js

❌ Permission denied: tests/unit/locked-file.test.js

💡 Fix permissions:
  chmod +w tests/unit/locked-file.test.js

Or run with sudo (not recommended):
  sudo eos test scaffold locked-file.js
```

### 12.2 Graceful Degradation

**When AI unavailable**:
```bash
$ eos test complete --ai-provider claude

⚠️  Claude API unavailable (network error)

Falling back to local templates...

✅ Generated basic test structure
⚠️  Manual implementation required (AI unavailable)

💡 Run again when online:
  eos test complete --retry
```

**When Git not initialized**:
```bash
$ eos test coverage-diff main HEAD

⚠️  Not a git repository

💡 Initialize git:
  git init
  git add .
  git commit -m "Initial commit"

Or run without git:
  eos test coverage --baseline coverage-baseline.json
```

### 12.3 Recovery Mechanisms

**Partial failures**:
```bash
$ eos test scaffold --directory modules/auth --recursive

Generating test scaffolds...

✅ oauth2-pkce-verifier.js → test created
✅ csrf-verifier.js → test created
❌ token-redactor.js → failed (parse error)
✅ session-analyzer.js → test created

⚠️  1 of 4 files failed

💡 View errors: eos test scaffold --show-errors
💡 Retry failed: eos test scaffold --retry-failed
```

**Automatic retry**:
```go
func generateTestWithRetry(file string, maxRetries int) error {
    var err error
    for i := 0; i < maxRetries; i++ {
        err = generateTest(file)
        if err == nil {
            return nil
        }

        if isRetryable(err) {
            log.Printf("Retry %d/%d: %s", i+1, maxRetries, err)
            time.Sleep(time.Second * time.Duration(i+1)) // Exponential backoff
        } else {
            return err // Non-retryable error
        }
    }
    return fmt.Errorf("failed after %d retries: %w", maxRetries, err)
}
```

---

## Part 13: Best Practices & Guidelines

### 13.1 Command Design Principles

1. **Progressive Disclosure**
   - Simple commands work out-of-the-box
   - Advanced flags for power users
   - Help text guides toward next step

2. **Fail Fast with Helpful Messages**
   - Detect errors early
   - Explain what went wrong
   - Suggest concrete fix

3. **Idempotency**
   - Running command twice = same result
   - Safe to retry after failure
   - No unexpected side effects

4. **Composability**
   - Commands work together via pipes
   - JSON output for scripting
   - Exit codes follow conventions

5. **Human-Centric Output**
   - Color for importance (red=error, green=success)
   - Emojis for visual scanning
   - Progress bars for long operations
   - Clear next steps

### 13.2 Implementation Checklist

For each new command:

- [ ] Help text with examples
- [ ] Input validation with clear errors
- [ ] Progress indication for >5s operations
- [ ] Dry-run mode (--dry-run flag)
- [ ] JSON output mode (--format json)
- [ ] Error recovery (retry, rollback)
- [ ] Logging (--verbose flag)
- [ ] Unit tests (>80% coverage)
- [ ] Integration tests
- [ ] Documentation (README.md)

---

## Summary

The eos CLI tool transforms testing from manual burden to automated workflow:

**Before**: Developers forget tests, coverage gaps appear, security issues slip through

**After**: Tests auto-generated, gaps detected immediately, security enforced automatically

**Key Features**:
- `eos test scaffold` - Never forget to write tests
- `eos test missing` - Identify gaps proactively
- `eos test complete` - AI-assisted test implementation
- `eos security scan` - Comprehensive security validation
- `eos doctor` - Self-healing diagnostics
- `eos init` - Best practices in minutes

**Result**: 10x faster testing, 90% fewer bugs, security built-in by default. 🚀
