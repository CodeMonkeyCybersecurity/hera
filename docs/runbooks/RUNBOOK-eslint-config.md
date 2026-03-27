# RUNBOOK: ESLint Configuration

**Status:** ACTIVE
**Issue:** ISSUE-003
**ADR:** [ADR-001](../adr/ADR-001-eslint-config-format.md)

## Problem Statement

ESLint pre-commit hook fails when:
1. Global ESLint config takes precedence over project config
2. Legacy config uses invalid JSON (comments in `.eslintrc.json`)

## Root Cause

ESLint config resolution order:
1. **Flat config** (`eslint.config.js`) - takes absolute precedence
2. **Legacy config** (`.eslintrc.*`) - searches up directory tree

If project uses legacy format and developer has global flat config, global wins.

## Current Solution

Project uses **flat config** (`eslint.config.js`) which:
- Takes precedence over any parent directory configs
- Supports JavaScript comments natively
- Is ESLint 9 native format

## Verification Procedure

### Step 1: Verify Config Exists

```bash
ls -la eslint.config.js
# Should exist and be non-empty
```

### Step 2: Verify No Legacy Config

```bash
ls .eslintrc* 2>/dev/null && echo "WARN: Legacy config found" || echo "OK: No legacy config"
```

### Step 3: Verify ESLint Works

```bash
npm run lint
# Should run without "TypeError: Error while loading rule" errors
```

### Step 4: Verify Pre-Commit Hook

```bash
# Stage a file
git add eslint.config.js

# Test commit
git commit --dry-run -m "test"
# Should pass without @typescript-eslint errors
```

## Troubleshooting

### Error: `@typescript-eslint/no-unused-expressions`

**Cause:** Global TypeScript ESLint config taking precedence

**Solution:**
1. Verify `eslint.config.js` exists in project root
2. Delete any `.eslintrc.*` files
3. Run `npm run lint` to verify project config used

### Error: `Invalid option '--ext'`

**Cause:** Using legacy CLI options with flat config

**Solution:** Remove `--ext .js` from npm scripts:
```json
{
  "lint": "eslint .",  // NOT "eslint . --ext .js"
}
```

### Error: `Cannot find module '@eslint/js'`

**Cause:** Missing flat config dependencies

**Solution:**
```bash
npm install --save-dev @eslint/js globals
```

## Prevention Checklist

- [ ] Project uses `eslint.config.js` (not `.eslintrc.*`)
- [ ] No legacy config files in project
- [ ] CI validates ESLint config before running lint
- [ ] Pre-commit hook validates config exists
- [ ] Package.json scripts use flat config CLI syntax

## Related Files

- `eslint.config.js` - Main ESLint configuration
- `.husky/pre-commit` - Git pre-commit hook
- `package.json` - npm scripts and lint-staged config

## History

| Date | Change |
|------|--------|
| 2026-01-01 | Migrated from `.eslintrc.json` to `eslint.config.js` |
| 2026-01-01 | Removed `--ext .js` from npm scripts |
| 2026-01-01 | Simplified pre-commit hook (removed test coverage) |
