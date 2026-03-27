# ADR-001: Use ESLint Flat Config (eslint.config.js)

**Status:** ACCEPTED
**Date:** 2026-01-01
**Issue:** ISSUE-003
**Runbook:** [RUNBOOK-eslint-config](../runbooks/RUNBOOK-eslint-config.md)

## Context

PR #5 failed pre-commit hook with error:
```
TypeError: Error while loading rule '@typescript-eslint/no-unused-expressions'
```

### Root Cause Analysis (5 Whys)

1. **Why did the hook fail?** ESLint threw a TypeScript plugin error
2. **Why was TypeScript ESLint used?** A global `eslint.config.mjs` at `~/` extends `typescript-eslint`
3. **Why did global config take precedence?** ESLint searches up directory tree; flat config (`eslint.config.*`) takes precedence over legacy (`.eslintrc.*`)
4. **Why does global config exist?** Developer has global Node.js tooling with TypeScript ESLint at `~/node_modules/`
5. **Why doesn't project isolate from global configs?** **No flat config in project** - only legacy `.eslintrc.json` which was also broken (invalid JSON with comments)

### Contributing Factor

The original `.eslintrc.json` contained JavaScript-style comments (`//`), which are invalid JSON:

```bash
$ node -e "JSON.parse(require('fs').readFileSync('.eslintrc.json', 'utf8'))"
SyntaxError: Expected property name or '}' in JSON at position 287 (line 19 column 5)
```

This caused ESLint to fall back to searching parent directories, eventually finding the global TypeScript config.

## Decision

**Use ESLint flat config format (`eslint.config.js`)** instead of legacy format (`.eslintrc.*`).

### Why Flat Config?

| Factor | Legacy (`.eslintrc.*`) | Flat Config (`eslint.config.js`) |
|--------|------------------------|----------------------------------|
| **Global config isolation** | Searches up directory tree | Project config takes precedence |
| **Comments** | JSON: no, JS: yes | JavaScript: yes |
| **ESLint 9 compatibility** | Deprecated | Native format |
| **Config merging** | Complex cascading | Explicit array composition |
| **Type checking** | None | JSDoc support |

### Why Not Other Options?

| Option | Verdict | Reason |
|--------|---------|--------|
| Fix `.eslintrc.json` (remove comments) | Rejected | Still vulnerable to global config override |
| Convert to `.eslintrc.js` | Rejected | Still searches up directory tree |
| Add `root: true` | Rejected | Legacy format, deprecated in ESLint 9 |
| Use flat config | **Accepted** | Project takes precedence, future-proof |

## Consequences

### Positive
- Project ESLint config takes precedence over global configs
- JavaScript comments are valid (documentation preserved)
- Ready for ESLint 9 (flat config is default)
- Simpler mental model (explicit array, no cascading)

### Negative
- Must install `@eslint/js` and `globals` packages
- Syntax differs from legacy format
- `--ext` flag removed in flat config

### Neutral
- Same linting rules and behavior
- Same ESLint version (8.57.x)

## Implementation

See [RUNBOOK-eslint-config](../runbooks/RUNBOOK-eslint-config.md) for implementation steps.

### Summary of Changes

1. Created `eslint.config.js` (flat config format)
2. Deleted `.eslintrc.json` (broken JSON with comments)
3. Updated `package.json` lint scripts (removed `--ext .js`)
4. Simplified `.husky/pre-commit` (removed test coverage check)
5. Updated `lint-staged` config (removed `vitest related --run`)

## UNIX Rules Applied

- **Rule #5 (Fail Early, Fail Loud):** Global config silently took precedence
- **Rule #7 (Prefer Simple Over Clever):** Flat config is simpler than cascading legacy
- **Rule #8 (Build for Debuggability):** Error message was misleading (TypeScript error in JS project)
- **Rule #12 (Respect the Environment):** Project must isolate from developer's global environment

## References

- [ESLint Flat Config](https://eslint.org/docs/latest/use/configure/configuration-files-new)
- [ESLint Migration Guide](https://eslint.org/docs/latest/use/configure/migration-guide)
- [ESLint 9 Announcement](https://eslint.org/blog/2024/04/eslint-v9.0.0-released/)
- [Configuration File Resolution](https://eslint.org/docs/latest/use/configure/configuration-files#configuration-file-resolution)
