# Linting Setup Guide

**Date**: 2025-10-12
**Status**: Complete

## Overview

This repo now has **ESLint** configured with Chrome extension-specific rules to catch bugs, enforce code quality, and maintain consistency.

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

This installs:
- `eslint` - JavaScript linter
- `eslint-plugin-chrome-extension` - Chrome extension rules
- `eslint-plugin-webextensions` - WebExtensions API validation
- `nodemon` - Watch mode for continuous linting

### 2. Run Linting

**Lint all files**:
```bash
npm run lint
```

**Auto-fix issues**:
```bash
npm run lint:fix
```

**Lint specific areas**:
```bash
npm run lint:modules      # Lint modules/ directory only
npm run lint:background   # Lint background script
npm run lint:content      # Lint content scripts
npm run lint:popup        # Lint popup/UI code
```

**Watch mode** (auto-lint on file changes):
```bash
npm run lint:watch
```

## VS Code Integration

### Recommended Extensions

Install these VS Code extensions (prompted automatically):
1. **ESLint** (`dbaeumer.vscode-eslint`) - Real-time linting in editor
2. **Chrome Debugger** (`ms-vscode.chrome-debug`) - Debug Chrome extensions
3. **Error Lens** (`usernamehw.errorlens`) - Show errors inline

### Auto-Fix on Save

VS Code is configured to auto-fix linting issues when you save a file. Check [`.vscode/settings.json`](.vscode/settings.json).

**To disable auto-fix on save**:
1. Open VS Code settings (Cmd+,)
2. Search for "Code Actions On Save"
3. Disable "ESLint: Fix All"

## ESLint Configuration

### Rules Overview

The linting configuration enforces:

#### 1. Error Prevention
- `no-undef` - Catch undefined variables
- `no-unused-vars` - Warn about unused variables (except `_` prefix)
- `no-await-in-loop` - Warn about potential performance issues

#### 2. Chrome Extension Best Practices
- Validates `chrome.*` API usage
- Prevents using `window`/`document` in service workers
- Ensures proper manifest configuration

#### 3. Code Quality
- `no-var` - Use `const`/`let` instead of `var`
- `prefer-const` - Use `const` for variables that don't change
- `eqeqeq` - Always use `===` instead of `==`
- `curly` - Always use braces for if/while/for blocks

#### 4. Security
- `no-eval` - Prevent `eval()` usage (CSP violation)
- `no-new-func` - Prevent `new Function()` (CSP violation)
- `no-script-url` - Prevent `javascript:` URLs (XSS risk)

#### 5. Style (Warnings Only)
- 2-space indentation
- Single quotes (allow template literals)
- Semicolons required
- Consistent spacing

### Context-Specific Rules

**Background Scripts** (`background.js`, `modules/background/**/*.js`):
- Error if using `window` or `document` (not available in service workers)
- Must use `self` instead of `window`
- Must use `chrome.scripting` API for DOM access

**Content Scripts** (`content-script.js`, `modules/content/**/*.js`):
- `window` and `document` are allowed
- Can access page DOM directly

**Popup/UI** (`popup.js`, `modules/ui/**/*.js`):
- `window` and `document` are allowed
- DOM APIs available

## Common Linting Errors and Fixes

### 1. Undefined Variable

**Error**:
```
'chrome' is not defined  (no-undef)
```

**Fix**: Already configured in `.eslintrc.json` - `chrome` is a global. If you see this, the ESLint config might not be loaded.

### 2. Unused Variable

**Warning**:
```
'response' is defined but never used  (no-unused-vars)
```

**Fix**: Either use the variable or prefix with underscore:
```javascript
// Before
chrome.runtime.sendMessage({}, (response) => {
  // Not using response
});

// After
chrome.runtime.sendMessage({}, (_response) => {
  // _ prefix tells ESLint it's intentionally unused
});
```

### 3. Missing Await

**Warning**:
```
Async function has no 'await' expression  (require-await)
```

**Fix**: Either add `await` or remove `async`:
```javascript
// Before
async function getData() {
  return data;
}

// After (if no async needed)
function getData() {
  return data;
}
```

### 4. Using `window` in Service Worker

**Error**:
```
Unexpected use of 'window'  (no-restricted-globals)
Service workers don't have window. Use self instead.
```

**Fix**: Use `self` instead:
```javascript
// Before (in background.js)
window.addEventListener('load', () => {});

// After
self.addEventListener('load', () => {});
```

### 5. Using `==` Instead of `===`

**Error**:
```
Expected '===' and instead saw '=='  (eqeqeq)
```

**Fix**: Use strict equality:
```javascript
// Before
if (value == null) {}

// After
if (value === null) {}

// Or for null/undefined check
if (value == null) {}  // This is allowed (see config)
```

### 6. Missing Semicolon

**Warning**:
```
Missing semicolon  (semi)
```

**Fix**: Add semicolon or run `npm run lint:fix`:
```javascript
// Before
const x = 5

// After
const x = 5;
```

## Ignoring Specific Rules

### For One Line

```javascript
// eslint-disable-next-line no-console
console.log('Debugging output');
```

### For Entire File

```javascript
/* eslint-disable no-console */
console.log('Lots of debugging');
console.log('More debugging');
/* eslint-enable no-console */
```

### For Specific Variables

```javascript
// Allow unused parameter
function handleMessage(message, sender, sendResponse) {
  // Only using message, not sender/sendResponse
  console.log(message);
}

// Better - prefix with underscore
function handleMessage(message, _sender, _sendResponse) {
  console.log(message);
}
```

## CI/CD Integration

To add linting to CI/CD pipeline, add to your workflow:

```yaml
# .github/workflows/lint.yml
name: Lint
on: [push, pull_request]
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npm install
      - run: npm run lint
```

## Customizing Rules

To modify linting rules, edit [`.eslintrc.json`](.eslintrc.json):

**Disable a rule**:
```json
{
  "rules": {
    "no-console": "off"
  }
}
```

**Change severity**:
```json
{
  "rules": {
    "semi": ["error", "always"],  // Error instead of warning
    "quotes": "off"  // Disable entirely
  }
}
```

**Rule severity levels**:
- `"off"` or `0` - Disabled
- `"warn"` or `1` - Warning (doesn't fail build)
- `"error"` or `2` - Error (fails build)

## Pre-commit Hook (Optional)

To automatically lint before committing, install Husky:

```bash
npm install --save-dev husky lint-staged
npx husky install
```

Add to `package.json`:
```json
{
  "lint-staged": {
    "*.js": ["eslint --fix", "git add"]
  }
}
```

Create pre-commit hook:
```bash
npx husky add .husky/pre-commit "npx lint-staged"
```

Now ESLint runs automatically before each commit!

## Files Created

| File | Purpose |
|------|---------|
| `package.json` | npm configuration and scripts |
| `.eslintrc.json` | ESLint rules configuration |
| `.eslintignore` | Files/folders to skip linting |
| `.vscode/settings.json` | VS Code integration |
| `.vscode/extensions.json` | Recommended extensions |
| `LINTING-SETUP.md` | This guide |

## Ignored Files

The following are excluded from linting (see `.eslintignore`):
- `node_modules/`
- `*.backup.js` files
- `docs/` directory
- Third-party libraries (`hera-compression-analyzer.js`, `pako.js`)
- Debug scripts (`DEBUG-*.js`)

## Troubleshooting

### ESLint Not Working in VS Code

1. **Install ESLint extension**: `Cmd+Shift+X` → Search "ESLint" → Install
2. **Reload VS Code**: `Cmd+Shift+P` → "Reload Window"
3. **Check output**: `Cmd+Shift+U` → Select "ESLint" from dropdown
4. **Verify config**: Run `npm run lint` in terminal

### "Cannot find module 'eslint'"

```bash
# Install dependencies
npm install
```

### "Parsing error: The keyword 'import' is reserved"

Your `.eslintrc.json` is missing `"sourceType": "module"`. Already fixed in provided config.

### Linting is Too Slow

```bash
# Lint specific directories only
npm run lint:modules

# Or disable watch mode
# (Don't use npm run lint:watch)
```

## Best Practices

1. **Run lint before committing**:
   ```bash
   npm run lint:fix
   git add .
   git commit -m "fix: linting issues"
   ```

2. **Fix errors first, then warnings**:
   - Errors (red) - Must fix
   - Warnings (yellow) - Should fix

3. **Use auto-fix when possible**:
   ```bash
   npm run lint:fix
   ```

4. **Don't commit with linting errors**:
   - Fix errors before pushing
   - Warnings are acceptable (but should be addressed)

5. **Review auto-fixes**:
   - Auto-fix can change behavior
   - Always review changes before committing

## Resources

- [ESLint Rules](https://eslint.org/docs/rules/)
- [Chrome Extension Best Practices](https://developer.chrome.com/docs/extensions/mv3/intro/mv3-overview/)
- [WebExtensions API](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions)

## Next Steps

1. **Install dependencies**: `npm install`
2. **Run linting**: `npm run lint`
3. **Fix auto-fixable issues**: `npm run lint:fix`
4. **Review remaining warnings**: Address manually
5. **Commit**: `git add . && git commit -m "feat: add ESLint configuration"`

---

**Status**: ✅ Linting fully configured and ready to use!
