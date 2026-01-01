// eslint.config.js - ESLint flat configuration for Hera Chrome Extension
// See docs/adr/ADR-001-eslint-config-format.md for rationale
// Using flat config format to prevent global config interference

import js from '@eslint/js';
import globals from 'globals';

export default [
  // Base configuration
  js.configs.recommended,

  // Global ignores
  {
    ignores: ['node_modules/**', 'dist/**', 'coverage/**']
  },

  // Default configuration for all JS files
  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.es2021,
        chrome: 'readonly'
      }
    },
    rules: {
      // Error Prevention
      'no-unused-vars': ['warn', {
        argsIgnorePattern: '^_',
        varsIgnorePattern: '^_'
      }],
      'no-undef': 'error',
      'no-console': 'off',
      'no-debugger': 'warn',
      'no-constant-condition': ['error', { checkLoops: false }],

      // Async/Await Best Practices
      'require-await': 'warn',
      'no-async-promise-executor': 'error',
      'no-await-in-loop': 'warn',

      // Code Quality
      'no-var': 'error',
      'prefer-const': 'warn',
      'prefer-arrow-callback': 'warn',
      'eqeqeq': ['error', 'always', { null: 'ignore' }],
      'curly': ['error', 'all'],
      'no-eval': 'error',
      'no-implied-eval': 'error',

      // Security
      'no-new-func': 'error',
      'no-script-url': 'error',

      // Style (warnings only)
      'semi': ['warn', 'always'],
      'quotes': ['warn', 'single', { avoidEscape: true, allowTemplateLiterals: true }],
      'indent': ['warn', 2, { SwitchCase: 1 }],
      'comma-dangle': ['warn', 'never'],
      'arrow-spacing': 'warn',
      'space-before-function-paren': ['warn', {
        anonymous: 'always',
        named: 'never',
        asyncArrow: 'always'
      }]
    }
  },

  // Background script - service worker context
  {
    files: ['background.js', 'modules/background/**/*.js'],
    rules: {
      'no-restricted-globals': ['error', {
        name: 'window',
        message: "Service workers don't have window. Use self instead."
      }, {
        name: 'document',
        message: "Service workers don't have document. Use chrome.scripting API."
      }]
    }
  },

  // Content scripts - DOM access allowed
  {
    files: ['content-script.js', 'modules/content/**/*.js'],
    languageOptions: {
      globals: {
        document: 'readonly',
        window: 'readonly'
      }
    }
  },

  // Popup and UI scripts - DOM access allowed
  {
    files: ['popup.js', 'modules/ui/**/*.js'],
    languageOptions: {
      globals: {
        document: 'readonly',
        window: 'readonly'
      }
    }
  },

  // Test files
  {
    files: ['**/test/**/*.js', '**/*.test.js', '**/*.spec.js'],
    languageOptions: {
      globals: {
        ...globals.mocha,
        ...globals.jest,
        describe: 'readonly',
        it: 'readonly',
        expect: 'readonly',
        beforeEach: 'readonly',
        afterEach: 'readonly',
        vi: 'readonly'
      }
    }
  }
];
