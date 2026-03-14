import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Test environment
    environment: 'jsdom',

    // Global test setup
    setupFiles: ['./tests/setup.js'],

    // Coverage configuration
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html', 'lcov'],
      exclude: [
        'node_modules/**',
        'tests/**',
        '*.config.js',
        'scripts/**',
        'lib/**', // External libraries
        'icons/**',
        'devtools/**'
      ],
      include: [
        'modules/**/*.js',
        'background.js',
        'content-script.js',
        'popup.js',
        'evidence-collector.js'
      ],
      // Coverage thresholds: ratchet strategy — thresholds = actual coverage to prevent regression.
      // Raise these as new tests are added (see follow-up issues for untested modules).
      // Global actual: ~10% (most modules untested — tracked as P2 follow-up)
      // Auth modules actual: ~31% aggregate (17 of 25 files still at 0% — tracked as P2)
      // Per-file actuals after fix/1 (2026-03-14):
      //   auth-issue-database.js: 99.18% stmts / 97.59% branches / 100% funcs / 100% lines
      //   auth-util-functions.js: 97.08% stmts / 89% branches / 100% funcs / 97% lines
      //   oauth2-analyzer.js:     98.61% stmts / 96.52% branches / 100% funcs / 98.52% lines
      thresholds: {
        lines: 8,
        functions: 8,
        branches: 8,
        statements: 8,
        'modules/auth/auth-issue-database.js': {
          lines: 99,
          functions: 100,
          branches: 97,
          statements: 99
        },
        'modules/auth/auth-util-functions.js': {
          lines: 96,
          functions: 100,
          branches: 88,
          statements: 96
        },
        'modules/auth/oauth2-analyzer.js': {
          lines: 98,
          functions: 100,
          branches: 96,
          statements: 98
        },
        'modules/auth/**/*.js': {
          lines: 30,
          functions: 30,
          branches: 25,
          statements: 30
        }
      },
      // Enable per-file coverage tracking
      perFile: true
    },

    // Test file patterns
    include: [
      'tests/**/*.test.js',
      'tests/**/*.spec.js'
    ],

    // Globals
    globals: true,

    // Test timeout
    testTimeout: 10000,

    // Concurrency
    threads: true,

    // Reporter
    reporter: ['verbose', 'html'],

    // Mock reset
    clearMocks: true,
    mockReset: true,
    restoreMocks: true
  }
});
