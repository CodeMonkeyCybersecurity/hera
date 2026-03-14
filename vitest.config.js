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
      // Global actual: ~9% (most modules untested — tracked as P2 follow-up)
      // Auth modules actual: ~31% (raised to match after auth-issue-database tests added)
      // auth-issue-database.js actual: 99% stmts / 96% branch / 100% funcs (security-critical)
      thresholds: {
        lines: 8,
        functions: 8,
        branches: 8,
        statements: 8,
        'modules/auth/auth-issue-database.js': {
          lines: 95,
          functions: 95,
          branches: 90,
          statements: 95
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
