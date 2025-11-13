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
      // Coverage thresholds (gradual increase to industry standards)
      // Phase 1: Match current coverage, prevent regression
      // Target (Week 8): 70% overall, 85% security modules
      thresholds: {
        lines: 10,
        functions: 10,
        branches: 10,
        statements: 10,
        // Per-file thresholds for tested modules
        // These will increase as new tests are added (see ACTION_PLAN.md)
        'modules/auth/**/*.js': {
          lines: 70,
          functions: 69,
          branches: 64,
          statements: 69
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
