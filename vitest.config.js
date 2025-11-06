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
      // Coverage thresholds (adjusted for current test coverage)
      // TODO: Increase as more tests are added
      thresholds: {
        lines: 5,
        functions: 5,
        branches: 5,
        statements: 5
      },
      // Per-file thresholds for tested modules
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
