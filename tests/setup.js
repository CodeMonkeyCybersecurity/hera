// Global test setup for Vitest
import { vi } from 'vitest';
import { chromeMock } from './mocks/chrome.js';

// Setup Chrome API mock
global.chrome = chromeMock;

// Setup browser globals
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;

// Setup crypto API (Web Crypto API)
if (!global.crypto) {
  const { webcrypto } = await import('crypto');
  global.crypto = webcrypto;
}

// Setup atob/btoa if not available
if (typeof global.atob === 'undefined') {
  global.atob = (str) => Buffer.from(str, 'base64').toString('binary');
}
if (typeof global.btoa === 'undefined') {
  global.btoa = (str) => Buffer.from(str, 'binary').toString('base64');
}

// Mock console methods to reduce noise in tests
global.console = {
  ...console,
  log: vi.fn(),
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn()
};
