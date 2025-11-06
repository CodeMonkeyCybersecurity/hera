// Test utility functions and helpers
import { vi } from 'vitest';

/**
 * Create a mock JWT token
 * @param {Object} header - JWT header
 * @param {Object} payload - JWT payload
 * @returns {string} JWT token string
 */
export function createMockJWT(header = {}, payload = {}) {
  const defaultHeader = { alg: 'RS256', typ: 'JWT', ...header };
  const defaultPayload = {
    sub: 'test-user-123',
    iss: 'https://issuer.example.com',
    aud: 'test-client-id',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    ...payload
  };

  const h = btoa(JSON.stringify(defaultHeader)).replace(/=/g, '');
  const p = btoa(JSON.stringify(defaultPayload)).replace(/=/g, '');
  return `${h}.${p}.mock-signature`;
}

/**
 * Create mock HTTP headers
 * @param {Object} headers - Custom headers
 * @returns {Array} Array of header objects
 */
export function createMockHeaders(headers = {}) {
  return Object.entries(headers).map(([name, value]) => ({ name, value }));
}

/**
 * Create mock Chrome webRequest details
 * @param {Object} options - Request options
 * @returns {Object} Mock request details
 */
export function createMockWebRequest(options = {}) {
  return {
    requestId: options.requestId || 'mock-request-123',
    url: options.url || 'https://example.com/api',
    method: options.method || 'GET',
    frameId: options.frameId || 0,
    parentFrameId: options.parentFrameId || -1,
    tabId: options.tabId || 1,
    type: options.type || 'xmlhttprequest',
    timeStamp: options.timeStamp || Date.now(),
    requestHeaders: options.requestHeaders || [],
    responseHeaders: options.responseHeaders || [],
    statusCode: options.statusCode || 200,
    statusLine: options.statusLine || 'HTTP/1.1 200 OK',
    ...options
  };
}

/**
 * Create mock OAuth2 token response
 * @param {Object} options - Token options
 * @returns {Object} Token response
 */
export function createMockTokenResponse(options = {}) {
  return {
    access_token: options.access_token || createMockJWT(),
    token_type: options.token_type || 'Bearer',
    expires_in: options.expires_in || 3600,
    refresh_token: options.refresh_token || undefined,
    scope: options.scope || 'openid profile email',
    id_token: options.id_token || undefined,
    ...options
  };
}

/**
 * Create mock OIDC token response with ID token
 * @param {Object} options - Token options
 * @returns {Object} OIDC token response
 */
export function createMockOIDCTokenResponse(options = {}) {
  const idTokenPayload = {
    sub: 'user-123',
    iss: 'https://issuer.example.com',
    aud: 'client-id',
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000),
    ...options.idTokenPayload
  };

  return createMockTokenResponse({
    id_token: createMockJWT({}, idTokenPayload),
    ...options
  });
}

/**
 * Wait for async operations to complete
 * @param {number} ms - Milliseconds to wait
 */
export function wait(ms = 0) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Create a mock response body
 * @param {Object} body - Response body object
 * @returns {string} JSON string
 */
export function createMockResponseBody(body) {
  return JSON.stringify(body);
}

/**
 * Mock crypto.subtle.digest for testing
 * @param {string} algorithm - Hash algorithm
 * @param {ArrayBuffer} data - Data to hash
 * @returns {Promise<ArrayBuffer>} Hash result
 */
export async function mockDigest(algorithm, data) {
  // Simple mock that returns predictable hash for testing
  const encoder = new TextEncoder();
  const mockHash = encoder.encode(`mock-hash-${algorithm}`);
  return mockHash.buffer;
}

/**
 * Create mock Chrome storage data
 * @param {Object} data - Storage data
 */
export function createMockStorageData(data = {}) {
  return {
    evidence: [],
    analysisResults: [],
    settings: {
      debugMode: false,
      enabledAnalyzers: [],
      ...data.settings
    },
    ...data
  };
}

/**
 * Assert that an issue has expected properties
 * @param {Object} issue - Issue object
 * @param {Object} expected - Expected properties
 */
export function assertIssue(issue, expected) {
  if (!issue) {
    throw new Error('Issue is undefined or null');
  }

  if (expected.type && issue.type !== expected.type) {
    throw new Error(`Expected issue type ${expected.type}, got ${issue.type}`);
  }

  if (expected.severity && issue.severity !== expected.severity) {
    throw new Error(`Expected severity ${expected.severity}, got ${issue.severity}`);
  }

  if (expected.cvss !== undefined && issue.cvss !== expected.cvss) {
    throw new Error(`Expected CVSS ${expected.cvss}, got ${issue.cvss}`);
  }

  return true;
}

/**
 * Create mock URL with query parameters
 * @param {string} base - Base URL
 * @param {Object} params - Query parameters
 * @returns {string} Full URL
 */
export function createMockURL(base, params = {}) {
  const url = new URL(base);
  Object.entries(params).forEach(([key, value]) => {
    url.searchParams.set(key, value);
  });
  return url.href;
}

/**
 * Mock console methods for testing
 */
export function mockConsole() {
  return {
    log: vi.fn(),
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn()
  };
}

/**
 * Calculate at_hash or c_hash for testing
 * @param {string} value - Value to hash (access_token or code)
 * @param {string} algorithm - JWT algorithm
 * @returns {Promise<string>} Base64url encoded hash
 */
export async function calculateHash(value, algorithm = 'RS256') {
  const hashAlg = algorithm.endsWith('256') ? 'SHA-256' :
                  algorithm.endsWith('384') ? 'SHA-384' :
                  algorithm.endsWith('512') ? 'SHA-512' : 'SHA-256';

  const encoder = new TextEncoder();
  const data = encoder.encode(value);
  const hashBuffer = await crypto.subtle.digest(hashAlg, data);
  const hashArray = new Uint8Array(hashBuffer);
  const halfLength = Math.floor(hashArray.length / 2);
  const leftHalf = hashArray.slice(0, halfLength);

  return btoa(String.fromCharCode(...leftHalf))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}
