/**
 * Header Analysis Utilities
 *
 * Pure functions for HTTP header parsing and security analysis.
 * Depends on cookie-utils for cookie parsing.
 */

import { parseCookieHeader, analyzeSetCookie } from './cookie-utils.js';

/**
 * Analyze request headers for authentication and security insights
 *
 * Detects various authentication methods from headers:
 * - Bearer tokens (OAuth/JWT)
 * - Basic authentication
 * - Digest authentication
 * - Kerberos/SPNEGO
 * - NTLM
 * - AWS Signature v4
 * - API keys (various custom headers)
 * - Azure AD tokens
 *
 * @param {Array<Object>} headers - Request headers array
 * @returns {Object} Request header analysis
 * @property {boolean} hasAuthHeaders - Whether auth headers detected
 * @property {string} userAgent - User-Agent header value
 * @property {string} referer - Referer header value
 * @property {string} origin - Origin header value
 * @property {number} cookieCount - Number of cookies in request
 * @property {Array<string>} authMethods - Detected auth methods
 * @property {Array<string>} securityHeaders - Security-related headers
 *
 * @example
 * analyzeRequestHeaders([
 *   { name: 'Authorization', value: 'Bearer eyJhbGc...' },
 *   { name: 'Cookie', value: 'session=abc; token=xyz' }
 * ])
 * // Returns: {
 * //   hasAuthHeaders: true,
 * //   cookieCount: 2,
 * //   authMethods: ['bearer_token'],
 * //   cookieDetails: [...]
 * // }
 */
export function analyzeRequestHeaders(headers) {
  if (!headers) return {};

  const analysis = {
    hasAuthHeaders: false,
    userAgent: null,
    acceptLanguage: null,
    referer: null,
    origin: null,
    cookieCount: 0,
    authMethods: [],
    securityHeaders: []
  };

  headers.forEach(header => {
    const name = header.name.toLowerCase();
    const value = header.value;

    switch (name) {
      case 'authorization':
        analysis.hasAuthHeaders = true;
        if (value.startsWith('Bearer ')) {
          analysis.authMethods.push('bearer_token');
        } else if (value.startsWith('Basic ')) {
          analysis.authMethods.push('basic_auth');
        } else if (value.startsWith('Digest ')) {
          analysis.authMethods.push('digest_auth');
        } else if (value.startsWith('Negotiate ')) {
          analysis.authMethods.push('kerberos_spnego');
        } else if (value.startsWith('NTLM ')) {
          analysis.authMethods.push('ntlm');
        } else if (value.startsWith('AWS4-HMAC-SHA256 ')) {
          analysis.authMethods.push('aws_signature');
        }
        break;
      case 'user-agent':
        analysis.userAgent = value;
        break;
      case 'accept-language':
        analysis.acceptLanguage = value;
        break;
      case 'referer':
        analysis.referer = value;
        break;
      case 'origin':
        analysis.origin = value;
        break;
      case 'cookie':
        analysis.cookieCount = (value.match(/;/g) || []).length + 1;
        analysis.cookieDetails = parseCookieHeader(value);
        break;
      case 'x-requested-with':
        if (value === 'XMLHttpRequest') {
          analysis.securityHeaders.push('ajax_request');
        }
        break;
      case 'x-api-key':
      case 'x-auth-token':
      case 'x-access-token':
        analysis.hasAuthHeaders = true;
        analysis.authMethods.push('api_key');
        break;
      case 'x-amz-security-token':
        analysis.hasAuthHeaders = true;
        analysis.authMethods.push('aws_session_token');
        break;
      case 'x-ms-token-aad-id-token':
      case 'x-ms-token-aad-access-token':
        analysis.hasAuthHeaders = true;
        analysis.authMethods.push('azure_ad_token');
        break;
    }
  });

  return analysis;
}

/**
 * Analyze response headers for security insights
 *
 * SECURITY: Checks for critical security headers:
 * - Strict-Transport-Security (HSTS)
 * - X-Frame-Options (clickjacking protection)
 * - X-Content-Type-Options (MIME sniffing protection)
 * - Content-Security-Policy (XSS protection)
 * - X-XSS-Protection
 * - Referrer-Policy
 *
 * Also analyzes CORS headers and cookie security.
 *
 * @param {Array<Object>} headers - Response headers array
 * @returns {Object} Response header analysis
 * @property {Object} securityHeaders - Detected security headers
 * @property {string} cacheControl - Cache-Control header value
 * @property {string} contentType - Content-Type header value
 * @property {Array<string>} setCookies - Set-Cookie header values
 * @property {Object} corsHeaders - CORS-related headers
 * @property {boolean} hasSecurityHeaders - Whether any security headers present
 *
 * @example
 * analyzeResponseHeaders([
 *   { name: 'Strict-Transport-Security', value: 'max-age=31536000' },
 *   { name: 'Set-Cookie', value: 'session=abc; HttpOnly; Secure' }
 * ])
 * // Returns: {
 * //   hasSecurityHeaders: true,
 * //   securityHeaders: { 'strict-transport-security': 'max-age=31536000' },
 * //   setCookies: ['session=abc; HttpOnly; Secure'],
 * //   cookieAnalysis: [{ securityScore: 4, attributes: {...} }]
 * // }
 */
export function analyzeResponseHeaders(headers) {
  if (!headers) return {};

  const analysis = {
    securityHeaders: {},
    cacheControl: null,
    contentType: null,
    setCookies: [],
    corsHeaders: {},
    hasSecurityHeaders: false
  };

  const securityHeadersToCheck = [
    'strict-transport-security',
    'x-frame-options',
    'x-content-type-options',
    'content-security-policy',
    'x-xss-protection',
    'referrer-policy'
  ];

  headers.forEach(header => {
    const name = header.name.toLowerCase();
    const value = header.value;

    if (securityHeadersToCheck.includes(name)) {
      analysis.securityHeaders[name] = value;
      analysis.hasSecurityHeaders = true;
    }

    switch (name) {
      case 'cache-control':
        analysis.cacheControl = value;
        break;
      case 'content-type':
        analysis.contentType = value;
        break;
      case 'set-cookie':
        analysis.setCookies.push(value);
        const cookieAnalysis = analyzeSetCookie(value);
        if (!analysis.cookieAnalysis) analysis.cookieAnalysis = [];
        analysis.cookieAnalysis.push(cookieAnalysis);
        break;
      case 'access-control-allow-origin':
        analysis.corsHeaders.allowOrigin = value;
        break;
      case 'access-control-allow-credentials':
        analysis.corsHeaders.allowCredentials = value;
        break;
      case 'access-control-allow-methods':
        analysis.corsHeaders.allowMethods = value;
        break;
    }
  });

  return analysis;
}
