/**
 * Cookie Utilities
 *
 * Pure functions for cookie parsing and security analysis.
 * No external dependencies, fully testable.
 */

/**
 * Parse Cookie header to extract individual cookies
 *
 * @param {string} cookieHeader - Raw Cookie header value
 * @returns {Array<Object>} Array of parsed cookies
 * @property {string} name - Cookie name
 * @property {string} value - Cookie value
 * @property {boolean} isSessionToken - Whether cookie appears to be a session token
 * @property {boolean} isAuthToken - Whether cookie appears to be an auth token
 *
 * @example
 * parseCookieHeader('session_id=abc123; token=xyz789')
 * // Returns: [
 * //   { name: 'session_id', value: 'abc123', isSessionToken: true, isAuthToken: false },
 * //   { name: 'token', value: 'xyz789', isSessionToken: false, isAuthToken: true }
 * // ]
 */
export function parseCookieHeader(cookieHeader) {
  const cookies = [];
  const pairs = cookieHeader.split(';');

  pairs.forEach(pair => {
    const [name, value] = pair.trim().split('=');
    if (name && value) {
      cookies.push({
        name: name.trim(),
        value: value.trim(),
        isSessionToken: isSessionCookie(name.trim()),
        isAuthToken: isAuthCookie(name.trim())
      });
    }
  });

  return cookies;
}

/**
 * Analyze Set-Cookie header for security attributes
 *
 * SECURITY: Checks for critical cookie security flags:
 * - HttpOnly: Prevents JavaScript access (XSS protection)
 * - Secure: Requires HTTPS transmission (MitM protection)
 * - SameSite: Prevents CSRF attacks
 *
 * @param {string} setCookieValue - Raw Set-Cookie header value
 * @returns {Object} Cookie analysis
 * @property {string} name - Cookie name
 * @property {string} value - Cookie value
 * @property {Object} attributes - Security and lifecycle attributes
 * @property {number} securityScore - Security score (0-5, higher is better)
 * @property {boolean} isSessionCookie - Whether this is a session cookie
 * @property {boolean} isAuthCookie - Whether this is an auth cookie
 *
 * @example
 * analyzeSetCookie('session=abc123; HttpOnly; Secure; SameSite=Strict')
 * // Returns: {
 * //   name: 'session',
 * //   value: 'abc123',
 * //   attributes: { httpOnly: true, secure: true, sameSite: 'strict', ... },
 * //   securityScore: 5,
 * //   isSessionCookie: true,
 * //   isAuthCookie: false
 * // }
 */
export function analyzeSetCookie(setCookieValue) {
  const analysis = {
    name: null,
    value: null,
    attributes: {
      httpOnly: false,
      secure: false,
      sameSite: null,
      domain: null,
      path: null,
      expires: null,
      maxAge: null
    },
    securityScore: 0,
    isSessionCookie: false,
    isAuthCookie: false
  };

  const parts = setCookieValue.split(';');

  // Parse cookie name and value
  if (parts[0]) {
    const [name, value] = parts[0].trim().split('=');
    analysis.name = name;
    analysis.value = value;
    analysis.isSessionCookie = isSessionCookie(name);
    analysis.isAuthCookie = isAuthCookie(name);
  }

  // Parse attributes
  parts.slice(1).forEach(part => {
    const trimmed = part.trim().toLowerCase();

    if (trimmed === 'httponly') {
      analysis.attributes.httpOnly = true;
      analysis.securityScore += 2;
    } else if (trimmed === 'secure') {
      analysis.attributes.secure = true;
      analysis.securityScore += 2;
    } else if (trimmed.startsWith('samesite=')) {
      analysis.attributes.sameSite = trimmed.split('=')[1];
      analysis.securityScore += 1;
    } else if (trimmed.startsWith('domain=')) {
      analysis.attributes.domain = trimmed.split('=')[1];
    } else if (trimmed.startsWith('path=')) {
      analysis.attributes.path = trimmed.split('=')[1];
    } else if (trimmed.startsWith('expires=')) {
      analysis.attributes.expires = trimmed.split('=')[1];
    } else if (trimmed.startsWith('max-age=')) {
      analysis.attributes.maxAge = trimmed.split('=')[1];
    }
  });

  return analysis;
}

/**
 * Check if cookie name indicates a session cookie
 *
 * Recognizes common session cookie naming patterns from popular frameworks:
 * - Express: connect.sid
 * - Laravel: laravel_session
 * - Django: django_session
 * - PHP: PHPSESSID
 * - Java: JSESSIONID
 * - ASP.NET: ASP.NET_SessionId
 *
 * @param {string} cookieName - Cookie name to check
 * @returns {boolean} True if appears to be a session cookie
 *
 * @example
 * isSessionCookie('JSESSIONID') // Returns true
 * isSessionCookie('user_preferences') // Returns false
 */
export function isSessionCookie(cookieName) {
  const sessionPatterns = [
    'session', 'sess', 'jsessionid', 'phpsessid', 'asp.net_sessionid',
    'connect.sid', 'laravel_session', 'django_session'
  ];

  const lowerName = cookieName.toLowerCase();
  return sessionPatterns.some(pattern => lowerName.includes(pattern));
}

/**
 * Check if cookie name indicates an authentication cookie
 *
 * Recognizes common authentication cookie naming patterns:
 * - JWT tokens
 * - Access/refresh tokens
 * - Bearer tokens
 * - Login/auth cookies
 * - User identity cookies
 *
 * @param {string} cookieName - Cookie name to check
 * @returns {boolean} True if appears to be an auth cookie
 *
 * @example
 * isAuthCookie('access_token') // Returns true
 * isAuthCookie('theme_preference') // Returns false
 */
export function isAuthCookie(cookieName) {
  const authPatterns = [
    'auth', 'token', 'jwt', 'access', 'refresh', 'bearer',
    'login', 'user', 'identity', 'credential'
  ];

  const lowerName = cookieName.toLowerCase();
  return authPatterns.some(pattern => lowerName.includes(pattern));
}
