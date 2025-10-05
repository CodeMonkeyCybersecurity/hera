/**
 * URL Utilities
 *
 * Pure functions for URL parsing, validation, and analysis.
 * No external dependencies, fully testable.
 */

/**
 * Analyze URL components for security insights
 *
 * @param {string} url - URL to analyze
 * @returns {Object} Analysis results
 * @property {string} protocol - URL protocol (http:, https:, etc.)
 * @property {string} hostname - Domain name
 * @property {string} port - Port number (if specified)
 * @property {string} pathname - URL path
 * @property {string} search - Query string
 * @property {string} hash - Fragment identifier
 * @property {number} parameterCount - Number of query parameters
 * @property {boolean} hasFragment - Whether URL has a fragment
 * @property {boolean} hasSensitiveParams - Whether URL contains sensitive parameters
 * @property {string[]} suspiciousPatterns - Array of detected suspicious patterns
 *
 * @example
 * analyzeUrl('https://example.com/api?token=abc123#section')
 * // Returns: { protocol: 'https:', hostname: 'example.com', ... }
 */
export function analyzeUrl(url) {
  try {
    const urlObj = new URL(url);
    const params = new URLSearchParams(urlObj.search);

    return {
      protocol: urlObj.protocol,
      hostname: urlObj.hostname,
      port: urlObj.port,
      pathname: urlObj.pathname,
      search: urlObj.search,
      hash: urlObj.hash,
      parameterCount: params.size,
      hasFragment: urlObj.hash.length > 0,
      hasSensitiveParams: hasSensitiveParameters(params),
      suspiciousPatterns: detectSuspiciousUrlPatterns(url)
    };
  } catch (e) {
    return { error: 'Invalid URL', url: url };
  }
}

/**
 * Check if URL parameters contain sensitive data
 *
 * SECURITY: Sensitive parameters in URLs are logged in server logs,
 * browser history, and referrer headers
 *
 * @param {URLSearchParams} params - URL search parameters
 * @returns {boolean} True if sensitive parameters detected
 *
 * @example
 * const params = new URLSearchParams('?access_token=secret&name=john')
 * hasSensitiveParameters(params) // Returns true
 */
export function hasSensitiveParameters(params) {
  const sensitiveParams = [
    'access_token', 'id_token', 'refresh_token', 'code', 'password',
    'client_secret', 'api_key', 'token', 'auth', 'session'
  ];

  for (const [key] of params) {
    if (sensitiveParams.some(sensitive => key.toLowerCase().includes(sensitive))) {
      return true;
    }
  }
  return false;
}

/**
 * Detect suspicious URL patterns (phishing, typosquatting, etc.)
 *
 * @param {string} url - URL to check
 * @returns {string[]} Array of detected pattern types
 *
 * @example
 * detectSuspiciousUrlPatterns('http://oauth.sketchy-site.tk')
 * // Returns ['non_standard_oauth_domain', 'suspicious_tld']
 */
export function detectSuspiciousUrlPatterns(url) {
  // P2-EIGHTH-1 FIX: Limit URL length to prevent ReDoS
  const MAX_URL_LENGTH = 2000; // RFC 2616 suggests 2KB limit

  const patterns = [];

  // P1-TENTH-5 FIX: Flag oversized URLs as suspicious instead of silently truncating
  // Attack: Attacker hides malicious params after 2000 chars to bypass detection
  if (url.length > MAX_URL_LENGTH) {
    console.warn(`Hera SECURITY: URL exceeds safe length (${url.length} > ${MAX_URL_LENGTH})`);
    patterns.push('url_too_long'); // Flag as suspicious
    url = url.substring(0, MAX_URL_LENGTH); // Still analyze truncated version
  }

  const lowerUrl = url.toLowerCase();

  // Check for common phishing patterns
  if (lowerUrl.includes('oauth') && !lowerUrl.includes('googleapis.com') &&
      !lowerUrl.includes('microsoft.com') && !lowerUrl.includes('github.com')) {
    patterns.push('non_standard_oauth_domain');
  }

  // Check for URL shorteners
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly'];
  if (shorteners.some(shortener => lowerUrl.includes(shortener))) {
    patterns.push('url_shortener');
  }

  // Check for suspicious TLDs
  const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf'];
  if (suspiciousTlds.some(tld => lowerUrl.includes(tld))) {
    patterns.push('suspicious_tld');
  }

  return patterns;
}

/**
 * Check if request is cross-origin
 *
 * @param {string} initiator - Request initiator URL
 * @param {string} targetUrl - Target URL
 * @returns {boolean} True if cross-origin
 *
 * @example
 * isCrossOrigin('https://example.com', 'https://api.example.com')
 * // Returns true (different subdomain = different origin)
 */
export function isCrossOrigin(initiator, targetUrl) {
  if (!initiator) return false;

  try {
    const initiatorUrl = new URL(initiator);
    const targetUrlObj = new URL(targetUrl);

    return initiatorUrl.origin !== targetUrlObj.origin;
  } catch (e) {
    return false;
  }
}

/**
 * Check if request is from an extension
 *
 * @param {string} initiator - Request initiator URL
 * @returns {boolean} True if from extension
 */
export function isExtensionRequest(initiator) {
  return initiator && initiator.startsWith('chrome-extension://');
}

/**
 * Check if request is third-party (different domain)
 *
 * @param {string} requestUrl - Request URL
 * @param {string} initiatorUrl - Initiator URL
 * @returns {boolean} True if third-party
 */
export function isThirdPartyRequest(requestUrl, initiatorUrl) {
  if (!initiatorUrl) return false;
  try {
    const reqHostname = new URL(requestUrl).hostname;
    const initHostname = new URL(initiatorUrl).hostname;
    // Check if it's not the same domain or a subdomain
    return !reqHostname.endsWith(initHostname);
  } catch (e) {
    return false;
  }
}

/**
 * Check if URL path contains sensitive keywords
 *
 * @param {string} path - URL path to check
 * @returns {boolean} True if path is sensitive
 */
export function isSensitivePath(path) {
  const sensitiveKeywords = [
    'admin', 'user', 'account', 'profile', 'settings', 'wallet', 'billing',
    'export', 'import', 'download', 'upload', 'delete', 'update', 'edit', 'create',
    'private', 'sensitive', 'internal', 'debug'
  ];
  const lowerPath = path.toLowerCase();
  return sensitiveKeywords.some(keyword => lowerPath.includes(`/${keyword}`));
}

/**
 * Validate probe request for SSRF protection
 *
 * SECURITY: Prevents Server-Side Request Forgery attacks by blocking:
 * - Private IP addresses (RFC1918, loopback, link-local)
 * - Metadata endpoints (AWS, GCP, Azure, Alibaba)
 * - Non-HTTP/HTTPS protocols
 * - Cross-origin requests
 *
 * @param {string} requestUrl - Target URL to validate
 * @param {string} senderTabUrl - Sender tab URL for origin check
 * @returns {Object} Validation result
 * @property {boolean} valid - Whether request is safe
 * @property {string} [error] - Error message if invalid
 *
 * @example
 * validateProbeRequest('http://169.254.169.254/metadata', 'https://example.com')
 * // Returns { valid: false, error: 'Blocked internal/metadata endpoint' }
 */
export function validateProbeRequest(requestUrl, senderTabUrl) {
  try {
    const targetUrl = new URL(requestUrl);

    // Block private/internal IP ranges (SSRF prevention)
    const blockedHosts = [
      'localhost', '127.0.0.1', '0.0.0.0', '[::]', '[::1]',
      '169.254.169.254',  // AWS metadata
      '169.254.170.2',    // ECS metadata
      '100.100.100.200',  // Alibaba metadata
      'metadata.google.internal',  // GCP metadata
    ];

    const hostname = targetUrl.hostname.toLowerCase();

    // Block exact matches
    if (blockedHosts.includes(hostname)) {
      return { valid: false, error: 'Blocked internal/metadata endpoint' };
    }

    // Block private IP ranges (RFC1918, link-local, loopback)
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(hostname)) {
      const parts = hostname.split('.').map(Number);
      // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16
      if (parts[0] === 10 ||
          parts[0] === 127 ||
          (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
          (parts[0] === 192 && parts[1] === 168) ||
          (parts[0] === 169 && parts[1] === 254)) {
        return { valid: false, error: 'Blocked private IP address' };
      }
    }

    // P1-EIGHTH-3 FIX: Block IPv6 loopback and private ranges
    if (hostname.startsWith('[') && hostname.endsWith(']')) {
      const ipv6 = hostname.slice(1, -1).toLowerCase();

      // Block loopback (::1 and 0:0:0:0:0:0:0:1)
      if (ipv6 === '::1' || ipv6 === '0:0:0:0:0:0:0:1') {
        return { valid: false, error: 'Blocked IPv6 loopback address' };
      }

      // Block link-local (fe80::/10)
      if (ipv6.startsWith('fe80:')) {
        return { valid: false, error: 'Blocked IPv6 link-local address' };
      }

      // Block unique local addresses (fc00::/7 and fd00::/8)
      if (ipv6.startsWith('fc') || ipv6.startsWith('fd')) {
        return { valid: false, error: 'Blocked IPv6 private address (ULA)' };
      }

      // Block IPv4-mapped IPv6 addresses (::ffff:192.168.0.1)
      if (ipv6.includes('::ffff:')) {
        const ipv4Part = ipv6.split('::ffff:')[1];
        if (ipv4Part) {
          // Recursively validate the IPv4 part
          const ipv4Validation = validateProbeRequest(`http://${ipv4Part}/`, senderTabUrl);
          if (!ipv4Validation.valid) {
            return { valid: false, error: 'Blocked IPv4-mapped IPv6 private address' };
          }
        }
      }
    }

    // SECURITY FIX P2: Only allow HTTP/HTTPS (prevent protocol smuggling)
    // Block file://, chrome-extension://, about:, data:, javascript:, etc.
    if (targetUrl.protocol !== 'https:' && targetUrl.protocol !== 'http:') {
      return { valid: false, error: `Protocol ${targetUrl.protocol} not allowed (only HTTP/HTTPS)` };
    }

    // Require same-origin as sender tab (prevent cross-origin SSRF)
    if (senderTabUrl) {
      const tabUrl = new URL(senderTabUrl);
      if (targetUrl.origin !== tabUrl.origin) {
        return { valid: false, error: 'Cross-origin probes not allowed' };
      }
    }

    return { valid: true };
  } catch (error) {
    return { valid: false, error: `Invalid URL: ${error.message}` };
  }
}

/**
 * Decode request body from chrome.webRequest format
 *
 * @param {Object} requestBody - Request body from webRequest.onBeforeRequest
 * @returns {string|null} Decoded body or null if decoding fails
 */
export function decodeRequestBody(requestBody) {
  if (!requestBody || !requestBody.raw) return null;
  try {
    const decoder = new TextDecoder('utf-8');
    const decodedParts = requestBody.raw.map(part => {
      if (part.bytes) {
        const byteValues = Object.values(part.bytes);
        return decoder.decode(new Uint8Array(byteValues));
      }
      return '';
    });
    return decodedParts.join('');
  } catch (e) {
    console.error('Hera: Failed to decode request body:', e);
    return '[Hera: Failed to decode body]';
  }
}
