// Security Input Validation Utilities
// Prevents injection attacks and validates untrusted input

export const SecurityValidation = {
  // Sanitize URLs for safe processing
  sanitizeURL: (url) => {
    if (typeof url !== 'string') return '';
    try {
      const urlObj = new URL(url);
      // Only allow http/https protocols
      if (!['http:', 'https:'].includes(urlObj.protocol)) {
        return '';
      }
      return url;
    } catch (e) {
      return '';
    }
  },

  // Validate and sanitize headers
  sanitizeHeaders: (headers) => {
    if (!Array.isArray(headers)) return [];
    return headers.filter(header => {
      return (
        header &&
        typeof header.name === 'string' &&
        typeof header.value === 'string' &&
        header.name.length < 1000 &&
        header.value.length < 10000
      );
    }).map(header => ({
      name: header.name.toLowerCase().trim(),
      value: header.value.trim()
    }));
  },

  // Validate request body size and content
  validateRequestBody: (body) => {
    if (!body) return null;

    // Limit body size (10MB max)
    const MAX_BODY_SIZE = 10 * 1024 * 1024;
    if (typeof body === 'string' && body.length > MAX_BODY_SIZE) {
      return body.substring(0, MAX_BODY_SIZE) + '[TRUNCATED]';
    }
    return body;
  },

  // Validate and sanitize domain names
  sanitizeDomain: (domain) => {
    if (typeof domain !== 'string') return '';

    // Basic domain validation
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/;
    if (!domainRegex.test(domain) || domain.length > 253) {
      return '';
    }
    return domain.toLowerCase();
  },

  // Rate limiting for request processing
  rateLimiter: {
    requestCounts: new Map(),
    MAX_REQUESTS_PER_MINUTE: 1000,

    checkRateLimit: (clientId) => {
      const now = Date.now();
      const windowStart = now - 60000; // 1 minute window

      if (!SecurityValidation.rateLimiter.requestCounts.has(clientId)) {
        SecurityValidation.rateLimiter.requestCounts.set(clientId, []);
      }

      const requests = SecurityValidation.rateLimiter.requestCounts.get(clientId);

      // Remove old requests outside the window
      const validRequests = requests.filter(timestamp => timestamp > windowStart);

      if (validRequests.length >= SecurityValidation.rateLimiter.MAX_REQUESTS_PER_MINUTE) {
        return false; // Rate limit exceeded
      }

      validRequests.push(now);
      SecurityValidation.rateLimiter.requestCounts.set(clientId, validRequests);
      return true;
    }
  },

  // Validate JWT tokens before processing
  validateJWTInput: (token) => {
    if (typeof token !== 'string') return null;

    // Basic JWT structure validation
    const parts = token.split('.');
    if (parts.length !== 3) return null;

    // Check each part is valid base64url
    for (const part of parts) {
      if (!/^[A-Za-z0-9_-]+$/.test(part)) {
        return null;
      }
    }

    // Reasonable length limits
    if (token.length > 10000) return null;

    return token;
  }
};
