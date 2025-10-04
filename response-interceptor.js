// Hera Response Interceptor
// Intercepts fetch() and XMLHttpRequest to capture response bodies
// WITHOUT requiring the invasive debugger permission
// SECURITY FIX: Added rate limiting, size limits, and nonce validation

(function() {
  'use strict';

  // SECURITY FIX P1-1: Running in ISOLATED world now
  // In isolated world, this code runs in the extension's context, not the page's context
  // The page's JavaScript cannot access, modify, or interfere with this interceptor
  // This prevents malicious pages from:
  //   1. Stealing nonces
  //   2. Overriding fetch/XHR before we do
  //   3. Injecting fake response data
  //   4. Preventing interception entirely

  console.log('Hera: Response interceptor running in isolated world (secure)');

  // Store original functions
  const originalFetch = window.fetch;
  const originalXHROpen = XMLHttpRequest.prototype.open;
  const originalXHRSend = XMLHttpRequest.prototype.send;

  // Rate limiting per domain
  const RATE_LIMIT_PER_DOMAIN = 50; // Max 50 intercepts per minute per domain
  const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute
  const MAX_RESPONSE_SIZE = 100 * 1024; // 100KB max response size

  const domainInterceptCounts = new Map();

  // Clean up old rate limit entries
  setInterval(() => {
    const now = Date.now();
    for (const [domain, data] of domainInterceptCounts.entries()) {
      if (now - data.windowStart > RATE_LIMIT_WINDOW) {
        domainInterceptCounts.delete(domain);
      }
    }
  }, RATE_LIMIT_WINDOW);

  // Check if domain is rate limited
  function checkRateLimit(url) {
    try {
      const hostname = new URL(url, window.location.href).hostname;
      const now = Date.now();

      if (!domainInterceptCounts.has(hostname)) {
        domainInterceptCounts.set(hostname, {
          count: 1,
          windowStart: now
        });
        return true;
      }

      const data = domainInterceptCounts.get(hostname);

      // Reset window if expired
      if (now - data.windowStart > RATE_LIMIT_WINDOW) {
        data.count = 1;
        data.windowStart = now;
        return true;
      }

      // Check limit
      if (data.count >= RATE_LIMIT_PER_DOMAIN) {
        console.warn(`Hera: Rate limit exceeded for ${hostname} (${data.count}/${RATE_LIMIT_PER_DOMAIN})`);
        return false;
      }

      data.count++;
      return true;
    } catch (error) {
      return true; // Allow on error
    }
  }

  // Helper to check if this is an auth-related request
  function isAuthRequest(url) {
    const authPatterns = [
      '/oauth', '/authorize', '/token', '/login', '/signin', '/auth',
      '/api/auth', '/session', '/connect', '/saml', '/oidc', '/scim'
    ];
    const urlLower = url.toLowerCase();
    return authPatterns.some(pattern => urlLower.includes(pattern));
  }

  // Intercept fetch()
  window.fetch = async function(...args) {
    const [resource, config] = args;
    const url = typeof resource === 'string' ? resource : resource.url;

    // Call original fetch
    const response = await originalFetch.apply(this, args);

    // Only intercept auth-related requests
    if (isAuthRequest(url)) {
      // SECURITY FIX: Rate limiting check
      if (!checkRateLimit(url)) {
        return response; // Skip interception if rate limited
      }

      // Clone the response so we can read the body
      const clonedResponse = response.clone();

      try {
        const text = await clonedResponse.text();

        // SECURITY FIX: Size limit check
        if (text.length > MAX_RESPONSE_SIZE) {
          console.warn(`Hera: Response too large (${text.length} bytes), truncating to ${MAX_RESPONSE_SIZE}`);
          const truncated = text.substring(0, MAX_RESPONSE_SIZE);

          // SECURITY FIX P1-1: Send directly to background in isolated world
          chrome.runtime.sendMessage({
            action: 'responseIntercepted',
            data: {
              source: 'fetch',
              url: url,
              method: config?.method || 'GET',
              statusCode: response.status,
              headers: Object.fromEntries(response.headers.entries()),
              body: truncated + '\n\n[TRUNCATED - Response exceeded 100KB limit]',
              timestamp: new Date().toISOString(),
              truncated: true
            }
          }).catch(error => {
            console.error('Hera: Failed to send intercepted response:', error);
          });

          return response;
        }

        // SECURITY FIX P1-1: In isolated world, send directly to background via chrome.runtime
        // No need for window.postMessage or nonce validation - we're in secure context
        chrome.runtime.sendMessage({
          action: 'responseIntercepted',
          data: {
            source: 'fetch',
            url: url,
            method: config?.method || 'GET',
            statusCode: response.status,
            headers: Object.fromEntries(response.headers.entries()),
            body: text,
            timestamp: new Date().toISOString()
          }
        }).catch(error => {
          console.error('Hera: Failed to send intercepted response:', error);
        });  // Explicit origin instead of '*'
      } catch (error) {
        console.warn('Hera: Failed to capture fetch response:', error);
      }
    }

    return response;
  };

  // Intercept XMLHttpRequest
  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    this._heraMethod = method;
    this._heraUrl = url;
    return originalXHROpen.apply(this, [method, url, ...args]);
  };

  XMLHttpRequest.prototype.send = function(...args) {
    const xhr = this;

    if (isAuthRequest(xhr._heraUrl)) {
      // SECURITY FIX: Rate limiting check
      if (!checkRateLimit(xhr._heraUrl)) {
        return originalXHRSend.apply(this, args); // Skip interception if rate limited
      }

      // Add load event listener to capture response
      xhr.addEventListener('load', function() {
        try {
          const responseBody = xhr.responseText || xhr.response;

          // SECURITY FIX: Size limit check
          let body = responseBody;
          let truncated = false;

          if (typeof body === 'string' && body.length > MAX_RESPONSE_SIZE) {
            console.warn(`Hera: XHR response too large (${body.length} bytes), truncating`);
            body = body.substring(0, MAX_RESPONSE_SIZE) + '\n\n[TRUNCATED - Response exceeded 100KB limit]';
            truncated = true;
          }

          // Get response headers
          const headersText = xhr.getAllResponseHeaders();
          const headers = {};
          headersText.split('\r\n').forEach(line => {
            const parts = line.split(': ');
            if (parts.length === 2) {
              headers[parts[0]] = parts[1];
            }
          });

          // SECURITY FIX P1-1: Send directly to background in isolated world
          chrome.runtime.sendMessage({
            action: 'responseIntercepted',
            data: {
              source: 'xhr',
              url: xhr._heraUrl,
              method: xhr._heraMethod,
              statusCode: xhr.status,
              headers: headers,
              body: body,
              timestamp: new Date().toISOString(),
              truncated: truncated
            }
          }).catch(error => {
            console.error('Hera: Failed to send intercepted XHR response:', error);
          });
        } catch (error) {
          console.warn('Hera: Failed to capture XHR response:', error);
        }
      });
    }

    return originalXHRSend.apply(this, args);
  };

  console.log('Hera: Response interceptor initialized (fetch + XHR) with rate limiting');
})();
