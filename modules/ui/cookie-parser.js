/**
 * Cookie Parser
 * Parse Cookie and Set-Cookie headers
 */

export const CookieParser = {
  /**
   * Parse Cookie header value
   * @param {string} cookieString - Cookie header value
   * @returns {Map} Map of cookie name to value
   */
  parseCookieHeader: (cookieString) => {
    const cookies = new Map();
    if (!cookieString) return cookies;

    cookieString.split(';').forEach(cookie => {
      const [name, value] = cookie.trim().split('=');
      if (name && value) {
        cookies.set(name.trim(), decodeURIComponent(value.trim()));
      }
    });

    return cookies;
  },

  /**
   * Parse Set-Cookie header value
   * @param {string} setCookieString - Set-Cookie header value
   * @returns {Object|null} Parsed cookie object or null
   */
  parseSetCookieHeader: (setCookieString) => {
    if (!setCookieString) return null;

    const parts = setCookieString.split(';').map(part => part.trim());
    const [name, value] = parts[0].split('=');

    if (!name || value === undefined) return null;

    const cookie = {
      name: name.trim(),
      value: value ? decodeURIComponent(value.trim()) : '',
      secure: false,
      httpOnly: false,
      sameSite: null
    };

    // Parse attributes
    parts.slice(1).forEach(part => {
      const [attr, attrValue] = part.split('=');
      const attrName = attr.toLowerCase();

      switch (attrName) {
        case 'secure':
          cookie.secure = true;
          break;
        case 'httponly':
          cookie.httpOnly = true;
          break;
        case 'samesite':
          cookie.sameSite = attrValue || 'true';
          break;
      }
    });

    return cookie;
  }
};
