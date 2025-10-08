/**
 * DOM Security Utilities
 * P0-FOURTEENTH-1 FIX: Safe DOM manipulation to prevent XSS
 * 
 * All user-controlled data MUST use these helpers before rendering.
 * 14TH REVIEW: Fixed XSS vulnerabilities in popup.js
 */

export const DOMSecurity = {
  /**
   * Sanitize HTML string to prevent XSS
   * @param {string} str - Raw string to sanitize
   * @returns {string} Sanitized string safe for innerHTML
   */
  sanitizeHTML: (str) => {
    if (typeof str !== 'string') return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  },

  /**
   * Safely set text content on an element
   * @param {HTMLElement} element - Target element
   * @param {string} text - Text to set
   */
  setTextContent: (element, text) => {
    if (!element) return;
    element.textContent = typeof text === 'string' ? text : String(text);
  },

  /**
   * Create element with safe content and attributes
   * @param {string} tag - HTML tag name
   * @param {string} content - Text content (will be sanitized)
   * @param {Object} attributes - Element attributes
   * @returns {HTMLElement} Created element
   */
  createSafeElement: (tag, content, attributes = {}) => {
    const element = document.createElement(tag);
    if (content) {
      element.textContent = content;
    }
    Object.entries(attributes).forEach(([key, value]) => {
      if (key === 'className') {
        element.className = value; // Class names don't need HTML escaping
      } else if (key === 'title') {
        element.setAttribute(key, value); // Title attributes with URLs don't need HTML escaping
      } else {
        element.setAttribute(key, DOMSecurity.sanitizeHTML(value));
      }
    });
    return element;
  },

  /**
   * Clear element and append children safely
   * @param {HTMLElement} parent - Parent element
   * @param {...Node} children - Child nodes to append
   */
  replaceChildren: (parent, ...children) => {
    if (!parent) return;
    parent.innerHTML = '';
    children.forEach(child => {
      if (child instanceof Node) {
        parent.appendChild(child);
      }
    });
  }
};
