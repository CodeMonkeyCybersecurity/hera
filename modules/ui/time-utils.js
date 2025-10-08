/**
 * Time Formatting Utilities
 * Human-readable time and duration formatting
 */

import { DOMSecurity } from './dom-security.js';

export const TimeUtils = {
  /**
   * Format timestamp with relative display and full timestamp
   * @param {string|number|Date} timestamp - Timestamp to format
   * @returns {Object} Object with relative, full, and ISO formats
   */
  formatTimeWithRelative: (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMinutes = Math.floor(diffMs / (1000 * 60));
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    let relativeTime;
    if (diffMinutes < 1) {
      relativeTime = 'Just now';
    } else if (diffMinutes < 60) {
      relativeTime = `${diffMinutes}m ago`;
    } else if (diffHours < 24) {
      relativeTime = `${diffHours}h ago`;
    } else if (diffDays < 7) {
      relativeTime = `${diffDays}d ago`;
    } else {
      relativeTime = date.toLocaleDateString();
    }

    return {
      relative: relativeTime,
      full: date.toLocaleString(),
      iso: date.toISOString()
    };
  },

  /**
   * Create a time element with relative display and full timestamp on hover
   * @param {string|number|Date} timestamp - Timestamp
   * @param {string} className - CSS class name
   * @returns {HTMLElement} Time element
   */
  createTimeElement: (timestamp, className = 'time') => {
    const timeInfo = TimeUtils.formatTimeWithRelative(timestamp);
    const element = DOMSecurity.createSafeElement('span', timeInfo.relative, {
      className: className,
      title: timeInfo.full
    });
    return element;
  },

  /**
   * Format duration in human readable format
   * @param {number} durationMs - Duration in milliseconds
   * @returns {string} Formatted duration
   */
  formatDuration: (durationMs) => {
    if (!durationMs || durationMs < 0) return 'Unknown';

    if (durationMs < 1000) {
      return `${Math.round(durationMs)}ms`;
    } else if (durationMs < 60000) {
      return `${(durationMs / 1000).toFixed(1)}s`;
    } else {
      const minutes = Math.floor(durationMs / 60000);
      const seconds = ((durationMs % 60000) / 1000).toFixed(1);
      return `${minutes}m ${seconds}s`;
    }
  }
};
