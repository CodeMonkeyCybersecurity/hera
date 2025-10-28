/**
 * Refresh Token Tracker - P0-B: Secure hash-based token tracking
 *
 * PURPOSE:
 * - Detect when OAuth2 refresh tokens are NOT rotated (RFC 9700 violation)
 * - Track token usage WITHOUT storing plaintext tokens
 * - Enable evidence-based refresh token rotation analysis
 *
 * SECURITY:
 * - Uses SHA-256 hashing - NEVER stores plaintext tokens
 * - Stores only first 16 chars of hash (sufficient for collision detection)
 * - Automatic cleanup of old hashes (7 day TTL)
 * - Memory-only storage (not persisted to disk)
 *
 * PRIVACY:
 * - Hash function is one-way (cannot recover token from hash)
 * - Hashes are ephemeral (cleared on browser restart)
 * - No PII stored
 *
 * RFC 9700 COMPLIANCE:
 * Section 4.13: "Authorization servers SHOULD rotate refresh tokens on each use"
 *
 * @see ROADMAP.md P0-B
 * @see ROADMAP.md P1-5: RFC 9700 Compliance
 * @see CLAUDE.md Part 7 - Adversarial Analysis: "Token Tracking Conflicts with Redaction"
 */

export class RefreshTokenTracker {
  constructor() {
    // Map of token hashes -> usage metadata
    // Key: first 16 chars of SHA-256 hash (sufficient for collision detection)
    // Value: { firstSeen, lastSeen, useCount, domain }
    this.tokenHashes = new Map();

    // Cleanup old hashes periodically
    this.HASH_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
    this.cleanupInterval = setInterval(() => this.cleanup(), 60 * 60 * 1000); // Every hour
  }

  /**
   * Hash a token using SHA-256
   *
   * SECURITY: SHA-256 is one-way - cannot recover token from hash
   *
   * @param {string} token - The token to hash
   * @returns {Promise<string>} - First 16 chars of hex-encoded hash
   */
  async hashToken(token) {
    if (!token) {
      throw new Error('Token is required');
    }

    // Convert token string to bytes
    const encoder = new TextEncoder();
    const data = encoder.encode(token);

    // Hash using SHA-256
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);

    // Convert to hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    // Return first 16 chars (64 bits - sufficient for collision detection)
    return hashHex.substring(0, 16);
  }

  /**
   * Track a refresh token from an OAuth2 token response
   *
   * DETECTS: Refresh token rotation violations (RFC 9700 Section 4.13)
   *
   * @param {Object} tokenResponse - The token response body (after redaction)
   * @param {string} domain - The authorization server domain
   * @returns {Promise<Object|null>} - Security finding if rotation violation detected
   */
  async trackRefreshToken(tokenResponse, domain) {
    // Extract refresh token from response
    const refreshToken = tokenResponse.refresh_token;

    if (!refreshToken) {
      // No refresh token in response (not all OAuth2 flows have refresh tokens)
      return null;
    }

    // Check if this is a redacted token
    if (typeof refreshToken === 'string' && refreshToken.startsWith('[REDACTED_')) {
      // Token was redacted by ResponseBodyCapturer
      // Extract original length for heuristic analysis
      const lengthMatch = refreshToken.match(/length=(\d+)/);
      const tokenLength = lengthMatch ? parseInt(lengthMatch[1]) : null;

      // Heuristic: If token is very short (<32 chars), it might be a weak token
      if (tokenLength && tokenLength < 32) {
        return {
          type: 'WEAK_REFRESH_TOKEN',
          severity: 'MEDIUM',
          confidence: 'MEDIUM',
          message: `Refresh token appears short (${tokenLength} chars)`,
          evidence: {
            tokenLength,
            domain,
            recommendation: 'RFC 6749 recommends refresh tokens have high entropy'
          },
          cwe: 'CWE-330'
        };
      }

      // Cannot track rotation without plaintext token
      return null;
    }

    // Hash the token
    const tokenHash = await this.hashToken(refreshToken);

    // Check if we've seen this hash before
    if (this.tokenHashes.has(tokenHash)) {
      const metadata = this.tokenHashes.get(tokenHash);

      // UPDATE: Increment use count
      metadata.useCount++;
      metadata.lastSeen = Date.now();
      this.tokenHashes.set(tokenHash, metadata);

      // FINDING: Refresh token was reused (rotation violation)
      return {
        type: 'REFRESH_TOKEN_NOT_ROTATED',
        severity: 'HIGH',
        confidence: 'HIGH',
        message: 'Refresh token was not rotated on use (RFC 9700 violation)',
        evidence: {
          domain,
          tokenHash: tokenHash, // Safe to include (one-way hash)
          firstSeen: new Date(metadata.firstSeen).toISOString(),
          lastSeen: new Date(metadata.lastSeen).toISOString(),
          useCount: metadata.useCount,
          timeSinceFirstUse: Date.now() - metadata.firstSeen,
          recommendation: 'Authorization servers SHOULD rotate refresh tokens on each use (RFC 9700 Section 4.13)'
        },
        references: [
          'RFC 9700 Section 4.13: Refresh Token Rotation',
          'OWASP ASVS 3.0.1: Verify that refresh tokens are rotated',
          'CWE-613: Insufficient Session Expiration'
        ],
        cwe: 'CWE-613'
      };
    }

    // NEW TOKEN: Record hash and metadata
    this.tokenHashes.set(tokenHash, {
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      useCount: 1,
      domain
    });

    // No finding (token is new, rotation working correctly)
    return null;
  }

  /**
   * Cleanup old token hashes (privacy/memory management)
   */
  cleanup() {
    const now = Date.now();
    let cleanupCount = 0;

    for (const [hash, metadata] of this.tokenHashes.entries()) {
      if (now - metadata.lastSeen > this.HASH_TTL_MS) {
        this.tokenHashes.delete(hash);
        cleanupCount++;
      }
    }

    if (cleanupCount > 0) {
      console.debug(`[RefreshTokenTracker] Cleaned up ${cleanupCount} old token hashes`);
    }
  }

  /**
   * Clear all tracked hashes (for testing or user request)
   */
  clear() {
    this.tokenHashes.clear();
    console.log('[RefreshTokenTracker] All token hashes cleared');
  }

  /**
   * Get statistics (for debugging/dashboard)
   */
  getStats() {
    return {
      trackedTokens: this.tokenHashes.size,
      domains: [...new Set([...this.tokenHashes.values()].map(m => m.domain))],
      oldestToken: Math.min(...[...this.tokenHashes.values()].map(m => m.firstSeen)),
      newestToken: Math.max(...[...this.tokenHashes.values()].map(m => m.lastSeen))
    };
  }

  /**
   * Destroy tracker (cleanup on extension unload)
   */
  destroy() {
    clearInterval(this.cleanupInterval);
    this.clear();
  }
}
