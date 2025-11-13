/**
 * Tests for RefreshTokenTracker
 *
 * PURPOSE: Verify RFC 9700 Section 4.13.2 compliance checking:
 * - Refresh token rotation detection
 * - DPoP compensating control detection
 * - mTLS compensating control detection
 * - Token reuse detection without sender-constraint
 *
 * @see modules/auth/refresh-token-tracker.js
 * @see RFC 9700 Section 4.13.2: Refresh Token Protection and Rotation
 * @see RFC 9449: OAuth 2.0 Demonstrating Proof-of-Possession (DPoP)
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { RefreshTokenTracker } from '../../modules/auth/refresh-token-tracker.js';

describe('RefreshTokenTracker', () => {
  let tracker;

  beforeEach(() => {
    tracker = new RefreshTokenTracker();
    // Mock console methods to avoid noise in test output
    vi.spyOn(console, 'debug').mockImplementation(() => {});
    vi.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    tracker.destroy();
    vi.restoreAllMocks();
  });

  describe('hashToken', () => {
    it('should hash a token using SHA-256', async () => {
      const token = 'test-token-123';
      const hash = await tracker.hashToken(token);

      expect(hash).toBeDefined();
      expect(typeof hash).toBe('string');
      expect(hash.length).toBe(16); // First 16 chars of SHA-256 hex
      expect(hash).toMatch(/^[0-9a-f]{16}$/); // Hex format
    });

    it('should produce consistent hashes for same token', async () => {
      const token = 'consistent-token';
      const hash1 = await tracker.hashToken(token);
      const hash2 = await tracker.hashToken(token);

      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different tokens', async () => {
      const hash1 = await tracker.hashToken('token-1');
      const hash2 = await tracker.hashToken('token-2');

      expect(hash1).not.toBe(hash2);
    });

    it('should throw error for empty token', async () => {
      await expect(tracker.hashToken('')).rejects.toThrow('Token is required');
    });

    it('should throw error for null token', async () => {
      await expect(tracker.hashToken(null)).rejects.toThrow('Token is required');
    });

    it('should throw error for undefined token', async () => {
      await expect(tracker.hashToken(undefined)).rejects.toThrow('Token is required');
    });
  });

  describe('trackRefreshToken - basic functionality', () => {
    it('should return null when no refresh_token in response', async () => {
      const tokenResponse = {
        access_token: 'access-123',
        token_type: 'Bearer'
      };

      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result).toBeNull();
      expect(tracker.tokenHashes.size).toBe(0);
    });

    it('should track new refresh token without finding', async () => {
      const tokenResponse = {
        access_token: 'access-123',
        refresh_token: 'refresh-token-abc123',
        token_type: 'Bearer'
      };

      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result).toBeNull(); // No finding for first use
      expect(tracker.tokenHashes.size).toBe(1); // Token tracked
    });

    it('should detect refresh token reuse without DPoP (HIGH severity)', async () => {
      const tokenResponse = {
        access_token: 'access-123',
        refresh_token: 'refresh-token-xyz789',
        token_type: 'Bearer'
      };

      // First use - track token
      const result1 = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');
      expect(result1).toBeNull();

      // Second use - detect reuse
      const result2 = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result2).toBeDefined();
      expect(result2.type).toBe('REFRESH_TOKEN_NOT_ROTATED');
      expect(result2.severity).toBe('HIGH');
      expect(result2.confidence).toBe('HIGH');
      expect(result2.evidence.domain).toBe('auth.example.com');
      expect(result2.evidence.useCount).toBe(2);
      expect(result2.evidence.recommendation).toContain('DPoP');
      expect(result2.cwe).toBe('CWE-613');
      expect(result2.references).toContain('RFC 9700 Section 4.13.2: Refresh Token Protection and Rotation');
    });

    it('should track multiple uses of same token', async () => {
      const tokenResponse = {
        refresh_token: 'reused-token',
        token_type: 'Bearer'
      };

      // Use token 3 times
      await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');
      await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');
      const result3 = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result3.evidence.useCount).toBe(3);
      expect(result3.evidence.firstSeen).toBeDefined();
      expect(result3.evidence.lastSeen).toBeDefined();
      expect(result3.evidence.timeSinceFirstUse).toBeGreaterThanOrEqual(0);
    });
  });

  describe('DPoP compensating control detection', () => {
    it('should detect DPoP via token_type field (lowercase)', async () => {
      const tokenResponse = {
        refresh_token: 'refresh-token-dpop',
        token_type: 'dpop' // lowercase
      };

      await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');
      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result).toBeDefined();
      expect(result.type).toBe('REFRESH_TOKEN_NOT_ROTATED_BUT_PROTECTED');
      expect(result.severity).toBe('LOW'); // Downgraded from HIGH
      expect(result.confidence).toBe('MEDIUM');
      expect(result.evidence.protection).toBe('DPoP');
      expect(result.evidence.note).toContain('RFC 9700 allows non-rotation');
      expect(result.references).toContain('RFC 9449: OAuth 2.0 Demonstrating Proof-of-Possession (DPoP)');
    });

    it('should detect DPoP via token_type field (mixed case)', async () => {
      const tokenResponse = {
        refresh_token: 'refresh-token-dpop2',
        token_type: 'DPoP' // Official casing
      };

      await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');
      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result.type).toBe('REFRESH_TOKEN_NOT_ROTATED_BUT_PROTECTED');
      expect(result.severity).toBe('LOW');
    });

    it('should detect DPoP via dpop_nonce field', async () => {
      const tokenResponse = {
        refresh_token: 'refresh-token-nonce',
        token_type: 'Bearer',
        dpop_nonce: 'nonce-12345'
      };

      await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');
      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result.type).toBe('REFRESH_TOKEN_NOT_ROTATED_BUT_PROTECTED');
      expect(result.severity).toBe('LOW');
    });

    it('should detect DPoP via token_binding field', async () => {
      const tokenResponse = {
        refresh_token: 'refresh-token-binding',
        token_type: 'Bearer',
        token_binding: { 'token-binding-id': 'binding-123' }
      };

      await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');
      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result.type).toBe('REFRESH_TOKEN_NOT_ROTATED_BUT_PROTECTED');
      expect(result.severity).toBe('LOW');
    });
  });

  describe('mTLS compensating control detection', () => {
    it('should detect mTLS via cnf field', async () => {
      const tokenResponse = {
        refresh_token: 'refresh-token-mtls',
        token_type: 'Bearer',
        cnf: { 'x5t#S256': 'cert-thumbprint' }
      };

      await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');
      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result.type).toBe('REFRESH_TOKEN_NOT_ROTATED_BUT_PROTECTED');
      expect(result.severity).toBe('LOW');
    });

    it('should detect mTLS via client-assertion-type field', async () => {
      const tokenResponse = {
        refresh_token: 'refresh-token-assertion',
        token_type: 'Bearer',
        'client-assertion-type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
      };

      await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');
      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result.type).toBe('REFRESH_TOKEN_NOT_ROTATED_BUT_PROTECTED');
      expect(result.severity).toBe('LOW');
    });
  });

  describe('redacted token handling', () => {
    it('should detect weak short tokens via redaction metadata', async () => {
      const tokenResponse = {
        refresh_token: '[REDACTED_REFRESH_TOKEN length=24 entropy=2.3]',
        token_type: 'Bearer'
      };

      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result).toBeDefined();
      expect(result.type).toBe('WEAK_REFRESH_TOKEN');
      expect(result.severity).toBe('MEDIUM');
      expect(result.confidence).toBe('MEDIUM');
      expect(result.evidence.tokenLength).toBe(24);
      expect(result.evidence.domain).toBe('auth.example.com');
      expect(result.cwe).toBe('CWE-330');
    });

    it('should return null for redacted tokens with sufficient length', async () => {
      const tokenResponse = {
        refresh_token: '[REDACTED_REFRESH_TOKEN length=128 entropy=5.2]',
        token_type: 'Bearer'
      };

      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result).toBeNull(); // Length >= 32, no finding
    });

    it('should return null for redacted tokens without length metadata', async () => {
      const tokenResponse = {
        refresh_token: '[REDACTED_REFRESH_TOKEN]',
        token_type: 'Bearer'
      };

      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result).toBeNull(); // Cannot analyze without metadata
    });
  });

  describe('cleanup functionality', () => {
    it('should cleanup old token hashes after TTL', async () => {
      // Track a token
      const tokenResponse = {
        refresh_token: 'old-token',
        token_type: 'Bearer'
      };
      await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(tracker.tokenHashes.size).toBe(1);

      // Manually age the token beyond TTL
      const hash = await tracker.hashToken('old-token');
      const metadata = tracker.tokenHashes.get(hash);
      metadata.lastSeen = Date.now() - (8 * 24 * 60 * 60 * 1000); // 8 days ago
      tracker.tokenHashes.set(hash, metadata);

      // Run cleanup
      tracker.cleanup();

      expect(tracker.tokenHashes.size).toBe(0);
      expect(console.debug).toHaveBeenCalledWith(expect.stringContaining('Cleaned up 1 old token hashes'));
    });

    it('should not cleanup recent tokens', async () => {
      const tokenResponse = {
        refresh_token: 'recent-token',
        token_type: 'Bearer'
      };
      await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      tracker.cleanup();

      expect(tracker.tokenHashes.size).toBe(1); // Still present
    });

    it('should cleanup multiple old tokens', async () => {
      // Track 3 tokens (unrolled to avoid await-in-loop)
      await tracker.trackRefreshToken({
        refresh_token: 'old-token-1',
        token_type: 'Bearer'
      }, 'auth.example.com');
      await tracker.trackRefreshToken({
        refresh_token: 'old-token-2',
        token_type: 'Bearer'
      }, 'auth.example.com');
      await tracker.trackRefreshToken({
        refresh_token: 'old-token-3',
        token_type: 'Bearer'
      }, 'auth.example.com');

      expect(tracker.tokenHashes.size).toBe(3);

      // Age all tokens
      for (const [hash, metadata] of tracker.tokenHashes.entries()) {
        metadata.lastSeen = Date.now() - (8 * 24 * 60 * 60 * 1000);
        tracker.tokenHashes.set(hash, metadata);
      }

      tracker.cleanup();

      expect(tracker.tokenHashes.size).toBe(0);
    });
  });

  describe('clear functionality', () => {
    it('should clear all tracked hashes', async () => {
      // Track 2 tokens
      await tracker.trackRefreshToken({ refresh_token: 'token1' }, 'domain1.com');
      await tracker.trackRefreshToken({ refresh_token: 'token2' }, 'domain2.com');

      expect(tracker.tokenHashes.size).toBe(2);

      tracker.clear();

      expect(tracker.tokenHashes.size).toBe(0);
      expect(console.log).toHaveBeenCalledWith('[RefreshTokenTracker] All token hashes cleared');
    });
  });

  describe('getStats functionality', () => {
    it('should return correct statistics', async () => {
      // Track tokens from different domains
      await tracker.trackRefreshToken({ refresh_token: 'token1' }, 'auth.example.com');
      await tracker.trackRefreshToken({ refresh_token: 'token2' }, 'oauth.test.com');
      await tracker.trackRefreshToken({ refresh_token: 'token3' }, 'auth.example.com');

      const stats = tracker.getStats();

      expect(stats.trackedTokens).toBe(3);
      expect(stats.domains).toContain('auth.example.com');
      expect(stats.domains).toContain('oauth.test.com');
      expect(stats.domains.length).toBe(2);
      expect(stats.oldestToken).toBeGreaterThan(0);
      expect(stats.newestToken).toBeGreaterThan(0);
      expect(stats.newestToken).toBeGreaterThanOrEqual(stats.oldestToken);
    });

    it('should handle empty tracker stats', () => {
      const stats = tracker.getStats();

      expect(stats.trackedTokens).toBe(0);
      expect(stats.domains).toEqual([]);
      expect(stats.oldestToken).toBe(Infinity);
      expect(stats.newestToken).toBe(-Infinity);
    });
  });

  describe('destroy functionality', () => {
    it('should clear interval and hashes on destroy', () => {
      const clearIntervalSpy = vi.spyOn(globalThis, 'clearInterval');

      tracker.destroy();

      expect(clearIntervalSpy).toHaveBeenCalled();
      expect(tracker.tokenHashes.size).toBe(0);
    });
  });

  describe('edge cases', () => {
    it('should handle token response with no token_type', async () => {
      const tokenResponse = {
        refresh_token: 'no-type-token'
      };

      await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');
      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result.type).toBe('REFRESH_TOKEN_NOT_ROTATED');
      expect(result.severity).toBe('HIGH'); // No DPoP detected
    });

    it('should handle empty domain', async () => {
      const tokenResponse = {
        refresh_token: 'domain-test-token',
        token_type: 'Bearer'
      };

      const result1 = await tracker.trackRefreshToken(tokenResponse, '');
      expect(result1).toBeNull();

      const result2 = await tracker.trackRefreshToken(tokenResponse, '');
      expect(result2.evidence.domain).toBe('');
    });

    it('should handle very long tokens', async () => {
      const longToken = 'a'.repeat(1000);
      const tokenResponse = {
        refresh_token: longToken,
        token_type: 'Bearer'
      };

      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');
      expect(result).toBeNull(); // First use is fine

      const hash = await tracker.hashToken(longToken);
      expect(hash.length).toBe(16); // Hash is still 16 chars
    });

    it('should handle special characters in tokens', async () => {
      const specialToken = 'token+with/special=chars&symbols!@#$%';
      const tokenResponse = {
        refresh_token: specialToken,
        token_type: 'Bearer'
      };

      await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');
      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result.type).toBe('REFRESH_TOKEN_NOT_ROTATED');
    });

    it('should handle null/undefined fields in token response', async () => {
      const tokenResponse = {
        refresh_token: 'valid-token',
        token_type: null,
        dpop_nonce: undefined
      };

      await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');
      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result.type).toBe('REFRESH_TOKEN_NOT_ROTATED');
      expect(result.severity).toBe('HIGH');
    });
  });

  describe('RFC 9700 Section 4.13.2 compliance validation', () => {
    it('should enforce HIGH severity when rotation AND sender-constraint both missing', async () => {
      const tokenResponse = {
        refresh_token: 'non-compliant-token',
        token_type: 'Bearer'
        // No rotation (token reused)
        // No DPoP
        // No mTLS
      };

      await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');
      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result.severity).toBe('HIGH');
      expect(result.message).toContain('RFC 9700 violation');
      expect(result.references).toContain('RFC 9700 Section 4.13.2: Refresh Token Protection and Rotation');
    });

    it('should accept LOW severity when rotation missing but sender-constraint present', async () => {
      const tokenResponse = {
        refresh_token: 'dpop-protected-token',
        token_type: 'DPoP'
      };

      await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');
      const result = await tracker.trackRefreshToken(tokenResponse, 'auth.example.com');

      expect(result.severity).toBe('LOW');
      expect(result.evidence.note).toContain('RFC 9700 allows non-rotation');
    });
  });
});
