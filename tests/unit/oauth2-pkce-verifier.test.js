/**
 * Tests for OAuth2PKCEVerifier
 *
 * This test suite verifies PKCE (Proof Key for Code Exchange) security validation
 * according to RFC 7636. PKCE is critical for preventing authorization code interception
 * attacks in public clients (mobile/SPA applications).
 *
 * Security Context:
 * - OWASP ASVS 2.6.2: OAuth2 authorization code flows must use PKCE for public clients
 * - RFC 7636: PKCE for OAuth Public Clients
 * - STRIDE: Spoofing (authorization code theft), Tampering (code substitution)
 *
 * Coverage Target: 90%+ (critical security module)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { OAuth2PKCEVerifier } from '../../modules/auth/oauth2-pkce-verifier.js';

describe('OAuth2PKCEVerifier', () => {
  let verifier;

  beforeEach(() => {
    verifier = new OAuth2PKCEVerifier();
  });

  describe('verifyPKCE - PKCE Implementation Detection', () => {
    it('should detect missing PKCE (HIGH severity vulnerability)', async () => {
      const url = 'https://auth.example.com/authorize?client_id=app123&response_type=code&redirect_uri=https://app.example.com/callback';

      const result = await verifier.verifyPKCE(url);

      expect(result.codeChallenge).toBeNull();
      expect(result.testResults).toHaveLength(1);
      expect(result.testResults[0]).toMatchObject({
        test: 'pkce_missing',
        result: 'VULNERABLE',
        severity: 'HIGH',
        evidence: {
          description: 'No code_challenge parameter found',
          recommendation: 'Implement PKCE for public clients'
        }
      });
    });

    it('should detect PKCE implementation with S256 method', async () => {
      // Valid S256 challenge (43-128 chars, base64url encoded)
      const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
      const url = `https://auth.example.com/authorize?client_id=app123&response_type=code&code_challenge=${challenge}&code_challenge_method=S256`;

      const result = await verifier.verifyPKCE(url);

      expect(result.codeChallenge).toBe(challenge);
      expect(result.codeChallengeMethod).toBe('S256');
      expect(result.testResults).toHaveLength(2);

      // Method test should be SECURE
      const methodTest = result.testResults.find(t => t.test === 'pkce_method');
      expect(methodTest).toMatchObject({
        result: 'SECURE',
        severity: 'SECURE'
      });
    });

    it('should detect PKCE with plain method (RFC 7636 violation)', async () => {
      const challenge = 'plaintext_verifier_123';
      const url = `https://auth.example.com/authorize?client_id=app123&response_type=code&code_challenge=${challenge}&code_challenge_method=plain`;

      const result = await verifier.verifyPKCE(url);

      expect(result.codeChallenge).toBe(challenge);
      expect(result.codeChallengeMethod).toBe('plain');

      const methodTest = result.testResults.find(t => t.test === 'pkce_method');
      expect(methodTest).toMatchObject({
        result: 'WEAK',
        severity: 'MEDIUM',
        evidence: {
          secure: false,
          method: 'plain',
          reason: 'Plain text method is insecure',
          recommendation: 'Use S256 method instead'
        }
      });
    });

    it('should detect missing code_challenge_method (defaults to plain)', async () => {
      // RFC 7636: If method is omitted, server defaults to "plain"
      const challenge = 'some_challenge_value';
      const url = `https://auth.example.com/authorize?client_id=app123&code_challenge=${challenge}`;

      const result = await verifier.verifyPKCE(url);

      expect(result.codeChallenge).toBe(challenge);
      expect(result.codeChallengeMethod).toBeNull();

      const methodTest = result.testResults.find(t => t.test === 'pkce_method');
      expect(methodTest).toMatchObject({
        result: 'WEAK',
        severity: 'MEDIUM',
        evidence: {
          secure: false,
          method: 'none',
          reason: 'Plain text method is insecure'
        }
      });
    });
  });

  describe('analyzeCodeChallengeMethod - Method Security Analysis', () => {
    it('should accept S256 as secure method', () => {
      const result = verifier.analyzeCodeChallengeMethod('S256');

      expect(result).toMatchObject({
        secure: true,
        method: 'S256',
        reason: 'SHA256 method is secure'
      });
      expect(result.recommendation).toBeUndefined();
    });

    it('should reject plain as insecure method', () => {
      const result = verifier.analyzeCodeChallengeMethod('plain');

      expect(result).toMatchObject({
        secure: false,
        method: 'plain',
        reason: 'Plain text method is insecure',
        recommendation: 'Use S256 method instead'
      });
    });

    it('should reject unknown methods', () => {
      const result = verifier.analyzeCodeChallengeMethod('SHA1');

      expect(result).toMatchObject({
        secure: false,
        method: 'SHA1',
        reason: 'Unknown or insecure method',
        recommendation: 'Use S256 method'
      });
    });

    it('should reject null method', () => {
      const result = verifier.analyzeCodeChallengeMethod(null);

      expect(result).toMatchObject({
        secure: false,
        method: 'none',
        reason: 'Plain text method is insecure',
        recommendation: 'Use S256 method instead'
      });
    });
  });

  describe('analyzeChallengeEntropy - Entropy Analysis', () => {
    it('should accept high-entropy challenge (128+ bits)', () => {
      // 43-char base64url string has ~256 bits entropy
      const highEntropyChallenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

      const result = verifier.analyzeChallengeEntropy(highEntropyChallenge);

      expect(result.sufficient).toBe(true);
      expect(result.length).toBe(43);
      expect(result.totalEntropy).toBeGreaterThanOrEqual(128);
      expect(result.minimumRequired).toBe(128);
    });

    it('should detect low-entropy challenge', () => {
      // Short or repetitive string has low entropy
      const lowEntropyChallenge = 'aaaaaa';

      const result = verifier.analyzeChallengeEntropy(lowEntropyChallenge);

      expect(result.sufficient).toBe(false);
      expect(result.totalEntropy).toBeLessThan(128);
      expect(result.reason).toBeUndefined(); // No reason field for valid but weak challenges
    });

    it('should handle null challenge', () => {
      const result = verifier.analyzeChallengeEntropy(null);

      expect(result).toMatchObject({
        sufficient: false,
        reason: 'No challenge provided'
      });
    });

    it('should handle empty string challenge', () => {
      const result = verifier.analyzeChallengeEntropy('');

      expect(result).toMatchObject({
        sufficient: false,
        reason: 'No challenge provided'
      });
    });
  });

  describe('calculateEntropy - Shannon Entropy Calculation', () => {
    it('should calculate zero entropy for empty string', () => {
      expect(verifier.calculateEntropy('')).toBe(0);
    });

    it('should calculate zero entropy for null', () => {
      expect(verifier.calculateEntropy(null)).toBe(0);
    });

    it('should calculate low entropy for repetitive string', () => {
      const entropy = verifier.calculateEntropy('aaaaaaa');
      expect(entropy).toBe(0); // All same character = 0 entropy
    });

    it('should calculate high entropy for random string', () => {
      const randomStr = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
      const entropy = verifier.calculateEntropy(randomStr);

      // Base64url charset has ~6 bits per char, so expect 4-5 bits/char
      expect(entropy).toBeGreaterThan(4);
      expect(entropy).toBeLessThanOrEqual(6);
    });

    it('should calculate correct entropy for two-char distribution', () => {
      const str = 'aaaabbbb'; // 50/50 distribution
      const entropy = verifier.calculateEntropy(str);

      // Entropy for 50/50 is exactly 1 bit
      expect(entropy).toBeCloseTo(1.0, 5);
    });
  });

  describe('extractCodeChallenge - URL Parameter Extraction', () => {
    it('should extract code_challenge from valid URL', () => {
      const challenge = 'test_challenge_123';
      const url = `https://auth.example.com/authorize?code_challenge=${challenge}`;

      expect(verifier.extractCodeChallenge(url)).toBe(challenge);
    });

    it('should return null for missing code_challenge', () => {
      const url = 'https://auth.example.com/authorize?client_id=app123';

      expect(verifier.extractCodeChallenge(url)).toBeNull();
    });

    it('should handle malformed URL gracefully', () => {
      const invalidUrl = 'not-a-valid-url';

      expect(verifier.extractCodeChallenge(invalidUrl)).toBeNull();
    });

    it('should handle URL with special characters in challenge', () => {
      const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
      const url = `https://auth.example.com/authorize?code_challenge=${challenge}&other=param`;

      expect(verifier.extractCodeChallenge(url)).toBe(challenge);
    });
  });

  describe('extractCodeChallengeMethod - Method Extraction', () => {
    it('should extract S256 method', () => {
      const url = 'https://auth.example.com/authorize?code_challenge_method=S256';

      expect(verifier.extractCodeChallengeMethod(url)).toBe('S256');
    });

    it('should extract plain method', () => {
      const url = 'https://auth.example.com/authorize?code_challenge_method=plain';

      expect(verifier.extractCodeChallengeMethod(url)).toBe('plain');
    });

    it('should return null for missing method', () => {
      const url = 'https://auth.example.com/authorize?client_id=app123';

      expect(verifier.extractCodeChallengeMethod(url)).toBeNull();
    });

    it('should handle malformed URL gracefully', () => {
      expect(verifier.extractCodeChallengeMethod('invalid-url')).toBeNull();
    });
  });

  describe('Integration Tests - Complete PKCE Flows', () => {
    it('should fully analyze secure PKCE implementation', async () => {
      const challenge = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
      const url = `https://auth.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https://client.example.com/cb&code_challenge=${challenge}&code_challenge_method=S256`;

      const result = await verifier.verifyPKCE(url);

      expect(result.codeChallenge).toBe(challenge);
      expect(result.codeChallengeMethod).toBe('S256');
      expect(result.originalRequest).toBe(url);
      expect(result.timestamp).toBeLessThanOrEqual(Date.now());

      // Should have 2 tests: method + entropy
      expect(result.testResults).toHaveLength(2);
      expect(result.testResults.every(t => t.result === 'SECURE')).toBe(true);
    });

    it('should detect multiple PKCE weaknesses simultaneously', async () => {
      // Weak challenge with plain method
      const url = 'https://auth.example.com/authorize?code_challenge=weak&code_challenge_method=plain';

      const result = await verifier.verifyPKCE(url);

      const methodTest = result.testResults.find(t => t.test === 'pkce_method');
      const entropyTest = result.testResults.find(t => t.test === 'pkce_entropy');

      expect(methodTest.result).toBe('WEAK');
      expect(entropyTest.result).toBe('WEAK');
      expect(result.testResults.filter(t => t.severity !== 'SECURE').length).toBe(2);
    });
  });

  describe('Edge Cases and Error Handling', () => {
    it('should handle URL with fragments', async () => {
      const challenge = 'valid_challenge_string_with_enough_entropy_123456789';
      const url = `https://auth.example.com/authorize?code_challenge=${challenge}#fragment`;

      const result = await verifier.verifyPKCE(url);

      expect(result.codeChallenge).toBe(challenge);
    });

    it('should handle duplicate parameters (takes first)', async () => {
      const url = 'https://auth.example.com/authorize?code_challenge=first&code_challenge=second';

      const result = await verifier.verifyPKCE(url);

      expect(result.codeChallenge).toBe('first');
    });

    it('should provide timestamp for audit trail', async () => {
      const before = Date.now();
      const result = await verifier.verifyPKCE('https://example.com/auth');
      const after = Date.now();

      expect(result.timestamp).toBeGreaterThanOrEqual(before);
      expect(result.timestamp).toBeLessThanOrEqual(after);
    });
  });
});
