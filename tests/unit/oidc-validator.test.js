// Unit tests for OIDC Validator
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { OIDCValidator } from '../../modules/auth/oidc-validator.js';

describe('OIDCValidator', () => {
  let validator;

  beforeEach(() => {
    validator = new OIDCValidator();
  });

  // Helper function to create JWT
  function createJWT(header, payload) {
    const h = btoa(JSON.stringify(header)).replace(/=/g, '');
    const p = btoa(JSON.stringify(payload)).replace(/=/g, '');
    return `${h}.${p}.signature`;
  }

  describe('validateIDToken - Required Claims', () => {
    it('should detect missing sub claim', async () => {
      const token = {
        header: { alg: 'RS256' },
        payload: {
          iss: 'https://issuer.example.com',
          aud: 'client-id',
          exp: Math.floor(Date.now() / 1000) + 3600
        }
      };

      const issues = await validator.validateIDToken(token);

      const subIssue = issues.find(i => i.type === 'MISSING_SUB_CLAIM');
      expect(subIssue).toBeDefined();
      expect(subIssue.severity).toBe('CRITICAL');
      expect(subIssue.cvss).toBe(7.0);
    });

    it('should detect missing iss claim', async () => {
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          aud: 'client-id',
          exp: Math.floor(Date.now() / 1000) + 3600
        }
      };

      const issues = await validator.validateIDToken(token);

      const issIssue = issues.find(i => i.type === 'MISSING_ISSUER_CLAIM');
      expect(issIssue).toBeDefined();
      expect(issIssue.severity).toBe('CRITICAL');
      expect(issIssue.cvss).toBe(8.0);
    });

    it('should detect missing aud claim', async () => {
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          exp: Math.floor(Date.now() / 1000) + 3600
        }
      };

      const issues = await validator.validateIDToken(token);

      const audIssue = issues.find(i => i.type === 'MISSING_AUDIENCE_CLAIM');
      expect(audIssue).toBeDefined();
      expect(audIssue.severity).toBe('CRITICAL');
      expect(audIssue.cvss).toBe(8.0);
    });

    it('should accept valid ID token with all required claims', async () => {
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          aud: 'client-id',
          exp: Math.floor(Date.now() / 1000) + 3600
        }
      };

      const issues = await validator.validateIDToken(token);

      const criticalIssues = issues.filter(i => i.severity === 'CRITICAL');
      expect(criticalIssues).toHaveLength(0);
    });
  });

  describe('validateIDToken - Audience Validation', () => {
    it('should detect audience mismatch with single audience', async () => {
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          aud: 'wrong-client-id',
          exp: Math.floor(Date.now() / 1000) + 3600
        }
      };
      const context = { clientId: 'correct-client-id' };

      const issues = await validator.validateIDToken(token, context);

      const audIssue = issues.find(i => i.type === 'AUDIENCE_MISMATCH');
      expect(audIssue).toBeDefined();
      expect(audIssue.severity).toBe('CRITICAL');
      expect(audIssue.cvss).toBe(9.0);
      expect(audIssue.cve).toBe('CVE-2021-27582');
    });

    it('should accept matching audience with single string', async () => {
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          aud: 'client-id',
          exp: Math.floor(Date.now() / 1000) + 3600
        }
      };
      const context = { clientId: 'client-id' };

      const issues = await validator.validateIDToken(token, context);

      const audIssue = issues.find(i => i.type === 'AUDIENCE_MISMATCH');
      expect(audIssue).toBeUndefined();
    });

    it('should accept matching audience in array', async () => {
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          aud: ['client-id', 'other-client-id'],
          exp: Math.floor(Date.now() / 1000) + 3600
        }
      };
      const context = { clientId: 'client-id' };

      const issues = await validator.validateIDToken(token, context);

      const audIssue = issues.find(i => i.type === 'AUDIENCE_MISMATCH');
      expect(audIssue).toBeUndefined();
    });
  });

  describe('validateIDToken - Expiration', () => {
    it('should detect missing exp claim', async () => {
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          aud: 'client-id'
        }
      };

      const issues = await validator.validateIDToken(token);

      const expIssue = issues.find(i => i.type === 'MISSING_EXPIRATION_CLAIM');
      expect(expIssue).toBeDefined();
      expect(expIssue.severity).toBe('HIGH');
    });

    it('should detect expired token', async () => {
      const now = Math.floor(Date.now() / 1000);
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          aud: 'client-id',
          exp: now - 3600 // Expired 1 hour ago
        }
      };

      const issues = await validator.validateIDToken(token);

      const expIssue = issues.find(i => i.type === 'ID_TOKEN_EXPIRED');
      expect(expIssue).toBeDefined();
      expect(expIssue.severity).toBe('MEDIUM');
    });

    it('should accept non-expired token', async () => {
      const now = Math.floor(Date.now() / 1000);
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          aud: 'client-id',
          exp: now + 3600 // Expires in 1 hour
        }
      };

      const issues = await validator.validateIDToken(token);

      const expIssue = issues.find(i => i.type === 'ID_TOKEN_EXPIRED');
      expect(expIssue).toBeUndefined();
    });
  });

  describe('validateIDToken - Nonce Validation', () => {
    it('should detect missing nonce when nonce was sent', async () => {
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          aud: 'client-id',
          exp: Math.floor(Date.now() / 1000) + 3600
        }
      };
      const context = { nonce: 'expected-nonce-123' };

      const issues = await validator.validateIDToken(token, context);

      const nonceIssue = issues.find(i => i.type === 'MISSING_NONCE_IN_ID_TOKEN');
      expect(nonceIssue).toBeDefined();
      expect(nonceIssue.severity).toBe('CRITICAL');
      expect(nonceIssue.cvss).toBe(8.0);
      expect(nonceIssue.cve).toBe('CVE-2020-26945');
    });

    it('should detect nonce mismatch', async () => {
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          aud: 'client-id',
          exp: Math.floor(Date.now() / 1000) + 3600,
          nonce: 'wrong-nonce'
        }
      };
      const context = { nonce: 'expected-nonce' };

      const issues = await validator.validateIDToken(token, context);

      const nonceIssue = issues.find(i => i.type === 'NONCE_MISMATCH');
      expect(nonceIssue).toBeDefined();
      expect(nonceIssue.severity).toBe('CRITICAL');
      expect(nonceIssue.cvss).toBe(9.0);
    });

    it('should accept matching nonce', async () => {
      const nonce = 'correct-nonce-123';
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          aud: 'client-id',
          exp: Math.floor(Date.now() / 1000) + 3600,
          nonce
        }
      };
      const context = { nonce };

      const issues = await validator.validateIDToken(token, context);

      const nonceIssues = issues.filter(i => i.type.includes('NONCE'));
      expect(nonceIssues).toHaveLength(0);
    });
  });

  describe('validateIDToken - Clock Skew', () => {
    it('should detect iat in future', async () => {
      const now = Math.floor(Date.now() / 1000);
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          aud: 'client-id',
          exp: now + 7200,
          iat: now + 600 // 10 minutes in future
        }
      };

      const issues = await validator.validateIDToken(token);

      const iatIssue = issues.find(i => i.type === 'IAT_IN_FUTURE');
      expect(iatIssue).toBeDefined();
      expect(iatIssue.severity).toBe('HIGH');
    });

    it('should allow reasonable clock skew', async () => {
      const now = Math.floor(Date.now() / 1000);
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          aud: 'client-id',
          exp: now + 3600,
          iat: now + 60 // 1 minute in future (within tolerance)
        }
      };

      const issues = await validator.validateIDToken(token);

      const iatIssue = issues.find(i => i.type === 'IAT_IN_FUTURE');
      expect(iatIssue).toBeUndefined();
    });
  });

  describe('validateIDToken - Multiple Audiences (azp)', () => {
    it('should detect missing azp with multiple audiences', async () => {
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          aud: ['client-1', 'client-2', 'client-3'],
          exp: Math.floor(Date.now() / 1000) + 3600
        }
      };

      const issues = await validator.validateIDToken(token);

      const azpIssue = issues.find(i => i.type === 'MISSING_AZP_CLAIM');
      expect(azpIssue).toBeDefined();
      expect(azpIssue.severity).toBe('HIGH');
      expect(azpIssue.cve).toBe('CVE-2023-45857');
    });

    it('should not require azp with single audience', async () => {
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          aud: 'client-id',
          exp: Math.floor(Date.now() / 1000) + 3600
        }
      };

      const issues = await validator.validateIDToken(token);

      const azpIssue = issues.find(i => i.type === 'MISSING_AZP_CLAIM');
      expect(azpIssue).toBeUndefined();
    });
  });

  describe('validateIDToken - Hash Claims (at_hash, c_hash)', () => {
    it('should detect missing at_hash when access_token present', async () => {
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          aud: 'client-id',
          exp: Math.floor(Date.now() / 1000) + 3600
        }
      };
      const context = { access_token: 'some-access-token' };

      const issues = await validator.validateIDToken(token, context);

      const atHashIssue = issues.find(i => i.type === 'MISSING_AT_HASH');
      expect(atHashIssue).toBeDefined();
      expect(atHashIssue.severity).toBe('HIGH');
      expect(atHashIssue.cvss).toBe(7.5);
    });

    it('should detect missing c_hash when code present', async () => {
      const token = {
        header: { alg: 'RS256' },
        payload: {
          sub: 'user-123',
          iss: 'https://issuer.example.com',
          aud: 'client-id',
          exp: Math.floor(Date.now() / 1000) + 3600
        }
      };
      const context = { code: 'authorization-code-123' };

      const issues = await validator.validateIDToken(token, context);

      const cHashIssue = issues.find(i => i.type === 'MISSING_C_HASH');
      expect(cHashIssue).toBeDefined();
      expect(cHashIssue.severity).toBe('HIGH');
      expect(cHashIssue.cvss).toBe(7.5);
    });
  });

  describe('validateAtHash - Cryptographic Validation', () => {
    it('should validate correct at_hash for RS256', async () => {
      const accessToken = 'test-access-token';

      // Calculate expected hash
      const encoder = new TextEncoder();
      const data = encoder.encode(accessToken);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = new Uint8Array(hashBuffer);
      const halfLength = Math.floor(hashArray.length / 2);
      const leftHalf = hashArray.slice(0, halfLength);
      const expectedHash = btoa(String.fromCharCode(...leftHalf))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      const result = await validator.validateAtHash(expectedHash, accessToken, 'RS256');

      expect(result.valid).toBe(true);
      expect(result.issue).toBeNull();
    });

    it('should detect incorrect at_hash', async () => {
      const accessToken = 'test-access-token';
      const wrongHash = 'wrong-hash-value';

      const result = await validator.validateAtHash(wrongHash, accessToken, 'RS256');

      expect(result.valid).toBe(false);
      expect(result.issue).toBeDefined();
      expect(result.issue.type).toBe('AT_HASH_MISMATCH');
      expect(result.issue.severity).toBe('CRITICAL');
      expect(result.issue.cvss).toBe(9.0);
    });

    it('should use SHA-384 for RS384', async () => {
      const accessToken = 'test-access-token';

      // Calculate expected hash with SHA-384
      const encoder = new TextEncoder();
      const data = encoder.encode(accessToken);
      const hashBuffer = await crypto.subtle.digest('SHA-384', data);
      const hashArray = new Uint8Array(hashBuffer);
      const halfLength = Math.floor(hashArray.length / 2);
      const leftHalf = hashArray.slice(0, halfLength);
      const expectedHash = btoa(String.fromCharCode(...leftHalf))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      const result = await validator.validateAtHash(expectedHash, accessToken, 'RS384');

      expect(result.valid).toBe(true);
    });

    it('should use SHA-512 for RS512', async () => {
      const accessToken = 'test-access-token';

      // Calculate expected hash with SHA-512
      const encoder = new TextEncoder();
      const data = encoder.encode(accessToken);
      const hashBuffer = await crypto.subtle.digest('SHA-512', data);
      const hashArray = new Uint8Array(hashBuffer);
      const halfLength = Math.floor(hashArray.length / 2);
      const leftHalf = hashArray.slice(0, halfLength);
      const expectedHash = btoa(String.fromCharCode(...leftHalf))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      const result = await validator.validateAtHash(expectedHash, accessToken, 'RS512');

      expect(result.valid).toBe(true);
    });
  });

  describe('validateCHash - Cryptographic Validation', () => {
    it('should validate correct c_hash for RS256', async () => {
      const code = 'authorization-code-123';

      // Calculate expected hash
      const encoder = new TextEncoder();
      const data = encoder.encode(code);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      const hashArray = new Uint8Array(hashBuffer);
      const halfLength = Math.floor(hashArray.length / 2);
      const leftHalf = hashArray.slice(0, halfLength);
      const expectedHash = btoa(String.fromCharCode(...leftHalf))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      const result = await validator.validateCHash(expectedHash, code, 'RS256');

      expect(result.valid).toBe(true);
      expect(result.issue).toBeNull();
    });

    it('should detect incorrect c_hash', async () => {
      const code = 'authorization-code-123';
      const wrongHash = 'wrong-hash-value';

      const result = await validator.validateCHash(wrongHash, code, 'RS256');

      expect(result.valid).toBe(false);
      expect(result.issue).toBeDefined();
      expect(result.issue.type).toBe('C_HASH_MISMATCH');
      expect(result.issue.severity).toBe('CRITICAL');
      expect(result.issue.cvss).toBe(9.0);
    });
  });

  describe('_isOIDCAuthorizationRequest', () => {
    it('should detect OIDC request with openid scope', () => {
      const params = { scope: 'openid profile email' };
      expect(validator._isOIDCAuthorizationRequest(params)).toBe(true);
    });

    it('should reject OAuth2 request without openid scope', () => {
      const params = { scope: 'profile email' };
      expect(validator._isOIDCAuthorizationRequest(params)).toBe(false);
    });
  });

  describe('_validateAuthorizationRequest', () => {
    it('should detect missing nonce in implicit flow', () => {
      const params = {
        response_type: 'id_token token',
        scope: 'openid',
        client_id: 'test-client'
      };

      const issues = validator._validateAuthorizationRequest(params);

      const nonceIssue = issues.find(i => i.type === 'MISSING_NONCE_IMPLICIT_FLOW');
      expect(nonceIssue).toBeDefined();
      expect(nonceIssue.severity).toBe('CRITICAL');
      expect(nonceIssue.cvss).toBe(8.0);
      expect(nonceIssue.cve).toBe('CVE-2020-26945');
    });

    it('should detect missing nonce in hybrid flow', () => {
      const params = {
        response_type: 'code id_token',
        scope: 'openid',
        client_id: 'test-client'
      };

      const issues = validator._validateAuthorizationRequest(params);

      const nonceIssue = issues.find(i => i.type === 'MISSING_NONCE_IMPLICIT_FLOW');
      expect(nonceIssue).toBeDefined();
    });

    it('should detect weak nonce', () => {
      const params = {
        response_type: 'id_token',
        scope: 'openid',
        client_id: 'test-client',
        nonce: 'short' // Too short
      };

      const issues = validator._validateAuthorizationRequest(params);

      const weakNonceIssue = issues.find(i => i.type === 'WEAK_NONCE');
      expect(weakNonceIssue).toBeDefined();
      expect(weakNonceIssue.severity).toBe('HIGH');
    });

    it('should accept strong nonce', () => {
      const params = {
        response_type: 'id_token',
        scope: 'openid',
        client_id: 'test-client',
        nonce: 'strong-nonce-with-enough-length-123'
      };

      const issues = validator._validateAuthorizationRequest(params);

      const weakNonceIssue = issues.find(i => i.type === 'WEAK_NONCE');
      expect(weakNonceIssue).toBeUndefined();
    });

    it('should not require nonce for authorization code flow', () => {
      const params = {
        response_type: 'code',
        scope: 'openid',
        client_id: 'test-client'
      };

      const issues = validator._validateAuthorizationRequest(params);

      const nonceIssues = issues.filter(i => i.type.includes('NONCE'));
      expect(nonceIssues).toHaveLength(0);
    });
  });

  describe('_validateDiscoveryEndpoint', () => {
    it('should detect HTTP discovery endpoint', () => {
      const url = new URL('http://example.com/.well-known/openid-configuration');

      const issues = validator._validateDiscoveryEndpoint(url);

      const httpIssue = issues.find(i => i.type === 'DISCOVERY_DOCUMENT_OVER_HTTP');
      expect(httpIssue).toBeDefined();
      expect(httpIssue.severity).toBe('CRITICAL');
      expect(httpIssue.cvss).toBe(9.0);
    });

    it('should accept HTTPS discovery endpoint', () => {
      const url = new URL('https://example.com/.well-known/openid-configuration');

      const issues = validator._validateDiscoveryEndpoint(url);

      expect(issues).toHaveLength(0);
    });
  });

  describe('_validateUserInfoEndpoint', () => {
    it('should detect HTTP userinfo endpoint', () => {
      const url = new URL('http://example.com/userinfo');
      const requestData = {};

      const issues = validator._validateUserInfoEndpoint(url, requestData);

      const httpIssue = issues.find(i => i.type === 'USERINFO_OVER_HTTP');
      expect(httpIssue).toBeDefined();
      expect(httpIssue.severity).toBe('MEDIUM');
    });

    it('should accept HTTPS userinfo endpoint', () => {
      const url = new URL('https://example.com/userinfo');
      const requestData = {};

      const issues = validator._validateUserInfoEndpoint(url, requestData);

      expect(issues).toHaveLength(0);
    });
  });
});
