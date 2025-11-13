// Unit tests for JWT Validator
import { describe, it, expect, beforeEach } from 'vitest';
import { JWTValidator } from '../../modules/auth/jwt-validator.js';

describe('JWTValidator', () => {
  let validator;

  beforeEach(() => {
    validator = new JWTValidator();
  });

  describe('parseJWT', () => {
    it('should parse a valid JWT token', () => {
      // Create a simple JWT (header.payload.signature)
      const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({ sub: '1234567890', name: 'Test User', iat: 1516239022 }));
      const signature = 'test-signature';
      const token = `${header}.${payload}.${signature}`;

      const result = validator.parseJWT(token);

      expect(result.valid).toBe(true);
      expect(result.header.alg).toBe('RS256');
      expect(result.payload.sub).toBe('1234567890');
      expect(result.payload.name).toBe('Test User');
      expect(result.signature).toBe(signature);
    });

    it('should reject token with invalid format (less than 3 parts)', () => {
      const token = 'invalid.token';
      const result = validator.parseJWT(token);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('must have 3 parts');
    });

    it('should reject token with invalid base64 encoding', () => {
      const token = 'not-base64!@#.not-base64!@#.signature';
      const result = validator.parseJWT(token);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('Failed to parse JWT');
    });

    it('should handle URL-safe base64 encoding', () => {
      // Base64url encoding uses - and _ instead of + and /
      const header = btoa(JSON.stringify({ alg: 'RS256' })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const payload = btoa(JSON.stringify({ sub: 'test' })).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const token = `${header}.${payload}.sig`;

      const result = validator.parseJWT(token);

      expect(result.valid).toBe(true);
      expect(result.header.alg).toBe('RS256');
    });
  });

  describe('validateJWT - Algorithm Security', () => {
    it('should detect alg:none vulnerability', () => {
      const header = btoa(JSON.stringify({ alg: 'none', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({ sub: 'test' }));
      const token = `${header}.${payload}.`;

      const result = validator.validateJWT(token);

      expect(result.issues).toBeDefined();
      const algIssue = result.issues.find(i => i.type === 'ALG_NONE_VULNERABILITY');
      expect(algIssue).toBeDefined();
      expect(algIssue.severity).toBe('CRITICAL');
      expect(algIssue.cvss).toBe(10.0);
      expect(algIssue.cve).toBe('CVE-2015-9235');
    });

    it('should detect alg:none with case variation bypass', () => {
      const header = btoa(JSON.stringify({ alg: 'None', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({ sub: 'test' }));
      const token = `${header}.${payload}.`;

      const result = validator.validateJWT(token);

      const algIssue = result.issues.find(i => i.type === 'ALG_NONE_VULNERABILITY');
      expect(algIssue).toBeDefined();
      expect(algIssue.evidence.bypass).toContain('Case variation');
    });

    it('should detect HMAC algorithm confusion risk', () => {
      const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({ sub: 'test', exp: Math.floor(Date.now() / 1000) + 3600 }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const algIssue = result.issues.find(i => i.type === 'ALGORITHM_CONFUSION_RISK');
      expect(algIssue).toBeDefined();
      expect(algIssue.severity).toBe('CRITICAL');
      expect(algIssue.cvss).toBe(9.0);
    });

    it('should detect JWT compression as potential DoS', () => {
      const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT', zip: 'DEF' }));
      const payload = btoa(JSON.stringify({ sub: 'test' }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const compressionIssue = result.issues.find(i => i.type === 'JWT_COMPRESSION_DETECTED');
      expect(compressionIssue).toBeDefined();
      expect(compressionIssue.cve).toBe('CVE-2025-27144');
    });

    it('should accept strong algorithms without issues', () => {
      const strongAlgs = ['RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512'];

      strongAlgs.forEach(alg => {
        const header = btoa(JSON.stringify({ alg, typ: 'JWT' }));
        const payload = btoa(JSON.stringify({
          sub: 'test',
          iss: 'test-issuer',
          aud: 'test-audience',
          exp: Math.floor(Date.now() / 1000) + 3600
        }));
        const token = `${header}.${payload}.sig`;

        const result = validator.validateJWT(token);

        const algIssue = result.issues.find(i => i.type.includes('ALGORITHM'));
        expect(algIssue).toBeUndefined();
      });
    });

    it('should detect missing algorithm', () => {
      const header = btoa(JSON.stringify({ typ: 'JWT' })); // No alg
      const payload = btoa(JSON.stringify({ sub: 'test' }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const algIssue = result.issues.find(i => i.type === 'MISSING_ALGORITHM');
      expect(algIssue).toBeDefined();
      expect(algIssue.severity).toBe('CRITICAL');
    });
  });

  describe('validateJWT - Expiration and Timing', () => {
    it('should detect missing expiration claim', () => {
      const header = btoa(JSON.stringify({ alg: 'RS512', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({ sub: 'test' })); // No exp
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const expIssue = result.issues.find(i => i.type === 'MISSING_EXPIRATION');
      expect(expIssue).toBeDefined();
      expect(expIssue.severity).toBe('HIGH');
    });

    it('should detect expired token', () => {
      const now = Math.floor(Date.now() / 1000);
      const header = btoa(JSON.stringify({ alg: 'RS512', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
        sub: 'test',
        exp: now - 3600 // Expired 1 hour ago
      }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const expIssue = result.issues.find(i => i.type === 'TOKEN_EXPIRED');
      expect(expIssue).toBeDefined();
      expect(expIssue.severity).toBe('MEDIUM');
    });

    it('should detect excessive token lifetime', () => {
      const now = Math.floor(Date.now() / 1000);
      const header = btoa(JSON.stringify({ alg: 'RS512', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
        sub: 'test',
        iat: now,
        exp: now + (86400 * 30) // 30 days
      }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const lifetimeIssue = result.issues.find(i => i.type === 'EXCESSIVE_LIFETIME');
      expect(lifetimeIssue).toBeDefined();
      expect(lifetimeIssue.severity).toBe('MEDIUM');
    });

    it('should accept reasonable token lifetime', () => {
      const now = Math.floor(Date.now() / 1000);
      const header = btoa(JSON.stringify({ alg: 'RS512', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
        sub: 'test',
        iat: now,
        exp: now + 3600, // 1 hour
        iss: 'test',
        aud: 'test'
      }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const lifetimeIssue = result.issues.find(i => i.type === 'EXCESSIVE_LIFETIME');
      expect(lifetimeIssue).toBeUndefined();
    });

    it('should detect clock skew attack (iat in future)', () => {
      const now = Math.floor(Date.now() / 1000);
      const header = btoa(JSON.stringify({ alg: 'RS512', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
        sub: 'test',
        iat: now + 600, // 10 minutes in future
        exp: now + 4200
      }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const clockIssue = result.issues.find(i => i.type === 'CLOCK_SKEW_ATTACK');
      expect(clockIssue).toBeDefined();
      expect(clockIssue.severity).toBe('HIGH');
    });

    it('should handle nbf (not before) claim', () => {
      const now = Math.floor(Date.now() / 1000);
      const header = btoa(JSON.stringify({ alg: 'RS512', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
        sub: 'test',
        nbf: now + 3600, // Not valid for 1 hour
        exp: now + 7200
      }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const nbfIssue = result.issues.find(i => i.type === 'TOKEN_NOT_YET_VALID');
      expect(nbfIssue).toBeDefined();
    });
  });

  describe('validateJWT - Claims Validation', () => {
    it('should detect missing issuer claim', () => {
      const now = Math.floor(Date.now() / 1000);
      const header = btoa(JSON.stringify({ alg: 'RS512', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
        sub: 'test',
        exp: now + 3600
      }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const issIssue = result.issues.find(i => i.type === 'MISSING_ISSUER');
      expect(issIssue).toBeDefined();
      expect(issIssue.severity).toBe('MEDIUM');
    });

    it('should detect missing audience claim', () => {
      const now = Math.floor(Date.now() / 1000);
      const header = btoa(JSON.stringify({ alg: 'RS512', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
        sub: 'test',
        iss: 'test-issuer',
        exp: now + 3600
      }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const audIssue = result.issues.find(i => i.type === 'MISSING_AUDIENCE');
      expect(audIssue).toBeDefined();
      expect(audIssue.severity).toBe('MEDIUM');
    });

    it('should detect missing subject claim', () => {
      const now = Math.floor(Date.now() / 1000);
      const header = btoa(JSON.stringify({ alg: 'RS512', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
        iss: 'test-issuer',
        aud: 'test-audience',
        exp: now + 3600
      }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const subIssue = result.issues.find(i => i.type === 'MISSING_SUBJECT');
      expect(subIssue).toBeDefined();
      expect(subIssue.severity).toBe('LOW');
    });

    it('should detect missing jti claim', () => {
      const now = Math.floor(Date.now() / 1000);
      const header = btoa(JSON.stringify({ alg: 'RS512', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
        sub: 'test',
        iss: 'test-issuer',
        aud: 'test-audience',
        exp: now + 3600
      }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const jtiIssue = result.issues.find(i => i.type === 'MISSING_JTI');
      expect(jtiIssue).toBeDefined();
      expect(jtiIssue.severity).toBe('LOW');
    });
  });

  describe('validateJWT - Sensitive Data Detection', () => {
    it('should detect password in payload', () => {
      const now = Math.floor(Date.now() / 1000);
      const header = btoa(JSON.stringify({ alg: 'RS512', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
        sub: 'test',
        password: 'secret123',
        exp: now + 3600
      }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const sensitiveIssue = result.issues.find(i => i.type === 'SENSITIVE_DATA_IN_JWT');
      expect(sensitiveIssue).toBeDefined();
      expect(sensitiveIssue.severity).toBe('CRITICAL');
      expect(sensitiveIssue.message).toContain('password');
    });

    it('should detect API key in payload', () => {
      const now = Math.floor(Date.now() / 1000);
      const header = btoa(JSON.stringify({ alg: 'RS512', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
        sub: 'test',
        api_key: 'sk-1234567890',
        exp: now + 3600
      }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const sensitiveIssue = result.issues.find(i => i.type === 'SENSITIVE_DATA_IN_JWT');
      expect(sensitiveIssue).toBeDefined();
      expect(sensitiveIssue.message).toContain('api_key');
    });

    it('should detect email as PII', () => {
      const now = Math.floor(Date.now() / 1000);
      const header = btoa(JSON.stringify({ alg: 'RS512', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
        sub: 'test',
        email: 'user@example.com',
        exp: now + 3600
      }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const piiIssue = result.issues.find(i => i.type === 'PII_IN_JWT');
      expect(piiIssue).toBeDefined();
      expect(piiIssue.severity).toBe('HIGH');
    });

    it('should detect phone number as PII', () => {
      const now = Math.floor(Date.now() / 1000);
      const header = btoa(JSON.stringify({ alg: 'RS512', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
        sub: 'test',
        phone: '555-123-4567',
        exp: now + 3600
      }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const piiIssue = result.issues.find(i => i.type === 'PII_IN_JWT');
      expect(piiIssue).toBeDefined();
    });

    it('should detect SSN pattern', () => {
      const now = Math.floor(Date.now() / 1000);
      const header = btoa(JSON.stringify({ alg: 'RS512', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
        sub: 'test',
        ssn: '123-45-6789',
        exp: now + 3600
      }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      const piiIssue = result.issues.find(i => i.type === 'PII_IN_JWT');
      expect(piiIssue).toBeDefined();
    });
  });

  describe('validateJWT - Risk Score and Recommendations', () => {
    it('should calculate high risk score for critical issues', () => {
      const header = btoa(JSON.stringify({ alg: 'none', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
        password: 'secret',
        exp: Math.floor(Date.now() / 1000) - 3600
      }));
      const token = `${header}.${payload}.`;

      const result = validator.validateJWT(token);

      expect(result.riskScore).toBeGreaterThan(70);
      expect(result.recommendation.action).toBe('REJECT');
    });

    it('should calculate low risk score for secure token', () => {
      const now = Math.floor(Date.now() / 1000);
      const header = btoa(JSON.stringify({ alg: 'RS512', typ: 'JWT' }));
      const payload = btoa(JSON.stringify({
        sub: 'test-user-id',
        iss: 'https://issuer.example.com',
        aud: 'client-id',
        exp: now + 3600,
        iat: now,
        jti: 'unique-token-id'
      }));
      const token = `${header}.${payload}.sig`;

      const result = validator.validateJWT(token);

      // Secure token should have low risk score (may have minor INFO-level issues)
      expect(result.riskScore).toBeLessThan(70);
      expect(result.recommendation.action).not.toBe('REJECT');
    });
  });

  describe('extractJWTs', () => {
    it('should extract JWT from Authorization header', () => {
      const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig';
      const headers = { 'authorization': `Bearer ${jwt}` };

      const tokens = validator.extractJWTs(headers, null, null);

      expect(tokens).toHaveLength(1);
      expect(tokens[0].location).toBe('Authorization header');
      expect(tokens[0].token).toBe(jwt);
    });

    it('should extract JWT from cookies', () => {
      const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig';
      const cookies = { 'auth_token': jwt };

      const tokens = validator.extractJWTs({}, null, cookies);

      expect(tokens).toHaveLength(1);
      expect(tokens[0].location).toContain('Cookie');
      expect(tokens[0].token).toBe(jwt);
    });

    it('should extract JWT from response body', () => {
      const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig';
      const body = JSON.stringify({ access_token: jwt });

      const tokens = validator.extractJWTs({}, body, null);

      expect(tokens).toHaveLength(1);
      expect(tokens[0].location).toContain('access_token');
      expect(tokens[0].token).toBe(jwt);
    });

    it('should extract multiple JWTs from different locations', () => {
      const jwt1 = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig';
      const jwt2 = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig2';
      const headers = { 'authorization': `Bearer ${jwt1}` };
      const body = JSON.stringify({ id_token: jwt2 });

      const tokens = validator.extractJWTs(headers, body, null);

      expect(tokens).toHaveLength(2);
    });
  });

  describe('_looksLikeJWT', () => {
    it('should identify valid JWT format', () => {
      const jwt = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature';
      expect(validator._looksLikeJWT(jwt)).toBe(true);
    });

    it('should reject non-JWT strings', () => {
      expect(validator._looksLikeJWT('not-a-jwt')).toBe(false);
      expect(validator._looksLikeJWT('one.two')).toBe(false);
      expect(validator._looksLikeJWT('a.b.c')).toBe(false); // Too short
    });

    it('should reject non-strings', () => {
      expect(validator._looksLikeJWT(null)).toBe(false);
      expect(validator._looksLikeJWT(undefined)).toBe(false);
      expect(validator._looksLikeJWT(123)).toBe(false);
      expect(validator._looksLikeJWT({})).toBe(false);
    });
  });
});
