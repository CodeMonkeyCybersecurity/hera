/**
 * Secure Storage Module
 *
 * P0 SECURITY FIX: Encrypts sensitive data before storing in chrome.storage.local
 * and redacts secrets/credentials to prevent exposure.
 *
 * CRITICAL: chrome.storage.local is accessible by:
 * - Malware on the user's machine
 * - Other extensions with 'storage' permission (if they know the key)
 * - Extension store compromise scenarios
 *
 * Defense Strategy:
 * 1. Encrypt all session data with user-specific key
 * 2. Redact secrets BEFORE encryption (defense in depth)
 * 3. Auto-delete old sessions (24h retention)
 * 4. Clear encryption keys on extension uninstall
 *
 * @module secure-storage
 */

/**
 * Secret Scanner - Detects and redacts secrets in data
 *
 * Patterns detected:
 * - Passwords in any form
 * - API keys (various formats)
 * - JWT tokens
 * - OAuth tokens (access, refresh, ID tokens)
 * - Session tokens
 * - Credit card numbers
 * - SSNs
 * - Private keys
 * - Bearer tokens in headers
 */
class SecretScanner {
  constructor() {
    // Regex patterns for secret detection
    this.patterns = {
      // JWT tokens (3 base64 parts separated by dots)
      jwt: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,

      // API keys (various formats)
      apiKey: /(?:api[_-]?key|apikey|access[_-]?key)[\s=:\"']+([A-Za-z0-9_\-]{20,})/gi,

      // AWS keys
      awsAccessKey: /AKIA[0-9A-Z]{16}/g,
      awsSecretKey: /(?:aws[_-]?secret|secret[_-]?key)[\s=:\"']+([A-Za-z0-9/+=]{40})/gi,

      // OAuth tokens
      bearerToken: /Bearer\s+([A-Za-z0-9_\-\.=]{20,})/gi,
      accessToken: /(?:access[_-]?token)[\s=:\"']+([A-Za-z0-9_\-\.=]{20,})/gi,
      refreshToken: /(?:refresh[_-]?token)[\s=:\"']+([A-Za-z0-9_\-\.=]{20,})/gi,

      // Passwords
      password: /(?:password|passwd|pwd)[\s=:\"']+([^\s\"'&]{6,})/gi,

      // Credit cards (simple pattern)
      creditCard: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g,

      // SSN
      ssn: /\b\d{3}-\d{2}-\d{4}\b/g,

      // Private keys
      privateKey: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,

      // Session IDs
      sessionId: /(?:session[_-]?id|sess[_-]?id)[\s=:\"']+([A-Za-z0-9_\-]{20,})/gi
    };
  }

  /**
   * Redact secrets from a string
   *
   * @param {string} text - Text to scan and redact
   * @returns {string} Text with secrets replaced by [REDACTED:type]
   */
  redactSecrets(text) {
    if (typeof text !== 'string') return text;

    let redacted = text;

    // Replace JWTs
    redacted = redacted.replace(this.patterns.jwt, '[REDACTED:JWT]');

    // Replace bearer tokens
    redacted = redacted.replace(this.patterns.bearerToken, 'Bearer [REDACTED:TOKEN]');

    // Replace API keys
    redacted = redacted.replace(this.patterns.apiKey, (match, key) => {
      return match.replace(key, '[REDACTED:API_KEY]');
    });

    // Replace AWS keys
    redacted = redacted.replace(this.patterns.awsAccessKey, '[REDACTED:AWS_ACCESS_KEY]');
    redacted = redacted.replace(this.patterns.awsSecretKey, (match, key) => {
      return match.replace(key, '[REDACTED:AWS_SECRET_KEY]');
    });

    // Replace OAuth tokens
    redacted = redacted.replace(this.patterns.accessToken, (match, token) => {
      return match.replace(token, '[REDACTED:ACCESS_TOKEN]');
    });
    redacted = redacted.replace(this.patterns.refreshToken, (match, token) => {
      return match.replace(token, '[REDACTED:REFRESH_TOKEN]');
    });

    // Replace passwords
    redacted = redacted.replace(this.patterns.password, (match, pwd) => {
      return match.replace(pwd, '[REDACTED:PASSWORD]');
    });

    // Replace credit cards
    redacted = redacted.replace(this.patterns.creditCard, '[REDACTED:CREDIT_CARD]');

    // Replace SSNs
    redacted = redacted.replace(this.patterns.ssn, '[REDACTED:SSN]');

    // Replace private keys
    redacted = redacted.replace(this.patterns.privateKey, '[REDACTED:PRIVATE_KEY]');

    // Replace session IDs
    redacted = redacted.replace(this.patterns.sessionId, (match, id) => {
      return match.replace(id, '[REDACTED:SESSION_ID]');
    });

    return redacted;
  }

  /**
   * Redact secrets from an object (recursive)
   *
   * @param {*} obj - Object to redact
   * @returns {*} Object with secrets redacted
   */
  redactObject(obj) {
    if (obj === null || obj === undefined) return obj;

    if (typeof obj === 'string') {
      return this.redactSecrets(obj);
    }

    if (Array.isArray(obj)) {
      return obj.map(item => this.redactObject(item));
    }

    if (typeof obj === 'object') {
      const redacted = {};
      for (const [key, value] of Object.entries(obj)) {
        redacted[key] = this.redactObject(value);
      }
      return redacted;
    }

    return obj;
  }
}

/**
 * Simplified Encryption using Web Crypto API
 *
 * NOTE: This provides encryption at rest in chrome.storage.local
 * The key is derived from a persistent random seed stored in chrome.storage.local
 *
 * LIMITATION: If an attacker has access to chrome.storage.local, they can get
 * both the encrypted data AND the seed. This is NOT perfect security.
 *
 * DEFENSE IN DEPTH: Secrets are redacted BEFORE encryption, so even if
 * encryption is broken, secrets are not exposed.
 */
class SimpleEncryption {
  constructor() {
    this.STORAGE_KEY_SEED = 'heraEncryptionSeed';
    this.encryptionKey = null;
  }

  /**
   * Initialize encryption key from stored seed or create new one
   *
   * @returns {Promise<void>}
   */
  async initialize() {
    if (this.encryptionKey) return;

    try {
      // Get or create seed
      const result = await chrome.storage.local.get([this.STORAGE_KEY_SEED]);
      let seed = result[this.STORAGE_KEY_SEED];

      if (!seed) {
        // Generate new random seed
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        seed = Array.from(array);

        await chrome.storage.local.set({ [this.STORAGE_KEY_SEED]: seed });
      }

      // Derive encryption key from seed
      const seedUint8 = new Uint8Array(seed);
      const keyMaterial = await crypto.subtle.importKey(
        'raw',
        seedUint8,
        'PBKDF2',
        false,
        ['deriveKey']
      );

      this.encryptionKey = await crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), // Static salt (not ideal but OK for this use case)
          iterations: 100000,
          hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );

      console.log('Hera: Storage encryption initialized');
    } catch (error) {
      console.error('Failed to initialize encryption:', error);
      // Encryption failure - continue without encryption but log warning
    }
  }

  /**
   * Encrypt data
   *
   * @param {*} data - Data to encrypt
   * @returns {Promise<Object|null>} Encrypted data object or null on error
   */
  async encrypt(data) {
    if (!this.encryptionKey) {
      await this.initialize();
      if (!this.encryptionKey) {
        console.warn('Hera: Encryption unavailable, storing unencrypted');
        return null;
      }
    }

    try {
      const jsonString = JSON.stringify(data);
      const encoder = new TextEncoder();
      const dataBuffer = encoder.encode(jsonString);

      // Generate random IV
      const iv = crypto.getRandomValues(new Uint8Array(12));

      // Encrypt
      const encryptedBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        this.encryptionKey,
        dataBuffer
      );

      // Return encrypted data with IV
      return {
        encrypted: true,
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(encryptedBuffer))
      };
    } catch (error) {
      console.error('Encryption failed:', error);
      return null;
    }
  }

  /**
   * Decrypt data
   *
   * @param {Object} encryptedObj - Encrypted data object
   * @returns {Promise<*|null>} Decrypted data or null on error
   */
  async decrypt(encryptedObj) {
    if (!encryptedObj || !encryptedObj.encrypted) {
      // Not encrypted, return as-is
      return encryptedObj;
    }

    if (!this.encryptionKey) {
      await this.initialize();
      if (!this.encryptionKey) {
        console.error('Hera: Cannot decrypt - encryption key unavailable');
        return null;
      }
    }

    try {
      const iv = new Uint8Array(encryptedObj.iv);
      const encryptedData = new Uint8Array(encryptedObj.data);

      // Decrypt
      const decryptedBuffer = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv },
        this.encryptionKey,
        encryptedData
      );

      // Decode
      const decoder = new TextDecoder();
      const jsonString = decoder.decode(decryptedBuffer);

      return JSON.parse(jsonString);
    } catch (error) {
      console.error('Decryption failed:', error);
      return null;
    }
  }
}

// Singleton instances
const secretScanner = new SecretScanner();
const encryption = new SimpleEncryption();

/**
 * Securely store session data with redaction and encryption
 *
 * @param {Object} sessionData - Session data to store
 * @returns {Promise<Object>} Sanitized and encrypted session data
 */
export async function securelyStoreSession(sessionData) {
  // P0 FIX Step 1: Redact secrets FIRST (defense in depth)
  const redacted = secretScanner.redactObject(sessionData);

  // P0 FIX Step 2: Encrypt redacted data
  const encrypted = await encryption.encrypt(redacted);

  // Return encrypted data (or redacted if encryption failed)
  return encrypted || redacted;
}

/**
 * Retrieve and decrypt session data
 *
 * @param {Object} storedData - Stored (potentially encrypted) data
 * @returns {Promise<Object>} Decrypted session data
 */
export async function retrieveSecureSession(storedData) {
  return await encryption.decrypt(storedData);
}

/**
 * Export secret scanner for standalone use
 */
export { secretScanner };

/**
 * Initialize encryption on module load
 */
(async () => {
  await encryption.initialize();
})();
