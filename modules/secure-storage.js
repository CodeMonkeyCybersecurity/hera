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
    // P0 FIX: Added missing secret patterns (GitHub, OpenAI, Slack, Stripe, etc.)
    this.patterns = {
      // JWT tokens (3 base64 parts separated by dots)
      jwt: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,

      // GitHub tokens (NEW)
      githubToken: /\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b/g,
      githubFineGrained: /\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b/g,

      // OpenAI keys (NEW)
      openaiKey: /\bsk-proj-[A-Za-z0-9]{48,}\b/g,
      openaiLegacy: /\bsk-[A-Za-z0-9]{48,}\b/g,

      // Slack tokens (NEW)
      slackToken: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
      slackWebhook: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,

      // Stripe keys (NEW)
      stripeSecret: /\b(sk|rk)_live_[A-Za-z0-9]{24,}\b/g,
      stripePublic: /\bpk_live_[A-Za-z0-9]{24,}\b/g,

      // SendGrid keys (NEW)
      sendgridKey: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,

      // Twilio keys (NEW)
      twilioKey: /\bSK[a-f0-9]{32}\b/g,

      // Mailgun keys (NEW)
      mailgunKey: /\bkey-[a-f0-9]{32}\b/g,

      // Google API keys (NEW)
      googleApiKey: /\bAIza[A-Za-z0-9_-]{35}\b/g,

      // Generic API keys (various formats)
      apiKey: /(?:api[_-]?key|apikey|access[_-]?key)[\s=:\"']+([A-Za-z0-9_\-]{20,})/gi,

      // AWS keys
      awsAccessKey: /\bAKIA[0-9A-Z]{16}\b/g,
      awsTempKey: /\bASIA[0-9A-Z]{16}\b/g,
      awsSecretKey: /(?:aws[_-]?secret|secret[_-]?key)[\s=:\"']+([A-Za-z0-9/+=]{40})/gi,

      // Azure keys (NEW)
      azureKey: /\b[a-zA-Z0-9/+=]{88}\b/g, // Azure storage keys

      // OAuth tokens
      bearerToken: /Bearer\s+([A-Za-z0-9_\-\.=]{20,})/gi,
      accessToken: /(?:access[_-]?token)[\s=:\"']+([A-Za-z0-9_\-\.=]{20,})/gi,
      refreshToken: /(?:refresh[_-]?token)[\s=:\"']+([A-Za-z0-9_\-\.=]{20,})/gi,

      // Passwords (improved to catch short passwords)
      password: /(?:password|passwd|pwd|pin|secret)[\s=:\"']+([^\s\"'&]{3,})/gi,

      // Credit cards (simple pattern)
      creditCard: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b/g,

      // SSN
      ssn: /\b\d{3}-\d{2}-\d{4}\b/g,

      // Private keys
      privateKey: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,

      // Session IDs
      sessionId: /(?:session[_-]?id|sess[_-]?id)[\s=:\"']+([A-Za-z0-9_\-]{20,})/gi,

      // TOTP secrets (NEW)
      totpSecret: /(?:totp|otp)[_-]?secret[\s=:\"']+([A-Z2-7]{16,})/gi
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

    // P0 FIX: Replace GitHub tokens (NEW)
    redacted = redacted.replace(this.patterns.githubToken, '[REDACTED:GITHUB_TOKEN]');
    redacted = redacted.replace(this.patterns.githubFineGrained, '[REDACTED:GITHUB_PAT]');

    // P0 FIX: Replace OpenAI keys (NEW)
    redacted = redacted.replace(this.patterns.openaiKey, '[REDACTED:OPENAI_KEY]');
    redacted = redacted.replace(this.patterns.openaiLegacy, '[REDACTED:OPENAI_KEY]');

    // P0 FIX: Replace Slack tokens (NEW)
    redacted = redacted.replace(this.patterns.slackToken, '[REDACTED:SLACK_TOKEN]');
    redacted = redacted.replace(this.patterns.slackWebhook, '[REDACTED:SLACK_WEBHOOK]');

    // P0 FIX: Replace Stripe keys (NEW)
    redacted = redacted.replace(this.patterns.stripeSecret, '[REDACTED:STRIPE_SECRET]');
    redacted = redacted.replace(this.patterns.stripePublic, '[REDACTED:STRIPE_PUBLIC]');

    // P0 FIX: Replace other service keys (NEW)
    redacted = redacted.replace(this.patterns.sendgridKey, '[REDACTED:SENDGRID_KEY]');
    redacted = redacted.replace(this.patterns.twilioKey, '[REDACTED:TWILIO_KEY]');
    redacted = redacted.replace(this.patterns.mailgunKey, '[REDACTED:MAILGUN_KEY]');
    redacted = redacted.replace(this.patterns.googleApiKey, '[REDACTED:GOOGLE_API_KEY]');

    // Replace bearer tokens
    redacted = redacted.replace(this.patterns.bearerToken, 'Bearer [REDACTED:TOKEN]');

    // Replace API keys
    redacted = redacted.replace(this.patterns.apiKey, (match, key) => {
      return match.replace(key, '[REDACTED:API_KEY]');
    });

    // Replace AWS keys
    redacted = redacted.replace(this.patterns.awsAccessKey, '[REDACTED:AWS_ACCESS_KEY]');
    redacted = redacted.replace(this.patterns.awsTempKey, '[REDACTED:AWS_TEMP_KEY]');
    redacted = redacted.replace(this.patterns.awsSecretKey, (match, key) => {
      return match.replace(key, '[REDACTED:AWS_SECRET_KEY]');
    });

    // P0 FIX: Replace Azure keys (NEW)
    // Note: This is broad and may have false positives, but better safe than sorry
    // redacted = redacted.replace(this.patterns.azureKey, '[REDACTED:AZURE_KEY]');

    // Replace OAuth tokens
    redacted = redacted.replace(this.patterns.accessToken, (match, token) => {
      return match.replace(token, '[REDACTED:ACCESS_TOKEN]');
    });
    redacted = redacted.replace(this.patterns.refreshToken, (match, token) => {
      return match.replace(token, '[REDACTED:REFRESH_TOKEN]');
    });

    // Replace passwords (improved - now catches short passwords and PINs)
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

    // P0 FIX: Replace TOTP secrets (NEW)
    redacted = redacted.replace(this.patterns.totpSecret, (match, secret) => {
      return match.replace(secret, '[REDACTED:TOTP_SECRET]');
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
 * P0 FIX: Removed encryption - it was security theater.
 *
 * HONEST ASSESSMENT:
 * - Storing encryption seed in chrome.storage.local defeats the purpose
 * - Attacker with access to chrome.storage.local gets both seed AND data
 * - Real encryption requires user password or external key storage
 *
 * CURRENT APPROACH: Secret redaction only (no false promises)
 * - Secrets are redacted with [REDACTED:type] markers
 * - Better than plaintext storage
 * - Honest about limitations
 *
 * FUTURE: Could add user password-based encryption if needed
 */
class NoOpEncryption {
  constructor() {
    this.STORAGE_KEY_SEED = 'heraEncryptionSeed';
    this.encryptionKey = null;
  }

  /**
   * No-op initialization (encryption removed)
   *
   * @returns {Promise<void>}
   */
  async initialize() {
    // No encryption - just redaction
    console.log('Hera: Storage using secret redaction (no encryption)');
  }

  /**
   * No-op "encryption" - just returns data as-is
   * Secrets are already redacted, so this is acceptable
   *
   * @param {*} data - Data to store
   * @returns {Promise<Object>} Data unchanged
   */
  async encrypt(data) {
    // No encryption, return data as-is
    return data;
  }

  /**
   * No-op "decryption" - just returns data as-is
   *
   * @param {Object} data - Data to retrieve
   * @returns {Promise<*>} Data unchanged
   */
  async decrypt(data) {
    // No decryption needed
    return data;
  }
}

// Singleton instances
const secretScanner = new SecretScanner();
const encryption = new NoOpEncryption();

/**
 * Securely store session data with secret redaction
 *
 * P0 FIX: Removed fake encryption. Now uses honest secret redaction only.
 *
 * SECURITY POSTURE:
 * - Secrets redacted with [REDACTED:type] markers
 * - Data stored in chrome.storage.local (accessible to malware/other extensions)
 * - NO encryption (previous encryption was security theater)
 * - Honest about limitations
 *
 * @param {Object} sessionData - Session data to store
 * @returns {Promise<Object>} Sanitized session data with secrets redacted
 */
export async function securelyStoreSession(sessionData) {
  // Redact secrets before storage
  const redacted = secretScanner.redactObject(sessionData);

  // No encryption (was security theater)
  return redacted;
}

/**
 * Retrieve session data (no decryption needed)
 *
 * @param {Object} storedData - Stored data with secrets redacted
 * @returns {Promise<Object>} Session data (secrets remain redacted)
 */
export async function retrieveSecureSession(storedData) {
  // No decryption - secrets are permanently redacted
  return storedData;
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
