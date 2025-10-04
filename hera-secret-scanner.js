// Hera JavaScript Secret Scanner
// Scans JavaScript code for hardcoded secrets like API keys and private keys.

class HeraSecretScanner {
  constructor() {
    // Regex patterns for common secret formats
    this.patterns = {
      GENERIC_API_KEY: new RegExp('[a-zA-Z0-9]{32,}', 'g'), // Generic high-entropy string
      GOOGLE_API_KEY: new RegExp('AIza[0-9A-Za-z\\-_]{35}', 'g'),
      AWS_ACCESS_KEY_ID: new RegExp('AKIA[0-9A-Z]{16}', 'g'),
      RSA_PRIVATE_KEY: new RegExp('-----BEGIN RSA PRIVATE KEY-----', 'g'),
      SSH_PRIVATE_KEY: new RegExp('-----BEGIN OPENSSH PRIVATE KEY-----', 'g'),
      SLACK_TOKEN: new RegExp('(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})', 'g'),
      STRIPE_API_KEY: new RegExp('sk_live_[0-9a-zA-Z]{24}', 'g'),
      FIREBASE_API_KEY: new RegExp('AIza[0-9A-Za-z\\-_]{35}', 'g'), // Same as Google
    };
  }

  scan(scriptContent, scriptUrl) {
    const findings = [];
    if (!scriptContent || typeof scriptContent !== 'string') {
      return findings;
    }

    for (const [type, pattern] of Object.entries(this.patterns)) {
      const matches = scriptContent.match(pattern);
      if (matches) {
        matches.forEach(match => {
          findings.push({
            type: 'HARDCODED_SECRET',
            severity: 'HIGH',
            message: `Potential ${type} found in JavaScript file.`,
            details: `Value: ${match.substring(0, 50)}...`,
            sourceFile: scriptUrl,
            exploitation: 'Hardcoded secrets can be stolen by any visitor and used to impersonate the application or access sensitive data.'
          });
        });
      }
    }

    return findings;
  }
}

export { HeraSecretScanner };
