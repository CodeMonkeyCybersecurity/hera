// // Hera JavaScript Secret Scanner
// // Scans JavaScript code for hardcoded secrets like API keys and private keys.

// class HeraSecretScanner {
//   constructor() {
//     // Regex patterns for common secret formats
//     this.patterns = {
//       // P0-ELEVENTH-1 FIX: Bounded quantifier to prevent ReDoS (was {32,} unbounded)
//       // Attack: 'x'.repeat(100000) + '!' causes exponential backtracking
//       GENERIC_API_KEY: new RegExp('[a-zA-Z0-9]{32,100}', 'g'), // Max 100 chars
//       GOOGLE_API_KEY: new RegExp('AIza[0-9A-Za-z\\-_]{35}', 'g'),
//       AWS_ACCESS_KEY_ID: new RegExp('AKIA[0-9A-Z]{16}', 'g'),
//       RSA_PRIVATE_KEY: new RegExp('-----BEGIN RSA PRIVATE KEY-----', 'g'),
//       SSH_PRIVATE_KEY: new RegExp('-----BEGIN OPENSSH PRIVATE KEY-----', 'g'),
//       SLACK_TOKEN: new RegExp('(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})', 'g'),
//       STRIPE_API_KEY: new RegExp('sk_live_[0-9a-zA-Z]{24}', 'g'),
//       FIREBASE_API_KEY: new RegExp('AIza[0-9A-Za-z\\-_]{35}', 'g'), // Same as Google
//     };

//     // P0-ELEVENTH-1 FIX: DoS protection limits
//     this.MAX_SCAN_SIZE = 1024 * 1024; // 1MB max to prevent memory exhaustion
//     this.REGEX_TIMEOUT_MS = 5000; // 5 second max per scan
//   }

//   scan(scriptContent, scriptUrl) {
//     const findings = [];
//     if (!scriptContent || typeof scriptContent !== 'string') {
//       return findings;
//     }

//     // P0-ELEVENTH-1 FIX: Limit input size to prevent ReDoS
//     if (scriptContent.length > this.MAX_SCAN_SIZE) {
//       console.warn(`Hera SECURITY: Script too large for secret scan (${scriptContent.length} bytes), skipping`);
//       findings.push({
//         type: 'SCAN_SKIPPED',
//         severity: 'MEDIUM',
//         message: `Script too large to scan safely (${scriptContent.length} bytes exceeds ${this.MAX_SCAN_SIZE} limit)`,
//         sourceFile: scriptUrl
//       });
//       return findings;
//     }

//     // P0-ELEVENTH-1 FIX: Timeout protection against catastrophic backtracking
//     const startTime = Date.now();

//     for (const [type, pattern] of Object.entries(this.patterns)) {
//       // Check timeout before each regex operation
//       if (Date.now() - startTime > this.REGEX_TIMEOUT_MS) {
//         console.error('Hera SECURITY: Secret scan timeout, aborting');
//         findings.push({
//           type: 'SCAN_TIMEOUT',
//           severity: 'HIGH',
//           message: 'Secret scan timed out - potential ReDoS attack or very large file',
//           sourceFile: scriptUrl
//         });
//         break;
//       }

//       const matches = scriptContent.match(pattern);
//       if (matches) {
//         matches.forEach(match => {
//           findings.push({
//             type: 'HARDCODED_SECRET',
//             severity: 'HIGH',
//             message: `Potential ${type} found in JavaScript file.`,
//             details: `Value: ${match.substring(0, 50)}...`,
//             sourceFile: scriptUrl,
//             exploitation: 'Hardcoded secrets can be stolen by any visitor and used to impersonate the application or access sensitive data.'
//           });
//         });
//       }
//     }

//     return findings;
//   }
// }

// export { HeraSecretScanner };
