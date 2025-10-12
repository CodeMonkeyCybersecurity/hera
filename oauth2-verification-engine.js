/**
 * OAuth2 and HSTS Verification Engine for Hera
 *
 * Main entry point that exports both OAuth2VerificationEngine and HSTSVerificationEngine.
 * This module maintains full backward compatibility with the original implementation.
 *
 * Modularization complete:
 * - OAuth2CSRFVerifier: CSRF protection testing (370 lines)
 * - OAuth2PKCEVerifier: PKCE verification (169 lines)
 * - OAuth2ReportGenerator: Bug bounty reports (165 lines)
 * - HSTSVerifier: HSTS verification (267 lines)
 * - OAuth2VerificationEngine: Main coordinator (167 lines)
 */

import { OAuth2VerificationEngine } from './modules/auth/oauth2-verification-engine.js';
import { HSTSVerifier as HSTSVerificationEngine } from './modules/auth/hsts-verifier.js';

export { OAuth2VerificationEngine, HSTSVerificationEngine };
