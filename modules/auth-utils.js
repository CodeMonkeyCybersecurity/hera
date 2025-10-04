/**
 * Authentication Utilities
 *
 * Pure functions for authentication protocol detection and analysis.
 * No external dependencies, fully testable.
 */

/**
 * Detect authentication type from URL and request body
 *
 * Recognizes major authentication protocols and flows:
 * - OAuth 2.0 (with grant types)
 * - OpenID Connect (OIDC)
 * - SAML/SAML2
 * - SCIM
 * - WebAuthn/FIDO2
 * - Kerberos/NTLM
 * - MFA/2FA
 * - Login/Logout flows
 *
 * @param {string} url - Request URL
 * @param {Object} [requestBody] - Request body (optional)
 * @returns {string} Authentication type identifier
 *
 * @example
 * detectAuthType('https://accounts.google.com/oauth/token')
 * // Returns: 'OAuth 2.0'
 *
 * detectAuthType('https://api.example.com/oauth/token', { formData: { grant_type: 'authorization_code' } })
 * // Returns: 'OAuth 2.0 (authorization_code)'
 */
export function detectAuthType(url, requestBody) {
  const lowerUrl = url.toLowerCase();

  // Check for logout/signout flows first
  if (lowerUrl.includes('logout') || lowerUrl.includes('signout') || lowerUrl.includes('sign-out')) {
    return 'Logout/Signout';
  }

  if (lowerUrl.includes('revoke') || lowerUrl.includes('invalidate')) {
    return 'Token Revocation';
  }

  if (lowerUrl.includes('end_session') || lowerUrl.includes('disconnect')) {
    return 'Session Termination';
  }

  if (lowerUrl.includes('saml') || lowerUrl.includes('saml2')) {
    return 'SAML';
  }

  if (lowerUrl.includes('scim')) {
    return 'SCIM';
  }

  if (lowerUrl.includes('token') || lowerUrl.includes('oauth') || lowerUrl.includes('authorize')) {
    return requestBody && requestBody.formData && requestBody.formData.grant_type
      ? `OAuth 2.0 (${requestBody.formData.grant_type})`
      : 'OAuth 2.0';
  }

  if (lowerUrl.includes('openid-configuration') || lowerUrl.includes('userinfo')) {
    return 'OIDC';
  }

  if (lowerUrl.includes('login') || lowerUrl.includes('signin') || lowerUrl.includes('sign-in')) {
    return 'Login/Signin';
  }

  if (lowerUrl.includes('sso')) {
    return 'Single Sign-On';
  }

  if (lowerUrl.includes('mfa') || lowerUrl.includes('2fa') || lowerUrl.includes('otp')) {
    return 'Multi-Factor Auth';
  }

  if (lowerUrl.includes('verify') || lowerUrl.includes('validate')) {
    return 'Verification';
  }

  if (lowerUrl.includes('challenge')) {
    return 'Auth Challenge';
  }

  if (lowerUrl.includes('negotiate') || lowerUrl.includes('ntlm') || lowerUrl.includes('kerberos')) {
    return 'Kerberos/NTLM';
  }

  if (lowerUrl.includes('spnego')) {
    return 'SPNEGO Negotiation';
  }

  if (lowerUrl.includes('ldap') || lowerUrl.includes('directory')) {
    return 'LDAP Authentication';
  }

  if (lowerUrl.includes('webauthn') || lowerUrl.includes('fido') || lowerUrl.includes('u2f')) {
    return 'WebAuthn/FIDO2';
  }

  if (lowerUrl.includes('api/auth') || lowerUrl.includes('api/login') || lowerUrl.includes('api/token')) {
    return 'API Authentication';
  }

  return 'Unknown';
}
