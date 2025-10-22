// SCIM (System for Cross-domain Identity Management) Security Analyzer
// Analyzes SCIM provisioning endpoints for security issues

class SCIMAnalyzer {
  constructor() {
    // SCIM endpoint patterns
    this.scimPatterns = [
      '/scim/v2/Users',
      '/scim/v2/Groups',
      '/scim/v2/ServiceProviderConfig',
      '/scim/v2/ResourceTypes',
      '/scim/v2/Schemas',
      '/scim/Users',
      '/scim/Groups',
      '/provisioning',
      '/directory/v1'
    ];

    // Sensitive SCIM attributes that should be write-only
    this.writeOnlyAttributes = [
      'password',
      'secret',
      'apiKey',
      'privateKey'
    ];

    // SCIM operations and their risk levels
    this.operations = {
      'POST': { risk: 'MEDIUM', action: 'Create user/group' },
      'PUT': { risk: 'HIGH', action: 'Replace user/group' },
      'PATCH': { risk: 'MEDIUM', action: 'Update user/group' },
      'DELETE': { risk: 'HIGH', action: 'Delete user/group' },
      'GET': { risk: 'LOW', action: 'Read user/group' }
    };
  }

  /**
   * Detect if URL is a SCIM endpoint
   */
  isSCIMEndpoint(url) {
    const urlLower = url.toLowerCase();
    return this.scimPatterns.some(pattern => urlLower.includes(pattern.toLowerCase()));
  }

  /**
   * Analyze SCIM request security
   * @param {Object} request - HTTP request with method, headers, body
   * @param {string} url - Request URL
   * @returns {Object} Security analysis
   */
  analyzeSCIMRequest(request, url) {
    const issues = [];
    let riskScore = 0;

    const { method, headers, body } = request;

    // 1. Check authentication
    const authIssue = this._checkAuthentication(headers);
    if (authIssue) {
      issues.push(authIssue);
      riskScore += authIssue.severity === 'CRITICAL' ? 60 : 30;
    }

    // 2. Check for HTTPS
    try {
      const urlObj = new URL(url);
      if (urlObj.protocol !== 'https:') {
        issues.push({
          severity: 'CRITICAL',
          type: 'SCIM_OVER_HTTP',
          message: 'SCIM endpoint accessed over HTTP',
          recommendation: 'Always use HTTPS for SCIM provisioning',
          detail: 'User credentials and PII transmitted in plaintext',
          cwe: 'CWE-319'
        });
        riskScore += 70;
      }
    } catch (e) {
      // Invalid URL
    }

    // 3. Check for bulk operations
    if (method === 'POST' && url.includes('/Bulk')) {
      const bulkIssue = this._checkBulkOperation(body);
      if (bulkIssue) {
        issues.push(bulkIssue);
        riskScore += 25;
      }
    }

    // 4. Check for password in response (write-only violation)
    if (method === 'GET' || method === 'POST' || method === 'PUT' || method === 'PATCH') {
      const writeOnlyIssue = this._checkWriteOnlyAttributes(body, method);
      if (writeOnlyIssue) {
        issues.push(writeOnlyIssue);
        riskScore += 50;
      }
    }

    // 5. Check for rate limiting headers
    if (!headers['x-ratelimit-limit'] && !headers['retry-after']) {
      issues.push({
        severity: 'MEDIUM',
        type: 'NO_RATE_LIMITING',
        message: 'SCIM endpoint missing rate limiting headers',
        recommendation: 'Implement rate limiting to prevent abuse',
        detail: 'Bulk operations without rate limiting enable DoS attacks'
      });
      riskScore += 20;
    }

    // 6. Check for schema validation
    const schemaIssue = this._checkSchemaCompliance(body, url);
    if (schemaIssue) {
      issues.push(schemaIssue);
      riskScore += 15;
    }

    return {
      isSCIM: true,
      method,
      endpoint: url,
      issues,
      riskScore: Math.min(riskScore, 100)
    };
  }

  /**
   * Analyze SCIM response for security issues
   */
  analyzeSCIMResponse(response, url) {
    const issues = [];
    let riskScore = 0;

    const { statusCode, headers, body } = response;

    // 1. Check for error information disclosure
    if (statusCode >= 400 && body) {
      try {
        const bodyObj = typeof body === 'string' ? JSON.parse(body) : body;

        if (bodyObj.detail && bodyObj.detail.length > 200) {
          issues.push({
            severity: 'MEDIUM',
            type: 'VERBOSE_ERROR_MESSAGE',
            message: 'SCIM error message too verbose',
            recommendation: 'Sanitize error messages to avoid information disclosure',
            detail: 'Detailed error messages may reveal internal system information',
            errorLength: bodyObj.detail.length
          });
          riskScore += 15;
        }
      } catch (e) {
        // Not JSON
      }
    }

    // 2. Check for password in response
    if (statusCode < 400 && body) {
      try {
        const bodyObj = typeof body === 'string' ? JSON.parse(body) : body;

        if (this._containsWriteOnlyAttributes(bodyObj)) {
          issues.push({
            severity: 'CRITICAL',
            type: 'PASSWORD_IN_RESPONSE',
            message: 'SCIM response contains write-only attributes',
            recommendation: 'Never return passwords or secrets in SCIM responses',
            detail: 'Write-only attributes like "password" must never be returned',
            cwe: 'CWE-200'
          });
          riskScore += 60;
        }
      } catch (e) {
        // Not JSON
      }
    }

    return {
      issues,
      riskScore: Math.min(riskScore, 100)
    };
  }

  /**
   * Check SCIM authentication method
   */
  _checkAuthentication(headers) {
    const authHeader = headers['authorization'] || headers['Authorization'];

    if (!authHeader) {
      return {
        severity: 'CRITICAL',
        type: 'NO_AUTHENTICATION',
        message: 'SCIM endpoint accessed without authentication',
        recommendation: 'Require OAuth2 Bearer tokens for SCIM access',
        detail: 'Unauthenticated SCIM access allows unauthorized provisioning',
        cwe: 'CWE-306'
      };
    }

    // Check for Basic auth (weak for SCIM)
    if (authHeader.startsWith('Basic ')) {
      return {
        severity: 'HIGH',
        type: 'BASIC_AUTH_SCIM',
        message: 'SCIM endpoint using Basic authentication',
        recommendation: 'Use OAuth2 Bearer tokens instead of Basic auth',
        detail: 'Basic auth credentials can be easily intercepted or brute-forced',
        cwe: 'CWE-522'
      };
    }

    // Check for Bearer token (recommended)
    if (!authHeader.startsWith('Bearer ')) {
      return {
        severity: 'MEDIUM',
        type: 'NON_STANDARD_AUTH',
        message: 'SCIM endpoint using non-standard authentication',
        recommendation: 'Use OAuth2 Bearer tokens as per SCIM spec',
        detail: 'SCIM 2.0 recommends OAuth2 for authentication'
      };
    }

    return null; // OAuth2 Bearer token - good!
  }

  /**
   * Check bulk operation safety
   */
  _checkBulkOperation(body) {
    if (!body) return null;

    try {
      const bodyObj = typeof body === 'string' ? JSON.parse(body) : body;

      if (bodyObj.Operations && Array.isArray(bodyObj.Operations)) {
        const opCount = bodyObj.Operations.length;

        if (opCount > 100) {
          return {
            severity: 'MEDIUM',
            type: 'LARGE_BULK_OPERATION',
            message: `Bulk operation with ${opCount} operations (>100)`,
            recommendation: 'Limit bulk operations to prevent resource exhaustion',
            detail: 'Large bulk operations can cause performance issues',
            operationCount: opCount
          };
        }
      }
    } catch (e) {
      // Not valid JSON
    }

    return null;
  }

  /**
   * Check for write-only attributes in responses
   */
  _checkWriteOnlyAttributes(body, method) {
    if (!body || method === 'POST') return null; // POST requests can contain passwords

    if (this._containsWriteOnlyAttributes(body)) {
      return {
        severity: 'CRITICAL',
        type: 'WRITE_ONLY_ATTRIBUTE_IN_RESPONSE',
        message: 'Write-only attributes detected in SCIM response',
        recommendation: 'Never return password or secret attributes',
        detail: 'Passwords must be write-only per SCIM 2.0 spec',
        reference: 'RFC 7643 Section 7'
      };
    }

    return null;
  }

  /**
   * Recursively check for write-only attributes
   */
  _containsWriteOnlyAttributes(obj) {
    if (typeof obj !== 'object' || obj === null) return false;

    for (const [key, value] of Object.entries(obj)) {
      const keyLower = key.toLowerCase();

      // Check if key matches write-only attribute
      if (this.writeOnlyAttributes.some(attr => keyLower.includes(attr.toLowerCase()))) {
        return true;
      }

      // Recursively check nested objects
      if (typeof value === 'object') {
        if (this._containsWriteOnlyAttributes(value)) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Check SCIM schema compliance
   */
  _checkSchemaCompliance(body, url) {
    if (!body) return null;

    try {
      const bodyObj = typeof body === 'string' ? JSON.parse(body) : body;

      // Check for required SCIM schema fields
      if (url.includes('/Users') && bodyObj.userName === undefined) {
        return {
          severity: 'LOW',
          type: 'MISSING_REQUIRED_FIELD',
          message: 'SCIM User resource missing required "userName" field',
          recommendation: 'Ensure all required SCIM fields are present',
          detail: 'SCIM 2.0 requires userName for User resources',
          reference: 'RFC 7643 Section 4.1'
        };
      }

      // Check for schema URNs
      if (!bodyObj.schemas || !Array.isArray(bodyObj.schemas)) {
        return {
          severity: 'LOW',
          type: 'MISSING_SCHEMA_URN',
          message: 'SCIM resource missing "schemas" field',
          recommendation: 'Include schema URNs for SCIM 2.0 compliance',
          detail: 'schemas field identifies the resource type',
          reference: 'RFC 7643 Section 3.1'
        };
      }
    } catch (e) {
      // Not valid JSON
    }

    return null;
  }

  /**
   * Extract SCIM operation type from URL
   */
  getSCIMOperation(url, method) {
    if (url.includes('/Users')) {
      return { resource: 'User', method, operation: this.operations[method] };
    } else if (url.includes('/Groups')) {
      return { resource: 'Group', method, operation: this.operations[method] };
    } else if (url.includes('/Bulk')) {
      return { resource: 'Bulk', method, operation: { risk: 'HIGH', action: 'Bulk operation' } };
    } else {
      return { resource: 'Unknown', method, operation: this.operations[method] || { risk: 'UNKNOWN' } };
    }
  }
}

export { SCIMAnalyzer };
