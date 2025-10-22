// Hera Port and Authentication Security Analyzer
// Analyzes network ports, authentication mechanisms, and authorization patterns

class HeraPortAuthAnalyzer {
  constructor() {
    // Common service ports and their typical auth mechanisms
    this.portProfiles = {
      // Web services
      80: { service: 'HTTP', secure: false, defaultAuth: 'none', risk: 'HIGH' },
      443: { service: 'HTTPS', secure: true, defaultAuth: 'varies', risk: 'LOW' },
      8080: { service: 'HTTP-Alt', secure: false, defaultAuth: 'none', risk: 'HIGH' },
      8443: { service: 'HTTPS-Alt', secure: true, defaultAuth: 'varies', risk: 'MEDIUM' },

      // API and microservices
      3000: { service: 'Node.js/React', secure: false, defaultAuth: 'token', risk: 'MEDIUM' },
      5000: { service: 'Flask/Python', secure: false, defaultAuth: 'token', risk: 'MEDIUM' },
      8000: { service: 'Django/Python', secure: false, defaultAuth: 'session', risk: 'MEDIUM' },
      9000: { service: 'PHP-FPM', secure: false, defaultAuth: 'session', risk: 'MEDIUM' },

      // Database ports
      3306: { service: 'MySQL', secure: false, defaultAuth: 'password', risk: 'CRITICAL' },
      5432: { service: 'PostgreSQL', secure: false, defaultAuth: 'password', risk: 'CRITICAL' },
      27017: { service: 'MongoDB', secure: false, defaultAuth: 'optional', risk: 'CRITICAL' },
      6379: { service: 'Redis', secure: false, defaultAuth: 'optional', risk: 'CRITICAL' },

      // LDAP and directory services
      389: { service: 'LDAP', secure: false, defaultAuth: 'bind', risk: 'HIGH' },
      636: { service: 'LDAPS', secure: true, defaultAuth: 'bind', risk: 'MEDIUM' },
      3268: { service: 'LDAP-GC', secure: false, defaultAuth: 'bind', risk: 'HIGH' },
      3269: { service: 'LDAPS-GC', secure: true, defaultAuth: 'bind', risk: 'MEDIUM' },

      // Authentication services
      88: { service: 'Kerberos', secure: true, defaultAuth: 'ticket', risk: 'LOW' },
      464: { service: 'Kerberos-admin', secure: true, defaultAuth: 'ticket', risk: 'MEDIUM' },
      1812: { service: 'RADIUS', secure: false, defaultAuth: 'shared-secret', risk: 'MEDIUM' },

      // Message queues
      5672: { service: 'RabbitMQ', secure: false, defaultAuth: 'guest:guest', risk: 'HIGH' },
      9092: { service: 'Kafka', secure: false, defaultAuth: 'optional', risk: 'HIGH' },

      // Admin panels
      9090: { service: 'Prometheus', secure: false, defaultAuth: 'none', risk: 'HIGH' },
      3001: { service: 'Grafana', secure: false, defaultAuth: 'admin:admin', risk: 'CRITICAL' },
      15672: { service: 'RabbitMQ-Mgmt', secure: false, defaultAuth: 'guest:guest', risk: 'CRITICAL' },
      8086: { service: 'InfluxDB', secure: false, defaultAuth: 'optional', risk: 'HIGH' }
    };

    // Default credentials database
    this.defaultCredentials = {
      'admin:admin': ['Grafana', 'Jenkins', 'Router-Admin'],
      'admin:password': ['Generic-Admin'],
      'root:root': ['MySQL', 'System-Admin'],
      'guest:guest': ['RabbitMQ', 'Guest-Access'],
      'test:test': ['Test-Environment'],
      'demo:demo': ['Demo-Access'],
      'postgres:postgres': ['PostgreSQL'],
      'elastic:changeme': ['Elasticsearch'],
      'admin:changeme': ['Kibana'],
      'sa:': ['SQL-Server-Empty'],
      'admin:': ['Empty-Password']
    };

    // Authentication vs Authorization patterns
    this.authPatterns = {
      authentication: {
        // Authentication (AuthN) - WHO you are
        patterns: [
          /login|signin|authenticate|auth$/i,
          /\/token|\/oauth\/token/i,
          /\/api\/v\d+\/auth/i,
          /password|passwd|pwd/i,
          /credentials|creds/i,
          /\/ldap\/bind/i,
          /\/saml\/login/i,
          /\/oidc\/auth/i
        ],
        headers: ['authorization', 'x-api-key', 'x-auth-token', 'cookie'],
        methods: ['POST', 'PUT'],
        description: 'Verifying user identity (Who are you?)'
      },
      authorization: {
        // Authorization (AuthZ) - WHAT you can do
        patterns: [
          /\/authorize|\/authz/i,
          /\/permissions|\/perms/i,
          /\/roles|\/rbac/i,
          /\/access|\/acl/i,
          /\/scope|\/scopes/i,
          /\/policy|\/policies/i,
          /can-[a-z]+|is-[a-z]+/i,
          /\/verify-access/i
        ],
        headers: ['x-user-role', 'x-permissions', 'x-scope'],
        methods: ['GET', 'POST'],
        description: 'Checking user permissions (What can you do?)'
      }
    };

    // LDAP-specific patterns
    this.ldapPatterns = {
      bindDN: /^(cn|uid)=[^,]+,.*dc=/i,
      searchBase: /dc=[^,]+,dc=/i,
      ldapURL: /^ldaps?:\/\//i,
      attributes: ['userPrincipalName', 'sAMAccountName', 'uid', 'cn', 'memberOf']
    };
  }

  // Extract port from URL
  extractPort(url) {
    try {
      const urlObj = new URL(url);
      if (urlObj.port) {
        return parseInt(urlObj.port);
      }
      // Default ports
      return urlObj.protocol === 'https:' ? 443 : 80;
    } catch (e) {
      return null;
    }
  }

  // Analyze port security
  analyzePortSecurity(url) {
    const port = this.extractPort(url);
    if (!port) return null;

    const profile = this.portProfiles[port] || {
      service: 'Unknown',
      secure: port === 443 || port === 8443,
      defaultAuth: 'unknown',
      risk: 'UNKNOWN'
    };

    return {
      port,
      ...profile,
      url: url,
      hostname: new URL(url).hostname,
      protocol: new URL(url).protocol.replace(':', ''),
      findings: this.generatePortFindings(port, profile)
    };
  }

  // Generate security findings for port
  generatePortFindings(port, profile) {
    const findings = [];

    if (!profile.secure && port !== 443) {
      findings.push({
        type: 'INSECURE_PORT',
        severity: 'HIGH',
        message: `Port ${port} typically uses unencrypted communication`,
        recommendation: 'Use HTTPS (port 443) or implement TLS encryption'
      });
    }

    if (profile.defaultAuth === 'none') {
      findings.push({
        type: 'NO_AUTH_REQUIRED',
        severity: 'CRITICAL',
        message: `Service on port ${port} may not require authentication`,
        recommendation: 'Implement proper authentication mechanism'
      });
    }

    if (profile.defaultAuth && profile.defaultAuth.includes(':')) {
      findings.push({
        type: 'DEFAULT_CREDENTIALS',
        severity: 'CRITICAL',
        message: `Port ${port} service often uses default credentials: ${profile.defaultAuth}`,
        recommendation: 'Change default credentials immediately'
      });
    }

    if (profile.risk === 'CRITICAL') {
      findings.push({
        type: 'CRITICAL_SERVICE_EXPOSED',
        severity: 'CRITICAL',
        message: `${profile.service} service should not be directly exposed`,
        recommendation: 'Place behind VPN or authentication proxy'
      });
    }

    return findings;
  }

  // Detect authentication vs authorization
  detectAuthType(request) {
    const url = request.url.toLowerCase();
    const method = request.method;
    const headers = request.requestHeaders || [];

    const result = {
      isAuthentication: false,
      isAuthorization: false,
      authMechanism: null,
      details: []
    };

    // Check for authentication patterns
    for (const pattern of this.authPatterns.authentication.patterns) {
      if (pattern.test(url)) {
        result.isAuthentication = true;
        result.details.push({
          type: 'AUTHENTICATION',
          pattern: pattern.source,
          description: this.authPatterns.authentication.description
        });
        break;
      }
    }

    // Check for authorization patterns
    for (const pattern of this.authPatterns.authorization.patterns) {
      if (pattern.test(url)) {
        result.isAuthorization = true;
        result.details.push({
          type: 'AUTHORIZATION',
          pattern: pattern.source,
          description: this.authPatterns.authorization.description
        });
        break;
      }
    }

    // Detect auth mechanism from headers
    const authHeader = headers.find(h => h.name.toLowerCase() === 'authorization');
    if (authHeader) {
      const value = authHeader.value.toLowerCase();
      if (value.startsWith('bearer ')) {
        result.authMechanism = 'Bearer Token (OAuth 2.0/JWT)';
      } else if (value.startsWith('basic ')) {
        result.authMechanism = 'Basic Authentication';
        result.details.push({
          type: 'WARNING',
          message: 'Basic Auth detected - credentials are only base64 encoded'
        });
      } else if (value.startsWith('digest ')) {
        result.authMechanism = 'Digest Authentication';
      } else if (value.startsWith('negotiate ') || value.startsWith('ntlm ')) {
        result.authMechanism = 'Windows Authentication (Kerberos/NTLM)';
      }
    }

    // Check for API key
    if (headers.find(h => h.name.toLowerCase() === 'x-api-key')) {
      result.authMechanism = 'API Key Authentication';
    }

    return result;
  }

  // Detect LDAP authentication
  detectLDAP(request) {
    const findings = [];
    const url = request.url;
    const body = request.requestBody;
    const headers = request.requestHeaders || [];

    // Check for LDAP ports
    const port = this.extractPort(url);
    if (port === 389 || port === 636 || port === 3268 || port === 3269) {
      findings.push({
        type: 'LDAP_PORT_DETECTED',
        severity: port === 389 || port === 3268 ? 'HIGH' : 'MEDIUM',
        message: `LDAP service detected on port ${port}`,
        secure: port === 636 || port === 3269
      });
    }

    // Check for LDAP patterns in request body
    if (body && typeof body === 'string') {
      if (this.ldapPatterns.bindDN.test(body)) {
        findings.push({
          type: 'LDAP_BIND_DETECTED',
          severity: 'INFO',
          message: 'LDAP Bind DN detected in request',
          details: 'Authentication attempt using LDAP distinguished name'
        });
      }

      // Check for LDAP attributes
      for (const attr of this.ldapPatterns.attributes) {
        if (body.includes(attr)) {
          findings.push({
            type: 'LDAP_ATTRIBUTE_DETECTED',
            severity: 'INFO',
            attribute: attr,
            message: `LDAP attribute '${attr}' found in request`
          });
        }
      }
    }

    // Check for LDAP in headers or URL
    if (url.includes('ldap') || headers.some(h => h.value.includes('ldap'))) {
      findings.push({
        type: 'LDAP_REFERENCE_DETECTED',
        severity: 'INFO',
        message: 'LDAP reference found in request'
      });
    }

    return findings;
  }

  // Check for default or weak credentials
  checkDefaultCredentials(request) {
    const findings = [];
    const body = (request.requestBody && typeof request.requestBody === 'string') ? request.requestBody : '';
    const headers = request.requestHeaders || [];

    // Check authorization header for basic auth
    const authHeader = headers.find(h => h.name.toLowerCase() === 'authorization');
    if (authHeader && authHeader.value.startsWith('Basic ')) {
      const encoded = authHeader.value.substring(6);
      try {
        const decoded = atob(encoded);
        for (const [creds, services] of Object.entries(this.defaultCredentials)) {
          if (decoded === creds) {
            findings.push({
              type: 'DEFAULT_CREDENTIALS_USED',
              severity: 'CRITICAL',
              message: `Default credentials detected: ${creds}`,
              services: services.join(', '),
              recommendation: 'Change default credentials immediately'
            });
          }
        }
      } catch (e) {
        // Invalid base64
      }
    }

    // Check for common weak passwords in body
    const weakPasswords = ['password', '123456', 'admin', 'test', 'demo', 'changeme'];
    for (const weak of weakPasswords) {
      if (body.includes(`"password":"${weak}"`) || body.includes(`password=${weak}`)) {
        findings.push({
          type: 'WEAK_PASSWORD_DETECTED',
          severity: 'HIGH',
          message: `Weak password detected: ${weak}`,
          recommendation: 'Use strong, unique passwords'
        });
      }
    }

    return findings;
  }

  // Main analysis function
  analyzeRequest(request) {
    const analysis = {
      timestamp: new Date().toISOString(),
      url: request.url,
      method: request.method,
      port: null,
      portSecurity: null,
      authType: null,
      ldapFindings: [],
      credentialFindings: [],
      overallRisk: 'LOW',
      recommendations: []
    };

    // Analyze port security
    analysis.portSecurity = this.analyzePortSecurity(request.url);
    if (analysis.portSecurity) {
      analysis.port = analysis.portSecurity.port;
    }

    // Detect auth type (authentication vs authorization)
    analysis.authType = this.detectAuthType(request);

    // Check for LDAP
    analysis.ldapFindings = this.detectLDAP(request);

    // Check for default credentials
    analysis.credentialFindings = this.checkDefaultCredentials(request);

    // Calculate overall risk
    analysis.overallRisk = this.calculateOverallRisk(analysis);

    // Generate recommendations
    analysis.recommendations = this.generateRecommendations(analysis);

    return analysis;
  }

  // Calculate overall risk level
  calculateOverallRisk(analysis) {
    let riskScore = 0;

    // Port security risk
    if (analysis.portSecurity) {
      switch (analysis.portSecurity.risk) {
        case 'CRITICAL': riskScore += 40; break;
        case 'HIGH': riskScore += 30; break;
        case 'MEDIUM': riskScore += 20; break;
        case 'LOW': riskScore += 10; break;
      }
    }

    // Credential risks
    if (analysis.credentialFindings.length > 0) {
      analysis.credentialFindings.forEach(finding => {
        if (finding.severity === 'CRITICAL') riskScore += 50;
        if (finding.severity === 'HIGH') riskScore += 30;
      });
    }

    // LDAP risks
    analysis.ldapFindings.forEach(finding => {
      if (finding.severity === 'HIGH') riskScore += 20;
      if (finding.severity === 'MEDIUM') riskScore += 10;
    });

    if (riskScore >= 70) return 'CRITICAL';
    if (riskScore >= 50) return 'HIGH';
    if (riskScore >= 30) return 'MEDIUM';
    return 'LOW';
  }

  // Generate recommendations
  generateRecommendations(analysis) {
    const recommendations = [];

    if (analysis.port && analysis.port !== 443 && analysis.port !== 636) {
      recommendations.push({
        priority: 'HIGH',
        action: 'Use HTTPS/TLS encryption for all authentication traffic'
      });
    }

    if (analysis.credentialFindings.length > 0) {
      recommendations.push({
        priority: 'CRITICAL',
        action: 'Replace all default and weak credentials with strong, unique passwords'
      });
    }

    if (analysis.authType && !analysis.authType.authMechanism) {
      recommendations.push({
        priority: 'HIGH',
        action: 'Implement proper authentication mechanism (OAuth 2.0, SAML, or similar)'
      });
    }

    if (analysis.ldapFindings.some(f => f.type === 'LDAP_PORT_DETECTED' && !f.secure)) {
      recommendations.push({
        priority: 'HIGH',
        action: 'Use LDAPS (port 636) instead of unencrypted LDAP (port 389)'
      });
    }

    return recommendations;
  }
}

// Export for ES6 modules
export { HeraPortAuthAnalyzer };
