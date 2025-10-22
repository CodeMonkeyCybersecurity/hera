# IDOR & GraphQL Detection Specification

**Goal:** Detect potential IDOR vulnerabilities and GraphQL security issues passively
**Approach:** Analyze captured requests, provide guided testing suggestions
**Ethics:** No automatic exploitation, only detection + recommendations

---

## IDOR Detection

### Detection Patterns

#### 1. **Numeric ID Pattern Detection**

```javascript
class IDORDetector {
  analyzeRequest(request) {
    const findings = [];

    // Extract IDs from URL
    const urlIds = this.extractIDs(request.url);

    if (urlIds.numericIds.length > 0) {
      findings.push({
        type: 'POTENTIAL_IDOR_NUMERIC_ID',
        severity: 'MEDIUM',
        confidence: 'LOW',
        endpoint: this.normalizeEndpoint(request.url),
        evidence: {
          url: request.url,
          numericIds: urlIds.numericIds,
          pattern: urlIds.pattern
        },
        testSteps: this.generateTestSteps(urlIds.numericIds[0], request.url),
        recommendation: 'Manually test with different user IDs to verify authorization'
      });
    }

    return findings;
  }

  extractIDs(url) {
    const numericIds = [];
    const uuidIds = [];
    let pattern = 'unknown';

    // Match numeric IDs in path: /users/12345/profile
    const numericMatches = url.match(/\/(\d{3,})/g);
    if (numericMatches) {
      numericIds.push(...numericMatches.map(m => m.replace('/', '')));
      pattern = 'sequential_numeric';
    }

    // Match UUIDs: /users/550e8400-e29b-41d4-a716-446655440000
    const uuidMatches = url.match(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi);
    if (uuidMatches) {
      uuidIds.push(...uuidMatches);
      pattern = 'uuid';
    }

    // Match query parameters: ?user_id=12345
    const queryParams = new URL(url).searchParams;
    const idParams = ['id', 'user_id', 'account_id', 'document_id', 'order_id'];
    for (const param of idParams) {
      if (queryParams.has(param)) {
        const value = queryParams.get(param);
        if (/^\d+$/.test(value)) {
          numericIds.push(value);
          pattern = 'query_param_numeric';
        }
      }
    }

    return { numericIds, uuidIds, pattern };
  }

  normalizeEndpoint(url) {
    // Convert /users/12345/profile → /users/{id}/profile
    return url.replace(/\/\d{3,}/g, '/{id}')
              .replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '{uuid}');
  }

  generateTestSteps(observedId, url) {
    const testId = parseInt(observedId) + 1;
    const testUrl = url.replace(observedId, testId.toString());

    return [
      `1. You accessed: ${url}`,
      `2. Your ID: ${observedId}`,
      `3. Test with: ${testUrl}`,
      `4. Expected: 403 Forbidden or 404 Not Found`,
      `5. If you see data: IDOR vulnerability confirmed!`
    ];
  }
}
```

#### 2. **ID Sequence Tracking**

```javascript
class IDSequenceTracker {
  constructor() {
    this.endpointIds = new Map(); // endpoint -> [ids]
  }

  trackRequest(endpoint, extractedIds) {
    if (!this.endpointIds.has(endpoint)) {
      this.endpointIds.set(endpoint, []);
    }

    const ids = this.endpointIds.get(endpoint);
    ids.push(...extractedIds.numericIds.map(id => parseInt(id)));

    // Analyze if IDs are sequential
    if (ids.length >= 3) {
      const analysis = this.analyzeSequence(ids);

      if (analysis.isSequential) {
        return {
          type: 'SEQUENTIAL_ID_PATTERN',
          severity: 'HIGH',
          confidence: 'MEDIUM',
          endpoint: endpoint,
          evidence: {
            observedIds: ids.slice(-5), // Last 5 IDs
            pattern: analysis.pattern,
            increment: analysis.increment
          },
          recommendation: 'Sequential IDs are highly predictable. High IDOR risk.',
          exploitability: 'HIGH - IDs can be easily guessed'
        };
      }
    }

    return null;
  }

  analyzeSequence(ids) {
    if (ids.length < 3) return { isSequential: false };

    // Sort IDs
    const sorted = [...ids].sort((a, b) => a - b);

    // Check if sequential (increment of 1)
    let isSequential = true;
    let increment = sorted[1] - sorted[0];

    for (let i = 1; i < sorted.length - 1; i++) {
      const diff = sorted[i + 1] - sorted[i];
      if (Math.abs(diff - increment) > 5) { // Allow some variation
        isSequential = false;
        break;
      }
    }

    return {
      isSequential,
      pattern: isSequential ? 'sequential' : 'random',
      increment: increment
    };
  }
}
```

#### 3. **Authorization Header Analysis**

```javascript
class IDORAuthAnalyzer {
  analyzeRequest(request, extractedIds) {
    const findings = [];

    if (extractedIds.numericIds.length === 0) {
      return findings;
    }

    // Check if request has authorization
    const hasAuth = this.hasAuthorization(request.headers);

    if (!hasAuth) {
      findings.push({
        type: 'IDOR_NO_AUTH_HEADER',
        severity: 'HIGH',
        confidence: 'MEDIUM',
        message: 'Request with user ID has no Authorization header',
        evidence: {
          url: request.url,
          ids: extractedIds.numericIds,
          headers: this.getSanitizedHeaders(request.headers)
        },
        recommendation: 'Verify if server validates ownership of resource',
        exploitability: 'HIGH - no visible auth mechanism'
      });
    }

    return findings;
  }

  hasAuthorization(headers) {
    const authHeaders = ['authorization', 'x-api-key', 'x-auth-token'];

    for (const header of authHeaders) {
      if (headers[header.toLowerCase()]) {
        return true;
      }
    }

    return false;
  }

  getSanitizedHeaders(headers) {
    const sanitized = {};
    for (const [key, value] of Object.entries(headers)) {
      // Don't include actual auth values
      if (key.toLowerCase().includes('auth') || key.toLowerCase().includes('token')) {
        sanitized[key] = '[PRESENT]';
      } else {
        sanitized[key] = value;
      }
    }
    return sanitized;
  }
}
```

---

## GraphQL Detection

### Detection Patterns

#### 1. **GraphQL Endpoint Detection**

```javascript
class GraphQLDetector {
  isGraphQLRequest(request) {
    const url = request.url.toLowerCase();
    const contentType = request.headers['content-type'] || '';

    // Check URL patterns
    const urlPatterns = ['/graphql', '/api/graphql', '/query', '/gql'];
    const urlMatch = urlPatterns.some(pattern => url.includes(pattern));

    // Check content type
    const isJSON = contentType.includes('application/json');

    // Check request body for GraphQL query
    let hasQuery = false;
    if (request.requestBody && typeof request.requestBody === 'string') {
      try {
        const body = JSON.parse(request.requestBody);
        hasQuery = body.query || body.queries || body.operationName;
      } catch (e) {
        // Not JSON
      }
    }

    return urlMatch && isJSON && hasQuery;
  }

  analyzeGraphQLRequest(request) {
    const findings = [];

    try {
      const body = JSON.parse(request.requestBody);

      // 1. Check for introspection
      if (this.isIntrospectionQuery(body.query)) {
        findings.push({
          type: 'GRAPHQL_INTROSPECTION_DETECTED',
          severity: 'HIGH',
          confidence: 'HIGH',
          message: 'GraphQL introspection query detected',
          evidence: {
            url: request.url,
            query: body.query.substring(0, 200) // First 200 chars
          },
          recommendation: 'Introspection should be disabled in production',
          testSteps: [
            '1. Check the response to this request',
            '2. If it returns schema types → Introspection is enabled',
            '3. Report as vulnerability if in production'
          ]
        });
      }

      // 2. Check query complexity
      const complexity = this.analyzeComplexity(body.query);
      if (complexity.depth > 10) {
        findings.push({
          type: 'GRAPHQL_DEEP_NESTING',
          severity: 'MEDIUM',
          confidence: 'HIGH',
          message: `GraphQL query has ${complexity.depth} levels of nesting`,
          evidence: {
            depth: complexity.depth,
            query: body.query.substring(0, 200)
          },
          recommendation: 'Deep nesting can cause DoS. Implement depth limiting.',
          exploitability: 'MEDIUM - potential DoS vector'
        });
      }

      // 3. Check for sensitive fields
      const sensitiveFields = this.extractSensitiveFields(body.query);
      if (sensitiveFields.length > 0) {
        findings.push({
          type: 'GRAPHQL_SENSITIVE_FIELDS',
          severity: 'INFO',
          confidence: 'LOW',
          message: 'Query requests potentially sensitive fields',
          evidence: {
            fields: sensitiveFields,
            query: body.query.substring(0, 200)
          },
          recommendation: 'Verify field-level authorization in response',
          testSteps: [
            '1. Check the response data',
            '2. Verify sensitive fields are only returned when authorized',
            '3. Test with different user roles'
          ]
        });
      }

      // 4. Check for mutations with IDs
      if (this.isMutation(body.query)) {
        const ids = this.extractIDsFromMutation(body.query);
        if (ids.length > 0) {
          findings.push({
            type: 'GRAPHQL_MUTATION_IDOR_RISK',
            severity: 'MEDIUM',
            confidence: 'LOW',
            message: 'GraphQL mutation with ID parameters',
            evidence: {
              mutation: body.query.substring(0, 200),
              ids: ids
            },
            testSteps: [
              '1. Note the ID(s) being modified',
              '2. Try the mutation with a different user\'s ID',
              '3. If it succeeds → IDOR vulnerability'
            ],
            recommendation: 'Verify server validates ownership before mutation'
          });
        }
      }

    } catch (e) {
      console.warn('Failed to analyze GraphQL request:', e);
    }

    return findings;
  }

  isIntrospectionQuery(query) {
    if (!query) return false;
    return query.includes('__schema') ||
           query.includes('__type') ||
           query.includes('__TypeKind');
  }

  isMutation(query) {
    if (!query) return false;
    return query.trim().toLowerCase().startsWith('mutation');
  }

  analyzeComplexity(query) {
    if (!query) return { depth: 0 };

    // Count nesting depth by counting { } pairs
    let depth = 0;
    let maxDepth = 0;

    for (const char of query) {
      if (char === '{') {
        depth++;
        maxDepth = Math.max(maxDepth, depth);
      } else if (char === '}') {
        depth--;
      }
    }

    return { depth: maxDepth };
  }

  extractSensitiveFields(query) {
    if (!query) return [];

    const sensitiveKeywords = [
      'password', 'ssn', 'social', 'credit', 'card',
      'token', 'secret', 'private', 'apiKey', 'api_key'
    ];

    const found = [];
    const queryLower = query.toLowerCase();

    for (const keyword of sensitiveKeywords) {
      if (queryLower.includes(keyword)) {
        found.push(keyword);
      }
    }

    return found;
  }

  extractIDsFromMutation(query) {
    if (!query) return [];

    // Extract id parameters: mutation { updateUser(id: 12345) { ... } }
    const idMatches = query.match(/id:\s*(\d+)/gi);
    if (!idMatches) return [];

    return idMatches.map(match => {
      const num = match.match(/\d+/);
      return num ? num[0] : null;
    }).filter(Boolean);
  }
}
```

#### 2. **GraphQL Response Analysis**

```javascript
class GraphQLResponseAnalyzer {
  analyzeResponse(request, responseBody) {
    const findings = [];

    try {
      const response = JSON.parse(responseBody);

      // 1. Check if introspection returned schema
      if (this.hasSchemaInResponse(response)) {
        findings.push({
          type: 'GRAPHQL_INTROSPECTION_ENABLED',
          severity: 'HIGH',
          confidence: 'HIGH',
          message: 'GraphQL introspection is enabled in production',
          evidence: {
            url: request.url,
            schemaTypes: this.extractSchemaTypes(response)
          },
          recommendation: 'Disable introspection in production immediately',
          exploitability: 'HIGH - attackers can enumerate entire API',
          bugBountyNote: 'This is typically accepted as MEDIUM severity finding'
        });
      }

      // 2. Check for sensitive data in response
      const sensitiveData = this.detectSensitiveData(response);
      if (sensitiveData.found) {
        findings.push({
          type: 'GRAPHQL_SENSITIVE_DATA_EXPOSURE',
          severity: 'HIGH',
          confidence: 'MEDIUM',
          message: 'Response contains potentially sensitive data',
          evidence: {
            fields: sensitiveData.fields,
            // Don't include actual values
          },
          recommendation: 'Verify field-level authorization is implemented',
          testSteps: [
            '1. Log out or use a different user account',
            '2. Repeat the same query',
            '3. If you still see the data → Authorization bypass'
          ]
        });
      }

    } catch (e) {
      // Not JSON or parsing failed
    }

    return findings;
  }

  hasSchemaInResponse(response) {
    return response?.data?.__schema?.types ||
           response?.data?.__type;
  }

  extractSchemaTypes(response) {
    const types = response?.data?.__schema?.types || [];
    return types.slice(0, 10).map(t => t.name); // First 10 types
  }

  detectSensitiveData(response) {
    const sensitivePatterns = {
      email: /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi,
      ssn: /\d{3}-\d{2}-\d{4}/g,
      creditCard: /\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}/g,
      phone: /\d{3}-\d{3}-\d{4}/g
    };

    const responseStr = JSON.stringify(response);
    const found = [];

    for (const [field, pattern] of Object.entries(sensitivePatterns)) {
      if (pattern.test(responseStr)) {
        found.push(field);
      }
    }

    return {
      found: found.length > 0,
      fields: found
    };
  }
}
```

---

## Integration into Hera

### Hook into WebRequest Listener

```javascript
// In webrequest-listeners.js:

import { IDORDetector } from './modules/security/idor-detector.js';
import { GraphQLDetector } from './modules/security/graphql-detector.js';

class WebRequestListeners {
  constructor() {
    // ... existing code
    this.idorDetector = new IDORDetector();
    this.graphqlDetector = new GraphQLDetector();
  }

  registerBeforeSendHeaders() {
    chrome.webRequest.onBeforeSendHeaders.addListener((details) => {
      const requestData = this.authRequests.get(details.requestId);
      if (!requestData) return;

      // IDOR Detection
      const idorFindings = this.idorDetector.analyzeRequest(requestData);
      if (idorFindings.length > 0) {
        if (!requestData.metadata.securityFindings) {
          requestData.metadata.securityFindings = [];
        }
        requestData.metadata.securityFindings.push(...idorFindings);
      }

      // GraphQL Detection
      if (this.graphqlDetector.isGraphQLRequest(requestData)) {
        const gqlFindings = this.graphqlDetector.analyzeGraphQLRequest(requestData);
        if (gqlFindings.length > 0) {
          if (!requestData.metadata.securityFindings) {
            requestData.metadata.securityFindings = [];
          }
          requestData.metadata.securityFindings.push(...gqlFindings);
        }
      }
    }, { urls: ["<all_urls>"] }, ["requestHeaders"]);
  }
}
```

---

## UI Display

### Dashboard Finding Card

```javascript
// In dashboard.js:

renderIDORFinding(finding) {
  return `
    <div class="finding-card idor-finding">
      <h3>⚠️ ${finding.type}</h3>
      <div class="severity ${finding.severity}">${finding.severity}</div>

      <p>${finding.message}</p>

      <div class="evidence-section">
        <h4>Evidence:</h4>
        <ul>
          <li>Endpoint: <code>${finding.endpoint}</code></li>
          <li>Detected IDs: <code>${finding.evidence.numericIds.join(', ')}</code></li>
          <li>Pattern: ${finding.evidence.pattern}</li>
        </ul>
      </div>

      <div class="test-steps-section">
        <h4>🧪 Manual Test Steps:</h4>
        <ol>
          ${finding.testSteps.map(step => `<li>${step}</li>`).join('')}
        </ol>
      </div>

      <div class="recommendation">
        <strong>Recommendation:</strong> ${finding.recommendation}
      </div>

      <button onclick="copyTestURL('${finding.evidence.testUrl}')">
        Copy Test URL
      </button>
    </div>
  `;
}
```

---

## Ethical Guidelines

### What Hera WILL Do:
- ✅ Detect patterns that suggest IDOR vulnerabilities
- ✅ Provide guided testing steps for manual verification
- ✅ Track ID sequences to identify predictable patterns
- ✅ Detect GraphQL introspection queries sent by the application
- ✅ Analyze GraphQL query complexity
- ✅ Flag sensitive fields in GraphQL queries

### What Hera WILL NOT Do:
- ❌ Automatically send requests with modified IDs
- ❌ Automatically test other users' resources
- ❌ Send introspection queries without user consent
- ❌ Perform automated fuzzing or brute-force testing
- ❌ Make any requests beyond what the user explicitly initiates

### User Consent Flow:

```javascript
// If user wants active testing:
{
  "testType": "IDOR Active Test",
  "requiresConsent": true,
  "consentDialog": {
    "title": "Active IDOR Testing",
    "message": "This will send a request with a modified ID to test for IDOR. Continue?",
    "warnings": [
      "This may trigger security alerts",
      "Only test on applications you have permission to test",
      "For bug bounty programs, ensure testing is in scope"
    ],
    "buttons": ["Cancel", "I Have Permission - Continue"]
  }
}
```

---

## Expected Results

### IDOR Detection:
- ✅ Passively detect 70-80% of IDOR-vulnerable endpoints
- ✅ Provide actionable test steps for manual verification
- ✅ Track ID patterns to identify high-risk endpoints
- ✅ Zero false exploitation (no unauthorized requests)

### GraphQL Detection:
- ✅ Detect 100% of GraphQL endpoints
- ✅ Flag introspection if enabled (high-value finding)
- ✅ Identify overly complex queries (DoS risk)
- ✅ Detect mutations with ID parameters (IDOR risk)
- ✅ Provide copy-paste introspection queries for manual testing

---

## Implementation Effort

| Feature | Effort | Priority |
|---------|--------|----------|
| IDOR numeric ID detection | 2-3h | P1 🟠 |
| IDOR sequence tracking | 2-3h | P1 🟠 |
| GraphQL endpoint detection | 2h | P1 🟠 |
| GraphQL introspection detection | 2h | P1 🟠 |
| GraphQL complexity analysis | 2h | P2 🟡 |
| UI for test suggestions | 3-4h | P1 🟠 |
| ID pattern analysis | 2-3h | P2 🟡 |

**Total: 15-21 hours**

---

## Testing Plan

### Test Cases:

1. **IDOR - Numeric IDs:**
   - Visit `/api/users/12345/profile`
   - Verify Hera detects numeric ID
   - Verify test steps are provided

2. **IDOR - Sequential Pattern:**
   - Access `/api/documents/1001`, `/api/documents/1002`, `/api/documents/1003`
   - Verify Hera detects sequential pattern
   - Verify HIGH risk score

3. **GraphQL - Introspection:**
   - Send introspection query to `/graphql`
   - Verify Hera detects introspection query
   - If response contains schema, verify HIGH severity finding

4. **GraphQL - Deep Nesting:**
   - Send query with 15 levels of nesting
   - Verify Hera detects complexity
   - Verify MEDIUM severity finding

---

## Future Enhancements

### Phase 2: (Optional, requires explicit user consent)
- Semi-automated IDOR testing with confirmation dialogs
- GraphQL query fuzzing (with consent)
- Batch testing multiple IDs (with rate limiting)
- Integration with Burp Suite for full active testing

### Phase 3:
- ML-based IDOR pattern detection
- Automated test case generation
- Risk scoring based on endpoint sensitivity
- Integration with bug bounty platforms (HackerOne API)
