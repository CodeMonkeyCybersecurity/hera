// Request Processor - Handles webRequest lifecycle and analysis

import { memoryManager } from './memory-manager.js';
import { storageManager } from './storage-manager.js';

export class RequestProcessor {
  constructor(heraAuthDetector, heraSecretScanner, heraPortAuthAnalyzer, alertManager) {
    this.heraAuthDetector = heraAuthDetector;
    this.heraSecretScanner = heraSecretScanner;
    this.heraPortAuthAnalyzer = heraPortAuthAnalyzer;
    this.alertManager = alertManager;
  }

  // Decode request body from webRequest
  decodeRequestBody(requestBody) {
    if (!requestBody || !requestBody.raw) return null;
    try {
      const decoder = new TextDecoder('utf-8');
      const decodedParts = requestBody.raw.map(part => {
        if (part.bytes) {
          const byteValues = Object.values(part.bytes);
          return decoder.decode(new Uint8Array(byteValues));
        }
        return '';
      });
      return decodedParts.join('');
    } catch (e) {
      console.error('Hera: Failed to decode request body:', e);
      return '[Hera: Failed to decode body]';
    }
  }

  // Handle onBeforeRequest
  handleBeforeRequest(details) {
    const isAuthRelated = this.heraAuthDetector.isAuthRequest(details.url, {});

    if (isAuthRelated) {
      memoryManager.addAuthRequest(details.requestId, {
        id: details.requestId,
        url: details.url,
        method: details.method,
        type: details.type,
        tabId: details.tabId,
        timestamp: new Date().toISOString(),
        requestBody: this.decodeRequestBody(details.requestBody),
        // Placeholders for data from other listeners
        requestHeaders: [],
        responseHeaders: [],
        statusCode: null,
        responseBody: null,
        metadata: {},
      });
    }
  }

  // Handle onBeforeSendHeaders
  handleBeforeSendHeaders(details) {
    const requestData = memoryManager.getAuthRequest(details.requestId);

    if (requestData) {
      requestData.requestHeaders = details.requestHeaders;

      // Perform analysis now that we have headers
      const authAnalysis = this.heraAuthDetector.analyze(
        details.url,
        details.method,
        details.requestHeaders,
        requestData.requestBody
      );

      requestData.authType = authAnalysis.protocol;

      // Ensure metadata exists
      if (!requestData.metadata) {
        requestData.metadata = {};
      }

      requestData.metadata.authAnalysis = authAnalysis;
      requestData.metadata.authAnalysis.riskCategory = this.heraAuthDetector.getRiskCategory(authAnalysis.riskScore);

      // Update port analysis with headers
      requestData.metadata.authTypeAnalysis = this.heraPortAuthAnalyzer.detectAuthType({
        url: details.url,
        method: details.method,
        requestHeaders: details.requestHeaders,
        requestBody: requestData.requestBody
      });

      // Check for default credentials
      requestData.metadata.credentialAnalysis = this.heraPortAuthAnalyzer.checkDefaultCredentials({
        url: details.url,
        requestHeaders: details.requestHeaders,
        requestBody: requestData.requestBody
      });
    }
  }

  // Handle onHeadersReceived
  handleHeadersReceived(details) {
    const requestData = memoryManager.getAuthRequest(details.requestId);

    if (requestData) {
      requestData.statusCode = details.statusCode;
      requestData.responseHeaders = details.responseHeaders;
    }
  }

  // Handle intercepted response (from fetch/XHR)
  async handleInterceptedResponse(data) {
    // Find the matching request in authRequests
    for (const [requestId, requestData] of memoryManager.authRequests.entries()) {
      if (requestData.url === data.url && !requestData.responseBody) {
        requestData.responseBody = data.body;
        requestData.statusCode = data.statusCode;

        // Analyze response body for security issues
        if (!requestData.metadata) requestData.metadata = {};
        if (!requestData.metadata.authAnalysis) {
          requestData.metadata.authAnalysis = { issues: [], riskScore: 0, riskCategory: 'low' };
        }

        const responseBodyIssues = this.heraAuthDetector.analyzeResponseBody(data.body);
        if (responseBodyIssues.length > 0) {
          requestData.metadata.authAnalysis.issues.push(...responseBodyIssues);
          requestData.metadata.authAnalysis.riskScore = this.heraAuthDetector.calculateRiskScore(
            requestData.metadata.authAnalysis.issues
          );
          requestData.metadata.authAnalysis.riskCategory = this.heraAuthDetector.getRiskCategory(
            requestData.metadata.authAnalysis.riskScore
          );
        }

        // P0 OIDC: Re-analyze with response data for OIDC token validation
        try {
          const responseData = {
            body: data.body,
            status: data.statusCode,
            headers: data.responseHeaders || {}
          };
          const oidcAnalysis = this.heraAuthDetector.analyzeRequest(requestData, responseData);
          if (oidcAnalysis.issues && oidcAnalysis.issues.length > 0) {
            // Merge new OIDC issues with existing analysis
            requestData.metadata.authAnalysis.issues.push(...oidcAnalysis.issues);
            requestData.metadata.authAnalysis.riskScore = this.heraAuthDetector.calculateRiskScore(
              requestData.metadata.authAnalysis.issues
            );
            requestData.metadata.authAnalysis.riskCategory = this.heraAuthDetector.getRiskCategory(
              requestData.metadata.authAnalysis.riskScore
            );
          }
        } catch (oidcError) {
          console.warn('OIDC response analysis error:', oidcError);
        }

        // Save to storage
        await storageManager.storeSession(requestData);
        await storageManager.updateBadge();
        memoryManager.deleteAuthRequest(requestId);

        break; // Found matching request
      }
    }
  }

  // Finalize request and save
  async finalizeRequest(requestData) {
    if (!requestData) return;

    // Ensure metadata structure exists
    if (!requestData.metadata) {
      requestData.metadata = {};
    }
    if (!requestData.metadata.authAnalysis) {
      requestData.metadata.authAnalysis = {
        issues: [],
        riskScore: 0,
        riskCategory: 'low'
      };
    }

    // If the content is JavaScript, scan it for secrets
    const contentType = requestData.responseDetails?.headers['content-type'] || '';
    if (requestData.responseBody && (contentType.includes('javascript') || contentType.includes('application/x-javascript'))) {
      const secretFindings = this.heraSecretScanner.scan(requestData.responseBody, requestData.url);
      if (secretFindings.length > 0) {
        requestData.metadata.authAnalysis.issues.push(...secretFindings);
      }
    }

    // Analyze the response body for security issues
    if (requestData.responseBody) {
      const responseBodyIssues = this.heraAuthDetector.analyzeResponseBody(requestData.responseBody);
      if (responseBodyIssues.length > 0) {
        requestData.metadata.authAnalysis.issues.push(...responseBodyIssues);
        // Recalculate risk score
        requestData.metadata.authAnalysis.riskScore = this.heraAuthDetector.calculateRiskScore(
          requestData.metadata.authAnalysis.issues
        );
        requestData.metadata.authAnalysis.riskCategory = this.heraAuthDetector.getRiskCategory(
          requestData.metadata.authAnalysis.riskScore
        );
      }
    }

    // Show alerts for critical findings
    if (requestData.metadata.authAnalysis.issues.length > 0) {
      const criticalFindings = requestData.metadata.authAnalysis.issues.filter(f => f.severity === 'CRITICAL');
      if (criticalFindings.length > 0 && this.alertManager) {
        this.alertManager.processFinding({
          ...criticalFindings[0],
          url: requestData.url,
          evidence: requestData.metadata.authAnalysis
        });
      }
    }

    // Save to storage
    await storageManager.storeSession(requestData);
    await storageManager.updateBadge();
  }
}
