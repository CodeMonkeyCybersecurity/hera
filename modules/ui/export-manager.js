/**
 * Export Manager
 * Handles exporting auth requests in multiple formats (JSON, Burp, Nuclei, cURL)
 */

export class ExportManager {
  constructor() {
    this.formats = ['json', 'burp', 'nuclei', 'curl'];
  }

  /**
   * Show export format selection modal
   * @param {Array} data - Data to export
   * @param {string} type - 'current' or 'all'
   */
  showExportModal(data, type) {
    const modal = document.createElement('div');
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0,0,0,0.8);
      z-index: 10000;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, sans-serif;
    `;

    modal.innerHTML = `
      <div style="
        background: white;
        padding: 30px;
        border-radius: 12px;
        max-width: 600px;
        width: 90%;
      ">
        <h2 style="margin: 0 0 20px 0; color: #333;">Export ${type === 'current' ? 'Current View' : 'All Sessions'}</h2>

        <div style="margin-bottom: 20px; color: #666;">
          Choose the export format for your security testing workflow:
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 30px;">
          <button class="export-option" data-format="json" style="
            padding: 20px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            background: white;
            cursor: pointer;
            text-align: left;
            transition: all 0.2s;
          ">
            <strong style="display: block; margin-bottom: 5px;">JSON (Default)</strong>
            <small style="color: #666;">Complete data for analysis</small>
          </button>

          <button class="export-option" data-format="burp" style="
            padding: 20px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            background: white;
            cursor: pointer;
            text-align: left;
            transition: all 0.2s;
          ">
            <strong style="display: block; margin-bottom: 5px;">Burp Suite</strong>
            <small style="color: #666;">Import-ready session file</small>
          </button>

          <button class="export-option" data-format="nuclei" style="
            padding: 20px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            background: white;
            cursor: pointer;
            text-align: left;
            transition: all 0.2s;
          ">
            <strong style="display: block; margin-bottom: 5px;">Nuclei Targets</strong>
            <small style="color: #666;">Host list for vulnerability scanning</small>
          </button>

          <button class="export-option" data-format="curl" style="
            padding: 20px;
            border: 2px solid #e0e0e0;
            border-radius: 8px;
            background: white;
            cursor: pointer;
            text-align: left;
            transition: all 0.2s;
          ">
            <strong style="display: block; margin-bottom: 5px;">cURL Commands</strong>
            <small style="color: #666;">Replay requests manually</small>
          </button>
        </div>

        <div style="display: flex; gap: 10px; justify-content: flex-end;">
          <button id="cancelExport" style="
            background: #666;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 6px;
            cursor: pointer;
          ">
            Cancel
          </button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    // Add hover effects and click handlers
    const options = modal.querySelectorAll('.export-option');
    options.forEach(option => {
      option.addEventListener('mouseenter', () => {
        option.style.borderColor = '#4CAF50';
        option.style.backgroundColor = '#f8f8f8';
      });
      option.addEventListener('mouseleave', () => {
        option.style.borderColor = '#e0e0e0';
        option.style.backgroundColor = 'white';
      });
      option.addEventListener('click', () => {
        const format = option.dataset.format;
        modal.remove();
        this.performExport(data, format, type);
      });
    });

    // Cancel button
    modal.querySelector('#cancelExport').addEventListener('click', () => {
      modal.remove();
    });
  }

  /**
   * Perform export based on format
   * @param {Array} data - Data to export
   * @param {string} format - Export format
   * @param {string} type - 'current' or 'all'
   */
  performExport(data, format, type) {
    const now = new Date();
    const date = now.toISOString().slice(2, 10); // YY-MM-DD
    const time = now.toISOString().slice(11, 19).replace(/:/g, '-'); // HH-MM-SS

    switch (format) {
      case 'json':
        this.exportAsJSON(data, type, date, time);
        break;
      case 'burp':
        this.exportAsBurp(data, type, date, time);
        break;
      case 'nuclei':
        this.exportAsNuclei(data, type, date, time);
        break;
      case 'curl':
        this.exportAsCurl(data, type, date, time);
        break;
      default:
        this.exportAsJSON(data, type, date, time);
    }
  }

  /**
   * Export as JSON
   */
  exportAsJSON(data, type, date, time) {
    const exportData = type === 'current'
      ? { timestamp: new Date().toISOString(), requests: data }
      : data;

    // Safe JSON serialization
    let jsonString;
    try {
      jsonString = JSON.stringify(exportData, (_, value) => {
        if (typeof value === 'function') return '[Function]';
        if (value instanceof Error) return value.message;
        if (value === undefined) return null;
        return value;
      }, 2);
    } catch (jsonError) {
      console.error('JSON serialization error:', jsonError);
      alert('Error creating export file: ' + jsonError.message);
      return;
    }

    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    chrome.downloads.download({
      url: url,
      filename: `${date}_${time}_hera-${type}.json`,
      saveAs: true
    });
  }

  /**
   * Export as Burp Suite session
   */
  exportAsBurp(data, type, date, time) {
    const requests = type === 'current' ? data : this.getAllRequestsFromSessions(data);

    const burpSession = {
      metadata: {
        version: "1.0.0",
        tool: "Hera Browser Extension",
        timestamp: new Date().toISOString(),
        description: "Authentication security analysis session"
      },
      proxy: {
        history: requests.map((req, index) => ({
          id: index + 1,
          url: req.url,
          method: req.method || 'GET',
          status: req.statusCode || 0,
          length: req.responseBody ? req.responseBody.length : 0,
          mime_type: req.responseHeaders?.find(h => h.name.toLowerCase() === 'content-type')?.value || 'text/html',
          protocol: req.url.startsWith('https') ? 'https' : 'http',
          host: new URL(req.url).hostname,
          path: new URL(req.url).pathname + new URL(req.url).search,
          request: {
            raw: this.buildRawRequest(req),
            headers: req.requestHeaders || [],
            body: req.requestBody || ''
          },
          response: {
            raw: this.buildRawResponse(req),
            headers: req.responseHeaders || [],
            body: req.responseBody || ''
          },
          comment: `Hera: ${req.authType || 'Unknown'} - Risk: ${req.metadata?.authAnalysis?.riskCategory || 'unknown'}`
        }))
      }
    };

    const jsonString = JSON.stringify(burpSession, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);

    chrome.downloads.download({
      url: url,
      filename: `${date}_${time}_hera-burp-session.json`,
      saveAs: true
    });
  }

  /**
   * Export as Nuclei target list
   */
  exportAsNuclei(data, type, date, time) {
    const requests = type === 'current' ? data : this.getAllRequestsFromSessions(data);

    // Extract unique hosts
    const hosts = [...new Set(requests.map(req => {
      try {
        return new URL(req.url).origin;
      } catch (e) {
        return null;
      }
    }))].filter(Boolean);

    const nucleiConfig = {
      targets: hosts,
      config: {
        "rate-limit": 150,
        "timeout": 10,
        "retries": 1,
        "severity": ["critical", "high", "medium"],
        "tags": ["auth", "oauth", "saml", "oidc", "jwt"]
      },
      context: {
        tool: "Hera Browser Extension",
        timestamp: new Date().toISOString(),
        total_hosts: hosts.length,
        auth_flows_detected: requests.length,
        high_risk_hosts: hosts.filter(host => {
          return requests.some(req =>
            req.url.includes(host) &&
            req.metadata?.authAnalysis?.riskScore > 70
          );
        })
      }
    };

    // Download config file
    const configBlob = new Blob([JSON.stringify(nucleiConfig, null, 2)], { type: 'application/json' });
    const configUrl = URL.createObjectURL(configBlob);
    chrome.downloads.download({
      url: configUrl,
      filename: `${date}_${time}_hera-nuclei-config.json`,
      saveAs: false
    });

    // Download target list
    const targetsBlob = new Blob([hosts.join('\n')], { type: 'text/plain' });
    const targetsUrl = URL.createObjectURL(targetsBlob);
    chrome.downloads.download({
      url: targetsUrl,
      filename: `${date}_${time}_hera-nuclei-targets.txt`,
      saveAs: true
    });
  }

  /**
   * Export as cURL commands
   */
  exportAsCurl(data, type, date, time) {
    const requests = type === 'current' ? data : this.getAllRequestsFromSessions(data);

    const curlCommands = requests.map((req, index) => {
      let curl = `# Request ${index + 1}: ${req.authType || 'Unknown'} - ${req.url}\n`;
      curl += `curl -X ${req.method || 'GET'} \\\n`;
      curl += `  '${req.url}' \\\n`;

      // Add headers
      if (req.requestHeaders && Array.isArray(req.requestHeaders)) {
        req.requestHeaders.forEach(header => {
          if (header.name && header.value) {
            curl += `  -H '${header.name}: ${header.value}' \\\n`;
          }
        });
      }

      // Add body if present
      if (req.requestBody) {
        curl += `  -d '${req.requestBody.replace(/'/g, "'\\''")}'\\\n`;
      }

      // Add common options
      curl += `  --silent \\\n`;
      curl += `  --show-error \\\n`;
      curl += `  --location \\\n`;
      curl += `  --max-time 30`;

      return curl;
    }).join('\n\n');

    const header = `#!/bin/bash
# Hera Authentication Flow Replay Script
# Generated: ${new Date().toISOString()}
# Total Requests: ${requests.length}
#
# Usage: bash ${date}_${time}_hera-curl-commands.sh
#

`;

    const fullScript = header + curlCommands;
    const blob = new Blob([fullScript], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);

    chrome.downloads.download({
      url: url,
      filename: `${date}_${time}_hera-curl-commands.sh`,
      saveAs: true
    });
  }

  /**
   * Build raw HTTP request
   */
  buildRawRequest(req) {
    const url = new URL(req.url);
    let raw = `${req.method || 'GET'} ${url.pathname}${url.search} HTTP/1.1\r\n`;
    raw += `Host: ${url.hostname}\r\n`;

    if (req.requestHeaders && Array.isArray(req.requestHeaders)) {
      req.requestHeaders.forEach(header => {
        if (header.name && header.value) {
          raw += `${header.name}: ${header.value}\r\n`;
        }
      });
    }

    raw += '\r\n';
    if (req.requestBody) {
      raw += req.requestBody;
    }

    return raw;
  }

  /**
   * Build raw HTTP response
   */
  buildRawResponse(req) {
    let raw = `HTTP/1.1 ${req.statusCode || 200} OK\r\n`;

    if (req.responseHeaders && Array.isArray(req.responseHeaders)) {
      req.responseHeaders.forEach(header => {
        if (header.name && header.value) {
          raw += `${header.name}: ${header.value}\r\n`;
        }
      });
    }

    raw += '\r\n';
    if (req.responseBody) {
      raw += req.responseBody;
    }

    return raw;
  }

  /**
   * Extract all requests from sessions
   */
  getAllRequestsFromSessions(data) {
    if (Array.isArray(data)) {
      return data;
    }

    const allRequests = [];
    if (data.sessions && Array.isArray(data.sessions)) {
      data.sessions.forEach(session => {
        if (session.requests && Array.isArray(session.requests)) {
          allRequests.push(...session.requests);
        }
      });
    }
    return allRequests;
  }
}
