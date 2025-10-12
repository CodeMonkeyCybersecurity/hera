// Authentication Issue Visualizer Module
// Visual display of authentication security issues and risk scores

class HeraAuthIssueVisualizer {
  /**
   * Display issues in a formatted container
   * @param {string} protocol - Detected authentication protocol
   * @param {Array} issues - Array of security issues
   * @param {number} riskScore - Calculated risk score (0-100)
   * @returns {HTMLElement} Formatted container element
   */
  displayIssues(protocol, issues, riskScore) {
    const container = document.createElement('div');
    container.className = 'hera-auth-issues';

    // Risk score header
    const riskHeader = document.createElement('div');
    riskHeader.className = `hera-risk-header risk-${this.getRiskLevel(riskScore)}`;
    riskHeader.innerHTML = `
      <div class="hera-risk-score">Risk Score: ${Math.round(riskScore)}/100</div>
      <div class="hera-protocol-badge">${protocol}</div>
    `;

    // Issue list
    const issueList = document.createElement('div');
    issueList.className = 'hera-issue-list';

    if (issues.length === 0) {
      issueList.innerHTML = '<div class="hera-no-issues">No security issues detected</div>';
    } else {
      issues.forEach(issue => {
        const issueDiv = document.createElement('div');
        issueDiv.className = `hera-issue hera-issue-${issue.severity.toLowerCase()}`;
        issueDiv.innerHTML = `
          <div class="hera-issue-header">
            <span class="hera-issue-icon">${this.getSeverityIcon(issue.severity)}</span>
            <span class="hera-issue-type">${issue.type}</span>
            <span class="hera-issue-severity">${issue.severity}</span>
          </div>
          <div class="hera-issue-message">${issue.message}</div>
          ${issue.exploitation ? `<div class="hera-issue-exploitation">${issue.exploitation}</div>` : ''}
        `;
        issueList.appendChild(issueDiv);
      });
    }

    container.appendChild(riskHeader);
    container.appendChild(issueList);

    return container;
  }

  /**
   * Get severity icon emoji
   * @param {string} severity - Severity level
   * @returns {string} Emoji icon
   */
  getSeverityIcon(severity) {
    const icons = {
      CRITICAL: '🔴',
      HIGH: '🟠',
      MEDIUM: '🟡',
      LOW: '🔵'
    };
    return icons[severity] || '⚪';
  }

  /**
   * Get risk level classification
   * @param {number} score - Risk score (0-100)
   * @returns {string} Risk level classification
   */
  getRiskLevel(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 30) return 'medium';
    return 'low';
  }
}

export { HeraAuthIssueVisualizer };
