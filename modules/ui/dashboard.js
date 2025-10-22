/**
 * Hera Dashboard
 * Modern dashboard for site security analysis
 */

import { DOMSecurity } from './dom-security.js';

export class HeraDashboard {
  constructor() {
    this.dashboardPanel = null;
    this.dashboardContent = null;
    this.triggerAnalysisBtn = null;
  }

  /**
   * Initialize dashboard
   */
  initialize() {
    this.dashboardPanel = document.getElementById('dashboardPanel');
    this.dashboardContent = document.getElementById('dashboardContent');
    this.triggerAnalysisBtn = document.getElementById('triggerAnalysisBtn');

    if (this.triggerAnalysisBtn) {
      this.triggerAnalysisBtn.addEventListener('click', () => {
        this.triggerManualAnalysis();
      });
    }

    // Load dashboard on init
    this.loadDashboard();
  }

  /**
   * Load dashboard data
   */
  async loadDashboard() {
    try {
      this.showLoadingState();

      // Get stored requests directly from storage
      const result = await chrome.storage.local.get(['authRequests']);
      const requests = result.authRequests || {};
      const requestArray = Object.values(requests);

      if (requestArray.length === 0) {
        this.showEmptyState();
        return;
      }

      // Aggregate findings from all requests
      const allFindings = [];
      requestArray.forEach(req => {
        if (req.metadata?.securityFindings) {
          allFindings.push(...req.metadata.securityFindings);
        }
        if (req.metadata?.evidencePackage?.evidence?.cookieFlags?.vulnerabilities) {
          allFindings.push(...req.metadata.evidencePackage.evidence.cookieFlags.vulnerabilities);
        }
        if (req.metadata?.authAnalysis?.issues) {
          allFindings.push(...req.metadata.authAnalysis.issues);
        }
      });

      // Create analysis object
      const analysis = {
        url: requestArray[0]?.url || 'Unknown',
        timestamp: Date.now(),
        findings: allFindings,
        score: this.calculateScore(allFindings)
      };

      this.renderDashboard(analysis);
    } catch (error) {
      console.error('Failed to load dashboard:', error);
      this.showErrorState(error?.message || String(error) || 'Unknown error');
    }
  }

  calculateScore(findings) {
    const critical = findings.filter(f => f.severity === 'CRITICAL' || f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'HIGH' || f.severity === 'high').length;
    const medium = findings.filter(f => f.severity === 'MEDIUM' || f.severity === 'medium').length;
    const low = findings.filter(f => f.severity === 'LOW' || f.severity === 'low').length;

    const score = 100 - (critical * 25) - (high * 10) - (medium * 5) - (low * 2);
    const totalFindings = critical + high + medium + low;

    let grade = 'A';
    let riskLevel = 'low';
    if (score < 50) { grade = 'F'; riskLevel = 'critical'; }
    else if (score < 60) { grade = 'D'; riskLevel = 'high'; }
    else if (score < 70) { grade = 'C'; riskLevel = 'medium'; }
    else if (score < 80) { grade = 'B'; riskLevel = 'low'; }

    return {
      grade,
      overallScore: Math.max(0, score),
      riskLevel,
      summary: `Found ${totalFindings} security ${totalFindings === 1 ? 'issue' : 'issues'}`,
      totalFindings,
      criticalIssues: critical,
      highIssues: high,
      mediumIssues: medium,
      lowIssues: low,
      categoryScores: {}
    };
  }

  /**
   * Trigger manual analysis
   */
  async triggerManualAnalysis() {
    try {
      console.log('Dashboard: Triggering manual analysis...');
      this.showLoadingState('Analyzing current page...');

      console.log('Dashboard: Sending TRIGGER_ANALYSIS message to background');
      const response = await chrome.runtime.sendMessage({ type: 'TRIGGER_ANALYSIS' });
      console.log('Dashboard: Received response:', response);

      if (response && response.success && response.score) {
        console.log('Dashboard: Analysis successful, score:', response.score);
        setTimeout(() => this.loadDashboard(), 500);
      } else {
        console.error('Dashboard: Analysis failed with response:', response);
        const errorMsg = response?.error || 'Analysis failed. Please try again.';
        this.showErrorState(errorMsg);
      }
    } catch (error) {
      console.error('Dashboard: Manual analysis exception:', error);
      console.error('Dashboard: Error stack:', error.stack);
      this.showErrorState(error.message || 'Analysis failed. Please try again.');
    }
  }

  /**
   * Render dashboard
   */
  async renderDashboard(analysis) {
    // Safety checks for undefined data
    if (!analysis || !analysis.score) {
      this.showEmptyState();
      return;
    }

    const { url, findings = [], score, timestamp } = analysis;

    DOMSecurity.replaceChildren(this.dashboardContent);

    const container = document.createElement('div');
    container.className = 'hera-dashboard';

    // Score card (always visible)
    const scoreCard = this.createScoreCard(score);
    container.appendChild(scoreCard);

    // Findings list (grouped by severity)
    const findingsSection = this.createFindingsSection(findings);
    container.appendChild(findingsSection);

    // Recent requests (expandable) - async
    const requestsSection = await this.createRecentRequestsSection();
    container.appendChild(requestsSection);

    // Site info
    const siteInfo = this.createSiteInfo(url, timestamp);
    container.appendChild(siteInfo);

    this.dashboardContent.appendChild(container);
  }

  createFindingsSection(findings) {
    const section = document.createElement('div');
    section.className = 'dashboard-section findings-section';

    const header = document.createElement('div');
    header.className = 'section-header';
    header.innerHTML = `<h3>🔍 Security Findings (${findings.length})</h3>`;
    header.style.cursor = 'pointer';
    section.appendChild(header);

    const content = document.createElement('div');
    content.className = 'section-content';
    content.style.display = 'block'; // Start expanded

    // Group by severity
    const bySeverity = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] };
    findings.forEach(f => {
      const sev = (f.severity || 'LOW').toUpperCase();
      if (bySeverity[sev]) bySeverity[sev].push(f);
    });

    // Create expandable groups
    ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].forEach(severity => {
      if (bySeverity[severity].length === 0) return;

      const group = document.createElement('details');
      group.className = `finding-group ${severity.toLowerCase()}`;
      group.open = severity === 'CRITICAL' || severity === 'HIGH';

      const summary = document.createElement('summary');
      summary.textContent = `${severity}: ${bySeverity[severity].length} issues`;
      group.appendChild(summary);

      const list = document.createElement('ul');
      bySeverity[severity].forEach(finding => {
        const item = document.createElement('li');
        item.textContent = finding.message || finding.type || 'Unknown issue';
        if (finding.cookie) item.textContent += ` (${finding.cookie})`;
        list.appendChild(item);
      });
      group.appendChild(list);
      content.appendChild(group);
    });

    section.appendChild(content);

    // Toggle visibility
    header.addEventListener('click', () => {
      content.style.display = content.style.display === 'none' ? 'block' : 'none';
    });

    return section;
  }

  async createRecentRequestsSection() {
    const section = document.createElement('div');
    section.className = 'dashboard-section requests-section';

    const header = document.createElement('div');
    header.className = 'section-header';
    header.innerHTML = '<h3>📡 Recent Auth Requests</h3>';
    header.style.cursor = 'pointer';
    section.appendChild(header);

    const content = document.createElement('div');
    content.className = 'section-content';
    content.style.display = 'none'; // Start collapsed

    // Get recent requests from storage
    const result = await chrome.storage.local.get(['authRequests']);
    const requests = Object.values(result.authRequests || {}).slice(0, 10);

    if (requests.length > 0) {
      const list = document.createElement('ul');
      requests.forEach(req => {
        const item = document.createElement('li');
        const url = new URL(req.url);
        item.textContent = `${req.method} ${url.pathname} (${req.statusCode})`;
        list.appendChild(item);
      });
      content.appendChild(list);
    } else {
      content.textContent = 'No recent requests';
    }

    section.appendChild(content);

    // Toggle visibility
    header.addEventListener('click', () => {
      content.style.display = content.style.display === 'none' ? 'block' : 'none';
    });

    return section;
  }

  /**
   * Create score card
   */
  createScoreCard(score) {
    const card = document.createElement('div');
    card.className = 'dashboard-score-card';

    // Safety: Provide defaults for missing score properties
    const grade = score.grade || 'N/A';
    const overallScore = score.overallScore !== undefined ? score.overallScore : 0;
    const riskLevel = score.riskLevel || 'unknown';
    const summaryText = score.summary || 'No analysis data available';
    const totalFindings = score.totalFindings || 0;
    const criticalIssues = score.criticalIssues || 0;
    const highIssues = score.highIssues || 0;
    const mediumIssues = score.mediumIssues || 0;
    const lowIssues = score.lowIssues || 0;

    // Grade display
    const gradeDisplay = document.createElement('div');
    gradeDisplay.className = `dashboard-grade grade-${grade.charAt(0).toLowerCase()}`;

    const gradeValue = DOMSecurity.createSafeElement('div', grade, { className: 'grade-value' });
    const gradeLabel = DOMSecurity.createSafeElement('div', `${Math.round(overallScore)}/100`, { className: 'grade-label' });

    gradeDisplay.appendChild(gradeValue);
    gradeDisplay.appendChild(gradeLabel);

    // Risk badge
    const riskBadge = DOMSecurity.createSafeElement('div', riskLevel.toUpperCase(), {
      className: `dashboard-risk-badge risk-${riskLevel}`
    });

    // Summary
    const summaryEl = DOMSecurity.createSafeElement('p', summaryText, { className: 'dashboard-summary' });

    // Stats
    const stats = document.createElement('div');
    stats.className = 'dashboard-stats';

    const statItems = [
      { label: 'Total Issues', value: totalFindings, className: 'total' },
      { label: 'Critical', value: criticalIssues, className: 'critical' },
      { label: 'High', value: highIssues, className: 'high' },
      { label: 'Medium', value: mediumIssues, className: 'medium' },
      { label: 'Low', value: lowIssues, className: 'low' }
    ];

    statItems.forEach(item => {
      const statItem = document.createElement('div');
      statItem.className = `stat-item ${item.className}`;

      const statValue = DOMSecurity.createSafeElement('div', String(item.value), { className: 'stat-value' });
      const statLabel = DOMSecurity.createSafeElement('div', item.label, { className: 'stat-label' });

      statItem.appendChild(statValue);
      statItem.appendChild(statLabel);
      stats.appendChild(statItem);
    });

    card.appendChild(gradeDisplay);
    card.appendChild(riskBadge);
    card.appendChild(summaryEl);
    card.appendChild(stats);

    return card;
  }

  /**
   * Create category breakdown
   */
  createCategoryBreakdown(score, allFindings = []) {
    const section = document.createElement('div');
    section.className = 'dashboard-section';

    const title = DOMSecurity.createSafeElement('h3', 'Issues by Category');
    section.appendChild(title);

    const categories = document.createElement('div');
    categories.className = 'dashboard-categories';

    // Sort categories by finding count
    const categoryScores = score.categoryScores || {};
    const sortedCategories = Object.entries(categoryScores)
      .sort((a, b) => b[1].findingCount - a[1].findingCount);

    for (const [categoryName, categoryData] of sortedCategories) {
      const categoryCard = document.createElement('div');
      categoryCard.className = 'category-card';

      const categoryHeader = document.createElement('div');
      categoryHeader.className = 'category-header';

      const categoryNameEl = DOMSecurity.createSafeElement('div', this.formatCategoryName(categoryName), { className: 'category-name' });
      const categoryScore = DOMSecurity.createSafeElement('div', `${Math.round(categoryData.score)}/100`, { className: 'category-score' });

      categoryHeader.appendChild(categoryNameEl);
      categoryHeader.appendChild(categoryScore);

      const categoryBar = document.createElement('div');
      categoryBar.className = 'category-bar';

      const categoryFill = document.createElement('div');
      categoryFill.className = 'category-fill';
      categoryFill.style.width = `${categoryData.score}%`;
      categoryFill.style.backgroundColor = this.getScoreColor(categoryData.score);

      categoryBar.appendChild(categoryFill);

      const categoryFindings = DOMSecurity.createSafeElement('div', 
        `${categoryData.findingCount} issue${categoryData.findingCount !== 1 ? 's' : ''}`,
        { className: 'category-findings' }
      );

      categoryCard.appendChild(categoryHeader);
      categoryCard.appendChild(categoryBar);
      categoryCard.appendChild(categoryFindings);

      // Add issues for this category
      if (allFindings && allFindings.length > 0) {
        const categoryIssues = allFindings.filter(f => f.category === categoryName);

        if (categoryIssues.length > 0) {
          const issuesList = document.createElement('div');
          issuesList.className = 'category-issues-list';

          const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          categoryIssues.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

          for (const issue of categoryIssues) {
            const issueItem = document.createElement('div');
            issueItem.className = `category-issue severity-${issue.severity}`;

            const issueHeader = document.createElement('div');
            issueHeader.className = 'issue-header-inline';

            const issueSeverity = issue.severity || 'info';
            const severityBadge = DOMSecurity.createSafeElement('span', issueSeverity.toUpperCase(), {
              className: `severity-badge ${issueSeverity}`
            });
            const issueTitle = DOMSecurity.createSafeElement('span', issue.title, { className: 'issue-title-inline' });

            issueHeader.appendChild(severityBadge);
            issueHeader.appendChild(issueTitle);

            const issueDesc = DOMSecurity.createSafeElement('div', issue.description, { className: 'issue-description-inline' });

            issueItem.appendChild(issueHeader);
            issueItem.appendChild(issueDesc);

            if (issue.recommendation) {
              const issueRec = DOMSecurity.createSafeElement('div', `→ ${issue.recommendation}`, { className: 'issue-recommendation-inline' });
              issueItem.appendChild(issueRec);
            }

            issuesList.appendChild(issueItem);
          }

          categoryCard.appendChild(issuesList);
        }
      }

      categories.appendChild(categoryCard);
    }

    section.appendChild(categories);
    return section;
  }

  /**
   * Create site info
   */
  createSiteInfo(url, timestamp) {
    const section = document.createElement('div');
    section.className = 'dashboard-section dashboard-site-info';

    const title = DOMSecurity.createSafeElement('h3', 'Analysis Details');
    section.appendChild(title);

    const info = document.createElement('div');
    info.className = 'site-info';

    const urlRow = document.createElement('div');
    urlRow.className = 'info-row';
    const urlLabel = DOMSecurity.createSafeElement('span', 'URL:', { className: 'info-label' });
    const urlValue = DOMSecurity.createSafeElement('span', url, { className: 'info-value' });
    urlRow.appendChild(urlLabel);
    urlRow.appendChild(urlValue);

    const timeRow = document.createElement('div');
    timeRow.className = 'info-row';
    const timeLabel = DOMSecurity.createSafeElement('span', 'Analyzed:', { className: 'info-label' });
    const timeValue = DOMSecurity.createSafeElement('span', new Date(timestamp).toLocaleString(), { className: 'info-value' });
    timeRow.appendChild(timeLabel);
    timeRow.appendChild(timeValue);

    info.appendChild(urlRow);
    info.appendChild(timeRow);
    section.appendChild(info);

    return section;
  }

  /**
   * Show loading state
   */
  showLoadingState(message = 'Loading site analysis...') {
    DOMSecurity.replaceChildren(this.dashboardContent);
    const loading = DOMSecurity.createSafeElement('div', message, { className: 'dashboard-loading' });
    this.dashboardContent.appendChild(loading);
  }

  /**
   * Show empty state
   */
  showEmptyState() {
    DOMSecurity.replaceChildren(this.dashboardContent);
    const empty = DOMSecurity.createSafeElement('div', 'No analysis data available. Navigate to a website to analyze.', { className: 'dashboard-empty' });
    this.dashboardContent.appendChild(empty);
  }

  /**
   * Show error state
   */
  showErrorState(message) {
    DOMSecurity.replaceChildren(this.dashboardContent);
    const error = DOMSecurity.createSafeElement('div', `Error: ${message}`, { className: 'dashboard-error' });
    this.dashboardContent.appendChild(error);
  }

  /**
   * Format category name
   */
  formatCategoryName(name) {
    return name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
  }

  /**
   * Get score color
   */
  getScoreColor(score) {
    if (score >= 90) return '#10b981'; // green
    if (score >= 70) return '#3b82f6'; // blue
    if (score >= 50) return '#f59e0b'; // yellow
    if (score >= 30) return '#f97316'; // orange
    return '#ef4444'; // red
  }
}
