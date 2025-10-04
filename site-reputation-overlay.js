// Site Reputation Overlay - On-page warning system for critical issues
// Displays non-intrusive badges and critical warnings based on risk score
// ARCHITECTURE FIX P0-2: Removed ES6 export - loaded via script tag, uses window assignment instead

class SiteReputationOverlay {
  constructor() {
    this.overlayId = 'hera-reputation-overlay';
    this.badgeId = 'hera-reputation-badge';
    this.bannerIdPrefix = 'hera-banner-';

    // Display thresholds
    this.thresholds = {
      showBanner: 60,      // Show warning banner if score below 60
      showCriticalAlert: 40 // Show blocking alert if score below 40
    };

    // Overlay state
    this.isVisible = false;
    this.currentBanners = [];
  }

  // Initialize overlay (called from content script)
  initialize() {
    // Inject styles
    this.injectStyles();

    // Listen for messages from background script
    this.setupMessageListener();

    console.log('Hera: Site Reputation Overlay initialized');
  }

  // Display reputation based on score
  displayReputation(scoreData) {
    // Remove existing overlays
    this.clear();

    const score = scoreData.overallScore;
    const riskLevel = scoreData.riskLevel;

    // Show appropriate UI based on score
    if (score < this.thresholds.showCriticalAlert) {
      this.showCriticalAlert(scoreData);
    } else if (score < this.thresholds.showBanner) {
      this.showWarningBanner(scoreData);
    } else {
      this.showBadge(scoreData);
    }
  }

  // Show critical blocking alert (for dangerous sites)
  showCriticalAlert(scoreData) {
    const overlay = document.createElement('div');
    overlay.id = this.overlayId;
    overlay.className = 'hera-critical-overlay';

    // Build alert content
    const content = document.createElement('div');
    content.className = 'hera-alert-content';

    // Icon
    const icon = document.createElement('div');
    icon.className = 'hera-alert-icon';
    icon.textContent = '⚠️';
    content.appendChild(icon);

    // Title
    const title = document.createElement('h1');
    title.className = 'hera-alert-title';
    title.textContent = 'Warning: High Risk Site';
    content.appendChild(title);

    // Summary
    const summary = document.createElement('p');
    summary.className = 'hera-alert-summary';
    summary.textContent = scoreData.summary;
    content.appendChild(summary);

    // Score display
    const scoreDisplay = document.createElement('div');
    scoreDisplay.className = 'hera-score-display';

    const scoreLabel = document.createElement('div');
    scoreLabel.className = 'hera-score-label';
    scoreLabel.textContent = 'Safety Score';
    scoreDisplay.appendChild(scoreLabel);

    const scoreValue = document.createElement('div');
    scoreValue.className = 'hera-score-value critical';
    scoreValue.textContent = `${scoreData.grade} (${Math.round(scoreData.overallScore)}/100)`;
    scoreDisplay.appendChild(scoreValue);

    content.appendChild(scoreDisplay);

    // Top recommendations
    if (scoreData.recommendations && scoreData.recommendations.length > 0) {
      const recsTitle = document.createElement('h2');
      recsTitle.className = 'hera-recs-title';
      recsTitle.textContent = 'Critical Issues:';
      content.appendChild(recsTitle);

      const recsList = document.createElement('ul');
      recsList.className = 'hera-recs-list';

      for (const rec of scoreData.recommendations.slice(0, 3)) {
        const recItem = document.createElement('li');
        recItem.textContent = `${rec.title} (${rec.findingCount} findings)`;
        recsList.appendChild(recItem);
      }

      content.appendChild(recsList);
    }

    // Buttons
    const buttonContainer = document.createElement('div');
    buttonContainer.className = 'hera-alert-buttons';

    const continueButton = document.createElement('button');
    continueButton.className = 'hera-button hera-button-danger';
    continueButton.textContent = 'Continue Anyway';
    continueButton.addEventListener('click', () => {
      this.clear();
      this.showBadge(scoreData); // Show badge instead
    });
    buttonContainer.appendChild(continueButton);

    const leaveButton = document.createElement('button');
    leaveButton.className = 'hera-button hera-button-primary';
    leaveButton.textContent = 'Leave Site';
    leaveButton.addEventListener('click', () => {
      window.history.back();
    });
    buttonContainer.appendChild(leaveButton);

    const detailsButton = document.createElement('button');
    detailsButton.className = 'hera-button hera-button-secondary';
    detailsButton.textContent = 'View Details';
    detailsButton.addEventListener('click', () => {
      // Open Hera popup
      chrome.runtime.sendMessage({ type: 'OPEN_POPUP' });
    });
    buttonContainer.appendChild(detailsButton);

    content.appendChild(buttonContainer);

    // Powered by
    const footer = document.createElement('div');
    footer.className = 'hera-alert-footer';
    footer.textContent = 'Protected by Hera Security';
    content.appendChild(footer);

    overlay.appendChild(content);
    document.body.appendChild(overlay);

    this.isVisible = true;
  }

  // Show warning banner (for moderate risk sites)
  showWarningBanner(scoreData) {
    const banner = document.createElement('div');
    banner.id = `${this.bannerIdPrefix}warning`;
    banner.className = 'hera-warning-banner';

    // Icon
    const icon = document.createElement('span');
    icon.className = 'hera-banner-icon';
    icon.textContent = '⚠️';
    banner.appendChild(icon);

    // Message
    const message = document.createElement('span');
    message.className = 'hera-banner-message';
    message.textContent = `Hera detected ${scoreData.totalFindings} issues on this site (Grade: ${scoreData.grade})`;
    banner.appendChild(message);

    // View button
    const viewButton = document.createElement('button');
    viewButton.className = 'hera-banner-button';
    viewButton.textContent = 'View Details';
    viewButton.addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'OPEN_POPUP' });
    });
    banner.appendChild(viewButton);

    // Close button
    const closeButton = document.createElement('button');
    closeButton.className = 'hera-banner-close';
    closeButton.textContent = '×';
    closeButton.addEventListener('click', () => {
      banner.remove();
      this.showBadge(scoreData); // Show badge instead
    });
    banner.appendChild(closeButton);

    document.body.appendChild(banner);
    this.currentBanners.push(banner);
    this.isVisible = true;
  }

  // Show unobtrusive badge (for good/moderate sites)
  showBadge(scoreData) {
    const badge = document.createElement('div');
    badge.id = this.badgeId;
    badge.className = `hera-badge hera-badge-${this.getBadgeClass(scoreData.grade)}`;
    badge.title = `Hera Safety Score: ${scoreData.grade} (${Math.round(scoreData.overallScore)}/100)`;

    // Badge content
    const gradeText = document.createElement('span');
    gradeText.className = 'hera-badge-grade';
    gradeText.textContent = scoreData.grade;
    badge.appendChild(gradeText);

    const labelText = document.createElement('span');
    labelText.className = 'hera-badge-label';
    labelText.textContent = 'Hera';
    badge.appendChild(labelText);

    // Click to expand
    badge.addEventListener('click', () => {
      this.toggleBadgeDetails(badge, scoreData);
    });

    document.body.appendChild(badge);
    this.isVisible = true;
  }

  // Toggle badge details panel
  toggleBadgeDetails(badge, scoreData) {
    const existingDetails = document.getElementById('hera-badge-details');

    if (existingDetails) {
      existingDetails.remove();
      return;
    }

    const details = document.createElement('div');
    details.id = 'hera-badge-details';
    details.className = 'hera-badge-details';

    // Title
    const title = document.createElement('div');
    title.className = 'hera-details-title';
    title.textContent = 'Hera Site Analysis';
    details.appendChild(title);

    // Score
    const scoreRow = document.createElement('div');
    scoreRow.className = 'hera-details-row';

    const scoreLabel = document.createElement('span');
    scoreLabel.textContent = 'Overall Score:';
    scoreRow.appendChild(scoreLabel);

    const scoreValue = document.createElement('span');
    scoreValue.className = 'hera-details-score';
    scoreValue.textContent = `${scoreData.grade} (${Math.round(scoreData.overallScore)}/100)`;
    scoreRow.appendChild(scoreValue);

    details.appendChild(scoreRow);

    // Findings summary
    const findingsRow = document.createElement('div');
    findingsRow.className = 'hera-details-row';
    findingsRow.textContent = `${scoreData.totalFindings} issues found`;
    details.appendChild(findingsRow);

    // Category breakdown
    if (scoreData.categoryScores) {
      const categoriesTitle = document.createElement('div');
      categoriesTitle.className = 'hera-details-subtitle';
      categoriesTitle.textContent = 'Categories:';
      details.appendChild(categoriesTitle);

      for (const [category, data] of Object.entries(scoreData.categoryScores)) {
        if (data.findingCount > 0) {
          const catRow = document.createElement('div');
          catRow.className = 'hera-details-category';
          catRow.textContent = `${this.formatCategoryName(category)}: ${data.findingCount} issues`;
          details.appendChild(catRow);
        }
      }
    }

    // View full report button
    const viewButton = document.createElement('button');
    viewButton.className = 'hera-details-button';
    viewButton.textContent = 'View Full Report';
    viewButton.addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: 'OPEN_POPUP' });
    });
    details.appendChild(viewButton);

    document.body.appendChild(details);
  }

  // Inject CSS styles
  injectStyles() {
    if (document.getElementById('hera-reputation-styles')) return;

    const style = document.createElement('style');
    style.id = 'hera-reputation-styles';
    style.textContent = `
      /* Critical overlay */
      .hera-critical-overlay {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: rgba(0, 0, 0, 0.95);
        z-index: 2147483647;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      }

      .hera-alert-content {
        background: white;
        border-radius: 16px;
        padding: 40px;
        max-width: 600px;
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
        text-align: center;
      }

      .hera-alert-icon {
        font-size: 64px;
        margin-bottom: 20px;
      }

      .hera-alert-title {
        font-size: 32px;
        font-weight: 700;
        color: #dc3545;
        margin: 0 0 16px 0;
      }

      .hera-alert-summary {
        font-size: 16px;
        color: #333;
        line-height: 1.6;
        margin: 0 0 24px 0;
      }

      .hera-score-display {
        background: #f8f9fa;
        border-radius: 8px;
        padding: 20px;
        margin: 24px 0;
      }

      .hera-score-label {
        font-size: 14px;
        color: #6c757d;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 8px;
      }

      .hera-score-value {
        font-size: 36px;
        font-weight: 700;
      }

      .hera-score-value.critical {
        color: #dc3545;
      }

      .hera-recs-title {
        font-size: 18px;
        font-weight: 600;
        margin: 24px 0 12px 0;
        text-align: left;
      }

      .hera-recs-list {
        text-align: left;
        list-style: none;
        padding: 0;
        margin: 0 0 24px 0;
      }

      .hera-recs-list li {
        padding: 8px 0;
        border-bottom: 1px solid #e9ecef;
        color: #495057;
      }

      .hera-alert-buttons {
        display: flex;
        gap: 12px;
        justify-content: center;
        margin-top: 24px;
      }

      .hera-button {
        padding: 12px 24px;
        border: none;
        border-radius: 8px;
        font-size: 16px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s;
      }

      .hera-button-primary {
        background: #007bff;
        color: white;
      }

      .hera-button-primary:hover {
        background: #0056b3;
      }

      .hera-button-secondary {
        background: #6c757d;
        color: white;
      }

      .hera-button-secondary:hover {
        background: #5a6268;
      }

      .hera-button-danger {
        background: #dc3545;
        color: white;
      }

      .hera-button-danger:hover {
        background: #c82333;
      }

      .hera-alert-footer {
        margin-top: 24px;
        font-size: 12px;
        color: #6c757d;
      }

      /* Warning banner */
      .hera-warning-banner {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        background: linear-gradient(135deg, #ffc107 0%, #ff9800 100%);
        color: #000;
        padding: 16px 24px;
        z-index: 2147483646;
        display: flex;
        align-items: center;
        gap: 16px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      }

      .hera-banner-icon {
        font-size: 24px;
      }

      .hera-banner-message {
        flex: 1;
        font-size: 14px;
        font-weight: 500;
      }

      .hera-banner-button {
        background: rgba(0, 0, 0, 0.8);
        color: white;
        border: none;
        padding: 8px 16px;
        border-radius: 6px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: background 0.2s;
      }

      .hera-banner-button:hover {
        background: rgba(0, 0, 0, 1);
      }

      .hera-banner-close {
        background: none;
        border: none;
        font-size: 24px;
        cursor: pointer;
        padding: 0;
        width: 32px;
        height: 32px;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 50%;
        transition: background 0.2s;
      }

      .hera-banner-close:hover {
        background: rgba(0, 0, 0, 0.1);
      }

      /* Badge */
      .hera-badge {
        position: fixed;
        bottom: 24px;
        right: 24px;
        width: 60px;
        height: 60px;
        border-radius: 50%;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        z-index: 2147483645;
        box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
        transition: transform 0.2s, box-shadow 0.2s;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      }

      .hera-badge:hover {
        transform: scale(1.1);
        box-shadow: 0 6px 20px rgba(0, 0, 0, 0.3);
      }

      .hera-badge-grade {
        font-size: 20px;
        font-weight: 700;
        color: white;
      }

      .hera-badge-label {
        font-size: 10px;
        color: white;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }

      .hera-badge-a { background: linear-gradient(135deg, #28a745 0%, #20c997 100%); }
      .hera-badge-b { background: linear-gradient(135deg, #17a2b8 0%, #007bff 100%); }
      .hera-badge-c { background: linear-gradient(135deg, #ffc107 0%, #fd7e14 100%); }
      .hera-badge-d { background: linear-gradient(135deg, #fd7e14 0%, #dc3545 100%); }
      .hera-badge-f { background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); }

      /* Badge details panel */
      .hera-badge-details {
        position: fixed;
        bottom: 100px;
        right: 24px;
        background: white;
        border-radius: 12px;
        padding: 20px;
        min-width: 280px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);
        z-index: 2147483645;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      }

      .hera-details-title {
        font-size: 18px;
        font-weight: 700;
        margin-bottom: 16px;
        color: #212529;
      }

      .hera-details-row {
        display: flex;
        justify-content: space-between;
        padding: 8px 0;
        border-bottom: 1px solid #e9ecef;
        font-size: 14px;
        color: #495057;
      }

      .hera-details-score {
        font-weight: 700;
        color: #007bff;
      }

      .hera-details-subtitle {
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
        color: #6c757d;
        margin: 16px 0 8px 0;
        letter-spacing: 0.5px;
      }

      .hera-details-category {
        font-size: 13px;
        padding: 6px 0;
        color: #495057;
      }

      .hera-details-button {
        width: 100%;
        margin-top: 16px;
        padding: 10px;
        background: #007bff;
        color: white;
        border: none;
        border-radius: 8px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        transition: background 0.2s;
      }

      .hera-details-button:hover {
        background: #0056b3;
      }
    `;

    document.head.appendChild(style);
  }

  // Setup message listener
  setupMessageListener() {
    window.addEventListener('message', (event) => {
      // Only accept messages from same origin
      if (event.origin !== window.location.origin) return;

      if (event.data.type === 'HERA_DISPLAY_REPUTATION') {
        this.displayReputation(event.data.scoreData);
      }
    });
  }

  // Clear all overlays
  clear() {
    const overlay = document.getElementById(this.overlayId);
    if (overlay) overlay.remove();

    const badge = document.getElementById(this.badgeId);
    if (badge) badge.remove();

    const details = document.getElementById('hera-badge-details');
    if (details) details.remove();

    for (const banner of this.currentBanners) {
      if (banner && banner.parentNode) {
        banner.remove();
      }
    }

    this.currentBanners = [];
    this.isVisible = false;
  }

  // Helper: Get badge CSS class from grade
  getBadgeClass(grade) {
    const letter = grade.charAt(0).toLowerCase();
    return letter;
  }

  // Helper: Format category name
  formatCategoryName(category) {
    return category
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  }
}

// Auto-initialize if loaded in content script context
if (typeof window !== 'undefined' && !window.heraReputationOverlay) {
  window.heraReputationOverlay = new SiteReputationOverlay();
  window.heraReputationOverlay.initialize();
}
