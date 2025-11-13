/**
 * Triaged Exporter - Phase 2 Evidence Quality & Transparency
 *
 * Provides confidence-based triage and export functionality for security findings.
 *
 * Features:
 * - Severity + Confidence matrix triage
 * - False positive likelihood filtering
 * - Evidence quality indicators
 * - Priority-sorted exports
 * - Summary statistics
 *
 * @author Hera Security Team
 * @date 2025-11-12
 */

import { ConfidenceScorer } from '../auth/confidence-scorer.js';

export class TriagedExporter {
  /**
   * Export findings with confidence-based triage
   * @param {Array} findings - Array of security findings
   * @param {Object} evidenceCollector - Evidence collector instance (optional)
   * @returns {Object} Triaged export package
   */
  static exportWithTriage(findings, evidenceCollector = null) {
    // Group findings by priority tier
    const triage = {
      critical: [],      // CRITICAL severity + HIGH confidence
      highPriority: [],  // HIGH severity + HIGH confidence, or CRITICAL + MEDIUM
      mediumPriority: [],// MEDIUM severity + HIGH confidence, or HIGH + MEDIUM
      lowPriority: [],   // LOW confidence or SPECULATIVE
      falsePositiveLikely: [] // High false positive likelihood
    };

    // Categorize each finding
    findings.forEach(finding => {
      const severity = finding.severity || 'MEDIUM';
      const confidence = finding.confidence || 'MEDIUM';
      const fpLikelihood = finding.falsePositiveLikelihood;

      // Calculate priority tier
      if (fpLikelihood === 'HIGH' || fpLikelihood === 'VERY_HIGH') {
        triage.falsePositiveLikely.push(finding);
      } else if (severity === 'CRITICAL' && confidence === 'HIGH') {
        triage.critical.push(finding);
      } else if (
        (severity === 'HIGH' && confidence === 'HIGH') ||
        (severity === 'CRITICAL' && confidence === 'MEDIUM')
      ) {
        triage.highPriority.push(finding);
      } else if (
        (severity === 'MEDIUM' && confidence === 'HIGH') ||
        (severity === 'HIGH' && confidence === 'MEDIUM')
      ) {
        triage.mediumPriority.push(finding);
      } else {
        triage.lowPriority.push(finding);
      }
    });

    // Calculate summary statistics
    const summary = this._calculateSummary(findings, triage);

    // Add evidence quality metrics if available
    let evidenceQuality = null;
    if (evidenceCollector && evidenceCollector.getAggregateEvidenceQuality) {
      evidenceQuality = evidenceCollector.getAggregateEvidenceQuality();
    }

    return {
      metadata: {
        exportDate: new Date().toISOString(),
        totalFindings: findings.length,
        heraVersion: '1.0.0', // TODO: Get from manifest
        exportFormat: 'triaged-v1'
      },
      summary,
      evidenceQuality,
      triage,
      allFindings: findings,
      recommendations: this._generateRecommendations(triage, evidenceQuality)
    };
  }

  /**
   * Calculate summary statistics
   * @private
   */
  static _calculateSummary(findings, triage) {
    const summary = {
      total: findings.length,
      critical: triage.critical.length,
      highPriority: triage.highPriority.length,
      mediumPriority: triage.mediumPriority.length,
      lowPriority: triage.lowPriority.length,
      needsReview: triage.falsePositiveLikely.length,
      bySeverity: {
        CRITICAL: 0,
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        INFO: 0
      },
      byConfidence: {
        HIGH: 0,
        MEDIUM: 0,
        LOW: 0,
        SPECULATIVE: 0
      }
    };

    findings.forEach(finding => {
      const severity = finding.severity || 'MEDIUM';
      const confidence = finding.confidence || 'MEDIUM';

      if (summary.bySeverity[severity] !== undefined) {
        summary.bySeverity[severity]++;
      }

      if (summary.byConfidence[confidence] !== undefined) {
        summary.byConfidence[confidence]++;
      }
    });

    return summary;
  }

  /**
   * Generate recommendations based on triage results
   * @private
   */
  static _generateRecommendations(triage, evidenceQuality) {
    const recommendations = [];

    if (triage.critical.length > 0) {
      recommendations.push({
        priority: 'URGENT',
        action: `Investigate ${triage.critical.length} critical issue(s) immediately`,
        details: 'These are high-confidence CRITICAL findings that likely represent exploitable vulnerabilities'
      });
    }

    if (triage.highPriority.length > 0) {
      recommendations.push({
        priority: 'HIGH',
        action: `Review ${triage.highPriority.length} high-priority finding(s) for bug bounty submission`,
        details: 'These findings have high confidence and severity - good candidates for reporting'
      });
    }

    if (triage.falsePositiveLikely.length > 0) {
      recommendations.push({
        priority: 'REVIEW',
        action: `Manually verify ${triage.falsePositiveLikely.length} finding(s) marked as potential false positives`,
        details: 'These findings have high false positive likelihood - validate before reporting'
      });
    }

    if (evidenceQuality && evidenceQuality.averageCompleteness < 70) {
      recommendations.push({
        priority: 'IMPROVEMENT',
        action: 'Enable debugger mode to improve evidence quality',
        details: `Current evidence completeness: ${evidenceQuality.averageCompleteness}% - enabling response body capture will improve accuracy`
      });
    }

    if (triage.lowPriority.length > triage.critical.length + triage.highPriority.length) {
      recommendations.push({
        priority: 'INFO',
        action: 'Focus on high-confidence findings first',
        details: 'Most findings are low confidence - prioritize HIGH confidence findings for investigation'
      });
    }

    return recommendations;
  }

  /**
   * Export to JSON format with pretty printing
   * @param {Object} triagedData - Data from exportWithTriage()
   * @returns {string} JSON string
   */
  static toJSON(triagedData) {
    return JSON.stringify(triagedData, null, 2);
  }

  /**
   * Export to CSV format (for spreadsheet tools)
   * @param {Array} findings - Array of findings
   * @returns {string} CSV string
   */
  static toCSV(findings) {
    if (!findings || findings.length === 0) {
      return 'No findings to export';
    }

    const headers = [
      'Type',
      'Severity',
      'Confidence',
      'Confidence Score',
      'False Positive Likelihood',
      'Message',
      'Recommendation',
      'URL',
      'Evidence Quality'
    ];

    const rows = findings.map(finding => [
      finding.type || '',
      finding.severity || '',
      finding.confidence || '',
      finding.confidenceScore || '',
      finding.falsePositiveLikelihood || '',
      (finding.message || '').replace(/"/g, '""'), // Escape quotes
      (finding.recommendation || '').replace(/"/g, '""'),
      finding.url || '',
      finding.evidenceQuality?.reliability || ''
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
    ].join('\n');

    return csvContent;
  }

  /**
   * Export to markdown format (for documentation/reports)
   * @param {Object} triagedData - Data from exportWithTriage()
   * @returns {string} Markdown string
   */
  static toMarkdown(triagedData) {
    const { metadata, summary, triage, recommendations } = triagedData;

    let markdown = `# Hera Security Findings Report\n\n`;
    markdown += `**Generated:** ${metadata.exportDate}\n`;
    markdown += `**Total Findings:** ${metadata.totalFindings}\n\n`;

    markdown += `## Summary\n\n`;
    markdown += `| Priority | Count |\n`;
    markdown += `|----------|-------|\n`;
    markdown += `| Critical | ${summary.critical} |\n`;
    markdown += `| High Priority | ${summary.highPriority} |\n`;
    markdown += `| Medium Priority | ${summary.mediumPriority} |\n`;
    markdown += `| Low Priority | ${summary.lowPriority} |\n`;
    markdown += `| Needs Review (Potential FP) | ${summary.needsReview} |\n\n`;

    if (recommendations.length > 0) {
      markdown += `## Recommendations\n\n`;
      recommendations.forEach(rec => {
        markdown += `### ${rec.priority}: ${rec.action}\n`;
        markdown += `${rec.details}\n\n`;
      });
    }

    if (triage.critical.length > 0) {
      markdown += `## Critical Issues (${triage.critical.length})\n\n`;
      triage.critical.forEach((finding, index) => {
        markdown += `### ${index + 1}. ${finding.type}\n`;
        markdown += `- **Severity:** ${finding.severity}\n`;
        markdown += `- **Confidence:** ${finding.confidence} (${finding.confidenceScore}/100)\n`;
        markdown += `- **Message:** ${finding.message}\n`;
        if (finding.recommendation) {
          markdown += `- **Recommendation:** ${finding.recommendation}\n`;
        }
        markdown += `\n`;
      });
    }

    if (triage.highPriority.length > 0) {
      markdown += `## High Priority Issues (${triage.highPriority.length})\n\n`;
      triage.highPriority.forEach((finding, index) => {
        markdown += `### ${index + 1}. ${finding.type}\n`;
        markdown += `- **Severity:** ${finding.severity}\n`;
        markdown += `- **Confidence:** ${finding.confidence}\n`;
        markdown += `- **Message:** ${finding.message}\n\n`;
      });
    }

    if (triage.falsePositiveLikely.length > 0) {
      markdown += `## Potential False Positives (${triage.falsePositiveLikely.length})\n\n`;
      markdown += `⚠️ **These findings have high false positive likelihood. Verify manually before reporting.**\n\n`;
      triage.falsePositiveLikely.forEach((finding, index) => {
        markdown += `### ${index + 1}. ${finding.type}\n`;
        markdown += `- **False Positive Likelihood:** ${finding.falsePositiveLikelihood}\n`;
        markdown += `- **Reason:** ${finding.confidenceReason}\n`;
        if (finding.confidenceRecommendation) {
          markdown += `- **Recommendation:** ${finding.confidenceRecommendation}\n`;
        }
        markdown += `\n`;
      });
    }

    return markdown;
  }

  /**
   * Get statistics for dashboard display
   * @param {Object} triagedData - Data from exportWithTriage()
   * @returns {Object} Statistics for UI display
   */
  static getDashboardStats(triagedData) {
    const { summary, evidenceQuality } = triagedData;

    return {
      totalFindings: summary.total,
      actionRequired: summary.critical + summary.highPriority,
      needsReview: summary.needsReview,
      lowPriority: summary.lowPriority,
      averageConfidence: this._calculateAverageConfidence(summary.byConfidence),
      evidenceQuality: evidenceQuality?.averageCompleteness || 0,
      recommendation: evidenceQuality?.recommendation || 'No evidence captured yet'
    };
  }

  /**
   * Calculate average confidence from distribution
   * @private
   */
  static _calculateAverageConfidence(byConfidence) {
    const weights = {
      HIGH: 90,
      MEDIUM: 65,
      LOW: 40,
      SPECULATIVE: 20
    };

    let total = 0;
    let count = 0;

    Object.entries(byConfidence).forEach(([level, num]) => {
      total += (weights[level] || 0) * num;
      count += num;
    });

    return count > 0 ? Math.round(total / count) : 0;
  }
}

export default TriagedExporter;
