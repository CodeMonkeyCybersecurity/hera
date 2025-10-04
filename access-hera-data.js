// Hera Enhanced Data Access Script with Security Analysis
// Run this in Chrome DevTools Console to access your stored data and analyze security findings

console.log('Hera Enhanced Data Access Tool');
console.log('==================================');

// Function to get all Hera data with enhanced security information
function getHeraData() {
  chrome.storage.local.get(null, (allData) => {
    console.log(' Complete Hera Storage:', allData);
    
    const sessions = allData.heraSessions || [];
    const syncQueue = allData.syncQueue || [];
    const config = allData.heraConfig || {};
    
    console.log(`\n📈 Statistics:`);
    console.log(`  • Total Sessions: ${sessions.length}`);
    console.log(`  • Pending Sync: ${syncQueue.length}`);
    console.log(`  • Storage Size: ${JSON.stringify(allData).length} bytes`);
    
    if (sessions.length > 0) {
      console.log(`\nRecent Authentication Events:`);
      sessions.slice(-5).forEach((session, index) => {
        const riskScore = session.metadata?.authAnalysis?.riskScore || session.riskScore || 0;
        const riskFactors = session.metadata?.authAnalysis?.issues || session.riskFactors || [];
        const riskIcon = getRiskIcon(riskScore);
        const protocol = session.metadata?.authAnalysis?.protocol || session.authType || 'Unknown';
        
        console.log(`  ${index + 1}. ${riskIcon} ${protocol} - ${session.url}`);
        console.log(`     Risk Score: ${riskScore}/100 | Issues: ${riskFactors.length} | ${new Date(session.timestamp).toLocaleString()}`);
        
        if (riskFactors.length > 0) {
          console.log(`      Security Issues:`);
          riskFactors.slice(0, 3).forEach(issue => {
            const severityIcon = getSeverityIcon(issue.severity);
            console.log(`       ${severityIcon} ${issue.type}: ${issue.message}`);
          });
          if (riskFactors.length > 3) {
            console.log(`       ... and ${riskFactors.length - 3} more issues`);
          }
        }
        console.log(''); // Empty line for readability
      });
    }
    
    if (syncQueue.length > 0) {
      console.log(`\n⏳ Pending Sync Events: ${syncQueue.length}`);
    }
    
    console.log(`\n💾 To export all data, run: exportHeraData()`);
    console.log(`To analyze security findings, run: analyzeSecurityFindings()`);
  });
}

// Helper functions for risk visualization
function getRiskIcon(riskScore) {
  if (riskScore >= 80) return '🔴'; // Critical
  if (riskScore >= 30) return '🟡'; // Moderate  
  return '🟢'; // Secure
}

function getSeverityIcon(severity) {
  const icons = {
    CRITICAL: '🔴',
    HIGH: '🟠', 
    MEDIUM: '🟡',
    LOW: '🔵'
  };
  return icons[severity] || '⚪';
}

// Function to analyze security findings across all sessions
function analyzeSecurityFindings() {
  chrome.storage.local.get(['heraSessions'], (result) => {
    const sessions = result.heraSessions || [];
    
    console.log('HERA SECURITY ANALYSIS REPORT');
    console.log('================================');
    
    if (sessions.length === 0) {
      console.log('No sessions found to analyze.');
      return;
    }
    
    // Collect all security issues
    const allIssues = [];
    const riskScores = [];
    const protocolCounts = {};
    
    sessions.forEach(session => {
      const authAnalysis = session.metadata?.authAnalysis;
      const riskScore = authAnalysis?.riskScore || session.riskScore || 0;
      const issues = authAnalysis?.issues || session.riskFactors || [];
      const protocol = authAnalysis?.protocol || session.authType || 'Unknown';
      
      riskScores.push(riskScore);
      protocolCounts[protocol] = (protocolCounts[protocol] || 0) + 1;
      
      issues.forEach(issue => {
        allIssues.push({
          ...issue,
          url: session.url,
          timestamp: session.timestamp,
          protocol: protocol
        });
      });
    });
    
    // Summary statistics
    const avgRiskScore = riskScores.length > 0 ? (riskScores.reduce((a, b) => a + b, 0) / riskScores.length).toFixed(1) : 0;
    const highRiskSessions = riskScores.filter(score => score >= 80).length;
    const moderateRiskSessions = riskScores.filter(score => score >= 30 && score < 80).length;
    const lowRiskSessions = riskScores.filter(score => score < 30).length;
    
    console.log(`\n SUMMARY STATISTICS:`);
    console.log(`  • Total Sessions Analyzed: ${sessions.length}`);
    console.log(`  • Average Risk Score: ${avgRiskScore}/100`);
    console.log(`  • High Risk Sessions (80+): ${highRiskSessions} 🔴`);
    console.log(`  • Moderate Risk Sessions (30-79): ${moderateRiskSessions} 🟡`);
    console.log(`  • Low Risk Sessions (<30): ${lowRiskSessions} 🟢`);
    console.log(`  • Total Security Issues Found: ${allIssues.length}`);
    
    // Protocol breakdown
    console.log(`\nAUTHENTICATION PROTOCOLS:`);
    Object.entries(protocolCounts)
      .sort(([,a], [,b]) => b - a)
      .forEach(([protocol, count]) => {
        console.log(`  • ${protocol}: ${count} sessions`);
      });
    
    // Top security issues
    if (allIssues.length > 0) {
      const issueTypes = {};
      allIssues.forEach(issue => {
        const key = `${issue.type} (${issue.severity})`;
        issueTypes[key] = (issueTypes[key] || 0) + 1;
      });
      
      console.log(`\n TOP SECURITY ISSUES:`);
      Object.entries(issueTypes)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 10)
        .forEach(([issueType, count]) => {
          const severity = issueType.match(/\((\w+)\)$/)?.[1] || 'UNKNOWN';
          const icon = getSeverityIcon(severity);
          console.log(`  ${icon} ${issueType}: ${count} occurrences`);
        });
      
      // Critical issues details
      const criticalIssues = allIssues.filter(issue => issue.severity === 'CRITICAL');
      if (criticalIssues.length > 0) {
        console.log(`\n🔴 CRITICAL ISSUES REQUIRING IMMEDIATE ATTENTION:`);
        criticalIssues.slice(0, 5).forEach((issue, index) => {
          console.log(`  ${index + 1}. ${issue.type}: ${issue.message}`);
          console.log(`     URL: ${issue.url}`);
          console.log(`     Time: ${new Date(issue.timestamp).toLocaleString()}`);
          if (issue.exploitation) {
            console.log(`     Risk: ${issue.exploitation}`);
          }
          console.log('');
        });
        
        if (criticalIssues.length > 5) {
          console.log(`     ... and ${criticalIssues.length - 5} more critical issues`);
        }
      }
    }
    
    // Recommendations
    console.log(`\n💡 RECOMMENDATIONS:`);
    if (highRiskSessions > 0) {
      console.log(`  🔴 ${highRiskSessions} sessions have critical security issues - investigate immediately`);
    }
    if (moderateRiskSessions > 0) {
      console.log(`  🟡 ${moderateRiskSessions} sessions have moderate security concerns - review when possible`);
    }
    if (allIssues.some(i => i.type === 'NO_TLS')) {
      console.log(`   Some authentication is happening over HTTP - enforce HTTPS`);
    }
    if (allIssues.some(i => i.type === 'CREDENTIALS_IN_URL')) {
      console.log(`  🔗 Credentials found in URLs - use POST body or headers instead`);
    }
    if (allIssues.some(i => i.type === 'algorithmNone')) {
      console.log(`  🔑 JWT tokens with no signature found - implement proper JWT validation`);
    }
    
    console.log(`\n📋 To export detailed findings, run: exportSecurityReport()`);
  });
}

// Function to export detailed security report
function exportSecurityReport() {
  chrome.storage.local.get(['heraSessions'], (result) => {
    const sessions = result.heraSessions || [];
    
    const report = {
      reportDate: new Date().toISOString(),
      reportType: 'Hera Security Analysis Report',
      version: '1.0.0',
      summary: {
        totalSessions: sessions.length,
        sessionsWithIssues: 0,
        totalIssues: 0,
        criticalIssues: 0,
        highIssues: 0,
        mediumIssues: 0,
        lowIssues: 0
      },
      findings: [],
      recommendations: []
    };
    
    sessions.forEach(session => {
      const authAnalysis = session.metadata?.authAnalysis;
      const issues = authAnalysis?.issues || session.riskFactors || [];
      
      if (issues.length > 0) {
        report.summary.sessionsWithIssues++;
        report.summary.totalIssues += issues.length;
        
        issues.forEach(issue => {
          switch(issue.severity) {
            case 'CRITICAL': report.summary.criticalIssues++; break;
            case 'HIGH': report.summary.highIssues++; break;
            case 'MEDIUM': report.summary.mediumIssues++; break;
            case 'LOW': report.summary.lowIssues++; break;
          }
        });
        
        report.findings.push({
          url: session.url,
          timestamp: session.timestamp,
          protocol: authAnalysis?.protocol || session.authType,
          riskScore: authAnalysis?.riskScore || session.riskScore,
          issues: issues
        });
      }
    });
    
    // Add recommendations based on findings
    if (report.summary.criticalIssues > 0) {
      report.recommendations.push('Immediately address all CRITICAL security issues');
    }
    if (report.summary.highIssues > 0) {
      report.recommendations.push('Review and fix HIGH severity security issues');
    }
    
    // Create downloadable file
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    const now = new Date();
    const date = now.toISOString().slice(2, 10); // YY-MM-DD format
    const time = now.toISOString().slice(11, 19).replace(/:/g, '-'); // HH-MM-SS format
    a.download = `${date}_${time}_hera-security-report.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    console.log('Security report exported to Downloads folder');
  });
}

// Function to export all data to file
function exportHeraData() {
  chrome.storage.local.get(null, (allData) => {
    const exportData = {
      exportDate: new Date().toISOString(),
      version: '1.0.0',
      data: allData,
      summary: {
        totalSessions: allData.heraSessions?.length || 0,
        pendingSync: allData.syncQueue?.length || 0,
        configurationStatus: allData.heraConfig ? 'Configured' : 'Default'
      }
    };
    
    // Create downloadable file
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    const now = new Date();
    const date = now.toISOString().slice(2, 10); // YY-MM-DD format
    const time = now.toISOString().slice(11, 19).replace(/:/g, '-'); // HH-MM-SS format
    a.download = `${date}_${time}_hera-complete-data.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    console.log('💾 Data exported to Downloads folder');
  });
}

// Function to get specific domain data with security analysis
function getDomainData(domain) {
  chrome.storage.local.get(['heraSessions'], (result) => {
    const sessions = result.heraSessions || [];
    const domainSessions = sessions.filter(session => {
      try {
        return new URL(session.url).hostname === domain;
      } catch (e) {
        return false;
      }
    });
    
    console.log(`Data for ${domain}:`);
    console.log(`  • Total Events: ${domainSessions.length}`);
    
    if (domainSessions.length > 0) {
      const protocols = [...new Set(domainSessions.map(s => s.metadata?.authAnalysis?.protocol || s.authType))];
      const riskScores = domainSessions.map(s => s.metadata?.authAnalysis?.riskScore || s.riskScore).filter(s => s);
      const allIssues = domainSessions.flatMap(s => s.metadata?.authAnalysis?.issues || s.riskFactors || []);
      
      console.log(`  • Authentication Protocols:`, protocols);
      console.log(`  • Risk Scores:`, riskScores);
      console.log(`  • Total Security Issues: ${allIssues.length}`);
      
      if (allIssues.length > 0) {
        const criticalIssues = allIssues.filter(i => i.severity === 'CRITICAL');
        const highIssues = allIssues.filter(i => i.severity === 'HIGH');
        
        console.log(`  • Critical Issues: ${criticalIssues.length} 🔴`);
        console.log(`  • High Issues: ${highIssues.length} 🟠`);
        
        if (criticalIssues.length > 0) {
          console.log(`  • Critical Issue Types:`, [...new Set(criticalIssues.map(i => i.type))]);
        }
      }
      
      console.log(`  • Recent Events:`, domainSessions.slice(-3));
    }
  });
}

// Function to get storage usage
function getStorageUsage() {
  chrome.storage.local.getBytesInUse(null, (bytesInUse) => {
    const maxBytes = chrome.storage.local.QUOTA_BYTES;
    const usagePercent = (bytesInUse / maxBytes * 100).toFixed(2);
    
    console.log(` Storage Usage:`);
    console.log(`  • Used: ${(bytesInUse / 1024).toFixed(1)} KB`);
    console.log(`  • Available: ${(maxBytes / 1024 / 1024).toFixed(1)} MB`);
    console.log(`  • Usage: ${usagePercent}%`);
    
    if (usagePercent > 80) {
      console.log(`  Warning: Storage is ${usagePercent}% full. Consider running cleanupOldData()`);
    }
  });
}

// Function to clean up old data (keep last N sessions)
function cleanupOldData(keepLast = 500) {
  chrome.storage.local.get(['heraSessions'], (result) => {
    const sessions = result.heraSessions || [];
    
    if (sessions.length > keepLast) {
      const trimmedSessions = sessions.slice(-keepLast);
      
      chrome.storage.local.set({ heraSessions: trimmedSessions }, () => {
        console.log(`🧹 Cleaned up old data. Kept ${keepLast} most recent sessions.`);
        console.log(`   Removed ${sessions.length - keepLast} old sessions.`);
      });
    } else {
      console.log(`No cleanup needed. Only ${sessions.length} sessions stored.`);
    }
  });
}

// Auto-run basic info
console.log('\n📋 Available Commands:');
console.log('  • getHeraData() - View all stored data with security analysis');
console.log('  • analyzeSecurityFindings() - Comprehensive security analysis report');
console.log('  • exportSecurityReport() - Export detailed security findings');
console.log('  • exportHeraData() - Export all data to file');
console.log('  • getDomainData("example.com") - Get security data for specific domain');
console.log('  • cleanupOldData(500) - Keep only last 500 sessions');
console.log('  • getStorageUsage() - Check storage usage');

console.log('\n🚀 Running basic check...');
getStorageUsage();
getHeraData();
