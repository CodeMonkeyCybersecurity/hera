// TODO P3-TENTH-1: Review DevTools CSP compliance
// manifest.json defines CSP for extension_pages but DevTools may have different requirements
// Verify no eval() usage and check if inline scripts comply with CSP. See TENTH-REVIEW-FINDINGS.md:2249

// Create a connection to the background page
const backgroundPageConnection = chrome.runtime.connect({
  name: 'devtools-page'
});

// Listen for messages from the background page
backgroundPageConnection.onMessage.addListener((message) => {
  if (message.type === 'AUTH_REQUEST') {
    addRequestToUI(message.data);
  } else if (message.type === 'TOKEN_DETECTED') {
    addTokenToUI(message.data);
  } else if (message.type === 'SECURITY_FINDING') {
    addSecurityFinding(message.data);
  }
});

// Set up the UI
document.addEventListener('DOMContentLoaded', () => {
  // Tab switching
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const tabName = button.getAttribute('data-tab');
      switchTab(tabName);
    });
  });
  
  // Toggle recording
  const recordBtn = document.getElementById('recordBtn');
  recordBtn.addEventListener('click', () => {
    recordBtn.classList.toggle('active');
    const isRecording = recordBtn.classList.contains('active');
    
    if (isRecording) {
      recordBtn.innerHTML = '<span class="icon">●</span> Recording';
    } else {
      recordBtn.innerHTML = '<span class="icon" style="color:#ccc">●</span> Paused';
    }
    
    backgroundPageConnection.postMessage({
      type: 'SET_RECORDING_STATE',
      isRecording: isRecording
    });
  });
  
  // Clear all requests
  const clearBtn = document.getElementById('clearBtn');
  clearBtn.addEventListener('click', () => {
    if (confirm('Are you sure you want to clear all captured requests?')) {
      document.getElementById('requestsList').innerHTML = `
        <div class="empty-state">
          <p>No authentication requests captured yet.</p>
          <p>Navigate to a website that uses OAuth, OIDC, SAML, or SCIM.</p>
        </div>
      `;
      
      backgroundPageConnection.postMessage({
        type: 'CLEAR_REQUESTS'
      });
    }
  });
  
  // Filter requests
  const filterInput = document.getElementById('filterInput');
  filterInput.addEventListener('input', (e) => {
    const filter = e.target.value.toLowerCase();
    const requestItems = document.querySelectorAll('.request-item');
    
    requestItems.forEach(item => {
      const text = item.textContent.toLowerCase();
      item.style.display = text.includes(filter) ? 'flex' : 'none';
    });
  });
  
  // Request initial state
  backgroundPageConnection.postMessage({
    type: 'INIT_DEVTOOLS'
  });
});

// Switch between tabs
function switchTab(tabName) {
  // Hide all tab contents
  document.querySelectorAll('.tab-content').forEach(content => {
    content.classList.remove('active');
  });
  
  // Deactivate all tab buttons
  document.querySelectorAll('.tab-btn').forEach(button => {
    button.classList.remove('active');
  });
  
  // Show the selected tab content
  document.getElementById(`${tabName}Tab`).classList.add('active');
  
  // Activate the clicked tab button
  document.querySelector(`.tab-btn[data-tab="${tabName}"]`).classList.add('active');
}

// Add a request to the UI
function addRequestToUI(request) {
  const requestsList = document.getElementById('requestsList');
  
  // Remove empty state if it exists
  const emptyState = requestsList.querySelector('.empty-state');
  if (emptyState) {
    requestsList.removeChild(emptyState);
  }
  
  // P0-TWELFTH-5 FIX: Use DOM methods instead of innerHTML to prevent XSS
  // request.url is user-controlled, could contain malicious HTML/scripts
  const requestEl = document.createElement('div');
  requestEl.className = 'request-item';
  requestEl.dataset.id = request.id;

  const statusCode = request.statusCode || 'Pending';
  const statusClass = statusCode >= 400 ? 'error' : statusCode >= 200 && statusCode < 300 ? 'success' : '';

  const methodDiv = document.createElement('div');
  methodDiv.className = `request-method ${statusClass}`;
  methodDiv.textContent = request.method || 'GET';

  const urlDiv = document.createElement('div');
  urlDiv.className = 'request-url';
  urlDiv.title = request.url || '';
  urlDiv.textContent = request.url || ''; // Safe - text node

  const typeDiv = document.createElement('div');
  typeDiv.className = 'request-type';
  typeDiv.textContent = request.authType || 'Unknown';

  const statusDiv = document.createElement('div');
  statusDiv.className = 'request-status';
  statusDiv.textContent = statusCode;

  requestEl.appendChild(methodDiv);
  requestEl.appendChild(urlDiv);
  requestEl.appendChild(typeDiv);
  requestEl.appendChild(statusDiv);
  
  // Add click handler to show request details
  requestEl.addEventListener('click', () => {
    showRequestDetails(request);
  });
  
  // Add to the top of the list
  requestsList.insertBefore(requestEl, requestsList.firstChild);
  
  // Auto-scroll if at bottom
  if (requestsList.scrollTop === 0) {
    requestsList.scrollTop = 0;
  }
}

// Show request details in a new panel
function showRequestDetails(request) {
  // In a real implementation, this would open a new panel with detailed request/response info
  // For this example, we'll just log it to the console
  console.log('Request details:', request);
  
  // You could implement a more detailed view here, similar to the popup's request details
  // This would involve creating a more complex UI to display headers, body, etc.
  alert(`Request details for ${request.url}\nMethod: ${request.method}\nStatus: ${request.statusCode || 'Pending'}\nType: ${request.authType || 'Unknown'}`);
}

// Add a token to the UI
function addTokenToUI(tokenData) {
  const tokenViewer = document.getElementById('tokenViewer');
  
  // Remove empty state if it exists
  const emptyState = tokenViewer.querySelector('.empty-state');
  if (emptyState) {
    tokenViewer.removeChild(emptyState);
  }
  
  // Create token section
  const tokenSection = document.createElement('div');
  tokenSection.className = 'token-section';
  
  // Format token header
  const tokenHeader = document.createElement('div');
  tokenHeader.className = 'token-header';
  tokenHeader.textContent = `Token (${tokenData.tokenType || 'Bearer'})`;
  
  // Format token content
  const tokenContent = document.createElement('div');
  tokenContent.className = 'token-content';
  
  try {
    // Try to parse and format the token
    const tokenParts = tokenData.token.split('.');
    const header = JSON.parse(atob(tokenParts[0]));
    const payload = JSON.parse(atob(tokenParts[1]));
    
    tokenContent.innerHTML = `
      <div><strong>Header:</strong></div>
      <div class="json-viewer">${syntaxHighlight(header)}</div>
      <div style="margin-top: 8px;"><strong>Payload:</strong></div>
      <div class="json-viewer">${syntaxHighlight(payload)}</div>
      <div style="margin-top: 8px;"><strong>Signature:</strong> ${tokenParts[2].substring(0, 10)}...</div>
    `;
  } catch (e) {
    // If token parsing fails, just show the raw token
    tokenContent.textContent = tokenData.token;
  }
  
  // Assemble the token section
  tokenSection.appendChild(tokenHeader);
  tokenSection.appendChild(tokenContent);
  
  // Add to the token viewer
  tokenViewer.insertBefore(tokenSection, tokenViewer.firstChild);
}

// Add a security finding to the UI
function addSecurityFinding(finding) {
  const securityFindings = document.getElementById('securityFindings');
  
  // Remove empty state if it exists
  const emptyState = securityFindings.querySelector('.empty-state');
  if (emptyState) {
    securityFindings.removeChild(emptyState);
  }
  
  // Create finding element
  const findingEl = document.createElement('div');
  findingEl.className = `security-issue ${finding.severity}`;
  
  findingEl.innerHTML = `
    <div class="icon">${getSeverityIcon(finding.severity)}</div>
    <div class="content">
      <h3>${finding.title}</h3>
      <p>${finding.description}</p>
      ${finding.recommendation ? 
        `<div class="recommendation">
          <strong>Recommendation:</strong> ${finding.recommendation}
        </div>` 
        : ''
      }
    </div>
  `;
  
  // Add to the security findings
  securityFindings.insertBefore(findingEl, securityFindings.firstChild);
}

// Helper function to syntax highlight JSON
function syntaxHighlight(json) {
  if (typeof json === 'string') {
    try {
      json = JSON.parse(json);
    } catch (e) {
      return json; // Not valid JSON, return as is
    }
  }
  
  const jsonString = JSON.stringify(json, null, 2);
  
  // Simple syntax highlighting for JSON
  return jsonString
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"(\\.|[^"])*"(\s*:)?/g, (match) => {
      let cls = 'json-string';
      if (/:$/.test(match)) {
        cls = 'json-key';
        match = match.replace(/\s*:$/, '');
      }
      return `<span class="${cls}">${match}</span>`;
    })
    .replace(/\b(true|false|null)\b/g, (match) => {
      return `<span class="json-boolean">${match}</span>`;
    })
    .replace(/\b\d+\b/g, (match) => {
      return `<span class="json-number">${match}</span>`;
    });
}

// Get icon for severity level
function getSeverityIcon(severity) {
  const icons = {
    critical: '🔴',
    warning: '🟠',
    info: '🔵'
  };
  return icons[severity] || 'ℹ️';
}

// Handle window resize
window.addEventListener('resize', () => {
  // Handle any responsive adjustments here
});
