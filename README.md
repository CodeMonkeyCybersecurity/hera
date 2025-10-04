# Hera by Code Monkey Cybersecurity

*"Like the goddess Hera, who could see through Zeus's disguises, this extension reveals the true nature of authentication requests."*

A comprehensive Chrome extension for detecting authentication scams, phishing attempts, and security misconfigurations. Hera provides real-time analysis of OAuth 2.0, OIDC, SAML, and SCIM flows with advanced threat detection capabilities.

##  **Anti-Scam & Anti-Phishing Features**

### **Real-Time Threat Detection**
- ** Rogue OAuth App Detection** - Identifies suspicious Microsoft Azure, Google, and other OAuth applications
- ** Homograph Attack Detection** - Catches Unicode-based domain spoofing (e.g., `microsоft.com` vs `microsoft.com`)
- ** DNS Intelligence** - Detects Domain Generation Algorithm (DGA) patterns and suspicious TLDs
- **🏗️ CDN Mismatch Analysis** - Verifies if sites are using expected infrastructure (e.g., Microsoft sites should use Azure CDN)
- **Consent Phishing Protection** - Analyzes OAuth permission requests for excessive or dangerous scopes

### **Advanced Security Analysis**
- **Certificate Chain Validation** - Monitors for suspicious SSL/TLS certificates
- **Token Security Analysis** - JWT inspection and lifetime analysis
- **Cross-Origin Request Monitoring** - Detects unauthorized cross-domain authentication
- **Session Hijacking Detection** - Monitors for suspicious cookie and session behavior

## Features

- **Real-time Monitoring**: Captures and displays authentication requests as they happen
- **Multiple Protocol Support**: Works with OAuth 2.0, OpenID Connect (OIDC), SAML, and SCIM
- **Request Inspection**: View detailed request and response data including headers and bodies
- **Security Analysis**: Automatically detects common security issues and misconfigurations
- **Token Decoding**: Decodes and displays JWT tokens with syntax highlighting
- **Export Capabilities**: Save captured requests for offline analysis
- **DevTools Integration**: Advanced debugging through the Chrome DevTools panel

## Installation

### From Chrome Web Store

1. Visit the [Chrome Web Store](https://chrome.google.com/webstore) and search for "Hera by Code Monkey Cybersecurity"
2. Click "Add to Chrome"
3. Confirm by clicking "Add extension"

### Manual Installation (for development)

1. Clone or download this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" in the top-right corner
4. Click "Load unpacked" and select the directory containing the extension files
5. The extension should now be installed and ready to use

## **Quick Start**

### **Basic Usage**
1. **Install Extension** - Load the unpacked extension in Chrome
2. **Navigate to Auth Sites** - Visit any site with OAuth/OIDC authentication
3. **Monitor Real-Time** - Hera automatically captures and analyzes all auth requests
4. **Review Alerts** - Check the pulsing red banner for critical security warnings
5. **Inspect Details** - Click any request to see comprehensive analysis

### **Key Interface Elements**

#### **OAuth Consent Tab**
- **Provider Analysis** - Shows which service you're authenticating to (Microsoft, Google, etc.)
- **Permission Breakdown** - Color-coded risk levels for requested scopes:
  - 🔴 **High Risk**: `mail.readwrite`, `directory.readwrite.all`, `.default` (full access)
  - 🟡 **Medium Risk**: `mail.read`, `profile`, `offline_access`
  - 🟢 **Low Risk**: `user.read`, `basic_info`
- **Application Verification** - Checks if the redirect URI and app are legitimate

#### ** DNS Intelligence Tab**
- **Homograph Detection** - Identifies Unicode spoofing attacks
- **DGA Analysis** - Detects algorithmically generated malicious domains
- **Typosquatting** - Catches domains similar to legitimate services
- **Infrastructure Analysis** - Verifies CDN providers match expected services

#### ** Real-Time Alerts**
When Hera detects dangerous authentication flows, you'll see:
- **Pulsing Red Banner** at the top of the popup
- **Critical Warnings** for high-risk OAuth scopes
- **Suspicious Domain Alerts** for potential phishing sites
- **CDN Mismatch Warnings** when infrastructure doesn't match expectations

### Popup Interface

- **Request List**: Shows all captured authentication requests
- **Request Details**: Displays detailed information about a selected request
  - **Overview**: Basic request/response information
  - **Headers**: Request and response headers
  - **Body**: Request and response bodies (if available)
  - **Security**: Security analysis and recommendations

### DevTools Panel

For advanced users, the DevTools panel provides additional features:

- **Requests Tab**: View and filter captured requests
- **Tokens Tab**: Inspect and decode JWT tokens
- **Security Tab**: Detailed security analysis of captured requests

## **Centralized Data Collection & Persistence**

### **Cross-Session Data Persistence**
Hera automatically stores authentication events locally using `chrome.storage.local`, ensuring data persists across:
- Browser restarts
- Computer shutdowns  
- Extension updates
- Chrome crashes

### **Remote Sync & Analysis Backend**

For advanced analysis and centralized monitoring, Hera can sync data to a backend API:

#### **Setup Backend (Python FastAPI)**
```bash
# Install dependencies
pip install fastapi uvicorn sqlite3

# Run the backend
python backend-example.py

# Backend will be available at http://localhost:8000
```

#### **Configure Extension Sync**
1. Open the Hera popup
2. Open browser console (F12)
3. Run the setup script:
```javascript
// Load the setup script
fetch('setup-sync.js').then(r => r.text()).then(eval);

// Configure sync endpoint
setupHeraSync();
```

#### **Backend Features**
- **Real-time Analytics** - Dashboard with authentication event statistics
- ** Domain Intelligence** - Tracks suspicious domains across all users
- ** Risk Scoring** - Advanced ML-based risk analysis
- **Threat Patterns** - Identifies emerging attack patterns
- ** Alert System** - Notifications for critical security events

### **Data Architecture Options**

#### **Option 1: Local + Cloud Sync**
```
Browser Extension → Local Storage → Cloud API → Analysis Engine
```
- Best for: Personal use with cloud backup
- Privacy: High (you control the backend)
- Scalability: Medium

#### **Option 2: Real-time Streaming**
```
Browser Extension → WebSocket → Kafka → Stream Processing → Dashboard
```
- Best for: Enterprise deployment
- Privacy: Configurable
- Scalability: High

#### **Option 3: Local Only**
```
Browser Extension → chrome.storage.local → Local Analysis
```
- Best for: Maximum privacy
- Privacy: Highest (no external data)
- Scalability: Low

## Security Analysis

The extension performs comprehensive security analysis on captured authentication requests: for common security issues, including:

- Insecure protocols (HTTP instead of HTTPS)
- Missing security headers
- Sensitive data in URLs
- Insecure token storage
- Weak token expiration settings
- And more...

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a new branch for your feature or bugfix
3. Commit your changes
4. Push to your fork and submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for educational and security research purposes only. Use it only on systems you own or have explicit permission to test. The developers are not responsible for any misuse or damage caused by this tool.
