/**
 * Repeater Tool
 * Allows replaying and modifying HTTP requests
 */

export class RepeaterTool {
  constructor() {
    this.repeaterPanel = null;
    this.sendToRepeaterBtn = null;
    this.closeRepeaterBtn = null;
    this.sendRepeaterBtn = null;
    this.repeaterRequestEl = null;
    this.repeaterResponseEl = null;
    this.selectedRequest = null;
  }

  /**
   * Initialize repeater tool
   */
  initialize() {
    this.repeaterPanel = document.getElementById('repeaterPanel');
    this.sendToRepeaterBtn = document.getElementById('sendToRepeaterBtn');
    this.closeRepeaterBtn = document.getElementById('closeRepeaterBtn');
    this.sendRepeaterBtn = document.getElementById('sendRepeaterBtn');
    this.repeaterRequestEl = document.getElementById('repeaterRequest');
    this.repeaterResponseEl = document.getElementById('repeaterResponse');

    // Send to repeater button
    if (this.sendToRepeaterBtn) {
      this.sendToRepeaterBtn.addEventListener('click', () => {
        this.sendToRepeater();
      });
    }

    // Close repeater button
    if (this.closeRepeaterBtn) {
      this.closeRepeaterBtn.addEventListener('click', () => {
        this.hide();
      });
    }

    // Send repeater request button
    if (this.sendRepeaterBtn) {
      this.sendRepeaterBtn.addEventListener('click', () => {
        this.sendRequest();
      });
    }

    // Listen for request selection
    window.addEventListener('requestSelected', (e) => {
      this.selectedRequest = e.detail;
      if (this.sendToRepeaterBtn) {
        this.sendToRepeaterBtn.style.display = 'block';
      }
    });
  }

  /**
   * Send current request to repeater
   */
  sendToRepeater() {
    if (!this.selectedRequest) {
      console.error('No request selected');
      return;
    }

    // Format the full HTTP request for the textarea
    let rawRequest = `${this.selectedRequest.method} ${this.selectedRequest.url} HTTP/1.1\n`;
    
    if (this.selectedRequest.requestHeaders) {
      this.selectedRequest.requestHeaders.forEach(h => {
        rawRequest += `${h.name}: ${h.value}\n`;
      });
    }
    
    rawRequest += '\n';
    
    if (this.selectedRequest.requestBody) {
      rawRequest += this.formatBody(this.selectedRequest.requestBody);
    }

    if (this.repeaterRequestEl) {
      this.repeaterRequestEl.value = rawRequest;
    }

    if (this.repeaterResponseEl) {
      this.repeaterResponseEl.textContent = '';
    }

    this.show();
  }

  /**
   * Send repeater request
   */
  sendRequest() {
    if (!this.repeaterRequestEl || !this.sendRepeaterBtn) return;

    this.sendRepeaterBtn.textContent = 'Sending...';
    this.sendRepeaterBtn.disabled = true;

    chrome.runtime.sendMessage({
      action: 'repeater:send',
      rawRequest: this.repeaterRequestEl.value
    }, response => {
      this.sendRepeaterBtn.textContent = 'Send';
      this.sendRepeaterBtn.disabled = false;

      if (this.repeaterResponseEl) {
        if (response && response.error) {
          this.repeaterResponseEl.textContent = `Error: ${response.error}`;
        } else if (response && response.rawResponse) {
          this.repeaterResponseEl.textContent = response.rawResponse;
        } else {
          this.repeaterResponseEl.textContent = 'No response received';
        }
      }
    });
  }

  /**
   * Show repeater panel
   */
  show() {
    if (this.repeaterPanel) {
      this.repeaterPanel.style.display = 'flex';
    }
  }

  /**
   * Hide repeater panel
   */
  hide() {
    if (this.repeaterPanel) {
      this.repeaterPanel.style.display = 'none';
    }
  }

  /**
   * Format body for display
   */
  formatBody(body) {
    if (!body) return '';

    try {
      if (typeof body === 'string') {
        const parsed = JSON.parse(body);
        return JSON.stringify(parsed, null, 2);
      } else if (typeof body === 'object') {
        return JSON.stringify(body, null, 2);
      }
      return String(body);
    } catch (e) {
      return String(body);
    }
  }
}
