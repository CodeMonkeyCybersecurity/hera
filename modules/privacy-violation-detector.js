// Privacy Violation Detector - Detects privacy invasions and GDPR violations
// Identifies cookie walls, fingerprinting, excessive tracking, and privacy violations

class PrivacyViolationDetector {
  constructor() {
    // Known tracking domains
    this.trackingDomains = [
      'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
      'facebook.com', 'facebook.net', 'connect.facebook.net',
      'scorecardresearch.com', 'quantserve.com', 'hotjar.com',
      'mixpanel.com', 'segment.com', 'fullstory.com',
      'mouseflow.com', 'clicktale.com', 'crazyegg.com'
    ];

    // GDPR required elements
    this.gdprRequirements = {
      consentRequired: true,
      mustBeOptIn: true, // Not opt-out
      mustBeGranular: true, // Separate consent for different purposes
      withdrawalEasy: true // Must be as easy to withdraw as to give
    };
  }

  // PERFORMANCE FIX P1-2a: Helper to check if element is visible
  isElementVisible(element) {
    if (!element) return false;
    const style = window.getComputedStyle(element);
    return style.display !== 'none' &&
           style.visibility !== 'hidden' &&
           style.opacity !== '0' &&
           element.offsetWidth > 0 &&
           element.offsetHeight > 0;
  }

  // PERFORMANCE FIX P1-2a: Helper to filter visible elements
  filterVisible(elements) {
    return Array.from(elements).filter(el => this.isElementVisible(el));
  }

  // PERFORMANCE FIX P1-2b: Batch process elements with requestIdleCallback
  async processInBatches(elements, processFunc, batchSize = 50) {
    const results = [];
    const batches = [];

    for (let i = 0; i < elements.length; i += batchSize) {
      batches.push(elements.slice(i, i + batchSize));
    }

    for (const batch of batches) {
      await new Promise(resolve => {
        if (typeof requestIdleCallback !== 'undefined') {
          requestIdleCallback(() => {
            results.push(...batch.map(processFunc));
            resolve();
          }, { timeout: 1000 });
        } else {
          setTimeout(() => {
            results.push(...batch.map(processFunc));
            resolve();
          }, 0);
        }
      });
    }

    return results;
  }

  // Main detection method
  async detectViolations(url, document) {
    const findings = [];

    // Run all detection methods
    findings.push(...await this.detectCookieWall(document));
    findings.push(...await this.detectCanvasFingerprinting(document));
    findings.push(...await this.detectWebGLFingerprinting(document));
    findings.push(...await this.detectAudioFingerprinting(document));
    findings.push(...await this.detectExcessiveTracking(document));
    findings.push(...await this.detectGDPRViolations(document));
    findings.push(...await this.detectLocalStorageAbuse(document));
    findings.push(...await this.detectThirdPartyLeaks(document));

    return findings;
  }

  // Detect cookie walls (GDPR violation)
  async detectCookieWall(document) {
    const findings = [];

    // PERFORMANCE FIX P1-2a: Filter visible modals only
    const modals = this.filterVisible(document.querySelectorAll('[role="dialog"], [class*="modal"], [class*="overlay"], [class*="consent"], [class*="cookie"]'));

    for (const modal of modals) {
        const text = modal.innerText.toLowerCase();

        // Check if it's a cookie consent modal
        const isCookieModal = text.includes('cookie') || text.includes('consent') || text.includes('privacy');

        if (isCookieModal) {
          // Look for accept/reject buttons
          const buttons = modal.querySelectorAll('button, a[role="button"]');
          const buttonTexts = Array.from(buttons).map(b => b.innerText.toLowerCase());

          const hasAccept = buttonTexts.some(t => t.includes('accept') || t.includes('agree') || t.includes('allow'));
          const hasReject = buttonTexts.some(t => t.includes('reject') || t.includes('decline') || t.includes('deny'));

          // Cookie wall = no way to reject
          if (hasAccept && !hasReject) {
            findings.push({
              type: 'privacy_violation',
              category: 'cookie_wall',
              severity: 'critical',
              title: 'Cookie Wall Detected (GDPR Violation)',
              description: 'Site forces cookie acceptance with no option to decline',
              evidence: {
                hasAcceptButton: hasAccept,
                hasRejectButton: hasReject,
                buttons: buttonTexts,
                gdprViolation: 'GDPR Article 7(4) - Consent must be freely given'
              },
              recommendation: 'Users must be able to refuse cookies without penalty',
              timestamp: new Date().toISOString()
            });
          }

          // Check if reject button is less prominent (dark pattern)
          if (hasAccept && hasReject) {
            const acceptButtons = Array.from(buttons).filter(b => {
              const text = b.innerText.toLowerCase();
              return text.includes('accept') || text.includes('agree') || text.includes('allow');
            });

            const rejectButtons = Array.from(buttons).filter(b => {
              const text = b.innerText.toLowerCase();
              return text.includes('reject') || text.includes('decline') || text.includes('deny');
            });

            if (acceptButtons.length > 0 && rejectButtons.length > 0) {
              const acceptStyle = window.getComputedStyle(acceptButtons[0]);
              const rejectStyle = window.getComputedStyle(rejectButtons[0]);

              const acceptSize = parseInt(acceptStyle.fontSize);
              const rejectSize = parseInt(rejectStyle.fontSize);

              // If accept button is significantly larger
              if (acceptSize > rejectSize * 1.2) {
                findings.push({
                  type: 'privacy_violation',
                  category: 'consent_dark_pattern',
                  severity: 'high',
                  title: 'Biased Consent Interface',
                  description: 'Accept button is more prominent than reject button',
                  evidence: {
                    acceptFontSize: acceptSize,
                    rejectFontSize: rejectSize,
                    gdprViolation: 'GDPR requires consent to be freely given without bias'
                  },
                  recommendation: 'Accept and reject options must be equally prominent',
                  timestamp: new Date().toISOString()
                });
              }
            }
          }

          // Check for pre-selected consent options
          const checkboxes = modal.querySelectorAll('input[type="checkbox"]:checked');
          if (checkboxes.length > 0) {
            findings.push({
              type: 'privacy_violation',
              category: 'pre_selected_consent',
              severity: 'high',
              title: 'Pre-selected Consent Checkboxes',
              description: 'Consent options are pre-checked (GDPR violation)',
              evidence: {
                preCheckedCount: checkboxes.length,
                gdprViolation: 'GDPR Article 4(11) - Pre-ticked boxes do not constitute consent'
              },
              recommendation: 'Consent must be given through clear affirmative action',
              timestamp: new Date().toISOString()
            });
          }
        }
    }

    return findings;
  }

  // Detect canvas fingerprinting
  async detectCanvasFingerprinting(document) {
    const findings = [];

    // Monitor canvas operations (this requires injection early in page load)
    // For now, we check if canvas elements exist and flag suspicious usage

    // PERFORMANCE FIX P1-2a: Get all canvas elements (we want both visible and hidden for fingerprinting detection)
    const canvasElements = Array.from(document.querySelectorAll('canvas'));

    if (canvasElements.length > 0) {
      // Check for hidden canvas elements (common in fingerprinting)
      for (const canvas of canvasElements) {
        const style = window.getComputedStyle(canvas);
        const rect = canvas.getBoundingClientRect();

        const isHidden = style.display === 'none' ||
                        style.visibility === 'hidden' ||
                        style.opacity === '0' ||
                        rect.width === 0 ||
                        rect.height === 0;

        if (isHidden) {
          findings.push({
            type: 'privacy_violation',
            category: 'canvas_fingerprinting',
            severity: 'high',
            title: 'Potential Canvas Fingerprinting',
            description: 'Page contains hidden canvas elements (used for fingerprinting)',
            evidence: {
              canvasCount: canvasElements.length,
              hiddenCanvas: true,
              dimensions: { width: rect.width, height: rect.height },
              note: 'Canvas fingerprinting uniquely identifies users without consent'
            },
            recommendation: 'Sites should disclose fingerprinting in privacy policy',
            timestamp: new Date().toISOString()
          });
        }
      }

      // Check for toDataURL calls (fingerprinting signature)
      // This would require early injection - flag for investigation
      if (canvasElements.length > 2) {
        findings.push({
          type: 'privacy_violation',
          category: 'excessive_canvas',
          severity: 'medium',
          title: 'Excessive Canvas Elements',
          description: `Page contains ${canvasElements.length} canvas elements`,
          evidence: {
            canvasCount: canvasElements.length,
            note: 'Multiple canvas elements may indicate fingerprinting attempts'
          },
          recommendation: 'Investigate if canvas elements are used for tracking',
          timestamp: new Date().toISOString()
        });
      }
    }

    return findings;
  }

  // Detect WebGL fingerprinting
  async detectWebGLFingerprinting(document) {
    const findings = [];

    // Check if page creates WebGL context
    const canvases = document.querySelectorAll('canvas');

    for (const canvas of canvases) {
      try {
        // Try to get WebGL context (non-invasive check)
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

        if (gl) {
          const style = window.getComputedStyle(canvas);
          const rect = canvas.getBoundingClientRect();

          const isHidden = style.display === 'none' ||
                          style.visibility === 'hidden' ||
                          rect.width === 0 ||
                          rect.height === 0;

          if (isHidden) {
            findings.push({
              type: 'privacy_violation',
              category: 'webgl_fingerprinting',
              severity: 'high',
              title: 'Potential WebGL Fingerprinting',
              description: 'Page uses hidden WebGL context (fingerprinting technique)',
              evidence: {
                hiddenWebGL: true,
                renderer: gl.getParameter(gl.RENDERER),
                vendor: gl.getParameter(gl.VENDOR),
                note: 'WebGL provides detailed GPU information for fingerprinting'
              },
              recommendation: 'Sites should disclose fingerprinting techniques',
              timestamp: new Date().toISOString()
            });
          }
        }
      } catch (error) {
        // Context not available, skip
      }
    }

    return findings;
  }

  // Detect audio fingerprinting
  async detectAudioFingerprinting(document) {
    const findings = [];

    // Check for AudioContext usage
    // This requires early injection - we can only detect if audio elements exist

    const audioElements = document.querySelectorAll('audio');

    // Check for hidden audio elements
    for (const audio of audioElements) {
      const style = window.getComputedStyle(audio);
      const rect = audio.getBoundingClientRect();

      const isHidden = style.display === 'none' ||
                      style.visibility === 'hidden' ||
                      rect.width === 0 ||
                      rect.height === 0;

      if (isHidden && audio.duration === 0) {
        findings.push({
          type: 'privacy_violation',
          category: 'audio_fingerprinting',
          severity: 'medium',
          title: 'Potential Audio Fingerprinting',
          description: 'Page contains hidden audio elements (may be used for fingerprinting)',
          evidence: {
            hiddenAudio: true,
            note: 'Audio context fingerprinting analyzes audio hardware characteristics'
          },
          recommendation: 'Investigate if AudioContext is used for tracking',
          timestamp: new Date().toISOString()
        });
      }
    }

    return findings;
  }

  // Detect excessive third-party tracking
  async detectExcessiveTracking(document) {
    const findings = [];

    // Count external scripts
    const scripts = document.querySelectorAll('script[src]');
    const externalScripts = Array.from(scripts).filter(s => {
      try {
        const srcURL = new URL(s.src, window.location.href);
        return srcURL.hostname !== window.location.hostname;
      } catch {
        return false;
      }
    });

    // Identify tracking scripts
    const trackingScripts = externalScripts.filter(s => {
      return this.trackingDomains.some(domain => s.src.includes(domain));
    });

    if (trackingScripts.length >= 3) {
      findings.push({
        type: 'privacy_violation',
        category: 'excessive_tracking',
        severity: 'high',
        title: 'Excessive Third-Party Tracking',
        description: `Page loads ${trackingScripts.length} known tracking scripts`,
        evidence: {
          totalExternalScripts: externalScripts.length,
          trackingScripts: trackingScripts.length,
          trackers: trackingScripts.map(s => {
            const url = new URL(s.src);
            return url.hostname;
          }).slice(0, 10)
        },
        recommendation: 'Minimize third-party trackers and disclose in privacy policy',
        timestamp: new Date().toISOString()
      });
    }

    // Count total external resources
    if (externalScripts.length >= 20) {
      findings.push({
        type: 'privacy_violation',
        category: 'excessive_third_party',
        severity: 'medium',
        title: 'Excessive Third-Party Resources',
        description: `Page loads ${externalScripts.length} external scripts`,
        evidence: {
          externalScriptCount: externalScripts.length,
          note: 'Each external script can access and track user data'
        },
        recommendation: 'Minimize external dependencies for better privacy',
        timestamp: new Date().toISOString()
      });
    }

    return findings;
  }

  // Detect GDPR violations
  async detectGDPRViolations(document) {
    const findings = [];

    // PERFORMANCE FIX P1-2a: Check for privacy policy link - filter visible links only
    const links = this.filterVisible(document.querySelectorAll('a'));
    const hasPrivacyPolicy = links.some(link => {
      const text = link.innerText.toLowerCase();
      const href = (link.href || '').toLowerCase();
      return text.includes('privacy') || href.includes('privacy');
    });

    if (!hasPrivacyPolicy) {
      findings.push({
        type: 'privacy_violation',
        category: 'missing_privacy_policy',
        severity: 'high',
        title: 'No Privacy Policy Link Found',
        description: 'Site appears to lack accessible privacy policy',
        evidence: {
          gdprViolation: 'GDPR Article 13 - Privacy information must be accessible',
          note: 'Privacy policy may exist but is not easily discoverable'
        },
        recommendation: 'Provide clear link to privacy policy',
        timestamp: new Date().toISOString()
      });
    }

    // PERFORMANCE FIX P1-2a: Check for data processing notice - filter visible forms only
    // P0-FIFTEENTH-1 FIX: Exclude trusted platforms (GitHub, GitLab) to reduce false positives
    const trustedDomains = ['github.com', 'gitlab.com', 'bitbucket.org', 'npmjs.com'];
    const isTrustedPlatform = trustedDomains.some(domain => window.location.hostname.includes(domain));

    if (!isTrustedPlatform) {
      const forms = this.filterVisible(document.querySelectorAll('form'));
      for (const form of forms) {
        const hasPersonalData = form.querySelector('input[type="email"], input[name*="email"], input[name*="name"], input[type="tel"]');

        if (hasPersonalData) {
          const formText = form.innerText.toLowerCase();
          const hasDataNotice = formText.includes('privacy') ||
                                formText.includes('personal data') ||
                                formText.includes('how we use') ||
                                formText.includes('data processing');

          if (!hasDataNotice) {
            findings.push({
              type: 'privacy_violation',
              category: 'missing_data_notice',
              severity: 'high',
              title: 'Form Lacks Data Processing Notice',
              description: 'Form collects personal data without privacy notice',
              evidence: {
                formId: form.id,
                formName: form.name,
                gdprViolation: 'GDPR Article 13 - Must inform users about data processing'
              },
              recommendation: 'Include privacy notice near data collection forms',
              timestamp: new Date().toISOString()
            });
          }
        }
      }
    }

    return findings;
  }

  // Detect localStorage/sessionStorage abuse
  async detectLocalStorageAbuse(document) {
    const findings = [];

    try {
      // Check localStorage size
      let localStorageSize = 0;
      for (let key in localStorage) {
        if (localStorage.hasOwnProperty(key)) {
          localStorageSize += localStorage[key].length + key.length;
        }
      }

      // Check sessionStorage size
      let sessionStorageSize = 0;
      for (let key in sessionStorage) {
        if (sessionStorage.hasOwnProperty(key)) {
          sessionStorageSize += sessionStorage[key].length + key.length;
        }
      }

      const totalStorageSize = localStorageSize + sessionStorageSize;

      // Flag if excessive (over 100KB)
      if (totalStorageSize > 100 * 1024) {
        findings.push({
          type: 'privacy_violation',
          category: 'excessive_storage',
          severity: 'medium',
          title: 'Excessive Local Storage Usage',
          description: `Site stores ${(totalStorageSize / 1024).toFixed(0)}KB in local storage`,
          evidence: {
            localStorageBytes: localStorageSize,
            sessionStorageBytes: sessionStorageSize,
            totalBytes: totalStorageSize,
            note: 'Large storage may contain tracking data that persists across sessions'
          },
          recommendation: 'Minimize persistent storage and disclose data retention',
          timestamp: new Date().toISOString()
        });
      }

      // Check for tracking IDs in storage
      const storageKeys = Object.keys(localStorage).concat(Object.keys(sessionStorage));
      const trackingKeywords = ['_ga', '_fbp', '_gid', 'uuid', 'uid', 'user_id', 'visitor_id', 'session_id', 'tracking'];

      const suspiciousKeys = storageKeys.filter(key =>
        trackingKeywords.some(keyword => key.toLowerCase().includes(keyword))
      );

      if (suspiciousKeys.length > 0) {
        findings.push({
          type: 'privacy_violation',
          category: 'tracking_storage',
          severity: 'medium',
          title: 'Tracking IDs in Local Storage',
          description: 'Site stores tracking identifiers in local storage',
          evidence: {
            trackingKeys: suspiciousKeys.slice(0, 10),
            keyCount: suspiciousKeys.length,
            note: 'Persistent tracking IDs can bypass cookie controls'
          },
          recommendation: 'Obtain consent before storing tracking identifiers',
          timestamp: new Date().toISOString()
        });
      }
    } catch (error) {
      // localStorage access denied or not available
    }

    return findings;
  }

  // Detect third-party data leaks
  async detectThirdPartyLeaks(document) {
    const findings = [];

    // PERFORMANCE FIX P1-2a: Check iframes - get all (both visible and hidden for tracking detection)
    const iframes = Array.from(document.querySelectorAll('iframe'));
    const thirdPartyIframes = [];

    for (const iframe of iframes) {
      try {
        if (iframe.src) {
          const iframeURL = new URL(iframe.src, window.location.href);
          if (iframeURL.hostname !== window.location.hostname) {
            thirdPartyIframes.push({
              src: iframe.src,
              hostname: iframeURL.hostname
            });
          }
        }
      } catch (error) {
        // Invalid URL
      }
    }

    if (thirdPartyIframes.length >= 3) {
      findings.push({
        type: 'privacy_violation',
        category: 'third_party_iframes',
        severity: 'medium',
        title: 'Multiple Third-Party Iframes',
        description: `Page embeds ${thirdPartyIframes.length} third-party iframes`,
        evidence: {
          iframeCount: thirdPartyIframes.length,
          domains: thirdPartyIframes.map(i => i.hostname).slice(0, 10),
          note: 'Iframes can access referrer data and track users'
        },
        recommendation: 'Minimize third-party embeds and use sandbox attributes',
        timestamp: new Date().toISOString()
      });
    }

    // Check for tracking pixels
    const images = document.querySelectorAll('img[width="1"][height="1"], img[style*="width: 1px"]');

    if (images.length > 0) {
      const trackingPixels = Array.from(images).filter(img => {
        try {
          const imgURL = new URL(img.src, window.location.href);
          return imgURL.hostname !== window.location.hostname;
        } catch {
          return false;
        }
      });

      if (trackingPixels.length > 0) {
        findings.push({
          type: 'privacy_violation',
          category: 'tracking_pixels',
          severity: 'medium',
          title: 'Tracking Pixels Detected',
          description: `Page contains ${trackingPixels.length} tracking pixels`,
          evidence: {
            pixelCount: trackingPixels.length,
            domains: trackingPixels.map(p => {
              try {
                return new URL(p.src).hostname;
              } catch {
                return 'unknown';
              }
            }).slice(0, 5),
            note: 'Tracking pixels send data to third parties without user knowledge'
          },
          recommendation: 'Disclose tracking pixels in privacy policy',
          timestamp: new Date().toISOString()
        });
      }
    }

    return findings;
  }
}

// CRITICAL FIX P0-1: Assign to window instead of ES6 export
window.privacyViolationDetector = new PrivacyViolationDetector();
console.log('Hera: Privacy violation detector loaded (no dynamic import needed)');
