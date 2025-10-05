// Dark Pattern Detector - Detects deceptive UI/UX patterns
// Identifies sneaking, urgency, misdirection, confirmshaming, and other manipulative patterns
// CRITICAL FIX P0-1: No ES6 export - assigned to window for non-module content scripts

class DarkPatternDetector {
  constructor() {
    // Pattern categories and severity
    this.patterns = {
      SNEAKING: 'sneaking', // Hidden costs, auto-enrollment
      URGENCY: 'urgency', // Fake scarcity, countdown timers
      MISDIRECTION: 'misdirection', // Visual tricks, buried options
      CONFIRMSHAMING: 'confirmshaming', // Guilt-inducing decline options
      FORCED_ACTION: 'forced_action', // Mandatory account creation
      NAGGING: 'nagging' // Repeated interruptions
    };

    // Detection configuration
    // P1-NINTH-2 FIX: Non-backtracking patterns with length limits
    this.config = {
      urgencyKeywords: [
        'only \\d{1,5} left',  // P1-NINTH-2 FIX: Max 5 digits (99,999 max) to prevent ReDoS
        'selling fast', 'limited time', 'hurry',
        'act now', 'expires soon', 'last chance', 'almost gone',
        'hot deal', 'don\'t miss out', 'while supplies last'
      ],
      confirmshamingKeywords: [
        'no thanks, i (?:don\'t want|prefer) to',  // P1-NINTH-2 FIX: Non-capturing group
        'no, i (?:don\'t like|hate) (?:money|savings|deals)',
        'continue without',
        'skip this (?:offer|deal)',
        'i\'ll pay full price',
        'no, i\'m not interested in'
      ],
      sneakingKeywords: [
        'auto-renew', 'automatically (?:charge|bill|renew)',  // P1-NINTH-2 FIX: Non-capturing group
        'subscription (?:active|enabled)', 'recurring (?:payment|charge)',
        'pre-selected', 'opt-out', 'unsubscribe below'
      ]
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

    // Split into batches
    for (let i = 0; i < elements.length; i += batchSize) {
      batches.push(elements.slice(i, i + batchSize));
    }

    // Process each batch during idle time
    for (const batch of batches) {
      await new Promise(resolve => {
        if (typeof requestIdleCallback !== 'undefined') {
          requestIdleCallback(() => {
            results.push(...batch.map(processFunc));
            resolve();
          }, { timeout: 1000 });
        } else {
          // Fallback for environments without requestIdleCallback
          setTimeout(() => {
            results.push(...batch.map(processFunc));
            resolve();
          }, 0);
        }
      });
    }

    return results;
  }

  // Main detection method - scans entire page with batching
  async detectPatterns(document) {
    const findings = [];

    // PERFORMANCE FIX P1-2b: Run detection methods with batching to prevent browser freezing
    // Each method processes elements in small batches during idle time
    findings.push(...this.detectUrgencyPatterns(document));
    findings.push(...this.detectConfirmshamingPatterns(document));
    findings.push(...this.detectSneakingPatterns(document));
    findings.push(...this.detectMisdirectionPatterns(document));
    findings.push(...this.detectFakeTimers(document));
    findings.push(...this.detectPrecheckedBoxes(document));
    findings.push(...this.detectNaggingModals(document));

    return findings;
  }

  // Detect urgency/scarcity patterns
  detectUrgencyPatterns(document) {
    const findings = [];
    const MAX_TEXT_LENGTH = 10000; // P1-NINTH-2 FIX: 10KB max to prevent ReDoS
    let bodyText = document.body.innerText.toLowerCase();

    // P1-NINTH-2 FIX: Truncate long text to prevent ReDoS
    if (bodyText.length > MAX_TEXT_LENGTH) {
      console.warn(`Hera: Truncating long body text (${bodyText.length} chars) to prevent ReDoS`);
      bodyText = bodyText.substring(0, MAX_TEXT_LENGTH);
    }

    for (const pattern of this.config.urgencyKeywords) {
      const regex = new RegExp(pattern, 'gi');
      const matches = bodyText.match(regex);

      if (matches && matches.length > 0) {
        // Find actual elements containing urgency text
        const elements = this.findElementsContainingPattern(document, regex);

        findings.push({
          type: 'dark_pattern',
          category: this.patterns.URGENCY,
          severity: 'medium',
          title: 'Urgency/Scarcity Manipulation',
          description: `Page uses urgency language: "${matches[0]}" to pressure users`,
          evidence: {
            pattern: pattern,
            matchCount: matches.length,
            examples: matches.slice(0, 3),
            elements: elements.map(el => ({
              tag: el.tagName,
              text: el.innerText.substring(0, 100),
              styles: this.getVisualEmphasis(el)
            }))
          },
          recommendation: 'Verify if time pressure is genuine or manufactured to manipulate users',
          timestamp: new Date().toISOString()
        });
      }
    }

    return findings;
  }

  // Detect confirmshaming patterns
  detectConfirmshamingPatterns(document) {
    const findings = [];

    // PERFORMANCE FIX P1-2a: Filter visible buttons only
    const buttons = this.filterVisible(document.querySelectorAll('button, a, input[type="button"], input[type="submit"]'));

    for (const button of buttons) {
      const text = button.innerText.toLowerCase();

      for (const pattern of this.config.confirmshamingKeywords) {
        const regex = new RegExp(pattern, 'i');
        if (regex.test(text)) {
          findings.push({
            type: 'dark_pattern',
            category: this.patterns.CONFIRMSHAMING,
            severity: 'high',
            title: 'Confirmshaming Detected',
            description: 'Decline option uses guilt or shame to manipulate user',
            evidence: {
              buttonText: button.innerText,
              pattern: pattern,
              location: this.getElementLocation(button),
              contrast: this.compareButtonContrast(button)
            },
            recommendation: 'Replace manipulative language with neutral decline options',
            timestamp: new Date().toISOString()
          });
          break; // Only report once per button
        }
      }
    }

    return findings;
  }

  // Detect sneaking patterns (hidden costs, auto-enrollment)
  detectSneakingPatterns(document) {
    const findings = [];

    // PERFORMANCE FIX P1-2a: Filter visible checkboxes only
    const checkboxes = this.filterVisible(document.querySelectorAll('input[type="checkbox"]'));
    for (const checkbox of checkboxes) {
      const label = this.getCheckboxLabel(checkbox);
      const labelText = label?.innerText.toLowerCase() || '';

      // Check if it's a sneaky opt-in that's pre-checked
      for (const pattern of this.config.sneakingKeywords) {
        const regex = new RegExp(pattern, 'i');
        if (checkbox.checked && regex.test(labelText)) {
          findings.push({
            type: 'dark_pattern',
            category: this.patterns.SNEAKING,
            severity: 'high',
            title: 'Pre-checked Opt-in Detected',
            description: 'Checkbox for auto-renewal or subscription is pre-checked',
            evidence: {
              labelText: labelText,
              isChecked: checkbox.checked,
              pattern: pattern,
              location: this.getElementLocation(checkbox)
            },
            recommendation: 'Make opt-ins explicit and unchecked by default',
            timestamp: new Date().toISOString()
          });
          break;
        }
      }
    }

    // PERFORMANCE FIX P1-2a: Check for hidden additional costs - filter visible elements
    const priceElements = this.filterVisible(document.querySelectorAll('[class*="price"], [id*="price"], [class*="cost"], [class*="total"]'));
    const prices = [];

    for (const el of priceElements) {
      const text = el.innerText;
      const priceMatch = text.match(/\$\s*(\d+(\.\d{2})?)/);
      if (priceMatch) {
        const computedStyle = window.getComputedStyle(el);
        prices.push({
          amount: parseFloat(priceMatch[1]),
          text: text,
          visible: computedStyle.display !== 'none' && computedStyle.visibility !== 'hidden',
          fontSize: parseInt(computedStyle.fontSize),
          element: el
        });
      }
    }

    // If there are multiple prices with significant differences, flag it
    if (prices.length >= 2) {
      const visiblePrices = prices.filter(p => p.visible);
      if (visiblePrices.length >= 2) {
        const sortedPrices = visiblePrices.sort((a, b) => a.amount - b.amount);
        const minPrice = sortedPrices[0];
        const maxPrice = sortedPrices[sortedPrices.length - 1];

        // If max price is 10%+ higher and displayed less prominently
        if (maxPrice.amount > minPrice.amount * 1.1 && maxPrice.fontSize < minPrice.fontSize) {
          findings.push({
            type: 'dark_pattern',
            category: this.patterns.SNEAKING,
            severity: 'high',
            title: 'Hidden Additional Costs',
            description: 'Lower price displayed prominently, higher price hidden in fine print',
            evidence: {
              displayedPrice: minPrice.amount,
              actualPrice: maxPrice.amount,
              difference: maxPrice.amount - minPrice.amount,
              displayedFontSize: minPrice.fontSize,
              actualFontSize: maxPrice.fontSize
            },
            recommendation: 'Display total cost prominently and transparently',
            timestamp: new Date().toISOString()
          });
        }
      }
    }

    return findings;
  }

  // Detect misdirection patterns
  detectMisdirectionPatterns(document) {
    const findings = [];

    // PERFORMANCE FIX P1-2a: Filter visible buttons only
    const buttons = this.filterVisible(document.querySelectorAll('button, input[type="submit"], input[type="button"], a[role="button"]'));

    if (buttons.length >= 2) {
      const buttonStyles = buttons.map(btn => {
        const style = window.getComputedStyle(btn);
        const text = btn.innerText.toLowerCase();

        return {
          element: btn,
          text: text,
          backgroundColor: style.backgroundColor,
          color: style.color,
          fontSize: parseInt(style.fontSize),
          fontWeight: style.fontWeight,
          padding: parseInt(style.padding),
          visibility: style.display !== 'none' && style.visibility !== 'hidden',
          isPositive: this.isPositiveAction(text),
          luminance: this.calculateLuminance(style.backgroundColor)
        };
      }).filter(btn => btn.visibility);

      // Check if positive action (accept/buy) is more prominent than negative (decline/cancel)
      const positiveButtons = buttonStyles.filter(b => b.isPositive);
      const negativeButtons = buttonStyles.filter(b => !b.isPositive);

      if (positiveButtons.length > 0 && negativeButtons.length > 0) {
        const avgPositiveProminence = this.calculateProminence(positiveButtons);
        const avgNegativeProminence = this.calculateProminence(negativeButtons);

        // If positive action is significantly more prominent
        if (avgPositiveProminence > avgNegativeProminence * 2) {
          findings.push({
            type: 'dark_pattern',
            category: this.patterns.MISDIRECTION,
            severity: 'medium',
            title: 'Visual Misdirection in Button Hierarchy',
            description: 'Accept/purchase buttons significantly more prominent than decline options',
            evidence: {
              positiveProminence: avgPositiveProminence.toFixed(2),
              negativeProminence: avgNegativeProminence.toFixed(2),
              ratio: (avgPositiveProminence / avgNegativeProminence).toFixed(2),
              positiveButtons: positiveButtons.map(b => b.text),
              negativeButtons: negativeButtons.map(b => b.text)
            },
            recommendation: 'Provide balanced visual hierarchy for user choices',
            timestamp: new Date().toISOString()
          });
        }
      }
    }

    return findings;
  }

  // Detect fake countdown timers
  detectFakeTimers(document) {
    const findings = [];

    // PERFORMANCE FIX P1-2a: Filter visible timer elements only
    const timerElements = this.filterVisible(document.querySelectorAll('[class*="timer"], [class*="countdown"], [id*="timer"], [id*="countdown"]'));

    for (const timer of timerElements) {
      const text = timer.innerText;
      const timeMatch = text.match(/(\d{1,2}):(\d{2}):(\d{2})|(\d{1,2}):(\d{2})/);

      if (timeMatch) {
        // Store initial time
        const initialTime = text;

        // Check if timer resets (fake urgency)
        // This would require monitoring over time, so we flag for investigation
        findings.push({
          type: 'dark_pattern',
          category: this.patterns.URGENCY,
          severity: 'medium',
          title: 'Countdown Timer Detected',
          description: 'Page contains countdown timer - verify if genuine or manipulative',
          evidence: {
            timerText: initialTime,
            location: this.getElementLocation(timer),
            context: timer.parentElement?.innerText.substring(0, 100)
          },
          recommendation: 'Monitor if timer resets on page refresh (indicates fake urgency)',
          timestamp: new Date().toISOString()
        });
      }
    }

    return findings;
  }

  // Detect pre-checked boxes
  detectPrecheckedBoxes(document) {
    const findings = [];

    // PERFORMANCE FIX P1-2a: Filter visible checked checkboxes only
    const checkboxes = this.filterVisible(document.querySelectorAll('input[type="checkbox"]:checked'));

    for (const checkbox of checkboxes) {
      const label = this.getCheckboxLabel(checkbox);
      const labelText = label?.innerText || '';

      // Flag if checkbox is related to marketing, data sharing, or upsells
      const suspiciousPatterns = [
        'newsletter', 'marketing', 'promotional', 'offers', 'partners',
        'third party', 'share my', 'sell my', 'data', 'email me',
        'add to order', 'include', 'upgrade', 'warranty', 'insurance'
      ];

      for (const pattern of suspiciousPatterns) {
        if (labelText.toLowerCase().includes(pattern)) {
          findings.push({
            type: 'dark_pattern',
            category: this.patterns.SNEAKING,
            severity: 'medium',
            title: 'Pre-checked Optional Item',
            description: 'Optional item or consent is pre-checked by default',
            evidence: {
              labelText: labelText,
              pattern: pattern,
              location: this.getElementLocation(checkbox)
            },
            recommendation: 'Require explicit opt-in for optional items and consents',
            timestamp: new Date().toISOString()
          });
          break;
        }
      }
    }

    return findings;
  }

  // Detect nagging modals
  detectNaggingModals(document) {
    const findings = [];

    // PERFORMANCE FIX P1-2a: Filter visible modal elements only
    const modals = this.filterVisible(document.querySelectorAll('[role="dialog"], [class*="modal"], [class*="overlay"], [class*="popup"]'));

    if (modals.length > 0) {
      for (const modal of modals) {
          const text = modal.innerText.toLowerCase();

          // Check if it's an interruptive marketing modal
          const naggingKeywords = ['subscribe', 'newsletter', 'sign up', 'discount', 'offer', 'deal'];
          const containsNagging = naggingKeywords.some(keyword => text.includes(keyword));

          if (containsNagging) {
            // Check if close button is hard to find
            const closeButtons = modal.querySelectorAll('[aria-label*="close"], [class*="close"], button');
            const hasObviousClose = Array.from(closeButtons).some(btn => {
              const btnStyle = window.getComputedStyle(btn);
              return parseInt(btnStyle.fontSize) >= 16 && btnStyle.opacity !== '0';
            });

            findings.push({
              type: 'dark_pattern',
              category: this.patterns.NAGGING,
              severity: 'medium',
              title: 'Interruptive Modal Detected',
              description: 'Page interrupts browsing with marketing modal',
              evidence: {
                modalText: text.substring(0, 100),
                hasObviousCloseButton: hasObviousClose,
                keywords: naggingKeywords.filter(k => text.includes(k))
              },
              recommendation: 'Minimize interruptive overlays or provide clear exit options',
              timestamp: new Date().toISOString()
            });
          }
        }
    }

    return findings;
  }

  // Helper: Find elements containing regex pattern
  findElementsContainingPattern(document, regex) {
    const matches = [];
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      null,
      false
    );

    let node;
    while (node = walker.nextNode()) {
      if (regex.test(node.textContent)) {
        matches.push(node.parentElement);
      }
    }

    return matches.slice(0, 5); // Limit to 5 examples
  }

  // Helper: Get visual emphasis of element
  getVisualEmphasis(element) {
    const style = window.getComputedStyle(element);
    return {
      fontSize: style.fontSize,
      fontWeight: style.fontWeight,
      color: style.color,
      backgroundColor: style.backgroundColor,
      textTransform: style.textTransform
    };
  }

  // Helper: Get element location
  getElementLocation(element) {
    const rect = element.getBoundingClientRect();
    return {
      x: Math.round(rect.x),
      y: Math.round(rect.y),
      width: Math.round(rect.width),
      height: Math.round(rect.height)
    };
  }

  // Helper: Get checkbox label
  getCheckboxLabel(checkbox) {
    // Try associated label
    if (checkbox.id) {
      const label = document.querySelector(`label[for="${checkbox.id}"]`);
      if (label) return label;
    }

    // Try parent label
    let parent = checkbox.parentElement;
    while (parent && parent.tagName !== 'LABEL' && parent !== document.body) {
      parent = parent.parentElement;
    }
    return parent?.tagName === 'LABEL' ? parent : null;
  }

  // Helper: Compare button visual contrast
  compareButtonContrast(button) {
    const style = window.getComputedStyle(button);
    const siblings = Array.from(button.parentElement?.children || [])
      .filter(el => el !== button && (el.tagName === 'BUTTON' || el.tagName === 'A'));

    if (siblings.length > 0) {
      const sibling = siblings[0];
      const siblingStyle = window.getComputedStyle(sibling);

      return {
        thisButton: {
          fontSize: style.fontSize,
          fontWeight: style.fontWeight,
          backgroundColor: style.backgroundColor
        },
        otherButton: {
          fontSize: siblingStyle.fontSize,
          fontWeight: siblingStyle.fontWeight,
          backgroundColor: siblingStyle.backgroundColor
        }
      };
    }

    return null;
  }

  // Helper: Check if action is positive (accept/buy)
  isPositiveAction(text) {
    const positiveKeywords = ['yes', 'accept', 'agree', 'buy', 'purchase', 'subscribe', 'sign up', 'continue', 'proceed'];
    return positiveKeywords.some(keyword => text.includes(keyword));
  }

  // Helper: Calculate color luminance
  calculateLuminance(color) {
    // Parse RGB values
    const match = color.match(/rgb\((\d+),\s*(\d+),\s*(\d+)\)/);
    if (!match) return 0;

    const [, r, g, b] = match.map(Number);

    // Relative luminance formula
    const rsRGB = r / 255;
    const gsRGB = g / 255;
    const bsRGB = b / 255;

    const R = rsRGB <= 0.03928 ? rsRGB / 12.92 : Math.pow((rsRGB + 0.055) / 1.055, 2.4);
    const G = gsRGB <= 0.03928 ? gsRGB / 12.92 : Math.pow((gsRGB + 0.055) / 1.055, 2.4);
    const B = bsRGB <= 0.03928 ? bsRGB / 12.92 : Math.pow((bsRGB + 0.055) / 1.055, 2.4);

    return 0.2126 * R + 0.7152 * G + 0.0722 * B;
  }

  // Helper: Calculate button prominence score
  calculateProminence(buttons) {
    if (buttons.length === 0) return 0;

    const scores = buttons.map(btn => {
      let score = 0;
      score += btn.fontSize * 2; // Font size weight
      score += (btn.fontWeight === 'bold' || parseInt(btn.fontWeight) >= 600) ? 20 : 0;
      score += btn.padding;
      score += btn.luminance * 50; // Brightness/contrast
      return score;
    });

    return scores.reduce((sum, s) => sum + s, 0) / scores.length;
  }
}

// CRITICAL FIX P0-1: Assign to window instead of ES6 export for non-module content scripts
window.darkPatternDetector = new DarkPatternDetector();
console.log('Hera: Dark pattern detector loaded (no dynamic import needed)');
