// Hera Throttled Message Queue
// SECURITY FIX P1-4 & NEW-P0-3: Proper message queue with priority

/**
 * ThrottledMessageQueue class
 * Manages message sending with throttling and priority
 */
export class ThrottledMessageQueue {
  constructor() {
    this.queue = [];
    this.lastMessageTime = 0;
    this.processing = false;
    this.maxQueueSize = 10;

    // SECURITY FIX P2-3: Different throttle rates per message type
    this.throttleRates = {
      'ANALYSIS_COMPLETE': 2000,    // 1 per 2 seconds (expensive)
      'ANALYSIS_ERROR': 5000,       // 1 per 5 seconds (rare)
      'default': 500                // 2 per second for others
    };

    // SECURITY FIX NEW-P0-3: Cleanup on page unload
    window.addEventListener('unload', () => this.cleanup());
  }

  getThrottleRate(messageType) {
    return this.throttleRates[messageType] || this.throttleRates.default;
  }

  getPriority(messageType) {
    // Higher priority = processed first
    const priorities = {
      'ANALYSIS_COMPLETE': 10,
      'ANALYSIS_ERROR': 5,
      'default': 1
    };
    return priorities[messageType] || priorities.default;
  }

  send(message) {
    const now = Date.now();
    const throttleRate = this.getThrottleRate(message.type);

    // Send immediately if throttle window passed and queue empty
    if (now - this.lastMessageTime >= throttleRate && this.queue.length === 0) {
      this._sendMessage(message);
      return true;
    }

    // Queue message with priority and timestamp
    const priority = this.getPriority(message.type);

    if (this.queue.length >= this.maxQueueSize) {
      // Find and remove lowest priority message
      let lowestIndex = 0;
      let lowestPriority = this.queue[0].priority;

      for (let i = 1; i < this.queue.length; i++) {
        if (this.queue[i].priority < lowestPriority) {
          lowestPriority = this.queue[i].priority;
          lowestIndex = i;
        }
      }

      console.warn('Hera: Queue full, dropping message:', this.queue[lowestIndex].message.type);
      this.queue.splice(lowestIndex, 1);
    }

    this.queue.push({ message, priority, timestamp: now });
    console.log(`Hera: Message queued (priority ${priority}):`, message.type);

    // Start processing if not already running
    if (!this.processing) {
      this._processQueue();
    }

    return false;
  }

  _processQueue() {
    if (this.processing || this.queue.length === 0) {
      return;
    }

    this.processing = true;

    const processNext = () => {
      if (this.queue.length === 0) {
        this.processing = false;
        return;
      }

      const now = Date.now();

      // Sort queue by priority (highest first)
      this.queue.sort((a, b) => b.priority - a.priority);

      const item = this.queue[0];
      const throttleRate = this.getThrottleRate(item.message.type);
      const timeSinceLastMessage = now - this.lastMessageTime;

      if (timeSinceLastMessage >= throttleRate) {
        // Send highest priority message
        this.queue.shift();
        this._sendMessage(item.message);

        // Schedule next processing
        if (this.queue.length > 0) {
          setTimeout(processNext, this.getThrottleRate(this.queue[0].message.type));
        } else {
          this.processing = false;
        }
      } else {
        // Wait for throttle window to pass
        const delay = throttleRate - timeSinceLastMessage;
        setTimeout(processNext, delay);
      }
    };

    processNext();
  }

  _sendMessage(message) {
    this.lastMessageTime = Date.now();
    try {
      chrome.runtime.sendMessage(message);
      console.log('Hera: Sent message:', message.type);
    } catch (error) {
      console.error('Hera: Failed to send message:', error);
    }
  }

  cleanup() {
    this.queue = [];
    this.processing = false;
    console.log('Hera: Message queue cleaned up');
  }
}

/**
 * Create a singleton instance
 */
let messageQueueInstance = null;

export function getMessageQueue() {
  if (!messageQueueInstance) {
    messageQueueInstance = new ThrottledMessageQueue();
  }
  return messageQueueInstance;
}

/**
 * Convenience function to send throttled messages
 * @param {Object} message - Message to send
 */
export function sendThrottledMessage(message) {
  const queue = getMessageQueue();
  queue.send(message);
}
