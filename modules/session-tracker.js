// Session Tracker - Persistent session correlation across service worker restarts
// CRITICAL FIX P0-NEW: Migrated to chrome.storage.local (was chrome.storage.session)
// Prevents split-brain storage architecture issues

export class SessionTracker {
  constructor() {
    // In-memory caches
    this._currentSessions = new Map();
    this._domainToSession = new Map();
    this._tabSessions = new Map();
    this._authenticatedDomains = new Set();

    this.temporalWindow = 30000; // 30 seconds for temporal correlation
    this.initialized = false;
    this.initPromise = this.initialize();
  }

  // Initialize by loading from storage.session
  async initialize() {
    if (this.initialized) return;

    try {
      // CRITICAL FIX P0-NEW: Use chrome.storage.local (survives browser restart)
      const data = await chrome.storage.local.get(['heraSessionTracker']);

      if (data.heraSessionTracker) {
        const restored = data.heraSessionTracker;

        // Restore currentSessions
        if (restored.currentSessions) {
          for (const [id, session] of Object.entries(restored.currentSessions)) {
            session.domains = new Set(session.domains);
            session.tabIds = new Set(session.tabIds);
            session.initiators = new Set(session.initiators);
            session.authTokenHashes = new Set(session.authTokenHashes);
            this._currentSessions.set(id, session);
          }
        }

        // Restore domainToSession
        if (restored.domainToSession) {
          for (const [domain, sessionId] of Object.entries(restored.domainToSession)) {
            this._domainToSession.set(domain, sessionId);
          }
        }

        // Restore tabSessions
        if (restored.tabSessions) {
          for (const [tabId, sessionIds] of Object.entries(restored.tabSessions)) {
            this._tabSessions.set(parseInt(tabId), new Set(sessionIds));
          }
        }

        // Restore authenticatedDomains
        if (restored.authenticatedDomains) {
          this._authenticatedDomains = new Set(restored.authenticatedDomains);
        }

        console.log(`Hera: Restored ${this._currentSessions.size} sessions from storage.session`);
      }

      this.initialized = true;
    } catch (error) {
      console.error('Hera: Failed to initialize session tracker:', error);
      this.initialized = true;
    }
  }

  // Background sync to storage.session
  async _syncToStorage() {
    try {
      await this.initPromise;

      // Convert Maps and Sets to plain objects/arrays
      const currentSessionsObj = {};
      for (const [id, session] of this._currentSessions.entries()) {
        currentSessionsObj[id] = {
          ...session,
          domains: Array.from(session.domains),
          tabIds: Array.from(session.tabIds),
          initiators: Array.from(session.initiators),
          authTokenHashes: Array.from(session.authTokenHashes)
        };
      }

      const domainToSessionObj = Object.fromEntries(this._domainToSession.entries());

      const tabSessionsObj = {};
      for (const [tabId, sessionIds] of this._tabSessions.entries()) {
        tabSessionsObj[tabId] = Array.from(sessionIds);
      }

      const authenticatedDomainsArr = Array.from(this._authenticatedDomains);

      // CRITICAL FIX P0-NEW: Use chrome.storage.local (survives browser restart)
      await chrome.storage.local.set({
        heraSessionTracker: {
          currentSessions: currentSessionsObj,
          domainToSession: domainToSessionObj,
          tabSessions: tabSessionsObj,
          authenticatedDomains: authenticatedDomainsArr
        }
      });
    } catch (error) {
      console.error('Hera: Failed to sync session tracker:', error);
    }
  }

  // Debounced sync
  syncWrite() {
    if (this._syncTimeout) clearTimeout(this._syncTimeout);
    this._syncTimeout = setTimeout(() => {
      this._syncToStorage().catch(err =>
        console.error('Hera: Session tracker sync failed:', err)
      );
    }, 100);
  }

  // === PUBLIC API ===

  getOrCreateSession(domain, service, requestContext = {}) {
    const { tabId, initiator, timestamp, authHeaders } = requestContext;

    // 1. Check for existing session correlation
    const correlatedSession = this.findCorrelatedSession(domain, service, requestContext);

    if (correlatedSession) {
      this.addDomainToSession(correlatedSession.id, domain);
      console.log(`Correlated ${domain} with existing ${service} session (${correlatedSession.correlationReason})`);
      return correlatedSession;
    }

    // 2. Create new session with smart grouping
    const sessionId = this.generateSessionId(domain, timestamp);
    const sessionInfo = {
      id: sessionId,
      primaryDomain: domain,
      domains: new Set([domain]),
      service: service,
      startTime: timestamp || Date.now(),
      lastActivity: timestamp || Date.now(),
      eventCount: 1,
      tabIds: new Set(tabId ? [tabId] : []),
      initiators: new Set(initiator ? [initiator] : []),
      authTokenHashes: new Set(),
      ecosystem: this.detectEcosystem(domain, service),
      correlationFactors: []
    };

    this._currentSessions.set(sessionId, sessionInfo);
    this._domainToSession.set(domain, sessionId);

    if (tabId) {
      if (!this._tabSessions.has(tabId)) {
        this._tabSessions.set(tabId, new Set());
      }
      this._tabSessions.get(tabId).add(sessionId);
    }

    this.syncWrite(); // Persist

    console.log(`New session started for ${service} (${domain}) - Session ID: ${sessionId}`);
    return sessionInfo;
  }

  findCorrelatedSession(domain, service, context) {
    const { tabId, initiator, timestamp, authHeaders } = context;
    const now = timestamp || Date.now();

    // Get all active sessions for this service
    const serviceSessions = Array.from(this._currentSessions.values())
      .filter(session => session.service === service && (now - session.lastActivity) < this.temporalWindow);

    for (const session of serviceSessions) {
      const correlationScore = this.calculateCorrelationScore(session, domain, context);

      if (correlationScore.score > 0.7) {
        session.correlationReason = correlationScore.reasons.join(', ');
        return session;
      }
    }

    return null;
  }

  calculateCorrelationScore(session, domain, context) {
    const { tabId, initiator, timestamp, authHeaders } = context;
    let score = 0;
    const reasons = [];

    // Same tab (+0.3)
    if (tabId && session.tabIds.has(tabId)) {
      score += 0.3;
      reasons.push('same tab');
    }

    // Same initiator (+0.2)
    if (initiator && session.initiators.has(initiator)) {
      score += 0.2;
      reasons.push('same initiator');
    }

    // Same ecosystem (+0.3)
    const ecosystem = this.detectEcosystem(domain, session.service);
    if (ecosystem === session.ecosystem && ecosystem !== 'unknown') {
      score += 0.3;
      reasons.push('same ecosystem');
    }

    // Related domain (+0.4)
    if (this.areDomainsRelated(domain, session.primaryDomain)) {
      score += 0.4;
      reasons.push('related domain');
    }

    return { score, reasons };
  }

  areDomainsRelated(domain1, domain2) {
    const getRootDomain = (domain) => {
      const parts = domain.split('.');
      return parts.length >= 2 ? parts.slice(-2).join('.') : domain;
    };

    return getRootDomain(domain1) === getRootDomain(domain2);
  }

  detectEcosystem(domain, service) {
    const ecosystems = {
      google: /google|gmail|youtube|gstatic/i,
      microsoft: /microsoft|live|outlook|office|azure/i,
      amazon: /amazon|aws|a2z/i,
      meta: /facebook|fb|instagram|meta/i,
      okta: /okta|oktapreview/i,
      auth0: /auth0/i
    };

    for (const [name, pattern] of Object.entries(ecosystems)) {
      if (pattern.test(domain) || pattern.test(service)) {
        return name;
      }
    }

    return 'unknown';
  }

  generateSessionId(domain, timestamp) {
    const time = timestamp || Date.now();
    const random = Math.random().toString(36).substring(2, 9);
    return `session_${time}_${random}`;
  }

  addDomainToSession(sessionId, domain) {
    const session = this._currentSessions.get(sessionId);
    if (session) {
      session.domains.add(domain);
      session.lastActivity = Date.now();
      session.eventCount++;
      this._domainToSession.set(domain, sessionId);
      this.syncWrite();
    }
  }

  identifyService(hostname) {
    const lowerHostname = hostname.toLowerCase();

    const legitimateServices = [
      'okta.com', 'oktapreview.com', 'auth0.com',
      'accounts.google.com', 'login.microsoftonline.com',
      'api.github.com', 'github.com',
      'login.salesforce.com', 'slack.com',
      'id.atlassian.com', 'auth.atlassian.com',
      'login.live.com', 'amazon.com',
      'app.terraform.io', 'gitlab.com'
    ];

    const matchedService = legitimateServices.find(service =>
      lowerHostname === service || lowerHostname.endsWith('.' + service)
    );

    return matchedService || hostname;
  }

  async cleanupOldSessions() {
    await this.initPromise;
    const now = Date.now();
    const sessionTimeout = 30 * 60 * 1000; // 30 minutes
    let cleaned = 0;

    for (const [sessionId, session] of this._currentSessions.entries()) {
      const age = now - session.lastActivity;
      if (age > sessionTimeout) {
        // Remove from all tracking structures
        for (const domain of session.domains) {
          this._domainToSession.delete(domain);
        }
        for (const tabId of session.tabIds) {
          const tabSessions = this._tabSessions.get(tabId);
          if (tabSessions) {
            tabSessions.delete(sessionId);
            if (tabSessions.size === 0) {
              this._tabSessions.delete(tabId);
            }
          }
        }
        this._currentSessions.delete(sessionId);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      console.log(`Hera: Cleaned up ${cleaned} old sessions`);
      await this._syncToStorage();
    }
  }

  // Getters for backward compatibility
  get currentSessions() {
    return this._currentSessions;
  }

  get domainToSession() {
    return this._domainToSession;
  }

  get tabSessions() {
    return this._tabSessions;
  }

  get authenticatedDomains() {
    return this._authenticatedDomains;
  }
}

// Export singleton
export const sessionTracker = new SessionTracker();
