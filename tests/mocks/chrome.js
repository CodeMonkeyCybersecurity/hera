// Mock Chrome Extension APIs for testing
import { vi } from 'vitest';

// Mock storage data
let storageData = {};

export const chromeMock = {
  // Storage API
  storage: {
    local: {
      get: vi.fn((keys, callback) => {
        const result = {};
        if (typeof keys === 'string') {
          result[keys] = storageData[keys];
        } else if (Array.isArray(keys)) {
          keys.forEach(key => {
            result[key] = storageData[key];
          });
        } else if (typeof keys === 'object') {
          Object.keys(keys).forEach(key => {
            result[key] = storageData[key] !== undefined ? storageData[key] : keys[key];
          });
        } else {
          Object.assign(result, storageData);
        }
        if (callback) callback(result);
        return Promise.resolve(result);
      }),
      set: vi.fn((items, callback) => {
        Object.assign(storageData, items);
        if (callback) callback();
        return Promise.resolve();
      }),
      remove: vi.fn((keys, callback) => {
        const keysArray = Array.isArray(keys) ? keys : [keys];
        keysArray.forEach(key => delete storageData[key]);
        if (callback) callback();
        return Promise.resolve();
      }),
      clear: vi.fn((callback) => {
        storageData = {};
        if (callback) callback();
        return Promise.resolve();
      })
    },
    sync: {
      get: vi.fn(),
      set: vi.fn(),
      remove: vi.fn(),
      clear: vi.fn()
    },
    onChanged: {
      addListener: vi.fn(),
      removeListener: vi.fn()
    }
  },

  // Runtime API
  runtime: {
    getManifest: vi.fn(() => ({
      manifest_version: 3,
      name: 'Hera',
      version: '1.0.0'
    })),
    sendMessage: vi.fn((message, callback) => {
      if (callback) callback({ success: true });
      return Promise.resolve({ success: true });
    }),
    onMessage: {
      addListener: vi.fn(),
      removeListener: vi.fn()
    },
    onInstalled: {
      addListener: vi.fn()
    },
    lastError: null,
    id: 'test-extension-id'
  },

  // Tabs API
  tabs: {
    query: vi.fn(() => Promise.resolve([{ id: 1, url: 'https://example.com' }])),
    sendMessage: vi.fn(() => Promise.resolve({ success: true })),
    create: vi.fn(() => Promise.resolve({ id: 2 })),
    update: vi.fn(() => Promise.resolve({ id: 1 })),
    remove: vi.fn(() => Promise.resolve()),
    onUpdated: {
      addListener: vi.fn(),
      removeListener: vi.fn()
    },
    onRemoved: {
      addListener: vi.fn(),
      removeListener: vi.fn()
    }
  },

  // WebRequest API
  webRequest: {
    onBeforeRequest: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
      hasListener: vi.fn(() => false)
    },
    onBeforeSendHeaders: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
      hasListener: vi.fn(() => false)
    },
    onSendHeaders: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
      hasListener: vi.fn(() => false)
    },
    onHeadersReceived: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
      hasListener: vi.fn(() => false)
    },
    onResponseStarted: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
      hasListener: vi.fn(() => false)
    },
    onCompleted: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
      hasListener: vi.fn(() => false)
    },
    onErrorOccurred: {
      addListener: vi.fn(),
      removeListener: vi.fn(),
      hasListener: vi.fn(() => false)
    },
    MAX_HANDLER_BEHAVIOR_CHANGED_CALLS_PER_10_MINUTES: 20
  },

  // DevTools API
  devtools: {
    panels: {
      create: vi.fn((title, icon, page, callback) => {
        const panel = { onShown: { addListener: vi.fn() }, onHidden: { addListener: vi.fn() } };
        if (callback) callback(panel);
      })
    },
    network: {
      onRequestFinished: {
        addListener: vi.fn(),
        removeListener: vi.fn()
      },
      getHAR: vi.fn()
    },
    inspectedWindow: {
      tabId: 1,
      eval: vi.fn()
    }
  },

  // Cookies API
  cookies: {
    get: vi.fn(),
    getAll: vi.fn(() => Promise.resolve([])),
    set: vi.fn(),
    remove: vi.fn(),
    onChanged: {
      addListener: vi.fn(),
      removeListener: vi.fn()
    }
  },

  // Alarms API
  alarms: {
    create: vi.fn(),
    clear: vi.fn(),
    clearAll: vi.fn(),
    get: vi.fn(),
    getAll: vi.fn(),
    onAlarm: {
      addListener: vi.fn(),
      removeListener: vi.fn()
    }
  },

  // Action API (Manifest V3)
  action: {
    setBadgeText: vi.fn(),
    setBadgeBackgroundColor: vi.fn(),
    setIcon: vi.fn(),
    setTitle: vi.fn(),
    onClicked: {
      addListener: vi.fn(),
      removeListener: vi.fn()
    }
  },

  // Scripting API (Manifest V3)
  scripting: {
    executeScript: vi.fn(),
    insertCSS: vi.fn(),
    removeCSS: vi.fn()
  },

  // Windows API
  windows: {
    getCurrent: vi.fn(() => Promise.resolve({ id: 1, focused: true })),
    getAll: vi.fn(() => Promise.resolve([{ id: 1 }])),
    create: vi.fn(),
    update: vi.fn()
  },

  // Permissions API
  permissions: {
    contains: vi.fn(() => Promise.resolve(true)),
    request: vi.fn(() => Promise.resolve(true)),
    remove: vi.fn()
  }
};

// Helper to reset all mocks
export function resetChromeMocks() {
  storageData = {};
  Object.values(chromeMock.storage.local).forEach(fn => {
    if (fn && typeof fn.mockClear === 'function') fn.mockClear();
  });
  Object.values(chromeMock.runtime).forEach(fn => {
    if (fn && typeof fn === 'object' && typeof fn.mockClear === 'function') fn.mockClear();
  });
  // Reset other APIs as needed
}

// Helper to set storage data for testing
export function setMockStorageData(data) {
  storageData = { ...data };
}

// Helper to get current storage data
export function getMockStorageData() {
  return { ...storageData };
}
