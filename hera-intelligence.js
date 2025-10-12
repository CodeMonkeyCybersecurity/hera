// Hera Comprehensive Website Intelligence Collection Framework
// Multi-layered data collection for sophisticated threat detection
// Modular architecture with specialized collectors

import { IntelligenceCoordinator } from './modules/intelligence/intelligence-coordinator.js';

// Backward compatibility wrapper
class HeraComprehensiveDataCollector extends IntelligenceCoordinator {
  constructor() {
    super();
  }
}

export { HeraComprehensiveDataCollector };
