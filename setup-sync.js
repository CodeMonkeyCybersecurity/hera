// Hera Extension - Sync Configuration Setup
// Run this in the browser console on the extension popup to configure remote sync

async function setupHeraSync() {
  console.log('🔧 Setting up Hera sync configuration...');
  
  // Configuration options
  const config = {
    syncEndpoint: 'http://localhost:8000/auth-events', // Change to your backend URL
    riskThreshold: 50, // Alert threshold for risk scores
    enableRealTimeAlerts: true,
    syncInterval: 5, // minutes
    maxLocalStorage: 1000 // max events to keep locally
  };
  
  try {
    // Store configuration
    await chrome.storage.local.set({ heraConfig: config });
    
    console.log('Hera sync configuration saved:', config);
    console.log('📡 Extension will now sync authentication events to:', config.syncEndpoint);
    
    // Test connection to backend
    try {
      const response = await fetch(config.syncEndpoint.replace('/auth-events', '/dashboard/stats'));
      if (response.ok) {
        const stats = await response.json();
        console.log(' Backend connection successful! Current stats:', stats);
      } else {
        console.log(' Backend connection failed. Make sure your backend is running.');
      }
    } catch (e) {
      console.log(' Could not connect to backend. Events will be stored locally only.');
    }
    
    return config;
  } catch (error) {
    console.error(' Failed to setup sync:', error);
    throw error;
  }
}

// Example usage for different deployment scenarios
const deploymentExamples = {
  // Local development
  local: {
    syncEndpoint: 'http://localhost:8000/auth-events',
    description: 'For local development with Python FastAPI backend'
  },
  
  // Cloud deployment examples
  aws: {
    syncEndpoint: 'https://your-api-gateway.amazonaws.com/prod/auth-events',
    description: 'AWS API Gateway + Lambda deployment'
  },
  
  heroku: {
    syncEndpoint: 'https://your-hera-backend.herokuapp.com/auth-events',
    description: 'Heroku deployment'
  },
  
  digitalocean: {
    syncEndpoint: 'https://your-droplet-ip:8000/auth-events',
    description: 'DigitalOcean droplet deployment'
  },
  
  // Self-hosted options
  selfHosted: {
    syncEndpoint: 'https://your-domain.com/hera/auth-events',
    description: 'Self-hosted with reverse proxy (nginx/apache)'
  }
};

console.log('Hera Sync Setup Ready!');
console.log('Available deployment options:', deploymentExamples);
console.log('🔧 Run setupHeraSync() to configure with default local settings');
console.log('🔧 Or modify the config object above and run setupHeraSync() with your settings');

// Auto-setup for development (uncomment to auto-configure)
// setupHeraSync();
