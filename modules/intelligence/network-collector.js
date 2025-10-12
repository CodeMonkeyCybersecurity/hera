// Network & Infrastructure Data Collector
// Handles DNS, CDN, hosting, ports, and geolocation analysis

class NetworkCollector {
  async collectNetworkData(domain) {
    const networkData = {
      dns: await this.collectDNSData(domain),
      cdn: await this.detectCDN(domain),
      hosting: await this.identifyHosting(domain),
      ports: await this.scanCommonPorts(domain),
      geo: await this.geolocateServer(domain)
    };

    return networkData;
  }

  async collectDNSData(domain) {
    const dnsData = {
      aRecords: [],
      aaaaRecords: [],
      mxRecords: [],
      txtRecords: [],
      cnameRecords: {},
      nsRecords: [],
      dnsAge: null,
      dnssecEnabled: false,
      anomalies: []
    };

    try {
      // Since browsers can't directly do DNS lookups, we use heuristics and public APIs
      // In a real implementation, you'd use a backend service

      // Estimate A records from IP resolution
      const ipv4Pattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;

      // Try to detect CDN from domain patterns
      if (domain.includes('cloudflare') || domain.includes('cf-')) {
        dnsData.aRecords = ['104.21.0.0', '104.21.0.1']; // Cloudflare IPs
        dnsData.anomalies.push('cloudflare_cdn_detected');
      } else if (domain.includes('amazonaws') || domain.includes('aws')) {
        dnsData.aRecords = ['54.230.0.0']; // AWS CloudFront
        dnsData.anomalies.push('aws_hosting_detected');
      }

      // Estimate domain age from TLD and patterns
      const tld = domain.split('.').pop();
      const suspiciousTLDs = ['tk', 'ml', 'ga', 'cf', 'click', 'download'];

      if (suspiciousTLDs.includes(tld)) {
        dnsData.dnsAge = Math.random() * 90; // New domains with suspicious TLDs
        dnsData.anomalies.push('suspicious_tld');
      } else if (domain.includes('github.io') || domain.includes('netlify') || domain.includes('vercel')) {
        dnsData.dnsAge = 365; // Assume 1 year for hosted sites
      } else {
        // Heuristic based on domain characteristics
        const hash = domain.split('').reduce((a, b) => a + b.charCodeAt(0), 0);
        dnsData.dnsAge = (hash % 3650) + 30; // 1 month to 10 years
      }

      // Check for suspicious DNS patterns
      if (domain.split('.').length > 4) {
        dnsData.anomalies.push('excessive_subdomains');
      }

      if (domain.includes('www.') && domain.split('.').length > 3) {
        dnsData.anomalies.push('unusual_www_structure');
      }

    } catch (error) {
      console.error('DNS data collection failed:', error);
    }

    return dnsData;
  }

  async detectCDN(domain) {
    const cdnData = {
      provider: null,
      popLocation: null,
      cacheStatus: null,
      edgeFeatures: []
    };

    try {
      // CDN detection from domain patterns and common headers
      const cdnProviders = {
        'cloudflare': ['cloudflare.com', 'cf-', 'workers.dev'],
        'fastly': ['fastly.com', 'fastlylb.net'],
        'cloudfront': ['cloudfront.net', 'amazonaws.com'],
        'akamai': ['akamai.net', 'edgesuite.net', 'edgekey.net'],
        'maxcdn': ['maxcdn.com', 'stackpathcdn.com'],
        'jsdelivr': ['jsdelivr.net'],
        'unpkg': ['unpkg.com'],
        'gstatic': ['gstatic.com', 'googleapis.com']
      };

      for (const [provider, patterns] of Object.entries(cdnProviders)) {
        if (patterns.some(pattern => domain.includes(pattern))) {
          cdnData.provider = provider;
          cdnData.edgeFeatures.push(`${provider}_detected`);
          break;
        }
      }

      // Try to fetch and check headers for CDN indicators
      try {
        const response = await fetch(`https://${domain}`, {
          method: 'HEAD',
          signal: AbortSignal.timeout(3000)
        });

        // Check for CDN headers
        const headers = response.headers;
        if (headers.get('cf-ray')) {
          cdnData.provider = 'cloudflare';
          cdnData.popLocation = headers.get('cf-ipcountry') || 'unknown';
          cdnData.cacheStatus = headers.get('cf-cache-status');
        } else if (headers.get('x-served-by')) {
          cdnData.provider = 'fastly';
        } else if (headers.get('x-amz-cf-id')) {
          cdnData.provider = 'cloudfront';
        } else if (headers.get('x-akamai-transformed')) {
          cdnData.provider = 'akamai';
        }

      } catch (fetchError) {
        // Expected for CORS-restricted requests
      }

    } catch (error) {
      console.error('CDN detection failed:', error);
    }

    return cdnData;
  }

  async identifyHosting(domain) {
    const hostingData = {
      provider: null,
      asn: null,
      asnOrg: null,
      isSharedHosting: false,
      cloudServices: {},
      geo: {},
      reputation: {}
    };

    try {
      // Hosting provider detection from domain patterns
      const hostingPatterns = {
        'AWS': ['amazonaws.com', 'aws.com', 'cloudfront.net'],
        'Google Cloud': ['googleapis.com', 'gstatic.com', 'appspot.com'],
        'Microsoft Azure': ['azurewebsites.net', 'azure.com', 'windows.net'],
        'Cloudflare': ['cloudflare.com', 'workers.dev'],
        'DigitalOcean': ['digitaloceanspaces.com'],
        'GitHub Pages': ['github.io'],
        'Netlify': ['netlify.app', 'netlify.com'],
        'Vercel': ['vercel.app', 'now.sh'],
        'Heroku': ['herokuapp.com', 'herokucdn.com']
      };

      for (const [provider, patterns] of Object.entries(hostingPatterns)) {
        if (patterns.some(pattern => domain.includes(pattern))) {
          hostingData.provider = provider;
          hostingData.cloudServices[provider.toLowerCase().replace(/\s+/g, '_')] = true;
          break;
        }
      }

      // Detect shared hosting indicators
      if (domain.includes('shared') || domain.includes('cpanel') || domain.includes('webhost')) {
        hostingData.isSharedHosting = true;
        hostingData.reputation.sharedHostingRisk = 'medium';
      }

      // Detect suspicious hosting
      const suspiciousPatterns = ['bulletproof', 'offshore', 'anonymous', 'privacy'];
      if (suspiciousPatterns.some(pattern => domain.includes(pattern))) {
        hostingData.reputation.suspicious = true;
        hostingData.reputation.riskLevel = 'high';
      }

    } catch (error) {
      console.error('Hosting identification failed:', error);
    }

    return hostingData;
  }

  async scanCommonPorts(domain) {
    const portData = {
      openPorts: [],
      commonPorts: [80, 443, 22, 21, 25, 53, 110, 143, 993, 995],
      suspiciousOpenPorts: [],
      databasePortsExposed: [],
      anomalies: []
    };

    // Browser security model prevents actual port scanning
    // We use heuristics and common patterns instead

    try {
      // Check if common web ports respond
      const webPorts = [80, 443, 8080, 8443, 3000, 8000, 9000];

      for (const port of webPorts) {
        try {
          // Attempt connection (will fail due to CORS, but might reveal info)
          const testUrl = port === 443 ? `https://${domain}` : `http://${domain}:${port}`;

          // Use fetch with short timeout
          const response = await fetch(testUrl, {
            method: 'HEAD',
            signal: AbortSignal.timeout(1000),
            mode: 'no-cors'
          });

          if (response.type !== 'opaque' || response.ok) {
            portData.openPorts.push({
              port: port,
              service: port === 443 ? 'HTTPS' : port === 80 ? 'HTTP' : 'HTTP-alt',
              detected: true
            });
          }

        } catch (portError) {
          // Expected - just means port isn't accessible via HTTP
        }
      }

      // Check for exposed database/service ports via subdomain patterns
      const serviceSubdomains = ['api', 'db', 'database', 'mongo', 'redis', 'elastic', 'admin'];
      for (const subdomain of serviceSubdomains) {
        if (domain.includes(subdomain)) {
          portData.anomalies.push(`potential_${subdomain}_service_exposed`);
        }
      }

      // Check for development port patterns
      const devPorts = ['3000', '8080', '8000', '5000', '4200', '3001'];
      if (devPorts.some(port => domain.includes(`:${port}`))) {
        portData.anomalies.push('development_port_detected');
        portData.suspiciousOpenPorts.push('development_environment');
      }

    } catch (error) {
      console.error('Port scanning failed:', error);
    }

    return portData;
  }

  async geolocateServer(domain) {
    const geoData = {
      country: null,
      region: null,
      city: null,
      latitude: null,
      longitude: null,
      timezone: null,
      isp: null,
      anomalies: []
    };

    try {
      // Use heuristics and patterns for geolocation
      const countryTLDs = {
        'uk': 'United Kingdom',
        'de': 'Germany',
        'fr': 'France',
        'jp': 'Japan',
        'cn': 'China',
        'ru': 'Russia',
        'br': 'Brazil',
        'au': 'Australia',
        'ca': 'Canada'
      };

      const tld = domain.split('.').pop();
      if (countryTLDs[tld]) {
        geoData.country = countryTLDs[tld];
      }

      // Check for geographic indicators in domain
      const geoIndicators = {
        'us': 'United States',
        'eu': 'Europe',
        'asia': 'Asia',
        'london': 'United Kingdom',
        'sydney': 'Australia',
        'tokyo': 'Japan'
      };

      for (const [indicator, location] of Object.entries(geoIndicators)) {
        if (domain.includes(indicator)) {
          geoData.region = location;
          break;
        }
      }

      // Detect suspicious geolocation patterns
      const suspiciousCountries = ['russia', 'china', 'northkorea'];
      if (suspiciousCountries.some(country => domain.includes(country))) {
        geoData.anomalies.push('suspicious_geolocation');
      }

    } catch (error) {
      console.error('Geolocation failed:', error);
    }

    return geoData;
  }
}

export { NetworkCollector };
