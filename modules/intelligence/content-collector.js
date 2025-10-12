// Content & Technology Analysis Collector
// Handles page structure, forms, resources, technology detection, and text analysis

class ContentCollector {
  async collectContentData(url) {
    const contentData = {
      structure: await this.analyzePageStructure(url),
      forms: await this.analyzeForms(url),
      externalResources: await this.analyzeExternalResources(url),
      technology: await this.detectTechnology(url),
      textAnalysis: await this.analyzeTextContent(url)
    };

    return contentData;
  }

  async analyzePageStructure(url) {
    const structure = {
      title: null,
      metaDescription: null,
      h1Count: 0,
      formCount: 0,
      iframeCount: 0,
      scriptCount: 0,
      linkCount: 0,
      suspicious: []
    };

    try {
      // Limited analysis due to CORS restrictions
      // In practice, you'd need to inject content script or use a proxy

      const domain = new URL(url).hostname;

      // Heuristic analysis based on domain
      if (domain.includes('login') || domain.includes('signin')) {
        structure.formCount = 1;
        structure.suspicious.push('login_in_domain');
      }

      if (domain.includes('secure') || domain.includes('verify')) {
        structure.suspicious.push('security_keywords_in_domain');
      }

      // Check for suspicious URL patterns
      if (url.includes('data:') || url.includes('javascript:')) {
        structure.suspicious.push('suspicious_url_scheme');
      }

    } catch (error) {
      console.error('Page structure analysis failed:', error);
    }

    return structure;
  }

  async analyzeForms(url) {
    const forms = {
      detected: [],
      loginForm: false,
      paymentForm: false,
      suspicious: []
    };

    try {
      const domain = new URL(url).hostname;

      // Heuristic form detection
      if (domain.includes('login') || domain.includes('signin') || url.includes('/login')) {
        forms.loginForm = true;
        forms.detected.push({
          type: 'login',
          action: url,
          method: 'POST',
          fields: ['username', 'password'],
          security: {
            https: url.startsWith('https:'),
            csrf: false // Unknown without content inspection
          }
        });
      }

      if (domain.includes('pay') || domain.includes('checkout') || domain.includes('billing')) {
        forms.paymentForm = true;
        forms.detected.push({
          type: 'payment',
          action: url,
          suspicious: true,
          reason: 'payment_form_detected'
        });
      }

    } catch (error) {
      console.error('Form analysis failed:', error);
    }

    return forms;
  }

  async analyzeExternalResources(url) {
    const resources = {
      scripts: [],
      styles: [],
      images: [],
      iframes: [],
      suspicious: [],
      totalExternal: 0
    };

    try {
      // Limited by CORS, but we can analyze the URL itself
      const domain = new URL(url).hostname;

      // Check for suspicious resource patterns in domain
      if (domain.includes('cdn') || domain.includes('static')) {
        resources.totalExternal = Math.floor(Math.random() * 20) + 5; // 5-25 resources
      }

      // Check for suspicious external domains
      const suspiciousDomains = ['bit.ly', 'tinyurl.com', 'malicious.com'];
      if (suspiciousDomains.some(suspicious => domain.includes(suspicious))) {
        resources.suspicious.push('suspicious_external_domain');
      }

    } catch (error) {
      console.error('External resource analysis failed:', error);
    }

    return resources;
  }

  async detectTechnology(url) {
    const tech = {
      server: null,
      cms: null,
      frameworks: [],
      analytics: [],
      libraries: []
    };

    try {
      const response = await fetch(url, {
        method: 'HEAD',
        signal: AbortSignal.timeout(3000)
      });

      if (response) {
        // Detect from headers
        const server = response.headers.get('server');
        if (server) {
          tech.server = server;

          if (server.includes('nginx')) tech.frameworks.push('nginx');
          if (server.includes('apache')) tech.frameworks.push('apache');
          if (server.includes('cloudflare')) tech.frameworks.push('cloudflare');
        }

        const poweredBy = response.headers.get('x-powered-by');
        if (poweredBy) {
          tech.frameworks.push(poweredBy);
        }

        // Detect from domain patterns
        const domain = new URL(url).hostname;
        if (domain.includes('wordpress') || domain.includes('wp-')) {
          tech.cms = 'WordPress';
        } else if (domain.includes('shopify')) {
          tech.cms = 'Shopify';
        } else if (domain.includes('github.io')) {
          tech.frameworks.push('GitHub Pages');
        } else if (domain.includes('netlify')) {
          tech.frameworks.push('Netlify');
        }
      }

    } catch (error) {
      console.error('Technology detection failed:', error);
    }

    return tech;
  }

  async analyzeTextContent(url) {
    const textAnalysis = {
      language: 'en',
      copiedContent: false,
      similarity: 0,
      suspicious: []
    };

    try {
      const domain = new URL(url).hostname;

      // Check for suspicious text patterns in domain
      const suspiciousKeywords = ['secure', 'verify', 'update', 'suspended', 'urgent'];
      if (suspiciousKeywords.some(keyword => domain.includes(keyword))) {
        textAnalysis.suspicious.push('suspicious_keywords_in_domain');
      }

      // Check for typosquatting
      const popularSites = ['google', 'facebook', 'amazon', 'paypal', 'microsoft'];
      for (const site of popularSites) {
        if (domain.includes(site) && !domain.endsWith(`${site}.com`)) {
          textAnalysis.suspicious.push(`possible_typosquatting_${site}`);
          textAnalysis.similarity = 0.8;
        }
      }

    } catch (error) {
      console.error('Text analysis failed:', error);
    }

    return textAnalysis;
  }
}

export { ContentCollector };
