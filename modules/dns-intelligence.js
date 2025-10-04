// DNS and IP Intelligence Module
// Extracted from background.js - DNS/IP resolution and geolocation analysis

import { ipCacheManager } from './ip-cache.js';
import { detectHomographAttack, detectDGAPattern, calculateStringSimilarity } from './string-utils.js';
import { privacyConsentManager } from './privacy-consent.js';

// CRITICAL FIX P1: IP cache migrated to persistent storage module
const ipCache = ipCacheManager.ipCache;
const ipRequestQueue = ipCacheManager.ipRequestQueue;

/**
 * Resolves IP addresses for a hostname using DNS over HTTPS (DoH)
 *
 * P0-NEW-4: GDPR compliance - requires privacy consent before DNS lookup
 *
 * @param {string} hostname - The hostname to resolve
 * @returns {Promise<Object>} IP information including IPv4/IPv6 addresses and geolocation data
 */
export async function resolveIPAddresses(hostname) {
  const ipInfo = {
    ipv4Addresses: [],
    ipv6Addresses: [],
    geoLocations: [],
    asn: null,
    organization: null,
    country: null,
    city: null,
    isp: null,
    isVPN: false,
    isTor: false,
    isProxy: false,
    threatLevel: 'low',
    consentRequired: false // P0-NEW-4: Track if consent was missing
  };

  // P0-NEW-4: Check privacy consent before DNS lookup (GDPR)
  // Defensive: check if module exists
  if (!privacyConsentManager) {
    console.warn('Hera: Privacy consent module not loaded - skipping DNS lookup');
    ipInfo.consentRequired = true;
    return ipInfo;
  }

  let hasConsent = false;
  try {
    hasConsent = await privacyConsentManager.hasPrivacyConsent();
  } catch (error) {
    console.error('Hera: Privacy consent check failed - skipping DNS lookup:', error);
    ipInfo.consentRequired = true;
    return ipInfo;
  }

  if (!hasConsent) {
    console.log('Hera: Skipping DNS lookup - no privacy consent');
    ipInfo.consentRequired = true;
    return ipInfo;
  }

  try {
    // Use DNS over HTTPS to resolve IP addresses
    const dohEndpoint = `https://cloudflare-dns.com/dns-query?name=${hostname}&type=A`;

    const response = await fetch(dohEndpoint, {
      headers: {
        'Accept': 'application/dns-json'
      }
    });

    if (response.ok) {
      const dnsData = await response.json();

      if (dnsData.Answer) {
        for (const record of dnsData.Answer) {
          if (record.type === 1) { // A record (IPv4)
            const ip = record.data;
            ipInfo.ipv4Addresses.push(ip);

            // Get geolocation for each IP
            const geoData = await getIPGeolocation(ip);
            if (geoData) {
              ipInfo.geoLocations.push({
                ip: ip,
                ...geoData
              });

              // Use first IP's data for main fields
              if (!ipInfo.country) {
                ipInfo.country = geoData.country;
                ipInfo.city = geoData.city;
                ipInfo.asn = geoData.asn;
                ipInfo.organization = geoData.organization;
                ipInfo.isp = geoData.isp;
                ipInfo.isVPN = geoData.isVPN;
                ipInfo.isTor = geoData.isTor;
                ipInfo.isProxy = geoData.isProxy;
                ipInfo.threatLevel = geoData.threatLevel;
              }
            }
          }
        }
      }
    }
  } catch (error) {
    console.log(`DNS resolution failed for ${hostname}:`, error);
  }

  return ipInfo;
}

/**
 * Gets IP geolocation data using ipapi.co API with caching and rate limiting
 *
 * P0-NEW-4: GDPR compliance - requires privacy consent before IP geolocation
 *
 * @param {string} ip - The IP address to look up
 * @returns {Promise<Object|null>} Geolocation data or null if cached/rate-limited
 */
export async function getIPGeolocation(ip) {
  // P0-NEW-4: Check privacy consent before IP geolocation (GDPR)
  // Defensive: check if module exists
  if (!privacyConsentManager) {
    console.warn('Hera: Privacy consent module not loaded - skipping IP geolocation');
    return null;
  }

  let hasConsent = false;
  try {
    hasConsent = await privacyConsentManager.hasPrivacyConsent();
  } catch (error) {
    console.error('Hera: Privacy consent check failed - skipping IP geolocation:', error);
    return null;
  }

  if (!hasConsent) {
    console.log('Hera: Skipping IP geolocation - no privacy consent');
    return null;
  }

  // Check cache first
  if (ipCache.has(ip)) {
    console.log(`Using cached IP data for ${ip}`);
    return ipCache.get(ip);
  }

  // Prevent duplicate requests
  if (ipRequestQueue.has(ip)) {
    console.log(`IP request already in progress for ${ip}`);
    return null;
  }

  // Rate limiting - only allow IP lookups for legitimate security analysis
  if (ipCache.size > 10) {
    console.log(`IP cache limit reached, skipping lookup for ${ip}`);
    return null;
  }

  // Skip IP lookups entirely for known legitimate services to prevent 429 errors
  const knownLegitimateIPs = [
    '160.79.104.10', // Claude.ai
    '151.101.0.176', '151.101.128.176', '151.101.64.176', '151.101.192.176' // Fastly CDN
  ];

  if (knownLegitimateIPs.includes(ip)) {
    console.log(`Skipping IP lookup for known legitimate IP: ${ip}`);
    return null;
  }

  // Skip IP lookups for known legitimate IP ranges (optional optimization)
  // Most IPs will be processed, but we can skip obvious ones

  // CRITICAL FIX P1: Use cache manager method to persist
  ipCacheManager.addToQueue(ip);

  try {
    console.log(`Looking up IP geolocation for ${ip}`);
    const response = await fetch(`https://ipapi.co/${ip}/json/`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' }
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }

    const data = await response.json();

    const geoData = {
      ip: ip,
      country: data.country_name || 'Unknown',
      city: data.city || 'Unknown',
      region: data.region || 'Unknown',
      isp: data.org || 'Unknown ISP',
      asn: data.asn || 'Unknown',
      timezone: data.timezone || 'Unknown',
      isVPN: data.threat?.is_anonymous || false,
      isTor: data.threat?.is_tor || false,
      isProxy: data.threat?.is_proxy || false,
      threatLevel: data.threat?.threat_types?.length > 0 ? 'high' : 'low'
    };

    // Cache the result
    // CRITICAL FIX P1: Use cache manager method to persist
    ipCacheManager.setCacheEntry(ip, geoData);
    console.log(`IP geolocation cached for ${ip}: ${geoData.city}, ${geoData.country}`);

    return geoData;
  } catch (error) {
    console.log(`IP geolocation failed for ${ip}:`, error);
    return null;
  } finally {
    // CRITICAL FIX P1: Use cache manager method to persist
    ipCacheManager.removeFromQueue(ip);
  }
}

/**
 * Gathers comprehensive DNS intelligence for domain analysis with IP resolution
 * @param {string} url - The URL to analyze
 * @param {string} requestId - The request ID to update with intelligence data
 * @param {Map} authRequests - The auth requests Map to update
 * @returns {Promise<void>}
 */
export async function gatherDNSIntelligence(url, requestId, authRequests) {
  try {
    const hostname = new URL(url).hostname;

    // Resolve IP addresses first
    const ipInfo = await resolveIPAddresses(hostname);

    const intelligence = {
      hostname: hostname,
      isNewDomain: false,
      isDGA: false,
      isHomograph: false,
      cdnProvider: null,
      suspiciousPatterns: [],
      whoisAge: null,
      ipAddresses: ipInfo, // Add IP information
      dnsRecords: {
        aRecords: ipInfo.ipv4Addresses,
        aaaaRecords: ipInfo.ipv6Addresses,
        cnameRecords: [],
        mxRecords: [],
        txtRecords: [],
        nsRecords: []
      },
      networkPath: {
        resolverUsed: 'cloudflare-dns.com',
        ttlValues: [],
        responseTime: null,
        isDohUsed: true
      },
      geoLocation: {
        country: ipInfo.country,
        city: ipInfo.city,
        asn: ipInfo.asn,
        organization: ipInfo.organization,
        isp: ipInfo.isp,
        isVPN: ipInfo.isVPN,
        isTor: ipInfo.isTor,
        isProxy: ipInfo.isProxy,
        threatLevel: ipInfo.threatLevel
      }
    };

    // Check for homograph attacks (Unicode lookalikes)
    intelligence.isHomograph = detectHomographAttack(hostname);

    // Check for Domain Generation Algorithm patterns
    intelligence.isDGA = detectDGAPattern(hostname);

    // Check for suspicious TLDs and patterns
    intelligence.suspiciousPatterns = detectSuspiciousDomainPatterns(hostname);

    // Update the stored request with DNS intelligence
    const requestData = authRequests.get(requestId);
    if (requestData) {
      requestData.metadata.dnsIntelligence = intelligence;
      authRequests.set(requestId, requestData);
    }

  } catch (error) {
    console.log('DNS intelligence gathering failed:', error);
  }
}

/**
 * Detects suspicious domain patterns including TLDs, typosquatting, and subdomain abuse
 * @param {string} hostname - The hostname to analyze
 * @returns {Array<string>} Array of detected suspicious patterns
 */
export function detectSuspiciousDomainPatterns(hostname) {
  const patterns = [];

  // Suspicious TLDs
  const suspiciousTLDs = ['.tk', '.ml', '.ga', '.cf', '.pw', '.top', '.click', '.download'];
  if (suspiciousTLDs.some(tld => hostname.endsWith(tld))) {
    patterns.push('suspicious_tld');
  }

  // Typosquatting patterns
  const legitimateDomains = ['google.com', 'microsoft.com', 'github.com', 'facebook.com'];
  legitimateDomains.forEach(legit => {
    if (hostname !== legit && calculateStringSimilarity(hostname, legit) > 0.7) {
      patterns.push('typosquatting_' + legit.replace('.com', ''));
    }
  });

  // Subdomain abuse
  const subdomainCount = hostname.split('.').length - 2;
  if (subdomainCount > 3) {
    patterns.push('excessive_subdomains');
  }

  // URL shortener domains
  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly'];
  if (shorteners.includes(hostname)) {
    patterns.push('url_shortener');
  }

  return patterns;
}
