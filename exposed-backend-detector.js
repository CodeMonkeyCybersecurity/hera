// // Hera - Exposed Backend Detection System
// // Prevents users from submitting data to insecure backends

// // P0-EIGHTH-2 FIX: SSRF Protection Helper
// function isPrivateOrMetadataIP(domain) {
//   const privateIPPatterns = [
//     /^127\./,                    // Loopback
//     /^10\./,                     // Private Class A
//     /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private Class B
//     /^192\.168\./,               // Private Class C
//     /^169\.254\./,               // Link-local
//     /^0\./,                      // Invalid
//     /^169\.254\.169\.254$/,      // AWS metadata
//     /^metadata\.google\.internal$/i, // GCP metadata
//     /^100\.64\./,                // Shared address space (CGNAT)
//     /^\[::1\]$/,                 // IPv6 loopback
//     /^\[fe80:/,                  // IPv6 link-local
//     /^\[fc00:/,                  // IPv6 ULA
//     /^\[fd00:/,                  // IPv6 ULA
//     /^localhost$/i               // localhost hostname
//   ];

//   return privateIPPatterns.some(pattern => pattern.test(domain));
// }

// class ExposedBackendDetector {
//   constructor() {
//     this.detectionResults = new Map();
//     this.criticalFindings = [];
//     this.blockedSubmissions = 0;
//     this.setupDetection();
//   }

//   async scanForExposedBackends(domain) {
//     console.log(` Scanning ${domain} for exposed backends...`);

//     const results = {
//       domain: domain,
//       timestamp: Date.now(),
//       exposed: [],
//       risks: [],
//       shouldBlockDataEntry: false,
//       riskScore: 0
//     };

//     // Parallel scanning for speed
//     const scanPromises = [
//       this.checkMongoDBExposure(domain),
//       this.checkS3Exposure(domain),
//       this.checkElasticsearchExposure(domain),
//       this.checkFirebaseExposure(domain),
//       this.checkRedisExposure(domain),
//       this.checkGraphQLExposure(domain),
//       this.checkGitExposure(domain),
//       this.checkEnvFileExposure(domain),
//       this.checkDatabaseDumps(domain),
//       this.checkAPIInfoDisclosure(domain),
//       this.checkDockerExposure(domain),
//       this.checkKubernetesExposure(domain),
//       this.checkCouchDBExposure(domain),
//       this.checkCassandraExposure(domain)
//     ];

//     const scanResults = await Promise.allSettled(scanPromises);

//     // Process results
//     for (const result of scanResults) {
//       if (result.status === 'fulfilled' && result.value?.exposed) {
//         results.exposed.push(result.value);
//         results.riskScore += result.value.riskPoints || 0;

//         if (result.value.severity === 'critical') {
//           results.shouldBlockDataEntry = true;
//           this.criticalFindings.push({
//             domain: domain,
//             finding: result.value,
//             timestamp: Date.now()
//           });
//         }
//       }
//     }

//     // Store results
//     this.detectionResults.set(domain, results);

//     return results;
//   }

//   async checkMongoDBExposure(domain) {
//     // P0-EIGHTH-2 FIX: SSRF Protection - Block private IPs and metadata endpoints
//     if (isPrivateOrMetadataIP(domain)) {
//       console.warn(`Hera: Blocked MongoDB scan on private/metadata IP: ${domain}`);
//       return {
//         exposed: false,
//         blocked: true,
//         reason: 'SSRF Protection: Scanning private IP addresses is not allowed',
//         severity: 'blocked'
//       };
//     }

//     const endpoints = [
//       `http://${domain}:27017/`,
//       `http://${domain}:27018/`,
//       `http://${domain}:28017/`, // MongoDB HTTP interface
//       `https://${domain}/mongodb/`,
//       `https://mongo.${domain}/`,
//       `https://db.${domain}/`,
//       `https://mongodb.${domain}/`
//     ];

//     for (const endpoint of endpoints) {
//       try {
//         // P0-EIGHTH-2 FIX: Validate EACH endpoint URL before fetching
//         const endpointDomain = new URL(endpoint).hostname;

//         if (isPrivateOrMetadataIP(endpointDomain)) {
//           console.warn(`Hera: Blocked SSRF to private endpoint: ${endpoint}`);
//           continue; // Skip this endpoint
//         }

//         // Check for MongoDB REST API
//         const response = await this.fetchWithTimeout(`${endpoint}admin/listDatabases?text=1`, 3000);

//         if (response && response.ok) {
//           const text = await response.text();
//           if (text.includes('databases') || text.includes('totalSize') || text.includes('admin')) {
//             const databases = this.parseMongoDBResponse(text);

//             return {
//               exposed: true,
//               type: 'mongodb',
//               severity: 'critical',
//               riskPoints: 100,
//               endpoint: endpoint,
//               details: `MongoDB instance exposed without authentication! Found ${databases.length} databases.`,
//               databases: databases,
//               recommendation: ' CRITICAL: Do not enter any personal data - database is completely exposed!',
//               bugBountyValue: '$5,000 - $15,000'
//             };
//           }
//         }

//         // Check for MongoDB web interface
//         const webResponse = await this.fetchWithTimeout(`http://${domain}:28017/`, 3000);
//         if (webResponse && webResponse.ok) {
//           const text = await webResponse.text();
//           if (text.includes('MongoDB') || text.includes('mongo') || text.includes('db version')) {
//             return {
//               exposed: true,
//               type: 'mongodb_web',
//               severity: 'critical',
//               riskPoints: 90,
//               endpoint: `http://${domain}:28017/`,
//               details: 'MongoDB HTTP interface exposed publicly!',
//               recommendation: ' Database admin interface accessible to anyone!',
//               bugBountyValue: '$3,000 - $10,000'
//             };
//           }
//         }

//       } catch (error) {
//         continue;
//       }
//     }

//     return { exposed: false };
//   }

//   async checkS3Exposure(domain) {
//     // P0-EIGHTH-2 FIX: SSRF Protection
//     if (isPrivateOrMetadataIP(domain)) {
//       console.warn(`Hera: Blocked S3 scan on private/metadata IP: ${domain}`);
//       return { exposed: false, blocked: true, reason: 'SSRF Protection', severity: 'blocked' };
//     }

//     const bucketPatterns = [
//       `https://s3.amazonaws.com/${domain}`,
//       `https://${domain}.s3.amazonaws.com`,
//       `https://s3-${domain}.amazonaws.com`,
//       `https://${domain}-assets.s3.amazonaws.com`,
//       `https://${domain}-backup.s3.amazonaws.com`,
//       `https://${domain}-data.s3.amazonaws.com`,
//       `https://${domain}-uploads.s3.amazonaws.com`,
//       `https://${domain.replace(/\./g, '-')}.s3.amazonaws.com`
//     ];

//     for (const bucketUrl of bucketPatterns) {
//       try {
//         const response = await this.fetchWithTimeout(bucketUrl, 5000);

//         if (response && response.ok) {
//           const text = await response.text();

//           // Check if bucket listing is enabled
//           if (text.includes('<ListBucketResult') || text.includes('<Contents>')) {
//             const files = this.parseS3Listing(text);
//             const sensitiveFiles = files.filter(f =>
//               f.includes('.sql') || f.includes('.db') || f.includes('.bak') ||
//               f.includes('backup') || f.includes('dump') || f.includes('.env')
//             );

//             return {
//               exposed: true,
//               type: 's3_bucket',
//               severity: sensitiveFiles.length > 0 ? 'critical' : 'high',
//               riskPoints: sensitiveFiles.length > 0 ? 95 : 70,
//               endpoint: bucketUrl,
//               details: `S3 bucket publicly readable with ${files.length} files exposed`,
//               files: files.slice(0, 20), // Show first 20 files
//               sensitiveFiles: sensitiveFiles,
//               recommendation: sensitiveFiles.length > 0 ?
//                 ' CRITICAL: Sensitive files exposed in S3 bucket!' :
//                 ' S3 bucket contents publicly visible',
//               bugBountyValue: sensitiveFiles.length > 0 ? '$2,000 - $8,000' : '$500 - $2,000'
//             };
//           }

//           // Check for directory listing
//           if (text.includes('Index of') || text.includes('<title>Index of')) {
//             return {
//               exposed: true,
//               type: 's3_directory_listing',
//               severity: 'high',
//               riskPoints: 60,
//               endpoint: bucketUrl,
//               details: 'S3 bucket has directory listing enabled',
//               recommendation: ' Bucket contents are publicly browsable'
//             };
//           }
//         }

//       } catch (error) {
//         continue;
//       }
//     }

//     return { exposed: false };
//   }

//   async checkElasticsearchExposure(domain) {
//     // P0-EIGHTH-2 FIX: SSRF Protection
//     if (isPrivateOrMetadataIP(domain)) {
//       console.warn(`Hera: Blocked Elasticsearch scan on private/metadata IP: ${domain}`);
//       return { exposed: false, blocked: true, reason: 'SSRF Protection', severity: 'blocked' };
//     }

//     const endpoints = [
//       `http://${domain}:9200/`,
//       `https://${domain}:9200/`,
//       `http://${domain}:9200/_cat/indices`,
//       `https://${domain}/elasticsearch/`,
//       `https://es.${domain}/`,
//       `https://elastic.${domain}/`
//     ];

//     for (const endpoint of endpoints) {
//       try {
//         const response = await this.fetchWithTimeout(endpoint, 3000);

//         if (response && response.ok) {
//           const text = await response.text();

//           // Check for Elasticsearch response
//           if (text.includes('elasticsearch') || text.includes('lucene_version') ||
//               text.includes('"cluster_name"')) {

//             // Try to get indices
//             const indicesResponse = await this.fetchWithTimeout(
//               endpoint.replace(/\/$/, '') + '/_cat/indices?v', 3000
//             );

//             let indices = [];
//             if (indicesResponse && indicesResponse.ok) {
//               const indicesText = await indicesResponse.text();
//               indices = this.parseElasticsearchIndices(indicesText);
//             }

//             return {
//               exposed: true,
//               type: 'elasticsearch',
//               severity: 'critical',
//               riskPoints: 95,
//               endpoint: endpoint,
//               details: `Elasticsearch cluster exposed without authentication! Found ${indices.length} indices.`,
//               indices: indices,
//               recommendation: ' CRITICAL: Search database completely exposed - all data readable!',
//               bugBountyValue: '$3,000 - $12,000'
//             };
//           }
//         }

//       } catch (error) {
//         continue;
//       }
//     }

//     return { exposed: false };
//   }

//   async checkFirebaseExposure(domain) {
//     // P0-EIGHTH-2 FIX: SSRF Protection
//     if (isPrivateOrMetadataIP(domain)) {
//       console.warn(`Hera: Blocked Firebase scan on private/metadata IP: ${domain}`);
//       return { exposed: false, blocked: true, reason: 'SSRF Protection', severity: 'blocked' };
//     }

//     const firebasePatterns = [
//       `https://${domain}.firebaseio.com/.json`,
//       `https://${domain}-default-rtdb.firebaseio.com/.json`,
//       `https://${domain}-default-rtdb.asia-southeast1.firebasedatabase.app/.json`,
//       `https://${domain}-default-rtdb.europe-west1.firebasedatabase.app/.json`
//     ];

//     for (const url of firebasePatterns) {
//       try {
//         const response = await this.fetchWithTimeout(url, 5000);

//         if (response && response.ok) {
//           const text = await response.text();

//           // Check if we can read Firebase data
//           if (text && text !== 'null' && text !== '{}') {
//             let data;
//             try {
//               data = JSON.parse(text);
//             } catch (e) {
//               data = text;
//             }

//             // Check for sensitive data patterns
//             const sensitiveKeys = this.findSensitiveKeys(data);

//             return {
//               exposed: true,
//               type: 'firebase',
//               severity: sensitiveKeys.length > 0 ? 'critical' : 'high',
//               riskPoints: sensitiveKeys.length > 0 ? 90 : 70,
//               endpoint: url,
//               details: `Firebase Realtime Database publicly readable`,
//               sensitiveData: sensitiveKeys,
//               dataSize: JSON.stringify(data).length,
//               recommendation: sensitiveKeys.length > 0 ?
//                 ' CRITICAL: Firebase contains sensitive user data!' :
//                 ' Firebase database is publicly readable',
//               bugBountyValue: sensitiveKeys.length > 0 ? '$2,000 - $8,000' : '$500 - $2,000'
//             };
//           }
//         }

//       } catch (error) {
//         continue;
//       }
//     }

//     return { exposed: false };
//   }

//   async checkRedisExposure(domain) {
//     // P0-EIGHTH-2 FIX: SSRF Protection
//     if (isPrivateOrMetadataIP(domain)) {
//       console.warn(`Hera: Blocked Redis scan on private/metadata IP: ${domain}`);
//       return { exposed: false, blocked: true, reason: 'SSRF Protection', severity: 'blocked' };
//     }

//     // Redis typically runs on port 6379
//     // We can't directly connect from browser, but check for Redis web interfaces
//     const endpoints = [
//       `http://${domain}:6379/`,
//       `https://${domain}/redis/`,
//       `https://redis.${domain}/`,
//       `http://${domain}:8001/`, // Redis Commander
//       `http://${domain}:9987/`  // RedisInsight
//     ];

//     for (const endpoint of endpoints) {
//       try {
//         const response = await this.fetchWithTimeout(endpoint, 3000);

//         if (response && response.ok) {
//           const text = await response.text();

//           if (text.includes('Redis') || text.includes('redis-server') ||
//               text.includes('RedisCommander') || text.includes('RedisInsight')) {

//             return {
//               exposed: true,
//               type: 'redis',
//               severity: 'critical',
//               riskPoints: 85,
//               endpoint: endpoint,
//               details: 'Redis web interface exposed without authentication',
//               recommendation: ' CRITICAL: In-memory database interface exposed!',
//               bugBountyValue: '$2,000 - $7,000'
//             };
//           }
//         }

//       } catch (error) {
//         continue;
//       }
//     }

//     return { exposed: false };
//   }

//   async checkGraphQLExposure(domain) {
//     // P0-EIGHTH-2 FIX: SSRF Protection
//     if (isPrivateOrMetadataIP(domain)) {
//       console.warn(`Hera: Blocked GraphQL scan on private/metadata IP: ${domain}`);
//       return { exposed: false, blocked: true, reason: 'SSRF Protection', severity: 'blocked' };
//     }

//     const endpoints = [
//       `https://${domain}/graphql`,
//       `https://${domain}/graphiql`,
//       `https://${domain}/api/graphql`,
//       `https://${domain}/v1/graphql`,
//       `https://api.${domain}/graphql`
//     ];

//     for (const endpoint of endpoints) {
//       try {
//         // Check for introspection query
//         const introspectionQuery = {
//           query: `
//             query IntrospectionQuery {
//               __schema {
//                 types {
//                   name
//                   fields {
//                     name
//                     type {
//                       name
//                     }
//                   }
//                 }
//               }
//             }
//           `
//         };

//         const response = await this.fetchWithTimeout(endpoint, {
//           method: 'POST',
//           headers: { 'Content-Type': 'application/json' },
//           body: JSON.stringify(introspectionQuery)
//         }, 5000);

//         if (response && response.ok) {
//           const data = await response.json();

//           if (data.data && data.data.__schema) {
//             const schema = data.data.__schema;
//             const sensitiveTypes = this.findSensitiveGraphQLTypes(schema.types);

//             return {
//               exposed: true,
//               type: 'graphql_introspection',
//               severity: sensitiveTypes.length > 0 ? 'critical' : 'high',
//               riskPoints: sensitiveTypes.length > 0 ? 80 : 60,
//               endpoint: endpoint,
//               details: `GraphQL introspection enabled - schema exposed`,
//               schema: schema.types.slice(0, 10), // Show first 10 types
//               sensitiveTypes: sensitiveTypes,
//               recommendation: sensitiveTypes.length > 0 ?
//                 ' CRITICAL: GraphQL exposes sensitive data types!' :
//                 ' GraphQL schema publicly introspectable',
//               bugBountyValue: sensitiveTypes.length > 0 ? '$1,500 - $5,000' : '$300 - $1,500'
//             };
//           }
//         }

//         // Also check for GraphiQL interface
//         const uiResponse = await this.fetchWithTimeout(endpoint.replace('graphql', 'graphiql'), 3000);
//         if (uiResponse && uiResponse.ok) {
//           const text = await uiResponse.text();
//           if (text.includes('GraphiQL') || text.includes('graphiql')) {
//             return {
//               exposed: true,
//               type: 'graphiql_interface',
//               severity: 'high',
//               riskPoints: 70,
//               endpoint: endpoint.replace('graphql', 'graphiql'),
//               details: 'GraphiQL development interface exposed in production',
//               recommendation: ' Development GraphQL interface publicly accessible'
//             };
//           }
//         }

//       } catch (error) {
//         continue;
//       }
//     }

//     return { exposed: false };
//   }

//   async checkGitExposure(domain) {
//     // P0-EIGHTH-2 FIX: SSRF Protection
//     if (isPrivateOrMetadataIP(domain)) {
//       console.warn(`Hera: Blocked Git scan on private/metadata IP: ${domain}`);
//       return { exposed: false, blocked: true, reason: 'SSRF Protection', severity: 'blocked' };
//     }

//     const gitPaths = [
//       '/.git/config',
//       '/.git/HEAD',
//       '/.git/logs/HEAD',
//       '/.git/index',
//       '/.git/objects/',
//       '/.gitignore'
//     ];

//     for (const path of gitPaths) {
//       try {
//         const response = await this.fetchWithTimeout(`https://${domain}${path}`, 3000);

//         if (response && response.ok) {
//           const text = await response.text();

//           if (text.includes('[core]') || text.includes('ref:') ||
//               text.includes('repository') || text.includes('*.log')) {

//             return {
//               exposed: true,
//               type: 'git_exposure',
//               severity: 'critical',
//               riskPoints: 95,
//               endpoint: `https://${domain}${path}`,
//               details: 'Git repository exposed - source code and secrets accessible!',
//               recommendation: ' CRITICAL: Entire source code history exposed!',
//               bugBountyValue: '$2,000 - $10,000'
//             };
//           }
//         }

//       } catch (error) {
//         continue;
//       }
//     }

//     return { exposed: false };
//   }

//   async checkEnvFileExposure(domain) {
//     // P0-EIGHTH-2 FIX: SSRF Protection
//     if (isPrivateOrMetadataIP(domain)) {
//       console.warn(`Hera: Blocked ENV scan on private/metadata IP: ${domain}`);
//       return { exposed: false, blocked: true, reason: 'SSRF Protection', severity: 'blocked' };
//     }

//     const envPaths = [
//       '/.env',
//       '/.env.local',
//       '/.env.production',
//       '/.env.development',
//       '/config/.env',
//       '/app/.env',
//       '/.environment',
//       '/environment.js'
//     ];

//     for (const path of envPaths) {
//       try {
//         const response = await this.fetchWithTimeout(`https://${domain}${path}`, 3000);

//         if (response && response.ok) {
//           const text = await response.text();

//           // Check for environment variable patterns
//           if (text.includes('API_KEY=') || text.includes('SECRET=') ||
//               text.includes('PASSWORD=') || text.includes('DB_') ||
//               text.includes('AWS_') || text.includes('STRIPE_')) {

//             const secrets = this.extractSecrets(text);

//             return {
//               exposed: true,
//               type: 'env_file',
//               severity: 'critical',
//               riskPoints: 100,
//               endpoint: `https://${domain}${path}`,
//               details: `Environment file exposed with ${secrets.length} secrets!`,
//               secrets: secrets.map(s => s.replace(/=.*/, '=***')), // Hide values
//               recommendation: ' CRITICAL: API keys and secrets exposed!',
//               bugBountyValue: '$3,000 - $15,000'
//             };
//           }
//         }

//       } catch (error) {
//         continue;
//       }
//     }

//     return { exposed: false };
//   }

//   // Form submission interceptor
//   setupFormInterceptor() {
//     document.addEventListener('submit', async (e) => {
//       const form = e.target;
//       const domain = window.location.hostname;

//       // Check if we have scan results for this domain
//       let scanResults = this.detectionResults.get(domain);

//       if (!scanResults) {
//         // Quick scan before form submission
//         scanResults = await this.scanForExposedBackends(domain);
//       }

//       if (scanResults.shouldBlockDataEntry) {
//         e.preventDefault();
//         this.showCriticalWarning(form, scanResults);
//         return false;
//       }

//       // Show warning for high-risk findings
//       if (scanResults.riskScore > 50) {
//         const userConsent = await this.showRiskWarning(form, scanResults);
//         if (!userConsent) {
//           e.preventDefault();
//           return false;
//         }
//       }
//     });
//   }

//   showCriticalWarning(form, scanResults) {
//     // Create blocking overlay
//     const overlay = document.createElement('div');
//     overlay.className = 'hera-critical-backend-warning';
//     overlay.style.cssText = `
//       position: fixed;
//       top: 0;
//       left: 0;
//       right: 0;
//       bottom: 0;
//       background: rgba(0, 0, 0, 0.95);
//       z-index: 999999;
//       display: flex;
//       align-items: center;
//       justify-content: center;
//       font-family: -apple-system, sans-serif;
//     `;

//     const criticalFindings = scanResults.exposed.filter(e => e.severity === 'critical');

//     overlay.innerHTML = `
//       <div style="
//         background: linear-gradient(135deg, #ff4444, #cc0000);
//         color: white;
//         padding: 40px;
//         border-radius: 12px;
//         max-width: 600px;
//         text-align: center;
//         box-shadow: 0 20px 40px rgba(0,0,0,0.5);
//       ">
//         <div style="font-size: 64px; margin-bottom: 20px;"></div>
//         <h1 style="margin: 0 0 20px 0; font-size: 28px;">
//           CRITICAL SECURITY RISK DETECTED
//         </h1>
//         <div style="font-size: 18px; margin-bottom: 30px; line-height: 1.6;">
//           This website has <strong>${criticalFindings.length} critical security vulnerabilities</strong>
//           that could expose your data:
//         </div>

//         <div style="text-align: left; margin: 20px 0; background: rgba(255,255,255,0.1); padding: 20px; border-radius: 8px;">
//           ${criticalFindings.map(finding => `
//             <div style="margin-bottom: 15px;">
//               <strong>• ${finding.type.toUpperCase()}:</strong> ${finding.details}
//             </div>
//           `).join('')}
//         </div>

//         <div style="font-size: 16px; margin: 30px 0; padding: 20px; background: rgba(255,255,255,0.1); border-radius: 8px;">
//           <strong> DO NOT ENTER PERSONAL INFORMATION</strong><br>
//           Your data could be stolen or exposed to the public.
//         </div>

//         <div style="display: flex; gap: 15px; justify-content: center; margin-top: 30px;">
//           <button onclick="this.parentElement.parentElement.parentElement.remove()" style="
//             background: white;
//             color: #cc0000;
//             border: none;
//             padding: 12px 24px;
//             border-radius: 6px;
//             font-weight: bold;
//             font-size: 16px;
//             cursor: pointer;
//           ">
//             Leave This Site
//           </button>
//           <button onclick="window.hera.showTechnicalDetails()" style="
//             background: transparent;
//             color: white;
//             border: 2px solid white;
//             padding: 12px 24px;
//             border-radius: 6px;
//             font-weight: bold;
//             font-size: 16px;
//             cursor: pointer;
//           ">
//             Technical Details
//           </button>
//         </div>
//       </div>
//     `;

//     document.body.appendChild(overlay);

//     // Track blocked submission
//     this.blockedSubmissions++;

//     // Report to backend for threat intelligence
//     this.reportCriticalFinding(scanResults);
//   }

//   // Helper methods
//   async fetchWithTimeout(url, options = {}, timeout = 5000) {
//     const controller = new AbortController();
//     const timeoutId = setTimeout(() => controller.abort(), timeout);

//     try {
//       const response = await fetch(url, {
//         ...options,
//         signal: controller.signal
//       });
//       clearTimeout(timeoutId);
//       return response;
//     } catch (error) {
//       clearTimeout(timeoutId);
//       return null;
//     }
//   }

//   parseMongoDBResponse(text) {
//     const databases = [];
//     try {
//       if (text.includes('databases')) {
//         const lines = text.split('\n');
//         for (const line of lines) {
//           if (line.includes('name') && line.includes('sizeOnDisk')) {
//             const match = line.match(/"name"\s*:\s*"([^"]+)"/);
//             if (match) databases.push(match[1]);
//           }
//         }
//       }
//     } catch (e) {
//       // Fallback parsing
//     }
//     return databases;
//   }

//   parseS3Listing(xml) {
//     const files = [];
//     const keyMatches = xml.match(/<Key>([^<]+)<\/Key>/g);
//     if (keyMatches) {
//       for (const match of keyMatches) {
//         const key = match.replace(/<\/?Key>/g, '');
//         files.push(key);
//       }
//     }
//     return files;
//   }

//   findSensitiveKeys(data, path = '') {
//     const sensitive = [];
//     const sensitivePatterns = [
//       /password/i, /secret/i, /token/i, /key/i, /email/i,
//       /phone/i, /ssn/i, /credit/i, /card/i, /address/i
//     ];

//     if (typeof data === 'object' && data !== null) {
//       for (const [key, value] of Object.entries(data)) {
//         const currentPath = path ? `${path}.${key}` : key;

//         if (sensitivePatterns.some(pattern => pattern.test(key))) {
//           sensitive.push({ key: currentPath, type: 'sensitive_key' });
//         }

//         if (typeof value === 'object') {
//           sensitive.push(...this.findSensitiveKeys(value, currentPath));
//         }
//       }
//     }

//     return sensitive;
//   }

//   extractSecrets(envContent) {
//     const secrets = [];
//     const lines = envContent.split('\n');

//     for (const line of lines) {
//       if (line.includes('=') && !line.startsWith('#')) {
//         const [key] = line.split('=');
//         if (key && (
//           key.includes('KEY') || key.includes('SECRET') ||
//           key.includes('PASSWORD') || key.includes('TOKEN')
//         )) {
//           secrets.push(line);
//         }
//       }
//     }

//     return secrets;
//   }

//   // Initialize the detector
//   setupDetection() {
//     // Set up form interceptor
//     if (document.readyState === 'loading') {
//       document.addEventListener('DOMContentLoaded', () => this.setupFormInterceptor());
//     } else {
//       this.setupFormInterceptor();
//     }

//     // Scan current domain on page load
//     this.scanForExposedBackends(window.location.hostname);
//   }
// }

// // Initialize the detector
// window.hera = window.hera || {};
// window.hera.backendDetector = new ExposedBackendDetector();
