import * as tls from 'tls';
import * as net from 'net';
import * as dns from 'dns/promises';
import type { CheckResult, AnalysisResponse, DomainInfo } from './types';

// ============================================================
// Constants
// ============================================================
const SUSPICIOUS_KEYWORDS = [
  'login', 'verify', 'secure', 'update', 'bank', 'paypal', 'amazon',
  'account', 'password', 'confirm', 'suspend', 'free', 'winner',
  'prize', 'crypto', 'wallet', 'reset',
];

const RISKY_TLDS = ['.xyz', '.top', '.click', '.loan', '.tk', '.ml', '.cf', '.ga', '.pw', '.gq'];

const BRAND_NAMES = [
  'google', 'microsoft', 'apple', 'amazon', 'paypal',
  'facebook', 'netflix', 'instagram', 'twitter', 'youtube',
];

// ============================================================
// Utility: Levenshtein similarity ratio
// ============================================================
function similarity(a: string, b: string): number {
  const lenA = a.length;
  const lenB = b.length;
  const matrix: number[][] = Array.from({ length: lenA + 1 }, (_, i) =>
    Array.from({ length: lenB + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= lenA; i++) {
    for (let j = 1; j <= lenB; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost,
      );
    }
  }
  const maxLen = Math.max(lenA, lenB);
  return maxLen === 0 ? 1 : 1 - matrix[lenA][lenB] / maxLen;
}

// ============================================================
// URL Validation
// ============================================================
export function validateUrl(rawUrl: string): { valid: boolean; formatted: string; error?: string } {
  let url = rawUrl.trim();
  if (!url) return { valid: false, formatted: '', error: 'URL cannot be empty.' };

  if (!/^https?:\/\//i.test(url)) {
    url = 'http://' + url;
  }

  try {
    const parsed = new URL(url);
    const host = parsed.hostname;

    // Allow IP addresses
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
      return { valid: true, formatted: url };
    }

    // Must have at least one dot
    if (!host.includes('.')) {
      return { valid: false, formatted: url, error: 'Invalid domain name.' };
    }

    return { valid: true, formatted: url };
  } catch {
    return { valid: false, formatted: url, error: 'Invalid URL format.' };
  }
}

// ============================================================
// Static Checks
// ============================================================
function checkHttps(parsed: URL): CheckResult {
  const is = parsed.protocol === 'https:';
  return {
    name: 'HTTPS Protocol',
    passed: is,
    details: is ? 'Site uses HTTPS encryption' : 'Site uses insecure HTTP',
    scoreImpact: is ? 20 : 0,
  };
}

function checkUrlLength(url: string): CheckResult {
  const len = url.length;
  if (len < 75) return { name: 'URL Length', passed: true, details: `URL length (${len}) is normal`, scoreImpact: 10 };
  if (len <= 120) return { name: 'URL Length', passed: 'warning', details: `URL length (${len}) is moderately long`, scoreImpact: 5 };
  return { name: 'URL Length', passed: false, details: `URL length (${len}) is suspiciously long`, scoreImpact: 0 };
}

function checkSuspiciousKeywords(url: string): CheckResult {
  const lower = url.toLowerCase();
  const found = SUSPICIOUS_KEYWORDS.filter(kw => lower.includes(kw));
  if (found.length === 0) return { name: 'Suspicious Keywords', passed: true, details: 'No suspicious keywords detected', scoreImpact: 10 };
  return { name: 'Suspicious Keywords', passed: false, details: `Found suspicious keywords: ${found.join(', ')}`, scoreImpact: 0 };
}

function checkHyphenCount(domain: string): CheckResult {
  const count = (domain.match(/-/g) || []).length;
  if (count <= 2) return { name: 'Hyphen Count', passed: true, details: `Domain has ${count} hyphen(s) — normal`, scoreImpact: 0 };
  return { name: 'Hyphen Count', passed: false, details: `Domain has ${count} hyphens — suspicious`, scoreImpact: -5 };
}

function checkIpAsDomain(domain: string): CheckResult {
  const isIp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain);
  if (!isIp) return { name: 'IP as Domain', passed: true, details: 'Domain is not an IP address', scoreImpact: 5 };
  return { name: 'IP as Domain', passed: false, details: `IP address used as domain: ${domain}`, scoreImpact: -15 };
}

function checkSubdomainCount(domain: string): CheckResult {
  const parts = domain.split('.');
  const count = Math.max(0, parts.length - 2);
  if (count <= 3) return { name: 'Subdomain Count', passed: true, details: `${count} subdomain(s) — normal`, scoreImpact: 0 };
  return { name: 'Subdomain Count', passed: false, details: `${count} subdomains — suspicious`, scoreImpact: -5 };
}

function checkRiskyTld(domain: string): CheckResult {
  const found = RISKY_TLDS.find(tld => domain.endsWith(tld));
  if (!found) return { name: 'Risky TLD', passed: true, details: 'TLD is not in risky list', scoreImpact: 5 };
  return { name: 'Risky TLD', passed: false, details: `Domain uses risky TLD: ${found}`, scoreImpact: 0 };
}

function checkTyposquatting(domain: string): CheckResult {
  const base = domain.split('.')[0].toLowerCase();
  const matches: string[] = [];
  for (const brand of BRAND_NAMES) {
    if (base === brand) continue;
    const ratio = similarity(base, brand);
    if (ratio >= 0.75) matches.push(`${brand} (${Math.round(ratio * 100)}%)`);
  }
  if (matches.length === 0) return { name: 'Typosquatting Check', passed: true, details: 'No typosquatting detected', scoreImpact: 5 };
  return { name: 'Typosquatting Check', passed: false, details: `Possible typosquatting of: ${matches.join(', ')}`, scoreImpact: -10 };
}

function checkPunycode(domain: string): CheckResult {
  if (domain.includes('xn--')) return { name: 'Punycode / Homograph', passed: false, details: 'Punycode (xn--) detected — possible homograph attack', scoreImpact: -10 };
  return { name: 'Punycode / Homograph', passed: true, details: 'No punycode detected', scoreImpact: 0 };
}

// ============================================================
// Real-Time Checks (actually probes the website)
// ============================================================

interface LiveProbeResult {
  dnsCheck: CheckResult;
  httpCheck: CheckResult;
  headersCheck: CheckResult;
  redirectChain: string[];
  responseHeaders: Record<string, string>;
  finalUrl: string;
  statusCode: number | null;
  reachable: boolean;
  htmlContent: string;
  pageTitle: string;
}

async function performLiveProbe(url: string, domain: string): Promise<LiveProbeResult> {
  // --- DNS Resolution ---
  let dnsCheck: CheckResult;
  let reachable = false;
  try {
    const addresses = await dns.resolve4(domain);
    if (addresses.length === 0) {
      dnsCheck = { name: 'DNS Resolution', passed: false, details: 'Domain does not resolve to any IP', scoreImpact: -15 };
    } else {
      const isPrivate = addresses.some(ip => /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)/.test(ip));
      if (isPrivate) {
        dnsCheck = { name: 'DNS Resolution', passed: 'warning', details: `Resolves to private IP: ${addresses[0]}`, scoreImpact: -5 };
      } else {
        dnsCheck = { name: 'DNS Resolution', passed: true, details: `Resolves to ${addresses.slice(0, 3).join(', ')}`, scoreImpact: 5 };
      }
      reachable = true;
    }
  } catch (e: any) {
    if (e.code === 'ENOTFOUND') {
      dnsCheck = { name: 'DNS Resolution', passed: false, details: 'Domain does not exist (NXDOMAIN)', scoreImpact: -20 };
    } else {
      dnsCheck = { name: 'DNS Resolution', passed: 'skipped', details: `DNS lookup failed: ${e.message}`, scoreImpact: 0 };
    }
  }

  // --- HTTP Probe (fetch the site, follow redirects) ---
  let httpCheck: CheckResult;
  let headersCheck: CheckResult;
  let redirectChain: string[] = [];
  let responseHeaders: Record<string, string> = {};
  let finalUrl = url;
  let statusCode: number | null = null;

  let htmlContent = '';
  let pageTitle = '';

  if (!reachable) {
    httpCheck = { name: 'Live Site Check', passed: false, details: 'Site is unreachable — DNS failed', scoreImpact: -10 };
    headersCheck = { name: 'Security Headers', passed: 'skipped', details: 'Cannot check headers — site unreachable', scoreImpact: 0 };
    return { dnsCheck, httpCheck, headersCheck, redirectChain, responseHeaders, finalUrl, statusCode, reachable: false, htmlContent, pageTitle };
  }

  try {
    // Follow redirects manually to track chain
    let currentUrl = url;
    let hops = 0;
    const maxHops = 10;
    let lastResponse: Response | null = null;

    while (hops < maxHops) {
      const resp = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        signal: AbortSignal.timeout(10000),
        headers: { 'User-Agent': 'TrustLens/2.0 SecurityAnalyzer' },
      });
      lastResponse = resp;
      statusCode = resp.status;

      if ([301, 302, 303, 307, 308].includes(resp.status)) {
        const location = resp.headers.get('location');
        if (!location) break;
        const nextUrl = new URL(location, currentUrl).href;
        redirectChain.push(`${currentUrl} → ${resp.status}`);
        currentUrl = nextUrl;
        hops++;
      } else {
        break;
      }
    }

    finalUrl = currentUrl;

    // Collect response headers and HTML body
    if (lastResponse) {
      lastResponse.headers.forEach((value, key) => {
        responseHeaders[key.toLowerCase()] = value;
      });
      // Read HTML body for content analysis (first 8KB)
      try {
        const contentType = lastResponse.headers.get('content-type') || '';
        if (contentType.includes('text/html') || contentType.includes('text/plain') || !contentType) {
          const body = await lastResponse.text();
          htmlContent = body.substring(0, 8000);
          const titleMatch = htmlContent.match(/<title[^>]*>([^<]*)<\/title>/i);
          pageTitle = titleMatch ? titleMatch[1].trim() : '';
        }
      } catch { /* ignore body read errors */ }
    }

    // Evaluate HTTP response
    if (statusCode && statusCode >= 200 && statusCode < 300) {
      const redirectInfo = redirectChain.length > 0 ? ` (${redirectChain.length} redirect${redirectChain.length > 1 ? 's' : ''})` : '';
      httpCheck = { name: 'Live Site Check', passed: true, details: `Site is live (HTTP ${statusCode})${redirectInfo}`, scoreImpact: 10 };
    } else if (statusCode && statusCode >= 400 && statusCode < 500) {
      httpCheck = { name: 'Live Site Check', passed: 'warning', details: `Site returned client error (HTTP ${statusCode})`, scoreImpact: -5 };
    } else if (statusCode && statusCode >= 500) {
      httpCheck = { name: 'Live Site Check', passed: 'warning', details: `Site returned server error (HTTP ${statusCode})`, scoreImpact: -5 };
    } else {
      httpCheck = { name: 'Live Site Check', passed: 'warning', details: `Unexpected status: HTTP ${statusCode}`, scoreImpact: 0 };
    }

    // Check for suspicious redirects
    if (redirectChain.length > 3) {
      httpCheck = { name: 'Live Site Check', passed: false, details: `Excessive redirects (${redirectChain.length} hops) — suspicious`, scoreImpact: -10 };
    } else if (finalUrl !== url) {
      const origDomain = new URL(url).hostname;
      const finalDomain = new URL(finalUrl).hostname;
      if (origDomain !== finalDomain) {
        httpCheck = {
          name: 'Live Site Check',
          passed: 'warning',
          details: `Redirects to different domain: ${finalDomain} (${redirectChain.length} hop${redirectChain.length > 1 ? 's' : ''})`,
          scoreImpact: -5,
        };
      }
    }

    // --- Security Headers Analysis ---
    const securityHeaders: { name: string; present: boolean; value?: string }[] = [
      { name: 'strict-transport-security', present: !!responseHeaders['strict-transport-security'], value: responseHeaders['strict-transport-security'] },
      { name: 'content-security-policy', present: !!responseHeaders['content-security-policy'], value: responseHeaders['content-security-policy'] },
      { name: 'x-frame-options', present: !!responseHeaders['x-frame-options'], value: responseHeaders['x-frame-options'] },
      { name: 'x-content-type-options', present: !!responseHeaders['x-content-type-options'], value: responseHeaders['x-content-type-options'] },
      { name: 'referrer-policy', present: !!responseHeaders['referrer-policy'], value: responseHeaders['referrer-policy'] },
      { name: 'permissions-policy', present: !!responseHeaders['permissions-policy'], value: responseHeaders['permissions-policy'] },
    ];

    const presentCount = securityHeaders.filter(h => h.present).length;
    const totalHeaders = securityHeaders.length;
    const missingNames = securityHeaders.filter(h => !h.present).map(h => h.name);

    if (presentCount >= 5) {
      headersCheck = { name: 'Security Headers', passed: true, details: `${presentCount}/${totalHeaders} security headers present — excellent`, scoreImpact: 10 };
    } else if (presentCount >= 3) {
      headersCheck = { name: 'Security Headers', passed: true, details: `${presentCount}/${totalHeaders} security headers present. Missing: ${missingNames.join(', ')}`, scoreImpact: 5 };
    } else if (presentCount >= 1) {
      headersCheck = { name: 'Security Headers', passed: 'warning', details: `Only ${presentCount}/${totalHeaders} security headers. Missing: ${missingNames.join(', ')}`, scoreImpact: -5 };
    } else {
      headersCheck = { name: 'Security Headers', passed: false, details: 'No security headers found — site may be misconfigured or malicious', scoreImpact: -10 };
    }

  } catch (e: any) {
    const msg = e.name === 'TimeoutError' ? 'Connection timed out' : e.message;
    httpCheck = { name: 'Live Site Check', passed: false, details: `Site unreachable: ${msg}`, scoreImpact: -10 };
    headersCheck = { name: 'Security Headers', passed: 'skipped', details: 'Cannot check — site unreachable', scoreImpact: 0 };
  }

  return { dnsCheck, httpCheck, headersCheck, redirectChain, responseHeaders, finalUrl, statusCode, reachable, htmlContent, pageTitle };
}

// ============================================================
// Content Analysis (inspects actual page HTML)
// ============================================================

function analyzePageContent(html: string, domain: string): CheckResult {
  if (!html || html.length < 50) {
    return { name: 'Page Content Analysis', passed: 'skipped', details: 'No HTML content available to analyze', scoreImpact: 0 };
  }

  const findings: string[] = [];
  let riskScore = 0;

  // 1. Login/password form detection on non-major sites
  const hasPasswordField = /<input[^>]*type\s*=\s*["']password["'][^>]*>/i.test(html);
  const hasLoginForm = hasPasswordField || /<form[^>]*>[\s\S]*?(?:login|sign.?in|log.?in|user.?name|email)[^<]*<\/form>/i.test(html);
  if (hasLoginForm) {
    const knownLoginDomains = ['google.com', 'facebook.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com', 'paypal.com', 'twitter.com', 'linkedin.com', 'instagram.com', 'accounts.google.com', 'login.microsoftonline.com'];
    const isDomainKnown = knownLoginDomains.some(d => domain === d || domain.endsWith('.' + d));
    if (!isDomainKnown) {
      findings.push('Login/password form detected on lesser-known domain');
      riskScore += 2;
    }
  }

  // 2. External form actions (form submits data to a different domain)
  const formActions = [...html.matchAll(/<form[^>]*action\s*=\s*["'](https?:\/\/[^"']+)["'][^>]*>/gi)];
  for (const match of formActions) {
    try {
      const actionDomain = new URL(match[1]).hostname;
      if (actionDomain !== domain && !actionDomain.endsWith('.' + domain)) {
        findings.push(`Form submits data to external domain: ${actionDomain}`);
        riskScore += 3;
      }
    } catch { /* invalid URL, skip */ }
  }

  // 3. Hidden iframes
  const hiddenIframes = html.match(/<iframe[^>]*(?:style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*:\s*0|height\s*:\s*0)[^"']*["']|width\s*=\s*["']0["']|height\s*=\s*["']0["'])[^>]*>/gi);
  if (hiddenIframes && hiddenIframes.length > 0) {
    findings.push(`${hiddenIframes.length} hidden iframe(s) detected`);
    riskScore += 3;
  }

  // 4. Suspicious JavaScript patterns
  const suspiciousPatterns = [
    { pattern: /eval\s*\(/gi, name: 'eval()' },
    { pattern: /document\.write\s*\(/gi, name: 'document.write()' },
    { pattern: /unescape\s*\(/gi, name: 'unescape()' },
    { pattern: /String\.fromCharCode/gi, name: 'fromCharCode' },
    { pattern: /window\.location\s*=\s*["'](?!#)/gi, name: 'JS redirect' },
  ];
  const jsFindings: string[] = [];
  for (const { pattern, name } of suspiciousPatterns) {
    const matches = html.match(pattern);
    if (matches && matches.length > 0) {
      jsFindings.push(`${name} (×${matches.length})`);
      riskScore += 1;
    }
  }
  if (jsFindings.length > 0) {
    findings.push(`Suspicious JS: ${jsFindings.join(', ')}`);
  }

  // 5. Meta refresh redirect
  const metaRefresh = /<meta[^>]*http-equiv\s*=\s*["']refresh["'][^>]*content\s*=\s*["'][^"']*url\s*=\s*([^"';\s]+)/i;
  const refreshMatch = html.match(metaRefresh);
  if (refreshMatch) {
    findings.push(`Meta refresh redirect to: ${refreshMatch[1].substring(0, 60)}`);
    riskScore += 2;
  }

  // 6. Known crypto miner scripts
  const minerPatterns = /coinhive|cryptoloot|coin-hive|jsecoin|cryptonight|minero\.cc|webminer/i;
  if (minerPatterns.test(html)) {
    findings.push('Cryptocurrency miner script detected');
    riskScore += 4;
  }

  // 7. Excessive external resources (more than 15 unique 3rd-party domains)
  const srcDomains = new Set<string>();
  const srcMatches = html.matchAll(/(?:src|href)\s*=\s*["'](https?:\/\/([^/"']+))/gi);
  for (const m of srcMatches) {
    try {
      const extDomain = m[2].toLowerCase();
      if (extDomain !== domain && !extDomain.endsWith('.' + domain)) {
        srcDomains.add(extDomain);
      }
    } catch { /* skip */ }
  }
  if (srcDomains.size > 15) {
    findings.push(`Loads resources from ${srcDomains.size} external domains`);
    riskScore += 1;
  }

  // 8. Data URI in iframes/scripts (obfuscation technique)
  if (/(?:src|href)\s*=\s*["']data:/i.test(html)) {
    findings.push('Data URI embedding detected (potential obfuscation)');
    riskScore += 2;
  }

  // Determine result
  if (findings.length === 0) {
    return { name: 'Page Content Analysis', passed: true, details: 'No suspicious content patterns detected in page HTML', scoreImpact: 10 };
  }
  if (riskScore >= 5) {
    return { name: 'Page Content Analysis', passed: false, details: findings.join('; '), scoreImpact: -15 };
  }
  return { name: 'Page Content Analysis', passed: 'warning', details: findings.join('; '), scoreImpact: -5 };
}

// ============================================================
// Brand Impersonation Detection (content-based)
// ============================================================

const BRAND_DOMAINS: Record<string, string[]> = {
  'google': ['google.com', 'google.co', 'accounts.google.com', 'mail.google.com'],
  'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'login.microsoftonline.com'],
  'apple': ['apple.com', 'icloud.com', 'appleid.apple.com'],
  'amazon': ['amazon.com', 'amazon.co', 'aws.amazon.com'],
  'paypal': ['paypal.com', 'paypal.me'],
  'facebook': ['facebook.com', 'fb.com', 'meta.com'],
  'netflix': ['netflix.com'],
  'instagram': ['instagram.com'],
  'twitter': ['twitter.com', 'x.com'],
  'youtube': ['youtube.com', 'youtu.be'],
  'linkedin': ['linkedin.com'],
  'github': ['github.com', 'github.io'],
  'yahoo': ['yahoo.com'],
  'dropbox': ['dropbox.com'],
  'adobe': ['adobe.com'],
  'bank of america': ['bankofamerica.com'],
  'chase': ['chase.com'],
  'wells fargo': ['wellsfargo.com'],
  'whatsapp': ['whatsapp.com', 'web.whatsapp.com'],
};

function checkBrandImpersonation(html: string, pageTitle: string, domain: string): CheckResult {
  if (!html && !pageTitle) {
    return { name: 'Brand Impersonation', passed: 'skipped', details: 'No page content to analyze', scoreImpact: 0 };
  }

  // Combine title + visible text signals
  const textToAnalyze = (pageTitle + ' ' + html
    .replace(/<script[\s\S]*?<\/script>/gi, '')
    .replace(/<style[\s\S]*?<\/style>/gi, '')
    .replace(/<[^>]+>/g, ' ')
    .substring(0, 3000)
  ).toLowerCase();

  const impersonated: string[] = [];

  for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
    // Check if content mentions the brand in login/account context
    const brandRegex = new RegExp(`(?:sign.?in|log.?in|verify|account|password|security).{0,30}${brand.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}|${brand.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}.{0,30}(?:sign.?in|log.?in|verify|account|password|security)`, 'i');
    if (brandRegex.test(textToAnalyze)) {
      // Check if domain actually belongs to this brand
      const isDomainLegit = domains.some(d => domain === d || domain.endsWith('.' + d.split('.').slice(-2).join('.')));
      if (!isDomainLegit) {
        impersonated.push(brand);
      }
    }
  }

  // Also check page title for exact brand mentions with login context
  if (pageTitle) {
    const titleLower = pageTitle.toLowerCase();
    for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
      if (titleLower.includes(brand) && (titleLower.includes('login') || titleLower.includes('sign in') || titleLower.includes('verify') || titleLower.includes('account'))) {
        const isDomainLegit = domains.some(d => domain === d || domain.endsWith('.' + d.split('.').slice(-2).join('.')));
        if (!isDomainLegit && !impersonated.includes(brand)) {
          impersonated.push(brand);
        }
      }
    }
  }

  if (impersonated.length === 0) {
    return { name: 'Brand Impersonation', passed: true, details: 'No brand impersonation detected in page content', scoreImpact: 5 };
  }
  return { name: 'Brand Impersonation', passed: false, details: `Page impersonates: ${impersonated.join(', ')} — likely phishing`, scoreImpact: -25 };
}

// ============================================================
// VirusTotal Integration
// ============================================================

async function checkVirusTotal(url: string): Promise<CheckResult> {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey || apiKey === 'YOUR_VIRUSTOTAL_API_KEY_HERE') {
    return { name: 'VirusTotal Scan', passed: 'skipped', details: 'API key not configured', scoreImpact: 0 };
  }

  try {
    // VirusTotal URL ID = base64url of the URL (no padding)
    const urlId = Buffer.from(url).toString('base64url');

    const resp = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      method: 'GET',
      headers: { 'x-apikey': apiKey, 'Accept': 'application/json' },
      signal: AbortSignal.timeout(12000),
    });

    if (resp.status === 404) {
      // No existing report — submit URL for scanning
      const submitResp = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: { 'x-apikey': apiKey, 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `url=${encodeURIComponent(url)}`,
        signal: AbortSignal.timeout(10000),
      });
      if (!submitResp.ok) {
        return { name: 'VirusTotal Scan', passed: 'skipped', details: 'Could not submit URL for scanning', scoreImpact: 0 };
      }
      // Wait briefly and fetch the result
      await new Promise(r => setTimeout(r, 3000));
      const retryResp = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        method: 'GET',
        headers: { 'x-apikey': apiKey, 'Accept': 'application/json' },
        signal: AbortSignal.timeout(10000),
      });
      if (!retryResp.ok) {
        return { name: 'VirusTotal Scan', passed: 'skipped', details: 'Scan submitted but results not yet ready', scoreImpact: 0 };
      }
      const retryData = await retryResp.json();
      return parseVirusTotalResult(retryData);
    }

    if (!resp.ok) {
      return { name: 'VirusTotal Scan', passed: 'skipped', details: `VirusTotal API error: HTTP ${resp.status}`, scoreImpact: 0 };
    }

    const data = await resp.json();
    return parseVirusTotalResult(data);
  } catch (e: any) {
    return { name: 'VirusTotal Scan', passed: 'skipped', details: `VirusTotal check failed: ${e.message}`, scoreImpact: 0 };
  }
}

function parseVirusTotalResult(data: any): CheckResult {
  const stats = data?.data?.attributes?.last_analysis_stats;
  if (!stats) {
    return { name: 'VirusTotal Scan', passed: 'skipped', details: 'No analysis stats available', scoreImpact: 0 };
  }

  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  const harmless = stats.harmless || 0;
  const undetected = stats.undetected || 0;
  const total = malicious + suspicious + harmless + undetected;

  if (malicious > 0) {
    return {
      name: 'VirusTotal Scan',
      passed: false,
      details: `${malicious}/${total} vendors flagged as MALICIOUS${suspicious > 0 ? `, ${suspicious} suspicious` : ''}`,
      scoreImpact: -20,
      threatFound: true,
    };
  }
  if (suspicious > 0) {
    return {
      name: 'VirusTotal Scan',
      passed: 'warning',
      details: `${suspicious}/${total} vendors flagged as suspicious, 0 malicious`,
      scoreImpact: -5,
    };
  }
  return {
    name: 'VirusTotal Scan',
    passed: true,
    details: `Clean: 0/${total} vendors detected threats (${harmless} harmless, ${undetected} undetected)`,
    scoreImpact: 15,
  };
}

// ============================================================
// API Checks
// ============================================================
async function checkGoogleSafeBrowsing(url: string): Promise<CheckResult> {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey || apiKey === 'YOUR_GOOGLE_SAFE_BROWSING_KEY_HERE') {
    return { name: 'Google Safe Browsing', passed: 'skipped', details: 'API key not configured', scoreImpact: 0 };
  }
  try {
    const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(apiKey)}`;
    const resp = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'trustlens', clientVersion: '1.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      }),
      signal: AbortSignal.timeout(10000),
    });
    const data = await resp.json();
    if (data.matches && data.matches.length > 0) {
      const types = [...new Set(data.matches.map((m: any) => m.threatType))].join(', ');
      return { name: 'Google Safe Browsing', passed: false, details: `THREAT DETECTED: ${types}`, scoreImpact: 0, threatFound: true };
    }
    return { name: 'Google Safe Browsing', passed: true, details: 'No threats found', scoreImpact: 25 };
  } catch (e: any) {
    return { name: 'Google Safe Browsing', passed: 'skipped', details: `API check failed: ${e.message}`, scoreImpact: 0 };
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number, fallback: T): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>(resolve => setTimeout(() => resolve(fallback), ms)),
  ]);
}

async function checkWhoisAge(domain: string): Promise<CheckResult> {
  const TIMEOUT_RESULT: CheckResult = { name: 'Domain Age (WHOIS)', passed: 'skipped', details: 'WHOIS lookup timed out', scoreImpact: 0 };
  return withTimeout(checkWhoisAgeInner(domain), 15000, TIMEOUT_RESULT);
}

async function checkWhoisAgeInner(domain: string): Promise<CheckResult> {
  try {
    const whoisJson = await import('whois-json').then(m => m.default || m);
    const data = await whoisJson(domain);
    let creation = data.creationDate || data.createdDate || data.domainRegistered;
    if (!creation) return { name: 'Domain Age (WHOIS)', passed: 'skipped', details: 'WHOIS data unavailable for this domain', scoreImpact: 0 };

    if (Array.isArray(creation)) creation = creation[0];
    const created = new Date(creation);
    if (isNaN(created.getTime())) return { name: 'Domain Age (WHOIS)', passed: 'skipped', details: 'Could not parse creation date', scoreImpact: 0 };

    const now = new Date();
    const ageDays = Math.floor((now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24));
    const ageYears = (ageDays / 365.25).toFixed(1);
    const ageStr = `${ageYears} years (${ageDays} days)`;

    if (ageDays < 180) return { name: 'Domain Age (WHOIS)', passed: false, details: `Domain age: ${ageStr} — HIGH RISK (< 6 months)`, scoreImpact: -20, domainAge: ageStr };
    if (ageDays < 365) return { name: 'Domain Age (WHOIS)', passed: 'warning', details: `Domain age: ${ageStr} — moderate risk (< 1 year)`, scoreImpact: -10, domainAge: ageStr };
    if (ageDays >= 730) return { name: 'Domain Age (WHOIS)', passed: true, details: `Domain age: ${ageStr} — established domain`, scoreImpact: 15, domainAge: ageStr };
    return { name: 'Domain Age (WHOIS)', passed: true, details: `Domain age: ${ageStr}`, scoreImpact: 5, domainAge: ageStr };
  } catch (e: any) {
    return { name: 'Domain Age (WHOIS)', passed: 'skipped', details: `WHOIS unavailable: ${e.message}`, scoreImpact: 0 };
  }
}

function checkSslCertificate(domain: string, isHttps: boolean): Promise<CheckResult> {
  if (!isHttps) {
    return Promise.resolve({ name: 'SSL Certificate', passed: 'skipped', details: 'Site does not use HTTPS — SSL check skipped', scoreImpact: 0 });
  }
  return new Promise(resolve => {
    const socket = tls.connect({ host: domain, port: 443, servername: domain, timeout: 10000 }, () => {
      try {
        const cert = socket.getPeerCertificate();
        socket.destroy();

        if (!cert || !cert.valid_to) {
          resolve({ name: 'SSL Certificate', passed: 'skipped', details: 'Could not retrieve certificate', scoreImpact: 0 });
          return;
        }

        const expiry = new Date(cert.valid_to);
        const now = new Date();
        const daysLeft = Math.floor((expiry.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
        const rawIssuer = cert.issuer?.O || cert.issuer?.CN || 'Unknown';
        const issuer = Array.isArray(rawIssuer) ? rawIssuer[0] : rawIssuer;

        if (daysLeft < 0) {
          resolve({ name: 'SSL Certificate', passed: false, details: `SSL certificate EXPIRED (${Math.abs(daysLeft)} days ago). Issuer: ${issuer}`, scoreImpact: -10, sslExpiry: cert.valid_to, sslIssuer: issuer });
        } else if (daysLeft < 30) {
          resolve({ name: 'SSL Certificate', passed: 'warning', details: `SSL expires in ${daysLeft} days. Issuer: ${issuer}`, scoreImpact: 5, sslExpiry: cert.valid_to, sslIssuer: issuer });
        } else {
          resolve({ name: 'SSL Certificate', passed: true, details: `Valid SSL certificate (expires in ${daysLeft} days). Issuer: ${issuer}`, scoreImpact: 15, sslExpiry: cert.valid_to, sslIssuer: issuer });
        }
      } catch {
        socket.destroy();
        resolve({ name: 'SSL Certificate', passed: 'skipped', details: 'SSL check failed', scoreImpact: 0 });
      }
    });
    socket.on('error', (e: any) => {
      resolve({ name: 'SSL Certificate', passed: 'skipped', details: `SSL check failed: ${e.message}`, scoreImpact: 0 });
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ name: 'SSL Certificate', passed: 'skipped', details: 'SSL check timed out', scoreImpact: 0 });
    });
  });
}

async function getGeminiAnalysis(url: string, allChecks: CheckResult[], probeResult: LiveProbeResult): Promise<CheckResult> {
  const apiKey = process.env.GEMINI_API_KEY;

  // Build a rich context from real-time findings
  const findings = allChecks
    .filter(c => c.name !== 'Gemini AI Analysis' && c.name !== 'AI Risk Assessment')
    .map(c => `- ${c.name}: ${c.passed === true ? 'PASS' : c.passed === false ? 'FAIL' : c.passed === 'warning' ? 'WARNING' : 'SKIPPED'} — ${c.details}`)
    .join('\n');

  const headersList = Object.entries(probeResult.responseHeaders)
    .slice(0, 15)
    .map(([k, v]) => `  ${k}: ${v.substring(0, 100)}`)
    .join('\n');

  const redirectInfo = probeResult.redirectChain.length > 0
    ? `Redirect chain: ${probeResult.redirectChain.join(' → ')}\nFinal URL: ${probeResult.finalUrl}`
    : 'No redirects.';

  // Page content snippet for AI analysis
  const contentSnippet = probeResult.htmlContent
    ? probeResult.htmlContent
        .replace(/<script[\s\S]*?<\/script>/gi, '[SCRIPT]')
        .replace(/<style[\s\S]*?<\/style>/gi, '[STYLE]')
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s+/g, ' ')
        .substring(0, 2000)
    : '(no content captured)';

  const prompt = `You are a senior cybersecurity analyst. Analyze this URL's safety using the following REAL-TIME scan data collected by probing the actual website.

URL: ${url}
Page Title: ${probeResult.pageTitle || '(none)'}
HTTP Status: ${probeResult.statusCode ?? 'unreachable'}
${redirectInfo}

LIVE SCAN RESULTS (${allChecks.length - 1} checks):
${findings}

RESPONSE HEADERS:
${headersList || '(none available)'}

PAGE CONTENT EXCERPT:
${contentSnippet}

Based on ALL the above real-time evidence, provide a concise 3-4 sentence risk assessment. Reference specific findings from the scan. Explain WHY this site is safe or dangerous based on the evidence. Be direct and actionable. Do not add disclaimers.`;

  // Try Gemini API if key is configured
  if (apiKey && apiKey !== 'YOUR_GEMINI_AI_STUDIO_KEY_HERE' && apiKey !== 'MY_GEMINI_API_KEY') {
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${encodeURIComponent(apiKey)}`;

    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const resp = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
          signal: AbortSignal.timeout(20000),
        });
        const data = await resp.json();

        if (resp.status === 429 && attempt < 2) {
          await new Promise(r => setTimeout(r, 2000 * (attempt + 1)));
          continue;
        }

        if (!resp.ok) {
          const errMsg = data?.error?.message || `HTTP ${resp.status}`;
          console.log(`Gemini API error: ${errMsg}, trying Groq fallback`);
          break;
        }
        const aiText = data?.candidates?.[0]?.content?.parts?.[0]?.text || '';
        if (!aiText) break;
        return { name: 'AI Risk Assessment', passed: true, details: 'AI analysis complete (Gemini 2.5 Flash + real-time data)', scoreImpact: 0, aiText };
      } catch (e: any) {
        if (attempt < 2) continue;
        break;
      }
    }
  }

  // Try Groq API (free tier — Llama 3.3 70B)
  const groqKey = process.env.GROQ_API_KEY;
  if (groqKey && groqKey !== 'YOUR_GROQ_API_KEY_HERE') {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        const resp = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${groqKey}`,
          },
          body: JSON.stringify({
            model: 'llama-3.3-70b-versatile',
            messages: [
              { role: 'system', content: 'You are a senior cybersecurity analyst. Provide concise, evidence-based risk assessments.' },
              { role: 'user', content: prompt },
            ],
            temperature: 0.3,
            max_tokens: 500,
          }),
          signal: AbortSignal.timeout(15000),
        });
        const data = await resp.json();

        if (resp.status === 429 && attempt < 1) {
          await new Promise(r => setTimeout(r, 3000));
          continue;
        }

        if (!resp.ok) {
          console.log(`Groq API error: ${data?.error?.message || resp.status}, using rule-based fallback`);
          break;
        }
        const aiText = data?.choices?.[0]?.message?.content || '';
        if (!aiText) break;
        return { name: 'AI Risk Assessment', passed: true, details: 'AI analysis complete (Groq Llama 3.3 70B + real-time data)', scoreImpact: 0, aiText };
      } catch (e: any) {
        if (attempt < 1) continue;
        break;
      }
    }
  }

  // ── Rule-Based Fallback ──
  const aiText = generateRuleBasedAssessment(url, allChecks, probeResult);
  return { name: 'AI Risk Assessment', passed: true, details: 'Rule-based assessment (Gemini unavailable)', scoreImpact: 0, aiText };
}

function generateRuleBasedAssessment(url: string, allChecks: CheckResult[], probeResult: LiveProbeResult): string {
  const failures = allChecks.filter(c => c.passed === false && c.name !== 'AI Risk Assessment');
  const warnings = allChecks.filter(c => c.passed === 'warning');
  const passes = allChecks.filter(c => c.passed === true && c.name !== 'AI Risk Assessment');
  const domain = new URL(url).hostname;

  const parts: string[] = [];

  // Opening assessment
  if (failures.length === 0 && warnings.length <= 2) {
    parts.push(`${domain} shows strong security indicators with ${passes.length} checks passed and no critical failures.`);
  } else if (failures.length >= 3) {
    parts.push(`${domain} raises significant security concerns with ${failures.length} failed checks out of ${allChecks.length - 1} total.`);
  } else {
    parts.push(`${domain} shows mixed security signals: ${passes.length} passed, ${warnings.length} warnings, and ${failures.length} failure(s).`);
  }

  // Reference specific critical findings
  const criticalFindings: string[] = [];
  for (const f of failures) {
    if (f.name === 'Brand Impersonation') criticalFindings.push(`The page appears to impersonate a known brand, which is a strong phishing indicator.`);
    else if (f.name === 'Page Content Analysis') criticalFindings.push(`Suspicious content patterns were found in the page HTML (${f.details.substring(0, 80)}).`);
    else if (f.name === 'DNS Resolution') criticalFindings.push(`The domain failed DNS resolution, meaning it may not exist or is unreachable.`);
    else if (f.name === 'VirusTotal Scan') criticalFindings.push(`VirusTotal vendors have flagged this URL as malicious.`);
    else if (f.name === 'Google Safe Browsing') criticalFindings.push(`Google Safe Browsing has flagged known threats on this URL.`);
    else if (f.name === 'Domain Age (WHOIS)') criticalFindings.push(`The domain was registered very recently, which is common for phishing sites.`);
    else if (f.name === 'SSL Certificate') criticalFindings.push(`The SSL certificate has issues: ${f.details.substring(0, 60)}.`);
  }
  if (criticalFindings.length > 0) {
    parts.push(criticalFindings.slice(0, 2).join(' '));
  }

  // Positive trust signals
  const trustSignals: string[] = [];
  const whois = allChecks.find(c => c.name === 'Domain Age (WHOIS)' && c.passed === true);
  if (whois) trustSignals.push(`established domain age (${whois.domainAge || 'known'})`);
  const ssl = allChecks.find(c => c.name === 'SSL Certificate' && c.passed === true);
  if (ssl) trustSignals.push('valid SSL certificate');
  const https = allChecks.find(c => c.name === 'HTTPS Protocol' && c.passed === true);
  if (https) trustSignals.push('HTTPS encryption');
  const content = allChecks.find(c => c.name === 'Page Content Analysis' && c.passed === true);
  if (content) trustSignals.push('clean page content');
  if (trustSignals.length > 0) {
    parts.push(`Trust signals include: ${trustSignals.join(', ')}.`);
  }

  // Actionable recommendation
  if (failures.length === 0 && warnings.length <= 2) {
    parts.push('This site appears safe for normal browsing. Continue using standard security practices.');
  } else if (failures.length >= 3) {
    parts.push('Exercise extreme caution. Do not enter personal information or credentials on this site.');
  } else {
    parts.push('Proceed with caution and verify the site\u2019s legitimacy before sharing sensitive data.');
  }

  return parts.join(' ');
}

// ============================================================
// Score Calculation
// ============================================================
function calculateScore(checks: CheckResult[]): { score: number; riskLevel: string; riskColor: string; warnings: string[]; positives: string[] } {
  let score = 0;
  const warnings: string[] = [];
  const positives: string[] = [];
  let threatFound = false;

  for (const c of checks) {
    if (c.name === 'AI Risk Assessment') continue;
    score += c.scoreImpact;
    if (c.threatFound) threatFound = true;
    if (c.passed === true) positives.push(c.details);
    else if (c.passed === false || c.passed === 'warning') warnings.push(c.details);
  }

  score = Math.max(0, Math.min(100, score));

  let riskLevel: string;
  let riskColor: string;

  if (threatFound) {
    riskLevel = 'HIGH RISK';
    riskColor = '#f85149';
    score = Math.min(score, 25);
  } else if (score >= 80) {
    riskLevel = 'SAFE';
    riskColor = '#3fb950';
  } else if (score >= 50) {
    riskLevel = 'MODERATE RISK';
    riskColor = '#d29922';
  } else {
    riskLevel = 'HIGH RISK';
    riskColor = '#f85149';
  }

  return { score, riskLevel, riskColor, warnings, positives };
}

// ============================================================
// Main Analysis Orchestrator
// ============================================================
export async function analyzeUrl(rawUrl: string): Promise<AnalysisResponse> {
  const { valid, formatted, error } = validateUrl(rawUrl);
  if (!valid) {
    return {
      url: rawUrl,
      score: 0,
      riskLevel: 'HIGH RISK',
      riskColor: '#f85149',
      checks: [],
      warnings: [error || 'Invalid URL'],
      positives: [],
      aiAnalysis: '',
      domainInfo: { age: null, sslExpiry: null, sslIssuer: null },
    };
  }

  const parsed = new URL(formatted);
  const domain = parsed.hostname;
  const isHttps = parsed.protocol === 'https:';

  // Phase 1: Run all real-time checks in parallel
  const [safeBrowsing, virusTotal, whoisAge, sslCert, liveProbe] = await Promise.all([
    checkGoogleSafeBrowsing(formatted),
    checkVirusTotal(formatted),
    checkWhoisAge(domain),
    checkSslCertificate(domain, isHttps),
    withTimeout(
      performLiveProbe(formatted, domain),
      20000,
      {
        dnsCheck: { name: 'DNS Resolution', passed: 'skipped', details: 'Probe timed out', scoreImpact: 0 } as CheckResult,
        httpCheck: { name: 'Live Site Check', passed: 'skipped', details: 'Probe timed out', scoreImpact: 0 } as CheckResult,
        headersCheck: { name: 'Security Headers', passed: 'skipped', details: 'Probe timed out', scoreImpact: 0 } as CheckResult,
        redirectChain: [],
        responseHeaders: {},
        finalUrl: formatted,
        statusCode: null,
        reachable: false,
        htmlContent: '',
        pageTitle: '',
      }
    ),
  ]);

  // Phase 2: Content analysis (depends on live probe HTML)
  const pageContent = analyzePageContent(liveProbe.htmlContent, domain);
  const brandCheck = checkBrandImpersonation(liveProbe.htmlContent, liveProbe.pageTitle, domain);

  const staticChecks: CheckResult[] = [
    checkHttps(parsed),
    checkUrlLength(formatted),
    checkSuspiciousKeywords(formatted),
    checkHyphenCount(domain),
    checkIpAsDomain(domain),
    checkSubdomainCount(domain),
    checkRiskyTld(domain),
    checkTyposquatting(domain),
    checkPunycode(domain),
  ];

  // Combine all checks before AI (so AI sees everything)
  const preAiChecks = [
    ...staticChecks,
    safeBrowsing,
    virusTotal,
    whoisAge,
    sslCert,
    liveProbe.dnsCheck,
    liveProbe.httpCheck,
    liveProbe.headersCheck,
    pageContent,
    brandCheck,
  ];

  // Phase 3: Feed all real-time findings to AI for informed analysis
  const gemini = await getGeminiAnalysis(formatted, preAiChecks, liveProbe);

  const allChecks = [...preAiChecks, gemini];
  const { score, riskLevel, riskColor, warnings, positives } = calculateScore(allChecks);

  const domainInfo: DomainInfo = {
    age: whoisAge.domainAge || null,
    sslExpiry: sslCert.sslExpiry || null,
    sslIssuer: sslCert.sslIssuer || null,
  };

  return {
    url: formatted,
    score,
    riskLevel: riskLevel as AnalysisResponse['riskLevel'],
    riskColor,
    checks: allChecks,
    warnings,
    positives,
    aiAnalysis: gemini.aiText || '',
    domainInfo,
  };
}
