import dns from 'dns/promises';
import {
  IndicatorType,
  LiveFeedSource,
  SeverityLevel,
  ComparisonSummary,
  ThreatIndicator,
  MatchStatus
} from '../types/threat';
import { validateIndicator } from './validation';

/**
 * Live Threat Intelligence Integration Service
 * Connects to public threat intelligence APIs:
 * - URLhaus (abuse.ch) for malware URLs and domains (Requires URLHAUS_API_KEY)
 * - AbuseIPDB for IP reputation and abuse reporting (Requires ABUSEIPDB_API_KEY; resolves domains safely to IPs first)
 * - AlienVault OTX for community pulses and threat indicators (Works in public mode or with OTX_API_KEY)
 */

const REQUEST_TIMEOUT_MS = 4500;
const DNS_TIMEOUT_MS = 2500;

function isPlaceholderKey(val: string | undefined, placeholders: string[]): boolean {
  if (!val) return true;
  const trimmed = val.trim().replace(/^["']|["']$/g, '');
  if (!trimmed) return true;
  return placeholders.some((p) => trimmed.toUpperCase() === p.toUpperCase());
}

function getCleanEnvKey(envVarName: string, placeholders: string[]): string | null {
  const raw = process.env[envVarName];
  if (isPlaceholderKey(raw, placeholders)) return null;
  return raw!.trim().replace(/^["']|["']$/g, '');
}

async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = REQUEST_TIMEOUT_MS
): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });
    clearTimeout(id);
    return response;
  } catch (error) {
    clearTimeout(id);
    throw error;
  }
}

async function safeParseJson(res: Response): Promise<{ ok: boolean; data?: any; rawPreview?: string }> {
  const text = await res.text();
  if (!text) return { ok: false, rawPreview: 'Empty response body' };
  try {
    return { ok: true, data: JSON.parse(text) };
  } catch {
    return { ok: false, rawPreview: text.slice(0, 140).replace(/\s+/g, ' ') };
  }
}

/**
 * Safely resolves a domain name to public IPv4/IPv6 addresses with a strict timeout.
 * Never throws; returns structured resolution result.
 */
export async function resolveDomainToPublicIP(domain: string): Promise<{
  ips: string[];
  primaryPublicIp: string | null;
  isPrivateOrReservedOnly: boolean;
  error?: string;
}> {
  const timeoutPromise = new Promise<never>((_, reject) => {
    setTimeout(() => reject(new Error('DNS lookup timed out')), DNS_TIMEOUT_MS);
  });

  try {
    const resolveAll = async () => {
      const [v4Res, v6Res] = await Promise.allSettled([
        dns.resolve4(domain),
        dns.resolve6(domain)
      ]);
      const v4 = v4Res.status === 'fulfilled' ? v4Res.value : [];
      const v6 = v6Res.status === 'fulfilled' ? v6Res.value : [];
      return [...v4, ...v6];
    };

    const ips = await Promise.race([resolveAll(), timeoutPromise]);
    if (!ips || ips.length === 0) {
      return {
        ips: [],
        primaryPublicIp: null,
        isPrivateOrReservedOnly: false,
        error: 'No A or AAAA DNS records found for domain'
      };
    }

    const publicIps: string[] = [];
    for (const candidate of ips) {
      const check = validateIndicator(candidate, 'ip');
      if (
        check.isValid &&
        !check.details?.isPrivate &&
        !check.details?.isLoopback &&
        !check.details?.isReserved
      ) {
        publicIps.push(check.sanitized);
      }
    }

    return {
      ips,
      primaryPublicIp: publicIps[0] || null,
      isPrivateOrReservedOnly: publicIps.length === 0 && ips.length > 0
    };
  } catch (err: any) {
    const code = err?.code || '';
    return {
      ips: [],
      primaryPublicIp: null,
      isPrivateOrReservedOnly: false,
      error: code ? `DNS resolution failed (${code})` : err?.message || 'DNS resolution failed'
    };
  }
}

/**
 * 1. URLhaus (abuse.ch) Threat Query
 * Supports both domain and IP host queries
 */
export async function queryURLhaus(indicator: string, _type: IndicatorType): Promise<LiveFeedSource> {
  const startTime = Date.now();
  const feed: LiveFeedSource = {
    id: 'urlhaus',
    name: 'URLhaus (abuse.ch)',
    indicator,
    status: 'unavailable',
    isThreatFound: false,
    details: 'Querying URLhaus threat intelligence database...',
    attributionUrl: `https://urlhaus.abuse.ch/host/${encodeURIComponent(indicator)}/`
  };

  const apiKey = getCleanEnvKey('URLHAUS_API_KEY', ['MY_URLHAUS_KEY', 'YOUR_URLHAUS_API_KEY']);
  if (!apiKey) {
    feed.status = 'not_configured';
    feed.errorCode = 'API_KEY_MISSING';
    feed.details =
      'API key missing: URLHAUS_API_KEY is not configured in backend environment variables. Set a free abuse.ch Auth-Key to enable live URLhaus malware lookups.';
    feed.queryTimeMs = 0;
    return feed;
  }

  try {
    const params = new URLSearchParams();
    params.append('host', indicator);

    const res = await fetchWithTimeout('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
        'Auth-Key': apiKey
      },
      body: params.toString()
    });

    feed.queryTimeMs = Date.now() - startTime;

    if (!res.ok) {
      feed.status = 'unavailable';
      if (res.status === 401 || res.status === 403) {
        feed.errorCode = 'AUTH_ERROR';
        feed.details = `URLhaus authentication failed (HTTP ${res.status}): Invalid or expired URLHAUS_API_KEY.`;
      } else if (res.status === 429) {
        feed.errorCode = 'RATE_LIMITED';
        feed.details = 'API rate limit exceeded by URLhaus (HTTP 429). Retry shortly.';
      } else {
        feed.errorCode = 'SERVICE_UNAVAILABLE';
        feed.details = `External threat intelligence service unavailable: URLhaus returned HTTP ${res.status} (${res.statusText}).`;
      }
      return feed;
    }

    const parsed = await safeParseJson(res);
    if (!parsed.ok || !parsed.data || typeof parsed.data !== 'object') {
      feed.status = 'unavailable';
      feed.errorCode = 'MALFORMED_RESPONSE';
      feed.details = `Malformed response received from URLhaus API (${parsed.rawPreview || 'invalid JSON'}).`;
      return feed;
    }

    const data = parsed.data;
    feed.rawAttributes = {
      query_status: data.query_status,
      url_count: data.url_count,
      firstseen: data.firstseen
    };

    if (data.query_status === 'ok' && (Number(data.url_count) > 0 || (Array.isArray(data.urls) && data.urls.length > 0))) {
      feed.status = 'detected_threat';
      feed.isThreatFound = true;
      feed.confidence = 94;
      feed.category = 'Malware';
      feed.severity = 'HIGH RISK';
      feed.lastReported = data.firstseen || data.urls?.[0]?.date_added || new Date().toISOString();

      const topTags = Array.isArray(data.urls?.[0]?.tags) ? data.urls[0].tags.join(', ') : '';
      feed.reputationSummary = `${data.url_count} malicious payload URL(s) cataloged`;
      feed.details = `Active malware distribution host identified in URLhaus! Associated with ${data.url_count} malicious payload URL(s). ${
        topTags ? `Tags: ${topTags}. ` : ''
      }Threat classification: ${data.urls?.[0]?.threat || 'Malware staging'}.`;
    } else if (data.query_status === 'no_results') {
      feed.status = 'clean_or_no_reports';
      feed.isThreatFound = false;
      feed.reputationSummary = '0 malware URLs reported';
      feed.details = 'No active malware hosting or distribution URLs cataloged in URLhaus database.';
    } else if (data.query_status === 'invalid_host') {
      feed.status = 'insufficient_evidence';
      feed.isThreatFound = false;
      feed.details = 'URLhaus could not evaluate host syntax.';
    } else {
      feed.status = 'clean_or_no_reports';
      feed.isThreatFound = false;
      feed.reputationSummary = `Query status: ${data.query_status || 'no_results'}`;
      feed.details = `URLhaus response status: ${data.query_status || 'No malicious activity reported'}.`;
    }
  } catch (err: any) {
    feed.queryTimeMs = Date.now() - startTime;
    feed.status = 'unavailable';
    if (err?.name === 'AbortError') {
      feed.errorCode = 'TIMEOUT';
      feed.details = 'Request timeout: URLhaus did not respond within 4.5 seconds.';
    } else {
      feed.errorCode = 'NETWORK_ERROR';
      feed.details = `External service unavailable: URLhaus lookup failed (${err?.message || 'Network connectivity error'}).`;
    }
  }

  return feed;
}

/**
 * 2. AbuseIPDB IP Reputation Query
 * For IP indicators: queries AbuseIPDB directly.
 * For Domain indicators: NEVER sends domain directly to AbuseIPDB IP endpoint;
 * safely resolves an associated public IP via DNS first and queries that IP if available.
 */
export async function queryAbuseIPDB(
  indicator: string,
  type: IndicatorType = 'ip',
  preResolvedIp?: { ips: string[]; primaryPublicIp: string | null; isPrivateOrReservedOnly: boolean; error?: string }
): Promise<LiveFeedSource> {
  const startTime = Date.now();
  const apiKey = getCleanEnvKey('ABUSEIPDB_API_KEY', ['MY_ABUSEIPDB_KEY', 'YOUR_ABUSEIPDB_API_KEY']);

  const feed: LiveFeedSource = {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    indicator,
    status: 'unavailable',
    isThreatFound: false,
    details: 'Checking AbuseIPDB IP reputation...',
    attributionUrl: type === 'ip' ? `https://www.abuseipdb.com/check/${encodeURIComponent(indicator)}` : 'https://www.abuseipdb.com/'
  };

  let targetIp = indicator;

  if (type === 'domain') {
    const dnsResult = preResolvedIp || (await resolveDomainToPublicIP(indicator));
    if (!dnsResult.primaryPublicIp) {
      feed.queryTimeMs = Date.now() - startTime;
      if (!apiKey) {
        feed.status = 'not_configured';
        feed.errorCode = 'API_KEY_MISSING';
        feed.details = dnsResult.isPrivateOrReservedOnly
          ? 'API key missing (ABUSEIPDB_API_KEY) and domain resolved only to a private/reserved IP.'
          : `API key missing (ABUSEIPDB_API_KEY). Note: AbuseIPDB evaluates IP addresses only (${dnsResult.error || 'no public A/AAAA record resolved'}).`;
        return feed;
      }

      feed.status = 'insufficient_evidence';
      feed.errorCode = 'DNS_RESOLUTION_FAILED';
      feed.details = dnsResult.isPrivateOrReservedOnly
        ? `Domain resolved only to private/reserved IP (${dnsResult.ips.join(', ')}); AbuseIPDB only scores public IP addresses.`
        : `AbuseIPDB evaluates IP addresses only. Safe DNS resolution for "${indicator}" returned no public IP (${dnsResult.error || 'NXDOMAIN'}).`;
      return feed;
    }

    targetIp = dnsResult.primaryPublicIp;
    feed.resolvedIp = targetIp;
    feed.attributionUrl = `https://www.abuseipdb.com/check/${encodeURIComponent(targetIp)}`;
  }

  if (!apiKey) {
    feed.status = 'not_configured';
    feed.errorCode = 'API_KEY_MISSING';
    feed.details =
      type === 'domain'
        ? `API key missing: ABUSEIPDB_API_KEY is not configured in backend environment variables. (Domain resolved to IP ${targetIp}; IP reputation lookup skipped).`
        : 'API key missing: ABUSEIPDB_API_KEY is not configured in backend environment variables. Set key to enable live 90-day IP reputation scoring.';
    feed.queryTimeMs = Date.now() - startTime;
    return feed;
  }

  try {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(targetIp)}&maxAgeInDays=90&verbose`;
    const res = await fetchWithTimeout(url, {
      method: 'GET',
      headers: {
        Key: apiKey,
        Accept: 'application/json'
      }
    });

    feed.queryTimeMs = Date.now() - startTime;

    if (!res.ok) {
      feed.status = 'unavailable';
      if (res.status === 401 || res.status === 403) {
        feed.errorCode = 'AUTH_ERROR';
        feed.details = 'AbuseIPDB authentication failed: Invalid or expired ABUSEIPDB_API_KEY.';
      } else if (res.status === 429) {
        feed.errorCode = 'RATE_LIMITED';
        feed.details = 'API rate limit exceeded by AbuseIPDB (HTTP 429).';
      } else if (res.status === 422) {
        feed.status = 'insufficient_evidence';
        feed.errorCode = 'UNSUPPORTED_INDICATOR';
        feed.details = `AbuseIPDB could not process IP ${targetIp} (HTTP 422 Unprocessable Entity).`;
      } else {
        feed.errorCode = 'SERVICE_UNAVAILABLE';
        feed.details = `External threat intelligence service unavailable: AbuseIPDB returned HTTP ${res.status}.`;
      }
      return feed;
    }

    const parsed = await safeParseJson(res);
    const data = parsed.ok ? parsed.data?.data : null;

    if (!data) {
      feed.status = 'unavailable';
      feed.errorCode = 'MALFORMED_RESPONSE';
      feed.details = `Malformed response received from AbuseIPDB (${parsed.rawPreview || 'missing data payload'}).`;
      return feed;
    }

    const score = Number(data.abuseConfidenceScore || 0);
    const totalReports = Number(data.totalReports || 0);
    feed.confidence = score;
    feed.lastReported = data.lastReportedAt || undefined;
    feed.rawAttributes = {
      queriedIp: targetIp,
      resolvedFromDomain: type === 'domain' ? indicator : undefined,
      abuseConfidenceScore: score,
      totalReports,
      countryCode: data.countryCode,
      isp: data.isp,
      usageType: data.usageType
    };

    const ipScopeLabel = type === 'domain' ? `Resolved host IP ${targetIp}` : `IP ${targetIp}`;
    feed.reputationSummary = `${ipScopeLabel}: ${score}% abuse confidence (${totalReports} reports / 90d)`;

    if (score >= 50 || totalReports >= 10) {
      feed.status = 'detected_threat';
      feed.isThreatFound = true;
      feed.severity = score >= 80 ? 'HIGH RISK' : 'MEDIUM RISK';
      feed.category = 'Suspicious Activity';
      feed.details = `${ipScopeLabel} has a high abuse confidence score of ${score}% (${totalReports} distinct reports in 90 days). ISP: ${
        data.isp || 'N/A'
      }.${type === 'domain' ? ' Note: Reputation reflects the resolved hosting IP, which may be shared infrastructure.' : ''}`;
    } else if (totalReports > 0) {
      feed.status = 'detected_threat';
      feed.isThreatFound = true;
      feed.severity = 'LOW RISK';
      feed.category = 'Suspicious Activity';
      feed.details = `${ipScopeLabel} has low-volume abuse reports (${totalReports} reports in 90 days; confidence ${score}%). ISP: ${
        data.isp || 'N/A'
      }.`;
    } else {
      feed.status = 'clean_or_no_reports';
      feed.isThreatFound = false;
      feed.details = `0 abuse reports recorded in AbuseIPDB over the past 90 days for ${ipScopeLabel}. Abuse confidence score: 0%. ISP: ${
        data.isp || 'N/A'
      }.`;
    }
  } catch (err: any) {
    feed.queryTimeMs = Date.now() - startTime;
    feed.status = 'unavailable';
    if (err?.name === 'AbortError') {
      feed.errorCode = 'TIMEOUT';
      feed.details = 'Request timeout: AbuseIPDB did not respond within 4.5 seconds.';
    } else {
      feed.errorCode = 'NETWORK_ERROR';
      feed.details = `External service unavailable: AbuseIPDB lookup failed (${err?.message || 'Network error'}).`;
    }
  }

  return feed;
}

/**
 * 3. AlienVault OTX Community Pulse Query
 * Supports both IP addresses and domain names
 */
export async function queryAlienVaultOTX(indicator: string, type: IndicatorType): Promise<LiveFeedSource> {
  const startTime = Date.now();
  const apiKey = getCleanEnvKey('OTX_API_KEY', ['MY_OTX_KEY', 'YOUR_OTX_API_KEY']);

  const feed: LiveFeedSource = {
    id: 'otx',
    name: 'AlienVault OTX',
    indicator,
    status: 'unavailable',
    isThreatFound: false,
    details: 'Querying AlienVault OTX community pulses...',
    attributionUrl: `https://otx.alienvault.com/indicator/${type === 'ip' ? 'ip' : 'domain'}/${encodeURIComponent(indicator)}`
  };

  try {
    const isIPv6 = indicator.includes(':');
    const endpointType = type === 'ip' ? (isIPv6 ? 'IPv6' : 'IPv4') : 'domain';
    const url = `https://otx.alienvault.com/api/v1/indicators/${endpointType}/${encodeURIComponent(indicator)}/general`;

    const headers: Record<string, string> = {
      Accept: 'application/json',
      'User-Agent': 'SOC-Threat-Intel-Dashboard/1.0'
    };
    if (apiKey) {
      headers['X-OTX-API-KEY'] = apiKey;
    }

    const res = await fetchWithTimeout(url, { method: 'GET', headers });
    feed.queryTimeMs = Date.now() - startTime;

    if (!res.ok) {
      if (res.status === 404) {
        feed.status = 'clean_or_no_reports';
        feed.isThreatFound = false;
        feed.reputationSummary = 'No OTX indicator record found';
        feed.details = 'Indicator is not cataloged in AlienVault OTX threat pulses.';
        return feed;
      }

      feed.status = 'unavailable';
      if (res.status === 401 || res.status === 403) {
        feed.errorCode = 'AUTH_ERROR';
        feed.details = `AlienVault OTX authentication failed (HTTP ${res.status}). Check OTX_API_KEY.`;
      } else if (res.status === 429) {
        feed.errorCode = 'RATE_LIMITED';
        feed.details = 'API rate limit exceeded by AlienVault OTX (HTTP 429).';
      } else {
        feed.errorCode = 'SERVICE_UNAVAILABLE';
        feed.details = `External threat intelligence service unavailable: AlienVault OTX returned HTTP ${res.status} (${res.statusText}).`;
      }
      return feed;
    }

    const parsed = await safeParseJson(res);
    if (!parsed.ok || !parsed.data || typeof parsed.data !== 'object') {
      feed.status = 'unavailable';
      feed.errorCode = 'MALFORMED_RESPONSE';
      feed.details = `Malformed response received from AlienVault OTX (${parsed.rawPreview || 'invalid JSON'}).`;
      return feed;
    }

    const data = parsed.data;
    const pulseCount = Number(data?.pulse_info?.count || 0);
    const pulses = Array.isArray(data?.pulse_info?.pulses) ? data.pulse_info.pulses : [];
    const validations = Array.isArray(data?.validation) ? data.validation : [];

    // Check OTX built-in whitelist/popular-domain validation flags (prevents false positives on example.com, google.com, etc.)
    const whitelistSignals = validations.filter((v: any) => {
      const src = String(v?.source || '').toLowerCase();
      const name = String(v?.name || '').toLowerCase();
      const msg = String(v?.message || '').toLowerCase();
      return (
        ['majestic', 'whitelist', 'false_positive', 'akamai', 'alexa', 'cisco', 'ad_network'].includes(src) ||
        name.includes('whitelisted') ||
        name.includes('popular domain') ||
        msg.includes('whitelisted')
      );
    });

    const validationNote = whitelistSignals.map((v: any) => v.message || v.name).filter(Boolean).join('; ');

    feed.rawAttributes = {
      pulseCount,
      reputation: data?.reputation,
      validation: validations.slice(0, 3),
      pulseNames: pulses.slice(0, 3).map((p: any) => p.name)
    };

    if (pulseCount > 0 && whitelistSignals.length === 0) {
      feed.status = 'detected_threat';
      feed.isThreatFound = true;
      feed.confidence = Math.min(96, 60 + pulseCount * 8);
      feed.severity = pulseCount >= 3 ? 'HIGH RISK' : 'MEDIUM RISK';
      feed.category = 'Command and Control';
      feed.lastReported = pulses[0]?.modified || pulses[0]?.created || new Date().toISOString();

      const pulseSummary = pulses.slice(0, 2).map((p: any) => `"${p.name}"`).join(', ');
      feed.reputationSummary = `Listed in ${pulseCount} OTX threat pulse(s)`;
      feed.details = `Indicator actively cataloged in ${pulseCount} AlienVault OTX threat intelligence pulses.${
        pulseSummary ? ` Top pulses: ${pulseSummary}.` : ''
      }`;
    } else if (pulseCount > 0 && whitelistSignals.length > 0) {
      // Domain appears in OTX pulses (common for example.com / documentation / CDN domains) but OTX marks it whitelisted/popular
      feed.status = 'clean_or_no_reports';
      feed.isThreatFound = false;
      feed.reputationSummary = `OTX Validation: ${validationNote} (${pulseCount} informational pulse mentions)`;
      feed.details = `OTX reports ${pulseCount} community pulse mention(s), but built-in validation flags this indicator as whitelisted/known infrastructure (${validationNote}). Not classified as an active threat.`;
    } else {
      feed.status = 'clean_or_no_reports';
      feed.isThreatFound = false;
      feed.reputationSummary = validationNote
        ? `0 threat pulses · ${validationNote}`
        : '0 OTX threat pulses';
      feed.details = validationNote
        ? `No threat pulses linked to this indicator in AlienVault OTX. OTX Reputation Context: ${validationNote}.`
        : 'No threat pulses or adversary campaigns linked to this indicator in AlienVault OTX.';
    }
  } catch (err: any) {
    feed.queryTimeMs = Date.now() - startTime;
    feed.status = 'unavailable';
    if (err?.name === 'AbortError') {
      feed.errorCode = 'TIMEOUT';
      feed.details = 'Request timeout: AlienVault OTX did not respond within 4.5 seconds.';
    } else {
      feed.errorCode = 'NETWORK_ERROR';
      feed.details = `External service unavailable: AlienVault OTX lookup failed (${err?.message || 'Network error'}).`;
    }
  }

  return feed;
}

/**
 * 4. Query All Configured Live Feeds Simultaneously
 */
export async function queryAllLiveFeeds(
  indicator: string,
  type: IndicatorType
): Promise<{ feeds: LiveFeedSource[]; resolvedIps: string[] }> {
  // For domains, resolve DNS once in parallel with URLhaus/OTX so AbuseIPDB receives an IP cleanly
  const dnsPromise = type === 'domain' ? resolveDomainToPublicIP(indicator) : Promise.resolve(undefined);

  const tasks: { id: LiveFeedSource['id']; name: string; promise: Promise<LiveFeedSource> }[] = [
    {
      id: 'urlhaus',
      name: 'URLhaus (abuse.ch)',
      promise: queryURLhaus(indicator, type)
    },
    {
      id: 'abuseipdb',
      name: 'AbuseIPDB',
      promise: dnsPromise.then((dnsRes) => queryAbuseIPDB(indicator, type, dnsRes))
    },
    {
      id: 'otx',
      name: 'AlienVault OTX',
      promise: queryAlienVaultOTX(indicator, type)
    }
  ];

  const [dnsRes, settledResults] = await Promise.all([
    dnsPromise,
    Promise.allSettled(tasks.map((t) => t.promise))
  ]);

  const feeds: LiveFeedSource[] = settledResults.map((r, idx) => {
    const task = tasks[idx];
    if (r.status === 'fulfilled') {
      return r.value;
    }
    return {
      id: task.id,
      name: task.name,
      indicator,
      status: 'unavailable',
      isThreatFound: false,
      errorCode: 'NETWORK_ERROR',
      details: `Live query failed unexpectedly: ${r.reason?.message || 'Unknown network error'}.`
    };
  });

  return {
    feeds,
    resolvedIps: dnsRes?.ips || []
  };
}

/**
 * 5. Compare & Correlate Live Intelligence with Local Threat Database
 */
export function correlateIntelligence(
  localRecord: ThreatIndicator | null,
  liveFeeds: LiveFeedSource[],
  options?: {
    liveFeedsEnabled?: boolean;
    localDbFailed?: boolean;
    localDbError?: string;
  }
): {
  matchStatus: MatchStatus;
  comparison: ComparisonSummary;
  elevatedSeverity: SeverityLevel;
  primaryCategory: string;
  sourceAttribution: string;
  combinedEvidence: string;
  reputationInfo: string;
} {
  const liveFeedsEnabled = options?.liveFeedsEnabled ?? true;
  const localDbFailed = Boolean(options?.localDbFailed);
  const localMatch = Boolean(localRecord);

  const configuredFeeds = liveFeeds.filter((f) => f.status !== 'not_configured');
  const successfulFeeds = liveFeeds.filter(
    (f) => f.status === 'detected_threat' || f.status === 'clean_or_no_reports'
  );
  const threatsDetected = liveFeeds.filter((f) => f.isThreatFound);
  const unavailableFeeds = liveFeeds.filter((f) => f.status === 'unavailable');
  const insufficientFeeds = liveFeeds.filter((f) => f.status === 'insufficient_evidence');

  let matchStatus: MatchStatus = 'No Match Found';
  let verdict: ComparisonSummary['correlationVerdict'] = 'No Match Across Sources';
  let summaryText = '';
  let elevatedSeverity: SeverityLevel = 'UNKNOWN';
  let primaryCategory = 'Unclassified / No Threat Record';

  if (localMatch && threatsDetected.length > 0) {
    matchStatus = 'Known Indicator Match';
    verdict = 'Multi-Source Correlated Threat';
    elevatedSeverity = 'HIGH RISK';
    primaryCategory = localRecord?.category || threatsDetected[0].category || 'Malware';
    summaryText = `Correlated Threat Confirmed: Detected simultaneously in local database and ${threatsDetected.length} live public intelligence feed(s) (${threatsDetected.map((t) => t.name).join(', ')}).`;
  } else if (!localMatch && threatsDetected.length > 0) {
    matchStatus = 'Known Indicator Match';
    verdict = 'Live Intelligence Detected Match';
    elevatedSeverity = threatsDetected.some((t) => t.severity === 'HIGH RISK')
      ? 'HIGH RISK'
      : threatsDetected.some((t) => t.severity === 'MEDIUM RISK')
      ? 'MEDIUM RISK'
      : 'LOW RISK';
    primaryCategory = threatsDetected[0].category || 'Malware';
    summaryText = `Live Threat Intelligence Match: Discovered active threat evidence in public feed (${threatsDetected.map((t) => t.name).join(', ')}), while local database contained no prior record.`;
  } else if (localMatch && threatsDetected.length === 0) {
    matchStatus = 'Known Indicator Match';
    verdict = 'Local Threat Record Match';
    elevatedSeverity = localRecord?.severity || 'HIGH RISK';
    primaryCategory = localRecord?.category || 'Malware';
    summaryText = `Local Threat Repository Match: Indicator matched local intelligence entry (${localRecord?.source})${
      liveFeedsEnabled ? ', with no new threat reports in responding live public feeds.' : ' (Live public feeds disabled by analyst).'
    }`;
  } else if (
    (localDbFailed && (!liveFeedsEnabled || successfulFeeds.length === 0)) ||
    (liveFeedsEnabled && unavailableFeeds.length > 0 && successfulFeeds.length === 0)
  ) {
    matchStatus = 'Lookup Failed';
    verdict = 'Feed Error / Incomplete Query';
    elevatedSeverity = 'UNKNOWN';
    primaryCategory = 'Lookup Error / Unverified';
    summaryText = localDbFailed
      ? `Database lookup failed (${options?.localDbError || 'connection error'}) and no live threat intelligence feeds succeeded. Do NOT treat this indicator as safe.`
      : `All queried external threat intelligence services failed or timed out (${unavailableFeeds.map((f) => f.name).join(', ')}). Absence of results due to lookup failure does NOT certify safety.`;
  } else if (
    liveFeedsEnabled &&
    (unavailableFeeds.length > 0 || (successfulFeeds.length === 0 && insufficientFeeds.length > 0) || configuredFeeds.length === 0)
  ) {
    matchStatus = 'Insufficient Evidence';
    verdict = 'Insufficient Evidence / Partial Lookup';
    elevatedSeverity = 'UNKNOWN';
    primaryCategory = 'Insufficient Evidence / Unverified';
    if (configuredFeeds.length === 0) {
      summaryText =
        'Local repository had no match, and no live external API providers are currently configured with API keys. Insufficient external intelligence to verify indicator reputation.';
    } else {
      summaryText = `No threat matches were found in responding sources (${successfulFeeds.map((f) => f.name).join(', ') || 'Local DB'}), but ${
        unavailableFeeds.length > 0
          ? `${unavailableFeeds.map((f) => f.name).join(', ')} was unavailable`
          : 'some providers lacked sufficient telemetry'
      }. Classified as INSUFFICIENT EVIDENCE under Zero-Trust policy.`;
    }
  } else {
    matchStatus = 'No Match Found';
    verdict = 'No Match Across Sources';
    elevatedSeverity = 'UNKNOWN';
    primaryCategory = 'Unclassified / No Threat Record';
    summaryText = liveFeedsEnabled
      ? 'No malicious records identified across local repository and responding public threat intelligence feeds. (Zero-trust notice: Unmatched indicators are never classified as safe).'
      : 'No malicious records identified in local threat intelligence repository (Live external feeds disabled). (Zero-trust notice: Unmatched indicators are never classified as safe).';
  }

  // Combine source attribution
  const sourceNames: string[] = [];
  if (localRecord) sourceNames.push(`Local DB (${localRecord.source})`);
  for (const f of threatsDetected) {
    sourceNames.push(`Live: ${f.name}`);
  }
  if (sourceNames.length === 0) {
    if (!liveFeedsEnabled) {
      sourceNames.push('Local Threat Database (No match)');
    } else if (successfulFeeds.length > 0) {
      sourceNames.push(`Local DB + ${successfulFeeds.map((f) => f.name).join(', ')} (No match)`);
    } else {
      sourceNames.push('Intelligence Pipeline (Lookup Incomplete)');
    }
  }

  // Reputation info summary from available feeds
  const repParts: string[] = [];
  if (localRecord) {
    repParts.push(`Local DB: ${localRecord.severity} (${localRecord.confidence}% confidence)`);
  }
  for (const f of liveFeeds) {
    if (f.reputationSummary) {
      repParts.push(`${f.name}: ${f.reputationSummary}`);
    }
  }
  const reputationInfo =
    repParts.length > 0
      ? repParts.join(' | ')
      : liveFeedsEnabled
      ? 'No external reputation score returned by queried providers'
      : 'Live reputation feeds disabled (Local DB lookup only)';

  // Combined evidence string
  let combinedEvidence = '';
  if (localRecord) {
    combinedEvidence += `[Local Intelligence]: ${localRecord.description} `;
  }
  for (const f of threatsDetected) {
    combinedEvidence += `[Live ${f.name}]: ${f.details} `;
  }
  if (!combinedEvidence) {
    combinedEvidence = summaryText;
  }

  return {
    matchStatus,
    comparison: {
      localMatch,
      liveFeedsChecked: successfulFeeds.length,
      liveFeedsReportingThreat: threatsDetected.length,
      correlationVerdict: verdict,
      summaryText
    },
    elevatedSeverity,
    primaryCategory,
    sourceAttribution: sourceNames.join(' · '),
    combinedEvidence: combinedEvidence.trim(),
    reputationInfo
  };
}
