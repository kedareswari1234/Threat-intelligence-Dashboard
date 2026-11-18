import { IndicatorType, LiveFeedSource, SeverityLevel, ComparisonSummary, ThreatIndicator } from '../types/threat';

/**
 * Live Threat Intelligence Integration Service
 * Connects to public threat intelligence APIs:
 * - URLhaus (abuse.ch) for malware URLs and domains (Open API, No Key Required)
 * - AbuseIPDB for IP reputation and abuse reporting (Requires ABUSEIPDB_API_KEY)
 * - AlienVault OTX for community pulses and threat indicators (Works with or without OTX_API_KEY)
 */

const REQUEST_TIMEOUT_MS = 4500;

async function fetchWithTimeout(url: string, options: RequestInit = {}, timeoutMs = REQUEST_TIMEOUT_MS): Promise<Response> {
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

/**
 * 1. URLhaus (abuse.ch) Threat Query
 * Supports both domain and IP host queries
 */
export async function queryURLhaus(indicator: string, type: IndicatorType): Promise<LiveFeedSource> {
  const startTime = Date.now();
  const feed: LiveFeedSource = {
    id: 'urlhaus',
    name: 'URLhaus (abuse.ch)',
    indicator,
    status: 'unavailable',
    isThreatFound: false,
    details: 'Querying URLhaus threat intelligence database...',
    attributionUrl: `https://urlhaus.abuse.ch/host/${indicator}/`
  };

  const apiKey = process.env.URLHAUS_API_KEY;
  if (!apiKey || apiKey === 'MY_URLHAUS_KEY' || apiKey.trim() === '') {
    feed.status = 'not_configured';
    feed.details = 'URLhaus Auth-Key not configured in environment (URLHAUS_API_KEY). Set key in .env or settings to query live abuse.ch malware telemetry.';
    feed.queryTimeMs = 0;
    return feed;
  }

  try {
    const params = new URLSearchParams();
    params.append('host', indicator);

    const headers: Record<string, string> = {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'application/json',
      'Auth-Key': apiKey
    };

    const res = await fetchWithTimeout('https://urlhaus-api.abuse.ch/v1/host/', {
      method: 'POST',
      headers,
      body: params.toString()
    });

    feed.queryTimeMs = Date.now() - startTime;

    if (!res.ok) {
      feed.status = 'unavailable';
      feed.details = `URLhaus API returned HTTP status ${res.status} (${res.statusText}).`;
      return feed;
    }

    const data = await res.json();
    feed.rawAttributes = {
      query_status: data.query_status,
      url_count: data.url_count,
      firstseen: data.firstseen
    };

    if (data.query_status === 'ok' && (data.url_count > 0 || (data.urls && data.urls.length > 0))) {
      feed.status = 'detected_threat';
      feed.isThreatFound = true;
      feed.confidence = 94;
      feed.category = 'Malware';
      feed.severity = 'HIGH RISK';
      feed.lastReported = data.firstseen || (data.urls?.[0]?.date_added) || new Date().toISOString();

      const topTags = (data.urls?.[0]?.tags || []).join(', ');
      feed.details = `Active malware distribution host identified in URLhaus! Associated with ${data.url_count} malicious payload URL(s). ${topTags ? `Tags: ${topTags}.` : ''} Threat classification: ${data.urls?.[0]?.threat || 'Malware staging'}.`;
    } else if (data.query_status === 'no_results') {
      feed.status = 'clean_or_no_reports';
      feed.isThreatFound = false;
      feed.details = 'No active malware hosting or distribution URLs cataloged in URLhaus database.';
    } else {
      feed.status = 'clean_or_no_reports';
      feed.isThreatFound = false;
      feed.details = `URLhaus response status: ${data.query_status || 'No malicious activity reported'}.`;
    }
  } catch (err: any) {
    feed.queryTimeMs = Date.now() - startTime;
    feed.status = 'unavailable';
    feed.details = `Lookup failed: ${err.name === 'AbortError' ? 'URLhaus request timed out (4.5s)' : err.message || 'Network connectivity error'}.`;
  }

  return feed;
}

/**
 * 2. AbuseIPDB IP Reputation Query
 * Only applicable for IP addresses
 */
export async function queryAbuseIPDB(ip: string): Promise<LiveFeedSource> {
  const startTime = Date.now();
  const apiKey = process.env.ABUSEIPDB_API_KEY;

  const feed: LiveFeedSource = {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    indicator: ip,
    status: 'unavailable',
    isThreatFound: false,
    details: 'Checking AbuseIPDB reputation score...',
    attributionUrl: `https://www.abuseipdb.com/check/${ip}`
  };

  if (!apiKey || apiKey === 'MY_ABUSEIPDB_KEY' || apiKey.trim() === '') {
    feed.status = 'not_configured';
    feed.details = 'AbuseIPDB API key not configured in environment (ABUSEIPDB_API_KEY). Set key in .env or Vercel settings to enable live IP reputation scoring.';
    feed.queryTimeMs = 0;
    return feed;
  }

  try {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
    const res = await fetchWithTimeout(url, {
      method: 'GET',
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      }
    });

    feed.queryTimeMs = Date.now() - startTime;

    if (!res.ok) {
      if (res.status === 401 || res.status === 403) {
        feed.status = 'unavailable';
        feed.details = 'AbuseIPDB authentication failed: Invalid or expired API key.';
      } else if (res.status === 429) {
        feed.status = 'unavailable';
        feed.details = 'AbuseIPDB rate limit reached (HTTP 429).';
      } else {
        feed.status = 'unavailable';
        feed.details = `AbuseIPDB returned HTTP error ${res.status}.`;
      }
      return feed;
    }

    const json = await res.json();
    const data = json?.data;

    if (!data) {
      feed.status = 'unavailable';
      feed.details = 'Malformed response received from AbuseIPDB.';
      return feed;
    }

    const score = Number(data.abuseConfidenceScore || 0);
    const totalReports = Number(data.totalReports || 0);
    feed.confidence = score;
    feed.lastReported = data.lastReportedAt || undefined;
    feed.rawAttributes = {
      abuseConfidenceScore: score,
      totalReports,
      countryCode: data.countryCode,
      isp: data.isp,
      usageType: data.usageType
    };

    if (score >= 50 || totalReports >= 10) {
      feed.status = 'detected_threat';
      feed.isThreatFound = true;
      feed.severity = score >= 80 ? 'HIGH RISK' : 'MEDIUM RISK';
      feed.category = 'Suspicious Activity';
      feed.details = `High abuse confidence score: ${score}%. Reported by ${totalReports} distinct security operators across external networks. ISP: ${data.isp || 'N/A'}.`;
    } else if (totalReports > 0) {
      feed.status = 'detected_threat';
      feed.isThreatFound = true;
      feed.severity = 'LOW RISK';
      feed.category = 'Suspicious Activity';
      feed.details = `Low-level abuse reports filed (${totalReports} reports in 90 days). Abuse confidence score: ${score}%.`;
    } else {
      feed.status = 'clean_or_no_reports';
      feed.isThreatFound = false;
      feed.details = `0 abuse reports recorded in AbuseIPDB over the past 90 days. Confidence score: 0%.`;
    }
  } catch (err: any) {
    feed.queryTimeMs = Date.now() - startTime;
    feed.status = 'unavailable';
    feed.details = `Lookup failed: ${err.name === 'AbortError' ? 'AbuseIPDB request timed out' : err.message || 'Network error'}.`;
  }

  return feed;
}

/**
 * 3. AlienVault OTX Community Pulse Query
 * Supports both IP addresses and domain names
 */
export async function queryAlienVaultOTX(indicator: string, type: IndicatorType): Promise<LiveFeedSource> {
  const startTime = Date.now();
  const apiKey = process.env.OTX_API_KEY;

  const feed: LiveFeedSource = {
    id: 'otx',
    name: 'AlienVault OTX',
    indicator,
    status: 'unavailable',
    isThreatFound: false,
    details: 'Querying AlienVault OTX community pulses...',
    attributionUrl: `https://otx.alienvault.com/indicator/${type === 'ip' ? 'ip' : 'domain'}/${indicator}`
  };

  try {
    const isIPv6 = indicator.includes(':');
    let endpointType = type === 'ip' ? (isIPv6 ? 'IPv6' : 'IPv4') : 'domain';
    const url = `https://otx.alienvault.com/api/v1/indicators/${endpointType}/${encodeURIComponent(indicator)}/general`;

    const headers: Record<string, string> = {
      'Accept': 'application/json'
    };
    if (apiKey && apiKey !== 'MY_OTX_KEY' && apiKey.trim() !== '') {
      headers['X-OTX-API-KEY'] = apiKey;
    }

    const res = await fetchWithTimeout(url, { method: 'GET', headers });
    feed.queryTimeMs = Date.now() - startTime;

    if (!res.ok) {
      feed.status = 'unavailable';
      feed.details = `AlienVault OTX API returned HTTP ${res.status} (${res.statusText}).`;
      return feed;
    }

    const data = await res.json();
    const pulseCount = Number(data?.pulse_info?.count || 0);
    const pulses = data?.pulse_info?.pulses || [];

    feed.rawAttributes = {
      pulseCount,
      reputation: data?.reputation,
      pulseNames: pulses.slice(0, 3).map((p: any) => p.name)
    };

    if (pulseCount > 0) {
      feed.status = 'detected_threat';
      feed.isThreatFound = true;
      feed.confidence = Math.min(96, 60 + pulseCount * 8);
      feed.severity = pulseCount >= 3 ? 'HIGH RISK' : 'MEDIUM RISK';
      feed.category = 'Command and Control';
      feed.lastReported = pulses[0]?.modified || pulses[0]?.created || new Date().toISOString();

      const pulseSummary = pulses.slice(0, 2).map((p: any) => `"${p.name}"`).join(', ');
      feed.details = `Indicator actively cataloged in ${pulseCount} AlienVault OTX threat intelligence pulses. Top pulses: ${pulseSummary}.`;
    } else {
      feed.status = 'clean_or_no_reports';
      feed.isThreatFound = false;
      feed.details = 'No threat pulses or adversary campaigns linked to this indicator in AlienVault OTX.';
    }
  } catch (err: any) {
    feed.queryTimeMs = Date.now() - startTime;
    feed.status = 'unavailable';
    feed.details = `Lookup failed: ${err.name === 'AbortError' ? 'AlienVault OTX request timed out' : err.message || 'Network error'}.`;
  }

  return feed;
}

/**
 * 4. Query All Configured Live Feeds Simultaneously
 */
export async function queryAllLiveFeeds(indicator: string, type: IndicatorType): Promise<LiveFeedSource[]> {
  const promises: Promise<LiveFeedSource>[] = [];

  // 1. URLhaus (Domain & IP)
  promises.push(queryURLhaus(indicator, type));

  // 2. AbuseIPDB (IP Only)
  if (type === 'ip') {
    promises.push(queryAbuseIPDB(indicator));
  }

  // 3. AlienVault OTX (Domain & IP)
  promises.push(queryAlienVaultOTX(indicator, type));

  const results = await Promise.allSettled(promises);
  return results.map((r, idx) => {
    if (r.status === 'fulfilled') {
      return r.value;
    } else {
      return {
        id: idx === 0 ? 'urlhaus' : idx === 1 ? 'abuseipdb' : 'otx',
        name: idx === 0 ? 'URLhaus' : idx === 1 ? 'AbuseIPDB' : 'AlienVault OTX',
        indicator,
        status: 'unavailable',
        isThreatFound: false,
        details: `Live query threw an unhandled error: ${r.reason?.message || 'Unknown network error'}.`
      };
    }
  });
}

/**
 * 5. Compare & Correlate Live Intelligence with Local Threat Database
 */
export function correlateIntelligence(
  localRecord: ThreatIndicator | null,
  liveFeeds: LiveFeedSource[]
): {
  comparison: ComparisonSummary;
  elevatedSeverity: SeverityLevel;
  primaryCategory: string;
  sourceAttribution: string;
  combinedEvidence: string;
} {
  const localMatch = Boolean(localRecord);
  const activeFeeds = liveFeeds.filter(f => f.status !== 'not_configured');
  const threatsDetected = liveFeeds.filter(f => f.isThreatFound);
  const hasUnavailableFeeds = liveFeeds.some(f => f.status === 'unavailable');

  let verdict: ComparisonSummary['correlationVerdict'] = 'No Match Across Sources';
  let summaryText = '';
  let elevatedSeverity: SeverityLevel = 'UNKNOWN';
  let primaryCategory = 'Unclassified / No Threat Record';

  if (localMatch && threatsDetected.length > 0) {
    verdict = 'Multi-Source Correlated Threat';
    elevatedSeverity = 'HIGH RISK';
    primaryCategory = localRecord?.category || threatsDetected[0].category || 'Malware';
    summaryText = `Correlated Threat Confirmed: Detected simultaneously in local database and ${threatsDetected.length} live public intelligence feed(s) (${threatsDetected.map(t => t.name).join(', ')}).`;
  } else if (!localMatch && threatsDetected.length > 0) {
    verdict = 'Live Intelligence Detected Match';
    elevatedSeverity = threatsDetected.some(t => t.severity === 'HIGH RISK') ? 'HIGH RISK' : 'MEDIUM RISK';
    primaryCategory = threatsDetected[0].category || 'Malware';
    summaryText = `Live Threat Intelligence Match: Discovered active malicious activity in public feed (${threatsDetected.map(t => t.name).join(', ')}), while local database contained no prior record.`;
  } else if (localMatch && threatsDetected.length === 0) {
    verdict = 'Local Threat Record Match';
    elevatedSeverity = localRecord?.severity || 'HIGH RISK';
    primaryCategory = localRecord?.category || 'Malware';
    summaryText = `Local Threat Repository Match: Indicator matched local intelligence entry (${localRecord?.source}), with no new live reports in queried public feeds.`;
  } else {
    verdict = hasUnavailableFeeds ? 'Feed Error / Incomplete Query' : 'No Match Across Sources';
    elevatedSeverity = 'UNKNOWN';
    primaryCategory = 'Unclassified / No Threat Record';
    summaryText = hasUnavailableFeeds
      ? 'No malicious matches found in responding feeds, but one or more external threat feeds were unavailable. (Absence of threat records does not guarantee safety).'
      : 'No malicious records identified across local repository and public threat intelligence feeds. (Zero-trust notice: Unmatched indicators are never classified as safe).';
  }

  // Combine source attribution
  const sourceNames: string[] = [];
  if (localRecord) sourceNames.push(`Local DB (${localRecord.source})`);
  for (const f of threatsDetected) {
    sourceNames.push(`Live: ${f.name}`);
  }
  if (sourceNames.length === 0) {
    sourceNames.push('Multi-Source Feed Analysis (No match)');
  }

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
    comparison: {
      localMatch,
      liveFeedsChecked: activeFeeds.length,
      liveFeedsReportingThreat: threatsDetected.length,
      correlationVerdict: verdict,
      summaryText
    },
    elevatedSeverity,
    primaryCategory,
    sourceAttribution: sourceNames.join(' · '),
    combinedEvidence: combinedEvidence.trim()
  };
}
