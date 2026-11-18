import { db } from '../db/db';
import { parseLogText, MAX_LOG_FILE_SIZE_BYTES } from './logParser';
import {
  ExtractedLogIndicator,
  LogAnalysisSession,
  MatchStatus,
  SeverityLevel,
  LiveFeedSource
} from '../types/threat';
import { queryAllLiveFeeds, correlateIntelligence } from './liveIntel';

export interface RunLogAnalysisOptions {
  fileName?: string;
  fileSize?: number;
  analyst?: string;
  skipLiveFeeds?: boolean;
}

/**
 * Executes a full network log analysis pipeline:
 * 1. Parses raw log text and detects format
 * 2. Extracts and validates unique IP and domain indicators
 * 3. Cross-references against local threat intelligence database & live feeds
 * 4. Applies Zero-Trust principles (unmatched indicators remain UNKNOWN, never marked safe)
 * 5. Automatically generates Security Alerts for matched high/medium/low threats
 * 6. Persists session in database
 */
export async function analyzeNetworkLog(
  rawText: string,
  options: RunLogAnalysisOptions = {}
): Promise<LogAnalysisSession> {
  const fileName = options.fileName || 'uploaded_network_log.log';
  const fileSize = options.fileSize || Buffer.byteLength(rawText, 'utf8');
  const analyst = options.analyst || 'SOC Analyst';
  const skipLiveFeeds = Boolean(options.skipLiveFeeds);

  if (fileSize > MAX_LOG_FILE_SIZE_BYTES) {
    throw new Error(`File size (${Math.round(fileSize / 1024)} KB) exceeds the maximum allowed limit of 5 MB.`);
  }

  // Step 1: Parse and extract indicators
  const parsed = parseLogText(rawText);

  // Step 2: Cross-reference indicators in batch
  const correlatedIndicators: ExtractedLogIndicator[] = [];
  let threatMatchesCount = 0;
  let unmatchedCount = 0;
  let lookupFailuresCount = 0;
  let highRiskCount = 0;
  let mediumRiskCount = 0;
  let lowRiskCount = 0;

  // Process unique indicators (limit to top 150 to ensure responsive latency if massive)
  const targetIndicators = parsed.uniqueIndicators.slice(0, 150);

  for (const item of targetIndicators) {
    try {
      // Query local threat DB
      const localThreat = await db.findThreatByIndicator(item.indicator).catch((err) => {
        console.warn(`[LogAnalysis] Error checking local DB for ${item.indicator}:`, err);
        return null;
      });

      // Optionally query live public feeds (URLhaus, AbuseIPDB, AlienVault OTX)
      // For efficiency during log analysis, we query live feeds if skipLiveFeeds is false
      let liveFeeds: LiveFeedSource[] = [];
      if (!skipLiveFeeds) {
        try {
          liveFeeds = await queryAllLiveFeeds(item.indicator, item.type);
        } catch (e) {
          console.warn(`[LogAnalysis] Live feed query error for ${item.indicator}:`, e);
          liveFeeds = [];
        }
      }

      const hasLiveThreat = liveFeeds.some((f) => f.isThreatFound);
      const isMatched = Boolean(localThreat) || hasLiveThreat;

      if (isMatched) {
        threatMatchesCount++;
        const correlation = correlateIntelligence(localThreat, liveFeeds);
        const severity: SeverityLevel = correlation.elevatedSeverity;
        const category = correlation.primaryCategory;
        const source = correlation.sourceAttribution;

        if (severity === 'HIGH RISK') highRiskCount++;
        else if (severity === 'MEDIUM RISK') mediumRiskCount++;
        else if (severity === 'LOW RISK') lowRiskCount++;

        const feedConfidences = liveFeeds.filter((f) => f.confidence !== undefined).map((f) => f.confidence as number);
        const maxLiveConfidence = feedConfidences.length > 0 ? Math.max(...feedConfidences) : 0;
        const confidence = Math.max(localThreat?.confidence || 0, maxLiveConfidence || 80);

        let evidenceText = `[THREAT DETECTED IN LOG] ${correlation.combinedEvidence}. Observed ${item.occurrences} time(s) in roles: ${item.roles.join(', ')}.`;
        if (item.ports && item.ports.length > 0) {
          evidenceText += ` Target port(s): ${item.ports.join(', ')}.`;
        }
        if (item.protocols && item.protocols.length > 0) {
          evidenceText += ` Protocol(s): ${item.protocols.join(', ')}.`;
        }

        // Automated Alert Generation for matched threats
        let alertCreated = false;
        let alertId: string | undefined = undefined;

        try {
          const alertResult = await db.createAlert({
            indicator: item.indicator,
            type: item.type,
            severity,
            category,
            description: `Network log analysis detected known malicious indicator ${item.indicator} [${category}] with ${item.occurrences} observed interaction(s).`,
            evidence: evidenceText,
            source: `Network Log Analysis (${source})`
          });
          alertCreated = !alertResult.isDuplicateSuppressed;
          alertId = alertResult.alert.id;
        } catch (alertErr) {
          console.warn('[LogAnalysis] Alert creation failed for indicator:', item.indicator, alertErr);
        }

        correlatedIndicators.push({
          ...item,
          matchStatus: 'Known Indicator Match',
          severity,
          category,
          source,
          confidence,
          evidence: evidenceText,
          asn: localThreat?.asn,
          country: localThreat?.country,
          isSynthetic: Boolean(localThreat?.isSynthetic && !hasLiveThreat),
          alertCreated,
          alertId,
          liveFeeds: liveFeeds.length > 0 ? liveFeeds : undefined
        });
      } else {
        // Zero-Trust: Do NOT mark as safe.
        unmatchedCount++;
        const rolesDesc = item.roles.join(', ');
        const zeroTrustEvidence = `Extracted from log in role (${rolesDesc}) across ${item.occurrences} event(s). No corresponding threat intelligence signatures found in local repository or external threat feeds. ZERO-TRUST NOTE: Unmatched indicators are classified as UNKNOWN risk and are not confirmed clean.`;

        correlatedIndicators.push({
          ...item,
          matchStatus: 'No Match Found',
          severity: 'UNKNOWN',
          category: 'Uncorrelated Traffic',
          source: 'Network Log Extraction (Zero-Trust Evaluation)',
          confidence: 0,
          evidence: zeroTrustEvidence,
          liveFeeds: liveFeeds.length > 0 ? liveFeeds : undefined
        });
      }
    } catch (err: any) {
      console.error(`[LogAnalysis] Error processing indicator ${item.indicator}:`, err);
      lookupFailuresCount++;
      correlatedIndicators.push({
        ...item,
        matchStatus: 'Lookup Failed',
        severity: 'UNKNOWN',
        category: 'Lookup Error',
        source: 'Analysis Engine',
        confidence: 0,
        evidence: `Automated lookup encountered an error during threat correlation: ${err?.message || 'Unknown query failure'}.`
      });
    }
  }

  // Sort correlated indicators: High risk first, then medium, then low, then unknown
  correlatedIndicators.sort((a, b) => {
    const score = (sev: SeverityLevel) => {
      if (sev === 'HIGH RISK') return 4;
      if (sev === 'MEDIUM RISK') return 3;
      if (sev === 'LOW RISK') return 2;
      return 1;
    };
    if (score(b.severity) !== score(a.severity)) {
      return score(b.severity) - score(a.severity);
    }
    return b.occurrences - a.occurrences;
  });

  const session: LogAnalysisSession = {
    id: `log-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    fileName,
    fileSize,
    logFormat: parsed.detectedFormat,
    totalLines: parsed.totalLines,
    parsedEntriesCount: parsed.parsedEntriesCount,
    totalExtracted: parsed.totalExtracted,
    uniqueIndicatorsCount: targetIndicators.length,
    threatMatchesCount,
    unmatchedCount,
    lookupFailuresCount,
    highRiskCount,
    mediumRiskCount,
    lowRiskCount,
    timestamp: new Date().toISOString(),
    analyst,
    indicators: correlatedIndicators,
    sampleLines: parsed.sampleLines
  };

  // Persist session to database
  await db.saveLogAnalysis(session);

  return session;
}
