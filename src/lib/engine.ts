import { db } from '../db/db';
import { validateIndicator } from './validation';
import { AnalysisResult, IndicatorType, LiveFeedSource, MatchStatus, SeverityLevel } from '../types/threat';
import { queryAllLiveFeeds, correlateIntelligence } from './liveIntel';

export interface AnalyzeOptions {
  analyst?: string;
  notes?: string;
  expectedType?: IndicatorType;
  skipLiveFeeds?: boolean;
}

export async function analyzeIndicator(
  rawInput: string,
  options: AnalyzeOptions = {}
): Promise<AnalysisResult> {
  const analyst = options.analyst || 'SOC Analyst';
  const notes = options.notes || '';
  const liveFeedsEnabled = !options.skipLiveFeeds;
  const warnings: string[] = [];

  // Step 1: Validate User Input
  const validation = validateIndicator(rawInput, options.expectedType);

  if (!validation.isValid || !validation.type) {
    const errMsg = validation.error || 'Input validation failed.';
    console.warn(`[Engine] Input validation rejected: type=${options.expectedType || 'auto'}, reason=${errMsg}`);
    return {
      indicator: rawInput.trim(),
      type: options.expectedType || 'ip',
      isValid: false,
      validationStatus: `Invalid ${options.expectedType === 'domain' ? 'Domain' : 'Indicator'} Format`,
      validationError: errMsg,
      matchStatus: 'Lookup Failed',
      severity: 'UNKNOWN',
      category: 'Validation Error',
      evidence: errMsg,
      source: 'Input Sanitizer & Validator',
      confidence: 0,
      reputationInfo: 'Validation failed before intelligence lookup',
      alertCreated: false,
      investigationId: `err-${Date.now()}`,
      timestamp: new Date().toISOString(),
      isSynthetic: false,
      diagnostics: {
        liveFeedsEnabled,
        warnings: [errMsg]
      }
    };
  }

  const sanitized = validation.sanitized;
  const indicatorType = validation.type;

  const validationStatus =
    indicatorType === 'domain'
      ? `Valid Domain (FQDN${validation.details?.tld ? `, TLD: .${validation.details.tld}` : ''})`
      : `Valid ${validation.subType?.toUpperCase() || 'IP'}${
          validation.details?.isPrivate
            ? ' (RFC 1918 Private)'
            : validation.details?.isLoopback
            ? ' (Loopback)'
            : ''
        }`;

  console.info(
    `[Engine] Starting analysis: indicator="${sanitized}" type=${indicatorType} liveFeedsEnabled=${liveFeedsEnabled}`
  );

  // Step 2: Query Local Database and Live Threat Intelligence Feeds in Parallel
  try {
    const [dbLookup, liveResult] = await Promise.all([
      db.findThreatByIndicatorDetailed(sanitized).catch((err) => {
        const msg = err?.message || 'Unknown local database error';
        console.error(`[Engine] Database lookup failed for "${sanitized}":`, msg);
        return {
          threat: null,
          dbConnected: false,
          provider: 'Database Error',
          error: `Database connection failed: ${msg}`
        };
      }),
      liveFeedsEnabled
        ? queryAllLiveFeeds(sanitized, indicatorType).catch((err) => {
            console.error(`[Engine] Live feeds pipeline error for "${sanitized}":`, err?.message || err);
            return { feeds: [] as LiveFeedSource[], resolvedIps: [] as string[] };
          })
        : Promise.resolve({ feeds: [] as LiveFeedSource[], resolvedIps: [] as string[] })
    ]);

    const matchedThreat = dbLookup.threat;
    const liveFeeds = liveResult.feeds;
    const resolvedIps = liveResult.resolvedIps;

    if (dbLookup.error) {
      warnings.push(dbLookup.error);
    }

    for (const feed of liveFeeds) {
      if (feed.status === 'unavailable' || feed.status === 'not_configured') {
        warnings.push(`${feed.name}: ${feed.details}`);
      }
    }

    // Step 3: Correlate Findings Between Local DB and Live Public Feeds
    const correlation = correlateIntelligence(matchedThreat, liveFeeds, {
      liveFeedsEnabled,
      localDbFailed: !dbLookup.dbConnected,
      localDbError: dbLookup.error
    });

    const hasLiveThreat = liveFeeds.some((f) => f.isThreatFound);
    const matchStatus: MatchStatus = correlation.matchStatus;
    const severity: SeverityLevel = correlation.elevatedSeverity;
    const category = correlation.primaryCategory;
    const source = correlation.sourceAttribution;

    // Highest reported confidence score
    const feedConfidences = liveFeeds
      .filter((f) => f.confidence !== undefined && f.isThreatFound)
      .map((f) => f.confidence as number);
    const maxLiveConfidence = feedConfidences.length > 0 ? Math.max(...feedConfidences) : 0;
    const confidence =
      matchStatus === 'Known Indicator Match'
        ? Math.max(matchedThreat?.confidence || 0, maxLiveConfidence || 75)
        : 0;

    // Country & ASN enrichment
    const abuseIPFeed = liveFeeds.find((f) => f.id === 'abuseipdb' && f.rawAttributes);
    const asn =
      matchedThreat?.asn ||
      (abuseIPFeed?.rawAttributes?.isp ? `ISP: ${abuseIPFeed.rawAttributes.isp}` : undefined);
    const country = matchedThreat?.country || abuseIPFeed?.rawAttributes?.countryCode || undefined;
    const isSynthetic = Boolean(matchedThreat?.isSynthetic && !hasLiveThreat);

    // Build evidence text
    let evidence = correlation.combinedEvidence;
    if (validation.details?.isPrivate) {
      evidence += ' [Notice: Indicator belongs to an RFC 1918 Private Network range.]';
    } else if (validation.details?.isLoopback) {
      evidence += ' [Notice: Indicator is a Loopback interface.]';
    }

    // Step 4: Automatically trigger Security Alert ONLY when supporting threat intelligence evidence matches
    let alertCreated = false;
    let alertId: string | undefined = undefined;
    let isDuplicateAlertSuppressed: boolean | undefined = undefined;
    let alertOccurrenceCount: number | undefined = undefined;

    if (
      matchStatus === 'Known Indicator Match' &&
      (severity === 'HIGH RISK' || severity === 'MEDIUM RISK' || severity === 'LOW RISK')
    ) {
      try {
        const alertResult = await db.createAlert({
          indicator: sanitized,
          type: indicatorType,
          severity,
          category,
          description: `Threat detection (${correlation.comparison.correlationVerdict}): ${evidence.slice(0, 240)}`,
          evidence,
          source
        });
        alertCreated = true;
        alertId = alertResult.alert.id;
        isDuplicateAlertSuppressed = alertResult.isDuplicateSuppressed;
        alertOccurrenceCount = alertResult.alert.occurrenceCount;
      } catch (alertErr: any) {
        console.warn(`[Engine] Alert creation skipped for "${sanitized}":`, alertErr?.message);
        warnings.push('Automated alert persistence encountered a database error.');
      }
    }

    // Step 5: Log to Investigation History Audit Trail (non-fatal if DB write fails)
    let investigationId = `inv-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    let timestamp = new Date().toISOString();
    try {
      const logged = await db.logInvestigation({
        indicator: sanitized,
        type: indicatorType,
        matchStatus,
        category,
        severity,
        source,
        confidence,
        evidence,
        asn,
        country,
        notes: notes || `Investigated indicator (${correlation.comparison.correlationVerdict})`,
        threatId: matchedThreat?.id,
        analyst,
        isSynthetic,
        liveFeeds,
        comparison: correlation.comparison
      });
      investigationId = logged.id;
      timestamp = logged.timestamp;
    } catch (logErr: any) {
      console.warn(`[Engine] History logging failed for "${sanitized}":`, logErr?.message);
      warnings.push('Investigation completed, but audit history persistence failed.');
    }

    console.info(
      `[Engine] Completed analysis for "${sanitized}": matchStatus="${matchStatus}" severity="${severity}" db="${dbLookup.provider}" feedsChecked=${correlation.comparison.liveFeedsChecked}`
    );

    return {
      indicator: sanitized,
      type: indicatorType,
      isValid: true,
      validationStatus,
      matchStatus,
      threatRecord: matchedThreat || undefined,
      severity,
      category,
      evidence,
      source,
      confidence,
      reputationInfo: correlation.reputationInfo,
      resolvedIps: resolvedIps.length > 0 ? resolvedIps : undefined,
      alertCreated,
      alertId,
      isDuplicateAlertSuppressed,
      alertOccurrenceCount,
      investigationId,
      timestamp,
      asn,
      country,
      isSynthetic,
      liveFeeds,
      comparison: correlation.comparison,
      databaseStatus: {
        provider: dbLookup.provider,
        connected: dbLookup.dbConnected,
        localMatchChecked: true,
        error: dbLookup.error
      },
      diagnostics: {
        liveFeedsEnabled,
        warnings
      }
    };
  } catch (error: any) {
    const errorMessage =
      error?.message || 'Database or intelligence pipeline error during indicator query.';
    console.error(`[Engine] Fatal error analyzing "${sanitized}":`, errorMessage);

    return {
      indicator: sanitized,
      type: indicatorType,
      isValid: true,
      validationStatus,
      matchStatus: 'Lookup Failed',
      severity: 'UNKNOWN',
      category: 'Lookup Error',
      evidence: `Query operation could not be completed: ${errorMessage}. (Absence of confirmation does not certify indicator safety).`,
      source: 'System Intelligence Pipeline',
      confidence: 0,
      reputationInfo: 'Lookup failed before reputation could be retrieved',
      alertCreated: false,
      investigationId: `err-${Date.now()}`,
      timestamp: new Date().toISOString(),
      isSynthetic: false,
      diagnostics: {
        liveFeedsEnabled,
        warnings: [errorMessage]
      }
    };
  }
}
