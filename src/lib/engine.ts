import { db } from '../db/db';
import { validateIndicator } from './validation';
import { AnalysisResult, IndicatorType, MatchStatus, SeverityLevel } from '../types/threat';
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

  // Step 1: Validate User Input
  const validation = validateIndicator(rawInput, options.expectedType);

  if (!validation.isValid || !validation.type) {
    return {
      indicator: rawInput.trim(),
      type: options.expectedType || 'ip',
      isValid: false,
      validationError: validation.error || 'Input validation failed.',
      matchStatus: 'Lookup Failed',
      severity: 'UNKNOWN',
      category: 'Validation Error',
      evidence: validation.error || 'The submitted indicator failed format verification.',
      source: 'Input Sanitizer & Validator',
      confidence: 0,
      alertCreated: false,
      investigationId: `err-${Date.now()}`,
      timestamp: new Date().toISOString(),
      isSynthetic: false
    };
  }

  const sanitized = validation.sanitized;
  const indicatorType = validation.type;

  // Step 2: Query Local Database and Live Threat Intelligence Feeds in Parallel
  try {
    const [matchedThreat, liveFeeds] = await Promise.all([
      db.findThreatByIndicator(sanitized).catch((err) => {
        console.warn('[Engine] Error querying local DB:', err);
        return null;
      }),
      options.skipLiveFeeds
        ? Promise.resolve([])
        : queryAllLiveFeeds(sanitized, indicatorType).catch((err) => {
            console.warn('[Engine] Error querying live feeds:', err);
            return [];
          })
    ]);

    // Step 3: Correlate Findings Between Local DB and Live Public Feeds
    const correlation = correlateIntelligence(matchedThreat, liveFeeds);
    const hasLiveThreat = liveFeeds.some((f) => f.isThreatFound);
    const isMatched = Boolean(matchedThreat) || hasLiveThreat;

    const matchStatus: MatchStatus = isMatched ? 'Known Indicator Match' : 'No Match Found';
    const severity: SeverityLevel = correlation.elevatedSeverity;
    const category = correlation.primaryCategory;
    const source = correlation.sourceAttribution;

    // Highest reported confidence score
    const feedConfidences = liveFeeds.filter((f) => f.confidence !== undefined).map((f) => f.confidence as number);
    const maxLiveConfidence = feedConfidences.length > 0 ? Math.max(...feedConfidences) : 0;
    const confidence = isMatched
      ? Math.max(matchedThreat?.confidence || 0, maxLiveConfidence || 75)
      : 0;

    // Country & ASN enrichment
    const abuseIPFeed = liveFeeds.find((f) => f.id === 'abuseipdb' && f.rawAttributes);
    const asn = matchedThreat?.asn || (abuseIPFeed?.rawAttributes?.isp ? `ISP: ${abuseIPFeed.rawAttributes.isp}` : undefined);
    const country = matchedThreat?.country || abuseIPFeed?.rawAttributes?.countryCode || undefined;
    const isSynthetic = Boolean(matchedThreat?.isSynthetic && !hasLiveThreat);

    // Build evidence text
    let evidence = correlation.combinedEvidence;
    if (validation.details?.isPrivate) {
      evidence += ' [Notice: Indicator belongs to an RFC 1918 Private Network range.]';
    } else if (validation.details?.isLoopback) {
      evidence += ' [Notice: Indicator is a Loopback interface.]';
    }

    // Step 4: Automatically trigger Security Alert when threat intelligence evidence matches
    let alertCreated = false;
    let alertId: string | undefined = undefined;
    let isDuplicateAlertSuppressed: boolean | undefined = undefined;
    let alertOccurrenceCount: number | undefined = undefined;

    if (isMatched && (severity === 'HIGH RISK' || severity === 'MEDIUM RISK' || severity === 'LOW RISK')) {
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
    }

    // Step 5: Log to Investigation History Audit Trail
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

    return {
      indicator: sanitized,
      type: indicatorType,
      isValid: true,
      matchStatus,
      threatRecord: matchedThreat || undefined,
      severity,
      category,
      evidence,
      source,
      confidence,
      alertCreated,
      alertId,
      isDuplicateAlertSuppressed,
      alertOccurrenceCount,
      investigationId: logged.id,
      timestamp: logged.timestamp,
      asn,
      country,
      isSynthetic,
      liveFeeds,
      comparison: correlation.comparison
    };
  } catch (error: any) {
    const matchStatus: MatchStatus = 'Lookup Failed';
    const severity: SeverityLevel = 'UNKNOWN';
    const errorMessage = error?.message || 'Database or intelligence pipeline error during indicator query.';

    return {
      indicator: sanitized,
      type: indicatorType,
      isValid: true,
      matchStatus,
      severity,
      category: 'Lookup Error',
      evidence: `Query operation could not be completed: ${errorMessage}. (Absence of confirmation does not certify indicator safety).`,
      source: 'System Intelligence Pipeline',
      confidence: 0,
      alertCreated: false,
      investigationId: `err-${Date.now()}`,
      timestamp: new Date().toISOString(),
      isSynthetic: false
    };
  }
}
