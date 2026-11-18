export type IndicatorType = 'ip' | 'domain';

export type ThreatCategory =
  | 'Phishing'
  | 'Malware'
  | 'Suspicious Activity'
  | 'Command and Control'
  | 'Ransomware'
  | 'Other';

export type SeverityLevel = 'HIGH RISK' | 'MEDIUM RISK' | 'LOW RISK' | 'UNKNOWN';

export type AlertStatus = 'Active' | 'Reviewed' | 'Resolved';

export type MatchStatus =
  | 'Known Indicator Match'
  | 'No Match Found'
  | 'Lookup Failed'
  | 'Insufficient Evidence';

export interface ThreatIndicator {
  id: string;
  indicator: string;
  type: IndicatorType;
  category: ThreatCategory;
  severity: SeverityLevel;
  source: string;
  description: string;
  confidence: number;
  asn: string;
  country: string;
  isSynthetic: boolean;
  createdAt: string;
  updatedAt: string;
}

export type FeedErrorCode =
  | 'API_KEY_MISSING'
  | 'AUTH_ERROR'
  | 'RATE_LIMITED'
  | 'TIMEOUT'
  | 'SERVICE_UNAVAILABLE'
  | 'MALFORMED_RESPONSE'
  | 'DNS_RESOLUTION_FAILED'
  | 'UNSUPPORTED_INDICATOR'
  | 'NETWORK_ERROR';

export interface LiveFeedSource {
  id: 'urlhaus' | 'abuseipdb' | 'otx';
  name: string;
  indicator: string;
  status:
    | 'available'
    | 'detected_threat'
    | 'clean_or_no_reports'
    | 'unavailable'
    | 'not_configured'
    | 'insufficient_evidence';
  isThreatFound: boolean;
  confidence?: number;
  category?: string;
  severity?: SeverityLevel;
  lastReported?: string;
  details: string;
  errorCode?: FeedErrorCode;
  resolvedIp?: string;
  reputationSummary?: string;
  rawAttributes?: Record<string, any>;
  queryTimeMs?: number;
  attributionUrl?: string;
}

export interface ComparisonSummary {
  localMatch: boolean;
  liveFeedsChecked: number;
  liveFeedsReportingThreat: number;
  correlationVerdict:
    | 'Multi-Source Correlated Threat'
    | 'Live Intelligence Detected Match'
    | 'Local Threat Record Match'
    | 'No Match Across Sources'
    | 'Feed Error / Incomplete Query'
    | 'Insufficient Evidence / Partial Lookup';
  summaryText: string;
}

export interface InvestigationRecord {
  id: string;
  indicator: string;
  type: IndicatorType;
  matchStatus: MatchStatus;
  category: string;
  severity: SeverityLevel;
  source: string;
  confidence: number;
  evidence: string;
  asn?: string;
  country?: string;
  notes?: string;
  threatId?: string;
  timestamp: string;
  analyst: string;
  isSynthetic: boolean;
  liveFeeds?: LiveFeedSource[];
  comparison?: ComparisonSummary;
}

export interface SecurityAlert {
  id: string;
  indicator: string;
  type: IndicatorType;
  severity: SeverityLevel;
  category: string;
  description: string;
  evidence: string;
  source: string;
  status: AlertStatus;
  createdAt: string;
  lastObservedAt: string;
  occurrenceCount: number;
  reviewedAt?: string;
  reviewedBy?: string;
  resolutionNotes?: string;
}

export interface AnalysisResult {
  indicator: string;
  type: IndicatorType;
  isValid: boolean;
  validationStatus?: string;
  validationError?: string;
  matchStatus: MatchStatus;
  threatRecord?: ThreatIndicator;
  severity: SeverityLevel;
  category: string;
  evidence: string;
  source: string;
  confidence: number;
  reputationInfo?: string;
  resolvedIps?: string[];
  alertCreated: boolean;
  alertId?: string;
  isDuplicateAlertSuppressed?: boolean;
  alertOccurrenceCount?: number;
  investigationId: string;
  timestamp: string;
  asn?: string;
  country?: string;
  isSynthetic: boolean;
  liveFeeds?: LiveFeedSource[];
  comparison?: ComparisonSummary;
  databaseStatus?: {
    provider: string;
    connected: boolean;
    localMatchChecked: boolean;
    error?: string;
  };
  diagnostics?: {
    liveFeedsEnabled: boolean;
    warnings: string[];
  };
}

export interface DashboardStats {
  totalIndicators: number;
  totalThreatMatches: number;
  highRiskCount: number;
  mediumRiskCount: number;
  lowRiskCount: number;
  unknownCount: number;
  recentInvestigationsCount: number;
  activeAlertsCount: number;
  categoryDistribution: { category: string; count: number }[];
  severityDistribution: { severity: SeverityLevel; count: number }[];
}

export interface ValidationResult {
  isValid: boolean;
  type?: IndicatorType;
  subType?: 'ipv4' | 'ipv6' | 'domain';
  error?: string;
  sanitized: string;
  details?: {
    isPrivate?: boolean;
    isLoopback?: boolean;
    isReserved?: boolean;
    tld?: string;
  };
}

export type NetworkLogRole = 'source' | 'destination' | 'domain' | 'host' | 'referrer';

export interface ExtractedLogIndicator {
  indicator: string;
  type: IndicatorType;
  subType?: 'ipv4' | 'ipv6' | 'domain';
  roles: NetworkLogRole[];
  occurrences: number;
  ports?: number[];
  protocols?: string[];
  firstSeen?: string;
  lastSeen?: string;
  matchStatus: MatchStatus;
  severity: SeverityLevel;
  category: string;
  source: string;
  confidence: number;
  evidence: string;
  asn?: string;
  country?: string;
  isSynthetic?: boolean;
  alertCreated?: boolean;
  alertId?: string;
  liveFeeds?: LiveFeedSource[];
}

export interface ParsedLogLine {
  lineNumber: number;
  raw: string;
  timestamp?: string;
  srcIp?: string;
  dstIp?: string;
  domain?: string;
  srcPort?: number;
  dstPort?: number;
  protocol?: string;
  action?: string;
  extractedCount: number;
}

export interface LogAnalysisSession {
  id: string;
  fileName: string;
  fileSize: number;
  logFormat: string;
  totalLines: number;
  parsedEntriesCount: number;
  totalExtracted: number;
  uniqueIndicatorsCount: number;
  threatMatchesCount: number;
  unmatchedCount: number;
  lookupFailuresCount: number;
  highRiskCount: number;
  mediumRiskCount: number;
  lowRiskCount: number;
  timestamp: string;
  analyst: string;
  indicators: ExtractedLogIndicator[];
  sampleLines?: ParsedLogLine[];
}
