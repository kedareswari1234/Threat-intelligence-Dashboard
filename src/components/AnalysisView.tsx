import React, { useState, useEffect } from 'react';
import {
  Search,
  Globe,
  AlertTriangle,
  CheckCircle2,
  Download,
  Info,
  ShieldAlert,
  FileText,
  HelpCircle,
  Network,
  Radio,
  ExternalLink,
  Layers,
  Activity,
  Check,
  XCircle,
  BellRing,
  Database
} from 'lucide-react';
import { IndicatorType, AnalysisResult, LiveFeedSource, MatchStatus } from '../types/threat';
import { validateIndicator } from '../lib/validation';
import { downloadInvestigationPDF } from '../lib/pdfReport';

interface AnalysisViewProps {
  initialType: IndicatorType;
  onAnalyze: (
    indicator: string,
    type: IndicatorType,
    notes?: string,
    analyst?: string,
    skipLiveFeeds?: boolean
  ) => Promise<AnalysisResult>;
  latestResult: AnalysisResult | null;
}

export const AnalysisView: React.FC<AnalysisViewProps> = ({
  initialType,
  onAnalyze,
  latestResult
}) => {
  const [activeType, setActiveType] = useState<IndicatorType>(initialType);
  const [inputVal, setInputVal] = useState('');
  const [analystName, setAnalystName] = useState('SOC Senior Analyst');
  const [analystNotes, setAnalystNotes] = useState('');
  const [enableLiveFeeds, setEnableLiveFeeds] = useState(true);
  const [isLoading, setIsLoading] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [validationSuccessInfo, setValidationSuccessInfo] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(latestResult);

  useEffect(() => {
    setActiveType(initialType);
    setValidationError(null);
    setAnalysisError(null);
    setValidationSuccessInfo(null);
  }, [initialType]);

  useEffect(() => {
    if (latestResult) {
      setResult(latestResult);
    }
  }, [latestResult]);

  // Real-time syntax pre-validation as user types
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const text = e.target.value;
    setInputVal(text);
    setAnalysisError(null);

    if (!text.trim()) {
      setValidationError(null);
      setValidationSuccessInfo(null);
      return;
    }

    const check = validateIndicator(text, activeType);
    if (!check.isValid) {
      setValidationError(check.error || 'Invalid format');
      setValidationSuccessInfo(null);
    } else {
      setValidationError(null);
      let details = `Valid ${check.subType?.toUpperCase()}`;
      if (check.details?.isPrivate) details += ' · RFC 1918 Private Subnet';
      if (check.details?.isLoopback) details += ' · Loopback Interface';
      if (check.details?.tld) details += ` · TLD: .${check.details.tld}`;
      setValidationSuccessInfo(details);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setAnalysisError(null);

    if (!inputVal.trim()) {
      setValidationError(
        activeType === 'domain'
          ? 'Please enter a domain name (e.g. google.com) to investigate.'
          : 'Please enter an IP address to investigate.'
      );
      return;
    }

    const preCheck = validateIndicator(inputVal, activeType);
    if (!preCheck.isValid) {
      setValidationError(preCheck.error || 'Validation failed before submission.');
      return;
    }

    setIsLoading(true);
    setValidationError(null);
    try {
      const res = await onAnalyze(
        preCheck.sanitized || inputVal.trim(),
        activeType,
        analystNotes,
        analystName,
        !enableLiveFeeds
      );
      setResult(res);
    } catch (err: any) {
      setAnalysisError(err?.message || 'Unable to complete threat intelligence analysis.');
    } finally {
      setIsLoading(false);
    }
  };

  const runSample = (sampleIndicator: string, type: IndicatorType, notes?: string) => {
    setActiveType(type);
    setInputVal(sampleIndicator);
    setValidationError(null);
    setAnalysisError(null);
    const check = validateIndicator(sampleIndicator, type);
    if (check.isValid) {
      let details = `Valid ${check.subType?.toUpperCase()}`;
      if (check.details?.tld) details += ` · TLD: .${check.details.tld}`;
      setValidationSuccessInfo(details);
    }
    if (notes) setAnalystNotes(notes);
    setIsLoading(true);
    onAnalyze(sampleIndicator, type, notes || 'Demonstration sample investigation run', analystName, !enableLiveFeeds)
      .then((res) => setResult(res))
      .catch((err) => setAnalysisError(err?.message || 'Unable to complete threat intelligence analysis.'))
      .finally(() => setIsLoading(false));
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'HIGH RISK':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      case 'MEDIUM RISK':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'LOW RISK':
        return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30';
      default:
        return 'text-slate-400 bg-slate-800/40 border-slate-700/50';
    }
  };

  const formatMatchStatusDisplay = (status: MatchStatus) => {
    switch (status) {
      case 'Known Indicator Match':
        return {
          label: 'KNOWN INDICATOR MATCH',
          sub: 'Confirmed by threat intelligence database or live feeds',
          colorClass: 'text-rose-400',
          icon: <ShieldAlert className="w-4 h-4 shrink-0" />
        };
      case 'Lookup Failed':
        return {
          label: 'LOOKUP FAILED',
          sub: 'External provider lookups failed — indicator NOT verified safe',
          colorClass: 'text-amber-400',
          icon: <XCircle className="w-4 h-4 shrink-0" />
        };
      case 'Insufficient Evidence':
        return {
          label: 'INSUFFICIENT EVIDENCE',
          sub: 'Partial provider coverage or skipped live feeds — monitor under Zero-Trust',
          colorClass: 'text-amber-300',
          icon: <AlertTriangle className="w-4 h-4 shrink-0" />
        };
      case 'No Match Found':
      default:
        return {
          label: 'NO MATCH FOUND',
          sub: 'No threat record found across queried sources (Zero-Trust: not assumed safe)',
          colorClass: 'text-slate-300',
          icon: <Info className="w-4 h-4 shrink-0" />
        };
    }
  };

  const getFeedStatusBadge = (status: LiveFeedSource['status']) => {
    switch (status) {
      case 'detected_threat':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3 text-rose-400" />
            Threat Detected
          </span>
        );
      case 'clean_or_no_reports':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 flex items-center gap-1">
            <Check className="w-3 h-3 text-emerald-400" />
            No Reports
          </span>
        );
      case 'not_configured':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono text-slate-300 bg-slate-800/80 border border-slate-700/60">
            API Key Missing
          </span>
        );
      case 'insufficient_evidence':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono text-amber-300 bg-amber-500/10 border border-amber-500/30 flex items-center gap-1">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            Insufficient Evidence
          </span>
        );
      case 'unavailable':
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono text-amber-300 bg-amber-500/10 border border-amber-500/30 flex items-center gap-1">
            <XCircle className="w-3 h-3 text-amber-400" />
            Lookup Failed
          </span>
        );
    }
  };

  const matchDisplay = result ? formatMatchStatusDisplay(result.matchStatus) : null;

  return (
    <div className="space-y-6 max-w-5xl">
      {/* Module Header */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="text-xs font-mono text-cyan-400 mb-1 flex items-center gap-2">
              <span className="flex items-center gap-1">
                <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                LIVE THREAT INTELLIGENCE & CORRELATION
              </span>
              <span aria-hidden="true">·</span>
              <span>URLHAUS · ABUSEIPDB · ALIENVAULT OTX</span>
            </div>
            <h1 className="text-xl sm:text-2xl font-extrabold text-white">
              {activeType === 'ip' ? 'Malicious IP Address Analysis' : 'Malicious Domain Name Analysis'}
            </h1>
            <p className="text-xs sm:text-sm text-slate-400 mt-1">
              Query live public threat feeds in real-time, cross-reference local databases, and evaluate multi-source telemetry.
            </p>
          </div>

          {/* Mode Switcher */}
          <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-lg border border-slate-800 shrink-0 self-start sm:self-auto">
            <button
              type="button"
              onClick={() => {
                setActiveType('ip');
                setValidationError(null);
                setAnalysisError(null);
                setValidationSuccessInfo(null);
              }}
              className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                activeType === 'ip'
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Search className="w-3.5 h-3.5" />
              <span>IP Address Lookup</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setActiveType('domain');
                setValidationError(null);
                setAnalysisError(null);
                setValidationSuccessInfo(null);
              }}
              className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                activeType === 'domain'
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>Domain Lookup</span>
            </button>
          </div>
        </div>

        {/* Input Form */}
        <form onSubmit={handleSubmit} className="mt-6 space-y-4">
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <label className="block text-xs font-medium text-slate-300">
                Target {activeType === 'ip' ? 'IP Address (IPv4 or IPv6)' : 'Domain Name (FQDN)'}
              </label>

              {/* Live Intelligence Feed Toggle */}
              <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300 select-none">
                <input
                  type="checkbox"
                  checked={enableLiveFeeds}
                  onChange={(e) => setEnableLiveFeeds(e.target.checked)}
                  className="w-3.5 h-3.5 rounded bg-slate-950 border-slate-700 accent-cyan-400"
                />
                <span className="font-mono text-[11px] text-cyan-300 flex items-center gap-1">
                  <Activity className="w-3 h-3 text-cyan-400" />
                  Live Public Feeds (URLhaus, AbuseIPDB, OTX)
                </span>
              </label>
            </div>

            <div className="relative">
              <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
                {activeType === 'ip' ? <Search className="w-4 h-4 text-cyan-400" /> : <Globe className="w-4 h-4 text-cyan-400" />}
              </div>
              <input
                type="text"
                value={inputVal}
                onChange={handleInputChange}
                placeholder={
                  activeType === 'ip'
                    ? 'e.g. 185.220.101.5 or 2001:db8:ffff:1::99'
                    : 'e.g. google.com, example.com, or secure-bank-login-update.com'
                }
                className="w-full pl-10 pr-36 py-3 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-hidden focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/40 font-mono"
              />
              <div className="absolute inset-y-1.5 right-1.5 flex items-center">
                <button
                  type="submit"
                  disabled={isLoading}
                  className="h-full px-5 rounded-md text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 transition-colors flex items-center gap-1.5"
                >
                  {isLoading ? (
                    <span className="flex items-center gap-1.5">
                      <span className="w-3.5 h-3.5 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                      Querying Feeds...
                    </span>
                  ) : (
                    <span>Analyze Indicator</span>
                  )}
                </button>
              </div>
            </div>

            {/* Client Format Validation Feedback */}
            {validationError && (
              <div className="mt-2 p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
                <span><strong>Validation Error:</strong> {validationError}</span>
              </div>
            )}

            {/* Backend / API / Network Analysis Error Feedback (distinct from client format validation) */}
            {analysisError && (
              <div className="mt-2 p-3 rounded-lg bg-amber-500/10 border border-amber-500/40 text-amber-200 text-xs flex items-start gap-2">
                <XCircle className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
                <div>
                  <span className="font-semibold text-amber-300">Analysis Error: </span>
                  <span>{analysisError}</span>
                </div>
              </div>
            )}

            {!validationError && !analysisError && validationSuccessInfo && (
              <div className="mt-2 p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-400" />
                <span><strong>Format Valid:</strong> {validationSuccessInfo}</span>
              </div>
            )}
          </div>

          {/* Optional Analyst Notes & ID */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
            <div className="sm:col-span-1">
              <label className="block text-xs font-medium text-slate-400 mb-1">
                Investigating Analyst
              </label>
              <input
                type="text"
                value={analystName}
                onChange={(e) => setAnalystName(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-hidden focus:border-cyan-500/60"
              />
            </div>
            <div className="sm:col-span-2">
              <label className="block text-xs font-medium text-slate-400 mb-1">
                Investigation Incident Notes (Optional)
              </label>
              <input
                type="text"
                value={analystNotes}
                onChange={(e) => setAnalystNotes(e.target.value)}
                placeholder="e.g. Host triggered outbound beaconing in SIEM alert #492"
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-hidden focus:border-cyan-500/60"
              />
            </div>
          </div>
        </form>

        {/* 1-Click Capstone & Live Test Scenarios */}
        <div className="mt-6 pt-5 border-t border-slate-800">
          <div className="flex items-center justify-between mb-2 text-xs font-mono text-slate-400">
            <div className="flex items-center gap-1.5">
              <HelpCircle className="w-3.5 h-3.5 text-cyan-400" />
              <span>Investigation Samples & Live Intelligence Detections:</span>
            </div>
            <span className="text-[10px] text-slate-500 hidden sm:inline">1-Click Test Scenarios</span>
          </div>
          <div className="flex flex-wrap gap-2 text-xs">
            <button
              type="button"
              onClick={() => runSample('185.220.101.5', 'ip', 'Testing known LockBit Tor exit node')}
              className="px-2.5 py-1 rounded bg-slate-950 border border-rose-500/30 hover:border-rose-400 text-rose-300 text-[11px] font-mono transition-colors"
            >
              1. LockBit C2 (Synthetic Demo Match)
            </button>
            <button
              type="button"
              onClick={() => runSample('2001:db8:ffff:1::99', 'ip', 'Testing IPv6 C2 beacon node')}
              className="px-2.5 py-1 rounded bg-slate-950 border border-rose-500/30 hover:border-rose-400 text-rose-300 text-[11px] font-mono transition-colors"
            >
              2. IPv6 Exfiltration C2 (High Risk)
            </button>
            <button
              type="button"
              onClick={() => runSample('secure-bank-login-update.com', 'domain', 'Testing banking credential harvester')}
              className="px-2.5 py-1 rounded bg-slate-950 border border-rose-500/30 hover:border-rose-400 text-rose-300 text-[11px] font-mono transition-colors"
            >
              3. Banking Harvester (Phishing)
            </button>
            <button
              type="button"
              onClick={() => runSample('45.33.32.156', 'ip', 'Testing SSH honeypot scanner')}
              className="px-2.5 py-1 rounded bg-slate-950 border border-amber-500/30 hover:border-amber-400 text-amber-300 text-[11px] font-mono transition-colors"
            >
              4. Scanner (Medium Risk)
            </button>
            <button
              type="button"
              onClick={() => runSample('google.com', 'domain', 'Testing public domain lookup & DNS IP resolution')}
              className="px-2.5 py-1 rounded bg-slate-950 border border-cyan-500/30 hover:border-cyan-400 text-cyan-300 text-[11px] font-mono transition-colors"
            >
              5. google.com (Live Domain Check)
            </button>
            <button
              type="button"
              onClick={() => runSample('example.com', 'domain', 'Testing RFC 2606 example.com domain')}
              className="px-2.5 py-1 rounded bg-slate-950 border border-cyan-500/30 hover:border-cyan-400 text-cyan-300 text-[11px] font-mono transition-colors"
            >
              6. example.com (Public Domain)
            </button>
            <button
              type="button"
              onClick={() => runSample('8.8.8.8', 'ip', 'Testing Google DNS resolver')}
              className="px-2.5 py-1 rounded bg-slate-950 border border-slate-700 hover:border-slate-500 text-slate-300 text-[11px] font-mono transition-colors"
            >
              7. 8.8.8.8 (Zero-Trust Unknown)
            </button>
          </div>
        </div>
      </div>

      {/* Investigation Forensic Report Card */}
      {result && matchDisplay && (
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-6 space-y-6 shadow-sm">
          {/* Card Top: Indicator Details & Triage Classification */}
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-5 border-b border-slate-800">
            <div>
              <div className="flex items-center gap-2 mb-1 flex-wrap">
                <span className="text-xs font-mono text-slate-400">
                  {result.type === 'domain' ? 'SUBMITTED DOMAIN:' : 'SUBMITTED INDICATOR:'}
                </span>
                <span className="text-lg font-mono font-bold text-white">{result.indicator}</span>
                <span className="text-[11px] font-mono uppercase px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-400">
                  {result.type}
                </span>

                {/* Validation Status Badge */}
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                  {result.validationStatus || 'Format Validated'}
                </span>

                {/* Source Origin Distinction Tag */}
                {result.isSynthetic ? (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/70 border border-amber-800/80 text-amber-300 font-semibold">
                    LOCAL DEMONSTRATION RECORD
                  </span>
                ) : (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/70 border border-emerald-800/80 text-emerald-300 font-semibold flex items-center gap-1">
                    <Radio className="w-3 h-3 text-emerald-400" />
                    LIVE PUBLIC INTEL QUERY
                  </span>
                )}
              </div>

              <div className="text-xs text-slate-400 flex flex-wrap items-center gap-3">
                <span>Ref ID: <strong className="font-mono text-slate-300">{result.investigationId}</strong></span>
                <span aria-hidden="true">·</span>
                <span>Timestamp: <strong className="font-mono text-slate-300">{new Date(result.timestamp).toUTCString()}</strong></span>
                {result.resolvedIps && result.resolvedIps.length > 0 && (
                  <>
                    <span aria-hidden="true">·</span>
                    <span>
                      DNS Resolved IP{result.resolvedIps.length > 1 ? 's' : ''}:{' '}
                      <strong className="font-mono text-cyan-300">{result.resolvedIps.join(', ')}</strong>
                    </span>
                  </>
                )}
              </div>
            </div>

            <div className="flex items-center gap-3 shrink-0">
              <div className="text-right">
                <span className="text-[11px] font-mono text-slate-400 block">SEVERITY LEVEL</span>
                <span className={`text-xs font-mono font-bold px-3 py-1 rounded border inline-block ${getSeverityBadge(result.severity)}`}>
                  {result.severity}
                </span>
              </div>
              <button
                onClick={() => downloadInvestigationPDF(result)}
                className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-white bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition-colors shadow-xs"
              >
                <Download className="w-4 h-4 text-cyan-400" />
                <span>Download PDF Report</span>
              </button>
            </div>
          </div>

          {/* Database / Diagnostics Warnings (non-fatal partial lookup notices) */}
          {(result.databaseStatus?.error || (result.diagnostics?.warnings && result.diagnostics.warnings.length > 0)) && (
            <div className="p-3.5 rounded-lg bg-amber-950/30 border border-amber-700/50 text-amber-200 text-xs space-y-1.5">
              <div className="font-mono font-bold text-amber-300 flex items-center gap-2">
                <Database className="w-4 h-4 text-amber-400 shrink-0" />
                <span>INVESTIGATION DIAGNOSTICS & PROVIDER NOTICES</span>
              </div>
              {result.databaseStatus?.error && (
                <p className="text-amber-200">{result.databaseStatus.error}</p>
              )}
              {result.diagnostics?.warnings?.map((w, idx) => (
                <p key={idx} className="text-slate-300">• {w}</p>
              ))}
            </div>
          )}

          {/* Multi-Source Correlation Summary Banner */}
          {result.comparison && (
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Layers className="w-4 h-4 text-cyan-400 shrink-0" />
                  <span className="text-xs font-mono font-bold text-white uppercase tracking-wider">
                    INTELLIGENCE CORRELATION: {result.comparison.correlationVerdict}
                  </span>
                </div>
                <p className="text-xs text-slate-300 font-sans leading-relaxed">
                  {result.comparison.summaryText}
                </p>
              </div>

              <div className="flex items-center gap-3 shrink-0 text-xs font-mono text-slate-400 border-t sm:border-t-0 sm:border-l border-slate-800 pt-2 sm:pt-0 sm:pl-4">
                <div>
                  <span className="text-[10px] block">LOCAL DB:</span>
                  <strong className={result.comparison.localMatch ? 'text-amber-400' : 'text-slate-400'}>
                    {result.comparison.localMatch ? 'RECORD FOUND' : 'NO RECORD'}
                  </strong>
                </div>
                <div>
                  <span className="text-[10px] block">LIVE FEEDS:</span>
                  <strong className={result.comparison.liveFeedsReportingThreat > 0 ? 'text-rose-400' : 'text-slate-400'}>
                    {result.comparison.liveFeedsReportingThreat}/{result.comparison.liveFeedsChecked} THREATS
                  </strong>
                </div>
              </div>
            </div>
          )}

          {/* Automated Security Alert Notification Callout */}
          {result.alertCreated && (
            <div className={`p-4 rounded-lg border ${
              result.isDuplicateAlertSuppressed
                ? 'border-amber-500/40 bg-amber-500/10'
                : 'border-rose-500/40 bg-rose-500/10'
            } flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs`}>
              <div className="flex items-center gap-3">
                <div className={`p-2 rounded-lg ${
                  result.isDuplicateAlertSuppressed ? 'bg-amber-500/20 text-amber-400' : 'bg-rose-500/20 text-rose-400'
                }`}>
                  <BellRing className="w-5 h-5 shrink-0" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold uppercase tracking-wider text-white">
                      {result.isDuplicateAlertSuppressed
                        ? 'Automated Alert Deduplication Active'
                        : 'Automated Security Alert Generated'}
                    </span>
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-950 border border-slate-800 text-slate-300">
                      Alert #{result.alertId}
                    </span>
                  </div>
                  <p className="text-slate-300 mt-0.5">
                    {result.isDuplicateAlertSuppressed
                      ? `Repeated investigation observed within 30-min deduplication window (count: ${result.alertOccurrenceCount}x). Existing incident alert updated without duplicate queue clutter.`
                      : `Correlated threat intelligence evidence has automatically triggered a Security Alert assigned severity ${result.severity}.`}
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <span className="px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-[11px] font-mono text-cyan-400 font-bold">
                  Queue: Security Alerts
                </span>
              </div>
            </div>
          )}

          {/* Core Findings Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 block mb-1">THREAT MATCH STATUS</span>
              <div className={`text-sm font-bold flex items-center gap-1.5 ${matchDisplay.colorClass}`}>
                {matchDisplay.icon}
                <span>{matchDisplay.label}</span>
              </div>
              <span className="text-[11px] text-slate-400 mt-1 block">
                {matchDisplay.sub}
              </span>
            </div>

            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 block mb-1">THREAT CATEGORY</span>
              <div className="text-sm font-bold text-cyan-300 truncate" title={result.category}>
                {result.category}
              </div>
              <span className="text-[11px] text-slate-400 mt-1 block">
                Confidence: <strong className="font-mono text-slate-300">{result.confidence}%</strong>
              </span>
            </div>

            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 block mb-1">INTELLIGENCE SOURCE</span>
              <div className="text-sm font-semibold text-slate-200 truncate" title={result.source}>
                {result.source}
              </div>
              <span className="text-[11px] text-slate-400 mt-1 block font-mono">
                {result.databaseStatus?.provider || 'Attribution Channel'}
              </span>
            </div>

            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[11px] font-mono text-slate-400 block mb-1">REPUTATION / ASN & GEO</span>
              <div className="text-xs font-semibold text-slate-200 line-clamp-2" title={result.reputationInfo}>
                {result.reputationInfo || result.asn || 'No reputation telemetry reported'}
              </div>
              <span className="text-[11px] text-slate-400 mt-1 block font-mono">
                {result.asn ? `${result.asn} · ` : ''}Country: {result.country || 'N/A'}
              </span>
            </div>
          </div>

          {/* Section: Live Threat Intelligence Feeds Breakdown */}
          {result.liveFeeds && result.liveFeeds.length > 0 && (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs font-mono text-slate-300 font-bold">
                <span className="flex items-center gap-1.5">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  PROVIDER LOOKUP STATUS & TELEMETRY
                </span>
                <span className="text-[11px] text-slate-400 font-normal">
                  Real-time public API queries
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {result.liveFeeds.map((feed) => (
                  <div
                    key={feed.id}
                    className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between space-y-3"
                  >
                    <div>
                      <div className="flex items-center justify-between gap-2 mb-2">
                        <span className="font-bold text-white text-xs">{feed.name}</span>
                        {getFeedStatusBadge(feed.status)}
                      </div>

                      {feed.resolvedIp && (
                        <div className="mb-1.5 text-[10px] font-mono text-cyan-300 bg-cyan-950/40 border border-cyan-900/60 px-2 py-0.5 rounded inline-block">
                          DNS Host IP: {feed.resolvedIp}
                        </div>
                      )}

                      <p className="text-xs text-slate-300 leading-relaxed">
                        {feed.details}
                      </p>

                      {feed.reputationSummary && (
                        <p className="text-[11px] font-mono text-slate-400 mt-1.5">
                          {feed.reputationSummary}
                        </p>
                      )}
                    </div>

                    <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] font-mono text-slate-400">
                      <span>
                        {feed.confidence !== undefined
                          ? `Confidence: ${feed.confidence}%`
                          : feed.queryTimeMs !== undefined
                          ? `${feed.queryTimeMs}ms`
                          : 'Public API'}
                      </span>
                      {feed.attributionUrl && (
                        <a
                          href={feed.attributionUrl}
                          target="_blank"
                          rel="noreferrer noopener"
                          className="text-cyan-400 hover:underline flex items-center gap-1"
                        >
                          Source <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Evidence and Intelligence Observations */}
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800">
            <div className="flex items-center gap-2 mb-2 text-xs font-bold text-white font-mono">
              <FileText className="w-4 h-4 text-cyan-400" />
              <span>MATCHING EVIDENCE & FORENSIC OBSERVATIONS</span>
            </div>
            <p className="text-xs sm:text-sm text-slate-300 leading-relaxed font-sans">
              {result.evidence}
            </p>
          </div>

          {/* Actionable Incident Response Advisory */}
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-800">
            <div className="text-xs font-bold text-white font-mono mb-2 flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              <span>RECOMMENDED MITIGATION PROCEDURES</span>
            </div>
            <ul className="text-xs text-slate-300 space-y-1.5 list-disc pl-4">
              {result.severity === 'HIGH RISK' ? (
                <>
                  <li><strong>Firewall Perimeter Enforcement:</strong> Add <span className="font-mono text-rose-300">{result.indicator}</span> to border egress drop rules immediately.</li>
                  <li><strong>DNS Sinkhole Redirection:</strong> Sinkhole resolution to prevent command-and-control beaconing.</li>
                  <li><strong>SIEM Telemetry Search:</strong> Audit past 30 days of proxy and VPN logs for hosts contacting this indicator.</li>
                </>
              ) : result.severity === 'MEDIUM RISK' ? (
                <>
                  <li><strong>Active SIEM Alerting:</strong> Place indicator on high-priority watch table for anomalous port traversal.</li>
                  <li><strong>Rate Limiting:</strong> Throttle inbound connection rate from this network block.</li>
                </>
              ) : (
                <>
                  <li><strong>Baseline Logging:</strong> Maintain normal syslog stream.</li>
                  <li><strong>Zero-Trust Advisory:</strong> An unmatched or incomplete indicator lookup is NOT verified safe; continue standard host EDR and DNS monitoring.</li>
                </>
              )}
            </ul>
          </div>

          {/* Alert Status Banner */}
          {result.alertCreated && (
            <div className="p-3.5 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-between text-xs text-rose-300">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
                <span>Security Alert created automatically in SOC Triage Queue (ID: {result.alertId}).</span>
              </div>
              <span className="text-[11px] font-mono text-rose-300 uppercase font-semibold">Triage Active</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
