import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Globe,
  AlertTriangle,
  History,
  CheckCircle2,
  ExternalLink,
  Download,
  Flame,
  ArrowRight,
  BellRing,
  Layers,
  Server
} from 'lucide-react';
import {
  DashboardStats,
  InvestigationRecord,
  SecurityAlert,
  IndicatorType,
  AnalysisResult
} from '../types/threat';
import { downloadInvestigationPDF } from '../lib/pdfReport';
import { NavTab } from './Sidebar';

interface DashboardViewProps {
  stats: DashboardStats | null;
  recentHistory: InvestigationRecord[];
  activeAlerts: SecurityAlert[];
  onNavigateTab: (tab: NavTab) => void;
  onRunAnalysis: (indicator: string, type: IndicatorType) => Promise<AnalysisResult> | void;
  isAnalyzing: boolean;
  latestResult: AnalysisResult | null;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  stats,
  recentHistory,
  activeAlerts,
  onNavigateTab,
  onRunAnalysis,
  isAnalyzing,
  latestResult
}) => {
  const [searchTab, setSearchTab] = useState<IndicatorType>('ip');
  const [inputValue, setInputValue] = useState('');
  const [inputError, setInputError] = useState('');

  const sampleIPs = [
    { label: 'LockBit C2 (High Risk)', val: '185.220.101.5' },
    { label: 'Mirai Botnet (High Risk)', val: '194.26.29.112' },
    { label: 'SSH Scanner (Med Risk)', val: '45.33.32.156' },
    { label: 'Clean DNS (Unmatched)', val: '8.8.8.8' }
  ];

  const sampleDomains = [
    { label: 'Bank Phishing (High Risk)', val: 'secure-bank-login-update.com' },
    { label: 'Lumma Malware CDN (High Risk)', val: 'payload-delivery-cdn.net' },
    { label: 'C2 Beacon (High Risk)', val: 'c2-command-beacon.org' },
    { label: 'Public Domain (Unmatched)', val: 'google.com' }
  ];

  const executeQuickAnalysis = async (val: string) => {
    setInputError('');
    try {
      await onRunAnalysis(val, searchTab);
    } catch (err: any) {
      setInputError(err?.message || 'Unable to complete indicator analysis.');
    }
  };

  const handleSearchSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputValue.trim()) {
      setInputError('Please enter an IP address or domain name to analyze.');
      return;
    }
    await executeQuickAnalysis(inputValue.trim());
  };

  const handleChipClick = async (val: string) => {
    setInputValue(val);
    await executeQuickAnalysis(val);
  };

  // Severity color utility
  const getSeverityStyle = (sev: string) => {
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

  const unresolvedAlerts = activeAlerts.filter((a) => a.status === 'Active');

  return (
    <div className="space-y-6">
      {/* Hero / Landing Header */}
      <div className="relative overflow-hidden rounded-xl border border-slate-800 bg-gradient-to-r from-slate-900 via-slate-900 to-slate-950 p-6 sm:p-8">
        <div className="relative z-10 max-w-3xl">
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-2">
            <span>CAPSTONE CYBERSECURITY SYSTEM</span>
            <span aria-hidden="true">·</span>
            <span>NIST SP 800-61 COMPLIANT</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white mb-2">
            Threat Intelligence Dashboard
          </h1>
          <p className="text-base sm:text-lg font-medium text-cyan-300/90 mb-3">
            Investigate. Analyze. Protect.
          </p>
          <p className="text-xs sm:text-sm text-slate-400 leading-relaxed max-w-2xl">
            Correlate suspicious IP addresses and domain names against curated threat intelligence feeds,
            classify risk severities, evaluate indicators of compromise (IOCs), and generate forensic triage reports.
          </p>
        </div>
      </div>

      {/* Active Alerts High-Priority Notification Banner */}
      {unresolvedAlerts.length > 0 && (
        <div className="rounded-xl border border-rose-500/40 bg-gradient-to-r from-rose-950/40 via-slate-900 to-slate-900 p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3.5">
            <div className="p-2.5 rounded-lg bg-rose-500/20 text-rose-400 border border-rose-500/30 shrink-0">
              <BellRing className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-rose-400">
                  Security Alert Notice
                </span>
                <span className="px-2 py-0.5 rounded-full bg-rose-500/30 text-rose-200 text-[10px] font-mono font-bold">
                  {unresolvedAlerts.length} Active Incidents
                </span>
              </div>
              <p className="text-xs sm:text-sm text-slate-200 mt-0.5">
                Investigated indicators have matched known threat intelligence records and require analyst review.
              </p>
            </div>
          </div>
          <button
            onClick={() => onNavigateTab('alerts')}
            className="px-4 py-2 text-xs font-bold text-slate-950 bg-rose-400 hover:bg-rose-300 rounded-lg transition-colors shrink-0 flex items-center gap-2 shadow-xs"
          >
            <span>Triage Alerts Now</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Module 1 Quick Search Station */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-xs">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
          <div>
            <h2 className="text-base font-bold text-white flex items-center gap-2">
              <Search className="w-4 h-4 text-cyan-400" />
              Indicator Investigation Station
            </h2>
            <div className="flex items-center gap-2 mt-0.5">
              <span className="text-xs text-slate-400">
                Correlate IP and domain indicators across local database & live public threat feeds.
              </span>
              <span className="hidden sm:inline-flex items-center gap-1 text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-1.5 py-0.5 rounded">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                Live Feeds Active
              </span>
            </div>
          </div>

          {/* Search Tabs: IP Address vs Domain */}
          <div className="flex items-center gap-1 p-1 bg-slate-950 rounded-lg border border-slate-800 shrink-0 self-start sm:self-auto">
            <button
              type="button"
              onClick={() => {
                setSearchTab('ip');
                setInputError('');
              }}
              className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                searchTab === 'ip'
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Search className="w-3.5 h-3.5" />
              <span>Analyze IP Address</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setSearchTab('domain');
                setInputError('');
              }}
              className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                searchTab === 'domain'
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              <Globe className="w-3.5 h-3.5" />
              <span>Analyze Domain</span>
            </button>
          </div>
        </div>

        {/* Input Form */}
        <form onSubmit={handleSearchSubmit} className="space-y-3">
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-500">
              {searchTab === 'ip' ? <Search className="w-4 h-4 text-cyan-400" /> : <Globe className="w-4 h-4 text-cyan-400" />}
            </div>
            <input
              type="text"
              value={inputValue}
              onChange={(e) => {
                setInputValue(e.target.value);
                if (inputError) setInputError('');
              }}
              placeholder={
                searchTab === 'ip'
                  ? 'Enter IPv4 or IPv6 address (e.g. 185.220.101.5 or 2001:db8:ffff:1::99)'
                  : 'Enter domain name (e.g. secure-bank-login-update.com or payload-delivery-cdn.net)'
              }
              className="w-full pl-10 pr-28 py-3 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white placeholder-slate-500 focus:outline-hidden focus:border-cyan-500/60 focus:ring-1 focus:ring-cyan-500/40 font-mono"
            />
            <div className="absolute inset-y-1.5 right-1.5 flex items-center">
              <button
                type="submit"
                disabled={isAnalyzing}
                className="h-full px-4 rounded-md text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 disabled:opacity-50 transition-colors flex items-center gap-1.5"
              >
                {isAnalyzing ? (
                  <span className="flex items-center gap-1">
                    <span className="w-3 h-3 border-2 border-slate-950 border-t-transparent rounded-full animate-spin" />
                    Querying...
                  </span>
                ) : (
                  <span>Analyze</span>
                )}
              </button>
            </div>
          </div>

          {inputError && (
            <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
              <span>{inputError}</span>
            </div>
          )}

          {/* Quick-test Synthetic Indicator Chips */}
          <div className="pt-2 flex flex-wrap items-center gap-2 text-xs">
            <span className="text-slate-400 font-mono text-[11px]">Demonstration Samples:</span>
            {(searchTab === 'ip' ? sampleIPs : sampleDomains).map((sample) => (
              <button
                key={sample.val}
                type="button"
                onClick={() => handleChipClick(sample.val)}
                className="px-2 py-1 rounded bg-slate-950 border border-slate-800 hover:border-cyan-500/40 text-slate-300 hover:text-cyan-300 text-[11px] font-mono transition-colors"
              >
                {sample.val} <span className="text-slate-400">({sample.label.split(' ')[0]})</span>
              </button>
            ))}
          </div>
        </form>

        {/* Live Analysis Result Preview Box */}
        {latestResult && (
          <div className="mt-5 p-4 rounded-lg bg-slate-950 border border-slate-800">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-400">Target Indicator:</span>
                <span className="text-sm font-mono font-bold text-white">{latestResult.indicator}</span>
                <span className="text-[11px] font-mono uppercase px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
                  {latestResult.type}
                </span>
                {latestResult.isSynthetic ? (
                  <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-amber-950/70 border border-amber-800/80 text-amber-300">
                    Local Demo Record
                  </span>
                ) : (
                  <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-emerald-950/70 border border-emerald-800/80 text-emerald-300">
                    Live Public Intel
                  </span>
                )}
                {latestResult.comparison && (
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300">
                    {latestResult.comparison.correlationVerdict}
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${getSeverityStyle(latestResult.severity)}`}>
                  {latestResult.severity}
                </span>
                <button
                  onClick={() => downloadInvestigationPDF(latestResult)}
                  className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-slate-300 hover:text-white bg-slate-900 hover:bg-slate-800 rounded border border-slate-700 transition-colors"
                >
                  <Download className="w-3.5 h-3.5 text-cyan-400" />
                  PDF Report
                </button>
              </div>
            </div>

            <div className="mt-3 grid grid-cols-1 sm:grid-cols-4 gap-3 text-xs">
              <div>
                <span className="text-slate-400 block text-[11px]">Match Status:</span>
                <span className={`font-semibold ${
                  latestResult.matchStatus === 'Known Indicator Match'
                    ? 'text-rose-400'
                    : latestResult.matchStatus === 'Lookup Failed' || latestResult.matchStatus === 'Insufficient Evidence'
                    ? 'text-amber-300'
                    : 'text-slate-200'
                }`}>
                  {latestResult.matchStatus.toUpperCase()}
                </span>
              </div>
              <div>
                <span className="text-slate-400 block text-[11px]">Threat Category:</span>
                <span className="font-semibold text-slate-200">{latestResult.category}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[11px]">Intelligence Source:</span>
                <span className="font-semibold text-slate-200 truncate block" title={latestResult.source}>{latestResult.source}</span>
              </div>
              <div>
                <span className="text-slate-400 block text-[11px]">Live Feeds Checked:</span>
                <span className="font-semibold text-cyan-300 font-mono">
                  {latestResult.liveFeeds ? `${latestResult.liveFeeds.length} Feeds (URLhaus, AbuseIPDB, OTX)` : 'Local DB'}
                </span>
              </div>
            </div>

            <div className="mt-3 pt-3 border-t border-slate-800/60 text-xs text-slate-300 leading-relaxed">
              <span className="text-slate-400 font-semibold block mb-0.5">Recorded Evidence & Findings:</span>
              <p>{latestResult.evidence}</p>
            </div>

            {/* Automated Security Alert Notification Callout */}
            {latestResult.alertCreated && (
              <div className="mt-3 pt-3 border-t border-slate-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-xs bg-slate-950/70 p-3 rounded-lg border border-slate-800">
                <div className="flex items-center gap-2.5">
                  <BellRing className={`w-4 h-4 shrink-0 ${latestResult.isDuplicateAlertSuppressed ? 'text-amber-400' : 'text-rose-400'}`} />
                  <div>
                    {latestResult.isDuplicateAlertSuppressed ? (
                      <span className="text-amber-300 font-mono text-[11px] block">
                        Deduplication Suppressed: Existing open alert updated (Observed {latestResult.alertOccurrenceCount}x within 30m window).
                      </span>
                    ) : (
                      <span className="text-rose-300 font-mono text-[11px] block">
                        Automated Security Alert Dispatched (#{latestResult.alertId}) for analyst review.
                      </span>
                    )}
                    <span className="text-[10px] text-slate-400">
                      Severity: <strong className="text-white">{latestResult.severity}</strong> · Threat category: <strong className="text-white">{latestResult.category}</strong>
                    </span>
                  </div>
                </div>
                <button
                  onClick={() => onNavigateTab('alerts')}
                  className="text-cyan-400 hover:text-cyan-300 text-xs font-semibold flex items-center gap-1 shrink-0 hover:underline"
                >
                  <span>Open Alerts Page</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Statistics Cards (4 Key Metrics) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Indicators */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase font-mono tracking-wider">Total Indicators</span>
            <Search className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-extrabold text-white font-mono tabular-nums">
            {stats?.totalIndicators ?? 0}
          </div>
          <div className="mt-2 text-xs text-slate-400">
            Cataloged in local intelligence database
          </div>
        </div>

        {/* Total Threat Matches */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase font-mono tracking-wider">Total Threat Matches</span>
            <Flame className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-extrabold text-amber-400 font-mono tabular-nums">
            {stats?.totalThreatMatches ?? 0}
          </div>
          <div className="mt-2 text-xs text-slate-400">
            Correlated across past investigations
          </div>
        </div>

        {/* High-Risk Indicators */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase font-mono tracking-wider">High-Risk Indicators</span>
            <AlertTriangle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-extrabold text-rose-400 font-mono tabular-nums">
            {stats?.highRiskCount ?? 0}
          </div>
          <div className="mt-2 text-xs text-slate-400">
            Critical C2, Ransomware & Phishing records
          </div>
        </div>

        {/* Recent Investigations */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase font-mono tracking-wider">Recent Investigations</span>
            <History className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl sm:text-3xl font-extrabold text-white font-mono tabular-nums">
            {stats?.recentInvestigationsCount ?? 0}
          </div>
          <div className="mt-2 text-xs text-slate-400">
            Stored audit inquiries in database
          </div>
        </div>
      </div>

      {/* Module 5: Network Log Analysis Feature Card */}
      <div className="rounded-xl border border-cyan-800/60 bg-gradient-to-r from-cyan-950/40 via-slate-900 to-slate-900 p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="w-10 h-10 rounded-lg bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shrink-0">
            <Server className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-white">Module 5: Network Log Analysis</span>
              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950 px-1.5 py-0.5 rounded border border-cyan-800 uppercase tracking-wider">New</span>
            </div>
            <p className="text-xs text-slate-300 mt-0.5">
              Upload firewall (Cisco ASA/iptables), web proxy, or AWS VPC flow logs to extract, deduplicate, and correlate indicators against threat records with Zero-Trust compliance.
            </p>
          </div>
        </div>
        <button
          onClick={() => onNavigateTab('log-analysis')}
          className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors flex items-center gap-1.5 shrink-0 shadow-sm"
        >
          <span>Launch Log Analyzer</span>
          <ArrowRight className="w-3.5 h-3.5 text-slate-950" />
        </button>
      </div>

      {/* Visual Charts: Severity Distribution & Category Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Section 2: Threat Distribution (High, Med, Low, Unknown) */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-white">Threat Severity Distribution</h2>
              <p className="text-xs text-slate-400">Breakdown of cataloged and investigated indicators</p>
            </div>
            <span className="text-xs font-mono text-cyan-400">CLASSIFICATIONS</span>
          </div>

          <div className="space-y-3 pt-2">
            {stats?.severityDistribution.map((item) => {
              const total = stats.totalIndicators + stats.unknownCount || 1;
              const pct = Math.round((item.count / total) * 100);
              let barColor = 'bg-slate-600';
              if (item.severity === 'HIGH RISK') barColor = 'bg-rose-500';
              if (item.severity === 'MEDIUM RISK') barColor = 'bg-amber-500';
              if (item.severity === 'LOW RISK') barColor = 'bg-cyan-500';

              return (
                <div key={item.severity} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-slate-300">{item.severity}</span>
                    <span className="font-mono tabular-nums text-slate-400">
                      {item.count} ({pct}%)
                    </span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-slate-950 overflow-hidden">
                    <div
                      className={`h-full ${barColor} rounded-full transition-all duration-500`}
                      style={{ width: `${Math.max(pct, item.count > 0 ? 4 : 0)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="mt-5 p-3 rounded-lg bg-slate-950 border border-slate-800/80 text-xs text-slate-400">
            <span className="text-cyan-400 font-semibold block mb-0.5">Classification Policy:</span>
            Unmatched lookups are classified as <strong className="text-slate-300">UNKNOWN</strong>, adhering strictly to cybersecurity best practices.
          </div>
        </div>

        {/* Threat Categories Breakdown */}
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-bold text-white">Threat Category Distribution</h2>
              <p className="text-xs text-slate-400">Recorded threat types in intelligence repository</p>
            </div>
            <button
              onClick={() => onNavigateTab('threat-intel')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
            >
              <span>Manage DB</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="space-y-3 pt-2">
            {(stats?.categoryDistribution || []).map((cat) => {
              const total = stats?.totalIndicators || 1;
              const pct = Math.round((cat.count / total) * 100);
              return (
                <div key={cat.category} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-300">{cat.category}</span>
                    <span className="font-mono tabular-nums text-slate-400">
                      {cat.count} records ({pct}%)
                    </span>
                  </div>
                  <div className="h-2 w-full rounded-full bg-slate-950 overflow-hidden">
                    <div
                      className="h-full bg-cyan-500/80 rounded-full transition-all duration-500"
                      style={{ width: `${Math.max(pct, 5)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>

          <div className="mt-5 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>Demonstration Test Dataset:</span>
            <span className="text-emerald-400 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" />
              SYNTHETIC INDICATORS ACTIVE
            </span>
          </div>
        </div>
      </div>

      {/* Active Security Alerts Banner / List */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-rose-400" />
            <div>
              <h2 className="text-sm font-bold text-white">Active Security Alerts</h2>
              <p className="text-xs text-slate-400">
                Triggered upon correlation with known High and Medium-Risk indicators
              </p>
            </div>
          </div>
          <button
            onClick={() => onNavigateTab('alerts')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
          >
            <span>View All Alerts</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {unresolvedAlerts.length === 0 ? (
          <div className="p-6 rounded-lg bg-slate-950 border border-slate-800 text-center text-xs text-slate-400">
            No active high-priority security alerts pending triage.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {unresolvedAlerts.slice(0, 3).map((alert) => (
              <div
                key={alert.id}
                className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="font-mono text-xs font-bold text-white truncate">
                      {alert.indicator}
                    </span>
                    <div className="flex items-center gap-1.5 shrink-0">
                      {(alert.occurrenceCount || 1) > 1 && (
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/40">
                          {alert.occurrenceCount}x
                        </span>
                      )}
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${getSeverityStyle(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </div>
                  </div>
                  <div className="text-xs text-cyan-400 font-medium mb-1">
                    {alert.category}
                  </div>
                  <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                    {alert.description}
                  </p>
                </div>
                <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400 font-mono">
                  <span className="truncate max-w-[140px]">{alert.source}</span>
                  <button
                    onClick={() => onNavigateTab('alerts')}
                    className="text-cyan-400 hover:underline font-semibold"
                  >
                    Triage →
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recent Investigations Audit Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-sm font-bold text-white">Recent Investigations</h2>
            <p className="text-xs text-slate-400">Previous searches with timestamps and forensic classifications</p>
          </div>
          <button
            onClick={() => onNavigateTab('history')}
            className="text-xs text-cyan-400 hover:text-cyan-300 font-medium flex items-center gap-1"
          >
            <span>Full Audit History</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                <th className="py-2.5 px-3">INDICATOR</th>
                <th className="py-2.5 px-3">TYPE</th>
                <th className="py-2.5 px-3">MATCH STATUS</th>
                <th className="py-2.5 px-3">SEVERITY</th>
                <th className="py-2.5 px-3">CATEGORY</th>
                <th className="py-2.5 px-3">TIMESTAMP</th>
                <th className="py-2.5 px-3 text-right">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {recentHistory.slice(0, 5).map((rec) => (
                <tr key={rec.id} className="hover:bg-slate-800/30 transition-colors">
                  <td className="py-3 px-3 text-white font-bold">{rec.indicator}</td>
                  <td className="py-3 px-3 uppercase text-slate-400">{rec.type}</td>
                  <td className="py-3 px-3">
                    <span className={rec.matchStatus === 'Known Indicator Match' ? 'text-amber-300' : 'text-slate-400'}>
                      {rec.matchStatus}
                    </span>
                  </td>
                  <td className="py-3 px-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityStyle(rec.severity)}`}>
                      {rec.severity}
                    </span>
                  </td>
                  <td className="py-3 px-3 font-sans text-slate-300">{rec.category}</td>
                  <td className="py-3 px-3 text-slate-400 tabular-nums">
                    {new Date(rec.timestamp).toISOString().slice(0, 16).replace('T', ' ')}
                  </td>
                  <td className="py-3 px-3 text-right">
                    <button
                      onClick={() => downloadInvestigationPDF(rec)}
                      className="px-2 py-1 text-[11px] font-sans font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded transition-colors inline-flex items-center gap-1"
                      title="Download PDF Investigation Report"
                    >
                      <Download className="w-3 h-3 text-cyan-400" />
                      PDF
                    </button>
                  </td>
                </tr>
              ))}
              {recentHistory.length === 0 && (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-slate-400 font-sans">
                    No recent investigations logged yet. Use the search bar above to begin.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
