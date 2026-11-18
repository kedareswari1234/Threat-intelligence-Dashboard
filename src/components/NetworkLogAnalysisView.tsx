import React, { useState, useRef, useEffect } from 'react';
import {
  UploadCloud,
  FileText,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Download,
  RefreshCw,
  Search,
  Filter,
  Server,
  Globe,
  Terminal,
  ExternalLink,
  Trash2,
  Eye,
  Clock,
  Layers,
  ArrowRight,
  FileCode,
  Info,
  Shield,
  History,
  Copy,
  Check
} from 'lucide-react';
import {
  LogAnalysisSession,
  ExtractedLogIndicator,
  SeverityLevel,
  IndicatorType
} from '../types/threat';
import { api } from '../lib/api';
import { downloadLogAnalysisPDF } from '../lib/pdfReport';
import { MAX_LOG_FILE_SIZE_BYTES } from '../lib/logParser';

interface NetworkLogAnalysisViewProps {
  onInvestigateIndicator: (indicator: string, type: IndicatorType) => void;
  onNavigateToAlerts?: () => void;
}

export const NetworkLogAnalysisView: React.FC<NetworkLogAnalysisViewProps> = ({
  onInvestigateIndicator,
  onNavigateToAlerts
}) => {
  // Input State
  const [rawLogText, setRawLogText] = useState<string>('');
  const [fileName, setFileName] = useState<string>('');
  const [fileSize, setFileSize] = useState<number>(0);
  const [analystName, setAnalystName] = useState<string>('SOC Lead Analyst');
  const [skipLiveFeeds, setSkipLiveFeeds] = useState<boolean>(false);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Active Session & Results
  const [currentSession, setCurrentSession] = useState<LogAnalysisSession | null>(null);
  const [pastSessions, setPastSessions] = useState<LogAnalysisSession[]>([]);
  const [loadingPastSessions, setLoadingPastSessions] = useState<boolean>(false);

  // Table Filters & Search
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterMatchStatus, setFilterMatchStatus] = useState<string>('all');
  const [filterType, setFilterType] = useState<string>('all');

  // UI Views & Modals
  const [activeTab, setActiveTab] = useState<'upload' | 'results' | 'raw_inspector' | 'history'>('upload');
  const [inspectIndicator, setInspectIndicator] = useState<ExtractedLogIndicator | null>(null);
  const [copiedIndicator, setCopiedIndicator] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // Load past analysis sessions on mount
  useEffect(() => {
    loadSessions();
  }, []);

  const loadSessions = async () => {
    setLoadingPastSessions(true);
    try {
      const list = await api.getLogAnalyses(25);
      setPastSessions(list);
    } catch (e) {
      console.warn('Failed to load past log analyses:', e);
    } finally {
      setLoadingPastSessions(false);
    }
  };

  // Handle File Upload
  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    if (file.size > MAX_LOG_FILE_SIZE_BYTES) {
      setErrorMessage(`Selected file is too large (${(file.size / 1024 / 1024).toFixed(2)} MB). Maximum allowed size is 5 MB.`);
      return;
    }

    setFileName(file.name);
    setFileSize(file.size);
    setErrorMessage(null);

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setRawLogText(content);
    };
    reader.onerror = () => {
      setErrorMessage('Failed to read selected log file.');
    };
    reader.readAsText(file);
  };

  // Handle Drag & Drop
  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    const file = e.dataTransfer.files?.[0];
    if (!file) return;

    if (file.size > MAX_LOG_FILE_SIZE_BYTES) {
      setErrorMessage(`Dropped file is too large (${(file.size / 1024 / 1024).toFixed(2)} MB). Maximum allowed size is 5 MB.`);
      return;
    }

    setFileName(file.name);
    setFileSize(file.size);
    setErrorMessage(null);

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      setRawLogText(content);
    };
    reader.readAsText(file);
  };

  // Load Pre-configured Sample Logs for Capstone Demonstration
  const loadSample = async (sampleType: 'firewall' | 'web-proxy' | 'vpc-flow') => {
    setErrorMessage(null);
    try {
      const sample = await api.getSampleLog(sampleType);
      setRawLogText(sample.content);
      setFileName(sample.fileName);
      setFileSize(sample.content.length);
    } catch (e: any) {
      setErrorMessage(e.message || 'Failed to load demonstration sample log.');
    }
  };

  // Run Log Analysis
  const handleAnalyze = async () => {
    if (!rawLogText.trim()) {
      setErrorMessage('Please upload a network log file or load a demonstration sample log before analyzing.');
      return;
    }

    setErrorMessage(null);
    setIsAnalyzing(true);
    try {
      const session = await api.analyzeNetworkLog(rawLogText, {
        fileName: fileName || 'uploaded_network_log.log',
        fileSize: fileSize || rawLogText.length,
        analyst: analystName,
        skipLiveFeeds
      });

      setCurrentSession(session);
      setActiveTab('results');
      loadSessions();
    } catch (err: any) {
      console.error('Log analysis failed:', err);
      setErrorMessage(err.message || 'Analysis failed. Please check the log format.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndicator(text);
    setTimeout(() => setCopiedIndicator(null), 2000);
  };

  const handleDeleteSession = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    if (!window.confirm('Are you sure you want to delete this log analysis session?')) return;
    try {
      await api.deleteLogAnalysis(id);
      if (currentSession?.id === id) {
        setCurrentSession(null);
        setActiveTab('upload');
      }
      loadSessions();
    } catch (e: any) {
      alert('Failed to delete session: ' + e.message);
    }
  };

  // Filtered Indicators
  const filteredIndicators = (currentSession?.indicators || []).filter((item) => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchInd = item.indicator.toLowerCase().includes(q);
      const matchCat = item.category.toLowerCase().includes(q);
      const matchSrc = item.source.toLowerCase().includes(q);
      const matchRole = item.roles.some((r) => r.toLowerCase().includes(q));
      if (!matchInd && !matchCat && !matchSrc && !matchRole) return false;
    }

    if (filterSeverity !== 'all' && item.severity !== filterSeverity) return false;
    if (filterMatchStatus !== 'all' && item.matchStatus !== filterMatchStatus) return false;
    if (filterType !== 'all' && item.type !== filterType) return false;

    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-6 backdrop-blur-xs relative overflow-hidden">
        <div className="absolute -top-12 -right-12 w-48 h-48 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="px-2.5 py-0.5 rounded-full text-[11px] font-semibold bg-cyan-950 text-cyan-400 border border-cyan-800 uppercase tracking-wider font-mono">
                Module 5 · Forensic Log Parser
              </span>
              <span className="text-xs text-slate-400 font-mono">
                Zero-Trust Correlator
              </span>
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              <Server className="w-6 h-6 text-cyan-400" />
              Network Log Analysis & Threat Correlation
            </h1>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Ingest firewall, syslog, proxy, or VPC flow logs. Automatically extract, validate, and deduplicate source/destination IPs and domains, cross-referencing them against local intelligence records and live public feeds.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setActiveTab('upload')}
              className={`px-3.5 py-2 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === 'upload'
                  ? 'bg-cyan-500 text-slate-950 font-semibold'
                  : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
              }`}
            >
              <UploadCloud className="w-4 h-4" />
              Ingest & Configure
            </button>
            {currentSession && (
              <button
                onClick={() => setActiveTab('results')}
                className={`px-3.5 py-2 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 ${
                  activeTab === 'results'
                    ? 'bg-cyan-500 text-slate-950 font-semibold'
                    : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                }`}
              >
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                Analysis Results ({currentSession.threatMatchesCount})
              </button>
            )}
            {currentSession && (
              <button
                onClick={() => setActiveTab('raw_inspector')}
                className={`px-3.5 py-2 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 ${
                  activeTab === 'raw_inspector'
                    ? 'bg-cyan-500 text-slate-950 font-semibold'
                    : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
                }`}
              >
                <Terminal className="w-4 h-4 text-emerald-400" />
                Log Inspector
              </button>
            )}
            <button
              onClick={() => setActiveTab('history')}
              className={`px-3.5 py-2 rounded-lg text-xs font-medium transition-colors flex items-center gap-1.5 ${
                activeTab === 'history'
                  ? 'bg-cyan-500 text-slate-950 font-semibold'
                  : 'bg-slate-800 hover:bg-slate-700 text-slate-300'
              }`}
            >
              <History className="w-4 h-4 text-amber-400" />
              History ({pastSessions.length})
            </button>
          </div>
        </div>
      </div>

      {errorMessage && (
        <div className="p-4 rounded-xl border border-rose-800/80 bg-rose-950/40 text-rose-300 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
          <div className="flex-1 text-sm">
            <span className="font-semibold block">Processing Error</span>
            {errorMessage}
          </div>
          <button
            onClick={() => setErrorMessage(null)}
            className="text-xs text-rose-400 hover:text-white"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 1: INGESTION & CONFIGURATION */}
      {/* ==================================================================== */}
      {activeTab === 'upload' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Upload Box */}
          <div className="lg:col-span-2 space-y-6">
            <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-6 space-y-5">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-base font-semibold text-white flex items-center gap-2">
                    <UploadCloud className="w-5 h-5 text-cyan-400" />
                    Upload Network Log File
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Drag and drop or browse CSV, plain text syslog, iptables, Cisco ASA, or VPC flow logs (Max 5MB).
                  </p>
                </div>
                {fileName && (
                  <span className="px-2.5 py-1 rounded bg-slate-800 text-slate-300 text-xs font-mono border border-slate-700">
                    {fileName} ({(fileSize / 1024).toFixed(1)} KB)
                  </span>
                )}
              </div>

              {/* Drag & Drop Zone */}
              <div
                onDragOver={(e) => e.preventDefault()}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className="border-2 border-dashed border-slate-700 hover:border-cyan-500/80 rounded-xl p-8 text-center cursor-pointer bg-slate-950/50 hover:bg-slate-950 transition-all group"
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".log,.txt,.csv"
                  onChange={handleFileChange}
                  className="hidden"
                />
                <div className="w-12 h-12 rounded-xl bg-slate-900 border border-slate-700 flex items-center justify-center mx-auto text-cyan-400 group-hover:scale-110 transition-transform shadow-xs">
                  <UploadCloud className="w-6 h-6" />
                </div>
                <h3 className="text-sm font-medium text-white mt-3">
                  Click to select a log file or drag & drop here
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Supported: <span className="text-cyan-400">.log</span>, <span className="text-cyan-400">.txt</span>, <span className="text-cyan-400">.csv</span> (Firewall, Syslog, Apache, Zeek, VPC Flows)
                </p>
                <div className="flex items-center justify-center gap-4 mt-3 text-[11px] text-slate-400">
                  <span>Strict 5MB cap</span>
                  <span>•</span>
                  <span>Regex parser (No code execution)</span>
                  <span>•</span>
                  <span>Zero-Trust validation</span>
                </div>
              </div>

              {/* Quick Sample Loaders for Capstone Demo */}
              <div className="rounded-lg border border-slate-800 bg-slate-950/60 p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono flex items-center gap-1.5">
                    <FileCode className="w-4 h-4 text-cyan-400" />
                    Load Capstone Demonstration Samples
                  </span>
                  <span className="text-[11px] text-slate-400">Ready-to-analyze real scenarios</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                  <button
                    type="button"
                    onClick={() => loadSample('firewall')}
                    className="p-3 rounded-lg border border-slate-800 bg-slate-900/80 hover:bg-cyan-950/40 hover:border-cyan-800 text-left transition-colors group"
                  >
                    <div className="text-xs font-semibold text-white group-hover:text-cyan-400 flex items-center justify-between">
                      <span>Firewall Egress</span>
                      <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">
                      Cisco ASA log with LockBit C2 (185.220.101.5) & Cobalt Strike beacons.
                    </p>
                  </button>

                  <button
                    type="button"
                    onClick={() => loadSample('web-proxy')}
                    className="p-3 rounded-lg border border-slate-800 bg-slate-900/80 hover:bg-cyan-950/40 hover:border-cyan-800 text-left transition-colors group"
                  >
                    <div className="text-xs font-semibold text-white group-hover:text-cyan-400 flex items-center justify-between">
                      <span>Web Gateway Log</span>
                      <Globe className="w-3.5 h-3.5 text-amber-400" />
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">
                      Proxy requests to phishing domain & Lumma Stealer delivery URL.
                    </p>
                  </button>

                  <button
                    type="button"
                    onClick={() => loadSample('vpc-flow')}
                    className="p-3 rounded-lg border border-slate-800 bg-slate-900/80 hover:bg-cyan-950/40 hover:border-cyan-800 text-left transition-colors group"
                  >
                    <div className="text-xs font-semibold text-white group-hover:text-cyan-400 flex items-center justify-between">
                      <span>AWS VPC Flow</span>
                      <Server className="w-3.5 h-3.5 text-cyan-400" />
                    </div>
                    <p className="text-[11px] text-slate-400 mt-1 line-clamp-2">
                      Cloud flow logs tracking lateral scanning and Emotet staging probe.
                    </p>
                  </button>
                </div>
              </div>

              {/* Raw Log Text Preview / Manual Paste */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono">
                    Log Content Preview / Direct Input
                  </label>
                  {rawLogText && (
                    <span className="text-[11px] text-slate-400 font-mono">
                      {rawLogText.split('\n').length} lines · {rawLogText.length.toLocaleString()} characters
                    </span>
                  )}
                </div>
                <textarea
                  value={rawLogText}
                  onChange={(e) => {
                    setRawLogText(e.target.value);
                    setFileSize(e.target.value.length);
                    if (!fileName) setFileName('custom_manual_input.log');
                  }}
                  rows={8}
                  placeholder="Paste network connection logs, iptables output, Cisco ASA firewall entries, or CSV text here..."
                  className="w-full rounded-lg bg-slate-950 border border-slate-800 p-3 font-mono text-xs text-slate-300 focus:outline-hidden focus:border-cyan-500 placeholder-slate-600 resize-y"
                />
              </div>

              {/* Analysis CTA */}
              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => {
                    setRawLogText('');
                    setFileName('');
                    setFileSize(0);
                  }}
                  disabled={!rawLogText || isAnalyzing}
                  className="px-4 py-2 rounded-lg text-xs font-medium text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 disabled:opacity-50 transition-colors"
                >
                  Clear Content
                </button>
                <button
                  type="button"
                  onClick={handleAnalyze}
                  disabled={!rawLogText.trim() || isAnalyzing}
                  className="px-6 py-2.5 rounded-lg text-xs font-semibold text-slate-950 bg-gradient-to-r from-cyan-400 to-blue-500 hover:from-cyan-300 hover:to-blue-400 shadow-md shadow-cyan-900/30 flex items-center gap-2 disabled:opacity-50 transition-all"
                >
                  {isAnalyzing ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Parsing & Cross-Referencing...
                    </>
                  ) : (
                    <>
                      <ShieldAlert className="w-4 h-4 text-slate-950" />
                      Start Forensic Threat Analysis
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          {/* Right Configuration & Architecture Sidebar */}
          <div className="space-y-6">
            {/* Triage Settings Card */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 space-y-4">
              <h3 className="text-xs font-semibold text-white uppercase tracking-wider font-mono flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                Investigation Parameters
              </h3>

              <div className="space-y-1.5">
                <label className="text-xs text-slate-300 block font-medium">
                  Investigating Analyst
                </label>
                <input
                  type="text"
                  value={analystName}
                  onChange={(e) => setAnalystName(e.target.value)}
                  className="w-full rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500"
                />
              </div>

              <div className="pt-2 border-t border-slate-800">
                <label className="flex items-center gap-2.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={skipLiveFeeds}
                    onChange={(e) => setSkipLiveFeeds(e.target.checked)}
                    className="rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-cyan-500/20"
                  />
                  <div className="text-xs">
                    <span className="text-slate-200 font-medium block">Local DB Only (Fast Mode)</span>
                    <span className="text-[11px] text-slate-400 block">
                      Skip querying external public threat feeds for faster offline batch triage.
                    </span>
                  </div>
                </label>
              </div>
            </div>

            {/* Zero-Trust Notice Card */}
            <div className="rounded-xl border border-amber-800/60 bg-amber-950/20 p-5 space-y-2.5">
              <div className="flex items-center gap-2 text-amber-400 font-semibold text-xs uppercase tracking-wider font-mono">
                <Shield className="w-4 h-4" />
                Zero-Trust Compliance Standard
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                <strong className="text-amber-300">Mandatory Rule:</strong> The presence of an IP or domain in a log does <span className="underline">not</span> make it malicious, nor does the absence of a threat record make it safe.
              </p>
              <p className="text-[11px] text-slate-400 leading-relaxed">
                Unmatched indicators are rigorously designated as <span className="font-mono text-slate-300">UNKNOWN (No Match Found)</span> to prevent false senses of security.
              </p>
            </div>

            {/* Security Safeguards Card */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-5 space-y-3">
              <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider font-mono flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5 text-cyan-400" />
                Ingestion Safeguards
              </h4>
              <ul className="text-xs text-slate-400 space-y-2">
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                  <span><strong>Safe Execution Boundary:</strong> Uploaded logs are processed purely as sanitized strings. No script execution.</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                  <span><strong>Automated Deduplication:</strong> Identical IPs/domains aggregated with occurrence counters.</span>
                </li>
                <li className="flex items-start gap-2">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                  <span><strong>Automatic Alert Generation:</strong> Any matched threat triggers an alert in the Security Alerts queue.</span>
                </li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 2: ANALYSIS RESULTS */}
      {/* ==================================================================== */}
      {activeTab === 'results' && currentSession && (
        <div className="space-y-6">
          {/* Key Metrics Bar (Requirement 9) */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
            {/* 1. Total Extracted */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-4">
              <div className="text-[11px] text-slate-400 font-mono uppercase tracking-wider">
                Total Extracted
              </div>
              <div className="text-2xl font-bold text-white mt-1">
                {currentSession.totalExtracted.toLocaleString()}
              </div>
              <div className="text-[11px] text-slate-400 mt-1 flex items-center gap-1">
                <span>From {currentSession.totalLines} lines</span>
              </div>
            </div>

            {/* 2. Unique Indicators */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-4">
              <div className="text-[11px] text-slate-400 font-mono uppercase tracking-wider">
                Unique Indicators
              </div>
              <div className="text-2xl font-bold text-cyan-400 mt-1">
                {currentSession.uniqueIndicatorsCount.toLocaleString()}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Deduplicated set
              </div>
            </div>

            {/* 3. Known Threat Matches */}
            <div className={`rounded-xl border p-4 ${
              currentSession.threatMatchesCount > 0
                ? 'border-rose-800 bg-rose-950/30'
                : 'border-slate-800 bg-slate-900/80'
            }`}>
              <div className="text-[11px] text-rose-400 font-mono uppercase tracking-wider flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" />
                Threat Matches
              </div>
              <div className="text-2xl font-bold text-rose-400 mt-1">
                {currentSession.threatMatchesCount}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                {currentSession.highRiskCount} High · {currentSession.mediumRiskCount} Med
              </div>
            </div>

            {/* 4. Unmatched Indicators */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-4">
              <div className="text-[11px] text-slate-400 font-mono uppercase tracking-wider">
                Unmatched (Zero-Trust)
              </div>
              <div className="text-2xl font-bold text-slate-300 mt-1">
                {currentSession.unmatchedCount.toLocaleString()}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Classified as UNKNOWN
              </div>
            </div>

            {/* 5. Lookup Failures */}
            <div className="rounded-xl border border-slate-800 bg-slate-900/80 p-4">
              <div className="text-[11px] text-slate-400 font-mono uppercase tracking-wider">
                Lookup Failures
              </div>
              <div className="text-2xl font-bold text-amber-400 mt-1">
                {currentSession.lookupFailuresCount}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Offline or feed errors
              </div>
            </div>
          </div>

          {/* High Priority Threat Match Banner if threats detected */}
          {currentSession.threatMatchesCount > 0 && (
            <div className="rounded-xl border border-rose-800 bg-gradient-to-r from-rose-950/60 via-slate-900 to-slate-900 p-5 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div className="flex items-start gap-3">
                <div className="w-10 h-10 rounded-lg bg-rose-500/20 border border-rose-500/40 flex items-center justify-center text-rose-400 shrink-0">
                  <ShieldAlert className="w-6 h-6 animate-pulse" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    Known Malicious Signatures Detected in Ingested Log
                  </h3>
                  <p className="text-xs text-rose-200/90 mt-0.5">
                    Found {currentSession.threatMatchesCount} confirmed threat match{currentSession.threatMatchesCount > 1 ? 'es' : ''} with active security evidence. Automated incident alerts have been queued for investigation.
                  </p>
                </div>
              </div>

              <div className="flex items-center gap-2.5 shrink-0">
                {onNavigateToAlerts && (
                  <button
                    onClick={onNavigateToAlerts}
                    className="px-3.5 py-2 rounded-lg text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 flex items-center gap-1.5 transition-colors shadow-sm"
                  >
                    <span>View Security Alerts</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}
                <button
                  onClick={() => downloadLogAnalysisPDF(currentSession)}
                  className="px-3.5 py-2 rounded-lg text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 flex items-center gap-1.5 transition-colors shadow-sm"
                >
                  <Download className="w-3.5 h-3.5 text-slate-950" />
                  <span>Download Forensic PDF</span>
                </button>
              </div>
            </div>
          )}

          {/* Action Bar & Filters */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-4 space-y-4">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
              {/* Search Bar */}
              <div className="relative flex-1 max-w-md">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Filter by IP, domain, category, or role..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full rounded-lg bg-slate-950 border border-slate-800 pl-9 pr-3 py-2 text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500 placeholder-slate-500"
                />
              </div>

              {/* Filters */}
              <div className="flex flex-wrap items-center gap-2">
                {/* Severity Filter */}
                <select
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value)}
                  className="rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-slate-300 focus:outline-hidden focus:border-cyan-500"
                >
                  <option value="all">All Severities</option>
                  <option value="HIGH RISK">HIGH RISK</option>
                  <option value="MEDIUM RISK">MEDIUM RISK</option>
                  <option value="LOW RISK">LOW RISK</option>
                  <option value="UNKNOWN">UNKNOWN</option>
                </select>

                {/* Match Status Filter */}
                <select
                  value={filterMatchStatus}
                  onChange={(e) => setFilterMatchStatus(e.target.value)}
                  className="rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-slate-300 focus:outline-hidden focus:border-cyan-500"
                >
                  <option value="all">All Match Statuses</option>
                  <option value="Known Indicator Match">Threat Matches Only</option>
                  <option value="No Match Found">Unmatched Only</option>
                  <option value="Lookup Failed">Failures Only</option>
                </select>

                {/* Type Filter */}
                <select
                  value={filterType}
                  onChange={(e) => setFilterType(e.target.value)}
                  className="rounded-lg bg-slate-950 border border-slate-800 px-3 py-2 text-xs text-slate-300 focus:outline-hidden focus:border-cyan-500"
                >
                  <option value="all">All Types</option>
                  <option value="ip">IP Addresses Only</option>
                  <option value="domain">Domains Only</option>
                </select>

                {/* Download PDF button */}
                <button
                  onClick={() => downloadLogAnalysisPDF(currentSession)}
                  className="px-3 py-2 rounded-lg text-xs font-semibold text-slate-900 bg-cyan-400 hover:bg-cyan-300 flex items-center gap-1.5 transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Export PDF</span>
                </button>
              </div>
            </div>

            {/* Results Counter */}
            <div className="text-[11px] text-slate-400 flex items-center justify-between border-t border-slate-800/80 pt-3">
              <span>
                Showing <strong>{filteredIndicators.length}</strong> of <strong>{currentSession.uniqueIndicatorsCount}</strong> unique indicators from <strong>{currentSession.fileName}</strong> ({currentSession.logFormat})
              </span>
              <span className="font-mono text-slate-400">
                Analyzed at {new Date(currentSession.timestamp).toLocaleTimeString()}
              </span>
            </div>
          </div>

          {/* Indicators Correlation Table */}
          <div className="rounded-xl border border-slate-800 bg-slate-900/90 overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs text-slate-300 border-collapse">
                <thead className="bg-slate-950 border-b border-slate-800 text-[11px] font-mono uppercase tracking-wider text-slate-400">
                  <tr>
                    <th className="py-3 px-4">Indicator</th>
                    <th className="py-3 px-3">Type</th>
                    <th className="py-3 px-3">Role in Log</th>
                    <th className="py-3 px-3">Occurrences</th>
                    <th className="py-3 px-3">Match Status</th>
                    <th className="py-3 px-3">Category</th>
                    <th className="py-3 px-3">Risk Level</th>
                    <th className="py-3 px-3">Source</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-sans">
                  {filteredIndicators.length === 0 ? (
                    <tr>
                      <td colSpan={9} className="py-12 text-center text-slate-500">
                        <Search className="w-8 h-8 mx-auto mb-2 text-slate-600" />
                        No indicators match the current filter criteria.
                      </td>
                    </tr>
                  ) : (
                    filteredIndicators.map((item, idx) => {
                      const isThreat = item.matchStatus === 'Known Indicator Match';
                      const isHigh = item.severity === 'HIGH RISK';
                      const isMed = item.severity === 'MEDIUM RISK';
                      const isLow = item.severity === 'LOW RISK';

                      return (
                        <tr
                          key={`${item.type}-${item.indicator}-${idx}`}
                          className={`transition-colors ${
                            isHigh
                              ? 'bg-rose-950/20 hover:bg-rose-950/30'
                              : isMed
                              ? 'bg-amber-950/10 hover:bg-amber-950/20'
                              : 'hover:bg-slate-800/40'
                          }`}
                        >
                          {/* Indicator */}
                          <td className="py-3 px-4 font-mono font-medium text-white">
                            <div className="flex items-center gap-2">
                              {item.type === 'ip' ? (
                                <Server className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                              ) : (
                                <Globe className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                              )}
                              <span className="truncate max-w-[200px]" title={item.indicator}>
                                {item.indicator}
                              </span>
                              <button
                                onClick={() => copyToClipboard(item.indicator)}
                                className="text-slate-500 hover:text-slate-300 p-0.5"
                                title="Copy indicator"
                              >
                                {copiedIndicator === item.indicator ? (
                                  <Check className="w-3 h-3 text-emerald-400" />
                                ) : (
                                  <Copy className="w-3 h-3" />
                                )}
                              </button>
                            </div>
                            {item.asn && (
                              <div className="text-[10px] text-slate-400 font-sans mt-0.5">
                                {item.asn} {item.country && `(${item.country})`}
                              </div>
                            )}
                          </td>

                          {/* Type */}
                          <td className="py-3 px-3 uppercase font-mono text-[11px] text-slate-400">
                            {item.subType || item.type}
                          </td>

                          {/* Role in Log */}
                          <td className="py-3 px-3">
                            <div className="flex flex-wrap gap-1">
                              {item.roles.map((role) => (
                                <span
                                  key={role}
                                  className={`px-1.5 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider ${
                                    role === 'destination'
                                      ? 'bg-purple-950/80 text-purple-300 border border-purple-800/60'
                                      : role === 'source'
                                      ? 'bg-blue-950/80 text-blue-300 border border-blue-800/60'
                                      : 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/60'
                                  }`}
                                >
                                  {role}
                                </span>
                              ))}
                            </div>
                            {item.ports && item.ports.length > 0 && (
                              <div className="text-[10px] text-slate-400 font-mono mt-0.5">
                                Port: {item.ports.slice(0, 3).join(', ')}
                              </div>
                            )}
                          </td>

                          {/* Occurrences */}
                          <td className="py-3 px-3 font-mono">
                            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-xs">
                              {item.occurrences}x
                            </span>
                          </td>

                          {/* Match Status */}
                          <td className="py-3 px-3">
                            {isThreat ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-rose-950 text-rose-300 border border-rose-800">
                                <AlertTriangle className="w-3 h-3 text-rose-400" />
                                Threat Match
                              </span>
                            ) : item.matchStatus === 'Lookup Failed' ? (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-amber-950 text-amber-300 border border-amber-800">
                                Lookup Failed
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium bg-slate-800 text-slate-400 border border-slate-700">
                                Unmatched
                              </span>
                            )}
                          </td>

                          {/* Category */}
                          <td className="py-3 px-3">
                            <span className="text-slate-300 text-xs font-medium">
                              {item.category}
                            </span>
                          </td>

                          {/* Risk Level */}
                          <td className="py-3 px-3">
                            <span
                              className={`px-2 py-0.5 rounded-full text-[10px] font-bold tracking-wider uppercase font-mono ${
                                isHigh
                                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                                  : isMed
                                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                                  : isLow
                                  ? 'bg-teal-500/20 text-teal-300 border border-teal-500/40'
                                  : 'bg-slate-800 text-slate-400 border border-slate-700'
                              }`}
                            >
                              {item.severity}
                            </span>
                          </td>

                          {/* Source */}
                          <td className="py-3 px-3 text-slate-400 text-[11px] max-w-[130px] truncate" title={item.source}>
                            {item.source}
                          </td>

                          {/* Actions */}
                          <td className="py-3 px-4 text-right">
                            <div className="flex items-center justify-end gap-1.5">
                              <button
                                onClick={() => setInspectIndicator(item)}
                                className="p-1.5 rounded-md hover:bg-slate-800 text-slate-400 hover:text-white transition-colors"
                                title="View Forensic Evidence"
                              >
                                <Eye className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => onInvestigateIndicator(item.indicator, item.type)}
                                className="p-1.5 rounded-md hover:bg-cyan-950/80 text-cyan-400 hover:text-cyan-300 transition-colors"
                                title="Open in Primary Workstation"
                              >
                                <ExternalLink className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 3: RAW LOG INSPECTOR */}
      {/* ==================================================================== */}
      {activeTab === 'raw_inspector' && currentSession && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <Terminal className="w-4 h-4 text-emerald-400" />
                Raw Line Extraction & Ingestion Telemetry
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Inspect how the forensic line parser parsed and tagged individual source/destination indicators.
              </p>
            </div>
            <span className="text-xs font-mono text-cyan-400 bg-slate-950 px-2.5 py-1 rounded border border-slate-800">
              {currentSession.logFormat}
            </span>
          </div>

          <div className="rounded-lg bg-slate-950 border border-slate-800 p-4 max-h-[500px] overflow-y-auto space-y-2.5 font-mono text-xs">
            {(!currentSession.sampleLines || currentSession.sampleLines.length === 0) ? (
              <div className="text-slate-500 py-6 text-center">No parsed sample lines available.</div>
            ) : (
              currentSession.sampleLines.map((line) => (
                <div key={line.lineNumber} className="p-2.5 rounded bg-slate-900/80 border border-slate-800/80 space-y-1">
                  <div className="flex items-center justify-between text-[11px] text-slate-400">
                    <span className="text-cyan-400">Line #{line.lineNumber}</span>
                    {line.timestamp && <span>{line.timestamp}</span>}
                  </div>
                  <div className="text-slate-200 text-xs break-all">
                    {line.raw}
                  </div>
                  {(line.srcIp || line.dstIp || line.domain) && (
                    <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px]">
                      {line.srcIp && (
                        <span className="px-1.5 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">
                          src: {line.srcIp}{line.srcPort ? `:${line.srcPort}` : ''}
                        </span>
                      )}
                      {line.dstIp && (
                        <span className="px-1.5 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800">
                          dst: {line.dstIp}{line.dstPort ? `:${line.dstPort}` : ''}
                        </span>
                      )}
                      {line.domain && (
                        <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                          dom: {line.domain}
                        </span>
                      )}
                      {line.protocol && (
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                          proto: {line.protocol}
                        </span>
                      )}
                      {line.action && (
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                          action: {line.action}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 4: SESSION HISTORY */}
      {/* ==================================================================== */}
      {activeTab === 'history' && (
        <div className="rounded-xl border border-slate-800 bg-slate-900/90 p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                <History className="w-4 h-4 text-amber-400" />
                Historical Network Log Analyses
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Persisted forensic log investigations stored in database. Click any session to reload its results.
              </p>
            </div>
            <button
              onClick={loadSessions}
              disabled={loadingPastSessions}
              className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300"
              title="Refresh sessions"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingPastSessions ? 'animate-spin' : ''}`} />
            </button>
          </div>

          <div className="divide-y divide-slate-800/80">
            {pastSessions.length === 0 ? (
              <div className="py-12 text-center text-slate-500 text-xs">
                No past network log analyses found. Analyze your first log file above.
              </div>
            ) : (
              pastSessions.map((sess) => (
                <div
                  key={sess.id}
                  onClick={() => {
                    setCurrentSession(sess);
                    setActiveTab('results');
                  }}
                  className="py-3 px-2 flex items-center justify-between hover:bg-slate-800/40 cursor-pointer rounded-lg transition-colors group"
                >
                  <div className="flex items-center gap-3">
                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center font-bold text-xs ${
                      sess.threatMatchesCount > 0
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : 'bg-slate-800 text-slate-400'
                    }`}>
                      {sess.threatMatchesCount > 0 ? sess.threatMatchesCount : '0'}
                    </div>
                    <div>
                      <span className="text-xs font-semibold text-white group-hover:text-cyan-400 transition-colors block">
                        {sess.fileName}
                      </span>
                      <span className="text-[11px] text-slate-400 flex items-center gap-2">
                        <span>{sess.logFormat}</span>
                        <span>•</span>
                        <span>{sess.uniqueIndicatorsCount} unique indicators</span>
                        <span>•</span>
                        <span>{new Date(sess.timestamp).toLocaleString()}</span>
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        downloadLogAnalysisPDF(sess);
                      }}
                      className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300"
                      title="Download PDF Report"
                    >
                      <Download className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={(e) => handleDeleteSession(sess.id, e)}
                      className="p-1.5 rounded bg-slate-800 hover:bg-rose-950 text-slate-400 hover:text-rose-400"
                      title="Delete Session"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Forensic Evidence Modal */}
      {inspectIndicator && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-xs p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-xl w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-[11px] font-mono text-cyan-400 uppercase tracking-wider block">
                  Indicator Evidence Details
                </span>
                <h3 className="text-lg font-bold text-white font-mono mt-0.5">
                  {inspectIndicator.indicator}
                </h3>
              </div>
              <button
                onClick={() => setInspectIndicator(null)}
                className="text-slate-400 hover:text-white p-1"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 gap-2 p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px]">
                <div>
                  <span className="text-slate-500 block">Match Status</span>
                  <span className="text-white font-semibold">{inspectIndicator.matchStatus}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Risk Level</span>
                  <span className={`font-semibold ${
                    inspectIndicator.severity === 'HIGH RISK' ? 'text-rose-400' :
                    inspectIndicator.severity === 'MEDIUM RISK' ? 'text-amber-400' :
                    inspectIndicator.severity === 'LOW RISK' ? 'text-teal-400' : 'text-slate-400'
                  }`}>
                    {inspectIndicator.severity}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block">Observed Roles</span>
                  <span className="text-slate-300">{inspectIndicator.roles.join(', ')}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Occurrences</span>
                  <span className="text-slate-300">{inspectIndicator.occurrences} events</span>
                </div>
              </div>

              <div>
                <span className="text-slate-400 font-semibold block mb-1">Forensic Evidence & Correlation:</span>
                <p className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 leading-relaxed font-mono text-[11px]">
                  {inspectIndicator.evidence}
                </p>
              </div>

              {inspectIndicator.liveFeeds && inspectIndicator.liveFeeds.length > 0 && (
                <div>
                  <span className="text-slate-400 font-semibold block mb-1">Public Feeds Intelligence:</span>
                  <div className="space-y-1.5">
                    {inspectIndicator.liveFeeds.map((feed) => (
                      <div key={feed.id} className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px]">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-white">{feed.name}</span>
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                            feed.isThreatFound ? 'bg-rose-950 text-rose-300' : 'bg-slate-800 text-slate-400'
                          }`}>
                            {feed.status.toUpperCase()}
                          </span>
                        </div>
                        <p className="text-slate-400 mt-1">{feed.details}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => {
                  onInvestigateIndicator(inspectIndicator.indicator, inspectIndicator.type);
                  setInspectIndicator(null);
                }}
                className="px-4 py-2 rounded-lg text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 flex items-center gap-1.5"
              >
                <span>Investigate in Workstation</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
