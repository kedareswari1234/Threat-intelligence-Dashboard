import React, { useState } from 'react';
import {
  BellRing,
  ShieldAlert,
  CheckCircle2,
  Clock,
  Filter,
  Search,
  ExternalLink,
  AlertTriangle,
  Flame,
  FileText,
  UserCheck,
  RotateCcw,
  Eye,
  X,
  Layers,
  Copy,
  Check,
  Info
} from 'lucide-react';
import { SecurityAlert, AlertStatus, SeverityLevel } from '../types/threat';

interface SecurityAlertsViewProps {
  alerts: SecurityAlert[];
  onUpdateStatus: (
    id: string,
    status: AlertStatus,
    analyst?: string,
    resolutionNotes?: string
  ) => Promise<void>;
  onInspectIndicator: (indicator: string, type: 'ip' | 'domain') => void;
  isLoading: boolean;
}

export const SecurityAlertsView: React.FC<SecurityAlertsViewProps> = ({
  alerts,
  onUpdateStatus,
  onInspectIndicator,
  isLoading
}) => {
  // Navigation tabs: 'active' (Unresolved/Pending) vs 'history' (Reviewed & Resolved audit)
  const [activeTab, setActiveTab] = useState<'active' | 'history'>('active');
  const [severityFilter, setSeverityFilter] = useState<'All' | SeverityLevel>('All');
  const [statusFilter, setStatusFilter] = useState<'All' | AlertStatus>('All');
  const [searchQuery, setSearchQuery] = useState('');
  
  // Modal states
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [isResolveModalOpen, setIsResolveModalOpen] = useState(false);
  const [targetAlertForResolve, setTargetAlertForResolve] = useState<SecurityAlert | null>(null);
  const [resolutionNotes, setResolutionNotes] = useState('');
  const [analystName, setAnalystName] = useState('SOC Lead Analyst');
  const [copiedIndicator, setCopiedIndicator] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Copy indicator to clipboard
  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndicator(text);
    setTimeout(() => setCopiedIndicator(null), 2000);
  };

  // Severity styling
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

  const getStatusBadge = (status: AlertStatus) => {
    switch (status) {
      case 'Active':
        return 'text-rose-300 bg-rose-500/15 border-rose-500/30';
      case 'Reviewed':
        return 'text-amber-300 bg-amber-500/15 border-amber-500/30';
      case 'Resolved':
        return 'text-emerald-300 bg-emerald-500/15 border-emerald-500/30';
      default:
        return 'text-slate-300 bg-slate-800 border-slate-700';
    }
  };

  // Counts
  const activeAlerts = alerts.filter((a) => a.status === 'Active');
  const reviewedAlerts = alerts.filter((a) => a.status === 'Reviewed');
  const resolvedAlerts = alerts.filter((a) => a.status === 'Resolved');
  const historyAlerts = alerts.filter((a) => a.status === 'Reviewed' || a.status === 'Resolved');

  // Filter based on active tab and filters
  const currentTabPool = activeTab === 'active' ? activeAlerts : historyAlerts;

  const filteredAlerts = currentTabPool.filter((alert) => {
    const q = searchQuery.toLowerCase().trim();
    const matchesSearch =
      !q ||
      alert.indicator.toLowerCase().includes(q) ||
      alert.description.toLowerCase().includes(q) ||
      alert.source.toLowerCase().includes(q) ||
      alert.category.toLowerCase().includes(q) ||
      (alert.evidence && alert.evidence.toLowerCase().includes(q));

    const matchesSeverity = severityFilter === 'All' || alert.severity === severityFilter;
    const matchesStatus =
      activeTab === 'active'
        ? true
        : statusFilter === 'All' || alert.status === statusFilter;

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  // Action handlers with error handling
  const handleMarkReviewed = async (alert: SecurityAlert) => {
    setActionError(null);
    setIsSubmitting(true);
    try {
      await onUpdateStatus(alert.id, 'Reviewed', analystName);
      if (selectedAlert?.id === alert.id) {
        setSelectedAlert({
          ...selectedAlert,
          status: 'Reviewed',
          reviewedAt: new Date().toISOString(),
          reviewedBy: analystName
        });
      }
    } catch (err: any) {
      setActionError(err?.message || 'Failed to update alert to Reviewed state.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleOpenResolveModal = (alert: SecurityAlert) => {
    setTargetAlertForResolve(alert);
    setResolutionNotes(`Verified and mitigated. Confirmed threat profile: ${alert.category} from ${alert.source}. Firewall rule or DNS sinkhole applied.`);
    setIsResolveModalOpen(true);
  };

  const handleConfirmResolve = async () => {
    if (!targetAlertForResolve) return;
    setActionError(null);
    setIsSubmitting(true);
    try {
      await onUpdateStatus(
        targetAlertForResolve.id,
        'Resolved',
        analystName,
        resolutionNotes.trim() || 'Remediation completed by SOC analyst.'
      );
      if (selectedAlert?.id === targetAlertForResolve.id) {
        setSelectedAlert({
          ...selectedAlert,
          status: 'Resolved',
          reviewedAt: new Date().toISOString(),
          reviewedBy: analystName,
          resolutionNotes: resolutionNotes.trim()
        });
      }
      setIsResolveModalOpen(false);
      setTargetAlertForResolve(null);
    } catch (err: any) {
      setActionError(err?.message || 'Failed to resolve alert.');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleReopenAlert = async (alert: SecurityAlert) => {
    setActionError(null);
    setIsSubmitting(true);
    try {
      await onUpdateStatus(alert.id, 'Active', analystName, 'Re-opened for secondary investigation');
      if (selectedAlert?.id === alert.id) {
        setSelectedAlert({
          ...selectedAlert,
          status: 'Active'
        });
      }
    } catch (err: any) {
      setActionError(err?.message || 'Failed to re-open alert.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 mb-1">
            <span>AUTOMATED THREAT ALERT & NOTIFICATION ENGINE</span>
            <span aria-hidden="true">·</span>
            <span>REAL-TIME IOC TRIAGE</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-extrabold text-white flex items-center gap-2.5">
            <BellRing className="w-6 h-6 text-rose-400" />
            Security Alerts
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-2xl">
            Real-time incident notifications triggered by confirmed threat intelligence matches.
            Equipped with 30-minute automated deduplication, severity prioritization, and forensic audit logs.
          </p>
        </div>

        {/* Counter Summary Badges */}
        <div className="flex items-center gap-2 shrink-0">
          <div className="px-3.5 py-2 rounded-lg bg-rose-500/10 border border-rose-500/30 text-center">
            <div className="text-lg font-mono font-black text-rose-400 tabular-nums">
              {activeAlerts.length}
            </div>
            <div className="text-[10px] uppercase font-mono tracking-wider text-rose-300">
              Active / Unresolved
            </div>
          </div>
          <div className="px-3.5 py-2 rounded-lg bg-amber-500/10 border border-amber-500/30 text-center">
            <div className="text-lg font-mono font-black text-amber-400 tabular-nums">
              {reviewedAlerts.length}
            </div>
            <div className="text-[10px] uppercase font-mono tracking-wider text-amber-300">
              Reviewed
            </div>
          </div>
          <div className="px-3.5 py-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-center">
            <div className="text-lg font-mono font-black text-emerald-400 tabular-nums">
              {resolvedAlerts.length}
            </div>
            <div className="text-[10px] uppercase font-mono tracking-wider text-emerald-300">
              Resolved
            </div>
          </div>
        </div>
      </div>

      {/* Global Error Banner */}
      {actionError && (
        <div className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-3.5 flex items-center justify-between text-xs text-rose-300">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{actionError}</span>
          </div>
          <button
            onClick={() => setActionError(null)}
            className="text-rose-400 hover:text-white font-mono text-[11px]"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Primary Navigation Tabs: Active vs Alert History */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('active')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'active'
                ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 shadow-xs'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <span>Active Alerts Pending Triage</span>
            <span className="px-1.5 py-0.2 rounded-full bg-rose-500/30 text-rose-200 text-[10px] font-mono">
              {activeAlerts.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('history')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'history'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-xs'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Clock className="w-4 h-4 text-cyan-400" />
            <span>Alert History & Audit Log</span>
            <span className="px-1.5 py-0.2 rounded-full bg-cyan-500/30 text-cyan-200 text-[10px] font-mono">
              {historyAlerts.length}
            </span>
          </button>
        </div>

        {/* Analyst Signature Selector */}
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <span className="text-[11px]">Active Operator:</span>
          <select
            value={analystName}
            onChange={(e) => setAnalystName(e.target.value)}
            className="px-2.5 py-1 bg-slate-900 border border-slate-800 rounded text-xs text-white focus:outline-hidden focus:border-cyan-500"
          >
            <option value="SOC Lead Analyst">SOC Lead Analyst</option>
            <option value="Senior Threat Hunter">Senior Threat Hunter</option>
            <option value="Incident Responder">Incident Responder</option>
            <option value="Security Engineer">Security Engineer</option>
          </select>
        </div>
      </div>

      {/* Filter and Search Controls */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-3 bg-slate-900 border border-slate-800 rounded-xl p-4">
        {/* Search */}
        <div className="md:col-span-5 relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by IP, domain, category, evidence..."
            className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-hidden focus:border-cyan-500/60 font-mono"
          />
        </div>

        {/* Severity Filter */}
        <div className="md:col-span-4 flex items-center gap-1 text-xs">
          <span className="text-slate-400 font-mono text-[11px] mr-1 flex items-center gap-1">
            <Filter className="w-3 h-3 text-cyan-400" /> Severity:
          </span>
          {(['All', 'HIGH RISK', 'MEDIUM RISK', 'LOW RISK'] as const).map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1.5 rounded text-[11px] font-mono transition-colors ${
                severityFilter === sev
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                  : 'text-slate-400 hover:text-white bg-slate-950 border border-slate-800/80'
              }`}
            >
              {sev === 'All' ? 'All' : sev.replace(' RISK', '')}
            </button>
          ))}
        </div>

        {/* Status Filter (Only in History Tab) */}
        {activeTab === 'history' && (
          <div className="md:col-span-3 flex items-center gap-1 text-xs">
            <span className="text-slate-400 font-mono text-[11px] mr-1">Status:</span>
            {(['All', 'Reviewed', 'Resolved'] as const).map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1.5 rounded text-[11px] font-mono transition-colors ${
                  statusFilter === st
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-bold'
                    : 'text-slate-400 hover:text-white bg-slate-950 border border-slate-800/80'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        )}

        {/* Deduplication Policy Banner Note */}
        <div className={`${activeTab === 'history' ? 'md:col-span-12' : 'md:col-span-3'} flex items-center justify-end text-[11px] font-mono text-slate-400 gap-1.5`}>
          <Layers className="w-3.5 h-3.5 text-cyan-400" />
          <span>Dedup Window: <strong className="text-slate-300">30 mins</strong></span>
        </div>
      </div>

      {/* Alerts Feed Cards */}
      <div className="space-y-3.5">
        {filteredAlerts.map((alert) => {
          const hasMultipleOccurrences = (alert.occurrenceCount || 1) > 1;
          const isHigh = alert.severity === 'HIGH RISK';

          return (
            <div
              key={alert.id}
              className={`rounded-xl border transition-all ${
                alert.status === 'Active'
                  ? isHigh
                    ? 'border-rose-500/40 bg-slate-900/90 hover:border-rose-500/70'
                    : 'border-amber-500/30 bg-slate-900/90 hover:border-amber-500/60'
                  : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
              } p-5 shadow-xs`}
            >
              {/* Card Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${
                    isHigh ? 'bg-rose-500/15 text-rose-400' : 'bg-amber-500/15 text-amber-400'
                  }`}>
                    <ShieldAlert className="w-5 h-5 shrink-0" />
                  </div>
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-mono font-bold text-white tracking-wide">
                        {alert.indicator}
                      </span>
                      <button
                        onClick={() => handleCopy(alert.indicator)}
                        className="text-slate-500 hover:text-cyan-400 p-0.5 transition-colors"
                        title="Copy indicator"
                      >
                        {copiedIndicator === alert.indicator ? (
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <Copy className="w-3.5 h-3.5" />
                        )}
                      </button>
                      <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300">
                        {alert.type}
                      </span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${getSeverityStyle(alert.severity)}`}>
                        {alert.severity}
                      </span>
                      {hasMultipleOccurrences && (
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-300 border border-indigo-500/40 flex items-center gap-1 font-semibold">
                          <Layers className="w-3 h-3 text-indigo-400" />
                          {alert.occurrenceCount}x Observed
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-cyan-400 font-medium mt-1 flex items-center gap-2">
                      <span>Threat Category: <strong className="text-slate-200">{alert.category}</strong></span>
                      <span className="text-slate-600">·</span>
                      <span>Source: <strong className="text-slate-300 font-mono text-[11px]">{alert.source}</strong></span>
                    </div>
                  </div>
                </div>

                {/* Right Status Badge & Primary Investigate CTA */}
                <div className="flex items-center gap-2 shrink-0 self-start sm:self-auto">
                  <span className={`text-xs font-mono px-2.5 py-1 rounded border font-semibold ${getStatusBadge(alert.status)}`}>
                    {alert.status}
                  </span>

                  <button
                    onClick={() => onInspectIndicator(alert.indicator, alert.type)}
                    className="px-2.5 py-1 text-xs font-medium text-slate-200 hover:text-white bg-slate-800 hover:bg-slate-700 rounded border border-slate-700 transition-colors inline-flex items-center gap-1.5"
                    title="Open in Investigation Workstation"
                  >
                    <ExternalLink className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Investigate</span>
                  </button>

                  <button
                    onClick={() => setSelectedAlert(alert)}
                    className="px-2.5 py-1 text-xs font-medium text-slate-300 hover:text-white bg-slate-950 hover:bg-slate-800 rounded border border-slate-800 transition-colors inline-flex items-center gap-1"
                    title="View Full Forensic Evidence"
                  >
                    <Eye className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Details</span>
                  </button>
                </div>
              </div>

              {/* Threat Description & Evidence Excerpt */}
              <div className="mt-3 space-y-2">
                <p className="text-xs sm:text-sm text-slate-300 leading-relaxed font-sans">
                  {alert.description}
                </p>

                {alert.evidence && (
                  <div className="rounded-lg bg-slate-950/80 border border-slate-800/80 p-3 text-xs font-mono text-slate-300">
                    <span className="text-cyan-400 font-bold block text-[10px] uppercase mb-1">
                      Correlated Forensic Evidence:
                    </span>
                    <p className="line-clamp-2 text-slate-300 leading-relaxed">
                      {alert.evidence}
                    </p>
                  </div>
                )}

                {/* Review Notes if available */}
                {alert.resolutionNotes && (
                  <div className="rounded-lg bg-emerald-950/20 border border-emerald-500/20 p-2.5 text-xs text-emerald-200 flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <span className="font-semibold text-emerald-300">Resolution Audit Note: </span>
                      <span>{alert.resolutionNotes}</span>
                      {alert.reviewedBy && (
                        <span className="text-emerald-400/80 font-mono text-[10px] ml-2">
                          (Resolved by {alert.reviewedBy} at {new Date(alert.reviewedAt || alert.createdAt).toLocaleTimeString()})
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </div>

              {/* Card Footer: Metadata and Triage Workflow Controls */}
              <div className="mt-4 pt-3 border-t border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs text-slate-400 font-mono">
                <div className="flex flex-wrap items-center gap-3 sm:gap-5 text-[11px]">
                  <span>
                    Detected: <strong className="text-slate-300">{new Date(alert.createdAt).toLocaleString()}</strong>
                  </span>
                  {alert.lastObservedAt && alert.lastObservedAt !== alert.createdAt && (
                    <span>
                      Last Repeated: <strong className="text-cyan-300">{new Date(alert.lastObservedAt).toLocaleTimeString()}</strong>
                    </span>
                  )}
                  {alert.reviewedBy && (
                    <span>
                      Reviewer: <strong className="text-slate-300">{alert.reviewedBy}</strong>
                    </span>
                  )}
                </div>

                {/* Interactive Triage Workflow Buttons */}
                <div className="flex items-center gap-2 font-sans self-end md:self-auto">
                  {alert.status === 'Active' && (
                    <>
                      <button
                        onClick={() => handleMarkReviewed(alert)}
                        disabled={isSubmitting}
                        className="px-3 py-1.5 text-xs font-semibold text-amber-300 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 rounded-lg transition-colors inline-flex items-center gap-1.5 disabled:opacity-50"
                      >
                        <UserCheck className="w-3.5 h-3.5" />
                        <span>Mark as Reviewed</span>
                      </button>

                      <button
                        onClick={() => handleOpenResolveModal(alert)}
                        disabled={isSubmitting}
                        className="px-3 py-1.5 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 rounded-lg transition-colors inline-flex items-center gap-1.5 disabled:opacity-50"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Resolve Alert</span>
                      </button>
                    </>
                  )}

                  {alert.status === 'Reviewed' && (
                    <>
                      <button
                        onClick={() => handleOpenResolveModal(alert)}
                        disabled={isSubmitting}
                        className="px-3 py-1.5 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 rounded-lg transition-colors inline-flex items-center gap-1.5 disabled:opacity-50"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Mark as Resolved</span>
                      </button>

                      <button
                        onClick={() => handleReopenAlert(alert)}
                        disabled={isSubmitting}
                        className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors inline-flex items-center gap-1.5 disabled:opacity-50"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        <span>Re-open</span>
                      </button>
                    </>
                  )}

                  {alert.status === 'Resolved' && (
                    <button
                      onClick={() => handleReopenAlert(alert)}
                      disabled={isSubmitting}
                      className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors inline-flex items-center gap-1.5 disabled:opacity-50"
                    >
                      <RotateCcw className="w-3.5 h-3.5" />
                      <span>Re-open for Review</span>
                    </button>
                  )}
                </div>
              </div>
            </div>
          );
        })}

        {filteredAlerts.length === 0 && (
          <div className="rounded-xl border border-slate-800 bg-slate-900 p-12 text-center text-xs text-slate-400">
            <BellRing className="w-8 h-8 text-slate-600 mx-auto mb-3" />
            <p className="text-slate-300 font-semibold mb-1">
              {activeTab === 'active'
                ? 'No active security alerts pending triage'
                : 'No alert history matching filter criteria'}
            </p>
            <p className="text-slate-500 max-w-md mx-auto">
              {activeTab === 'active'
                ? 'Security alerts are automatically dispatched when newly analyzed indicators correlate with confirmed malicious threat intelligence.'
                : 'Try adjusting your severity or search query filters above.'}
            </p>
          </div>
        )}
      </div>

      {/* MODAL 1: Full Forensic Alert Details Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs">
          <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-6 max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <ShieldAlert className="w-5 h-5 text-rose-400" />
                <h2 className="text-lg font-bold text-white font-sans">
                  Security Alert Forensic Dossier
                </h2>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="p-1 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="mt-4 space-y-4 text-xs">
              {/* Alert Banner */}
              <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div>
                  <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">
                    TARGET INDICATOR
                  </div>
                  <div className="text-base font-mono font-bold text-white flex items-center gap-2">
                    {selectedAlert.indicator}
                    <button
                      onClick={() => handleCopy(selectedAlert.indicator)}
                      className="text-slate-500 hover:text-cyan-400"
                    >
                      {copiedIndicator === selectedAlert.indicator ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold border ${getSeverityStyle(selectedAlert.severity)}`}>
                    {selectedAlert.severity}
                  </span>
                  <span className={`px-2.5 py-1 rounded text-xs font-mono font-semibold border ${getStatusBadge(selectedAlert.status)}`}>
                    {selectedAlert.status}
                  </span>
                </div>
              </div>

              {/* Grid Attributes */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">INDICATOR TYPE</span>
                  <span className="font-mono text-slate-200 uppercase font-semibold">{selectedAlert.type}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">THREAT CATEGORY</span>
                  <span className="font-semibold text-slate-200">{selectedAlert.category}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">INTELLIGENCE SOURCE</span>
                  <span className="font-semibold text-slate-200 truncate block">{selectedAlert.source}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">DETECTION TIME</span>
                  <span className="font-mono text-slate-200">{new Date(selectedAlert.createdAt).toLocaleString()}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">LAST OBSERVED</span>
                  <span className="font-mono text-slate-200">{new Date(selectedAlert.lastObservedAt || selectedAlert.createdAt).toLocaleTimeString()}</span>
                </div>
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80">
                  <span className="text-[10px] font-mono text-slate-500 uppercase block">OCCURRENCE COUNT</span>
                  <span className="font-mono text-indigo-300 font-bold">{selectedAlert.occurrenceCount || 1}x In Dedup Window</span>
                </div>
              </div>

              {/* Description */}
              <div>
                <span className="text-[11px] font-semibold text-slate-400 block mb-1">Incident Summary:</span>
                <p className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 leading-relaxed font-sans">
                  {selectedAlert.description}
                </p>
              </div>

              {/* Forensic Evidence */}
              <div>
                <span className="text-[11px] font-semibold text-cyan-400 block mb-1">Matching Threat Evidence:</span>
                <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 font-mono text-[11px] leading-relaxed max-h-48 overflow-y-auto whitespace-pre-wrap">
                  {selectedAlert.evidence || 'No extended forensic evidence recorded.'}
                </div>
              </div>

              {/* Resolution / Review Audit Record */}
              {(selectedAlert.reviewedBy || selectedAlert.resolutionNotes) && (
                <div className="p-3 rounded-lg bg-slate-950 border border-emerald-500/30">
                  <span className="text-[11px] font-semibold text-emerald-400 block mb-1">Audit Trail Record:</span>
                  <div className="text-slate-300 space-y-1">
                    {selectedAlert.reviewedBy && (
                      <p>Reviewer: <strong className="text-white">{selectedAlert.reviewedBy}</strong> ({new Date(selectedAlert.reviewedAt || selectedAlert.createdAt).toLocaleString()})</p>
                    )}
                    {selectedAlert.resolutionNotes && (
                      <p>Notes: <span className="text-emerald-200">{selectedAlert.resolutionNotes}</span></p>
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Modal Footer */}
            <div className="mt-6 pt-4 border-t border-slate-800 flex items-center justify-between">
              <button
                onClick={() => {
                  setSelectedAlert(null);
                  onInspectIndicator(selectedAlert.indicator, selectedAlert.type);
                }}
                className="px-3 py-1.5 text-xs font-semibold text-cyan-400 hover:text-cyan-300 hover:bg-slate-800 rounded-lg transition-colors flex items-center gap-1.5"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>Open in Workstation</span>
              </button>

              <div className="flex items-center gap-2">
                {selectedAlert.status === 'Active' && (
                  <button
                    onClick={() => handleMarkReviewed(selectedAlert)}
                    disabled={isSubmitting}
                    className="px-3 py-1.5 text-xs font-semibold text-amber-300 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 rounded-lg transition-colors"
                  >
                    Mark as Reviewed
                  </button>
                )}

                {selectedAlert.status !== 'Resolved' ? (
                  <button
                    onClick={() => {
                      const alert = selectedAlert;
                      setSelectedAlert(null);
                      handleOpenResolveModal(alert);
                    }}
                    className="px-3.5 py-1.5 text-xs font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 rounded-lg transition-colors"
                  >
                    Resolve Alert
                  </button>
                ) : (
                  <button
                    onClick={() => handleReopenAlert(selectedAlert)}
                    className="px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-lg transition-colors"
                  >
                    Re-open
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 2: Resolve Alert with Resolution Notes Prompt */}
      {isResolveModalOpen && targetAlertForResolve && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs">
          <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-xl shadow-2xl p-6">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2 text-emerald-400">
                <CheckCircle2 className="w-5 h-5" />
                <h3 className="text-base font-bold text-white">Resolve Security Alert</h3>
              </div>
              <button
                onClick={() => setIsResolveModalOpen(false)}
                className="p-1 text-slate-400 hover:text-white rounded"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="mt-4 space-y-3 text-xs">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <div className="text-slate-400 text-[11px]">Resolving Alert for:</div>
                <div className="font-mono text-sm font-bold text-white">{targetAlertForResolve.indicator}</div>
                <div className="text-cyan-400 text-[11px] mt-0.5">{targetAlertForResolve.category} · {targetAlertForResolve.severity}</div>
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Resolution & Remediation Notes <span className="text-rose-400">*</span>
                </label>
                <textarea
                  rows={4}
                  value={resolutionNotes}
                  onChange={(e) => setResolutionNotes(e.target.value)}
                  placeholder="Describe containment, DNS sinkhole, firewall blockage, or host isolation action taken..."
                  className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-hidden focus:border-cyan-500 text-xs font-mono"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  SOC Analyst Sign-off
                </label>
                <input
                  type="text"
                  value={analystName}
                  onChange={(e) => setAnalystName(e.target.value)}
                  className="w-full p-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-hidden focus:border-cyan-500 text-xs"
                />
              </div>
            </div>

            <div className="mt-5 pt-3 border-t border-slate-800 flex items-center justify-end gap-2 text-xs">
              <button
                onClick={() => setIsResolveModalOpen(false)}
                className="px-3 py-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmResolve}
                disabled={isSubmitting || !resolutionNotes.trim()}
                className="px-4 py-1.5 rounded-lg font-semibold text-slate-950 bg-emerald-400 hover:bg-emerald-300 transition-colors disabled:opacity-50"
              >
                {isSubmitting ? 'Resolving...' : 'Confirm Resolution'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
