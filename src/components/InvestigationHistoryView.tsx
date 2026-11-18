import React, { useState } from 'react';
import {
  History,
  Search,
  Download,
  Trash2,
  FileSpreadsheet,
  FileText,
  X,
  ShieldAlert,
  Info,
  Calendar
} from 'lucide-react';
import { InvestigationRecord } from '../types/threat';
import { downloadInvestigationPDF } from '../lib/pdfReport';

interface InvestigationHistoryViewProps {
  history: InvestigationRecord[];
  onClearHistory: () => Promise<void>;
  onDeleteHistoryItem: (id: string) => Promise<void>;
  isLoading: boolean;
}

export const InvestigationHistoryView: React.FC<InvestigationHistoryViewProps> = ({
  history,
  onClearHistory,
  onDeleteHistoryItem,
  isLoading
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('All');
  const [severityFilter, setSeverityFilter] = useState('All');
  const [categoryFilter, setCategoryFilter] = useState('All');
  const [dateFilter, setDateFilter] = useState('All'); // 'All', '24h', '7d', '30d'

  const [selectedRecord, setSelectedRecord] = useState<InvestigationRecord | null>(null);
  const [showClearConfirm, setShowClearConfirm] = useState(false);

  const filteredHistory = history.filter((item) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      !q ||
      item.indicator.toLowerCase().includes(q) ||
      item.evidence.toLowerCase().includes(q) ||
      (item.notes && item.notes.toLowerCase().includes(q)) ||
      item.analyst.toLowerCase().includes(q);

    const matchesType = typeFilter === 'All' || item.type === typeFilter;
    const matchesSeverity = severityFilter === 'All' || item.severity === severityFilter;
    const matchesCategory = categoryFilter === 'All' || item.category === categoryFilter;

    let matchesDate = true;
    if (dateFilter !== 'All') {
      const now = new Date().getTime();
      const itemTime = new Date(item.timestamp).getTime();
      const diffHours = (now - itemTime) / (1000 * 60 * 60);

      if (dateFilter === '24h') matchesDate = diffHours <= 24;
      if (dateFilter === '7d') matchesDate = diffHours <= 24 * 7;
      if (dateFilter === '30d') matchesDate = diffHours <= 24 * 30;
    }

    return matchesSearch && matchesType && matchesSeverity && matchesCategory && matchesDate;
  });

  const exportCsv = () => {
    const headers = [
      'ID',
      'Indicator',
      'Type',
      'Match Status',
      'Severity',
      'Category',
      'Source',
      'Confidence',
      'ASN',
      'Country',
      'Analyst',
      'Timestamp',
      'Evidence'
    ];

    const rows = filteredHistory.map((h) => [
      h.id,
      h.indicator,
      h.type,
      h.matchStatus,
      h.severity,
      h.category,
      h.source,
      `${h.confidence}%`,
      h.asn || '',
      h.country || '',
      h.analyst,
      h.timestamp,
      `"${(h.evidence || '').replace(/"/g, '""')}"`
    ]);

    const csvContent =
      'data:text/csv;charset=utf-8,' +
      [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `investigation_history_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
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

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="text-xs font-mono text-cyan-400 mb-1">MODULE 3 · INCIDENT AUDIT TRAIL</div>
          <h1 className="text-xl sm:text-2xl font-extrabold text-white">Investigation History</h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Searchable log of all analyzed indicators, risk ratings, and timestamped forensic evidence.
          </p>
        </div>

        <div className="flex items-center gap-2.5 shrink-0">
          <button
            onClick={exportCsv}
            disabled={filteredHistory.length === 0}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-950 border border-slate-800 hover:border-slate-700 rounded-lg transition-colors disabled:opacity-50"
          >
            <FileSpreadsheet className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export CSV</span>
          </button>

          <button
            onClick={() => setShowClearConfirm(true)}
            disabled={history.length === 0}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-rose-300 hover:text-rose-200 bg-rose-500/10 border border-rose-500/30 rounded-lg transition-colors disabled:opacity-50"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear History</span>
          </button>
        </div>
      </div>

      {/* Multi-Filters: Type, Severity, Category, Date, Search */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {/* Search Query */}
          <div className="relative lg:col-span-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter by indicator, analyst..."
              className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-hidden focus:border-cyan-500/60 font-mono"
            />
          </div>

          {/* Type Filter */}
          <div>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500/60"
            >
              <option value="All">All Types</option>
              <option value="ip">IP Addresses</option>
              <option value="domain">Domain Names</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500/60 font-mono"
            >
              <option value="All">All Severities</option>
              <option value="HIGH RISK">HIGH RISK</option>
              <option value="MEDIUM RISK">MEDIUM RISK</option>
              <option value="LOW RISK">LOW RISK</option>
              <option value="UNKNOWN">UNKNOWN</option>
            </select>
          </div>

          {/* Category Filter */}
          <div>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500/60"
            >
              <option value="All">All Categories</option>
              <option value="Phishing">Phishing</option>
              <option value="Malware">Malware</option>
              <option value="Command and Control">Command and Control</option>
              <option value="Ransomware">Ransomware</option>
              <option value="Suspicious Activity">Suspicious Activity</option>
              <option value="Unclassified / No Threat Record">Unclassified</option>
            </select>
          </div>

          {/* Date Filter */}
          <div>
            <select
              value={dateFilter}
              onChange={(e) => setDateFilter(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500/60"
            >
              <option value="All">All Timeframes</option>
              <option value="24h">Past 24 Hours</option>
              <option value="7d">Past 7 Days</option>
              <option value="30d">Past 30 Days</option>
            </select>
          </div>
        </div>
      </div>

      {/* History Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden shadow-xs">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400">
          <span>
            RECORD COUNT: <strong className="text-cyan-400">{filteredHistory.length}</strong> LOGGED INVESTIGATIONS
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-mono text-[11px]">
                <th className="py-3 px-4">TIMESTAMP</th>
                <th className="py-3 px-4">INDICATOR</th>
                <th className="py-3 px-3">TYPE</th>
                <th className="py-3 px-3">MATCH STATUS</th>
                <th className="py-3 px-3">SEVERITY</th>
                <th className="py-3 px-3">CATEGORY</th>
                <th className="py-3 px-3">ANALYST</th>
                <th className="py-3 px-4 text-right">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredHistory.map((rec) => (
                <tr key={rec.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-4 text-slate-400 tabular-nums">
                    {new Date(rec.timestamp).toISOString().slice(0, 16).replace('T', ' ')}
                  </td>
                  <td className="py-3 px-4">
                    <button
                      onClick={() => setSelectedRecord(rec)}
                      className="font-bold text-white hover:text-cyan-400 text-left transition-colors"
                    >
                      {rec.indicator}
                    </button>
                    {rec.notes && (
                      <div className="text-[11px] text-slate-400 font-sans truncate max-w-xs">
                        {rec.notes}
                      </div>
                    )}
                  </td>
                  <td className="py-3 px-3 uppercase text-slate-400">{rec.type}</td>
                  <td className="py-3 px-3">
                    <span className={rec.matchStatus === 'Known Indicator Match' ? 'text-amber-300 font-medium' : 'text-slate-400'}>
                      {rec.matchStatus}
                    </span>
                  </td>
                  <td className="py-3 px-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(rec.severity)}`}>
                      {rec.severity}
                    </span>
                  </td>
                  <td className="py-3 px-3 font-sans text-slate-300">{rec.category}</td>
                  <td className="py-3 px-3 font-sans text-slate-400 truncate max-w-[120px]">{rec.analyst}</td>
                  <td className="py-3 px-4 text-right font-sans">
                    <div className="flex items-center justify-end gap-1.5">
                      <button
                        onClick={() => setSelectedRecord(rec)}
                        className="px-2 py-1 text-[11px] font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded transition-colors inline-flex items-center gap-1"
                        title="View Full Case Details"
                      >
                        <FileText className="w-3 h-3 text-cyan-400" />
                        Details
                      </button>
                      <button
                        onClick={() => downloadInvestigationPDF(rec)}
                        className="px-2 py-1 text-[11px] font-medium text-slate-300 hover:text-white bg-slate-800 hover:bg-slate-700 rounded transition-colors inline-flex items-center gap-1"
                        title="Download PDF Investigation Report"
                      >
                        <Download className="w-3 h-3 text-cyan-400" />
                        PDF
                      </button>
                      <button
                        onClick={() => onDeleteHistoryItem(rec.id)}
                        className="p-1 text-slate-500 hover:text-rose-400 rounded transition-colors"
                        title="Remove from History"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {filteredHistory.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-400 font-sans">
                    No investigation records match your filter parameters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Record Details Modal */}
      {selectedRecord && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-2xl overflow-hidden shadow-2xl">
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-cyan-400" />
                  Investigation Case: <span className="font-mono">{selectedRecord.indicator}</span>
                </h3>
                <span className="text-[11px] font-mono text-slate-400">
                  Case ID: {selectedRecord.id}
                </span>
              </div>
              <button
                onClick={() => setSelectedRecord(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-6 space-y-4 text-xs font-sans">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">Type:</span>
                  <span className="font-mono uppercase font-bold text-white">{selectedRecord.type}</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">Match Status:</span>
                  <span className="font-semibold text-slate-200">{selectedRecord.matchStatus}</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">Severity:</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold border inline-block ${getSeverityBadge(selectedRecord.severity)}`}>
                    {selectedRecord.severity}
                  </span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800">
                  <span className="text-slate-400 block text-[11px]">Confidence:</span>
                  <span className="font-mono text-cyan-400 font-bold">{selectedRecord.confidence}%</span>
                </div>
              </div>

              <div className="p-3.5 rounded bg-slate-950 border border-slate-800 space-y-1">
                <span className="text-slate-400 font-mono text-[11px] block">Recorded Forensic Evidence & Findings:</span>
                <p className="text-slate-300 leading-relaxed font-sans">{selectedRecord.evidence}</p>
              </div>

              {selectedRecord.notes && (
                <div className="p-3.5 rounded bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-slate-400 font-mono text-[11px] block">Analyst Case Notes:</span>
                  <p className="text-slate-300 leading-relaxed font-sans">{selectedRecord.notes}</p>
                </div>
              )}

              <div className="grid grid-cols-2 gap-3 text-slate-400 font-mono text-[11px]">
                <div>Source: <strong className="text-slate-200 font-sans">{selectedRecord.source}</strong></div>
                <div>Investigator: <strong className="text-slate-200 font-sans">{selectedRecord.analyst}</strong></div>
                <div>ASN: <strong className="text-slate-200">{selectedRecord.asn || 'N/A'}</strong></div>
                <div>Country: <strong className="text-slate-200">{selectedRecord.country || 'N/A'}</strong></div>
              </div>
            </div>

            <div className="px-6 py-3.5 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between">
              <span className="text-[11px] font-mono text-slate-400">
                Logged: {new Date(selectedRecord.timestamp).toUTCString()}
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => downloadInvestigationPDF(selectedRecord)}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  Download PDF
                </button>
                <button
                  onClick={() => setSelectedRecord(null)}
                  className="px-3 py-1.5 text-xs font-medium text-slate-300 hover:text-white rounded hover:bg-slate-800"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Clear Confirmation Modal */}
      {showClearConfirm && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-sm p-6 text-center space-y-4">
            <div className="w-12 h-12 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-400 flex items-center justify-center mx-auto">
              <Trash2 className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Clear All Investigation History?</h3>
              <p className="text-xs text-slate-400 mt-1">
                This will purge all previous search records and audit entries from the database.
              </p>
            </div>
            <div className="flex items-center justify-center gap-3 pt-2">
              <button
                onClick={() => setShowClearConfirm(false)}
                className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-white rounded-lg hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                onClick={async () => {
                  await onClearHistory();
                  setShowClearConfirm(false);
                }}
                className="px-4 py-2 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 rounded-lg transition-colors"
              >
                Yes, Clear All
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
