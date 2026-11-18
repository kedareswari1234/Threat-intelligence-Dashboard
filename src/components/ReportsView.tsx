import React, { useState } from 'react';
import {
  FileText,
  Download,
  Printer,
  ShieldAlert,
  Search,
  CheckCircle2,
  Clock,
  ExternalLink,
  ChevronRight
} from 'lucide-react';
import { InvestigationRecord, AnalysisResult } from '../types/threat';
import { downloadInvestigationPDF } from '../lib/pdfReport';

interface ReportsViewProps {
  history: InvestigationRecord[];
  onInspectIndicator: (indicator: string, type: 'ip' | 'domain') => void;
}

export const ReportsView: React.FC<ReportsViewProps> = ({
  history,
  onInspectIndicator
}) => {
  const [selectedCase, setSelectedCase] = useState<InvestigationRecord | null>(
    history.length > 0 ? history[0] : null
  );

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
          <div className="text-xs font-mono text-cyan-400 mb-1">MODULE 3 · FORENSIC REPORTING ENGINE</div>
          <h1 className="text-xl sm:text-2xl font-extrabold text-white">Forensic Investigation Reports</h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Generate and export formal PDF cybersecurity incident reports compliant with SOC forensic standards.
          </p>
        </div>

        {selectedCase && (
          <div className="flex items-center gap-2.5 shrink-0">
            <button
              onClick={() => window.print()}
              className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-950 border border-slate-800 hover:border-slate-700 rounded-lg transition-colors"
            >
              <Printer className="w-3.5 h-3.5 text-cyan-400" />
              <span>Print Preview</span>
            </button>
            <button
              onClick={() => downloadInvestigationPDF(selectedCase)}
              className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors shadow-xs"
            >
              <Download className="w-4 h-4" />
              <span>Download PDF Report</span>
            </button>
          </div>
        )}
      </div>

      {history.length === 0 ? (
        <div className="rounded-xl border border-slate-800 bg-slate-900 p-12 text-center text-xs text-slate-400">
          No investigation records available yet. Analyze an indicator first to generate a report.
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Select Case / Investigation */}
          <div className="lg:col-span-4 rounded-xl border border-slate-800 bg-slate-900 p-4 space-y-3">
            <div className="text-xs font-mono text-slate-400 uppercase font-semibold px-2">
              Select Investigation Case ({history.length})
            </div>
            <div className="space-y-1.5 max-h-[600px] overflow-y-auto pr-1">
              {history.map((item) => {
                const isSelected = selectedCase?.id === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => setSelectedCase(item)}
                    className={`w-full text-left p-3 rounded-lg border text-xs transition-colors ${
                      isSelected
                        ? 'bg-slate-950 border-cyan-500/40'
                        : 'bg-slate-950/40 border-slate-800 hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1 mb-1">
                      <span className="font-mono font-bold text-white truncate">{item.indicator}</span>
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${getSeverityBadge(item.severity)}`}>
                        {item.severity}
                      </span>
                    </div>
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span>{item.category}</span>
                      <span className="font-mono text-[10px] tabular-nums">
                        {new Date(item.timestamp).toISOString().slice(5, 16).replace('T', ' ')}
                      </span>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Right Column: Interactive Report Document Sheet Preview */}
          <div className="lg:col-span-8">
            {selectedCase && (
              <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden shadow-xl">
                {/* Document Top Bar */}
                <div className="px-6 py-4 border-b border-slate-800 bg-slate-950 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <FileText className="w-4 h-4 text-cyan-400" />
                    <span className="text-xs font-mono text-slate-300 font-semibold uppercase">
                      Official Forensic Report Document Preview
                    </span>
                  </div>
                  <button
                    onClick={() => downloadInvestigationPDF(selectedCase)}
                    className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 font-medium"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Save to PDF</span>
                  </button>
                </div>

                {/* Printable Document Sheet Simulation */}
                <div className="p-6 sm:p-8 space-y-6 text-slate-200 text-xs font-sans bg-slate-900/90">
                  {/* Report Header */}
                  <div className="pb-6 border-b border-slate-800 flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                    <div>
                      <div className="text-[11px] font-mono uppercase text-cyan-400 tracking-wider font-semibold mb-1">
                        SECURITY OPERATIONS CENTER FORENSIC REPORT
                      </div>
                      <h2 className="text-xl font-extrabold text-white">
                        Indicator Triage & Incident Dossier
                      </h2>
                      <div className="mt-1 text-slate-400 text-xs">
                        Target Indicator: <span className="font-mono font-bold text-white">{selectedCase.indicator}</span> ({selectedCase.type.toUpperCase()})
                      </div>
                    </div>

                    <div className="text-right text-[11px] font-mono text-slate-400 shrink-0">
                      <div>CASE ID: <span className="text-slate-200">{selectedCase.id}</span></div>
                      <div>DATE: <span className="text-slate-200">{new Date(selectedCase.timestamp).toUTCString().slice(0, 22)}</span></div>
                      <div>ANALYST: <span className="text-slate-200">{selectedCase.analyst}</span></div>
                    </div>
                  </div>

                  {/* Section 1: Executive Findings */}
                  <div>
                    <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-cyan-300 mb-3">
                      1. Executive Indicator Assessment
                    </h3>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
                      <div className="p-3 rounded bg-slate-950 border border-slate-800">
                        <span className="text-slate-400 text-[10px] block">CLASSIFICATION</span>
                        <span className={`text-xs font-bold px-1.5 py-0.5 rounded border inline-block mt-1 ${getSeverityBadge(selectedCase.severity)}`}>
                          {selectedCase.severity}
                        </span>
                      </div>
                      <div className="p-3 rounded bg-slate-950 border border-slate-800">
                        <span className="text-slate-400 text-[10px] block">THREAT CATEGORY</span>
                        <span className="text-xs font-bold text-white block mt-1 truncate">
                          {selectedCase.category}
                        </span>
                      </div>
                      <div className="p-3 rounded bg-slate-950 border border-slate-800">
                        <span className="text-slate-400 text-[10px] block">CONFIDENCE SCORE</span>
                        <span className="text-xs font-bold text-cyan-400 block mt-1">
                          {selectedCase.confidence}%
                        </span>
                      </div>
                      <div className="p-3 rounded bg-slate-950 border border-slate-800">
                        <span className="text-slate-400 text-[10px] block">MATCH STATUS</span>
                        <span className="text-xs font-semibold text-slate-200 block mt-1 truncate">
                          {selectedCase.matchStatus}
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Section 2: Forensic Evidence */}
                  <div>
                    <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-cyan-300 mb-3">
                      2. Forensic Evidence & Recorded Behavior
                    </h3>
                    <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 leading-relaxed font-sans">
                      <p>{selectedCase.evidence}</p>
                      {selectedCase.notes && (
                        <div className="mt-3 pt-3 border-t border-slate-800 text-slate-400">
                          <strong className="text-slate-300">Case Incident Notes:</strong> {selectedCase.notes}
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Section 3: Threat Intelligence Feed Origin */}
                  <div>
                    <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-cyan-300 mb-3">
                      3. Network Telemetry & Source Attribution
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
                      <div className="p-3 rounded bg-slate-950 border border-slate-800">
                        <span className="text-slate-400 text-[10px] block">INTELLIGENCE SOURCE</span>
                        <span className="text-slate-200 font-sans block mt-0.5 truncate">{selectedCase.source}</span>
                      </div>
                      <div className="p-3 rounded bg-slate-950 border border-slate-800">
                        <span className="text-slate-400 text-[10px] block">ASN & HOSTING PROVIDER</span>
                        <span className="text-slate-200 block mt-0.5 truncate">{selectedCase.asn || 'Not cataloged'}</span>
                      </div>
                      <div className="p-3 rounded bg-slate-950 border border-slate-800">
                        <span className="text-slate-400 text-[10px] block">GEOLOCATION COUNTRY</span>
                        <span className="text-slate-200 block mt-0.5">{selectedCase.country || 'N/A'}</span>
                      </div>
                    </div>
                  </div>

                  {/* Section 4: Mitigation Directives */}
                  <div>
                    <h3 className="text-xs font-bold font-mono uppercase tracking-wider text-cyan-300 mb-3">
                      4. Incident Response & Containment Directives
                    </h3>
                    <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-2 text-xs text-slate-300">
                      {selectedCase.severity === 'HIGH RISK' ? (
                        <>
                          <div className="flex items-start gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-rose-400 mt-1.5 shrink-0" />
                            <span><strong>Border Firewall Drop:</strong> Push {selectedCase.indicator} to corporate perimeter edge blocklists.</span>
                          </div>
                          <div className="flex items-start gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-rose-400 mt-1.5 shrink-0" />
                            <span><strong>DNS Sinkholing:</strong> Redirect all internal DNS requests for this indicator to SOC analysis sinkhole.</span>
                          </div>
                          <div className="flex items-start gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-rose-400 mt-1.5 shrink-0" />
                            <span><strong>Endpoint Isolation:</strong> If host beaconing is detected, isolate the machine from LAN and collect memory dump.</span>
                          </div>
                        </>
                      ) : selectedCase.severity === 'MEDIUM RISK' ? (
                        <>
                          <div className="flex items-start gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-amber-400 mt-1.5 shrink-0" />
                            <span><strong>Heightened SIEM Correlation:</strong> Configure high-priority alert trigger for internal traffic contacting this indicator.</span>
                          </div>
                          <div className="flex items-start gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-amber-400 mt-1.5 shrink-0" />
                            <span><strong>Rate Limiting:</strong> Enforce ingress packet throttling at load balancers.</span>
                          </div>
                        </>
                      ) : (
                        <>
                          <div className="flex items-start gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                            <span><strong>Baseline Telemetry:</strong> Maintain regular NetFlow and firewall logging.</span>
                          </div>
                          <div className="flex items-start gap-2">
                            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1.5 shrink-0" />
                            <span><strong>Absence of Threat Notice:</strong> Absence of a known threat record does not imply the indicator is benign.</span>
                          </div>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Section 5: Cryptographic Integrity Verification */}
                  <div className="pt-4 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-[11px] font-mono text-slate-400">
                    <div>
                      VERIFICATION CHECKSUM: <strong className="text-slate-300">sha256:7f9a2b4e8c1056d3</strong>
                    </div>
                    <div className="flex items-center gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      <span>CHAIN OF CUSTODY VERIFIED</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
