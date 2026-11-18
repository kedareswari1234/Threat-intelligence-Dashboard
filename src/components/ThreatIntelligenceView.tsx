import React, { useState } from 'react';
import {
  Plus,
  Search,
  Filter,
  Trash2,
  Edit2,
  Database,
  Download,
  RotateCcw,
  AlertTriangle,
  X,
  CheckCircle2,
  ShieldAlert
} from 'lucide-react';
import { ThreatIndicator, IndicatorType, ThreatCategory, SeverityLevel } from '../types/threat';
import { validateIndicator } from '../lib/validation';

interface ThreatIntelligenceViewProps {
  threats: ThreatIndicator[];
  onAddThreat: (threat: Omit<ThreatIndicator, 'id' | 'createdAt' | 'updatedAt'>) => Promise<void>;
  onUpdateThreat: (id: string, updates: Partial<ThreatIndicator>) => Promise<void>;
  onDeleteThreat: (id: string) => Promise<void>;
  onResetSeed: () => Promise<void>;
  isLoading: boolean;
}

export const ThreatIntelligenceView: React.FC<ThreatIntelligenceViewProps> = ({
  threats,
  onAddThreat,
  onUpdateThreat,
  onDeleteThreat,
  onResetSeed,
  isLoading
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('All');
  const [selectedType, setSelectedType] = useState<string>('All');

  // Modal States
  const [isAddModalOpen, setIsAddModalOpen] = useState(false);
  const [editingThreat, setEditingThreat] = useState<ThreatIndicator | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  // Form Fields
  const [formIndicator, setFormIndicator] = useState('');
  const [formType, setFormType] = useState<IndicatorType>('ip');
  const [formCategory, setFormCategory] = useState<ThreatCategory>('Malware');
  const [formSeverity, setFormSeverity] = useState<SeverityLevel>('HIGH RISK');
  const [formSource, setFormSource] = useState('Analyst Verified Threat Feed');
  const [formDescription, setFormDescription] = useState('');
  const [formConfidence, setFormConfidence] = useState(90);
  const [formAsn, setFormAsn] = useState('');
  const [formCountry, setFormCountry] = useState('US');
  const [formIsSynthetic, setFormIsSynthetic] = useState(true);
  const [formError, setFormError] = useState<string | null>(null);

  const categories: ThreatCategory[] = [
    'Phishing',
    'Malware',
    'Suspicious Activity',
    'Command and Control',
    'Ransomware',
    'Other'
  ];

  const severities: SeverityLevel[] = ['HIGH RISK', 'MEDIUM RISK', 'LOW RISK', 'UNKNOWN'];

  const filteredThreats = threats.filter((t) => {
    const q = searchQuery.toLowerCase();
    const matchesSearch =
      !q ||
      t.indicator.toLowerCase().includes(q) ||
      t.description.toLowerCase().includes(q) ||
      t.source.toLowerCase().includes(q);

    const matchesCategory = selectedCategory === 'All' || t.category === selectedCategory;
    const matchesSeverity = selectedSeverity === 'All' || t.severity === selectedSeverity;
    const matchesType = selectedType === 'All' || t.type === selectedType;

    return matchesSearch && matchesCategory && matchesSeverity && matchesType;
  });

  const resetForm = () => {
    setFormIndicator('');
    setFormType('ip');
    setFormCategory('Malware');
    setFormSeverity('HIGH RISK');
    setFormSource('Analyst Verified Threat Feed');
    setFormDescription('');
    setFormConfidence(90);
    setFormAsn('');
    setFormCountry('US');
    setFormIsSynthetic(true);
    setFormError(null);
  };

  const handleOpenAdd = () => {
    resetForm();
    setIsAddModalOpen(true);
  };

  const handleOpenEdit = (t: ThreatIndicator) => {
    setEditingThreat(t);
    setFormIndicator(t.indicator);
    setFormType(t.type);
    setFormCategory(t.category);
    setFormSeverity(t.severity);
    setFormSource(t.source);
    setFormDescription(t.description);
    setFormConfidence(t.confidence);
    setFormAsn(t.asn || '');
    setFormCountry(t.country || '');
    setFormIsSynthetic(t.isSynthetic);
    setFormError(null);
  };

  const handleSaveAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!formIndicator.trim()) {
      setFormError('Please enter an indicator value.');
      return;
    }

    const check = validateIndicator(formIndicator, formType);
    if (!check.isValid) {
      setFormError(check.error || 'Indicator format invalid.');
      return;
    }

    try {
      await onAddThreat({
        indicator: check.sanitized,
        type: formType,
        category: formCategory,
        severity: formSeverity,
        source: formSource.trim(),
        description: formDescription.trim() || 'Recorded threat indicator.',
        confidence: Number(formConfidence),
        asn: formAsn.trim(),
        country: formCountry.trim().toUpperCase(),
        isSynthetic: formIsSynthetic
      });
      setIsAddModalOpen(false);
      resetForm();
    } catch (err: any) {
      setFormError(err.message || 'Failed to save threat indicator.');
    }
  };

  const handleSaveEdit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingThreat) return;

    const check = validateIndicator(formIndicator, formType);
    if (!check.isValid) {
      setFormError(check.error || 'Indicator format invalid.');
      return;
    }

    try {
      await onUpdateThreat(editingThreat.id, {
        indicator: check.sanitized,
        type: formType,
        category: formCategory,
        severity: formSeverity,
        source: formSource.trim(),
        description: formDescription.trim(),
        confidence: Number(formConfidence),
        asn: formAsn.trim(),
        country: formCountry.trim().toUpperCase(),
        isSynthetic: formIsSynthetic
      });
      setEditingThreat(null);
      resetForm();
    } catch (err: any) {
      setFormError(err.message || 'Failed to update threat indicator.');
    }
  };

  const exportToJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(threats, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `threat_intelligence_export_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
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
      {/* Header bar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="text-xs font-mono text-cyan-400 mb-1">MODULE 2 · LOCAL THREAT INTELLIGENCE REPOSITORY</div>
          <h1 className="text-xl sm:text-2xl font-extrabold text-white">Threat Intelligence Database</h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1">
            Maintain curated indicator records, source telemetry, and rule-based risk classifications.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5 shrink-0">
          <button
            onClick={exportToJson}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-950 border border-slate-800 hover:border-slate-700 rounded-lg transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span>Export JSON</span>
          </button>

          <button
            onClick={onResetSeed}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-300 hover:text-white bg-slate-950 border border-slate-800 hover:border-slate-700 rounded-lg transition-colors"
            title="Reset to default demonstration synthetic threat records"
          >
            <RotateCcw className="w-3.5 h-3.5 text-amber-400" />
            <span>Reset Demo Seeds</span>
          </button>

          <button
            onClick={handleOpenAdd}
            className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors shadow-xs"
          >
            <Plus className="w-4 h-4" />
            <span>Add Threat Record</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 p-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {/* Search text */}
          <div className="relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search indicator, source, description..."
              className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-hidden focus:border-cyan-500/60 font-mono"
            />
          </div>

          {/* Type filter */}
          <div>
            <select
              value={selectedType}
              onChange={(e) => setSelectedType(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500/60"
            >
              <option value="All">All Types (IP & Domain)</option>
              <option value="ip">IP Addresses Only</option>
              <option value="domain">Domain Names Only</option>
            </select>
          </div>

          {/* Severity filter */}
          <div>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500/60"
            >
              <option value="All">All Severities</option>
              {severities.map((sev) => (
                <option key={sev} value={sev}>{sev}</option>
              ))}
            </select>
          </div>

          {/* Category filter */}
          <div>
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500/60"
            >
              <option value="All">All Categories</option>
              {categories.map((cat) => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {/* Threats Table */}
      <div className="rounded-xl border border-slate-800 bg-slate-900 overflow-hidden shadow-xs">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div className="text-xs font-mono text-slate-400">
            SHOWING <strong className="text-cyan-400">{filteredThreats.length}</strong> OF <strong className="text-white">{threats.length}</strong> THREAT INDICATORS
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-mono text-[11px]">
                <th className="py-3 px-4">INDICATOR</th>
                <th className="py-3 px-3">TYPE</th>
                <th className="py-3 px-3">SEVERITY</th>
                <th className="py-3 px-3">CATEGORY</th>
                <th className="py-3 px-3">CONFIDENCE</th>
                <th className="py-3 px-4">SOURCE FEED</th>
                <th className="py-3 px-3">DEMO</th>
                <th className="py-3 px-4 text-right">ACTIONS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredThreats.map((t) => (
                <tr key={t.id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-4">
                    <div className="font-bold text-white text-xs">{t.indicator}</div>
                    <div className="text-[11px] text-slate-400 font-sans line-clamp-1 max-w-sm mt-0.5">
                      {t.description}
                    </div>
                  </td>
                  <td className="py-3 px-3 uppercase text-slate-400">{t.type}</td>
                  <td className="py-3 px-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(t.severity)}`}>
                      {t.severity}
                    </span>
                  </td>
                  <td className="py-3 px-3 font-sans text-slate-300 font-medium">{t.category}</td>
                  <td className="py-3 px-3 tabular-nums text-slate-300">{t.confidence}%</td>
                  <td className="py-3 px-4 font-sans text-slate-400 truncate max-w-xs">{t.source}</td>
                  <td className="py-3 px-3">
                    {t.isSynthetic ? (
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/50 text-cyan-300">
                        Demo
                      </span>
                    ) : (
                      <span className="text-[10px] text-slate-400">Live</span>
                    )}
                  </td>
                  <td className="py-3 px-4 text-right font-sans">
                    <div className="flex items-center justify-end gap-1.5">
                      <button
                        onClick={() => handleOpenEdit(t)}
                        className="p-1.5 text-slate-400 hover:text-cyan-400 rounded hover:bg-slate-800 transition-colors"
                        title="Edit Threat Indicator"
                      >
                        <Edit2 className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => setDeletingId(t.id)}
                        className="p-1.5 text-slate-400 hover:text-rose-400 rounded hover:bg-slate-800 transition-colors"
                        title="Delete Threat Record"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {filteredThreats.length === 0 && (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-400 font-sans">
                    No threat records match your filter criteria.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add / Edit Threat Modal */}
      {(isAddModalOpen || editingThreat) && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-lg overflow-hidden shadow-2xl">
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Database className="w-4 h-4 text-cyan-400" />
                {editingThreat ? 'Edit Threat Indicator' : 'Add Threat Intelligence Record'}
              </h3>
              <button
                onClick={() => {
                  setIsAddModalOpen(false);
                  setEditingThreat(null);
                }}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={editingThreat ? handleSaveEdit : handleSaveAdd} className="p-6 space-y-4">
              {formError && (
                <div className="p-2.5 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
                  <span>{formError}</span>
                </div>
              )}

              <div className="grid grid-cols-3 gap-3">
                <div className="col-span-2">
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Indicator (IP or Domain) *
                  </label>
                  <input
                    type="text"
                    required
                    value={formIndicator}
                    onChange={(e) => setFormIndicator(e.target.value)}
                    placeholder="e.g. 198.51.100.24 or evil-portal.xyz"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-hidden focus:border-cyan-500/60 font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Type *
                  </label>
                  <select
                    value={formType}
                    onChange={(e) => setFormType(e.target.value as IndicatorType)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500/60"
                  >
                    <option value="ip">IP Address</option>
                    <option value="domain">Domain Name</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Threat Category *
                  </label>
                  <select
                    value={formCategory}
                    onChange={(e) => setFormCategory(e.target.value as ThreatCategory)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500/60"
                  >
                    {categories.map((c) => (
                      <option key={c} value={c}>{c}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Severity Level *
                  </label>
                  <select
                    value={formSeverity}
                    onChange={(e) => setFormSeverity(e.target.value as SeverityLevel)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-hidden focus:border-cyan-500/60 font-mono"
                  >
                    <option value="HIGH RISK">HIGH RISK</option>
                    <option value="MEDIUM RISK">MEDIUM RISK</option>
                    <option value="LOW RISK">LOW RISK</option>
                    <option value="UNKNOWN">UNKNOWN</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Intelligence Source Feed *
                </label>
                <input
                  type="text"
                  required
                  value={formSource}
                  onChange={(e) => setFormSource(e.target.value)}
                  placeholder="e.g. CISA Automated Feed (Synthetic) or Internal SOC Blacklist"
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-hidden focus:border-cyan-500/60"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Forensic Description & Observed Behavior *
                </label>
                <textarea
                  required
                  rows={3}
                  value={formDescription}
                  onChange={(e) => setFormDescription(e.target.value)}
                  placeholder="Observed hosting credential harvesting portal, port scanning, or malware beaconing..."
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white placeholder-slate-500 focus:outline-hidden focus:border-cyan-500/60 leading-relaxed"
                />
              </div>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Confidence ({formConfidence}%)
                  </label>
                  <input
                    type="range"
                    min="10"
                    max="100"
                    value={formConfidence}
                    onChange={(e) => setFormConfidence(Number(e.target.value))}
                    className="w-full accent-cyan-400"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    ASN (Optional)
                  </label>
                  <input
                    type="text"
                    value={formAsn}
                    onChange={(e) => setFormAsn(e.target.value)}
                    placeholder="e.g. AS13335"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white font-mono"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Country Code
                  </label>
                  <input
                    type="text"
                    maxLength={2}
                    value={formCountry}
                    onChange={(e) => setFormCountry(e.target.value)}
                    placeholder="US"
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-white font-mono uppercase"
                  />
                </div>
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="synthCheck"
                  checked={formIsSynthetic}
                  onChange={(e) => setFormIsSynthetic(e.target.checked)}
                  className="w-4 h-4 rounded bg-slate-950 border-slate-800 accent-cyan-400"
                />
                <label htmlFor="synthCheck" className="text-xs text-slate-300 cursor-pointer">
                  Mark as Synthetic Demonstration Indicator (Recommended for capstone tests)
                </label>
              </div>

              <div className="mt-5 pt-4 border-t border-slate-800 flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setIsAddModalOpen(false);
                    setEditingThreat(null);
                  }}
                  className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-white rounded-lg hover:bg-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 text-xs font-semibold text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors"
                >
                  {editingThreat ? 'Update Record' : 'Save Threat Record'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deletingId && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl w-full max-w-sm p-6 text-center space-y-4">
            <div className="w-12 h-12 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-400 flex items-center justify-center mx-auto">
              <Trash2 className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Delete Threat Record?</h3>
              <p className="text-xs text-slate-400 mt-1">
                This will remove the indicator from the active threat database. Subsequent searches for this indicator will return unclassified.
              </p>
            </div>
            <div className="flex items-center justify-center gap-3 pt-2">
              <button
                onClick={() => setDeletingId(null)}
                className="px-4 py-2 text-xs font-medium text-slate-400 hover:text-white rounded-lg hover:bg-slate-800"
              >
                Cancel
              </button>
              <button
                onClick={async () => {
                  await onDeleteThreat(deletingId);
                  setDeletingId(null);
                }}
                className="px-4 py-2 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-500 rounded-lg transition-colors"
              >
                Confirm Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
