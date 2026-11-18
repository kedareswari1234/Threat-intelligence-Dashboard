import React, { useState, useEffect } from 'react';
import { Menu, ShieldAlert, Clock, RefreshCw } from 'lucide-react';
import { NavTab } from './Sidebar';

interface TopBarProps {
  currentTab: NavTab;
  onOpenSidebar: () => void;
  onQuickAnalyze: () => void;
  onRefreshData?: () => void;
  isRefreshing?: boolean;
  activeAlertsCount?: number;
  onNavigateAlerts?: () => void;
}

const tabTitles: Record<NavTab, string> = {
  'dashboard': 'Security Operations Center · Overview',
  'ip-analysis': 'Module 1 · Malicious IP Address Analysis',
  'domain-analysis': 'Module 1 · Malicious Domain Name Analysis',
  'log-analysis': 'Module 5 · Network Log Analysis & Zero-Trust Correlation',
  'threat-intel': 'Module 2 · Threat Intelligence Database',
  'history': 'Module 3 · Investigation Audit History',
  'alerts': 'Module 4 · Automated Threat Alerts & Triage',
  'reports': 'Forensic Report Generation & Export',
  'settings': 'Platform Settings & Neon Database'
};

export const TopBar: React.FC<TopBarProps> = ({
  currentTab,
  onOpenSidebar,
  onQuickAnalyze,
  onRefreshData,
  isRefreshing,
  activeAlertsCount,
  onNavigateAlerts
}) => {
  const [currentTime, setCurrentTime] = useState<string>('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setCurrentTime(now.toUTCString().slice(17, 25) + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-16 bg-slate-900 border-b border-slate-800 px-4 lg:px-8 flex items-center justify-between gap-4 sticky top-0 z-30">
      {/* Zone 1: Hamburger (mobile) + Breadcrumb */}
      <div className="flex items-center gap-3 min-w-0">
        <button
          onClick={onOpenSidebar}
          className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 lg:hidden"
          aria-label="Open menu"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 truncate">
          <span className="hidden sm:inline font-semibold text-slate-300">SOC Console</span>
          <span className="hidden sm:inline" aria-hidden="true">/</span>
          <span className="text-cyan-400 truncate font-sans font-medium text-sm">
            {tabTitles[currentTab]}
          </span>
        </div>
      </div>

      {/* Zone 2: Middle SOC Clock & System Status */}
      <div className="hidden md:flex items-center gap-4 text-xs font-mono text-slate-400">
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-950 border border-slate-800">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span className="tabular-nums text-slate-300">{currentTime || '00:00:00 UTC'}</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-cyan-400" />
          <span className="text-slate-300 font-sans text-xs">SOC Active</span>
        </div>
      </div>

      {/* Zone 3: Primary Action, Notifications & Refresh */}
      <div className="flex items-center gap-2.5 shrink-0">
        {onNavigateAlerts && (
          <button
            onClick={onNavigateAlerts}
            className="relative p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 border border-transparent hover:border-slate-700 transition-colors"
            title="Unresolved Security Alerts"
            aria-label="View security alerts"
          >
            <ShieldAlert className="w-4 h-4 text-slate-300" />
            {(activeAlertsCount ?? 0) > 0 && (
              <span className="absolute -top-1 -right-1 flex h-4 min-w-4 px-1 items-center justify-center rounded-full bg-rose-500 text-[10px] font-mono font-bold text-white shadow-xs">
                {activeAlertsCount}
              </span>
            )}
          </button>
        )}

        {onRefreshData && (
          <button
            onClick={onRefreshData}
            disabled={isRefreshing}
            className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 border border-transparent hover:border-slate-700 transition-colors"
            title="Refresh statistics and alerts"
            aria-label="Refresh data"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        )}

        <button
          onClick={onQuickAnalyze}
          className="flex items-center gap-2 px-3.5 py-2 text-xs font-medium text-slate-950 bg-cyan-400 hover:bg-cyan-300 rounded-lg transition-colors whitespace-nowrap shadow-xs"
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>New Investigation</span>
        </button>
      </div>
    </header>
  );
};
