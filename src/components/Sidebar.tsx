import React from 'react';
import {
  ShieldAlert,
  Search,
  Globe,
  Database,
  History,
  BellRing,
  FileText,
  Settings,
  X,
  Server
} from 'lucide-react';

export type NavTab =
  | 'dashboard'
  | 'ip-analysis'
  | 'domain-analysis'
  | 'log-analysis'
  | 'threat-intel'
  | 'history'
  | 'alerts'
  | 'reports'
  | 'settings';

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  activeAlertsCount: number;
  isOpen: boolean;
  onClose: () => void;
  dbProvider?: string;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  activeAlertsCount,
  isOpen,
  onClose,
  dbProvider
}) => {
  const navItems = [
    { id: 'dashboard' as NavTab, label: 'Dashboard', icon: ShieldAlert },
    { id: 'ip-analysis' as NavTab, label: 'IP Address Analysis', icon: Search },
    { id: 'domain-analysis' as NavTab, label: 'Domain Analysis', icon: Globe },
    { id: 'log-analysis' as NavTab, label: 'Network Log Analysis', icon: Server },
    { id: 'threat-intel' as NavTab, label: 'Threat Intelligence', icon: Database },
    { id: 'history' as NavTab, label: 'Investigation History', icon: History },
    {
      id: 'alerts' as NavTab,
      label: 'Security Alerts',
      icon: BellRing,
      badge: activeAlertsCount > 0 ? activeAlertsCount : undefined
    },
    { id: 'reports' as NavTab, label: 'Reports', icon: FileText },
    { id: 'settings' as NavTab, label: 'Settings & Database', icon: Settings }
  ];

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div
          onClick={onClose}
          className="fixed inset-0 z-40 bg-black/70 backdrop-blur-xs lg:hidden"
        />
      )}

      {/* Sidebar Panel */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-72 bg-slate-900 border-r border-slate-800 flex flex-col transition-transform duration-200 ease-in-out lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand Lockup */}
        <div className="h-16 px-6 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white font-bold shadow-xs">
              <ShieldAlert className="w-5 h-5 text-slate-950" />
            </div>
            <div>
              <span className="text-sm font-bold tracking-tight text-white block">
                ThreatIntel SOC
              </span>
              <span className="text-[11px] text-cyan-400 font-mono tracking-wider uppercase block">
                Capstone Platform
              </span>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-md text-slate-400 hover:text-white lg:hidden"
            aria-label="Close menu"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation Links */}
        <div className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
          <div className="px-3 py-2 text-[11px] font-semibold tracking-wider text-slate-400 uppercase font-mono">
            Navigation Modules
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => {
                  onSelectTab(item.id);
                  onClose();
                }}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-colors ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                    : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                }`}
              >
                <div className="flex items-center gap-3 truncate">
                  <Icon
                    className={`w-4 h-4 shrink-0 ${
                      isActive ? 'text-cyan-400' : 'text-slate-400'
                    }`}
                  />
                  <span className="truncate">{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <span className="px-1.5 py-0.5 text-[10px] font-mono font-semibold text-rose-300 bg-rose-500/20 rounded border border-rose-500/30">
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Database & Runtime Status in Sidebar Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-900/60 text-xs">
          <div className="flex items-center gap-2 mb-1.5">
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-[11px] font-mono text-slate-300 font-medium">Database Backend</span>
          </div>
          <div className="text-[11px] text-slate-400 truncate">
            {dbProvider || 'Neon PostgreSQL Ready'}
          </div>
          <div className="mt-2 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-400">
            <span>SOC Node: v2.4-capstone</span>
            <span className="font-mono text-cyan-400">ONLINE</span>
          </div>
        </div>
      </aside>
    </>
  );
};
