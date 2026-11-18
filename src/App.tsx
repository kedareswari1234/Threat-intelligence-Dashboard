import React, { useState, useEffect, useCallback } from 'react';
import { Sidebar, NavTab } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { DashboardView } from './components/DashboardView';
import { AnalysisView } from './components/AnalysisView';
import { ThreatIntelligenceView } from './components/ThreatIntelligenceView';
import { InvestigationHistoryView } from './components/InvestigationHistoryView';
import { SecurityAlertsView } from './components/SecurityAlertsView';
import { ReportsView } from './components/ReportsView';
import { SettingsView } from './components/SettingsView';
import { NetworkLogAnalysisView } from './components/NetworkLogAnalysisView';
import { api } from './lib/api';
import {
  ThreatIndicator,
  InvestigationRecord,
  SecurityAlert,
  DashboardStats,
  IndicatorType,
  AnalysisResult,
  AlertStatus
} from './types/threat';

export default function App() {
  const [currentTab, setCurrentTab] = useState<NavTab>('dashboard');
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);

  // Core Data States
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [threats, setThreats] = useState<ThreatIndicator[]>([]);
  const [history, setHistory] = useState<InvestigationRecord[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [dbStatus, setDbStatus] = useState<any>(null);

  // Analysis State
  const [latestResult, setLatestResult] = useState<AnalysisResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Initial Data Fetch
  const loadData = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const [statsData, threatsData, historyData, alertsData, healthData] = await Promise.all([
        api.getStats().catch(() => null),
        api.getThreats().catch(() => []),
        api.getHistory().catch(() => []),
        api.getAlerts().catch(() => []),
        api.getHealth().catch(() => null)
      ]);

      if (statsData) setStats(statsData);
      if (threatsData) setThreats(threatsData);
      if (historyData) setHistory(historyData);
      if (alertsData) setAlerts(alertsData);
      if (healthData) setDbStatus(healthData);
    } catch (err) {
      console.error('Error loading SOC data:', err);
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Master Analyze Function
  const handleRunAnalysis = async (
    indicator: string,
    type: IndicatorType,
    notes?: string,
    analyst?: string,
    skipLiveFeeds?: boolean
  ): Promise<AnalysisResult> => {
    setIsAnalyzing(true);
    try {
      const result = await api.analyze(indicator, type, notes, analyst, skipLiveFeeds);
      setLatestResult(result);

      // Refresh stats, history, and alerts in background
      api.getStats().then((s) => setStats(s)).catch(() => {});
      api.getHistory().then((h) => setHistory(h)).catch(() => {});
      api.getAlerts().then((a) => setAlerts(a)).catch(() => {});

      return result;
    } finally {
      setIsAnalyzing(false);
    }
  };

  // Threat CRUD Handlers
  const handleAddThreat = async (
    threat: Omit<ThreatIndicator, 'id' | 'createdAt' | 'updatedAt'>
  ) => {
    await api.createThreat(threat);
    await loadData();
  };

  const handleUpdateThreat = async (id: string, updates: Partial<ThreatIndicator>) => {
    await api.updateThreat(id, updates);
    await loadData();
  };

  const handleDeleteThreat = async (id: string) => {
    await api.deleteThreat(id);
    await loadData();
  };

  // History Handlers
  const handleClearHistory = async () => {
    await api.deleteHistory();
    await loadData();
  };

  const handleDeleteHistoryItem = async (id: string) => {
    await api.deleteHistory(id);
    await loadData();
  };

  // Alert Handlers
  const handleUpdateAlertStatus = async (
    id: string,
    status: AlertStatus,
    analyst?: string,
    resolutionNotes?: string
  ) => {
    await api.updateAlertStatus(id, status, analyst, resolutionNotes);
    const updated = await api.getAlerts();
    setAlerts(updated);
    api.getStats().then((s) => setStats(s)).catch(() => {});
  };

  // Reset Seeds Handler
  const handleResetSeeds = async () => {
    await api.resetSeed();
    await loadData();
  };

  // Inspect Indicator helper from other tabs
  const handleInspectIndicator = (indicator: string, type: IndicatorType) => {
    if (type === 'ip') {
      setCurrentTab('ip-analysis');
    } else {
      setCurrentTab('domain-analysis');
    }
    handleRunAnalysis(indicator, type);
  };

  const activeAlertsCount = alerts.filter((a) => a.status === 'Active').length;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Sidebar Navigation */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        activeAlertsCount={activeAlertsCount}
        isOpen={mobileSidebarOpen}
        onClose={() => setMobileSidebarOpen(false)}
        dbProvider={dbStatus?.provider}
      />

      {/* Main Layout Area */}
      <div className="lg:pl-72 flex-1 flex flex-col min-w-0">
        <TopBar
          currentTab={currentTab}
          onOpenSidebar={() => setMobileSidebarOpen(true)}
          onQuickAnalyze={() => setCurrentTab('ip-analysis')}
          onRefreshData={loadData}
          isRefreshing={isRefreshing}
          activeAlertsCount={activeAlertsCount}
          onNavigateAlerts={() => setCurrentTab('alerts')}
        />

        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto">
          {currentTab === 'dashboard' && (
            <DashboardView
              stats={stats}
              recentHistory={history}
              activeAlerts={alerts}
              onNavigateTab={setCurrentTab}
              onRunAnalysis={(ind, type) => handleRunAnalysis(ind, type)}
              isAnalyzing={isAnalyzing}
              latestResult={latestResult}
            />
          )}

          {currentTab === 'ip-analysis' && (
            <AnalysisView
              initialType="ip"
              onAnalyze={handleRunAnalysis}
              latestResult={latestResult?.type === 'ip' ? latestResult : null}
            />
          )}

          {currentTab === 'domain-analysis' && (
            <AnalysisView
              initialType="domain"
              onAnalyze={handleRunAnalysis}
              latestResult={latestResult?.type === 'domain' ? latestResult : null}
            />
          )}

          {currentTab === 'log-analysis' && (
            <NetworkLogAnalysisView
              onInvestigateIndicator={handleInspectIndicator}
              onNavigateToAlerts={() => setCurrentTab('alerts')}
            />
          )}

          {currentTab === 'threat-intel' && (
            <ThreatIntelligenceView
              threats={threats}
              onAddThreat={handleAddThreat}
              onUpdateThreat={handleUpdateThreat}
              onDeleteThreat={handleDeleteThreat}
              onResetSeed={handleResetSeeds}
              isLoading={isRefreshing}
            />
          )}

          {currentTab === 'history' && (
            <InvestigationHistoryView
              history={history}
              onClearHistory={handleClearHistory}
              onDeleteHistoryItem={handleDeleteHistoryItem}
              isLoading={isRefreshing}
            />
          )}

          {currentTab === 'alerts' && (
            <SecurityAlertsView
              alerts={alerts}
              onUpdateStatus={handleUpdateAlertStatus}
              onInspectIndicator={handleInspectIndicator}
              isLoading={isRefreshing}
            />
          )}

          {currentTab === 'reports' && (
            <ReportsView
              history={history}
              onInspectIndicator={handleInspectIndicator}
            />
          )}

          {currentTab === 'settings' && (
            <SettingsView
              dbStatus={dbStatus}
              onResetSeeds={handleResetSeeds}
              onRunTestScenario={handleRunAnalysis}
            />
          )}
        </main>
      </div>
    </div>
  );
}
