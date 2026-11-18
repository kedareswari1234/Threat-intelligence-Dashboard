import {
  ThreatIndicator,
  InvestigationRecord,
  SecurityAlert,
  AnalysisResult,
  DashboardStats,
  ValidationResult,
  IndicatorType,
  AlertStatus,
  LogAnalysisSession
} from '../types/threat';

export const api = {
  async getHealth() {
    const res = await fetch('/api/health');
    return res.json();
  },

  async getLiveFeedsStatus(): Promise<{
    feeds: {
      id: string;
      name: string;
      type: string;
      status: string;
      requiresKey: boolean;
      supports: string[];
      description: string;
    }[];
  }> {
    const res = await fetch('/api/live-feeds/status');
    if (!res.ok) throw new Error('Failed to fetch live feeds status');
    return res.json();
  },

  async validate(indicator: string, type?: IndicatorType): Promise<ValidationResult> {
    const res = await fetch('/api/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator, type })
    });
    return res.json();
  },

  async analyze(indicator: string, type?: IndicatorType, notes?: string, analyst?: string, skipLiveFeeds?: boolean): Promise<AnalysisResult> {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator, type, notes, analyst, skipLiveFeeds })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to complete analysis.');
    }
    return res.json();
  },

  async getThreats(params?: { q?: string; category?: string; severity?: string; type?: string }): Promise<ThreatIndicator[]> {
    const sp = new URLSearchParams();
    if (params?.q) sp.set('q', params.q);
    if (params?.category) sp.set('category', params.category);
    if (params?.severity) sp.set('severity', params.severity);
    if (params?.type) sp.set('type', params.type);

    const res = await fetch(`/api/threats?${sp.toString()}`);
    if (!res.ok) throw new Error('Failed to fetch threat indicators');
    return res.json();
  },

  async createThreat(threat: Omit<ThreatIndicator, 'id' | 'createdAt' | 'updatedAt'>): Promise<ThreatIndicator> {
    const res = await fetch('/api/threats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(threat)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to create threat indicator');
    }
    return res.json();
  },

  async updateThreat(id: string, updates: Partial<ThreatIndicator>): Promise<ThreatIndicator> {
    const res = await fetch(`/api/threats/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates)
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to update threat record');
    }
    return res.json();
  },

  async deleteThreat(id: string): Promise<void> {
    const res = await fetch(`/api/threats/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete threat indicator');
  },

  async getHistory(params?: { q?: string; type?: string; severity?: string; category?: string }): Promise<InvestigationRecord[]> {
    const sp = new URLSearchParams();
    if (params?.q) sp.set('q', params.q);
    if (params?.type) sp.set('type', params.type);
    if (params?.severity) sp.set('severity', params.severity);
    if (params?.category) sp.set('category', params.category);

    const res = await fetch(`/api/history?${sp.toString()}`);
    if (!res.ok) throw new Error('Failed to fetch investigation history');
    return res.json();
  },

  async deleteHistory(id?: string): Promise<void> {
    const url = id ? `/api/history/${id}` : '/api/history';
    const res = await fetch(url, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete history');
  },

  async getAlerts(params?: { status?: string; severity?: string; q?: string }): Promise<SecurityAlert[]> {
    const sp = new URLSearchParams();
    if (params?.status && params.status !== 'All') sp.set('status', params.status);
    if (params?.severity && params.severity !== 'All') sp.set('severity', params.severity);
    if (params?.q) sp.set('q', params.q);

    const res = await fetch(`/api/alerts?${sp.toString()}`);
    if (!res.ok) throw new Error('Failed to fetch security alerts');
    return res.json();
  },

  async updateAlertStatus(
    id: string,
    status: AlertStatus,
    analyst = 'SOC Analyst',
    resolutionNotes?: string
  ): Promise<SecurityAlert> {
    const res = await fetch(`/api/alerts/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, analyst, resolutionNotes })
    });
    if (!res.ok) throw new Error('Failed to update alert status');
    return res.json();
  },

  async getStats(): Promise<DashboardStats> {
    const res = await fetch('/api/stats');
    if (!res.ok) throw new Error('Failed to fetch dashboard statistics');
    return res.json();
  },

  async resetSeed(): Promise<void> {
    const res = await fetch('/api/seed', { method: 'POST' });
    if (!res.ok) throw new Error('Failed to reset demonstration dataset');
  },

  // Network Log Analysis API
  async analyzeNetworkLog(
    rawLog: string,
    options?: { fileName?: string; fileSize?: number; analyst?: string; skipLiveFeeds?: boolean }
  ): Promise<LogAnalysisSession> {
    const res = await fetch('/api/logs/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        rawLog,
        fileName: options?.fileName,
        fileSize: options?.fileSize,
        analyst: options?.analyst,
        skipLiveFeeds: options?.skipLiveFeeds
      })
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to analyze network log');
    }
    return res.json();
  },

  async getLogAnalyses(limit = 50): Promise<LogAnalysisSession[]> {
    const res = await fetch(`/api/logs?limit=${limit}`);
    if (!res.ok) throw new Error('Failed to fetch log analyses');
    return res.json();
  },

  async getLogAnalysisById(id: string): Promise<LogAnalysisSession> {
    const res = await fetch(`/api/logs/${id}`);
    if (!res.ok) throw new Error('Failed to fetch log analysis session');
    return res.json();
  },

  async deleteLogAnalysis(id: string): Promise<void> {
    const res = await fetch(`/api/logs/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Failed to delete log analysis session');
  },

  async getSampleLog(sampleType: 'firewall' | 'web-proxy' | 'vpc-flow'): Promise<{
    fileName: string;
    format: string;
    content: string;
  }> {
    const res = await fetch(`/api/logs/sample/${sampleType}`);
    if (!res.ok) throw new Error('Failed to load sample log');
    return res.json();
  }
};
