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

async function parseErrorResponse(res: Response, fallbackAction: string): Promise<string> {
  const status = res.status;
  let rawText = '';
  try {
    rawText = await res.text();
  } catch {
    rawText = '';
  }

  if (rawText) {
    try {
      const parsed = JSON.parse(rawText);
      const msg = parsed?.error || parsed?.message;
      if (typeof msg === 'string' && msg.trim()) {
        return msg.trim();
      }
    } catch {
      // Non-JSON response (e.g., proxy/HTML 404 or 502 error page)
    }
  }

  switch (status) {
    case 400:
      return 'Invalid indicator format or missing request parameters (HTTP 400).';
    case 401:
    case 403:
      return 'Backend API authentication or access error (HTTP ' + status + ').';
    case 404:
      return 'Backend API route not found (HTTP 404). Verify the API server is running.';
    case 429:
      return 'Threat intelligence rate limit exceeded. Please wait briefly and try again (HTTP 429).';
    case 502:
    case 503:
      return 'External threat intelligence service or backend is temporarily unavailable (HTTP ' + status + ').';
    case 504:
      return 'Investigation request timed out while querying intelligence feeds (HTTP 504).';
    default:
      return `${fallbackAction} (HTTP ${status || 'Unknown'}).`;
  }
}

async function safeFetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
  try {
    return await fetch(input, init);
  } catch (err: any) {
    throw new Error(
      err?.name === 'AbortError'
        ? 'Request timeout: Investigation took too long to respond.'
        : 'Network error: Unable to reach the backend threat intelligence API.'
    );
  }
}

export const api = {
  async getHealth() {
    const res = await safeFetch('/api/health');
    if (!res.ok) {
      throw new Error(await parseErrorResponse(res, 'Health check failed'));
    }
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
    const res = await safeFetch('/api/live-feeds/status');
    if (!res.ok) {
      throw new Error(await parseErrorResponse(res, 'Failed to fetch live feeds status'));
    }
    return res.json();
  },

  async validate(indicator: string, type?: IndicatorType): Promise<ValidationResult> {
    const res = await safeFetch('/api/validate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator, type })
    });
    if (!res.ok) {
      const msg = await parseErrorResponse(res, 'Validation request failed');
      return { isValid: false, error: msg, sanitized: indicator.trim() };
    }
    return res.json();
  },

  async analyze(
    indicator: string,
    type?: IndicatorType,
    notes?: string,
    analyst?: string,
    skipLiveFeeds?: boolean
  ): Promise<AnalysisResult> {
    const res = await safeFetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ indicator, type, notes, analyst, skipLiveFeeds })
    });
    if (!res.ok) {
      throw new Error(await parseErrorResponse(res, 'Threat intelligence analysis failed'));
    }
    try {
      return await res.json();
    } catch {
      throw new Error('Malformed JSON response received from /api/analyze.');
    }
  },

  async getThreats(params?: { q?: string; category?: string; severity?: string; type?: string }): Promise<ThreatIndicator[]> {
    const sp = new URLSearchParams();
    if (params?.q) sp.set('q', params.q);
    if (params?.category) sp.set('category', params.category);
    if (params?.severity) sp.set('severity', params.severity);
    if (params?.type) sp.set('type', params.type);

    const res = await safeFetch(`/api/threats?${sp.toString()}`);
    if (!res.ok) throw new Error(await parseErrorResponse(res, 'Failed to fetch threat indicators'));
    return res.json();
  },

  async createThreat(threat: Omit<ThreatIndicator, 'id' | 'createdAt' | 'updatedAt'>): Promise<ThreatIndicator> {
    const res = await safeFetch('/api/threats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(threat)
    });
    if (!res.ok) {
      throw new Error(await parseErrorResponse(res, 'Failed to create threat indicator'));
    }
    return res.json();
  },

  async updateThreat(id: string, updates: Partial<ThreatIndicator>): Promise<ThreatIndicator> {
    const res = await safeFetch(`/api/threats/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates)
    });
    if (!res.ok) {
      throw new Error(await parseErrorResponse(res, 'Failed to update threat record'));
    }
    return res.json();
  },

  async deleteThreat(id: string): Promise<void> {
    const res = await safeFetch(`/api/threats/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error(await parseErrorResponse(res, 'Failed to delete threat indicator'));
  },

  async getHistory(params?: { q?: string; type?: string; severity?: string; category?: string }): Promise<InvestigationRecord[]> {
    const sp = new URLSearchParams();
    if (params?.q) sp.set('q', params.q);
    if (params?.type) sp.set('type', params.type);
    if (params?.severity) sp.set('severity', params.severity);
    if (params?.category) sp.set('category', params.category);

    const res = await safeFetch(`/api/history?${sp.toString()}`);
    if (!res.ok) throw new Error(await parseErrorResponse(res, 'Failed to fetch investigation history'));
    return res.json();
  },

  async deleteHistory(id?: string): Promise<void> {
    const url = id ? `/api/history/${id}` : '/api/history';
    const res = await safeFetch(url, { method: 'DELETE' });
    if (!res.ok) throw new Error(await parseErrorResponse(res, 'Failed to delete history'));
  },

  async getAlerts(params?: { status?: string; severity?: string; q?: string }): Promise<SecurityAlert[]> {
    const sp = new URLSearchParams();
    if (params?.status && params.status !== 'All') sp.set('status', params.status);
    if (params?.severity && params.severity !== 'All') sp.set('severity', params.severity);
    if (params?.q) sp.set('q', params.q);

    const res = await safeFetch(`/api/alerts?${sp.toString()}`);
    if (!res.ok) throw new Error(await parseErrorResponse(res, 'Failed to fetch security alerts'));
    return res.json();
  },

  async updateAlertStatus(
    id: string,
    status: AlertStatus,
    analyst = 'SOC Analyst',
    resolutionNotes?: string
  ): Promise<SecurityAlert> {
    const res = await safeFetch(`/api/alerts/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status, analyst, resolutionNotes })
    });
    if (!res.ok) throw new Error(await parseErrorResponse(res, 'Failed to update alert status'));
    return res.json();
  },

  async getStats(): Promise<DashboardStats> {
    const res = await safeFetch('/api/stats');
    if (!res.ok) throw new Error(await parseErrorResponse(res, 'Failed to fetch dashboard statistics'));
    return res.json();
  },

  async resetSeed(): Promise<void> {
    const res = await safeFetch('/api/seed', { method: 'POST' });
    if (!res.ok) throw new Error(await parseErrorResponse(res, 'Failed to reset demonstration dataset'));
  },

  // Network Log Analysis API
  async analyzeNetworkLog(
    rawLog: string,
    options?: { fileName?: string; fileSize?: number; analyst?: string; skipLiveFeeds?: boolean }
  ): Promise<LogAnalysisSession> {
    const res = await safeFetch('/api/logs/analyze', {
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
      throw new Error(await parseErrorResponse(res, 'Failed to analyze network log'));
    }
    return res.json();
  },

  async getLogAnalyses(limit = 50): Promise<LogAnalysisSession[]> {
    const res = await safeFetch(`/api/logs?limit=${limit}`);
    if (!res.ok) throw new Error(await parseErrorResponse(res, 'Failed to fetch log analyses'));
    return res.json();
  },

  async getLogAnalysisById(id: string): Promise<LogAnalysisSession> {
    const res = await safeFetch(`/api/logs/${id}`);
    if (!res.ok) throw new Error(await parseErrorResponse(res, 'Failed to fetch log analysis session'));
    return res.json();
  },

  async deleteLogAnalysis(id: string): Promise<void> {
    const res = await safeFetch(`/api/logs/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error(await parseErrorResponse(res, 'Failed to delete log analysis session'));
  },

  async getSampleLog(sampleType: 'firewall' | 'web-proxy' | 'vpc-flow'): Promise<{
    fileName: string;
    format: string;
    content: string;
  }> {
    const res = await safeFetch(`/api/logs/sample/${sampleType}`);
    if (!res.ok) throw new Error(await parseErrorResponse(res, 'Failed to load sample log'));
    return res.json();
  }
};
