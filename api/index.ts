import express, { Request, Response } from 'express';
import { db } from '../src/db/db';
import { analyzeIndicator } from '../src/lib/engine';
import { validateIndicator } from '../src/lib/validation';
import { analyzeNetworkLog } from '../src/lib/logAnalysisEngine';
import {
  SAMPLE_LOG_FIREWALL_EGRESS,
  SAMPLE_LOG_WEB_PROXY,
  SAMPLE_LOG_VPC_FLOW
} from '../src/lib/logParser';

const app = express();
app.use(express.json());

app.get('/api/health', async (_req: Request, res: Response) => {
  try {
    const status = await db.getStatus();
    res.json({ status: 'ok', timestamp: new Date().toISOString(), ...status });
  } catch (error: any) {
    res.status(500).json({ status: 'error', message: error.message });
  }
});

app.get('/api/live-feeds/status', (_req: Request, res: Response) => {
  const hasURLhaus = Boolean(process.env.URLHAUS_API_KEY && process.env.URLHAUS_API_KEY !== 'MY_URLHAUS_KEY');
  const hasAbuseIPDB = Boolean(process.env.ABUSEIPDB_API_KEY && process.env.ABUSEIPDB_API_KEY !== 'MY_ABUSEIPDB_KEY');
  const hasOTX = Boolean(process.env.OTX_API_KEY && process.env.OTX_API_KEY !== 'MY_OTX_KEY');

  res.json({
    feeds: [
      {
        id: 'urlhaus',
        name: 'URLhaus (abuse.ch)',
        type: 'Malware & Domain Host API',
        status: hasURLhaus ? 'Configured (Auth Key)' : 'Auth Key Required',
        requiresKey: true,
        supports: ['domain', 'ip'],
        description: 'Malware URL and distribution domain host tracker from abuse.ch'
      },
      {
        id: 'abuseipdb',
        name: 'AbuseIPDB',
        type: 'IP Reputation API',
        status: hasAbuseIPDB ? 'Configured' : 'Key Not Set',
        requiresKey: true,
        supports: ['ip'],
        description: 'Crowdsourced IP abuse reports and confidence scoring (90-day window)'
      },
      {
        id: 'otx',
        name: 'AlienVault OTX',
        type: 'Community Threat Exchange',
        status: hasOTX ? 'Configured (API Key)' : 'Active (Public Mode)',
        requiresKey: false,
        supports: ['domain', 'ip'],
        description: 'Global cybersecurity research community threat pulses and IOCs'
      }
    ]
  });
});

app.post('/api/validate', (req: Request, res: Response) => {
  const { indicator, type } = req.body;
  if (!indicator) {
    res.status(400).json({ isValid: false, error: 'Indicator is required' });
    return;
  }
  res.json(validateIndicator(indicator, type));
});

app.post('/api/analyze', async (req: Request, res: Response) => {
  try {
    const { indicator, type, analyst, notes, skipLiveFeeds } = req.body;
    if (!indicator || typeof indicator !== 'string') {
      res.status(400).json({ error: 'Indicator string is required.' });
      return;
    }
    const analysis = await analyzeIndicator(indicator, {
      expectedType: type,
      analyst: analyst || 'SOC Analyst',
      notes: notes || '',
      skipLiveFeeds: Boolean(skipLiveFeeds)
    });
    res.json(analysis);
  } catch (error: any) {
    res.status(500).json({ error: 'Internal analysis error occurred.' });
  }
});

app.get('/api/threats', async (req: Request, res: Response) => {
  try {
    const { q, category, severity, type } = req.query;
    const threats = await db.getThreats(
      q as string | undefined,
      category as string | undefined,
      severity as string | undefined,
      type as string | undefined
    );
    res.json(threats);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/threats', async (req: Request, res: Response) => {
  try {
    const { indicator, type, category, severity, source, description, confidence, asn, country, isSynthetic } = req.body;
    const valid = validateIndicator(indicator, type);
    if (!valid.isValid) {
      res.status(400).json({ error: `Indicator validation failed: ${valid.error}` });
      return;
    }
    const created = await db.createThreat({
      indicator: valid.sanitized,
      type,
      category,
      severity,
      source: source || 'Analyst Manual Entry',
      description: description || 'No description provided.',
      confidence: typeof confidence === 'number' ? confidence : 80,
      asn: asn || '',
      country: country || '',
      isSynthetic: isSynthetic !== undefined ? Boolean(isSynthetic) : true
    });
    res.status(201).json(created);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/threats/:id', async (req: Request, res: Response) => {
  try {
    const updated = await db.updateThreat(req.params.id, req.body);
    if (!updated) {
      res.status(404).json({ error: 'Threat indicator not found.' });
      return;
    }
    res.json(updated);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/threats/:id', async (req: Request, res: Response) => {
  try {
    const deleted = await db.deleteThreat(req.params.id);
    if (!deleted) {
      res.status(404).json({ error: 'Threat indicator not found.' });
      return;
    }
    res.json({ success: true, message: 'Threat record removed.' });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/history', async (req: Request, res: Response) => {
  try {
    const { q, type, severity, category } = req.query;
    const history = await db.getHistory({
      query: q as string | undefined,
      type: type as string | undefined,
      severity: severity as string | undefined,
      category: category as string | undefined
    });
    res.json(history);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/history/:id', async (req: Request, res: Response) => {
  try {
    const deleted = await db.deleteHistory(req.params.id);
    res.json({ success: deleted });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/history', async (_req: Request, res: Response) => {
  try {
    await db.deleteHistory();
    res.json({ success: true, message: 'Investigation history cleared.' });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/alerts', async (req: Request, res: Response) => {
  try {
    const { status, severity, q } = req.query;
    const alerts = await db.getAlerts({
      status: status as string | undefined,
      severity: severity as string | undefined,
      query: q as string | undefined
    });
    res.json(alerts);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.patch('/api/alerts/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    let { status, analyst, resolutionNotes } = req.body;
    if (status === 'Acknowledged') status = 'Reviewed';

    if (!status || !['Active', 'Reviewed', 'Resolved'].includes(status)) {
      res.status(400).json({ error: 'Valid status (Active, Reviewed, Resolved) is required.' });
      return;
    }
    const updated = await db.updateAlertStatus(id, status, analyst, resolutionNotes);
    if (!updated) {
      res.status(404).json({ error: 'Alert not found.' });
      return;
    }
    res.json(updated);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/stats', async (_req: Request, res: Response) => {
  try {
    const stats = await db.getDashboardStats();
    res.json(stats);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/seed', async (_req: Request, res: Response) => {
  try {
    await db.resetToDemoSeeds();
    res.json({ success: true, message: 'Demonstration dataset re-seeded successfully.' });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// MODULE 5: NETWORK LOG ANALYSIS ROUTES
// ============================================================================

app.post('/api/logs/analyze', async (req: Request, res: Response) => {
  try {
    const { rawLog, fileName, fileSize, analyst, skipLiveFeeds } = req.body;
    if (!rawLog || typeof rawLog !== 'string') {
      res.status(400).json({ error: 'Log content string (rawLog) is required.' });
      return;
    }

    const session = await analyzeNetworkLog(rawLog, {
      fileName: fileName || 'uploaded_network_log.log',
      fileSize: typeof fileSize === 'number' ? fileSize : Buffer.byteLength(rawLog, 'utf8'),
      analyst: analyst || 'SOC Analyst',
      skipLiveFeeds: Boolean(skipLiveFeeds)
    });

    res.json(session);
  } catch (error: any) {
    console.error('[API /api/logs/analyze] error:', error);
    res.status(500).json({ error: error?.message || 'Failed to analyze network log.' });
  }
});

app.get('/api/logs', async (req: Request, res: Response) => {
  try {
    const limit = parseInt((req.query.limit as string) || '50', 10);
    const sessions = await db.getLogAnalyses(limit);
    res.json(sessions);
  } catch (error: any) {
    res.status(500).json({ error: error?.message || 'Failed to retrieve log analyses.' });
  }
});

app.get('/api/logs/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const session = await db.getLogAnalysisById(id);
    if (!session) {
      res.status(404).json({ error: 'Log analysis session not found.' });
      return;
    }
    res.json(session);
  } catch (error: any) {
    res.status(500).json({ error: error?.message || 'Failed to retrieve log session.' });
  }
});

app.delete('/api/logs/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const deleted = await db.deleteLogAnalysis(id);
    res.json({ success: deleted });
  } catch (error: any) {
    res.status(500).json({ error: error?.message || 'Failed to delete log session.' });
  }
});

app.get('/api/logs/sample/:sampleType', (req: Request, res: Response) => {
  const { sampleType } = req.params;
  if (sampleType === 'firewall') {
    res.json({
      fileName: 'perimeter_firewall_incident.log',
      format: 'Cisco ASA Firewall Egress Log',
      content: SAMPLE_LOG_FIREWALL_EGRESS
    });
  } else if (sampleType === 'web-proxy') {
    res.json({
      fileName: 'secure_web_proxy_gateway.log',
      format: 'Combined Web Proxy & HTTP Access Log',
      content: SAMPLE_LOG_WEB_PROXY
    });
  } else if (sampleType === 'vpc-flow') {
    res.json({
      fileName: 'aws_vpc_flow_incident.log',
      format: 'AWS VPC Flow Log',
      content: SAMPLE_LOG_VPC_FLOW
    });
  } else {
    res.status(400).json({ error: 'Unknown sample type. Options: firewall, web-proxy, vpc-flow' });
  }
});

export default app;
