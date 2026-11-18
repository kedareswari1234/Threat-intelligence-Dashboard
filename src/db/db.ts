import pg from 'pg';
import fs from 'fs';
import path from 'path';
import {
  ThreatIndicator,
  InvestigationRecord,
  SecurityAlert,
  DashboardStats,
  SeverityLevel,
  IndicatorType,
  AlertStatus,
  LogAnalysisSession
} from '../types/threat';
import { INITIAL_DEMO_THREATS, INITIAL_DEMO_ALERTS, INITIAL_DEMO_HISTORY } from './seeds';

const { Pool } = pg;

interface LocalDataStore {
  threats: ThreatIndicator[];
  history: InvestigationRecord[];
  alerts: SecurityAlert[];
  logAnalyses: LogAnalysisSession[];
}

const DATA_DIR = path.resolve(process.cwd(), 'data');
const DATA_FILE = path.join(DATA_DIR, 'threat_store.json');

class DatabaseManager {
  private pool: pg.Pool | null = null;
  private isPostgres = false;
  private localStore: LocalDataStore = {
    threats: [...INITIAL_DEMO_THREATS],
    history: [...INITIAL_DEMO_HISTORY],
    alerts: [...INITIAL_DEMO_ALERTS],
    logAnalyses: []
  };

  constructor() {
    this.init();
  }

  private init() {
    // Check if DATABASE_URL is set
    const dbUrl = process.env.DATABASE_URL;
    if (dbUrl && (dbUrl.startsWith('postgres://') || dbUrl.startsWith('postgresql://'))) {
      try {
        this.pool = new Pool({
          connectionString: dbUrl,
          ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : undefined,
          connectionTimeoutMillis: 5000
        });
        this.initPostgresSchema();
      } catch (err) {
        console.warn('[DB] Failed to initialize PostgreSQL pool, falling back to local store:', err);
        this.initLocalStore();
      }
    } else {
      this.initLocalStore();
    }
  }

  private initLocalStore() {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      if (fs.existsSync(DATA_FILE)) {
        const raw = fs.readFileSync(DATA_FILE, 'utf-8');
        const parsed = JSON.parse(raw);
        if (parsed.threats && Array.isArray(parsed.threats)) {
          this.localStore = {
            ...parsed,
            logAnalyses: Array.isArray(parsed.logAnalyses) ? parsed.logAnalyses : []
          };
          return;
        }
      }
      // Save default seeds
      this.saveLocalStore();
    } catch (e) {
      console.warn('[DB] Could not load or save local data file, keeping in-memory:', e);
    }
  }

  private saveLocalStore() {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }
      fs.writeFileSync(DATA_FILE, JSON.stringify(this.localStore, null, 2), 'utf-8');
    } catch (e) {
      console.error('[DB] Error writing to data file:', e);
    }
  }

  private async initPostgresSchema() {
    if (!this.pool) return;
    try {
      const client = await this.pool.connect();
      try {
        await client.query(`
          CREATE TABLE IF NOT EXISTS ThreatIndicators (
            id VARCHAR(64) PRIMARY KEY,
            indicator VARCHAR(255) NOT NULL UNIQUE,
            type VARCHAR(16) NOT NULL,
            category VARCHAR(64) NOT NULL,
            severity VARCHAR(32) NOT NULL,
            source VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            confidence INTEGER DEFAULT 80,
            asn VARCHAR(255) DEFAULT '',
            country VARCHAR(16) DEFAULT '',
            is_synthetic BOOLEAN DEFAULT true,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
          );

          CREATE TABLE IF NOT EXISTS InvestigationHistory (
            id VARCHAR(64) PRIMARY KEY,
            indicator VARCHAR(255) NOT NULL,
            type VARCHAR(16) NOT NULL,
            match_status VARCHAR(64) NOT NULL,
            category VARCHAR(64) NOT NULL,
            severity VARCHAR(32) NOT NULL,
            source VARCHAR(255) NOT NULL,
            confidence INTEGER DEFAULT 0,
            evidence TEXT NOT NULL,
            asn VARCHAR(255) DEFAULT '',
            country VARCHAR(16) DEFAULT '',
            notes TEXT DEFAULT '',
            threat_id VARCHAR(64),
            timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            analyst VARCHAR(128) DEFAULT 'SOC Analyst',
            is_synthetic BOOLEAN DEFAULT false
          );

          CREATE TABLE IF NOT EXISTS SecurityAlerts (
            id VARCHAR(64) PRIMARY KEY,
            indicator VARCHAR(255) NOT NULL,
            type VARCHAR(16) NOT NULL,
            severity VARCHAR(32) NOT NULL,
            category VARCHAR(64) NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT DEFAULT '',
            source VARCHAR(255) NOT NULL,
            status VARCHAR(32) DEFAULT 'Active',
            occurrence_count INTEGER DEFAULT 1,
            created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            last_observed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TIMESTAMPTZ,
            reviewed_by VARCHAR(128),
            resolution_notes TEXT
          );

          CREATE TABLE IF NOT EXISTS NetworkLogAnalyses (
            id VARCHAR(64) PRIMARY KEY,
            file_name VARCHAR(255) NOT NULL,
            file_size INTEGER NOT NULL,
            log_format VARCHAR(64) NOT NULL,
            total_lines INTEGER NOT NULL,
            parsed_entries_count INTEGER NOT NULL,
            total_extracted INTEGER NOT NULL,
            unique_indicators_count INTEGER NOT NULL,
            threat_matches_count INTEGER NOT NULL,
            unmatched_count INTEGER NOT NULL,
            lookup_failures_count INTEGER NOT NULL,
            high_risk_count INTEGER NOT NULL,
            medium_risk_count INTEGER NOT NULL,
            low_risk_count INTEGER NOT NULL,
            timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
            analyst VARCHAR(128) DEFAULT 'SOC Analyst',
            indicators_json JSONB NOT NULL,
            sample_lines_json JSONB
          );

          ALTER TABLE SecurityAlerts ADD COLUMN IF NOT EXISTS evidence TEXT DEFAULT '';
          ALTER TABLE SecurityAlerts ADD COLUMN IF NOT EXISTS occurrence_count INTEGER DEFAULT 1;
          ALTER TABLE SecurityAlerts ADD COLUMN IF NOT EXISTS last_observed_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;
          ALTER TABLE SecurityAlerts ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
          ALTER TABLE SecurityAlerts ADD COLUMN IF NOT EXISTS reviewed_by VARCHAR(128);
          ALTER TABLE SecurityAlerts ADD COLUMN IF NOT EXISTS resolution_notes TEXT;
        `);

        // Check if threats table is empty, seed if empty
        const countRes = await client.query('SELECT COUNT(*) FROM ThreatIndicators');
        if (parseInt(countRes.rows[0].count, 10) === 0) {
          for (const item of INITIAL_DEMO_THREATS) {
            await client.query(
              `INSERT INTO ThreatIndicators (id, indicator, type, category, severity, source, description, confidence, asn, country, is_synthetic, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
               ON CONFLICT (indicator) DO NOTHING`,
              [
                item.id,
                item.indicator.toLowerCase(),
                item.type,
                item.category,
                item.severity,
                item.source,
                item.description,
                item.confidence,
                item.asn,
                item.country,
                item.isSynthetic,
                item.createdAt,
                item.updatedAt
              ]
            );
          }
        }
        this.isPostgres = true;
        console.log('[DB] Connected to PostgreSQL / Neon database successfully.');
      } finally {
        client.release();
      }
    } catch (err) {
      console.warn('[DB] PostgreSQL initialization failed, using local store:', err);
      this.isPostgres = false;
      this.initLocalStore();
    }
  }

  // --- HEALTH STATUS ---
  public async getStatus() {
    return {
      connected: true,
      provider: this.isPostgres ? 'PostgreSQL (Neon)' : 'Local File Persistence (Neon Ready)',
      isPostgres: this.isPostgres,
      threatCount: (await this.getThreats()).length,
      historyCount: (await this.getHistory()).length,
      alertCount: (await this.getAlerts()).length
    };
  }

  // --- THREAT INDICATORS ---
  public async getThreats(query?: string, category?: string, severity?: string, type?: string): Promise<ThreatIndicator[]> {
    if (this.isPostgres && this.pool) {
      try {
        let sql = 'SELECT * FROM ThreatIndicators WHERE 1=1';
        const params: any[] = [];
        let pIndex = 1;

        if (query) {
          sql += ` AND (indicator ILIKE $${pIndex} OR description ILIKE $${pIndex} OR source ILIKE $${pIndex})`;
          params.push(`%${query}%`);
          pIndex++;
        }
        if (category && category !== 'All') {
          sql += ` AND category = $${pIndex}`;
          params.push(category);
          pIndex++;
        }
        if (severity && severity !== 'All') {
          sql += ` AND severity = $${pIndex}`;
          params.push(severity);
          pIndex++;
        }
        if (type && type !== 'All') {
          sql += ` AND type = $${pIndex}`;
          params.push(type);
          pIndex++;
        }

        sql += ' ORDER BY created_at DESC';
        const res = await this.pool.query(sql, params);
        return res.rows.map(r => ({
          id: r.id,
          indicator: r.indicator,
          type: r.type,
          category: r.category,
          severity: r.severity,
          source: r.source,
          description: r.description,
          confidence: r.confidence,
          asn: r.asn || '',
          country: r.country || '',
          isSynthetic: Boolean(r.is_synthetic),
          createdAt: r.created_at,
          updatedAt: r.updated_at
        }));
      } catch (err) {
        console.error('[DB] Postgres query error in getThreats:', err);
      }
    }

    // Local fallback
    let items = [...this.localStore.threats];
    if (query) {
      const q = query.toLowerCase();
      items = items.filter(
        t => t.indicator.toLowerCase().includes(q) ||
             t.description.toLowerCase().includes(q) ||
             t.source.toLowerCase().includes(q)
      );
    }
    if (category && category !== 'All') {
      items = items.filter(t => t.category === category);
    }
    if (severity && severity !== 'All') {
      items = items.filter(t => t.severity === severity);
    }
    if (type && type !== 'All') {
      items = items.filter(t => t.type === type);
    }

    return items;
  }

  public async findThreatByIndicator(rawIndicator: string): Promise<ThreatIndicator | null> {
    const indicator = rawIndicator.trim().toLowerCase();
    if (this.isPostgres && this.pool) {
      try {
        const res = await this.pool.query(
          'SELECT * FROM ThreatIndicators WHERE LOWER(indicator) = $1 LIMIT 1',
          [indicator]
        );
        if (res.rows.length > 0) {
          const r = res.rows[0];
          return {
            id: r.id,
            indicator: r.indicator,
            type: r.type,
            category: r.category,
            severity: r.severity,
            source: r.source,
            description: r.description,
            confidence: r.confidence,
            asn: r.asn || '',
            country: r.country || '',
            isSynthetic: Boolean(r.is_synthetic),
            createdAt: r.created_at,
            updatedAt: r.updated_at
          };
        }
        return null;
      } catch (err) {
        console.error('[DB] findThreatByIndicator Postgres error:', err);
      }
    }

    const match = this.localStore.threats.find(t => t.indicator.toLowerCase() === indicator);
    return match || null;
  }

  public async createThreat(threat: Omit<ThreatIndicator, 'id' | 'createdAt' | 'updatedAt'>): Promise<ThreatIndicator> {
    const newThreat: ThreatIndicator = {
      ...threat,
      id: `threat-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      indicator: threat.indicator.trim().toLowerCase(),
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    if (this.isPostgres && this.pool) {
      try {
        await this.pool.query(
          `INSERT INTO ThreatIndicators (id, indicator, type, category, severity, source, description, confidence, asn, country, is_synthetic, created_at, updated_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
          [
            newThreat.id,
            newThreat.indicator,
            newThreat.type,
            newThreat.category,
            newThreat.severity,
            newThreat.source,
            newThreat.description,
            newThreat.confidence,
            newThreat.asn || '',
            newThreat.country || '',
            newThreat.isSynthetic,
            newThreat.createdAt,
            newThreat.updatedAt
          ]
        );
        return newThreat;
      } catch (err) {
        console.error('[DB] Postgres insert threat error:', err);
      }
    }

    // Check duplicate in local store
    const existingIndex = this.localStore.threats.findIndex(t => t.indicator.toLowerCase() === newThreat.indicator);
    if (existingIndex >= 0) {
      this.localStore.threats[existingIndex] = newThreat;
    } else {
      this.localStore.threats.unshift(newThreat);
    }
    this.saveLocalStore();
    return newThreat;
  }

  public async updateThreat(id: string, updates: Partial<ThreatIndicator>): Promise<ThreatIndicator | null> {
    if (this.isPostgres && this.pool) {
      try {
        const existing = await this.pool.query('SELECT * FROM ThreatIndicators WHERE id = $1', [id]);
        if (existing.rows.length === 0) return null;

        const current = existing.rows[0];
        const updated = {
          indicator: updates.indicator ? updates.indicator.toLowerCase() : current.indicator,
          type: updates.type || current.type,
          category: updates.category || current.category,
          severity: updates.severity || current.severity,
          source: updates.source || current.source,
          description: updates.description || current.description,
          confidence: updates.confidence !== undefined ? updates.confidence : current.confidence,
          asn: updates.asn !== undefined ? updates.asn : current.asn,
          country: updates.country !== undefined ? updates.country : current.country,
          isSynthetic: updates.isSynthetic !== undefined ? updates.isSynthetic : current.is_synthetic,
          updatedAt: new Date().toISOString()
        };

        await this.pool.query(
          `UPDATE ThreatIndicators
           SET indicator = $1, type = $2, category = $3, severity = $4, source = $5, description = $6, confidence = $7, asn = $8, country = $9, is_synthetic = $10, updated_at = $11
           WHERE id = $12`,
          [
            updated.indicator,
            updated.type,
            updated.category,
            updated.severity,
            updated.source,
            updated.description,
            updated.confidence,
            updated.asn,
            updated.country,
            updated.isSynthetic,
            updated.updatedAt,
            id
          ]
        );

        return {
          id,
          ...updated,
          createdAt: current.created_at
        };
      } catch (err) {
        console.error('[DB] Postgres update threat error:', err);
      }
    }

    const idx = this.localStore.threats.findIndex(t => t.id === id);
    if (idx === -1) return null;

    this.localStore.threats[idx] = {
      ...this.localStore.threats[idx],
      ...updates,
      updatedAt: new Date().toISOString()
    };
    this.saveLocalStore();
    return this.localStore.threats[idx];
  }

  public async deleteThreat(id: string): Promise<boolean> {
    if (this.isPostgres && this.pool) {
      try {
        const res = await this.pool.query('DELETE FROM ThreatIndicators WHERE id = $1', [id]);
        return (res.rowCount ?? 0) > 0;
      } catch (err) {
        console.error('[DB] Postgres delete threat error:', err);
      }
    }

    const initialLen = this.localStore.threats.length;
    this.localStore.threats = this.localStore.threats.filter(t => t.id !== id);
    if (this.localStore.threats.length !== initialLen) {
      this.saveLocalStore();
      return true;
    }
    return false;
  }

  // --- INVESTIGATION HISTORY ---
  public async getHistory(filters?: { query?: string; type?: string; severity?: string; category?: string }): Promise<InvestigationRecord[]> {
    if (this.isPostgres && this.pool) {
      try {
        let sql = 'SELECT * FROM InvestigationHistory WHERE 1=1';
        const params: any[] = [];
        let p = 1;

        if (filters?.query) {
          sql += ` AND (indicator ILIKE $${p} OR notes ILIKE $${p} OR evidence ILIKE $${p})`;
          params.push(`%${filters.query}%`);
          p++;
        }
        if (filters?.type && filters.type !== 'All') {
          sql += ` AND type = $${p}`;
          params.push(filters.type);
          p++;
        }
        if (filters?.severity && filters.severity !== 'All') {
          sql += ` AND severity = $${p}`;
          params.push(filters.severity);
          p++;
        }
        if (filters?.category && filters.category !== 'All') {
          sql += ` AND category = $${p}`;
          params.push(filters.category);
          p++;
        }

        sql += ' ORDER BY timestamp DESC';
        const res = await this.pool.query(sql, params);
        return res.rows.map(r => ({
          id: r.id,
          indicator: r.indicator,
          type: r.type,
          matchStatus: r.match_status,
          category: r.category,
          severity: r.severity,
          source: r.source,
          confidence: r.confidence,
          evidence: r.evidence,
          asn: r.asn || '',
          country: r.country || '',
          notes: r.notes || '',
          threatId: r.threat_id,
          timestamp: r.timestamp,
          analyst: r.analyst,
          isSynthetic: Boolean(r.is_synthetic)
        }));
      } catch (err) {
        console.error('[DB] Postgres getHistory error:', err);
      }
    }

    let records = [...this.localStore.history];
    if (filters?.query) {
      const q = filters.query.toLowerCase();
      records = records.filter(
        r => r.indicator.toLowerCase().includes(q) ||
             (r.notes && r.notes.toLowerCase().includes(q)) ||
             r.evidence.toLowerCase().includes(q)
      );
    }
    if (filters?.type && filters.type !== 'All') {
      records = records.filter(r => r.type === filters.type);
    }
    if (filters?.severity && filters.severity !== 'All') {
      records = records.filter(r => r.severity === filters.severity);
    }
    if (filters?.category && filters.category !== 'All') {
      records = records.filter(r => r.category === filters.category);
    }

    return records;
  }

  public async logInvestigation(record: Omit<InvestigationRecord, 'id' | 'timestamp'>): Promise<InvestigationRecord> {
    const newRecord: InvestigationRecord = {
      ...record,
      id: `inv-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      timestamp: new Date().toISOString()
    };

    if (this.isPostgres && this.pool) {
      try {
        await this.pool.query(
          `INSERT INTO InvestigationHistory (id, indicator, type, match_status, category, severity, source, confidence, evidence, asn, country, notes, threat_id, timestamp, analyst, is_synthetic)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
          [
            newRecord.id,
            newRecord.indicator,
            newRecord.type,
            newRecord.matchStatus,
            newRecord.category,
            newRecord.severity,
            newRecord.source,
            newRecord.confidence,
            newRecord.evidence,
            newRecord.asn || '',
            newRecord.country || '',
            newRecord.notes || '',
            newRecord.threatId || null,
            newRecord.timestamp,
            newRecord.analyst || 'SOC Analyst',
            newRecord.isSynthetic
          ]
        );
        return newRecord;
      } catch (err) {
        console.error('[DB] Postgres logInvestigation error:', err);
      }
    }

    this.localStore.history.unshift(newRecord);
    // Keep max 200 history records in local storage to prevent bloating
    if (this.localStore.history.length > 200) {
      this.localStore.history = this.localStore.history.slice(0, 200);
    }
    this.saveLocalStore();
    return newRecord;
  }

  public async deleteHistory(id?: string): Promise<boolean> {
    if (this.isPostgres && this.pool) {
      try {
        if (id) {
          const res = await this.pool.query('DELETE FROM InvestigationHistory WHERE id = $1', [id]);
          return (res.rowCount ?? 0) > 0;
        } else {
          await this.pool.query('DELETE FROM InvestigationHistory');
          return true;
        }
      } catch (err) {
        console.error('[DB] Postgres deleteHistory error:', err);
      }
    }

    if (id) {
      this.localStore.history = this.localStore.history.filter(h => h.id !== id);
    } else {
      this.localStore.history = [];
    }
    this.saveLocalStore();
    return true;
  }

  // --- SECURITY ALERTS ---
  public async getAlerts(filters?: { status?: string; severity?: string; query?: string }): Promise<SecurityAlert[]> {
    if (this.isPostgres && this.pool) {
      try {
        let sql = 'SELECT * FROM SecurityAlerts WHERE 1=1';
        const params: any[] = [];
        let p = 1;

        if (filters?.status && filters.status !== 'All') {
          sql += ` AND status = $${p}`;
          params.push(filters.status);
          p++;
        }
        if (filters?.severity && filters.severity !== 'All') {
          sql += ` AND severity = $${p}`;
          params.push(filters.severity);
          p++;
        }
        if (filters?.query) {
          sql += ` AND (indicator ILIKE $${p} OR description ILIKE $${p} OR evidence ILIKE $${p} OR category ILIKE $${p})`;
          params.push(`%${filters.query}%`);
          p++;
        }

        sql += ' ORDER BY last_observed_at DESC, created_at DESC';
        const res = await this.pool.query(sql, params);
        return res.rows.map(r => ({
          id: r.id,
          indicator: r.indicator,
          type: r.type,
          severity: r.severity,
          category: r.category,
          description: r.description,
          evidence: r.evidence || '',
          source: r.source,
          status: r.status,
          occurrenceCount: Number(r.occurrence_count) || 1,
          createdAt: r.created_at,
          lastObservedAt: r.last_observed_at || r.created_at,
          reviewedAt: r.reviewed_at || undefined,
          reviewedBy: r.reviewed_by || undefined,
          resolutionNotes: r.resolution_notes || undefined
        }));
      } catch (err) {
        console.error('[DB] Postgres getAlerts error:', err);
      }
    }

    let alerts = [...this.localStore.alerts];
    if (filters?.status && filters.status !== 'All') {
      alerts = alerts.filter(a => a.status === filters.status);
    }
    if (filters?.severity && filters.severity !== 'All') {
      alerts = alerts.filter(a => a.severity === filters.severity);
    }
    if (filters?.query) {
      const q = filters.query.toLowerCase();
      alerts = alerts.filter(
        a =>
          a.indicator.toLowerCase().includes(q) ||
          a.description.toLowerCase().includes(q) ||
          (a.evidence && a.evidence.toLowerCase().includes(q)) ||
          a.category.toLowerCase().includes(q)
      );
    }

    alerts.sort((a, b) => new Date(b.lastObservedAt || b.createdAt).getTime() - new Date(a.lastObservedAt || a.createdAt).getTime());
    return alerts;
  }

  public async createAlert(alertData: {
    indicator: string;
    type: IndicatorType;
    severity: SeverityLevel;
    category: string;
    description: string;
    evidence?: string;
    source: string;
  }): Promise<{ alert: SecurityAlert; isDuplicateSuppressed: boolean }> {
    const dedupWindowMinutes = parseInt(process.env.ALERT_DEDUP_MINUTES || '30', 10);
    const dedupWindowMs = dedupWindowMinutes * 60 * 1000;
    const now = new Date();
    const nowIso = now.toISOString();
    const cleanIndicator = alertData.indicator.trim().toLowerCase();

    if (this.isPostgres && this.pool) {
      try {
        const thresholdDate = new Date(now.getTime() - dedupWindowMs).toISOString();
        const existing = await this.pool.query(
          `SELECT * FROM SecurityAlerts
           WHERE LOWER(indicator) = $1
             AND status != 'Resolved'
             AND last_observed_at >= $2
           ORDER BY last_observed_at DESC LIMIT 1`,
          [cleanIndicator, thresholdDate]
        );

        if (existing.rows.length > 0) {
          const row = existing.rows[0];
          const newCount = (Number(row.occurrence_count) || 1) + 1;
          const updatedEvidence = alertData.evidence && !row.evidence?.includes(alertData.evidence)
            ? `${row.evidence || ''} | [Update]: ${alertData.evidence}`.trim()
            : row.evidence;

          await this.pool.query(
            `UPDATE SecurityAlerts
             SET occurrence_count = $1, last_observed_at = $2, evidence = $3
             WHERE id = $4`,
            [newCount, nowIso, updatedEvidence, row.id]
          );

          return {
            alert: {
              id: row.id,
              indicator: row.indicator,
              type: row.type,
              severity: row.severity,
              category: row.category,
              description: row.description,
              evidence: updatedEvidence || '',
              source: row.source,
              status: row.status,
              occurrenceCount: newCount,
              createdAt: row.created_at,
              lastObservedAt: nowIso,
              reviewedAt: row.reviewed_at,
              reviewedBy: row.reviewed_by,
              resolutionNotes: row.resolution_notes
            },
            isDuplicateSuppressed: true
          };
        }

        const newAlertId = `alert-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
        await this.pool.query(
          `INSERT INTO SecurityAlerts (id, indicator, type, severity, category, description, evidence, source, status, occurrence_count, created_at, last_observed_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
          [
            newAlertId,
            alertData.indicator,
            alertData.type,
            alertData.severity,
            alertData.category,
            alertData.description,
            alertData.evidence || '',
            alertData.source,
            'Active',
            1,
            nowIso,
            nowIso
          ]
        );

        return {
          alert: {
            id: newAlertId,
            indicator: alertData.indicator,
            type: alertData.type,
            severity: alertData.severity,
            category: alertData.category,
            description: alertData.description,
            evidence: alertData.evidence || '',
            source: alertData.source,
            status: 'Active',
            occurrenceCount: 1,
            createdAt: nowIso,
            lastObservedAt: nowIso
          },
          isDuplicateSuppressed: false
        };
      } catch (err) {
        console.error('[DB] Postgres createAlert error:', err);
      }
    }

    // Local store fallback
    const thresholdMs = now.getTime() - dedupWindowMs;
    const existingIndex = this.localStore.alerts.findIndex(
      a =>
        a.indicator.toLowerCase() === cleanIndicator &&
        a.status !== 'Resolved' &&
        new Date(a.lastObservedAt || a.createdAt).getTime() >= thresholdMs
    );

    if (existingIndex !== -1) {
      const existing = this.localStore.alerts[existingIndex];
      existing.occurrenceCount = (existing.occurrenceCount || 1) + 1;
      existing.lastObservedAt = nowIso;
      if (alertData.evidence && !existing.evidence?.includes(alertData.evidence)) {
        existing.evidence = `${existing.evidence || ''} | [Update]: ${alertData.evidence}`.trim();
      }
      this.saveLocalStore();
      return { alert: existing, isDuplicateSuppressed: true };
    }

    const freshAlert: SecurityAlert = {
      id: `alert-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      indicator: alertData.indicator,
      type: alertData.type,
      severity: alertData.severity,
      category: alertData.category,
      description: alertData.description,
      evidence: alertData.evidence || alertData.description,
      source: alertData.source,
      status: 'Active',
      occurrenceCount: 1,
      createdAt: nowIso,
      lastObservedAt: nowIso
    };

    this.localStore.alerts.unshift(freshAlert);
    this.saveLocalStore();
    return { alert: freshAlert, isDuplicateSuppressed: false };
  }

  public async updateAlertStatus(
    id: string,
    status: AlertStatus,
    analyst = 'SOC Analyst',
    resolutionNotes?: string
  ): Promise<SecurityAlert | null> {
    const nowIso = new Date().toISOString();
    const reviewedAt = status === 'Reviewed' || status === 'Resolved' ? nowIso : undefined;
    const reviewedBy = reviewedAt ? analyst : undefined;

    if (this.isPostgres && this.pool) {
      try {
        const res = await this.pool.query(
          `UPDATE SecurityAlerts
           SET status = $1, reviewed_at = $2, reviewed_by = $3, resolution_notes = COALESCE($4, resolution_notes)
           WHERE id = $5
           RETURNING *`,
          [status, reviewedAt || null, reviewedBy || null, resolutionNotes || null, id]
        );
        if (res.rows.length > 0) {
          const r = res.rows[0];
          return {
            id: r.id,
            indicator: r.indicator,
            type: r.type,
            severity: r.severity,
            category: r.category,
            description: r.description,
            evidence: r.evidence || '',
            source: r.source,
            status: r.status,
            occurrenceCount: Number(r.occurrence_count) || 1,
            createdAt: r.created_at,
            lastObservedAt: r.last_observed_at || r.created_at,
            reviewedAt: r.reviewed_at,
            reviewedBy: r.reviewed_by,
            resolutionNotes: r.resolution_notes
          };
        }
      } catch (err) {
        console.error('[DB] Postgres updateAlertStatus error:', err);
      }
    }

    const alert = this.localStore.alerts.find(a => a.id === id);
    if (!alert) return null;

    alert.status = status;
    if (reviewedAt) {
      alert.reviewedAt = reviewedAt;
      alert.reviewedBy = reviewedBy;
    }
    if (resolutionNotes) {
      alert.resolutionNotes = resolutionNotes;
    }
    this.saveLocalStore();
    return alert;
  }

  // --- STATS & AGGREGATIONS ---
  public async getDashboardStats(): Promise<DashboardStats> {
    const threats = await this.getThreats();
    const history = await this.getHistory();
    const alerts = await this.getAlerts();

    const matchesCount = history.filter(h => h.matchStatus === 'Known Indicator Match').length;
    const highRisk = threats.filter(t => t.severity === 'HIGH RISK').length;
    const medRisk = threats.filter(t => t.severity === 'MEDIUM RISK').length;
    const lowRisk = threats.filter(t => t.severity === 'LOW RISK').length;
    const unknownCount = history.filter(h => h.severity === 'UNKNOWN').length;

    // Category distribution
    const catMap: Record<string, number> = {};
    for (const t of threats) {
      catMap[t.category] = (catMap[t.category] || 0) + 1;
    }
    const categoryDistribution = Object.entries(catMap).map(([category, count]) => ({
      category,
      count
    }));

    const severityDistribution: { severity: SeverityLevel; count: number }[] = [
      { severity: 'HIGH RISK', count: highRisk },
      { severity: 'MEDIUM RISK', count: medRisk },
      { severity: 'LOW RISK', count: lowRisk },
      { severity: 'UNKNOWN', count: unknownCount }
    ];

    const activeAlerts = alerts.filter(a => a.status === 'Active').length;

    return {
      totalIndicators: threats.length,
      totalThreatMatches: matchesCount,
      highRiskCount: highRisk,
      mediumRiskCount: medRisk,
      lowRiskCount: lowRisk,
      unknownCount,
      recentInvestigationsCount: history.length,
      activeAlertsCount: activeAlerts,
      categoryDistribution,
      severityDistribution
    };
  }

  // --- SEED RESET ---
  public async resetToDemoSeeds(): Promise<void> {
    if (this.isPostgres && this.pool) {
      try {
        await this.pool.query('DELETE FROM SecurityAlerts');
        await this.pool.query('DELETE FROM InvestigationHistory');
        await this.pool.query('DELETE FROM ThreatIndicators');

        for (const item of INITIAL_DEMO_THREATS) {
          await this.pool.query(
            `INSERT INTO ThreatIndicators (id, indicator, type, category, severity, source, description, confidence, asn, country, is_synthetic, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
            [
              item.id,
              item.indicator.toLowerCase(),
              item.type,
              item.category,
              item.severity,
              item.source,
              item.description,
              item.confidence,
              item.asn,
              item.country,
              item.isSynthetic,
              item.createdAt,
              item.updatedAt
            ]
          );
        }
        for (const alert of INITIAL_DEMO_ALERTS) {
          await this.pool.query(
            `INSERT INTO SecurityAlerts (id, indicator, type, severity, category, description, evidence, source, status, occurrence_count, created_at, last_observed_at, reviewed_at, reviewed_by, resolution_notes)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
            [
              alert.id,
              alert.indicator,
              alert.type,
              alert.severity,
              alert.category,
              alert.description,
              alert.evidence || '',
              alert.source,
              alert.status,
              alert.occurrenceCount || 1,
              alert.createdAt,
              alert.lastObservedAt || alert.createdAt,
              alert.reviewedAt || null,
              alert.reviewedBy || null,
              alert.resolutionNotes || null
            ]
          );
        }
        for (const hist of INITIAL_DEMO_HISTORY) {
          await this.pool.query(
            `INSERT INTO InvestigationHistory (id, indicator, type, match_status, category, severity, source, confidence, evidence, asn, country, notes, threat_id, timestamp, analyst, is_synthetic)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
            [
              hist.id,
              hist.indicator,
              hist.type,
              hist.matchStatus,
              hist.category,
              hist.severity,
              hist.source,
              hist.confidence,
              hist.evidence,
              hist.asn,
              hist.country,
              hist.notes,
              hist.threatId || null,
              hist.timestamp,
              hist.analyst,
              hist.isSynthetic
            ]
          );
        }
        return;
      } catch (err) {
        console.error('[DB] Postgres resetToDemoSeeds error:', err);
      }
    }

    this.localStore = {
      threats: JSON.parse(JSON.stringify(INITIAL_DEMO_THREATS)),
      history: JSON.parse(JSON.stringify(INITIAL_DEMO_HISTORY)),
      alerts: JSON.parse(JSON.stringify(INITIAL_DEMO_ALERTS)),
      logAnalyses: []
    };
    this.saveLocalStore();
  }

  // ==========================================================================
  // MODULE 5: NETWORK LOG ANALYSES
  // ==========================================================================
  async saveLogAnalysis(session: LogAnalysisSession): Promise<LogAnalysisSession> {
    if (this.isPostgres && this.pool) {
      try {
        await this.pool.query(
          `INSERT INTO NetworkLogAnalyses (
             id, file_name, file_size, log_format, total_lines, parsed_entries_count,
             total_extracted, unique_indicators_count, threat_matches_count, unmatched_count,
             lookup_failures_count, high_risk_count, medium_risk_count, low_risk_count,
             timestamp, analyst, indicators_json, sample_lines_json
           ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
           ON CONFLICT (id) DO UPDATE SET
             indicators_json = EXCLUDED.indicators_json,
             threat_matches_count = EXCLUDED.threat_matches_count`,
          [
            session.id,
            session.fileName,
            session.fileSize,
            session.logFormat,
            session.totalLines,
            session.parsedEntriesCount,
            session.totalExtracted,
            session.uniqueIndicatorsCount,
            session.threatMatchesCount,
            session.unmatchedCount,
            session.lookupFailuresCount,
            session.highRiskCount,
            session.mediumRiskCount,
            session.lowRiskCount,
            session.timestamp,
            session.analyst,
            JSON.stringify(session.indicators),
            JSON.stringify(session.sampleLines || [])
          ]
        );
        return session;
      } catch (err) {
        console.error('[DB] Postgres saveLogAnalysis error:', err);
      }
    }

    if (!Array.isArray(this.localStore.logAnalyses)) {
      this.localStore.logAnalyses = [];
    }
    const existingIndex = this.localStore.logAnalyses.findIndex((s) => s.id === session.id);
    if (existingIndex >= 0) {
      this.localStore.logAnalyses[existingIndex] = session;
    } else {
      this.localStore.logAnalyses.unshift(session);
    }
    this.saveLocalStore();
    return session;
  }

  async getLogAnalyses(limit = 50): Promise<LogAnalysisSession[]> {
    if (this.isPostgres && this.pool) {
      try {
        const res = await this.pool.query(
          `SELECT * FROM NetworkLogAnalyses ORDER BY timestamp DESC LIMIT $1`,
          [limit]
        );
        return res.rows.map((row) => ({
          id: row.id,
          fileName: row.file_name,
          fileSize: row.file_size,
          logFormat: row.log_format,
          totalLines: row.total_lines,
          parsedEntriesCount: row.parsed_entries_count,
          totalExtracted: row.total_extracted,
          uniqueIndicatorsCount: row.unique_indicators_count,
          threatMatchesCount: row.threat_matches_count,
          unmatchedCount: row.unmatched_count,
          lookupFailuresCount: row.lookup_failures_count,
          highRiskCount: row.high_risk_count,
          mediumRiskCount: row.medium_risk_count,
          lowRiskCount: row.low_risk_count,
          timestamp: new Date(row.timestamp).toISOString(),
          analyst: row.analyst,
          indicators: typeof row.indicators_json === 'string' ? JSON.parse(row.indicators_json) : row.indicators_json || [],
          sampleLines: typeof row.sample_lines_json === 'string' ? JSON.parse(row.sample_lines_json) : row.sample_lines_json || []
        }));
      } catch (err) {
        console.error('[DB] Postgres getLogAnalyses error:', err);
      }
    }

    if (!Array.isArray(this.localStore.logAnalyses)) {
      this.localStore.logAnalyses = [];
    }
    return this.localStore.logAnalyses.slice(0, limit);
  }

  async getLogAnalysisById(id: string): Promise<LogAnalysisSession | null> {
    if (this.isPostgres && this.pool) {
      try {
        const res = await this.pool.query(
          `SELECT * FROM NetworkLogAnalyses WHERE id = $1 LIMIT 1`,
          [id]
        );
        if (res.rows.length === 0) return null;
        const row = res.rows[0];
        return {
          id: row.id,
          fileName: row.file_name,
          fileSize: row.file_size,
          logFormat: row.log_format,
          totalLines: row.total_lines,
          parsedEntriesCount: row.parsed_entries_count,
          totalExtracted: row.total_extracted,
          uniqueIndicatorsCount: row.unique_indicators_count,
          threatMatchesCount: row.threat_matches_count,
          unmatchedCount: row.unmatched_count,
          lookupFailuresCount: row.lookup_failures_count,
          highRiskCount: row.high_risk_count,
          mediumRiskCount: row.medium_risk_count,
          lowRiskCount: row.low_risk_count,
          timestamp: new Date(row.timestamp).toISOString(),
          analyst: row.analyst,
          indicators: typeof row.indicators_json === 'string' ? JSON.parse(row.indicators_json) : row.indicators_json || [],
          sampleLines: typeof row.sample_lines_json === 'string' ? JSON.parse(row.sample_lines_json) : row.sample_lines_json || []
        };
      } catch (err) {
        console.error('[DB] Postgres getLogAnalysisById error:', err);
      }
    }

    if (!Array.isArray(this.localStore.logAnalyses)) {
      this.localStore.logAnalyses = [];
    }
    return this.localStore.logAnalyses.find((s) => s.id === id) || null;
  }

  async deleteLogAnalysis(id: string): Promise<boolean> {
    if (this.isPostgres && this.pool) {
      try {
        const res = await this.pool.query(`DELETE FROM NetworkLogAnalyses WHERE id = $1`, [id]);
        return (res.rowCount || 0) > 0;
      } catch (err) {
        console.error('[DB] Postgres deleteLogAnalysis error:', err);
      }
    }

    if (!Array.isArray(this.localStore.logAnalyses)) {
      this.localStore.logAnalyses = [];
      return false;
    }
    const idx = this.localStore.logAnalyses.findIndex((s) => s.id === id);
    if (idx >= 0) {
      this.localStore.logAnalyses.splice(idx, 1);
      this.saveLocalStore();
      return true;
    }
    return false;
  }
}

export const db = new DatabaseManager();
