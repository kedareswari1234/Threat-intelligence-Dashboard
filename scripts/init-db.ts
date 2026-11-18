import pg from 'pg';
import dotenv from 'dotenv';
import { INITIAL_DEMO_THREATS, INITIAL_DEMO_ALERTS, INITIAL_DEMO_HISTORY } from '../src/db/seeds';

dotenv.config();

const { Pool } = pg;

async function initDatabase() {
  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    console.log('[Init-DB] No DATABASE_URL specified in environment.');
    console.log('[Init-DB] If using local development without PostgreSQL, the application uses local JSON persistence in ./data/threat_store.json automatically.');
    console.log('[Init-DB] To initialize a Neon/PostgreSQL database, set DATABASE_URL in your .env file and re-run.');
    process.exit(0);
  }

  console.log('[Init-DB] Connecting to PostgreSQL / Neon database...');
  const pool = new Pool({
    connectionString: dbUrl,
    ssl: { rejectUnauthorized: false }
  });

  const client = await pool.connect();
  try {
    console.log('[Init-DB] Creating tables if not existing...');
    await client.query(`
      CREATE TABLE IF NOT EXISTS ThreatIndicators (
        id VARCHAR(64) PRIMARY KEY,
        indicator VARCHAR(255) NOT NULL UNIQUE,
        type VARCHAR(16) NOT NULL CHECK (type IN ('ip', 'domain')),
        category VARCHAR(64) NOT NULL,
        severity VARCHAR(32) NOT NULL CHECK (severity IN ('HIGH RISK', 'MEDIUM RISK', 'LOW RISK', 'UNKNOWN')),
        source VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        confidence INTEGER DEFAULT 80 CHECK (confidence >= 0 AND confidence <= 100),
        asn VARCHAR(255) DEFAULT '',
        country VARCHAR(16) DEFAULT '',
        is_synthetic BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS InvestigationHistory (
        id VARCHAR(64) PRIMARY KEY,
        indicator VARCHAR(255) NOT NULL,
        type VARCHAR(16) NOT NULL CHECK (type IN ('ip', 'domain')),
        match_status VARCHAR(64) NOT NULL CHECK (match_status IN ('Known Indicator Match', 'No Match Found', 'Lookup Failed', 'Insufficient Evidence')),
        category VARCHAR(128) NOT NULL,
        severity VARCHAR(32) NOT NULL CHECK (severity IN ('HIGH RISK', 'MEDIUM RISK', 'LOW RISK', 'UNKNOWN')),
        source TEXT NOT NULL,
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
        type VARCHAR(16) NOT NULL CHECK (type IN ('ip', 'domain')),
        severity VARCHAR(32) NOT NULL CHECK (severity IN ('HIGH RISK', 'MEDIUM RISK', 'LOW RISK')),
        category VARCHAR(128) NOT NULL,
        description TEXT NOT NULL,
        evidence TEXT DEFAULT '',
        source TEXT NOT NULL,
        status VARCHAR(32) DEFAULT 'Active' CHECK (status IN ('Active', 'Reviewed', 'Acknowledged', 'Resolved')),
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
    `);

    console.log('[Init-DB] Seeding demonstration threat indicators...');
    for (const item of INITIAL_DEMO_THREATS) {
      await client.query(
        `INSERT INTO ThreatIndicators (id, indicator, type, category, severity, source, description, confidence, asn, country, is_synthetic, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         ON CONFLICT (indicator) DO UPDATE
         SET category = EXCLUDED.category, severity = EXCLUDED.severity, description = EXCLUDED.description`,
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

    console.log('[Init-DB] Seeding initial alerts and history...');
    for (const alert of INITIAL_DEMO_ALERTS) {
      await client.query(
        `INSERT INTO SecurityAlerts (id, indicator, type, severity, category, description, source, status, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (id) DO NOTHING`,
        [
          alert.id,
          alert.indicator,
          alert.type,
          alert.severity,
          alert.category,
          alert.description,
          alert.source,
          alert.status,
          alert.createdAt
        ]
      );
    }

    for (const hist of INITIAL_DEMO_HISTORY) {
      await client.query(
        `INSERT INTO InvestigationHistory (id, indicator, type, match_status, category, severity, source, confidence, evidence, asn, country, notes, threat_id, timestamp, analyst, is_synthetic)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
         ON CONFLICT (id) DO NOTHING`,
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

    console.log('[Init-DB] Successfully initialized and seeded PostgreSQL / Neon database!');
  } catch (err) {
    console.error('[Init-DB] Error initializing database:', err);
  } finally {
    client.release();
    await pool.end();
  }
}

initDatabase();
