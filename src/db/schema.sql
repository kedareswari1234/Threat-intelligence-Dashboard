-- ====================================================================
-- THREAT INTELLIGENCE DASHBOARD FOR MALICIOUS IP AND DOMAIN ANALYSIS
-- Database Schema for PostgreSQL / Neon Database
-- Capstone Project Specification
-- ====================================================================

-- 1. Threat Indicators Table (Local & Imported Threat Intelligence)
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

CREATE INDEX IF NOT EXISTS idx_threat_indicator ON ThreatIndicators (indicator);
CREATE INDEX IF NOT EXISTS idx_threat_type ON ThreatIndicators (type);
CREATE INDEX IF NOT EXISTS idx_threat_severity ON ThreatIndicators (severity);
CREATE INDEX IF NOT EXISTS idx_threat_category ON ThreatIndicators (category);

-- 2. Investigation History Table (Audit Trail of all User Inquiries)
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
    threat_id VARCHAR(64) REFERENCES ThreatIndicators(id) ON DELETE SET NULL,
    timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    analyst VARCHAR(128) DEFAULT 'SOC Analyst',
    is_synthetic BOOLEAN DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_history_indicator ON InvestigationHistory (indicator);
CREATE INDEX IF NOT EXISTS idx_history_type ON InvestigationHistory (type);
CREATE INDEX IF NOT EXISTS idx_history_severity ON InvestigationHistory (severity);
CREATE INDEX IF NOT EXISTS idx_history_timestamp ON InvestigationHistory (timestamp DESC);

-- 3. Security Alerts Table (Automated Threat Alerts & Incident Triage)
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

CREATE INDEX IF NOT EXISTS idx_alerts_indicator ON SecurityAlerts (indicator);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON SecurityAlerts (status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON SecurityAlerts (severity);
CREATE INDEX IF NOT EXISTS idx_alerts_last_observed ON SecurityAlerts (last_observed_at DESC);

-- 4. Network Log Analyses Table
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
