# Threat Intelligence Dashboard for Malicious IP and Domain Analysis

> **Investigate. Analyze. Protect.**  
> *A Security Operations Center (SOC) Capstone Cybersecurity Platform.*

---

## 🛡️ Project Overview

The **Threat Intelligence Dashboard for Malicious IP and Domain Analysis** is a production-grade full-stack cybersecurity web application designed for security analysts, incident responders, and SOC teams. It allows investigators to evaluate suspicious IP addresses and domain names, cross-reference them against stored threat intelligence records, classify risk severities, triage automated security alerts, and generate formal forensic PDF investigation reports.

This project was engineered to satisfy all requirements for a **College Capstone Project Demonstration**, adhering strictly to NIST SP 800-61 incident response guidelines and zero-trust verification principles.

---

## 🚀 Key Modules & Architecture

### **Module 1: IP Address and Domain Analysis**
- **Dual Investigation Modes**: Dedicated tabs for **IP Address Lookup** and **Domain Name Lookup**.
- **Comprehensive Syntax Validation**:
  - **IPv4**: Exact 4-octet checks (0–255), leading-zero rejections, RFC 1918 Private subnet detection (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and loopback detection.
  - **IPv6**: Full standard and compressed (`::`) RFC 4291 syntax validation.
  - **Domain Names**: RFC 1035 / RFC 1123 compliant FQDN parsing, label length bounds, hyphen rules, and TLD validation.
- **Input Sanitization**: Automatically strips protocols (`http://`, `https://`), trailing slashes, port numbers, paths, and query parameters.
- **Clear Error Feedback**: Precise, human-friendly error messages explaining exactly why an input is malformed.

### **Module 2: Threat Intelligence & Live Integration Engine**
- **Live Public Threat Intelligence Integrations**:
  - **AlienVault OTX**: Live community threat pulses, malicious campaign correlation, and adversary tracking. Active in open community mode or with `OTX_API_KEY`.
  - **URLhaus (abuse.ch)**: Real-time malware distribution URL and payload host detection using `URLHAUS_API_KEY`.
  - **AbuseIPDB**: 90-day multi-reporter IP abuse reputation scoring and ISP telemetry using `ABUSEIPDB_API_KEY`.
- **Multi-Source Correlation**: Cross-references local database indicators with live public feeds in parallel and outputs correlation verdicts (`Multi-Source Correlated Threat`, `Live Intelligence Detected Match`, `Local Threat Record Match`, `No Match Across Sources`).
- **Threat Intelligence Database**: Stores local indicators with threat categories, severities, confidence metrics, ASN, geolocation, intelligence source, and forensic descriptions.
- **Strict Risk Classification Rules**:
  - `HIGH RISK`: Confirmed C2 nodes, Ransomware staging, active Phishing portals.
  - `MEDIUM RISK`: Port scanning honeypot triggers, suspicious crypto drainers.
  - `LOW RISK`: SIP/VoIP census probes, aggressive fingerprinting.
  - `UNKNOWN`: Unmatched indicators. *(Crucial cybersecurity policy: Unmatched indicators are NEVER marked "safe", as absence of threat data does not equal clean).*
- **Synthetic Demonstration Dataset**: Pre-populated with clearly labelled demonstration IOCs.
- **Threat Management (CRUD)**: Create, search, update, delete, and export threat records.

### **Module 3: Security Dashboard, Alerts & PDF Reporting**
- **SOC Executive Dashboard**:
  - Metric cards: Total Indicators, Threat Matches, High-Risk Records, Recent Audits.
  - Severity distribution visualizer (High, Medium, Low, Unknown).
  - Threat category distribution chart.
- **Active Security Alerts**: Automatically creates alert records for high-risk matches with workflow states (`Active` → `Acknowledged` → `Resolved`).
- **Audit Investigation History**: Searchable, multi-filtered history with CSV export and case detail modals.
- **Forensic PDF Reports**: Client-side PDF generation using `jspdf` and `jspdf-autotable` featuring official SOC headers, incident details, mitigation directives, and cryptographic verification checksums.

---

## 🗄️ Database Architecture

The application uses **PostgreSQL** via Neon Database with an automatic local persistent JSON storage fallback (`data/threat_store.json`), allowing instant local execution even before setting up a remote database.

### Tables

1. **`ThreatIndicators`**:
   - `id VARCHAR(64) PRIMARY KEY`
   - `indicator VARCHAR(255) NOT NULL UNIQUE`
   - `type VARCHAR(16) NOT NULL CHECK (type IN ('ip', 'domain'))`
   - `category VARCHAR(64) NOT NULL`
   - `severity VARCHAR(32) NOT NULL CHECK (severity IN ('HIGH RISK', 'MEDIUM RISK', 'LOW RISK', 'UNKNOWN'))`
   - `source VARCHAR(255) NOT NULL`
   - `description TEXT NOT NULL`
   - `confidence INTEGER DEFAULT 80`
   - `asn VARCHAR(255)`, `country VARCHAR(16)`
   - `is_synthetic BOOLEAN DEFAULT true`
   - `created_at`, `updated_at`

2. **`InvestigationHistory`**:
   - `id VARCHAR(64) PRIMARY KEY`
   - `indicator VARCHAR(255) NOT NULL`
   - `type VARCHAR(16) NOT NULL`
   - `match_status VARCHAR(64) NOT NULL`
   - `category VARCHAR(64)`, `severity VARCHAR(32)`, `source VARCHAR(255)`
   - `confidence INTEGER`, `evidence TEXT`, `asn VARCHAR(255)`, `country VARCHAR(16)`
   - `notes TEXT`, `threat_id VARCHAR(64)`
   - `timestamp TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP`
   - `analyst VARCHAR(128)`, `is_synthetic BOOLEAN`

3. **`SecurityAlerts`**:
   - `id VARCHAR(64) PRIMARY KEY`
   - `indicator VARCHAR(255) NOT NULL`
   - `type VARCHAR(16) NOT NULL`
   - `severity VARCHAR(32) NOT NULL`
   - `category VARCHAR(64)`, `description TEXT`, `source VARCHAR(255)`
   - `status VARCHAR(32) DEFAULT 'Active' CHECK (status IN ('Active', 'Acknowledged', 'Resolved'))`
   - `created_at TIMESTAMPTZ`, `acknowledged_at TIMESTAMPTZ`

---

## 💻 Tech Stack

- **Frontend**: React 19, TypeScript, Tailwind CSS v4, Lucide Icons, jsPDF & jsPDF-AutoTable
- **Backend**: Node.js, Express, tsx
- **Database**: PostgreSQL (Neon-compatible `pg` pool) with automatic local persistent store fallback
- **Build & Dev**: Vite 8, TypeScript 7

---

## 📦 Project Structure

```
├── .env.example              # Environment variables template
├── index.html                # HTML entry point with fonts & metadata
├── metadata.json             # Applet metadata definition
├── package.json              # Dependencies and scripts
├── server.ts                 # Full-stack Express server with Vite dev integration
├── vercel.json               # Vercel deployment configuration
├── api/
│   └── index.ts              # Vercel serverless API router
├── data/
│   └── threat_store.json     # Local fallback persistent JSON storage
├── scripts/
│   └── init-db.ts            # Neon/PostgreSQL schema migration & seeder
└── src/
    ├── App.tsx               # Root component wiring all views and state
    ├── main.tsx              # React DOM entry point
    ├── index.css             # Tailwind CSS & dark theme tokens
    ├── components/
    │   ├── Sidebar.tsx       # SOC sidebar navigation
    │   ├── TopBar.tsx        # Top bar with real-time UTC clock & quick action
    │   ├── DashboardView.tsx # Executive SOC dashboard & quick search
    │   ├── AnalysisView.tsx  # Module 1 & 2 IP/Domain investigation workstation
    │   ├── ThreatIntelligenceView.tsx # Module 2 threat DB CRUD manager
    │   ├── InvestigationHistoryView.tsx # Module 3 investigation audit trail
    │   ├── SecurityAlertsView.tsx # Module 3 incident triage queue
    │   ├── ReportsView.tsx   # Module 3 forensic report preview & PDF generator
    │   └── SettingsView.tsx  # DB connection test, DDL viewer & capstone test suite
    ├── db/
    │   ├── db.ts             # Hybrid database abstraction (Neon/Postgres + Local)
    │   ├── schema.sql        # Standard PostgreSQL DDL definition
    │   └── seeds.ts          # Initial synthetic demonstration test IOCs
    ├── lib/
    │   ├── api.ts            # Frontend API client
    │   ├── engine.ts         # Threat classification & alert generation engine
    │   ├── pdfReport.ts      # Client-side SOC forensic PDF generator
    │   └── validation.ts     # Strict IPv4, IPv6, and FQDN validation logic
    └── types/
        └── threat.ts         # TypeScript interfaces and data models
```

---

## 🛠️ Local Setup & Execution Instructions

### Prerequisites
- Node.js (v18.0.0 or higher)
- npm or yarn
- Visual Studio Code or any modern editor

### Step 1: Install Dependencies
```bash
npm install
```

### Step 2: Configure Environment
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
*(Optional)* If you have a Neon PostgreSQL database, set `DATABASE_URL` in `.env`:
```env
DATABASE_URL="postgres://username:password@ep-cool-lake-123456.us-east-2.aws.neon.tech/neondb?sslmode=require"
```
*Note: If no `DATABASE_URL` is provided, the application runs automatically using the local persistent database file (`data/threat_store.json`).*

### Step 3: Run Database Migrations (Optional for Neon)
```bash
npm run db:init
```

### Step 4: Start Development Server
```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your web browser.

---

## 🚀 Vercel Deployment Instructions

1. **Push to GitHub**:
   Commit and push your project to a GitHub repository:
   ```bash
   git init
   git add .
   git commit -m "feat: Capstone Threat Intelligence Dashboard"
   git remote add origin https://github.com/your-username/threat-intelligence-dashboard.git
   git push -u origin main
   ```

2. **Deploy on Vercel**:
   - Go to [vercel.com](https://vercel.com) and click **"Add New Project"**.
   - Import your GitHub repository.
   - Framework Preset: **Vite**.
   - Build Command: `npm run build`.
   - Output Directory: `dist`.

3. **Configure Neon PostgreSQL Environment Variable**:
   - Create a free database at [neon.tech](https://neon.tech).
   - In Vercel Project Settings → **Environment Variables**, add:
     - `DATABASE_URL` = your Neon PostgreSQL connection string.
     - `NODE_ENV` = `production`.

4. **Deploy**:
   - Click **Deploy**. Vercel will build the frontend and serve both the SPA and serverless `/api` routes!

---

## 🧪 Capstone Demonstration Test Scenarios

| Test # | Scenario | Sample Indicator | Expected Outcome |
|---|---|---|---|
| 1 | **Valid IPv4 Address** | `185.220.101.5` | Validated, matched to LockBit Tor Exit Node, `HIGH RISK`, security alert generated |
| 2 | **Valid IPv6 Address** | `2001:db8:ffff:1::99` | Validated, matched to Covert Exfiltration C2, `HIGH RISK` |
| 3 | **Valid Domain Name** | `secure-bank-login-update.com` | Validated, matched to Phishing Credential Harvester, `HIGH RISK` |
| 4 | **Invalid IP Address** | `999.400.12.300` | Rejected with: *"Octet 1 (999) is out of range (0-255)"* |
| 5 | **Invalid Domain Name** | `invalid..domain.xyz` | Rejected with: *"Domain cannot contain consecutive dots"* |
| 6 | **Unmatched Indicator** | `8.8.8.8` | Classified as `UNKNOWN` with advisory: *"Absence of threat record does not imply benign"* |
| 7 | **Audit History Logging** | Any lookup | Automatically logged in `InvestigationHistory` with timestamp, analyst notes, and verdict |
| 8 | **PDF Report Generation** | Click *"PDF Report"* | Generates professional forensic incident report with checksum & mitigation directives |

---

## ⚖️ Academic Honor & License
Built as an educational cybersecurity capstone project. Synthetic test indicators are provided solely for academic evaluation and demonstration.
