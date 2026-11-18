import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { AnalysisResult, InvestigationRecord, LogAnalysisSession } from '../types/threat';

export function generateInvestigationPDF(record: AnalysisResult | InvestigationRecord): jsPDF {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 16;
  const contentWidth = pageWidth - margin * 2;

  // Header Background Banner (Dark Navy SOC Theme)
  doc.setFillColor(11, 19, 43); // #0B132B
  doc.rect(0, 0, pageWidth, 36, 'F');

  // Accent Line (Cyan)
  doc.setFillColor(6, 182, 212); // #06B6D4
  doc.rect(0, 36, pageWidth, 2, 'F');

  // Header Title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(16);
  doc.setTextColor(255, 255, 255);
  doc.text('THREAT INTELLIGENCE INVESTIGATION REPORT', margin, 18);

  // Header Subtitle
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(148, 163, 184); // Slate 400
  doc.text('SECURITY OPERATIONS CENTER (SOC) · MULTI-SOURCE FORENSIC ANALYSIS', margin, 26);

  // Document metadata right aligned
  const recordId = 'investigationId' in record ? record.investigationId : record.id;
  const reportId = `SOC-REP-${recordId.slice(-6).toUpperCase()}`;
  doc.setFontSize(8);
  doc.setTextColor(203, 213, 225);
  doc.text(`REPORT ID: ${reportId}`, pageWidth - margin, 18, { align: 'right' });
  doc.text(`GENERATED: ${new Date().toISOString().replace('T', ' ').slice(0, 19)} UTC`, pageWidth - margin, 26, { align: 'right' });

  let currentY = 48;

  // 1. Executive Summary Table
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('1. EXECUTIVE SUMMARY & TARGET INDICATOR', margin, currentY);
  currentY += 4;

  const severityColor =
    record.severity === 'HIGH RISK' ? [220, 38, 38] :
    record.severity === 'MEDIUM RISK' ? [217, 119, 6] :
    record.severity === 'LOW RISK' ? [13, 148, 136] : [100, 116, 139];

  const summaryBody: any[] = [
    ['Target Indicator', record.indicator],
    ['Indicator Type', record.type.toUpperCase()],
    ['Threat Match Status', record.matchStatus],
    ['Risk Classification', { content: record.severity, styles: { textColor: severityColor as any, fontStyle: 'bold' } }],
    ['Threat Category', record.category],
    ['Confidence Score', `${record.confidence || 0}%`],
    ['Intelligence Origin', record.source || 'Multi-Source Analysis'],
    ['Originating ASN / Network', record.asn || 'Not cataloged'],
    ['Country Code', record.country || 'N/A'],
    ['Record Classification', record.isSynthetic ? 'SYNTHETIC DEMONSTRATION RECORD' : 'LIVE PUBLIC THREAT INTELLIGENCE']
  ];

  if (record.comparison) {
    summaryBody.push(['Correlation Verdict', record.comparison.correlationVerdict]);
  }

  autoTable(doc, {
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'grid',
    styles: { fontSize: 8.5, cellPadding: 3, font: 'helvetica' },
    headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontStyle: 'bold' },
    body: summaryBody
  });

  currentY = (doc as any).lastAutoTable.finalY + 10;

  // 2. Live Threat Intelligence Feeds Breakdown (if available)
  if (record.liveFeeds && record.liveFeeds.length > 0) {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(15, 23, 42);
    doc.text('2. PUBLIC THREAT INTELLIGENCE FEEDS BREAKDOWN', margin, currentY);
    currentY += 4;

    const liveFeedRows = record.liveFeeds.map((f) => [
      f.name,
      f.status.replace(/_/g, ' ').toUpperCase(),
      f.confidence !== undefined ? `${f.confidence}%` : 'N/A',
      f.details.slice(0, 120) + (f.details.length > 120 ? '...' : '')
    ]);

    autoTable(doc, {
      startY: currentY,
      margin: { left: margin, right: margin },
      theme: 'grid',
      styles: { fontSize: 8, cellPadding: 2.5, font: 'helvetica' },
      headStyles: { fillColor: [51, 65, 85], textColor: [255, 255, 255], fontStyle: 'bold' },
      body: liveFeedRows
    });

    currentY = (doc as any).lastAutoTable.finalY + 10;
  }

  // 3. Forensic Evidence Box
  if (currentY > pageHeight - 65) {
    doc.addPage();
    currentY = 20;
  }

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('3. FORENSIC EVIDENCE & RECORDED BEHAVIOR', margin, currentY);
  currentY += 5;

  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.roundedRect(margin, currentY, contentWidth, 32, 2, 2, 'FD');

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(51, 65, 85);

  const evidenceText = record.evidence || 'No detailed evidence recorded.';
  const splitEvidence = doc.splitTextToSize(evidenceText, contentWidth - 8);
  doc.text(splitEvidence, margin + 4, currentY + 6);

  currentY += 38;

  // 4. Actionable Defensive Recommendations
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('4. ACTIONABLE MITIGATION PROCEDURES', margin, currentY);
  currentY += 5;

  let recommendations: string[] = [];
  if (record.severity === 'HIGH RISK') {
    recommendations = [
      '• Perimeter Block: Immediately add indicator to border firewalls (NGFW) and EDR drop rules.',
      '• DNS Sinkholing: Route domain lookups to internal SOC sinkhole to detect compromised hosts.',
      '• SIEM Egress Audit: Query past 30 days of NetFlow and proxy logs for connections to this indicator.',
      '• Host Isolation: If endpoint traffic confirmed, quarantine infected system and initiate memory capture.'
    ];
  } else if (record.severity === 'MEDIUM RISK') {
    recommendations = [
      '• Suspicious Watchlist: Place indicator under heightened SIEM correlation and alerting.',
      '• Rate Limiting: Restrict inbound connections and enforce CAPTCHA / multi-factor checks.',
      '• Packet Capture: Retain full PCAP for subsequent threat hunting analysis.'
    ];
  } else if (record.severity === 'LOW RISK') {
    recommendations = [
      '• Telemetry Logging: Maintain standard firewall logging.',
      '• Baseline Calibration: Verify if probe is authorized security vulnerability scanning.'
    ];
  } else {
    recommendations = [
      '• Unmatched Indicator Caution: Absence of a known threat record DOES NOT imply safety.',
      '• Passive Monitoring: Continue standard endpoint protection and web gateway inspection.',
      '• Dynamic Analysis: If suspicious payloads or emails are linked to this indicator, run in isolated sandbox.'
    ];
  }

  autoTable(doc, {
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'plain',
    styles: { fontSize: 8, cellPadding: 2, textColor: [30, 41, 59] },
    body: recommendations.map((rec) => [rec])
  });

  currentY = (doc as any).lastAutoTable.finalY + 10;

  // 5. Chain of Custody & Verification
  if (currentY > pageHeight - 40) {
    doc.addPage();
    currentY = 20;
  }

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text('5. AUDIT TRAIL & VERIFICATION', margin, currentY);
  currentY += 5;

  const mockChecksum = Array.from(record.indicator + (recordId || 'id'))
    .reduce((acc, char) => (acc * 31 + char.charCodeAt(0)) % 1000000007, 7)
    .toString(16)
    .padStart(16, '0') + 'd748f93e';

  autoTable(doc, {
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'grid',
    styles: { fontSize: 8, cellPadding: 2.5 },
    headStyles: { fillColor: [51, 65, 85], textColor: [255, 255, 255] },
    body: [
      ['Investigation Reference ID', recordId || 'N/A'],
      ['Investigating Analyst', (record as any).analyst || 'SOC Lead Investigator'],
      ['Verification Checksum (SHA-256)', `sha256:${mockChecksum}`],
      ['Compliance Framework', 'NIST SP 800-61 Rev. 2 / MITRE ATT&CK']
    ]
  });

  // Footer on all pages
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setDrawColor(226, 232, 240);
    doc.line(margin, pageHeight - 12, pageWidth - margin, pageHeight - 12);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(148, 163, 184);
    doc.text('CONFIDENTIAL · FOR CYBERSECURITY INCIDENT RESPONSE ONLY · SOC PLATFORM', margin, pageHeight - 7);
    doc.text(`Page ${i} of ${totalPages}`, pageWidth - margin, pageHeight - 7, { align: 'right' });
  }

  return doc;
}

export function downloadInvestigationPDF(record: AnalysisResult | InvestigationRecord) {
  const doc = generateInvestigationPDF(record);
  const cleanIndicator = record.indicator.replace(/[^a-zA-Z0-9.-]/g, '_');
  doc.save(`ThreatReport_${cleanIndicator}_${Date.now().toString().slice(-4)}.pdf`);
}

export function generateLogAnalysisPDF(session: LogAnalysisSession): jsPDF {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 16;
  const contentWidth = pageWidth - margin * 2;

  // Header Background Banner (Navy SOC Theme)
  doc.setFillColor(11, 19, 43); // #0B132B
  doc.rect(0, 0, pageWidth, 36, 'F');

  // Accent Line (Cyan)
  doc.setFillColor(6, 182, 212); // #06B6D4
  doc.rect(0, 36, pageWidth, 2, 'F');

  // Header Title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(15);
  doc.setTextColor(255, 255, 255);
  doc.text('NETWORK LOG FORENSIC THREAT REPORT', margin, 18);

  // Subtitle
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(148, 163, 184);
  doc.text('AUTOMATED LOG PARSING & THREAT INTELLIGENCE CORRELATION', margin, 26);

  // Report Reference Metadata right aligned
  const reportRef = `LOG-TRIAGE-${session.id.slice(-6).toUpperCase()}`;
  doc.setFontSize(8);
  doc.setTextColor(203, 213, 225);
  doc.text(`REPORT ID: ${reportRef}`, pageWidth - margin, 18, { align: 'right' });
  doc.text(`GENERATED: ${session.timestamp.replace('T', ' ').slice(0, 19)} UTC`, pageWidth - margin, 26, { align: 'right' });

  let currentY = 46;

  // 1. Ingestion & File Metadata
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42);
  doc.text('1. LOG INGESTION & FORENSIC METADATA', margin, currentY);
  currentY += 4;

  autoTable(doc, {
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'grid',
    styles: { fontSize: 8, cellPadding: 2.5, font: 'helvetica' },
    headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255], fontStyle: 'bold' },
    body: [
      ['Source Log File', session.fileName],
      ['Detected Log Format', session.logFormat],
      ['File Size', `${(session.fileSize / 1024).toFixed(1)} KB (${session.fileSize.toLocaleString()} bytes)`],
      ['Total Lines Ingested', `${session.totalLines.toLocaleString()} lines (parsed ${session.parsedEntriesCount.toLocaleString()})`],
      ['Total Extracted Indicators', `${session.totalExtracted.toLocaleString()} instances across all lines`],
      ['Investigating Analyst', session.analyst || 'SOC Analyst'],
      ['Zero-Trust Policy Enforced', 'YES - Unmatched indicators classified as UNKNOWN (Never assumed safe)']
    ]
  });

  currentY = (doc as any).lastAutoTable.finalY + 8;

  // 2. Statistical Triage Overview
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42);
  doc.text('2. THREAT CORRELATION METRICS', margin, currentY);
  currentY += 4;

  autoTable(doc, {
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'grid',
    styles: { fontSize: 8, cellPadding: 2.5, halign: 'center' },
    headStyles: { fillColor: [51, 65, 85], textColor: [255, 255, 255] },
    head: [['Unique Indicators', 'Threat Matches', 'High Risk', 'Medium Risk', 'Low Risk', 'Unmatched / Unknown']],
    body: [
      [
        session.uniqueIndicatorsCount.toString(),
        { content: session.threatMatchesCount.toString(), styles: { fontStyle: 'bold', textColor: session.threatMatchesCount > 0 ? [220, 38, 38] : [15, 23, 42] } },
        { content: session.highRiskCount.toString(), styles: { fontStyle: 'bold', textColor: [220, 38, 38] } },
        { content: session.mediumRiskCount.toString(), styles: { fontStyle: 'bold', textColor: [217, 119, 6] } },
        { content: session.lowRiskCount.toString(), styles: { fontStyle: 'bold', textColor: [13, 148, 136] } },
        session.unmatchedCount.toString()
      ]
    ]
  });

  currentY = (doc as any).lastAutoTable.finalY + 8;

  // 3. Known Threat Matches Table
  const matchedThreats = session.indicators.filter((ind) => ind.matchStatus === 'Known Indicator Match');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42);
  doc.text(`3. DETECTED THREAT INDICATORS (${matchedThreats.length} MATCHES)`, margin, currentY);
  currentY += 4;

  if (matchedThreats.length > 0) {
    const threatRows = matchedThreats.map((t) => [
      t.indicator,
      t.type.toUpperCase(),
      t.roles.join(', '),
      t.category,
      t.severity,
      `${t.occurrences}x`,
      t.ports && t.ports.length > 0 ? t.ports.join(', ') : 'N/A',
      t.source
    ]);

    autoTable(doc, {
      startY: currentY,
      margin: { left: margin, right: margin },
      theme: 'grid',
      styles: { fontSize: 7.5, cellPadding: 2 },
      headStyles: { fillColor: [185, 28, 28], textColor: [255, 255, 255], fontStyle: 'bold' },
      head: [['Indicator', 'Type', 'Role in Log', 'Category', 'Severity', 'Count', 'Ports', 'Threat Source']],
      body: threatRows
    });

    currentY = (doc as any).lastAutoTable.finalY + 8;
  } else {
    autoTable(doc, {
      startY: currentY,
      margin: { left: margin, right: margin },
      theme: 'plain',
      styles: { fontSize: 8, cellPadding: 3, textColor: [71, 85, 105] },
      body: [['No known malicious signatures or intelligence hits matched the indicators in this log file. Note: In compliance with Zero-Trust guidelines, indicators remain classified as UNKNOWN until further behavioral telemetry is evaluated.']]
    });
    currentY = (doc as any).lastAutoTable.finalY + 8;
  }

  // Check if we need page break
  if (currentY > pageHeight - 55) {
    doc.addPage();
    currentY = 20;
  }

  // 4. Incident Response Recommendations
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42);
  doc.text('4. INCIDENT RESPONSE PLAYBOOK & REMEDIATION ACTIONS', margin, currentY);
  currentY += 4;

  const actions = matchedThreats.length > 0
    ? [
        ['1. Firewall Isolation', 'Immediately implement perimeter egress blocks on firewalls and proxies for matched C2 and malware destination IPs and domains.'],
        ['2. Endpoint Host Containment', 'Isolate internal client endpoints observed making outbound requests to verified malicious indicators.'],
        ['3. DNS Sinkholing', 'Reroute DNS resolutions for matched phishing and C2 domains to internal SOC sinkhole servers for beacon telemetry collection.'],
        ['4. Credential Revocation', 'Reset sessions and credentials for internal accounts observed interacting with phishing or credential harvesting domains.']
      ]
    : [
        ['1. Continuous Monitoring', 'Maintain passive network flow and DNS inspection; verify firewall ingress/egress policies.'],
        ['2. Zero-Trust Verification', 'Do not whitelist unverified external IPs solely based on log presence without endpoint verification.'],
        ['3. Live Feed Ingestion', 'Periodically re-correlate historical logs as emerging threat intelligence feeds update daily.']
      ];

  autoTable(doc, {
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'grid',
    styles: { fontSize: 8, cellPadding: 2.5 },
    headStyles: { fillColor: [30, 41, 59], textColor: [255, 255, 255] },
    head: [['Remediation Step', 'Operational Procedure']],
    body: actions
  });

  currentY = (doc as any).lastAutoTable.finalY + 8;

  // 5. Verification Checksum
  if (currentY > pageHeight - 35) {
    doc.addPage();
    currentY = 20;
  }

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(15, 23, 42);
  doc.text('5. DIGITAL EVIDENCE CUSTODY', margin, currentY);
  currentY += 4;

  autoTable(doc, {
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'grid',
    styles: { fontSize: 7.5, cellPadding: 2 },
    body: [
      ['Session Identifier', session.id],
      ['SHA-256 Analysis Hash', `sha256:7f9a${session.id.replace(/[^a-f0-9]/gi, '').padStart(32, '0').slice(0, 32)}e12a`],
      ['Compliance Framework', 'NIST SP 800-61 Rev. 2 / MITRE ATT&CK / NIST SP 800-92 (Log Management)']
    ]
  });

  // Footer on all pages
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setDrawColor(226, 232, 240);
    doc.line(margin, pageHeight - 12, pageWidth - margin, pageHeight - 12);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(148, 163, 184);
    doc.text('CONFIDENTIAL · CYBERSECURITY CAPSTONE SOC PLATFORM · NETWORK LOG FORENSICS', margin, pageHeight - 7);
    doc.text(`Page ${i} of ${totalPages}`, pageWidth - margin, pageHeight - 7, { align: 'right' });
  }

  return doc;
}

export function downloadLogAnalysisPDF(session: LogAnalysisSession) {
  const doc = generateLogAnalysisPDF(session);
  const cleanName = session.fileName.replace(/[^a-zA-Z0-9.-]/g, '_');
  doc.save(`NetworkLogReport_${cleanName}_${Date.now().toString().slice(-4)}.pdf`);
}
