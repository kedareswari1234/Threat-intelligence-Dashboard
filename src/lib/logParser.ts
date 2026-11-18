import {
  ExtractedLogIndicator,
  ParsedLogLine,
  NetworkLogRole,
  IndicatorType
} from '../types/threat';
import { validateIndicator } from './validation';

export interface ParseLogResult {
  detectedFormat: string;
  totalLines: number;
  parsedEntriesCount: number;
  totalExtracted: number;
  uniqueIndicators: ExtractedLogIndicator[];
  sampleLines: ParsedLogLine[];
}

// Maximum limits for security and performance
export const MAX_LOG_FILE_SIZE_BYTES = 5 * 1024 * 1024; // 5 MB
export const MAX_LOG_LINES = 10000;

// Regular expressions for extraction
const IPV4_REGEX = /\b(?!(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|127\.|0\.))((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b/g;
const ANY_IPV4_REGEX = /\b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))\b/g;
const IPV6_REGEX = /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b/g;
const DOMAIN_REGEX = /\b(?!(?:https?|ftp|file|ssh):\/\/)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|dev|biz|info|edu|gov|xyz|top|online|ru|cn|cc|co|me|cloud|live|site|app|tech|mobi|security|pro|club|agency|vip|shop|icu|quest)\b/gi;

// Extensions / false positives to discard from domain extraction
const IGNORED_EXTENSIONS = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico',
  'css', 'js', 'json', 'xml', 'html', 'htm', 'woff', 'woff2', 'ttf',
  'pdf', 'zip', 'tar', 'gz', 'mp4', 'mp3', 'wav', 'exe', 'bin', 'dll', 'log', 'txt', 'csv'
]);

const IGNORED_DOMAINS = new Set([
  'localhost',
  'example.com',
  'example.org',
  'example.net',
  'w3.org',
  'schema.org',
  'schemas.microsoft.com',
  'google.protobuf'
]);

/**
 * Detect log format based on pattern signatures in sample lines
 */
export function detectLogFormat(lines: string[]): string {
  const sample = lines.slice(0, 15).join('\n');

  if (sample.includes('SRC=') && sample.includes('DST=')) {
    return 'Linux iptables / Netfilter Firewall';
  }
  if (sample.includes('%ASA-') || sample.includes('%FTD-')) {
    return 'Cisco ASA / Firepower Firewall';
  }
  if (/^\d+\s+\d{10,14}\s+eni-[a-z0-9]+/m.test(sample)) {
    return 'AWS VPC Flow Log';
  }
  if (/^"(?:timestamp|src|dst|ip|domain)"/i.test(lines[0] || '') || lines[0]?.includes(',')) {
    // Check if first line contains common CSV headers
    const firstLineLower = (lines[0] || '').toLowerCase();
    if (firstLineLower.includes('ip') || firstLineLower.includes('src') || firstLineLower.includes('dst') || firstLineLower.includes('domain')) {
      return 'CSV Delimited Network Log';
    }
  }
  if (/^(\d{1,3}\.){3}\d{1,3}\s+-\s+-\s+\[.+\]\s+"[A-Z]+\s+/.test(sample)) {
    return 'Apache / Nginx Combined Web Access Log';
  }
  if (sample.includes('#separator') || sample.includes('#fields') || sample.includes('\tid.orig_h\t')) {
    return 'Zeek / Bro Network Bro Security Log';
  }
  return 'Standard Syslog / Plaintext Network Log';
}

/**
 * Clean and normalize domain strings extracted from URLs or logs
 */
function cleanExtractedDomain(rawDomain: string): string | null {
  let cleaned = rawDomain.toLowerCase().trim();
  // Strip trailing punctuation like comma, dot, parenthesis
  cleaned = cleaned.replace(/[),;:'">\s]+$/, '').replace(/^[<('"\s]+/, '');

  if (cleaned.includes('/')) {
    cleaned = cleaned.split('/')[0];
  }
  if (cleaned.includes(':')) {
    cleaned = cleaned.split(':')[0];
  }

  const parts = cleaned.split('.');
  if (parts.length < 2) return null;

  const tld = parts[parts.length - 1];
  if (IGNORED_EXTENSIONS.has(tld)) return null;
  if (IGNORED_DOMAINS.has(cleaned)) return null;
  if (/^\d+$/.test(tld)) return null; // Avoid IP endings

  // Basic sanity validation
  if (!/^[a-z0-9.-]+$/.test(cleaned)) return null;

  return cleaned;
}

/**
 * Multi-format line parser
 */
export function parseLogText(rawText: string): ParseLogResult {
  const sanitizedText = rawText.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  const allLines = sanitizedText.split('\n').filter((l) => l.trim().length > 0);
  const totalLines = allLines.length;
  const linesToParse = allLines.slice(0, MAX_LOG_LINES);

  const detectedFormat = detectLogFormat(linesToParse);

  // Map to collect and deduplicate indicators
  interface IndicatorAggregator {
    indicator: string;
    type: IndicatorType;
    subType: 'ipv4' | 'ipv6' | 'domain';
    roles: Set<NetworkLogRole>;
    occurrences: number;
    ports: Set<number>;
    protocols: Set<string>;
    firstSeen?: string;
    lastSeen?: string;
  }

  const aggregatorMap = new Map<string, IndicatorAggregator>();
  const sampleLines: ParsedLogLine[] = [];
  let totalExtractedCount = 0;

  // Helper to add an indicator to the aggregator
  const addIndicator = (
    indicator: string,
    type: IndicatorType,
    subType: 'ipv4' | 'ipv6' | 'domain',
    role: NetworkLogRole,
    timestamp?: string,
    port?: number,
    protocol?: string
  ) => {
    totalExtractedCount++;
    const key = `${type}:${indicator.toLowerCase()}`;
    let item = aggregatorMap.get(key);
    if (!item) {
      item = {
        indicator: indicator.toLowerCase(),
        type,
        subType,
        roles: new Set<NetworkLogRole>([role]),
        occurrences: 1,
        ports: new Set<number>(),
        protocols: new Set<string>(),
        firstSeen: timestamp,
        lastSeen: timestamp
      };
      aggregatorMap.set(key, item);
    } else {
      item.occurrences++;
      item.roles.add(role);
      if (timestamp) {
        if (!item.firstSeen) item.firstSeen = timestamp;
        item.lastSeen = timestamp;
      }
    }

    if (port && port > 0 && port <= 65535) {
      item.ports.add(port);
    }
    if (protocol) {
      item.protocols.add(protocol.toUpperCase());
    }
  };

  // Inspect lines according to detected format or fallbacks
  linesToParse.forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) return;

    let parsedSrcIp: string | undefined;
    let parsedDstIp: string | undefined;
    let parsedDomain: string | undefined;
    let parsedSrcPort: number | undefined;
    let parsedDstPort: number | undefined;
    let parsedProtocol: string | undefined;
    let parsedAction: string | undefined;
    let parsedTimestamp: string | undefined;
    let extractedInThisLine = 0;

    // Check for common timestamp in line (ISO, syslog, Apache)
    const isoMatch = trimmed.match(/\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b/);
    const apacheDateMatch = trimmed.match(/\[(\d{2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]/);
    const syslogDateMatch = trimmed.match(/^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/);

    if (isoMatch) {
      parsedTimestamp = isoMatch[0];
    } else if (apacheDateMatch) {
      parsedTimestamp = apacheDateMatch[1];
    } else if (syslogDateMatch) {
      parsedTimestamp = syslogDateMatch[1];
    }

    // Format 1: Linux iptables
    if (trimmed.includes('SRC=') && trimmed.includes('DST=')) {
      const srcMatch = trimmed.match(/SRC=([0-9a-fA-F.:]+)/);
      const dstMatch = trimmed.match(/DST=([0-9a-fA-F.:]+)/);
      const protoMatch = trimmed.match(/PROTO=([A-Za-z0-9]+)/);
      const sptMatch = trimmed.match(/SPT=(\d+)/);
      const dptMatch = trimmed.match(/DPT=(\d+)/);
      const actMatch = trimmed.match(/(ACCEPT|DROP|REJECT|BLOCK)/i);

      if (protoMatch) parsedProtocol = protoMatch[1];
      if (sptMatch) parsedSrcPort = parseInt(sptMatch[1], 10);
      if (dptMatch) parsedDstPort = parseInt(dptMatch[1], 10);
      if (actMatch) parsedAction = actMatch[1].toUpperCase();

      if (srcMatch) {
        parsedSrcIp = srcMatch[1];
        addIndicator(parsedSrcIp, 'ip', parsedSrcIp.includes(':') ? 'ipv6' : 'ipv4', 'source', parsedTimestamp, parsedSrcPort, parsedProtocol);
        extractedInThisLine++;
      }
      if (dstMatch) {
        parsedDstIp = dstMatch[1];
        addIndicator(parsedDstIp, 'ip', parsedDstIp.includes(':') ? 'ipv6' : 'ipv4', 'destination', parsedTimestamp, parsedDstPort, parsedProtocol);
        extractedInThisLine++;
      }
    }
    // Format 2: Cisco ASA firewall
    else if (trimmed.includes('%ASA-') || trimmed.includes('%FTD-')) {
      // Example: Built outbound TCP connection 12345 for outside:185.220.101.5/443 (185.220.101.5/443) to inside:192.168.1.105/52412
      const connMatch = trimmed.match(/(outside|inside|dmz|WAN|LAN):([0-9.]+)(?:\/(\d+))?.*?(?:to|from)\s+(outside|inside|dmz|WAN|LAN):([0-9.]+)(?:\/(\d+))?/i);
      if (connMatch) {
        const ip1 = connMatch[2];
        const port1 = connMatch[3] ? parseInt(connMatch[3], 10) : undefined;
        const ip2 = connMatch[5];
        const port2 = connMatch[6] ? parseInt(connMatch[6], 10) : undefined;

        parsedSrcIp = ip1;
        parsedDstIp = ip2;
        parsedSrcPort = port1;
        parsedDstPort = port2;

        addIndicator(ip1, 'ip', 'ipv4', 'source', parsedTimestamp, port1, 'TCP');
        addIndicator(ip2, 'ip', 'ipv4', 'destination', parsedTimestamp, port2, 'TCP');
        extractedInThisLine += 2;
      }
    }
    // Format 3: AWS VPC Flow Log
    // Standard format: <version> <account-id> <interface-id> <srcaddr> <dstaddr> <srcport> <dstport> <protocol> <packets> <bytes> <start> <end> <action> <log-status>
    else if (/^\d+\s+\d{10,14}\s+eni-[a-z0-9]+/i.test(trimmed)) {
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 14) {
        parsedSrcIp = parts[3];
        parsedDstIp = parts[4];
        parsedSrcPort = parseInt(parts[5], 10) || undefined;
        parsedDstPort = parseInt(parts[6], 10) || undefined;
        const protoNum = parts[7];
        parsedProtocol = protoNum === '6' ? 'TCP' : protoNum === '17' ? 'UDP' : protoNum === '1' ? 'ICMP' : `PROTO-${protoNum}`;
        parsedAction = parts[12].toUpperCase();

        if (parsedSrcIp && parsedSrcIp !== '-') {
          addIndicator(parsedSrcIp, 'ip', parsedSrcIp.includes(':') ? 'ipv6' : 'ipv4', 'source', parsedTimestamp, parsedSrcPort, parsedProtocol);
          extractedInThisLine++;
        }
        if (parsedDstIp && parsedDstIp !== '-') {
          addIndicator(parsedDstIp, 'ip', parsedDstIp.includes(':') ? 'ipv6' : 'ipv4', 'destination', parsedTimestamp, parsedDstPort, parsedProtocol);
          extractedInThisLine++;
        }
      }
    }
    // Format 4: CSV logs
    else if (detectedFormat.includes('CSV') && trimmed.includes(',')) {
      const cols = trimmed.split(',').map((c) => c.replace(/^["']|["']$/g, '').trim());
      // Scan each column for IP or Domain
      cols.forEach((col, colIdx) => {
        // IP check
        if (/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(col)) {
          const role: NetworkLogRole = colIdx === 0 || colIdx === 1 ? 'source' : 'destination';
          addIndicator(col, 'ip', 'ipv4', role, parsedTimestamp);
          extractedInThisLine++;
          if (!parsedSrcIp) parsedSrcIp = col;
          else if (!parsedDstIp) parsedDstIp = col;
        } else {
          // Domain check
          const cleanDom = cleanExtractedDomain(col);
          if (cleanDom) {
            addIndicator(cleanDom, 'domain', 'domain', 'domain', parsedTimestamp);
            extractedInThisLine++;
            if (!parsedDomain) parsedDomain = cleanDom;
          }
        }
      });
    }

    // Format 5: Apache / Nginx Web Access Log
    if (trimmed.includes('HTTP/')) {
      // First IP is typically client source IP
      const webClientIpMatch = trimmed.match(/^([0-9.]+)\s+/);
      if (webClientIpMatch) {
        parsedSrcIp = webClientIpMatch[1];
        addIndicator(parsedSrcIp, 'ip', 'ipv4', 'source', parsedTimestamp);
        extractedInThisLine++;
      }

      // Check for host headers or referrers with domains
      const urlMatches = trimmed.match(/https?:\/\/([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?::\d+)?/gi);
      if (urlMatches) {
        urlMatches.forEach((u) => {
          const domPart = u.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
          const cleanDom = cleanExtractedDomain(domPart);
          if (cleanDom) {
            addIndicator(cleanDom, 'domain', 'domain', 'referrer', parsedTimestamp);
            extractedInThisLine++;
            if (!parsedDomain) parsedDomain = cleanDom;
          }
        });
      }
    }

    // Universal Regex Fallback: Scan line for any IPv4, IPv6, or domains not captured
    if (extractedInThisLine === 0) {
      // IPv4
      const ipMatches = trimmed.match(ANY_IPV4_REGEX);
      if (ipMatches) {
        ipMatches.forEach((ip, i) => {
          // Validate octets
          const octets = ip.split('.').map(Number);
          if (octets.every((o) => o >= 0 && o <= 255)) {
            const role: NetworkLogRole = i === 0 ? 'source' : 'destination';
            addIndicator(ip, 'ip', 'ipv4', role, parsedTimestamp);
            extractedInThisLine++;
            if (!parsedSrcIp) parsedSrcIp = ip;
            else if (!parsedDstIp) parsedDstIp = ip;
          }
        });
      }

      // IPv6
      const ipv6Matches = trimmed.match(IPV6_REGEX);
      if (ipv6Matches) {
        ipv6Matches.forEach((ip6) => {
          if (ip6.includes(':') && ip6.length > 3) {
            addIndicator(ip6, 'ip', 'ipv6', 'source', parsedTimestamp);
            extractedInThisLine++;
          }
        });
      }

      // Domains
      const domainMatches = trimmed.match(DOMAIN_REGEX);
      if (domainMatches) {
        domainMatches.forEach((rawDom) => {
          const cleanDom = cleanExtractedDomain(rawDom);
          if (cleanDom) {
            addIndicator(cleanDom, 'domain', 'domain', 'domain', parsedTimestamp);
            extractedInThisLine++;
            if (!parsedDomain) parsedDomain = cleanDom;
          }
        });
      }
    }

    // Keep up to 30 sample lines for user inspection in UI
    if (sampleLines.length < 30) {
      sampleLines.push({
        lineNumber: index + 1,
        raw: trimmed.length > 200 ? trimmed.slice(0, 197) + '...' : trimmed,
        timestamp: parsedTimestamp,
        srcIp: parsedSrcIp,
        dstIp: parsedDstIp,
        domain: parsedDomain,
        srcPort: parsedSrcPort,
        dstPort: parsedDstPort,
        protocol: parsedProtocol,
        action: parsedAction,
        extractedCount: extractedInThisLine
      });
    }
  });

  // Convert aggregator map to unique indicators array
  const uniqueIndicators: ExtractedLogIndicator[] = Array.from(aggregatorMap.values()).map(
    (item) => ({
      indicator: item.indicator,
      type: item.type,
      subType: item.subType,
      roles: Array.from(item.roles),
      occurrences: item.occurrences,
      ports: item.ports.size > 0 ? Array.from(item.ports) : undefined,
      protocols: item.protocols.size > 0 ? Array.from(item.protocols) : undefined,
      firstSeen: item.firstSeen,
      lastSeen: item.lastSeen,
      // Default initial states prior to threat matching:
      matchStatus: 'No Match Found',
      severity: 'UNKNOWN',
      category: 'Uncorrelated Indicator',
      source: 'Network Log Extraction Engine',
      confidence: 0,
      evidence: `Extracted from uploaded network log (${item.occurrences} observed event${item.occurrences > 1 ? 's' : ''} in roles: ${Array.from(item.roles).join(', ')}). Awaiting threat intelligence correlation.`
    })
  );

  return {
    detectedFormat,
    totalLines,
    parsedEntriesCount: linesToParse.length,
    totalExtracted: totalExtractedCount,
    uniqueIndicators,
    sampleLines
  };
}

// ============================================================================
// BUILT-IN SAMPLE LOGS FOR CAPSTONE DEMONSTRATION
// ============================================================================

export const SAMPLE_LOG_FIREWALL_EGRESS = `# ============================================================================
# ENTERPRISE PERIMETER FIREWALL LOG - SECURITY OPERATIONS CENTER INCIDENT #4819
# Device: Cisco ASA 5585-X / Internal DMZ Border Firewall
# Location: Data Center East - Egress Inspection Feed
# ============================================================================
2026-10-29T14:22:01.104Z %ASA-6-302013: Built outbound TCP connection 849201 for outside:185.220.101.5/443 (185.220.101.5/443) to inside:192.168.1.105/52412 (192.168.1.105/52412)
2026-10-29T14:22:04.281Z %ASA-6-302013: Built outbound TCP connection 849202 for outside:185.220.101.5/443 (185.220.101.5/443) to inside:192.168.1.105/52414 (192.168.1.105/52414)
2026-10-29T14:22:15.652Z %ASA-6-302014: Teardown TCP connection 849201 for outside:185.220.101.5/443 to inside:192.168.1.105/52412 duration 0:00:14 bytes 14820 TCP FINs
2026-10-29T14:23:40.012Z %ASA-6-302013: Built outbound TCP connection 849310 for outside:91.240.118.172/8080 (91.240.118.172/8080) to inside:192.168.1.105/52440 (192.168.1.105/52440)
2026-10-29T14:24:10.890Z %ASA-4-106023: Deny tcp src outside:45.33.32.156/44122 dst inside:192.168.1.1/22 by access-group "OUTSIDE_IN" [0x8201a412, 0x0]
2026-10-29T14:25:02.115Z %ASA-6-302015: Built outbound UDP connection 849401 for outside:8.8.8.8/53 (8.8.8.8/53) to inside:192.168.1.2/61201 (192.168.1.2/61201)
2026-10-29T14:25:02.210Z %ASA-6-302016: Teardown UDP connection 849401 for outside:8.8.8.8/53 to inside:192.168.1.2/61201 duration 0:00:01 bytes 184
2026-10-29T14:26:45.330Z %ASA-6-302015: Built outbound UDP connection 849455 for outside:1.1.1.1/53 (1.1.1.1/53) to inside:192.168.1.2/61205 (192.168.1.2/61205)
2026-10-29T14:27:11.782Z %ASA-4-106023: Deny tcp src outside:194.26.29.114/58120 dst inside:192.168.1.20/445 by access-group "OUTSIDE_IN" [0x8201a412, 0x0]
2026-10-29T14:28:05.412Z %ASA-6-302013: Built outbound TCP connection 849502 for outside:142.250.190.46/443 (142.250.190.46/443) to inside:192.168.1.120/49180 (192.168.1.120/49180)
2026-10-29T14:29:19.901Z %ASA-4-106023: Deny tcp src outside:193.142.146.35/3389 dst inside:192.168.1.15/3389 by access-group "OUTSIDE_IN" [0x8201a412, 0x0]
2026-10-29T14:30:00.000Z %ASA-6-302014: Teardown TCP connection 849310 for outside:91.240.118.172/8080 to inside:192.168.1.105/52440 duration 0:06:20 bytes 2490100 TCP FINs
`;

export const SAMPLE_LOG_WEB_PROXY = `# ============================================================================
# CORPORATE SECURE WEB GATEWAY (SWG) & PROXY ACCESS LOG
# Format: Combined Web Access / Proxy Forwarded Log with Referrer Headers
# ============================================================================
192.168.10.45 - - [29/Oct/2026:09:14:22 +0000] "GET /login.html HTTP/1.1" 200 4820 "https://secure-bank-login-update.com/login?auth=session_8192" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.10.45 - - [29/Oct/2026:09:14:25 +0000] "POST /submit_creds.php HTTP/1.1" 302 512 "https://secure-bank-login-update.com/login" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.10.88 - - [29/Oct/2026:09:20:10 +0000] "GET /tracking/payload.exe HTTP/1.1" 200 892010 "https://global-shipping-track-update.com/delivery" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.10.12 - - [29/Oct/2026:09:25:01 +0000] "GET /api/v1/user HTTP/1.1" 200 1204 "https://api.github.com/users/octocat" "GitHub-Hookshot/1.0"
192.168.10.99 - - [29/Oct/2026:09:28:44 +0000] "GET /auth/saml/login HTTP/1.1" 200 6512 "https://portal-company-sso-verify.net/sso/auth" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
192.168.10.14 - - [29/Oct/2026:09:32:15 +0000] "GET /jquery.min.js HTTP/1.1" 304 0 "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0" "Mozilla/5.0"
192.168.10.14 - - [29/Oct/2026:09:33:02 +0000] "GET /search?q=cybersecurity+threats HTTP/1.1" 200 32410 "https://www.google.com/search" "Mozilla/5.0"
192.168.10.77 - - [29/Oct/2026:09:41:09 +0000] "GET /invoices/view HTTP/1.1" 200 3829 "https://billing-portal-invoice-docs.org/download" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.10.88 - - [29/Oct/2026:09:45:18 +0000] "POST /c2/checkin HTTP/1.1" 404 128 "https://global-shipping-track-update.com/gate.php" "WinHTTP-Agent/1.0"
192.168.10.50 - - [29/Oct/2026:09:50:33 +0000] "GET /cdn/bootstrap.css HTTP/1.1" 200 19280 "https://cdn.jsdelivr.net/npm/bootstrap" "Mozilla/5.0"
`;

export const SAMPLE_LOG_VPC_FLOW = `# ============================================================================
# AWS VPC FLOW LOGS - CLOUD INFRATRUCTURE INGESTION
# Format: version account-id eni-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
# ============================================================================
2 109283746192 eni-048a19283f 194.26.29.114 10.0.1.15 44102 445 6 12 584 1761748200 1761748260 REJECT OK
2 109283746192 eni-048a19283f 194.26.29.114 10.0.1.15 44103 445 6 12 584 1761748261 1761748320 REJECT OK
2 109283746192 eni-088f91283c 193.142.146.35 10.0.2.80 51922 3389 6 25 1204 1761748300 1761748360 REJECT OK
2 109283746192 eni-091c78192a 10.0.1.50 185.220.101.5 49182 443 6 450 198200 1761748350 1761748410 ACCEPT OK
2 109283746192 eni-091c78192a 10.0.1.50 91.240.118.172 49190 8080 6 320 145000 1761748420 1761748480 ACCEPT OK
2 109283746192 eni-012b33918a 10.0.1.10 8.8.8.8 53201 53 17 2 168 1761748500 1761748560 ACCEPT OK
2 109283746192 eni-012b33918a 10.0.1.10 1.1.1.1 53202 53 17 2 168 1761748505 1761748565 ACCEPT OK
2 109283746192 eni-055a88291f 45.33.32.156 10.0.3.20 38291 22 6 8 416 1761748600 1761748660 REJECT OK
2 109283746192 eni-099d44182b 10.0.1.120 142.250.190.46 51290 443 6 80 45200 1761748700 1761748760 ACCEPT OK
2 109283746192 eni-099d44182b 10.0.1.120 10.0.2.100 2049 2049 6 1200 950000 1761748800 1761748860 ACCEPT OK
`;
