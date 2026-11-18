import { ValidationResult, IndicatorType } from '../types/threat';

/**
 * Sanitizes input string by trimming whitespace, lowercasing, and removing protocols/paths
 */
export function sanitizeIndicator(rawInput: string): string {
  if (!rawInput) return '';
  let sanitized = rawInput.trim();

  // Strip protocol (http://, https://, ftp://, etc.)
  sanitized = sanitized.replace(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//, '');

  // Strip path, query params, hash first so domain:port/path isolates domain:port
  sanitized = sanitized.split('/')[0].split('?')[0].split('#')[0];

  // Strip userinfo if present (e.g. user@domain.com)
  if (sanitized.includes('@')) {
    sanitized = sanitized.split('@').pop() || sanitized;
  }

  // Strip port if present (for domain:port or ipv4:port, or [ipv6]:port)
  if (sanitized.startsWith('[') && sanitized.includes(']:')) {
    sanitized = sanitized.slice(1, sanitized.indexOf(']:'));
  } else if (!sanitized.startsWith('[') && sanitized.includes(':') && !sanitized.includes('::')) {
    const parts = sanitized.split(':');
    if (parts.length === 2 && /^\d+$/.test(parts[1])) {
      sanitized = parts[0];
    }
  }

  // Remove IPv6 brackets if present e.g. [2001:db8::1]
  if (sanitized.startsWith('[') && sanitized.endsWith(']')) {
    sanitized = sanitized.slice(1, -1);
  }

  return sanitized.trim().toLowerCase();
}

/**
 * Validates IPv4 address
 */
export function validateIPv4(ip: string): { isValid: boolean; error?: string; isPrivate?: boolean; isLoopback?: boolean; isReserved?: boolean } {
  const parts = ip.split('.');
  if (parts.length !== 4) {
    return { isValid: false, error: 'IPv4 address must contain exactly 4 octets separated by dots (e.g., 192.168.1.1).' };
  }

  for (let i = 0; i < 4; i++) {
    const octet = parts[i];
    if (!/^\d+$/.test(octet)) {
      return { isValid: false, error: `Octet ${i + 1} ("${octet}") contains non-numeric characters.` };
    }
    // Reject leading zeroes like "01", "002" unless it is single "0"
    if (octet.length > 1 && octet.startsWith('0')) {
      return { isValid: false, error: `Octet ${i + 1} ("${octet}") has invalid leading zeros.` };
    }
    const num = parseInt(octet, 10);
    if (num < 0 || num > 255) {
      return { isValid: false, error: `Octet ${i + 1} (${num}) is out of range. Values must be between 0 and 255.` };
    }
  }

  const o1 = parseInt(parts[0], 10);
  const o2 = parseInt(parts[1], 10);

  const isLoopback = o1 === 127;
  const isPrivate =
    o1 === 10 ||
    (o1 === 172 && o2 >= 16 && o2 <= 31) ||
    (o1 === 192 && o2 === 168);
  const isReserved =
    (o1 === 169 && o2 === 254) || // Link-local
    (o1 >= 224 && o1 <= 239) ||   // Multicast
    (o1 >= 240);                  // Reserved

  return { isValid: true, isPrivate, isLoopback, isReserved };
}

/**
 * Validates IPv6 address (supports standard full, compressed ::, and loopback)
 */
export function validateIPv6(ip: string): { isValid: boolean; error?: string; isLoopback?: boolean } {
  // Check for invalid characters
  if (!/^[0-9a-fA-F:]+$/.test(ip)) {
    return { isValid: false, error: 'IPv6 address contains invalid hexadecimal characters.' };
  }

  // Count :: occurrences (at most one)
  const doubleColonCount = (ip.match(/::/g) || []).length;
  if (doubleColonCount > 1) {
    return { isValid: false, error: 'IPv6 address cannot contain more than one "::" compression sequence.' };
  }

  const isCompressed = doubleColonCount === 1;

  if (isCompressed) {
    const halves = ip.split('::');
    const leftParts = halves[0] ? halves[0].split(':') : [];
    const rightParts = halves[1] ? halves[1].split(':') : [];

    const totalExplicit = leftParts.length + rightParts.length;
    if (totalExplicit >= 8) {
      return { isValid: false, error: 'IPv6 address with "::" has too many hextets.' };
    }

    const allParts = [...leftParts, ...rightParts];
    for (const part of allParts) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(part)) {
        return { isValid: false, error: `Invalid IPv6 hextet "${part}". Each must be 1 to 4 hexadecimal digits.` };
      }
    }
  } else {
    const parts = ip.split(':');
    if (parts.length !== 8) {
      return { isValid: false, error: `Standard uncompressed IPv6 address must have exactly 8 hextets (found ${parts.length}).` };
    }
    for (const part of parts) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(part)) {
        return { isValid: false, error: `Invalid IPv6 hextet "${part}". Each must be 1 to 4 hexadecimal digits.` };
      }
    }
  }

  const isLoopback = ip === '::1' || ip === '0:0:0:0:0:0:0:1';
  return { isValid: true, isLoopback };
}

/**
 * Validates domain name (RFC 1035 / RFC 1123)
 */
export function validateDomain(domain: string): { isValid: boolean; error?: string; tld?: string } {
  if (!domain || domain.length === 0) {
    return { isValid: false, error: 'Domain name cannot be empty.' };
  }

  if (domain.length > 253) {
    return { isValid: false, error: 'Domain name exceeds maximum allowed length of 253 characters.' };
  }

  // Check for spaces or disallowed symbols
  if (/\s/.test(domain)) {
    return { isValid: false, error: 'Domain name cannot contain spaces.' };
  }

  if (domain.includes('..')) {
    return { isValid: false, error: 'Domain name cannot contain consecutive dots.' };
  }

  if (domain.startsWith('.') || domain.endsWith('.')) {
    return { isValid: false, error: 'Domain name cannot start or end with a dot.' };
  }

  const labels = domain.split('.');
  if (labels.length < 2) {
    return { isValid: false, error: 'Domain name must include a Top-Level Domain (TLD), e.g., "example.com".' };
  }

  const tld = labels[labels.length - 1];

  // TLD validation: at least 2 chars alpha, or valid punycode xn--...
  if (!/^(xn--[a-zA-Z0-9]{2,}|[a-zA-Z]{2,})$/.test(tld)) {
    return { isValid: false, error: `Invalid Top-Level Domain ".${tld}". TLD must contain at least 2 alphabetic characters.` };
  }

  // Validate each label
  for (let i = 0; i < labels.length; i++) {
    const label = labels[i];
    if (label.length === 0) {
      return { isValid: false, error: 'Domain label cannot be empty.' };
    }
    if (label.length > 63) {
      return { isValid: false, error: `Domain label "${label.substring(0, 15)}..." exceeds maximum limit of 63 characters.` };
    }
    if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$/.test(label)) {
      return {
        isValid: false,
        error: `Domain label "${label}" is invalid. Labels can only contain letters, digits, and hyphens, and cannot start or end with a hyphen.`
      };
    }
  }

  return { isValid: true, tld };
}

/**
 * Master validation function that inspects indicator and target type
 */
export function validateIndicator(rawInput: string, expectedType?: IndicatorType): ValidationResult {
  const sanitized = sanitizeIndicator(rawInput);

  if (!sanitized) {
    return {
      isValid: false,
      sanitized: '',
      error: 'Please enter an IP address or domain name to analyze.'
    };
  }

  // Check if expectedType is 'ip' or if input appears to be an IP
  const looksLikeIPv4 = /^[0-9.]+$/.test(sanitized) && sanitized.includes('.');
  const looksLikeIPv6 = sanitized.includes(':');

  if (expectedType === 'ip' || (!expectedType && (looksLikeIPv4 || looksLikeIPv6))) {
    // Try IPv4 first
    if (looksLikeIPv4 || (!looksLikeIPv6 && /^\d/.test(sanitized))) {
      const ipv4Res = validateIPv4(sanitized);
      if (ipv4Res.isValid) {
        return {
          isValid: true,
          type: 'ip',
          subType: 'ipv4',
          sanitized,
          details: {
            isPrivate: ipv4Res.isPrivate,
            isLoopback: ipv4Res.isLoopback,
            isReserved: ipv4Res.isReserved
          }
        };
      } else if (expectedType === 'ip' && !looksLikeIPv6) {
        return {
          isValid: false,
          type: 'ip',
          subType: 'ipv4',
          sanitized,
          error: ipv4Res.error
        };
      }
    }

    // Try IPv6
    if (looksLikeIPv6) {
      const ipv6Res = validateIPv6(sanitized);
      if (ipv6Res.isValid) {
        return {
          isValid: true,
          type: 'ip',
          subType: 'ipv6',
          sanitized,
          details: {
            isLoopback: ipv6Res.isLoopback
          }
        };
      } else if (expectedType === 'ip') {
        return {
          isValid: false,
          type: 'ip',
          subType: 'ipv6',
          sanitized,
          error: ipv6Res.error
        };
      }
    }

    if (expectedType === 'ip') {
      return {
        isValid: false,
        type: 'ip',
        sanitized,
        error: 'Invalid IP address format. Please enter a valid IPv4 (e.g. 192.0.2.1) or IPv6 address (e.g. 2001:db8::1).'
      };
    }
  }

  // Check domain validation
  const domainRes = validateDomain(sanitized);
  if (domainRes.isValid) {
    return {
      isValid: true,
      type: 'domain',
      subType: 'domain',
      sanitized,
      details: {
        tld: domainRes.tld
      }
    };
  }

  if (expectedType === 'domain') {
    return {
      isValid: false,
      type: 'domain',
      subType: 'domain',
      sanitized,
      error: domainRes.error || 'Invalid domain name format.'
    };
  }

  // Generic fallback error
  return {
    isValid: false,
    sanitized,
    error: 'Input could not be recognized as a valid IPv4, IPv6 address, or domain name.'
  };
}
