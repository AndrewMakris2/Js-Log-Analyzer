// plaintextParser.js - Parses plaintext log files using regex heuristics
// Handles syslog, auth.log, apache/nginx access logs, generic logs

import { createEvent, normalizeStatus, guessSeverity } from './normalizer.js';

// Regex patterns for common log formats
const PATTERNS = {
  // Timestamps
  isoTimestamp: /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?/,
  syslogTimestamp: /(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}/,
  genericTimestamp: /\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}/,

  // IPs
  ipAddress: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,

  // Users
  userPatterns: [
    /(?:user|username|for user|account)\s+['"']?(\w[\w.-]{1,32})['"']?/i,
    /(?:su|sudo)\s+[-\w]+\s+(\w+)/i,
    /\bfor\s+(\w+)\s+from\b/i,
    /invalid user\s+(\w+)/i,
    /Failed password for (?:invalid user )?(\w+)/i,
    /Accepted (?:password|publickey) for (\w+)/i,
  ],

  // HTTP methods
  httpMethod: /\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP\/[\d.]+/i,

  // HTTP status codes
  httpStatus: /\s(2\d{2}|3\d{2}|4\d{2}|5\d{2})\s/,

  // Auth events
  failedLogin: /(?:failed|failure|invalid|incorrect|wrong)\s+(?:password|login|auth|credential)/i,
  successLogin: /(?:accepted|success|successful)\s+(?:password|login|auth|publickey)/i,
  sudoUse: /\bsudo\b/i,
  suUse: /\bsu\b/i,
  assumeRole: /(?:assume.?role|sts|assumerole)/i,

  // Privilege changes
  privilegeChange: /(?:privilege|escalat|sudo|root|admin|permission|policy|role)/i,

  // Error indicators
  errorIndicators: /(?:error|exception|critical|alert|emergency|panic|fatal)/i,
  warningIndicators: /(?:warn|warning|notice)/i,

  // Process/command indicators
  processIndicators: /(?:exec|spawn|fork|process|command|cmd|shell|bash|sh\s)/i,
};

/**
 * Extracts timestamp from a log line
 */
function extractTimestamp(line) {
  let match = line.match(PATTERNS.isoTimestamp);
  if (match) return new Date(match[0]).toISOString();

  match = line.match(PATTERNS.genericTimestamp);
  if (match) {
    try {
      return new Date(match[0]).toISOString();
    } catch (e) {
      return null;
    }
  }

  match = line.match(PATTERNS.syslogTimestamp);
  if (match) {
    try {
      const year = new Date().getFullYear();
      return new Date(`${match[0]} ${year}`).toISOString();
    } catch (e) {
      return null;
    }
  }

  return null;
}

/**
 * Extracts IP addresses from a log line
 */
function extractIPs(line) {
  const matches = line.match(PATTERNS.ipAddress);
  if (!matches) return [];
  // Filter out version-looking numbers
  return [...new Set(matches)].filter((ip) => {
    const parts = ip.split('.').map(Number);
    return parts.every((p) => p <= 255);
  });
}

/**
 * Extracts username from a log line
 */
function extractUser(line) {
  for (const pattern of PATTERNS.userPatterns) {
    const match = line.match(pattern);
    if (match && match[1]) return match[1];
  }
  return null;
}

/**
 * Determines event type from log line content
 */
function getEventType(line) {
  const lower = line.toLowerCase();
  if (PATTERNS.failedLogin.test(line) || PATTERNS.successLogin.test(line)) return 'auth';
  if (lower.includes('ssh') || lower.includes('login') || lower.includes('pam')) return 'auth';
  if (PATTERNS.assumeRole.test(line)) return 'iam';
  if (PATTERNS.privilegeChange.test(line) && !PATTERNS.failedLogin.test(line)) return 'iam';
  if (PATTERNS.httpMethod.test(line)) return 'network';
  if (lower.includes('firewall') || lower.includes('iptables') || lower.includes('network')) return 'network';
  if (PATTERNS.processIndicators.test(line) || PATTERNS.sudoUse.test(line)) return 'process';
  return 'unknown';
}

/**
 * Determines status from log line
 */
function getStatus(line) {
  if (PATTERNS.failedLogin.test(line)) return 'failure';
  if (PATTERNS.successLogin.test(line)) return 'success';

  const httpMatch = line.match(PATTERNS.httpStatus);
  if (httpMatch) {
    const code = parseInt(httpMatch[1]);
    if (code >= 200 && code < 400) return 'success';
    if (code >= 400) return 'failure';
  }

  if (PATTERNS.errorIndicators.test(line)) return 'failure';
  return 'unknown';
}

/**
 * Determines severity hint from log line
 */
function getSeverityHint(line) {
  const lower = line.toLowerCase();
  if (lower.includes('critical') || lower.includes('emergency') || lower.includes('panic')) return 'critical';
  if (PATTERNS.failedLogin.test(line) || lower.includes('error') || lower.includes('denied')) return 'high';
  if (PATTERNS.warningIndicators.test(line) || lower.includes('warn')) return 'medium';
  return 'low';
}

/**
 * Extracts the action/operation from a log line
 */
function extractAction(line) {
  // HTTP method
  const httpMatch = line.match(PATTERNS.httpMethod);
  if (httpMatch) return `${httpMatch[1]} ${httpMatch[2]}`;

  // Sudo
  if (PATTERNS.sudoUse.test(line)) return 'sudo';

  // Failed login
  if (PATTERNS.failedLogin.test(line)) return 'failed_login';
  if (PATTERNS.successLogin.test(line)) return 'successful_login';

  // Assume role
  if (PATTERNS.assumeRole.test(line)) return 'assume_role';

  // First significant word after timestamp/hostname (best effort)
  const words = line.trim().split(/\s+/);
  const meaningfulWords = words.filter(
    (w) => w.length > 3 && !/^\d+$/.test(w) && !/^\d{4}-/.test(w)
  );
  return meaningfulWords[0] || null;
}

/**
 * Parses plaintext log file into normalized events
 * @param {string} rawText - raw log text
 * @returns {Object} - { events, confidence }
 */
export function parsePlaintext(rawText) {
  if (!rawText || rawText.trim().length === 0) {
    return { events: [], confidence: 0, error: 'Empty file' };
  }

  const lines = rawText.split('\n').filter((l) => l.trim().length > 0);
  let parsedCount = 0;

  const events = lines.map((line) => {
    const timestamp = extractTimestamp(line);
    const ips = extractIPs(line);
    const user = extractUser(line);
    const action = extractAction(line);
    const status = getStatus(line);
    const eventType = getEventType(line);
    const severityHint = getSeverityHint(line);

    if (timestamp || user || ips.length > 0) parsedCount++;

    return createEvent({
      timestamp,
      source: 'plaintext',
      eventType,
      actor: {
        user,
        ip: ips[0] || null,
        userAgent: null,
      },
      action,
      target: ips[1] || null,
      status,
      severityHint,
      raw: { line },
    });
  });

  // Confidence based on how many lines we could extract meaningful data from
  const confidence = Math.min(0.85, parsedCount / lines.length);

  return {
    events,
    confidence,
    meta: {
      totalLines: lines.length,
      parsedLines: parsedCount,
      format: 'plaintext',
    },
  };
}