// csvParser.js - Parses SIEM CSV exports into normalized events
// Updated with syslog and extended column detection

import { parse } from 'csv-parse/sync';
import { createEvent, normalizeStatus, guessSeverity } from './normalizer.js';

// Extended column name mappings including syslog specific fields
const COLUMN_MAP = {
  timestamp: [
    'timestamp', 'time', 'date', 'datetime', 'event_time', 'eventtime',
    'created_at', '@timestamp', 'event.created', 'system.syslog.timestamp',
    'log.syslog.timestamp', 'firsttime', 'lasttime', '_time', 'occurred',
  ],
  user: [
    'user', 'username', 'user_name', 'actor', 'src_user', 'account',
    'identity', 'user.name', 'source.user.name', 'winlog.event_data.SubjectUserName',
    'userid', 'user_id', 'login', 'logon_user',
  ],
  ip: [
    'ip', 'src_ip', 'source_ip', 'srcip', 'client_ip', 'remote_ip',
    'ipaddress', 'source.ip', 'src', 'sourceip', 'host_ip',
    'system.syslog.hostname', 'agent.ip',
  ],
  destIp: [
    'dest_ip', 'dst_ip', 'destination_ip', 'destip', 'target_ip',
    'destination.ip', 'dest', 'dstip',
  ],
  action: [
    'action', 'event', 'event_type', 'eventname', 'operation', 'activity',
    'command', 'event.action', 'event_id', 'event.code', 'eventid',
    'system.syslog.program', 'process.name', 'winlog.event_id',
    'event.category', 'type',
  ],
  status: [
    'status', 'outcome', 'result', 'state', 'response', 'event.outcome',
    'result_code', 'errorcode', 'error_code', 'status_code',
  ],
  message: [
    'message', 'msg', 'description', 'details', 'log_message',
    'event.original', 'log.original', 'system.syslog.message',
    'message_text', 'log_text', 'raw_message',
  ],
  userAgent: [
    'useragent', 'user_agent', 'ua', 'browser',
    'http.request.headers.user-agent', 'agent',
  ],
  target: [
    'target', 'resource', 'object', 'dest', 'destination', 'host',
    'hostname', 'dest_host', 'target_host', 'computer_name',
    'system.syslog.hostname', 'host.name', 'beat.hostname',
  ],
  severity: [
    'severity', 'level', 'log.level', 'log_level', 'priority',
    'system.syslog.severity.name', 'alert.severity', 'risk_level',
  ],
  facility: [
    'facility', 'system.syslog.facility.name', 'log.facility',
  ],
};

/**
 * Finds the best matching column from a list of candidates
 */
function findColumn(headers, candidates) {
  const normalized = headers.map((h) => h.toLowerCase().trim());
  for (const candidate of candidates) {
    const idx = normalized.indexOf(candidate.toLowerCase());
    if (idx !== -1) return headers[idx];
  }
  return null;
}

/**
 * Tries to parse a syslog severity into our schema
 */
function parseSyslogSeverity(severity) {
  if (!severity) return null;
  const s = severity.toLowerCase();
  if (['emergency', 'alert', 'critical'].includes(s)) return 'critical';
  if (['error', 'err'].includes(s)) return 'high';
  if (['warning', 'warn', 'notice'].includes(s)) return 'medium';
  if (['informational', 'info', 'debug'].includes(s)) return 'low';
  return null;
}

/**
 * Parses CSV text into normalized events
 */
export function parseCsv(rawText) {
  let records;

  try {
    records = parse(rawText, {
      columns: true,
      skip_empty_lines: true,
      trim: true,
      relax_quotes: true,
      relax_column_count: true,
    });
  } catch (e) {
    return { events: [], confidence: 0, error: `CSV parse error: ${e.message}` };
  }

  if (!records || records.length === 0) {
    return { events: [], confidence: 0.2, error: 'No rows found in CSV' };
  }

  const headers = Object.keys(records[0]);
  const cols = {
    timestamp: findColumn(headers, COLUMN_MAP.timestamp),
    user: findColumn(headers, COLUMN_MAP.user),
    ip: findColumn(headers, COLUMN_MAP.ip),
    action: findColumn(headers, COLUMN_MAP.action),
    status: findColumn(headers, COLUMN_MAP.status),
    message: findColumn(headers, COLUMN_MAP.message),
    userAgent: findColumn(headers, COLUMN_MAP.userAgent),
    target: findColumn(headers, COLUMN_MAP.target),
    severity: findColumn(headers, COLUMN_MAP.severity),
    facility: findColumn(headers, COLUMN_MAP.facility),
  };

  const matchedCols = Object.values(cols).filter(Boolean).length;
  const confidence = Math.min(0.92, 0.4 + matchedCols * 0.07);

  const events = records.map((record) => {
    const rawAction = cols.action ? record[cols.action] : null;
    const rawStatus = cols.status ? record[cols.status] : null;
    const rawMessage = cols.message ? record[cols.message] : '';
    const rawSeverity = cols.severity ? record[cols.severity] : null;

    // Try to extract user from message if not in dedicated column
    let user = cols.user ? record[cols.user] : null;
    if (!user && rawMessage) {
      const userMatch = rawMessage.match(/(?:user|account|for)\s+['"']?(\w[\w.-]{1,32})['"']?/i);
      if (userMatch) user = userMatch[1];
    }

    // Try to extract IP from message if not in dedicated column
    let ip = cols.ip ? record[cols.ip] : null;
    if (!ip && rawMessage) {
      const ipMatch = rawMessage.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
      if (ipMatch) ip = ipMatch[0];
    }

    return createEvent({
      timestamp: cols.timestamp ? record[cols.timestamp] : null,
      source: 'siem',
      eventType: guessEventTypeFromCsv(rawAction, rawMessage),
      actor: {
        user: user || null,
        ip: ip || null,
        userAgent: cols.userAgent ? record[cols.userAgent] : null,
      },
      action: rawAction || null,
      target: cols.target ? record[cols.target] : null,
      status: normalizeStatus(rawStatus || ''),
      severityHint:
        parseSyslogSeverity(rawSeverity) ||
        guessSeverity({ action: rawAction, message: rawMessage }),
      raw: record,
    });
  });

  return {
    events,
    confidence,
    meta: {
      totalRecords: records.length,
      detectedColumns: cols,
      format: 'csv',
    },
  };
}

function guessEventTypeFromCsv(action, message) {
  const text = `${action || ''} ${message || ''}`.toLowerCase();
  if (text.includes('login') || text.includes('auth') || text.includes('password') ||
      text.includes('signin') || text.includes('logon') || text.includes('ssh')) return 'auth';
  if (text.includes('network') || text.includes('firewall') || text.includes('connection') ||
      text.includes('traffic') || text.includes('packet') || text.includes('dns')) return 'network';
  if (text.includes('iam') || text.includes('role') || text.includes('policy') ||
      text.includes('permission') || text.includes('privilege') || text.includes('sudo')) return 'iam';
  if (text.includes('process') || text.includes('command') || text.includes('exec') ||
      text.includes('run') || text.includes('spawn') || text.includes('script')) return 'process';
  return 'unknown';
}