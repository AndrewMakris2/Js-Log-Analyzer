// csvParser.js - Parses SIEM CSV exports into normalized events
// Uses csv-parse library, auto-detects common column names

import { parse } from 'csv-parse/sync';
import { createEvent, normalizeStatus, guessSeverity } from './normalizer.js';

// Common column name mappings - maps various SIEM column names to our schema
const COLUMN_MAP = {
  timestamp: ['timestamp', 'time', 'date', 'datetime', 'event_time', 'eventtime', 'created_at', '@timestamp'],
  user: ['user', 'username', 'user_name', 'actor', 'src_user', 'account', 'identity'],
  ip: ['ip', 'src_ip', 'source_ip', 'srcip', 'client_ip', 'remote_ip', 'ipaddress'],
  destIp: ['dest_ip', 'dst_ip', 'destination_ip', 'destip', 'target_ip'],
  action: ['action', 'event', 'event_type', 'eventname', 'operation', 'activity', 'command'],
  status: ['status', 'outcome', 'result', 'state', 'response'],
  message: ['message', 'msg', 'description', 'details', 'log_message'],
  userAgent: ['useragent', 'user_agent', 'ua', 'browser'],
  target: ['target', 'resource', 'object', 'dest', 'destination', 'host', 'hostname'],
};

/**
 * Finds the best matching column from a list of candidates
 * @param {string[]} headers - actual CSV headers
 * @param {string[]} candidates - possible column names
 * @returns {string|null}
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
 * Parses CSV text into normalized events
 * @param {string} rawText - raw CSV string
 * @returns {Object} - { events, confidence }
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

  // Detect columns from first record's keys
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
  };

  // Calculate confidence based on how many columns we matched
  const matchedCols = Object.values(cols).filter(Boolean).length;
  const confidence = Math.min(0.9, 0.4 + matchedCols * 0.07);

  const events = records.map((record) => {
    const rawAction = cols.action ? record[cols.action] : null;
    const rawStatus = cols.status ? record[cols.status] : null;
    const rawMessage = cols.message ? record[cols.message] : '';

    return createEvent({
      timestamp: cols.timestamp ? record[cols.timestamp] : null,
      source: 'siem',
      eventType: guessEventTypeFromCsv(rawAction, rawMessage),
      actor: {
        user: cols.user ? record[cols.user] : null,
        ip: cols.ip ? record[cols.ip] : null,
        userAgent: cols.userAgent ? record[cols.userAgent] : null,
      },
      action: rawAction || null,
      target: cols.target ? record[cols.target] : null,
      status: normalizeStatus(rawStatus || ''),
      severityHint: guessSeverity({ action: rawAction, message: rawMessage }),
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

/**
 * Guesses event type from CSV action/message fields
 */
function guessEventTypeFromCsv(action, message) {
  const text = `${action || ''} ${message || ''}`.toLowerCase();
  if (text.includes('login') || text.includes('auth') || text.includes('password') ||
      text.includes('signin') || text.includes('logon')) return 'auth';
  if (text.includes('network') || text.includes('firewall') || text.includes('connection') ||
      text.includes('traffic') || text.includes('packet')) return 'network';
  if (text.includes('iam') || text.includes('role') || text.includes('policy') ||
      text.includes('permission') || text.includes('privilege')) return 'iam';
  if (text.includes('process') || text.includes('command') || text.includes('exec') ||
      text.includes('run') || text.includes('spawn')) return 'process';
  return 'unknown';
}