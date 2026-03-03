// cloudtrailParser.js - Parses AWS CloudTrail JSON logs
// Handles the Records[] array format from CloudTrail

import { createEvent, normalizeStatus, guessSeverity } from './normalizer.js';

/**
 * Maps a CloudTrail errorCode to a severity hint
 */
function errorCodeSeverity(errorCode) {
  if (!errorCode) return null;
  const code = errorCode.toLowerCase();
  if (code.includes('accessdenied') || code.includes('unauthorized')) return 'high';
  if (code.includes('throttl')) return 'medium';
  return 'medium';
}

/**
 * Determines eventType from CloudTrail eventName
 */
function getEventType(eventName, eventSource) {
  if (!eventName) return 'unknown';
  const name = eventName.toLowerCase();
  const source = (eventSource || '').toLowerCase();

  if (source.includes('iam') || name.includes('user') || name.includes('role') ||
      name.includes('policy') || name.includes('group')) return 'iam';

  if (name.includes('login') || name.includes('signin') || name.includes('auth') ||
      name.includes('password') || name.includes('credential')) return 'auth';

  if (name.includes('network') || name.includes('vpc') || name.includes('security group') ||
      name.includes('subnet') || name.includes('route')) return 'network';

  if (name.includes('run') || name.includes('invoke') || name.includes('execute') ||
      name.includes('start') || name.includes('launch')) return 'process';

  return 'unknown';
}

/**
 * Parses AWS CloudTrail JSON into normalized events
 * @param {string} rawText - raw JSON string
 * @returns {Object} - { events, confidence }
 */
export function parseCloudTrail(rawText) {
  let parsed;

  try {
    parsed = JSON.parse(rawText);
  } catch (e) {
    return { events: [], confidence: 0, error: 'Invalid JSON' };
  }

  // CloudTrail exports wrap records in a "Records" array
  const records = parsed.Records || parsed.records || (Array.isArray(parsed) ? parsed : []);

  if (records.length === 0) {
    return { events: [], confidence: 0.3, error: 'No Records found' };
  }

  const events = records.map((record) => {
    const errorCode = record.errorCode || record.errorMessage || null;
    const status = errorCode ? 'failure' : 'success';

    // Extract user identity
    const identity = record.userIdentity || {};
    const user =
      identity.userName ||
      identity.sessionContext?.sessionIssuer?.userName ||
      identity.arn ||
      identity.type ||
      null;

    // Extract resources
    const resources = record.resources
      ? record.resources.map((r) => r.ARN || r.resourceName || '').join(', ')
      : record.requestParameters
      ? JSON.stringify(record.requestParameters).slice(0, 100)
      : null;

    const fields = {
      timestamp: record.eventTime || null,
      source: 'cloudtrail',
      eventType: getEventType(record.eventName, record.eventSource),
      actor: {
        user,
        ip: record.sourceIPAddress || null,
        userAgent: record.userAgent || null,
      },
      action: record.eventName || null,
      target: resources || record.eventSource || null,
      status: normalizeStatus(status),
      severityHint: errorCode
        ? errorCodeSeverity(errorCode)
        : guessSeverity({ eventName: record.eventName }),
      raw: record,
    };

    return createEvent(fields);
  });

  return {
    events,
    confidence: 0.95,
    meta: {
      totalRecords: records.length,
      format: 'cloudtrail',
    },
  };
}