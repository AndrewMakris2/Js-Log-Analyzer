// normalizer.js - Common event schema converter
// Every parser outputs events in this exact format

/**
 * Creates a normalized event object with defaults
 * @param {Object} fields - partial event fields
 * @returns {Object} - normalized event
 */
export function createEvent(fields = {}) {
  return {
    timestamp: fields.timestamp || null,
    source: fields.source || 'unknown',
    eventType: fields.eventType || 'unknown',
    actor: {
      user: fields.actor?.user || null,
      ip: fields.actor?.ip || null,
      userAgent: fields.actor?.userAgent || null,
    },
    action: fields.action || null,
    target: fields.target || null,
    status: fields.status || 'unknown',
    severityHint: fields.severityHint || null,
    raw: fields.raw || {},
  };
}

/**
 * Normalizes a status string to success/failure/unknown
 * @param {string} status
 * @returns {string}
 */
export function normalizeStatus(status) {
  if (!status) return 'unknown';
  const s = status.toLowerCase();
  if (['success', 'succeeded', 'ok', '200', 'accepted', 'allow', 'allowed'].includes(s)) return 'success';
  if (['failure', 'failed', 'fail', 'error', 'denied', 'reject', 'rejected', 'blocked'].includes(s)) return 'failure';
  return 'unknown';
}

/**
 * Guesses severity based on action/status keywords
 * @param {Object} fields
 * @returns {string}
 */
export function guessSeverity(fields = {}) {
  const text = JSON.stringify(fields).toLowerCase();

  if (
    text.includes('critical') ||
    text.includes('malware') ||
    text.includes('ransomware') ||
    text.includes('rootkit')
  ) return 'critical';

  if (
    text.includes('deletePolicy') ||
    text.includes('putrolepolicy') ||
    text.includes('privilege') ||
    text.includes('escalat') ||
    text.includes('accessdenied') ||
    text.includes('unauthorized')
  ) return 'high';

  if (
    text.includes('failed') ||
    text.includes('failure') ||
    text.includes('error') ||
    text.includes('warn') ||
    text.includes('assumeRole') ||
    text.includes('createuser')
  ) return 'medium';

  return 'low';
}