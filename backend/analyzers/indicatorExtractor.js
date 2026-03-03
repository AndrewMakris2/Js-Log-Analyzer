// indicatorExtractor.js - Extracts and counts top indicators
// IPs, users, actions, resources with frequency counts

/**
 * Counts occurrences of values and returns sorted array
 */
function countAndSort(values, limit = 20) {
  const counts = {};
  for (const val of values) {
    if (!val) continue;
    counts[val] = (counts[val] || 0) + 1;
  }

  return Object.entries(counts)
    .map(([value, count]) => ({ value, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

/**
 * Extracts top indicators from normalized events
 * @param {Array} events - normalized events
 * @returns {Object} - { ips, users, actions, resources }
 */
export function extractIndicators(events) {
  if (!events || events.length === 0) {
    return { ips: [], users: [], actions: [], resources: [] };
  }

  const ips = countAndSort(events.map((e) => e.actor.ip));
  const users = countAndSort(events.map((e) => e.actor.user));
  const actions = countAndSort(events.map((e) => e.action));
  const resources = countAndSort(events.map((e) => e.target));

  // Also extract error codes if present (CloudTrail)
  const errorCodes = countAndSort(
    events
      .map((e) => e.raw?.errorCode)
      .filter(Boolean)
  );

  // User agents
  const userAgents = countAndSort(
    events.map((e) => e.actor.userAgent).filter(Boolean),
    10
  );

  return {
    ips,
    users,
    actions,
    resources,
    errorCodes,
    userAgents,
    summary: {
      totalEvents: events.length,
      uniqueIPs: ips.length,
      uniqueUsers: users.length,
      uniqueActions: actions.length,
      failureRate: (
        (events.filter((e) => e.status === 'failure').length / events.length) *
        100
      ).toFixed(1) + '%',
    },
  };
}