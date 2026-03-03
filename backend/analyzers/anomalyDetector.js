// anomalyDetector.js - Rule-based anomaly detection
// Groups events into anomaly categories before LLM processing

/**
 * Groups events by a key function
 */
function groupBy(events, keyFn) {
  return events.reduce((acc, event) => {
    const key = keyFn(event);
    if (!key) return acc;
    if (!acc[key]) acc[key] = [];
    acc[key].push(event);
    return acc;
  }, {});
}

/**
 * Checks if two events are within a time window (minutes)
 */
function withinWindow(event1, event2, minutes = 10) {
  if (!event1.timestamp || !event2.timestamp) return true;
  const diff = Math.abs(
    new Date(event1.timestamp) - new Date(event2.timestamp)
  );
  return diff <= minutes * 60 * 1000;
}

/**
 * Detects multiple failed logins by same user or IP
 */
function detectBruteForce(events) {
  const failures = events.filter(
    (e) => e.status === 'failure' && (e.eventType === 'auth' || e.action?.includes('login'))
  );

  const byUser = groupBy(failures, (e) => e.actor.user);
  const byIp = groupBy(failures, (e) => e.actor.ip);

  const anomalies = [];

  // User-based brute force (5+ failures)
  for (const [user, evts] of Object.entries(byUser)) {
    if (evts.length >= 5) {
      anomalies.push({
        category: 'Authentication Anomaly',
        title: `Brute Force - User: ${user}`,
        severity: evts.length >= 20 ? 'critical' : 'high',
        evidence: evts.slice(0, 10),
        explanation: `User "${user}" had ${evts.length} failed login attempts.`,
      });
    }
  }

  // IP-based brute force (10+ failures)
  for (const [ip, evts] of Object.entries(byIp)) {
    if (evts.length >= 10) {
      anomalies.push({
        category: 'Authentication Anomaly',
        title: `Brute Force from IP: ${ip}`,
        severity: evts.length >= 50 ? 'critical' : 'high',
        evidence: evts.slice(0, 10),
        explanation: `IP "${ip}" triggered ${evts.length} failed login attempts.`,
      });
    }
  }

  return anomalies;
}

/**
 * Detects AccessDenied bursts
 */
function detectAccessDeniedBursts(events) {
  const denied = events.filter(
    (e) =>
      e.status === 'failure' &&
      (JSON.stringify(e.raw).toLowerCase().includes('accessdenied') ||
        JSON.stringify(e.raw).toLowerCase().includes('unauthorized'))
  );

  const byUser = groupBy(denied, (e) => e.actor.user || e.actor.ip || 'unknown');
  const anomalies = [];

  for (const [actor, evts] of Object.entries(byUser)) {
    if (evts.length >= 5) {
      anomalies.push({
        category: 'Authorization Anomaly',
        title: `AccessDenied Burst - ${actor}`,
        severity: 'high',
        evidence: evts.slice(0, 10),
        explanation: `Actor "${actor}" received ${evts.length} AccessDenied responses. Possible unauthorized enumeration or misconfigured permissions.`,
      });
    }
  }

  return anomalies;
}

/**
 * Detects privilege escalation and IAM changes
 */
function detectPrivilegeChanges(events) {
  const iamEvents = events.filter((e) => e.eventType === 'iam');
  const suspiciousActions = [
    'putrolepolicy', 'attachrolepolicy', 'createpolicy', 'deletepolicy',
    'createuser', 'deleteuser', 'addusertgroup', 'createaccesskey',
    'updateassumerolepolicydocument', 'putuserpolicy', 'attachuserpolicy',
  ];

  const privilegeEvents = iamEvents.filter((e) => {
    const action = (e.action || '').toLowerCase();
    return suspiciousActions.some((s) => action.includes(s));
  });

  if (privilegeEvents.length === 0) return [];

  const byUser = groupBy(privilegeEvents, (e) => e.actor.user || 'unknown');
  const anomalies = [];

  for (const [user, evts] of Object.entries(byUser)) {
    anomalies.push({
      category: 'Privilege Change',
      title: `IAM Modification by: ${user}`,
      severity: evts.length >= 5 ? 'critical' : 'high',
      evidence: evts.slice(0, 10),
      explanation: `User "${user}" performed ${evts.length} IAM modification(s): ${[...new Set(evts.map((e) => e.action))].join(', ')}.`,
    });
  }

  return anomalies;
}

/**
 * Detects role assumption spikes
 */
function detectRoleAssumptionSpikes(events) {
  const roleEvents = events.filter(
    (e) =>
      (e.action || '').toLowerCase().includes('assumerole') ||
      (e.action || '').toLowerCase().includes('assume_role')
  );

  if (roleEvents.length < 3) return [];

  const byUser = groupBy(roleEvents, (e) => e.actor.user || 'unknown');
  const anomalies = [];

  for (const [user, evts] of Object.entries(byUser)) {
    if (evts.length >= 3) {
      anomalies.push({
        category: 'Privilege Change',
        title: `Role Assumption Spike - ${user}`,
        severity: 'medium',
        evidence: evts.slice(0, 10),
        explanation: `User "${user}" assumed roles ${evts.length} times. Repeated role assumptions may indicate privilege escalation attempts.`,
      });
    }
  }

  return anomalies;
}

/**
 * Detects rare/unusual actions in the dataset
 */
function detectRareActions(events) {
  const actionCounts = {};
  for (const event of events) {
    const action = event.action || 'unknown';
    actionCounts[action] = (actionCounts[action] || 0) + 1;
  }

  const totalEvents = events.length;
  const rareThreshold = Math.max(1, totalEvents * 0.01); // Less than 1% of events

  const rareEvents = events.filter(
    (e) => e.action && actionCounts[e.action] <= rareThreshold
  );

  if (rareEvents.length === 0) return [];

  // Group rare events
  const rareActions = [...new Set(rareEvents.map((e) => e.action))];

  return [
    {
      category: 'Suspicious Activity',
      title: `Rare Actions Detected (${rareActions.length} unique)`,
      severity: 'medium',
      evidence: rareEvents.slice(0, 10),
      explanation: `${rareActions.length} rare actions detected that appear in less than 1% of events: ${rareActions.slice(0, 5).join(', ')}${rareActions.length > 5 ? '...' : ''}.`,
    },
  ];
}

/**
 * Detects new/unusual IPs for known users
 */
function detectNewIPs(events) {
  const userIPs = {};

  for (const event of events) {
    const user = event.actor.user;
    const ip = event.actor.ip;
    if (!user || !ip) continue;
    if (!userIPs[user]) userIPs[user] = new Set();
    userIPs[user].add(ip);
  }

  const anomalies = [];

  for (const [user, ips] of Object.entries(userIPs)) {
    if (ips.size >= 5) {
      anomalies.push({
        category: 'Network Anomaly',
        title: `Multiple IPs for User: ${user}`,
        severity: 'medium',
        evidence: events.filter((e) => e.actor.user === user).slice(0, 5),
        explanation: `User "${user}" accessed from ${ips.size} different IP addresses: ${[...ips].slice(0, 5).join(', ')}.`,
      });
    }
  }

  return anomalies;
}

/**
 * Detects suspicious process/command indicators
 */
function detectSuspiciousProcesses(events) {
  const suspiciousPatterns = [
    /(?:base64|b64decode)/i,
    /(?:curl|wget)\s+http/i,
    /(?:nc|netcat)\s+-/i,
    /(?:\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)/i,
    /(?:chmod\s+[74][74][74])/i,
    /(?:rm\s+-rf)/i,
    /(?:mkfifo|mknod)/i,
  ];

  const suspicious = events.filter((e) => {
    const text = JSON.stringify(e.raw);
    return suspiciousPatterns.some((p) => p.test(text));
  });

  if (suspicious.length === 0) return [];

  return [
    {
      category: 'Suspicious Process/Command',
      title: `Suspicious Commands Detected (${suspicious.length})`,
      severity: 'high',
      evidence: suspicious.slice(0, 10),
      explanation: `${suspicious.length} events contain suspicious command patterns (base64, reverse shells, destructive commands).`,
    },
  ];
}

/**
 * Main anomaly detection function
 * @param {Array} events - normalized events
 * @returns {Array} - anomalies
 */
export function detectAnomalies(events) {
  if (!events || events.length === 0) return [];

  const allAnomalies = [
    ...detectBruteForce(events),
    ...detectAccessDeniedBursts(events),
    ...detectPrivilegeChanges(events),
    ...detectRoleAssumptionSpikes(events),
    ...detectRareActions(events),
    ...detectNewIPs(events),
    ...detectSuspiciousProcesses(events),
  ];

  console.log(`Detected ${allAnomalies.length} anomalies`);
  return allAnomalies;
}