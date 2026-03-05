// anomalyDetector.js - Rule-based anomaly detection
// Updated with off-hours and volume spike rules

function groupBy(events, keyFn) {
  return events.reduce((acc, event) => {
    const key = keyFn(event);
    if (!key) return acc;
    if (!acc[key]) acc[key] = [];
    acc[key].push(event);
    return acc;
  }, {});
}

function detectBruteForce(events) {
  const failures = events.filter(
    (e) => e.status === 'failure' && (e.eventType === 'auth' || (e.action || '').includes('login'))
  );

  const byUser = groupBy(failures, (e) => e.actor.user);
  const byIp = groupBy(failures, (e) => e.actor.ip);
  const anomalies = [];

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
        explanation: `Actor "${actor}" received ${evts.length} AccessDenied responses.`,
      });
    }
  }

  return anomalies;
}

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
        explanation: `User "${user}" assumed roles ${evts.length} times.`,
      });
    }
  }

  return anomalies;
}

function detectRareActions(events) {
  const actionCounts = {};
  for (const event of events) {
    const action = event.action || 'unknown';
    actionCounts[action] = (actionCounts[action] || 0) + 1;
  }

  const totalEvents = events.length;
  const rareThreshold = Math.max(1, totalEvents * 0.01);

  const rareEvents = events.filter(
    (e) => e.action && actionCounts[e.action] <= rareThreshold
  );

  if (rareEvents.length === 0) return [];

  const rareActions = [...new Set(rareEvents.map((e) => e.action))];

  return [{
    category: 'Suspicious Activity',
    title: `Rare Actions Detected (${rareActions.length} unique)`,
    severity: 'medium',
    evidence: rareEvents.slice(0, 10),
    explanation: `${rareActions.length} rare actions detected: ${rareActions.slice(0, 5).join(', ')}.`,
  }];
}

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
        explanation: `User "${user}" accessed from ${ips.size} different IPs: ${[...ips].slice(0, 5).join(', ')}.`,
      });
    }
  }

  return anomalies;
}

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

  return [{
    category: 'Suspicious Process/Command',
    title: `Suspicious Commands Detected (${suspicious.length})`,
    severity: 'high',
    evidence: suspicious.slice(0, 10),
    explanation: `${suspicious.length} events contain suspicious command patterns.`,
  }];
}

// NEW - Off hours activity
function detectOffHoursActivity(events) {
  const businessHours = [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18];

  const offHours = events.filter((e) => {
    if (!e.timestamp) return false;
    try {
      const hour = new Date(e.timestamp).getHours();
      return !businessHours.includes(hour);
    } catch { return false; }
  });

  if (offHours.length < 10) return [];

  const offHoursPct = ((offHours.length / events.length) * 100).toFixed(0);

  if (offHoursPct < 20) return [];

  return [{
    category: 'Suspicious Activity',
    title: `High Off-Hours Activity (${offHoursPct}% of events)`,
    severity: offHoursPct > 50 ? 'high' : 'medium',
    evidence: offHours.slice(0, 10),
    explanation: `${offHours.length} events (${offHoursPct}%) occurred outside business hours (7am-6pm). This may indicate automated processes or unauthorized access.`,
  }];
}

// NEW - Weekend activity
function detectWeekendActivity(events) {
  const weekendEvents = events.filter((e) => {
    if (!e.timestamp) return false;
    try {
      const day = new Date(e.timestamp).getDay();
      return day === 0 || day === 6;
    } catch { return false; }
  });

  if (weekendEvents.length < 5) return [];

  const weekendPct = ((weekendEvents.length / events.length) * 100).toFixed(0);
  if (weekendPct < 15) return [];

  return [{
    category: 'Suspicious Activity',
    title: `Significant Weekend Activity (${weekendEvents.length} events)`,
    severity: 'medium',
    evidence: weekendEvents.slice(0, 10),
    explanation: `${weekendEvents.length} events (${weekendPct}%) occurred on weekends. Review if this is expected for your environment.`,
  }];
}

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
    ...detectOffHoursActivity(events),
    ...detectWeekendActivity(events),
  ];

  console.log(`Detected ${allAnomalies.length} anomalies`);
  return allAnomalies;
}