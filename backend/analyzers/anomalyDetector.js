// anomalyDetector.js - Rule-based anomaly detection with rich context

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
 * Extracts rich context from an event for display
 */
function enrichEvent(event) {
  const raw = event.raw || {};
  const rawStr = JSON.stringify(raw);

  const emailMatch = rawStr.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
  const email = emailMatch ? emailMatch[0] : null;

  const ua = event.actor.userAgent || raw.userAgent || raw.user_agent || null;
  let device = null;
  if (ua) {
    if (/mobile|android|iphone|ipad/i.test(ua)) device = 'Mobile Device';
    else if (/windows/i.test(ua)) device = 'Windows PC';
    else if (/macintosh|mac os/i.test(ua)) device = 'Mac';
    else if (/linux/i.test(ua)) device = 'Linux';
    else if (/curl|python|java|go-http|boto/i.test(ua)) device = 'Automated/Script';
    else device = 'Unknown Device';
  }

  const awsRegion = raw.awsRegion || raw.aws_region || null;
  const accountId = raw.recipientAccountId || raw.account_id || null;
  const errorCode = raw.errorCode || raw.error_code || null;
  const errorMessage = raw.errorMessage || raw.error_message || null;

  return {
    ...event,
    _enriched: {
      email,
      device,
      awsRegion,
      accountId,
      errorCode,
      errorMessage,
      ua,
    },
  };
}

/**
 * Gets first and last timestamps from a list of events
 */
function getTimeSpan(events) {
  const timestamps = events
    .map((e) => e.timestamp)
    .filter(Boolean)
    .map((t) => new Date(t).getTime())
    .filter((t) => !isNaN(t));

  if (timestamps.length === 0) return { first: null, last: null, spanMinutes: null };

  const first = new Date(Math.min(...timestamps)).toISOString();
  const last = new Date(Math.max(...timestamps)).toISOString();
  const spanMinutes = Math.round((Math.max(...timestamps) - Math.min(...timestamps)) / 60000);

  return { first, last, spanMinutes };
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
      const enriched = evts.map(enrichEvent);
      const timeSpan = getTimeSpan(evts);
      const ips = [...new Set(evts.map((e) => e.actor.ip).filter(Boolean))];
      const targets = [...new Set(evts.map((e) => e.target).filter(Boolean))];

      anomalies.push({
        category: 'Authentication Anomaly',
        title: `Brute Force Attack - User: ${user}`,
        severity: evts.length >= 20 ? 'critical' : 'high',
        evidence: enriched.slice(0, 10),
        context: {
          who: {
            user,
            email: enriched[0]?._enriched?.email || null,
            ips,
            device: enriched[0]?._enriched?.device || null,
            userAgent: enriched[0]?._enriched?.ua || null,
          },
          what: {
            action: 'Multiple failed authentication attempts',
            count: evts.length,
            targets,
            errorCode: enriched[0]?._enriched?.errorCode || null,
          },
          when: timeSpan,
          where: {
            source: evts[0]?.source || null,
            awsRegion: enriched[0]?._enriched?.awsRegion || null,
            accountId: enriched[0]?._enriched?.accountId || null,
          },
        },
        explanation: `User "${user}" failed authentication ${evts.length} times${timeSpan.spanMinutes !== null ? ` over ${timeSpan.spanMinutes} minutes` : ''}. This volume of failures strongly indicates an automated brute force or credential stuffing attack.`,
        whySuspicious: `Normal users rarely fail login more than 1-2 times. ${evts.length} consecutive failures from ${ips.length} IP(s) is a strong indicator of an automated attack.`,
        recommendedAction: `1. Lock the account "${user}" immediately.\n2. Force password reset.\n3. Enable MFA if not already active.\n4. Block source IPs: ${ips.slice(0, 3).join(', ')}.\n5. Review if any subsequent successful logins occurred.`,
      });
    }
  }

  for (const [ip, evts] of Object.entries(byIp)) {
    if (evts.length >= 10) {
      const enriched = evts.map(enrichEvent);
      const timeSpan = getTimeSpan(evts);
      const users = [...new Set(evts.map((e) => e.actor.user).filter(Boolean))];

      anomalies.push({
        category: 'Authentication Anomaly',
        title: `Brute Force from IP: ${ip}`,
        severity: evts.length >= 50 ? 'critical' : 'high',
        evidence: enriched.slice(0, 10),
        context: {
          who: {
            user: users.length === 1 ? users[0] : `${users.length} users targeted`,
            ips: [ip],
            device: enriched[0]?._enriched?.device || null,
            userAgent: enriched[0]?._enriched?.ua || null,
          },
          what: {
            action: 'Credential stuffing / password spray',
            count: evts.length,
            targets: users,
            errorCode: enriched[0]?._enriched?.errorCode || null,
          },
          when: timeSpan,
          where: {
            source: evts[0]?.source || null,
            awsRegion: enriched[0]?._enriched?.awsRegion || null,
          },
        },
        explanation: `IP address ${ip} attempted authentication ${evts.length} times against ${users.length} user account(s)${timeSpan.spanMinutes !== null ? ` over ${timeSpan.spanMinutes} minutes` : ''}.`,
        whySuspicious: `A single IP generating ${evts.length} failed auth attempts is a classic indicator of an automated attack tool.`,
        recommendedAction: `1. Block IP ${ip} at the firewall immediately.\n2. Check if this IP appears in threat intelligence feeds.\n3. Review if any targeted accounts were successfully compromised.\n4. Enable rate limiting on authentication endpoints.`,
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
      const enriched = evts.map(enrichEvent);
      const timeSpan = getTimeSpan(evts);
      const actions = [...new Set(evts.map((e) => e.action).filter(Boolean))];
      const targets = [...new Set(evts.map((e) => e.target).filter(Boolean))];
      const ips = [...new Set(evts.map((e) => e.actor.ip).filter(Boolean))];

      anomalies.push({
        category: 'Authorization Anomaly',
        title: `AccessDenied Burst - ${actor}`,
        severity: 'high',
        evidence: enriched.slice(0, 10),
        context: {
          who: {
            user: actor,
            email: enriched[0]?._enriched?.email || null,
            ips,
            device: enriched[0]?._enriched?.device || null,
            userAgent: enriched[0]?._enriched?.ua || null,
          },
          what: {
            action: 'Repeated access denied responses',
            count: evts.length,
            targets,
            actions,
            errorCode: 'AccessDenied',
          },
          when: timeSpan,
          where: {
            source: evts[0]?.source || null,
            awsRegion: enriched[0]?._enriched?.awsRegion || null,
            accountId: enriched[0]?._enriched?.accountId || null,
          },
        },
        explanation: `Actor "${actor}" received ${evts.length} AccessDenied responses${timeSpan.spanMinutes !== null ? ` over ${timeSpan.spanMinutes} minutes` : ''} while attempting: ${actions.slice(0, 3).join(', ')}.`,
        whySuspicious: `Repeated AccessDenied errors suggest the actor is attempting to access resources beyond their permissions. This could be reconnaissance or a compromised account probing for accessible resources.`,
        recommendedAction: `1. Review IAM permissions for "${actor}".\n2. Check if these access patterns are expected.\n3. If unexpected, treat as potential compromise.\n4. Review what resources were being targeted: ${targets.slice(0, 3).join(', ')}.`,
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
    const enriched = evts.map(enrichEvent);
    const timeSpan = getTimeSpan(evts);
    const actions = [...new Set(evts.map((e) => e.action).filter(Boolean))];
    const targets = [...new Set(evts.map((e) => e.target).filter(Boolean))];
    const ips = [...new Set(evts.map((e) => e.actor.ip).filter(Boolean))];

    anomalies.push({
      category: 'Privilege Change',
      title: `IAM Modification by: ${user}`,
      severity: evts.length >= 5 ? 'critical' : 'high',
      evidence: enriched.slice(0, 10),
      context: {
        who: {
          user,
          email: enriched[0]?._enriched?.email || null,
          ips,
          device: enriched[0]?._enriched?.device || null,
          userAgent: enriched[0]?._enriched?.ua || null,
        },
        what: {
          action: 'IAM policy/user/role modifications',
          count: evts.length,
          targets,
          actions,
        },
        when: timeSpan,
        where: {
          source: evts[0]?.source || null,
          awsRegion: enriched[0]?._enriched?.awsRegion || null,
          accountId: enriched[0]?._enriched?.accountId || null,
        },
      },
      explanation: `User "${user}" performed ${evts.length} IAM modification(s) including: ${actions.join(', ')}. IAM changes directly affect who can access what in your environment.`,
      whySuspicious: `IAM modifications outside of normal change management windows are high risk. These actions can grant attackers persistent access or create backdoor accounts.`,
      recommendedAction: `1. Immediately review all IAM changes made by "${user}".\n2. Revert any unauthorized policy changes.\n3. Check if any new users or access keys were created.\n4. Review CloudTrail for all actions by this user in the same session.\n5. Verify with the user if these changes were intentional.`,
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
      const enriched = evts.map(enrichEvent);
      const timeSpan = getTimeSpan(evts);
      const roles = [...new Set(evts.map((e) => e.target).filter(Boolean))];
      const ips = [...new Set(evts.map((e) => e.actor.ip).filter(Boolean))];

      anomalies.push({
        category: 'Privilege Change',
        title: `Role Assumption Spike - ${user}`,
        severity: 'medium',
        evidence: enriched.slice(0, 10),
        context: {
          who: {
            user,
            email: enriched[0]?._enriched?.email || null,
            ips,
            device: enriched[0]?._enriched?.device || null,
          },
          what: {
            action: 'AssumeRole',
            count: evts.length,
            targets: roles,
          },
          when: timeSpan,
          where: {
            source: evts[0]?.source || null,
            awsRegion: enriched[0]?._enriched?.awsRegion || null,
            accountId: enriched[0]?._enriched?.accountId || null,
          },
        },
        explanation: `User "${user}" assumed ${evts.length} roles${timeSpan.spanMinutes !== null ? ` over ${timeSpan.spanMinutes} minutes` : ''}. Roles assumed: ${roles.slice(0, 3).join(', ')}.`,
        whySuspicious: `While role assumption is normal in AWS, ${evts.length} assumptions in a short period is unusual. Attackers use role chaining to gain higher privileges or move between accounts.`,
        recommendedAction: `1. Verify that "${user}" has a legitimate need to assume these roles.\n2. Check what actions were performed after each role assumption.\n3. Review if any assumed roles have admin or sensitive permissions.`,
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
  const enriched = rareEvents.map(enrichEvent);
  const users = [...new Set(rareEvents.map((e) => e.actor.user).filter(Boolean))];
  const ips = [...new Set(rareEvents.map((e) => e.actor.ip).filter(Boolean))];

  return [{
    category: 'Suspicious Activity',
    title: `Rare Actions Detected (${rareActions.length} unique action types)`,
    severity: 'medium',
    evidence: enriched.slice(0, 10),
    context: {
      who: {
        user: users.length === 1 ? users[0] : `${users.length} users`,
        ips: ips.slice(0, 3),
      },
      what: {
        action: 'Rare/unusual operations',
        count: rareEvents.length,
        actions: rareActions.slice(0, 10),
      },
      when: getTimeSpan(rareEvents),
      where: {
        source: rareEvents[0]?.source || null,
      },
    },
    explanation: `${rareActions.length} action types detected that each appear in less than 1% of all events. Rare actions: ${rareActions.slice(0, 5).join(', ')}.`,
    whySuspicious: `Actions that appear very rarely stand out because they deviate from established behavioral patterns. Attackers often use unusual API calls to avoid triggering common detection rules.`,
    recommendedAction: `1. Review each rare action to determine if it was authorized.\n2. Cross-reference with change management tickets.\n3. Pay special attention to rare IAM, data access, or destructive actions.`,
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
      const userEvents = events.filter((e) => e.actor.user === user);
      const enriched = userEvents.map(enrichEvent).slice(0, 5);
      const timeSpan = getTimeSpan(userEvents);

      anomalies.push({
        category: 'Network Anomaly',
        title: `Multiple Source IPs for User: ${user}`,
        severity: 'medium',
        evidence: enriched,
        context: {
          who: {
            user,
            email: enriched[0]?._enriched?.email || null,
            ips: [...ips],
            device: enriched[0]?._enriched?.device || null,
          },
          what: {
            action: 'Access from multiple IPs',
            count: ips.size,
            targets: [],
          },
          when: timeSpan,
          where: {
            source: userEvents[0]?.source || null,
          },
        },
        explanation: `User "${user}" accessed the system from ${ips.size} different IP addresses: ${[...ips].slice(0, 5).join(', ')}.`,
        whySuspicious: `Legitimate users typically access from a small number of known IPs. ${ips.size} different source IPs may indicate account sharing or compromise.`,
        recommendedAction: `1. Verify with user "${user}" if they accessed from all these IPs.\n2. Check if any IPs are from unexpected geographic regions.\n3. Look for concurrent sessions from different IPs.`,
      });
    }
  }

  return anomalies;
}

function detectSuspiciousProcesses(events) {
  const suspiciousPatterns = [
    { pattern: /(?:base64|b64decode)/i, label: 'Base64 encoding (obfuscation)' },
    { pattern: /(?:curl|wget)\s+http/i, label: 'Remote file download' },
    { pattern: /(?:nc|netcat)\s+-/i, label: 'Netcat usage (reverse shell indicator)' },
    { pattern: /(?:\/bin\/sh|\/bin\/bash|cmd\.exe|powershell)/i, label: 'Shell execution' },
    { pattern: /(?:chmod\s+[74][74][74])/i, label: 'Making file executable' },
    { pattern: /(?:rm\s+-rf)/i, label: 'Destructive file deletion' },
    { pattern: /(?:mkfifo|mknod)/i, label: 'Named pipe creation (reverse shell)' },
  ];

  const suspicious = events.filter((e) => {
    const text = JSON.stringify(e.raw);
    return suspiciousPatterns.some((p) => p.pattern.test(text));
  });

  if (suspicious.length === 0) return [];

  const enriched = suspicious.map((e) => {
    const text = JSON.stringify(e.raw);
    const matchedPatterns = suspiciousPatterns
      .filter((p) => p.pattern.test(text))
      .map((p) => p.label);
    return { ...enrichEvent(e), _matchedPatterns: matchedPatterns };
  });

  const users = [...new Set(suspicious.map((e) => e.actor.user).filter(Boolean))];
  const ips = [...new Set(suspicious.map((e) => e.actor.ip).filter(Boolean))];
  const allPatterns = [...new Set(enriched.flatMap((e) => e._matchedPatterns || []))];

  return [{
    category: 'Suspicious Process/Command',
    title: `Suspicious Commands Detected (${suspicious.length} events)`,
    severity: 'high',
    evidence: enriched.slice(0, 10),
    context: {
      who: {
        user: users.length === 1 ? users[0] : `${users.length} users`,
        ips: ips.slice(0, 3),
        email: enriched[0]?._enriched?.email || null,
      },
      what: {
        action: 'Suspicious command execution',
        count: suspicious.length,
        actions: allPatterns,
      },
      when: getTimeSpan(suspicious),
      where: {
        source: suspicious[0]?.source || null,
      },
    },
    explanation: `${suspicious.length} events contain suspicious command patterns. Patterns detected: ${allPatterns.join(', ')}.`,
    whySuspicious: `These command patterns are strongly associated with attacker toolkits. Legitimate administrative tasks rarely require base64 encoding, netcat, or destructive rm -rf commands.`,
    recommendedAction: `1. Immediately isolate the affected system(s).\n2. Capture memory and disk image for forensics.\n3. Review all commands executed in the same session.\n4. Check for persistence mechanisms (cron jobs, startup scripts).\n5. Determine the initial access vector.`,
  }];
}

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
  if (parseInt(offHoursPct) < 20) return [];

  const users = [...new Set(offHours.map((e) => e.actor.user).filter(Boolean))];
  const ips = [...new Set(offHours.map((e) => e.actor.ip).filter(Boolean))];
  const enriched = offHours.map(enrichEvent).slice(0, 10);
  const timeSpan = getTimeSpan(offHours);

  const hourDist = {};
  offHours.forEach((e) => {
    if (e.timestamp) {
      const h = new Date(e.timestamp).getHours();
      hourDist[h] = (hourDist[h] || 0) + 1;
    }
  });

  const peakOffHourEntry = Object.entries(hourDist).sort((a, b) => b[1] - a[1])[0];
  const peakOffHour = peakOffHourEntry ? `${peakOffHourEntry[0]}:00 (${peakOffHourEntry[1]} events)` : null;

  return [{
    category: 'Suspicious Activity',
    title: `High Off-Hours Activity (${offHoursPct}% of events outside business hours)`,
    severity: parseInt(offHoursPct) > 50 ? 'high' : 'medium',
    evidence: enriched,
    context: {
      who: {
        user: users.length === 1 ? users[0] : `${users.length} users`,
        ips: ips.slice(0, 3),
      },
      what: {
        action: 'Activity outside business hours (7am-6pm)',
        count: offHours.length,
      },
      when: {
        ...timeSpan,
        peakHour: peakOffHour,
      },
      where: {
        source: offHours[0]?.source || null,
      },
    },
    explanation: `${offHours.length} events (${offHoursPct}%) occurred outside normal business hours (7am-6pm). Peak off-hours activity: ${peakOffHour || 'unknown'}. Users active: ${users.slice(0, 3).join(', ')}.`,
    whySuspicious: `Attackers often operate during off-hours to avoid detection. A high percentage of off-hours activity warrants investigation especially if it involves sensitive resources.`,
    recommendedAction: `1. Verify if any scheduled jobs or automation account for this activity.\n2. Confirm with users ${users.slice(0, 2).join(', ')} if off-hours access was intentional.\n3. Review what resources were accessed during these hours.\n4. Consider implementing off-hours access alerts.`,
  }];
}

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
  if (parseInt(weekendPct) < 15) return [];

  const users = [...new Set(weekendEvents.map((e) => e.actor.user).filter(Boolean))];
  const ips = [...new Set(weekendEvents.map((e) => e.actor.ip).filter(Boolean))];
  const enriched = weekendEvents.map(enrichEvent).slice(0, 10);

  return [{
    category: 'Suspicious Activity',
    title: `Significant Weekend Activity (${weekendEvents.length} events)`,
    severity: 'medium',
    evidence: enriched,
    context: {
      who: {
        user: users.length === 1 ? users[0] : `${users.length} users`,
        ips: ips.slice(0, 3),
      },
      what: {
        action: 'Weekend activity',
        count: weekendEvents.length,
      },
      when: getTimeSpan(weekendEvents),
      where: {
        source: weekendEvents[0]?.source || null,
      },
    },
    explanation: `${weekendEvents.length} events (${weekendPct}%) occurred on weekends. Users involved: ${users.slice(0, 3).join(', ')}.`,
    whySuspicious: `Weekend activity involving sensitive resources or privileged actions is unusual in most enterprise environments.`,
    recommendedAction: `1. Review what actions were performed over the weekend.\n2. Confirm with users if weekend work was planned.\n3. Check if weekend activity involved sensitive data or privilege changes.`,
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