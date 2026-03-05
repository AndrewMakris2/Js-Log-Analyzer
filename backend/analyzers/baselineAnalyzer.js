// baselineAnalyzer.js - Builds a baseline of normal behavior from log data
// Then detects deviations from that baseline

/**
 * Builds a baseline profile from normalized events
 * @param {Array} events - all normalized events
 * @returns {Object} - baseline profile
 */
export function buildBaseline(events) {
  if (!events || events.length === 0) return null;

  // Hour distribution - which hours are normally active
  const hourCounts = new Array(24).fill(0);
  const dayOfWeekCounts = new Array(7).fill(0);

  // Per user normal behavior
  const userProfiles = {};

  // Per IP normal behavior
  const ipProfiles = {};

  // Action frequency
  const actionCounts = {};

  // Volume per hour
  const volumePerHour = {};

  for (const event of events) {
    // Time analysis
    if (event.timestamp) {
      try {
        const d = new Date(event.timestamp);
        const hour = d.getHours();
        const day = d.getDay();
        const hourKey = `${d.toDateString()}-${hour}`;

        hourCounts[hour]++;
        dayOfWeekCounts[day]++;
        volumePerHour[hourKey] = (volumePerHour[hourKey] || 0) + 1;
      } catch (e) {}
    }

    // User profiling
    const user = event.actor.user;
    if (user) {
      if (!userProfiles[user]) {
        userProfiles[user] = {
          actions: {},
          ips: new Set(),
          hours: new Array(24).fill(0),
          successCount: 0,
          failureCount: 0,
          totalEvents: 0,
          firstSeen: event.timestamp,
          lastSeen: event.timestamp,
        };
      }
      const profile = userProfiles[user];
      profile.totalEvents++;
      if (event.action) {
        profile.actions[event.action] = (profile.actions[event.action] || 0) + 1;
      }
      if (event.actor.ip) profile.ips.add(event.actor.ip);
      if (event.status === 'success') profile.successCount++;
      if (event.status === 'failure') profile.failureCount++;
      if (event.timestamp) {
        try {
          profile.hours[new Date(event.timestamp).getHours()]++;
          if (new Date(event.timestamp) > new Date(profile.lastSeen)) {
            profile.lastSeen = event.timestamp;
          }
        } catch (e) {}
      }
    }

    // IP profiling
    const ip = event.actor.ip;
    if (ip) {
      if (!ipProfiles[ip]) {
        ipProfiles[ip] = {
          users: new Set(),
          actions: {},
          totalEvents: 0,
          failureCount: 0,
        };
      }
      ipProfiles[ip].totalEvents++;
      if (user) ipProfiles[ip].users.add(user);
      if (event.action) {
        ipProfiles[ip].actions[event.action] =
          (ipProfiles[ip].actions[event.action] || 0) + 1;
      }
      if (event.status === 'failure') ipProfiles[ip].failureCount++;
    }

    // Action counts
    if (event.action) {
      actionCounts[event.action] = (actionCounts[event.action] || 0) + 1;
    }
  }

  // Calculate normal hours (top 50% of activity)
  const maxHourCount = Math.max(...hourCounts);
  const normalHours = hourCounts
    .map((count, hour) => ({ hour, count }))
    .filter((h) => h.count >= maxHourCount * 0.1)
    .map((h) => h.hour);

  // Calculate average volume per hour
  const hourlyVolumes = Object.values(volumePerHour);
  const avgHourlyVolume =
    hourlyVolumes.length > 0
      ? hourlyVolumes.reduce((a, b) => a + b, 0) / hourlyVolumes.length
      : 0;
  const maxHourlyVolume = Math.max(...hourlyVolumes, 0);

  // Overall failure rate
  const totalFailures = events.filter((e) => e.status === 'failure').length;
  const normalFailureRate = totalFailures / events.length;

  // Serialize Sets to Arrays for JSON
  const serializedUserProfiles = {};
  for (const [user, profile] of Object.entries(userProfiles)) {
    serializedUserProfiles[user] = {
      ...profile,
      ips: [...profile.ips],
      normalActions: Object.entries(profile.actions)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([action]) => action),
      failureRate:
        profile.totalEvents > 0
          ? profile.failureCount / profile.totalEvents
          : 0,
      normalHours: profile.hours
        .map((count, hour) => ({ hour, count }))
        .filter((h) => h.count > 0)
        .map((h) => h.hour),
    };
  }

  const serializedIpProfiles = {};
  for (const [ip, profile] of Object.entries(ipProfiles)) {
    serializedIpProfiles[ip] = {
      ...profile,
      users: [...profile.users],
      failureRate:
        profile.totalEvents > 0
          ? profile.failureCount / profile.totalEvents
          : 0,
    };
  }

  return {
    totalEvents: events.length,
    normalHours,
    hourCounts,
    dayOfWeekCounts,
    avgHourlyVolume,
    maxHourlyVolume,
    normalFailureRate,
    userProfiles: serializedUserProfiles,
    ipProfiles: serializedIpProfiles,
    actionCounts,
    topActions: Object.entries(actionCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 20)
      .map(([action, count]) => ({ action, count })),
    uniqueUsers: Object.keys(userProfiles).length,
    uniqueIPs: Object.keys(ipProfiles).length,
  };
}

/**
 * Detects deviations from the baseline
 * @param {Array} events - normalized events
 * @param {Object} baseline - baseline profile
 * @returns {Array} - baseline anomalies
 */
export function detectBaselineDeviations(events, baseline) {
  if (!baseline || !events || events.length === 0) return [];

  const anomalies = [];

  // 1. Off-hours activity detection
  const offHoursEvents = events.filter((e) => {
    if (!e.timestamp) return false;
    try {
      const hour = new Date(e.timestamp).getHours();
      return !baseline.normalHours.includes(hour);
    } catch {
      return false;
    }
  });

  if (offHoursEvents.length > 0 && baseline.normalHours.length > 0) {
    const offHoursUsers = [...new Set(offHoursEvents.map((e) => e.actor.user).filter(Boolean))];
    anomalies.push({
      category: 'Baseline Deviation',
      title: `Off-Hours Activity Detected (${offHoursEvents.length} events)`,
      severity: offHoursEvents.length > 50 ? 'high' : 'medium',
      evidence: offHoursEvents.slice(0, 10),
      explanation: `${offHoursEvents.length} events occurred outside normal active hours. Normal hours are ${baseline.normalHours.slice(0, 5).join(', ')}:00. Affected users: ${offHoursUsers.slice(0, 3).join(', ') || 'unknown'}.`,
    });
  }

  // 2. Volume spike detection
  const volumePerHour = {};
  for (const event of events) {
    if (!event.timestamp) continue;
    try {
      const d = new Date(event.timestamp);
      const key = `${d.toDateString()}-${d.getHours()}`;
      volumePerHour[key] = (volumePerHour[key] || 0) + 1;
    } catch {}
  }

  const spikeThreshold = baseline.avgHourlyVolume * 3;
  for (const [hourKey, count] of Object.entries(volumePerHour)) {
    if (count > spikeThreshold && baseline.avgHourlyVolume > 0) {
      anomalies.push({
        category: 'Baseline Deviation',
        title: `Volume Spike: ${count} events in 1 hour (${hourKey})`,
        severity: 'high',
        evidence: events.slice(0, 5),
        explanation: `${count} events in one hour vs normal average of ${Math.round(baseline.avgHourlyVolume)}. This is ${Math.round(count / baseline.avgHourlyVolume)}x above normal volume.`,
      });
      break; // Only report first spike to avoid noise
    }
  }

  // 3. User doing unusual actions
  for (const [user, profile] of Object.entries(baseline.userProfiles)) {
    const userEvents = events.filter((e) => e.actor.user === user);
    const unusualActions = userEvents.filter(
      (e) => e.action && !profile.normalActions.includes(e.action)
    );

    if (unusualActions.length > 0 && profile.normalActions.length > 0) {
      const uniqueUnusual = [...new Set(unusualActions.map((e) => e.action))];
      anomalies.push({
        category: 'Baseline Deviation',
        title: `Unusual Actions by ${user} (${uniqueUnusual.length} new action types)`,
        severity: 'medium',
        evidence: unusualActions.slice(0, 5),
        explanation: `User "${user}" performed ${uniqueUnusual.length} action(s) not seen in their normal behavior profile: ${uniqueUnusual.slice(0, 3).join(', ')}.`,
      });
    }
  }

  // 4. New IP for known user
  for (const [user, profile] of Object.entries(baseline.userProfiles)) {
    const userEvents = events.filter((e) => e.actor.user === user);
    const newIPEvents = userEvents.filter(
      (e) => e.actor.ip && !profile.ips.includes(e.actor.ip)
    );

    if (newIPEvents.length > 0 && profile.ips.length > 0) {
      const newIPs = [...new Set(newIPEvents.map((e) => e.actor.ip))];
      anomalies.push({
        category: 'Baseline Deviation',
        title: `New IP for Known User: ${user}`,
        severity: 'medium',
        evidence: newIPEvents.slice(0, 5),
        explanation: `User "${user}" accessed from ${newIPs.length} new IP(s) not in their normal profile: ${newIPs.slice(0, 3).join(', ')}. Known IPs: ${profile.ips.slice(0, 3).join(', ')}.`,
      });
    }
  }

  // 5. Failure rate spike per user
  for (const [user, profile] of Object.entries(baseline.userProfiles)) {
    const userEvents = events.filter((e) => e.actor.user === user);
    if (userEvents.length < 5) continue;

    const currentFailureRate =
      userEvents.filter((e) => e.status === 'failure').length / userEvents.length;

    if (
      currentFailureRate > 0.5 &&
      currentFailureRate > profile.failureRate * 2 &&
      profile.failureRate < 0.3
    ) {
      anomalies.push({
        category: 'Baseline Deviation',
        title: `Failure Rate Spike for ${user}`,
        severity: 'high',
        evidence: userEvents.filter((e) => e.status === 'failure').slice(0, 5),
        explanation: `User "${user}" has a ${(currentFailureRate * 100).toFixed(0)}% failure rate vs their normal ${(profile.failureRate * 100).toFixed(0)}%. This sudden spike may indicate credential stuffing or account compromise.`,
      });
    }
  }

  // 6. First time seen user
  const knownUsers = new Set(Object.keys(baseline.userProfiles));
  const allUsers = [...new Set(events.map((e) => e.actor.user).filter(Boolean))];
  const newUsers = allUsers.filter((u) => !knownUsers.has(u));

  if (newUsers.length > 0) {
    const newUserEvents = events.filter((e) => newUsers.includes(e.actor.user));
    anomalies.push({
      category: 'Baseline Deviation',
      title: `New Users Detected (${newUsers.length})`,
      severity: newUsers.length > 5 ? 'high' : 'medium',
      evidence: newUserEvents.slice(0, 5),
      explanation: `${newUsers.length} user(s) appeared that were not seen before: ${newUsers.slice(0, 5).join(', ')}.`,
    });
  }

  console.log(`Detected ${anomalies.length} baseline deviations`);
  return anomalies;
}

/**
 * Generates a human readable baseline summary
 * @param {Object} baseline
 * @returns {Object}
 */
export function summarizeBaseline(baseline) {
  if (!baseline) return null;

  const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const mostActiveDay = baseline.dayOfWeekCounts.indexOf(
    Math.max(...baseline.dayOfWeekCounts)
  );

  const mostActiveHours = baseline.hourCounts
    .map((count, hour) => ({ hour, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 3)
    .map((h) => `${h.hour}:00`);

  return {
    totalEvents: baseline.totalEvents,
    uniqueUsers: baseline.uniqueUsers,
    uniqueIPs: baseline.uniqueIPs,
    normalHours: baseline.normalHours,
    mostActiveDay: DAYS[mostActiveDay],
    mostActiveHours,
    avgHourlyVolume: Math.round(baseline.avgHourlyVolume),
    normalFailureRate: (baseline.normalFailureRate * 100).toFixed(1) + '%',
    topActions: baseline.topActions.slice(0, 5),
    userCount: Object.keys(baseline.userProfiles).length,
    userProfiles: baseline.userProfiles,
  };
}