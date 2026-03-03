// sequenceDetector.js - Detects suspicious multi-step sequences
// Looks for patterns like: failed auth -> success -> privilege change

/**
 * Sorts events by timestamp
 */
function sortByTime(events) {
  return [...events].sort((a, b) => {
    if (!a.timestamp) return 1;
    if (!b.timestamp) return -1;
    return new Date(a.timestamp) - new Date(b.timestamp);
  });
}

/**
 * Detects: failed auth -> successful auth -> privilege change
 * Classic brute force then escalation pattern
 */
function detectBruteForceEscalation(events) {
  const sequences = [];
  const sorted = sortByTime(events);

  const byUser = {};
  for (const e of sorted) {
    const user = e.actor.user || e.actor.ip || 'unknown';
    if (!byUser[user]) byUser[user] = [];
    byUser[user].push(e);
  }

  for (const [user, userEvents] of Object.entries(byUser)) {
    const failures = userEvents.filter(
      (e) => e.status === 'failure' && e.eventType === 'auth'
    );
    const successes = userEvents.filter(
      (e) => e.status === 'success' && e.eventType === 'auth'
    );
    const privilegeChanges = userEvents.filter(
      (e) => e.eventType === 'iam' || (e.action || '').toLowerCase().includes('assumerole')
    );

    if (failures.length >= 3 && successes.length >= 1 && privilegeChanges.length >= 1) {
      const firstFailure = failures[0];
      const firstSuccess = successes.find(
        (s) => !firstFailure.timestamp || new Date(s.timestamp) > new Date(firstFailure.timestamp)
      );
      const firstPrivChange = privilegeChanges.find(
        (p) => !firstSuccess?.timestamp || new Date(p.timestamp) > new Date(firstSuccess.timestamp)
      );

      if (firstSuccess) {
        sequences.push({
          title: `Brute Force → Auth Success → Privilege Change: ${user}`,
          severity: 'critical',
          steps: [
            { label: 'Multiple Failed Logins', event: firstFailure, count: failures.length },
            { label: 'Successful Login', event: firstSuccess },
            ...(firstPrivChange ? [{ label: 'Privilege/Role Change', event: firstPrivChange }] : []),
          ],
          narrative: `User "${user}" had ${failures.length} failed login attempts followed by a successful authentication${firstPrivChange ? ', then immediately performed privilege/IAM changes' : ''}. This is consistent with a brute force attack leading to unauthorized access.`,
        });
      }
    }
  }

  return sequences;
}

/**
 * Detects: role assumption -> sensitive action -> potential data exfil
 */
function detectRoleAssumptionToExfil(events) {
  const sequences = [];
  const sorted = sortByTime(events);

  const roleAssumptions = sorted.filter(
    (e) => (e.action || '').toLowerCase().includes('assumerole')
  );

  for (const roleEvent of roleAssumptions) {
    const user = roleEvent.actor.user || roleEvent.actor.ip;
    if (!user) continue;

    // Find sensitive actions after role assumption by same user
    const afterRole = sorted.filter(
      (e) =>
        (e.actor.user === user || e.actor.ip === roleEvent.actor.ip) &&
        roleEvent.timestamp &&
        e.timestamp &&
        new Date(e.timestamp) > new Date(roleEvent.timestamp)
    );

    const sensitiveActions = afterRole.filter((e) => {
      const action = (e.action || '').toLowerCase();
      return (
        action.includes('getobject') ||
        action.includes('listbucket') ||
        action.includes('getparameter') ||
        action.includes('describesecret') ||
        action.includes('getсекrет') ||
        action.includes('export') ||
        action.includes('download')
      );
    });

    if (sensitiveActions.length >= 2) {
      sequences.push({
        title: `Role Assumption → Sensitive Data Access: ${user}`,
        severity: 'high',
        steps: [
          { label: 'Role Assumed', event: roleEvent },
          { label: 'Sensitive Actions', event: sensitiveActions[0], count: sensitiveActions.length },
        ],
        narrative: `User "${user}" assumed a role and then performed ${sensitiveActions.length} sensitive data access operations (${[...new Set(sensitiveActions.map((e) => e.action))].join(', ')}). This may indicate unauthorized data exfiltration.`,
      });
    }
  }

  return sequences;
}

/**
 * Detects: repeated AccessDenied -> then success
 * Suggests persistence until finding a misconfigured resource
 */
function detectDeniedThenSuccess(events) {
  const sequences = [];
  const sorted = sortByTime(events);

  const byActor = {};
  for (const e of sorted) {
    const actor = e.actor.user || e.actor.ip || 'unknown';
    if (!byActor[actor]) byActor[actor] = [];
    byActor[actor].push(e);
  }

  for (const [actor, actorEvents] of Object.entries(byActor)) {
    const denied = actorEvents.filter((e) => e.status === 'failure');
    const successes = actorEvents.filter((e) => e.status === 'success');

    if (denied.length >= 5 && successes.length >= 1) {
      const lastDenied = denied[denied.length - 1];
      const firstSuccessAfter = successes.find(
        (s) =>
          !lastDenied.timestamp ||
          !s.timestamp ||
          new Date(s.timestamp) >= new Date(lastDenied.timestamp)
      );

      if (firstSuccessAfter) {
        sequences.push({
          title: `Persistent Access Attempts → Success: ${actor}`,
          severity: 'high',
          steps: [
            { label: `${denied.length} Access Denied/Failures`, event: denied[0], count: denied.length },
            { label: 'Eventually Succeeded', event: firstSuccessAfter },
          ],
          narrative: `Actor "${actor}" received ${denied.length} failures/denials before eventually succeeding. This pattern suggests persistent enumeration until finding accessible resources.`,
        });
      }
    }
  }

  return sequences;
}

/**
 * Main sequence detection function
 * @param {Array} events - normalized events
 * @returns {Array} - suspicious sequences
 */
export function detectSequences(events) {
  if (!events || events.length === 0) return [];

  const allSequences = [
    ...detectBruteForceEscalation(events),
    ...detectRoleAssumptionToExfil(events),
    ...detectDeniedThenSuccess(events),
  ];

  console.log(`Detected ${allSequences.length} suspicious sequences`);
  return allSequences;
}