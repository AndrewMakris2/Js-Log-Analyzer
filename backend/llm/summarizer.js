// summarizer.js - LLM abstraction layer
// Fixed: uses real event count from indicators not hardcoded 100

export async function summarizeWithLLM({
  normalizedEvents,
  anomalies,
  sequences,
  indicators,
  score,
  baseline,
  totalEvents,
  mode = 'full',
}) {
  const apiKey = process.env.OPENAI_API_KEY;

  if (!apiKey) {
    console.log('No OPENAI_API_KEY set - using mock LLM response');
    return getMockResponse({ normalizedEvents, anomalies, sequences, indicators, score, baseline, totalEvents });
  }

  return getMockResponse({ normalizedEvents, anomalies, sequences, indicators, score, baseline, totalEvents });
}

function getMockResponse({ anomalies, sequences, indicators, score, baseline, totalEvents }) {
  // Use real total from indicators or passed totalEvents - NOT hardcoded 100
  const eventCount = totalEvents || indicators?.summary?.totalEvents || 0;
  const topUser = indicators?.users?.[0]?.value || 'unknown';
  const topIP = indicators?.ips?.[0]?.value || 'unknown';
  const topAction = indicators?.actions?.[0]?.value || 'unknown';
  const highAnomalies = anomalies.filter((a) => ['high', 'critical'].includes(a.severity));
  const baselineAnomalies = anomalies.filter((a) => a.category === 'Baseline Deviation');

  return {
    summary: {
      narrative: `Analysis of ${eventCount.toLocaleString()} log events revealed ${anomalies.length} anomalies and ${sequences.length} suspicious sequences. The most active entity was "${topUser}" originating from IP "${topIP}", performing "${topAction}" as the top action. ${highAnomalies.length > 0 ? `${highAnomalies.length} high/critical severity issues require immediate attention.` : 'No critical issues were detected.'} ${baselineAnomalies.length > 0 ? `${baselineAnomalies.length} baseline deviations detected indicating unusual behavior patterns.` : ''} Overall severity score is ${score?.value || 0}/100 (${score?.label || 'Unknown'}).`,
      keyFindings: [
        `${eventCount.toLocaleString()} total events analyzed across ${indicators?.summary?.uniqueIPs || 0} unique IPs and ${indicators?.summary?.uniqueUsers || 0} unique users`,
        `Failure rate: ${indicators?.summary?.failureRate || '0%'} of all events`,
        `Top actor: ${topUser} (${indicators?.users?.[0]?.count || 0} events)`,
        `Most common action: ${topAction} (${indicators?.actions?.[0]?.count || 0} occurrences)`,
        ...(highAnomalies.length > 0
          ? [`${highAnomalies.length} high/critical anomalies detected requiring investigation`]
          : ['No high severity anomalies detected']),
        ...(sequences.length > 0
          ? [`${sequences.length} suspicious multi-step sequences identified`]
          : []),
        ...(baselineAnomalies.length > 0
          ? [`${baselineAnomalies.length} baseline deviations: unusual behavior compared to normal patterns`]
          : []),
        ...(baseline
          ? [`Normal activity hours: ${baseline.normalHours?.slice(0, 4).join(':00, ')}:00`]
          : []),
      ],
    },
    enrichedAnomalies: anomalies.map((a) => ({
      ...a,
      explanation: a.explanation + (a.category === 'Baseline Deviation'
        ? ' [Baseline Analysis: This deviates from established normal behavior patterns in this log set.]'
        : ' [Analysis: This pattern matches known attack techniques. Recommended: Review associated logs and verify user identity.]'),
    })),
    enrichedSequences: sequences.map((s) => ({
      ...s,
      narrative: s.narrative + ' Recommended next steps: (1) Immediately revoke suspicious sessions, (2) Review full audit logs for affected user, (3) Check for lateral movement, (4) Notify security team.',
    })),
    confidence: 0.0,
    llmUsed: false,
  };
}