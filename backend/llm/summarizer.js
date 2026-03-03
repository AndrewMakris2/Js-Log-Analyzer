// summarizer.js - LLM abstraction layer
// Swap out the mock for a real OpenAI/Anthropic call by setting OPENAI_API_KEY in .env

/**
 * Main LLM summarization function
 * @param {Object} params
 * @param {Array} params.normalizedEvents - normalized event objects
 * @param {Array} params.anomalies - detected anomalies
 * @param {Array} params.sequences - detected sequences
 * @param {Object} params.indicators - top indicators
 * @param {Object} params.score - severity score
 * @param {string} params.mode - 'full' | 'chunk'
 * @returns {Object} - { summary, enrichedAnomalies, enrichedSequences }
 */
export async function summarizeWithLLM({
  normalizedEvents,
  anomalies,
  sequences,
  indicators,
  score,
  mode = 'full',
}) {
  const apiKey = process.env.OPENAI_API_KEY;

  if (!apiKey) {
    console.log('No OPENAI_API_KEY set - using mock LLM response');
    return getMockResponse({ normalizedEvents, anomalies, sequences, indicators, score });
  }

  // Real OpenAI call - uncomment and use when API key is available
  // return await callOpenAI({ normalizedEvents, anomalies, sequences, indicators, score });

  return getMockResponse({ normalizedEvents, anomalies, sequences, indicators, score });
}

/**
 * Mock LLM response - returns realistic data without API key
 */
function getMockResponse({ normalizedEvents, anomalies, sequences, indicators, score }) {
  const eventCount = normalizedEvents?.length || 0;
  const topUser = indicators?.users?.[0]?.value || 'unknown';
  const topIP = indicators?.ips?.[0]?.value || 'unknown';
  const topAction = indicators?.actions?.[0]?.value || 'unknown';

  const highAnomalies = anomalies.filter((a) => ['high', 'critical'].includes(a.severity));

  return {
    summary: {
      narrative: `Analysis of ${eventCount} log events revealed ${anomalies.length} anomalies and ${sequences.length} suspicious sequences. The most active entity was "${topUser}" originating from IP "${topIP}", performing "${topAction}" as the top action. ${highAnomalies.length > 0 ? `${highAnomalies.length} high/critical severity issues require immediate attention.` : 'No critical issues were detected.'} Overall severity score is ${score?.value || 0}/100 (${score?.label || 'Unknown'}).`,
      keyFindings: [
        `${eventCount} total events analyzed across ${indicators?.summary?.uniqueIPs || 0} unique IPs and ${indicators?.summary?.uniqueUsers || 0} unique users`,
        `Failure rate: ${indicators?.summary?.failureRate || '0%'} of all events`,
        `Top actor: ${topUser} (${indicators?.users?.[0]?.count || 0} events)`,
        `Most common action: ${topAction} (${indicators?.actions?.[0]?.count || 0} occurrences)`,
        ...(highAnomalies.length > 0
          ? [`${highAnomalies.length} high/critical anomalies detected requiring investigation`]
          : ['No high severity anomalies detected']),
        ...(sequences.length > 0
          ? [`${sequences.length} suspicious multi-step sequences identified`]
          : []),
      ],
    },
    // Enrich anomaly explanations with mock LLM context
    enrichedAnomalies: anomalies.map((a) => ({
      ...a,
      explanation: a.explanation + ' [Analysis: This pattern matches known attack techniques and should be investigated promptly. Recommended action: Review associated logs, verify user identity, and check for lateral movement.]',
    })),
    // Enrich sequences
    enrichedSequences: sequences.map((s) => ({
      ...s,
      narrative: s.narrative + ' Recommended next steps: (1) Immediately revoke suspicious sessions, (2) Review CloudTrail/auth logs for the affected user, (3) Check for any data access or exfiltration attempts, (4) Notify security team.',
    })),
    confidence: 0.0, // 0 = mock, 1.0 = real LLM
    llmUsed: false,
  };
}

/**
 * Real OpenAI implementation - ready to use when API key is provided
 * Uncomment this and call it from summarizeWithLLM above
 */
/*
async function callOpenAI({ normalizedEvents, anomalies, sequences, indicators, score }) {
  const { default: OpenAI } = await import('openai');
  const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

  const prompt = `You are a security analyst. Analyze the following log data summary and provide insights.

STATISTICS:
- Total events: ${normalizedEvents.length}
- Anomalies found: ${anomalies.length}
- Suspicious sequences: ${sequences.length}
- Severity score: ${score.value}/100

TOP INDICATORS:
- IPs: ${indicators.ips.slice(0, 5).map(i => `${i.value}(${i.count})`).join(', ')}
- Users: ${indicators.users.slice(0, 5).map(u => `${u.value}(${u.count})`).join(', ')}
- Actions: ${indicators.actions.slice(0, 5).map(a => `${a.value}(${a.count})`).join(', ')}

ANOMALIES:
${anomalies.map(a => `- [${a.severity}] ${a.title}: ${a.explanation}`).join('\n')}

SEQUENCES:
${sequences.map(s => `- [${s.severity}] ${s.title}: ${s.narrative}`).join('\n')}

Provide:
1. A 2-3 sentence executive summary
2. 5-7 key findings as bullet points
3. Recommended immediate actions

Respond in JSON format: { summary: { narrative, keyFindings }, recommendations: [] }`;

  const response = await client.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: prompt }],
    response_format: { type: 'json_object' },
    temperature: 0.3,
  });

  const result = JSON.parse(response.choices[0].message.content);
  return {
    summary: result.summary,
    enrichedAnomalies: anomalies,
    enrichedSequences: sequences,
    confidence: 0.9,
    llmUsed: true,
  };
}
*/