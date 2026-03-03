// scorer.js - Calculates overall severity score 0-100
// Based on anomaly count, severity levels, and event patterns

/**
 * Severity weights
 */
const SEVERITY_WEIGHTS = {
  critical: 25,
  high: 15,
  medium: 8,
  low: 2,
};

/**
 * Calculates a severity score from 0-100
 * @param {Array} anomalies
 * @param {Array} sequences
 * @param {Array} events
 * @returns {Object} - { value: number, reasons: string[] }
 */
export function calculateScore(anomalies, sequences, events) {
  let score = 0;
  const reasons = [];

  // Score from anomalies
  for (const anomaly of anomalies) {
    const weight = SEVERITY_WEIGHTS[anomaly.severity] || 2;
    score += weight;
    if (weight >= 15) {
      reasons.push(`${anomaly.severity.toUpperCase()}: ${anomaly.title}`);
    }
  }

  // Score from sequences (sequences are more serious)
  for (const sequence of sequences) {
    const weight = (SEVERITY_WEIGHTS[sequence.severity] || 2) * 1.5;
    score += weight;
    reasons.push(`SEQUENCE: ${sequence.title}`);
  }

  // Failure rate bonus
  if (events.length > 0) {
    const failureRate =
      events.filter((e) => e.status === 'failure').length / events.length;
    if (failureRate > 0.5) {
      score += 15;
      reasons.push(`High failure rate: ${(failureRate * 100).toFixed(0)}% of events are failures`);
    } else if (failureRate > 0.2) {
      score += 8;
      reasons.push(`Elevated failure rate: ${(failureRate * 100).toFixed(0)}% of events are failures`);
    }
  }

  // Cap at 100
  const finalScore = Math.min(100, Math.round(score));

  // Add summary reason if score is low
  if (reasons.length === 0) {
    reasons.push('No significant anomalies detected');
  }

  return {
    value: finalScore,
    reasons: reasons.slice(0, 8), // Top 8 reasons
    label: finalScore >= 75 ? 'Critical' :
           finalScore >= 50 ? 'High' :
           finalScore >= 25 ? 'Medium' : 'Low',
  };
}