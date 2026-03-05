import React from 'react';
import { Score } from '../../types/analysis';
import { CheckCircle, AlertTriangle, AlertOctagon, Info } from 'lucide-react';

interface Props {
  summary: { narrative: string; keyFindings: string[] };
  score: Score;
}

const SCORE_RING_COLOR = (val: number) => {
  if (val >= 75) return '#ef4444';
  if (val >= 50) return '#f97316';
  if (val >= 25) return '#eab308';
  return '#22c55e';
};

const SCORE_LABEL_COLOR = (val: number) => {
  if (val >= 75) return 'text-red-400';
  if (val >= 50) return 'text-orange-400';
  if (val >= 25) return 'text-yellow-400';
  return 'text-green-400';
};

function FindingIcon({ text }: { text: string }) {
  const lower = text.toLowerCase();
  if (lower.includes('critical') || lower.includes('high')) return <AlertOctagon className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />;
  if (lower.includes('anomal') || lower.includes('suspicious') || lower.includes('deviation')) return <AlertTriangle className="w-4 h-4 text-yellow-400 shrink-0 mt-0.5" />;
  if (lower.includes('no ') || lower.includes('normal')) return <CheckCircle className="w-4 h-4 text-green-400 shrink-0 mt-0.5" />;
  return <Info className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />;
}

export default function SummaryTab({ summary, score }: Props) {
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference - (score.value / 100) * circumference;

  return (
    <div className="space-y-6">
      {/* Top row: narrative + score gauge */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Narrative */}
        <div className="md:col-span-2 bg-[#1a1d27] border border-[#2a2d3a] rounded-xl p-6">
          <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-3">
            Executive Summary
          </h2>
          <p className="text-slate-200 leading-relaxed text-sm">{summary.narrative}</p>
        </div>

        {/* Score Gauge */}
        <div className="bg-[#1a1d27] border border-[#2a2d3a] rounded-xl p-6 flex flex-col items-center justify-center">
          <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">
            Severity Score
          </h2>
          <div className="relative">
            <svg width="140" height="140" className="-rotate-90">
              <circle cx="70" cy="70" r={radius} fill="none" stroke="#2a2d3a" strokeWidth="10" />
              <circle
                cx="70" cy="70" r={radius}
                fill="none"
                stroke={SCORE_RING_COLOR(score.value)}
                strokeWidth="10"
                strokeDasharray={circumference}
                strokeDashoffset={dashOffset}
                strokeLinecap="round"
                style={{ transition: 'stroke-dashoffset 1s ease' }}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className={`text-3xl font-bold ${SCORE_LABEL_COLOR(score.value)}`}>
                {score.value}
              </span>
              <span className="text-xs text-slate-400">/ 100</span>
            </div>
          </div>
          <p className={`text-lg font-semibold mt-2 ${SCORE_LABEL_COLOR(score.value)}`}>
            {score.label}
          </p>
        </div>
      </div>

      {/* Key Findings */}
      <div className="bg-[#1a1d27] border border-[#2a2d3a] rounded-xl p-6">
        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">
          Key Findings
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {summary.keyFindings.map((finding, idx) => (
            <div key={idx} className="flex items-start gap-3 bg-[#0f1117] rounded-lg p-3 border border-[#2a2d3a]">
              <FindingIcon text={finding} />
              <p className="text-sm text-slate-300">{finding}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Score Reasons */}
      {score.reasons.length > 0 && (
        <div className="bg-[#1a1d27] border border-[#2a2d3a] rounded-xl p-6">
          <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">
            Score Breakdown
          </h2>
          <div className="space-y-2">
            {score.reasons.map((reason, idx) => (
              <div key={idx} className="flex items-center gap-3 text-sm">
                <div className="w-1.5 h-1.5 rounded-full bg-indigo-500 shrink-0" />
                <span className="text-slate-300">{reason}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}