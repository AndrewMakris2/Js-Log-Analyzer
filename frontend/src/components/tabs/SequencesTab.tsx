// SequencesTab.tsx - Suspicious multi-step sequence cards

import { Sequence } from '../../types/analysis';
import { ArrowDown, AlertTriangle, AlertOctagon } from 'lucide-react';

interface Props {
  sequences: Sequence[];
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'border-red-800 bg-red-950/20',
  high: 'border-orange-800 bg-orange-950/20',
  medium: 'border-yellow-800 bg-yellow-950/20',
  low: 'border-green-800 bg-green-950/20',
};

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-950/50 text-red-300 border-red-800',
  high: 'bg-orange-950/50 text-orange-300 border-orange-800',
  medium: 'bg-yellow-950/50 text-yellow-300 border-yellow-800',
  low: 'bg-green-950/50 text-green-300 border-green-800',
};

export default function SequencesTab({ sequences }: Props) {
  if (sequences.length === 0) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="w-12 h-12 text-slate-500 mx-auto mb-3" />
        <p className="text-white font-medium">No suspicious sequences detected</p>
        <p className="text-slate-400 text-sm mt-1">No multi-step attack patterns found in this log</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {sequences.map((seq, idx) => (
        <div key={idx} className={`border rounded-xl p-5 ${SEVERITY_COLORS[seq.severity] || SEVERITY_COLORS.low}`}>
          {/* Header */}
          <div className="flex items-start gap-3 mb-4">
            <AlertOctagon className={`w-5 h-5 mt-0.5 shrink-0 ${
              seq.severity === 'critical' ? 'text-red-400' :
              seq.severity === 'high' ? 'text-orange-400' : 'text-yellow-400'
            }`} />
            <div className="flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${SEVERITY_BADGE[seq.severity]}`}>
                  {seq.severity}
                </span>
              </div>
              <h3 className="text-white font-semibold mt-1">{seq.title}</h3>
            </div>
          </div>

          {/* Steps */}
          <div className="space-y-2 mb-4">
            {seq.steps.map((step, stepIdx) => (
              <div key={stepIdx}>
                <div className="flex items-start gap-3 bg-[#0f1117]/60 rounded-lg p-3">
                  <div className="w-6 h-6 rounded-full bg-indigo-900 border border-indigo-700 flex items-center justify-center shrink-0 mt-0.5">
                    <span className="text-xs text-indigo-300 font-bold">{stepIdx + 1}</span>
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-white">{step.label}</p>
                    {step.count && step.count > 1 && (
                      <span className="text-xs text-indigo-400">×{step.count} occurrences</span>
                    )}
                    {step.event && (
                      <div className="text-xs text-slate-400 mt-1 space-x-2">
                        {step.event.timestamp && (
                          <span>{new Date(step.event.timestamp).toLocaleString()}</span>
                        )}
                        {step.event.action && <span className="text-slate-300">{step.event.action}</span>}
                        {step.event.actor.user && <span>by {step.event.actor.user}</span>}
                        {step.event.actor.ip && <span>from {step.event.actor.ip}</span>}
                      </div>
                    )}
                  </div>
                </div>
                {stepIdx < seq.steps.length - 1 && (
                  <div className="flex justify-center py-1">
                    <ArrowDown className="w-4 h-4 text-slate-600" />
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Narrative */}
          <div className="bg-[#0f1117]/60 rounded-lg p-4 border border-[#2a2d3a]">
            <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Analysis</p>
            <p className="text-sm text-slate-300 leading-relaxed">{seq.narrative}</p>
          </div>
        </div>
      ))}
    </div>
  );
}