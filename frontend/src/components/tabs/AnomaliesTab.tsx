// AnomaliesTab.tsx - Grouped anomaly cards with expandable evidence

import React, { useState } from 'react';
import { Anomaly } from '../../types/analysis';
import { ChevronDown, ChevronRight, AlertTriangle, AlertOctagon, Info, Shield } from 'lucide-react';

interface Props {
  anomalies: Anomaly[];
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-950/50 text-red-300 border-red-800',
  high: 'bg-orange-950/50 text-orange-300 border-orange-800',
  medium: 'bg-yellow-950/50 text-yellow-300 border-yellow-800',
  low: 'bg-green-950/50 text-green-300 border-green-800',
  unknown: 'bg-slate-800 text-slate-300 border-slate-600',
};

const SEVERITY_ICON: Record<string, React.ReactElement> = {
  critical: <AlertOctagon className="w-4 h-4 text-red-400" />,
  high: <AlertTriangle className="w-4 h-4 text-orange-400" />,
  medium: <AlertTriangle className="w-4 h-4 text-yellow-400" />,
  low: <Info className="w-4 h-4 text-green-400" />,
  unknown: <Shield className="w-4 h-4 text-slate-400" />,
};

function AnomalyCard({ anomaly }: { anomaly: Anomaly }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="bg-[#1a1d27] border border-[#2a2d3a] rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-start gap-4 p-4 hover:bg-[#1e2130] transition-colors text-left"
      >
        <div className="mt-0.5">{SEVERITY_ICON[anomaly.severity] || SEVERITY_ICON.unknown}</div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${SEVERITY_BADGE[anomaly.severity]}`}>
              {anomaly.severity}
            </span>
            <span className="text-xs text-slate-500">{anomaly.category}</span>
          </div>
          <p className="text-sm font-medium text-white mt-1">{anomaly.title}</p>
          <p className="text-xs text-slate-400 mt-1 line-clamp-2">{anomaly.explanation}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className="text-xs text-slate-500">{anomaly.evidence.length} events</span>
          {expanded
            ? <ChevronDown className="w-4 h-4 text-slate-400" />
            : <ChevronRight className="w-4 h-4 text-slate-400" />
          }
        </div>
      </button>

      {/* Evidence list */}
      {expanded && anomaly.evidence.length > 0 && (
        <div className="border-t border-[#2a2d3a] divide-y divide-[#2a2d3a]">
          <div className="px-4 py-2 bg-[#0f1117]">
            <p className="text-xs text-slate-400 font-medium">Evidence Events</p>
          </div>
          {anomaly.evidence.slice(0, 5).map((event, idx) => (
            <div key={idx} className="px-4 py-3 text-xs space-y-1 hover:bg-[#1e2130]">
              <div className="flex items-center gap-3 flex-wrap">
                <span className="text-slate-500">
                  {event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Unknown time'}
                </span>
                <span className={`font-medium ${event.status === 'failure' ? 'text-red-400' : 'text-green-400'}`}>
                  {event.status}
                </span>
                <span className="text-indigo-400">{event.eventType}</span>
              </div>
              <p className="text-slate-300">
                <span className="text-white">{event.action || 'Unknown action'}</span>
                {event.actor.user && <span className="text-slate-400"> · user: {event.actor.user}</span>}
                {event.actor.ip && <span className="text-slate-500"> · ip: {event.actor.ip}</span>}
              </p>
              {event.target && <p className="text-slate-500">→ {event.target}</p>}
            </div>
          ))}
          {anomaly.evidence.length > 5 && (
            <div className="px-4 py-2 text-xs text-slate-500">
              + {anomaly.evidence.length - 5} more events
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function AnomaliesTab({ anomalies }: Props) {
  if (anomalies.length === 0) {
    return (
      <div className="text-center py-12">
        <Shield className="w-12 h-12 text-green-500 mx-auto mb-3" />
        <p className="text-white font-medium">No anomalies detected</p>
        <p className="text-slate-400 text-sm mt-1">The log file appears clean based on rule-based analysis</p>
      </div>
    );
  }

  // Group by category
  const grouped = anomalies.reduce((acc, a) => {
    if (!acc[a.category]) acc[a.category] = [];
    acc[a.category].push(a);
    return acc;
  }, {} as Record<string, Anomaly[]>);

  return (
    <div className="space-y-6">
      {Object.entries(grouped).map(([category, items]) => (
        <div key={category}>
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
            {category} ({items.length})
          </h3>
          <div className="space-y-3">
            {items.map((anomaly, idx) => (
              <AnomalyCard key={idx} anomaly={anomaly} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}