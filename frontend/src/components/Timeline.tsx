// Timeline.tsx - Vertical timeline grouped by hour

import { NormalizedEvent } from '../types/analysis';
import { useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';

interface Props {
  events: NormalizedEvent[];
}

const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-green-500',
  unknown: 'bg-slate-500',
};

const STATUS_COLOR: Record<string, string> = {
  success: 'text-green-400',
  failure: 'text-red-400',
  unknown: 'text-slate-400',
};

function groupByHour(events: NormalizedEvent[]) {
  const groups: Record<string, NormalizedEvent[]> = {};

  for (const event of events) {
    let key = 'Unknown Time';
    if (event.timestamp) {
      try {
        const d = new Date(event.timestamp);
        key = `${d.toLocaleDateString()} ${d.getHours().toString().padStart(2, '0')}:00`;
      } catch {
        key = 'Unknown Time';
      }
    }
    if (!groups[key]) groups[key] = [];
    groups[key].push(event);
  }

  return groups;
}

export default function Timeline({ events }: Props) {
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const groups = groupByHour(events);

  function toggle(key: string) {
    setCollapsed((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  if (events.length === 0) {
    return <p className="text-slate-400 text-sm text-center py-8">No events to display</p>;
  }

  return (
    <div className="space-y-4">
      {Object.entries(groups).map(([hour, hourEvents]) => (
        <div key={hour} className="border border-[#2a2d3a] rounded-xl overflow-hidden">
          {/* Group header */}
          <button
            onClick={() => toggle(hour)}
            className="w-full flex items-center justify-between px-4 py-3 bg-[#1a1d27] hover:bg-[#2a2d3a] transition-colors"
          >
            <div className="flex items-center gap-3">
              {collapsed[hour]
                ? <ChevronRight className="w-4 h-4 text-slate-400" />
                : <ChevronDown className="w-4 h-4 text-slate-400" />
              }
              <span className="text-sm font-medium text-white">{hour}</span>
              <span className="text-xs bg-indigo-900/50 text-indigo-300 px-2 py-0.5 rounded-full">
                {hourEvents.length} events
              </span>
            </div>
          </button>

          {/* Events in group */}
          {!collapsed[hour] && (
            <div className="divide-y divide-[#2a2d3a]">
              {hourEvents.map((event, idx) => (
                <div key={idx} className="px-4 py-3 flex items-start gap-3 hover:bg-[#1e2130] transition-colors">
                  {/* Severity dot */}
                  <div className="mt-1.5 shrink-0">
                    <div className={`w-2 h-2 rounded-full ${SEVERITY_DOT[event.severityHint || 'unknown']}`} />
                  </div>

                  {/* Event details */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs text-slate-500">
                        {event.timestamp
                          ? new Date(event.timestamp).toLocaleTimeString()
                          : 'Unknown time'}
                      </span>
                      <span className="text-xs bg-[#2a2d3a] text-slate-300 px-2 py-0.5 rounded">
                        {event.eventType}
                      </span>
                      <span className={`text-xs font-medium ${STATUS_COLOR[event.status]}`}>
                        {event.status}
                      </span>
                    </div>
                    <p className="text-sm text-white mt-0.5 truncate">
                      {event.action || 'Unknown action'}
                      {event.actor.user && <span className="text-slate-400"> by {event.actor.user}</span>}
                      {event.actor.ip && <span className="text-slate-500"> from {event.actor.ip}</span>}
                    </p>
                    {event.target && (
                      <p className="text-xs text-slate-500 truncate mt-0.5">→ {event.target}</p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}