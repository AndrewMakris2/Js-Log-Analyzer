// Timeline.tsx - Rich detail vertical timeline

import { NormalizedEvent } from '../types/analysis';
import { useState } from 'react';
import { ChevronDown, ChevronRight, User, Monitor, Zap, Target, AlertCircle } from 'lucide-react';

interface Props {
  events: NormalizedEvent[];
}

const SEVERITY_DOT: Record<string, string> = {
  critical: 'bg-red-500 ring-2 ring-red-500/30',
  high: 'bg-orange-500 ring-2 ring-orange-500/30',
  medium: 'bg-yellow-500 ring-2 ring-yellow-500/30',
  low: 'bg-green-500',
  unknown: 'bg-slate-500',
};

const SEVERITY_LEFT_BORDER: Record<string, string> = {
  critical: 'border-l-red-700',
  high: 'border-l-orange-700',
  medium: 'border-l-yellow-700',
  low: 'border-l-green-700',
  unknown: 'border-l-slate-700',
};

const STATUS_BADGE: Record<string, string> = {
  success: 'text-green-300 bg-green-950/40 border-green-800/50',
  failure: 'text-red-300 bg-red-950/40 border-red-800/50',
  unknown: 'text-slate-300 bg-slate-800 border-slate-600',
};

const EVENT_TYPE_COLOR: Record<string, string> = {
  auth: 'text-blue-400 bg-blue-950/30',
  network: 'text-cyan-400 bg-cyan-950/30',
  iam: 'text-purple-400 bg-purple-950/30',
  process: 'text-orange-400 bg-orange-950/30',
  unknown: 'text-slate-400 bg-slate-800',
};

function parseUserAgent(ua: string | null): string | null {
  if (!ua) return null;
  if (/mobile|android|iphone|ipad/i.test(ua)) return '📱 Mobile';
  if (/windows/i.test(ua)) return '🖥️ Windows';
  if (/macintosh|mac os/i.test(ua)) return '🍎 Mac';
  if (/linux/i.test(ua)) return '🐧 Linux';
  if (/curl|python|java|go-http|boto/i.test(ua)) return '🤖 Script/Bot';
  return '❓ Unknown Device';
}

function extractEmail(raw: any): string | null {
  const str = JSON.stringify(raw || '');
  const match = str.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
  return match ? match[0] : null;
}

function extractAwsRegion(raw: any): string | null {
  return raw?.awsRegion || raw?.aws_region || null;
}

function extractErrorCode(raw: any): string | null {
  return raw?.errorCode || raw?.error_code || null;
}

function EventRow({ event }: { event: NormalizedEvent }) {
  const [expanded, setExpanded] = useState(false);
  const severity = event.severityHint || 'unknown';
  const email = extractEmail(event.raw);
  const device = parseUserAgent(event.actor.userAgent);
  const awsRegion = extractAwsRegion(event.raw);
  const errorCode = extractErrorCode(event.raw);

  return (
    <div
      className={`border-l-2 pl-4 py-3 hover:bg-[#1e2130] transition-colors cursor-pointer rounded-r-lg ${SEVERITY_LEFT_BORDER[severity]}`}
      onClick={() => setExpanded(!expanded)}
    >
      {/* Top row - time + badges */}
      <div className="flex items-center gap-2 flex-wrap mb-2">
        <div className={`w-2 h-2 rounded-full shrink-0 ${SEVERITY_DOT[severity]}`} />
        <span className="text-xs font-mono text-slate-500">
          {event.timestamp
            ? new Date(event.timestamp).toLocaleString()
            : 'Unknown time'}
        </span>
        <span className={`text-xs px-1.5 py-0.5 rounded ${EVENT_TYPE_COLOR[event.eventType]}`}>
          {event.eventType}
        </span>
        <span className={`text-xs px-1.5 py-0.5 rounded border ${STATUS_BADGE[event.status]}`}>
          {event.status}
        </span>
        {severity !== 'unknown' && severity !== 'low' && (
          <span className="text-xs text-slate-500 capitalize">{severity}</span>
        )}
        <div className="ml-auto">
          {expanded
            ? <ChevronDown className="w-3.5 h-3.5 text-slate-500" />
            : <ChevronRight className="w-3.5 h-3.5 text-slate-500" />
          }
        </div>
      </div>

      {/* Main info row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-1">
        {/* Action */}
        {event.action && (
          <div className="flex items-center gap-2 text-xs">
            <Zap className="w-3 h-3 text-slate-500 shrink-0" />
            <span className="text-white font-medium truncate">{event.action}</span>
          </div>
        )}

        {/* User + Email */}
        {(event.actor.user || email) && (
          <div className="flex items-center gap-2 text-xs">
            <User className="w-3 h-3 text-slate-500 shrink-0" />
            <span className="text-slate-300 truncate">
              {event.actor.user || 'unknown'}
              {email && <span className="text-slate-500"> ({email})</span>}
            </span>
          </div>
        )}

        {/* IP */}
        {event.actor.ip && (
          <div className="flex items-center gap-2 text-xs">
            <Monitor className="w-3 h-3 text-slate-500 shrink-0" />
            <span className="text-slate-300 font-mono">{event.actor.ip}</span>
            {device && <span className="text-slate-500">{device}</span>}
          </div>
        )}

        {/* Target */}
        {event.target && (
          <div className="flex items-center gap-2 text-xs">
            <Target className="w-3 h-3 text-slate-500 shrink-0" />
            <span className="text-slate-400 truncate">{event.target}</span>
          </div>
        )}
      </div>

      {/* Error code inline */}
      {errorCode && (
        <div className="flex items-center gap-2 mt-1.5">
          <AlertCircle className="w-3 h-3 text-red-400 shrink-0" />
          <span className="text-xs text-red-400 font-mono">{errorCode}</span>
        </div>
      )}

      {/* Expanded detail */}
      {expanded && (
        <div className="mt-3 bg-[#0f1117] rounded-lg border border-[#2a2d3a] p-3 space-y-1.5">
          <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
            {[
              { label: 'Source', value: event.source },
              { label: 'Event Type', value: event.eventType },
              { label: 'Status', value: event.status },
              { label: 'Severity', value: event.severityHint || 'unknown' },
              { label: 'User', value: event.actor.user },
              { label: 'Email', value: email },
              { label: 'IP Address', value: event.actor.ip },
              { label: 'Device', value: device },
              { label: 'Action', value: event.action },
              { label: 'Target', value: event.target },
              { label: 'AWS Region', value: awsRegion },
              { label: 'Error Code', value: errorCode },
              {
                label: 'User Agent',
                value: event.actor.userAgent
                  ? event.actor.userAgent.slice(0, 60) + (event.actor.userAgent.length > 60 ? '...' : '')
                  : null
              },
            ].filter((r) => r.value).map((row, idx) => (
              <div key={idx} className="text-xs">
                <span className="text-slate-500">{row.label}: </span>
                <span className="text-slate-300 font-mono break-all">{row.value}</span>
              </div>
            ))}
          </div>

          {/* Raw log line for plaintext */}
          {event.source === 'plaintext' && event.raw?.line && (
            <div className="mt-2 pt-2 border-t border-[#2a2d3a]">
              <p className="text-xs text-slate-500 mb-1">Raw Log Line:</p>
              <p className="text-xs text-slate-400 font-mono break-all">{event.raw.line}</p>
            </div>
          )}

          {/* Raw JSON for cloudtrail/siem */}
          {event.source !== 'plaintext' && (
            <div className="mt-2 pt-2 border-t border-[#2a2d3a]">
              <p className="text-xs text-slate-500 mb-1">Raw Event:</p>
              <pre className="text-xs text-slate-400 overflow-x-auto max-h-32">
                {JSON.stringify(event.raw, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function groupByHour(events: NormalizedEvent[]) {
  const groups: Record<string, NormalizedEvent[]> = {};
  for (const event of events) {
    let key = 'Unknown Time';
    if (event.timestamp) {
      try {
        const d = new Date(event.timestamp);
        key = `${d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' })} · ${d.getHours().toString().padStart(2, '0')}:00`;
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
    <div className="space-y-3">
      <p className="text-xs text-slate-500">
        Click any event to expand full details · {events.length} events shown
      </p>
      {Object.entries(groups).map(([hour, hourEvents]) => {
        const criticalCount = hourEvents.filter((e) => e.severityHint === 'critical').length;
        const highCount = hourEvents.filter((e) => e.severityHint === 'high').length;
        const failureCount = hourEvents.filter((e) => e.status === 'failure').length;

        return (
          <div key={hour} className="border border-[#2a2d3a] rounded-xl overflow-hidden">
            {/* Group header */}
            <button
              onClick={() => toggle(hour)}
              className="w-full flex items-center gap-3 px-4 py-3 bg-[#1a1d27] hover:bg-[#2a2d3a] transition-colors"
            >
              {collapsed[hour]
                ? <ChevronRight className="w-4 h-4 text-slate-400 shrink-0" />
                : <ChevronDown className="w-4 h-4 text-slate-400 shrink-0" />
              }
              <span className="text-sm font-medium text-white">{hour}</span>
              <span className="text-xs bg-indigo-900/50 text-indigo-300 px-2 py-0.5 rounded-full">
                {hourEvents.length} events
              </span>
              {criticalCount > 0 && (
                <span className="text-xs bg-red-950/50 text-red-300 border border-red-800 px-2 py-0.5 rounded-full">
                  {criticalCount} critical
                </span>
              )}
              {highCount > 0 && (
                <span className="text-xs bg-orange-950/50 text-orange-300 border border-orange-800 px-2 py-0.5 rounded-full">
                  {highCount} high
                </span>
              )}
              {failureCount > 0 && (
                <span className="text-xs text-red-400 ml-auto">
                  {failureCount} failures
                </span>
              )}
            </button>

            {/* Events */}
            {!collapsed[hour] && (
              <div className="px-4 py-2 space-y-1 bg-[#0f1117]">
                {hourEvents.map((event, idx) => (
                  <EventRow key={idx} event={event} />
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}