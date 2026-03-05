// AnomaliesTab.tsx - Rich detail anomaly cards

import React, { useState } from 'react';
import { Anomaly } from '../../types/analysis';
import {
  ChevronDown, ChevronRight, AlertTriangle, AlertOctagon,
  Info, Shield, User, Monitor, Clock, MapPin,
  Activity, AlertCircle, CheckCircle, Zap
} from 'lucide-react';

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

const SEVERITY_BORDER: Record<string, string> = {
  critical: 'border-red-900/50',
  high: 'border-orange-900/50',
  medium: 'border-yellow-900/50',
  low: 'border-green-900/50',
  unknown: 'border-slate-700',
};

const SEVERITY_ICON: Record<string, React.ReactElement> = {
  critical: <AlertOctagon className="w-5 h-5 text-red-400" />,
  high: <AlertTriangle className="w-5 h-5 text-orange-400" />,
  medium: <AlertTriangle className="w-5 h-5 text-yellow-400" />,
  low: <Info className="w-5 h-5 text-green-400" />,
  unknown: <Shield className="w-5 h-5 text-slate-400" />,
};

function DetailRow({ label, value, mono = false }: { label: string; value: string | null | undefined; mono?: boolean }) {
  if (!value) return null;
  return (
    <div className="flex items-start gap-2">
      <span className="text-xs text-slate-500 w-24 shrink-0 mt-0.5">{label}</span>
      <span className={`text-xs ${mono ? 'font-mono' : ''} text-slate-300 break-all`}>{value}</span>
    </div>
  );
}

function AnomalyCard({ anomaly }: { anomaly: Anomaly & { context?: any; whySuspicious?: string; recommendedAction?: string } }) {
  const [expanded, setExpanded] = useState(false);
  const [showRaw, setShowRaw] = useState(false);
  const ctx = anomaly.context;

  return (
    <div className={`bg-[#1a1d27] border rounded-xl overflow-hidden ${SEVERITY_BORDER[anomaly.severity] || 'border-[#2a2d3a]'}`}>
      {/* Header - always visible */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-start gap-4 p-4 hover:bg-[#1e2130] transition-colors text-left"
      >
        <div className="mt-0.5 shrink-0">{SEVERITY_ICON[anomaly.severity] || SEVERITY_ICON.unknown}</div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${SEVERITY_BADGE[anomaly.severity]}`}>
              {anomaly.severity.toUpperCase()}
            </span>
            <span className="text-xs text-slate-500 bg-[#2a2d3a] px-2 py-0.5 rounded">{anomaly.category}</span>
            {ctx?.what?.count && (
              <span className="text-xs text-slate-500">{ctx.what.count} events</span>
            )}
          </div>
          <p className="text-sm font-semibold text-white">{anomaly.title}</p>
          <p className="text-xs text-slate-400 mt-1 line-clamp-2">{anomaly.explanation}</p>
        </div>
        <div className="shrink-0 mt-1">
          {expanded
            ? <ChevronDown className="w-4 h-4 text-slate-400" />
            : <ChevronRight className="w-4 h-4 text-slate-400" />
          }
        </div>
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div className="border-t border-[#2a2d3a]">

          {/* Context grid - WHO WHAT WHEN WHERE */}
          {ctx && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-0 border-b border-[#2a2d3a]">

              {/* WHO */}
              <div className="p-4 border-b md:border-b-0 md:border-r border-[#2a2d3a]">
                <div className="flex items-center gap-2 mb-3">
                  <User className="w-3.5 h-3.5 text-indigo-400" />
                  <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Who</span>
                </div>
                <div className="space-y-1.5">
                  <DetailRow label="User" value={ctx.who?.user} />
                  <DetailRow label="Email" value={ctx.who?.email} />
                  <DetailRow label="IP(s)" value={ctx.who?.ips?.join(', ')} mono />
                  <DetailRow label="Device" value={ctx.who?.device} />
                  <DetailRow label="User Agent" value={ctx.who?.userAgent} />
                </div>
              </div>

              {/* WHAT */}
              <div className="p-4 border-b border-[#2a2d3a]">
                <div className="flex items-center gap-2 mb-3">
                  <Activity className="w-3.5 h-3.5 text-indigo-400" />
                  <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">What</span>
                </div>
                <div className="space-y-1.5">
                  <DetailRow label="Action" value={ctx.what?.action} />
                  <DetailRow label="Count" value={ctx.what?.count?.toString()} />
                  <DetailRow label="Error Code" value={ctx.what?.errorCode} mono />
                  <DetailRow label="Operations" value={ctx.what?.actions?.slice(0, 3).join(', ')} />
                  <DetailRow label="Targets" value={ctx.what?.targets?.slice(0, 2).join(', ')} />
                </div>
              </div>

              {/* WHEN */}
              <div className="p-4 border-b md:border-b-0 md:border-r border-[#2a2d3a]">
                <div className="flex items-center gap-2 mb-3">
                  <Clock className="w-3.5 h-3.5 text-indigo-400" />
                  <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">When</span>
                </div>
                <div className="space-y-1.5">
                  <DetailRow
                    label="First Seen"
                    value={ctx.when?.first ? new Date(ctx.when.first).toLocaleString() : null}
                  />
                  <DetailRow
                    label="Last Seen"
                    value={ctx.when?.last ? new Date(ctx.when.last).toLocaleString() : null}
                  />
                  <DetailRow
                    label="Duration"
                    value={ctx.when?.spanMinutes !== null && ctx.when?.spanMinutes !== undefined
                      ? `${ctx.when.spanMinutes} minutes`
                      : null}
                  />
                  <DetailRow label="Peak Hour" value={(ctx.when as any)?.peakHour} />
                </div>
              </div>

              {/* WHERE */}
              <div className="p-4">
                <div className="flex items-center gap-2 mb-3">
                  <MapPin className="w-3.5 h-3.5 text-indigo-400" />
                  <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Where</span>
                </div>
                <div className="space-y-1.5">
                  <DetailRow label="Log Source" value={ctx.where?.source} />
                  <DetailRow label="AWS Region" value={ctx.where?.awsRegion} mono />
                  <DetailRow label="Account ID" value={ctx.where?.accountId} mono />
                </div>
              </div>
            </div>
          )}

          {/* Why Suspicious */}
          {anomaly.whySuspicious && (
            <div className="p-4 border-b border-[#2a2d3a] bg-yellow-950/10">
              <div className="flex items-center gap-2 mb-2">
                <AlertCircle className="w-3.5 h-3.5 text-yellow-400" />
                <span className="text-xs font-semibold text-yellow-400 uppercase tracking-wider">Why This Is Suspicious</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">{anomaly.whySuspicious}</p>
            </div>
          )}

          {/* Recommended Action */}
          {anomaly.recommendedAction && (
            <div className="p-4 border-b border-[#2a2d3a] bg-indigo-950/10">
              <div className="flex items-center gap-2 mb-2">
                <CheckCircle className="w-3.5 h-3.5 text-indigo-400" />
                <span className="text-xs font-semibold text-indigo-400 uppercase tracking-wider">Recommended Actions</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-line">{anomaly.recommendedAction}</p>
            </div>
          )}

          {/* Evidence Events */}
          {anomaly.evidence.length > 0 && (
            <div>
              <div className="px-4 py-2 bg-[#0f1117] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Zap className="w-3.5 h-3.5 text-slate-400" />
                  <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Evidence ({anomaly.evidence.length} events)
                  </span>
                </div>
                <button
                  onClick={(e) => { e.stopPropagation(); setShowRaw(!showRaw); }}
                  className="text-xs text-slate-500 hover:text-white transition-colors"
                >
                  {showRaw ? 'Hide Raw' : 'Show Raw'}
                </button>
              </div>

              <div className="divide-y divide-[#2a2d3a]">
                {anomaly.evidence.slice(0, 5).map((event: any, idx: number) => (
                  <div key={idx} className="px-4 py-3 hover:bg-[#1e2130] transition-colors">
                    {/* Event header row */}
                    <div className="flex items-center gap-3 flex-wrap mb-1.5">
                      <span className="text-xs text-slate-500 font-mono">
                        {event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Unknown time'}
                      </span>
                      <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${
                        event.status === 'failure'
                          ? 'text-red-300 bg-red-950/40'
                          : event.status === 'success'
                          ? 'text-green-300 bg-green-950/40'
                          : 'text-slate-300 bg-slate-800'
                      }`}>
                        {event.status}
                      </span>
                      <span className="text-xs text-indigo-400 bg-indigo-950/30 px-1.5 py-0.5 rounded">
                        {event.eventType}
                      </span>
                      {event.severityHint && (
                        <span className={`text-xs px-1.5 py-0.5 rounded border ${SEVERITY_BADGE[event.severityHint]}`}>
                          {event.severityHint}
                        </span>
                      )}
                    </div>

                    {/* Event detail rows */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-0.5">
                      {event.action && (
                        <div className="flex gap-2 text-xs">
                          <span className="text-slate-500 w-16 shrink-0">Action</span>
                          <span className="text-white font-medium truncate">{event.action}</span>
                        </div>
                      )}
                      {event.actor?.user && (
                        <div className="flex gap-2 text-xs">
                          <span className="text-slate-500 w-16 shrink-0">User</span>
                          <span className="text-slate-300">{event.actor.user}</span>
                        </div>
                      )}
                      {event._enriched?.email && (
                        <div className="flex gap-2 text-xs">
                          <span className="text-slate-500 w-16 shrink-0">Email</span>
                          <span className="text-slate-300">{event._enriched.email}</span>
                        </div>
                      )}
                      {event.actor?.ip && (
                        <div className="flex gap-2 text-xs">
                          <span className="text-slate-500 w-16 shrink-0">IP</span>
                          <span className="text-slate-300 font-mono">{event.actor.ip}</span>
                        </div>
                      )}
                      {event._enriched?.device && (
                        <div className="flex gap-2 text-xs">
                          <span className="text-slate-500 w-16 shrink-0">Device</span>
                          <span className="text-slate-300">{event._enriched.device}</span>
                        </div>
                      )}
                      {event.target && (
                        <div className="flex gap-2 text-xs">
                          <span className="text-slate-500 w-16 shrink-0">Target</span>
                          <span className="text-slate-300 truncate">{event.target}</span>
                        </div>
                      )}
                      {event._enriched?.awsRegion && (
                        <div className="flex gap-2 text-xs">
                          <span className="text-slate-500 w-16 shrink-0">Region</span>
                          <span className="text-slate-300 font-mono">{event._enriched.awsRegion}</span>
                        </div>
                      )}
                      {event._enriched?.errorCode && (
                        <div className="flex gap-2 text-xs">
                          <span className="text-slate-500 w-16 shrink-0">Error</span>
                          <span className="text-red-400 font-mono">{event._enriched.errorCode}</span>
                        </div>
                      )}
                    </div>

                    {/* Raw data */}
                    {showRaw && (
                      <pre className="mt-2 text-xs text-slate-400 bg-[#0a0c12] border border-[#2a2d3a] rounded p-2 overflow-x-auto max-h-32">
                        {JSON.stringify(event.raw, null, 2)}
                      </pre>
                    )}
                  </div>
                ))}
                {anomaly.evidence.length > 5 && (
                  <div className="px-4 py-2 text-xs text-slate-500 bg-[#0f1117]">
                    + {anomaly.evidence.length - 5} more events in this anomaly
                  </div>
                )}
              </div>
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

  const grouped = anomalies.reduce((acc, a) => {
    if (!acc[a.category]) acc[a.category] = [];
    acc[a.category].push(a);
    return acc;
  }, {} as Record<string, Anomaly[]>);

  const criticalCount = anomalies.filter((a) => a.severity === 'critical').length;
  const highCount = anomalies.filter((a) => a.severity === 'high').length;

  return (
    <div className="space-y-6">
      {/* Summary bar */}
      <div className="flex items-center gap-3 flex-wrap">
        <span className="text-sm text-slate-400">{anomalies.length} anomalies detected</span>
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
        <span className="text-xs text-slate-500">Click any anomaly to expand full details</span>
      </div>

      {Object.entries(grouped).map(([category, items]) => (
        <div key={category}>
          <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 flex items-center gap-2">
            <div className="w-1 h-4 bg-indigo-500 rounded" />
            {category} ({items.length})
          </h3>
          <div className="space-y-3">
            {items.map((anomaly, idx) => (
              <AnomalyCard key={idx} anomaly={anomaly as any} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}