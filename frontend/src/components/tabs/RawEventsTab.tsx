// RawEventsTab.tsx - Searchable paginated table of raw events

import { useState } from 'react';
import { NormalizedEvent } from '../../types/analysis';
import { ChevronLeft, ChevronRight, ChevronDown, ChevronRight as ChevronR } from 'lucide-react';

interface Props {
  events: NormalizedEvent[];
  totalEvents: number;
}

const PAGE_SIZE = 50;

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

const EVENT_TYPE_COLOR: Record<string, string> = {
  auth: 'text-blue-400 bg-blue-950/30',
  network: 'text-cyan-400 bg-cyan-950/30',
  iam: 'text-purple-400 bg-purple-950/30',
  process: 'text-orange-400 bg-orange-950/30',
  unknown: 'text-slate-400 bg-slate-800',
};

export default function RawEventsTab({ events, totalEvents }: Props) {
  const [page, setPage] = useState(0);
  const [expandedRow, setExpandedRow] = useState<number | null>(null);
  const [search, setSearch] = useState('');

  const filtered = search
    ? events.filter((e) =>
        JSON.stringify(e).toLowerCase().includes(search.toLowerCase())
      )
    : events;

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const pageEvents = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <p className="text-sm text-slate-400">
          Showing {filtered.length.toLocaleString()} of {totalEvents.toLocaleString()} total events
          {totalEvents > 200 && ' (first 200 loaded)'}
        </p>
        <input
          type="text"
          placeholder="Search events..."
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(0); }}
          className="bg-[#0f1117] border border-[#2a2d3a] rounded-lg px-3 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 w-64"
        />
      </div>

      {/* Table */}
      <div className="bg-[#1a1d27] border border-[#2a2d3a] rounded-xl overflow-hidden">
        {/* Table header */}
        <div className="grid grid-cols-12 gap-2 px-4 py-3 bg-[#0f1117] border-b border-[#2a2d3a] text-xs font-medium text-slate-400 uppercase tracking-wider">
          <div className="col-span-1">Sev</div>
          <div className="col-span-2">Timestamp</div>
          <div className="col-span-1">Type</div>
          <div className="col-span-2">Actor</div>
          <div className="col-span-2">Action</div>
          <div className="col-span-2">Target</div>
          <div className="col-span-1">Status</div>
          <div className="col-span-1"></div>
        </div>

        {/* Rows */}
        <div className="divide-y divide-[#2a2d3a]">
          {pageEvents.map((event, idx) => {
            const globalIdx = page * PAGE_SIZE + idx;
            const isExpanded = expandedRow === globalIdx;

            return (
              <div key={idx}>
                <div
                  className="grid grid-cols-12 gap-2 px-4 py-3 text-xs hover:bg-[#1e2130] cursor-pointer transition-colors"
                  onClick={() => setExpandedRow(isExpanded ? null : globalIdx)}
                >
                  <div className="col-span-1 flex items-center">
                    <div className={`w-2 h-2 rounded-full ${SEVERITY_DOT[event.severityHint || 'unknown']}`} />
                  </div>
                  <div className="col-span-2 text-slate-400 truncate">
                    {event.timestamp
                      ? new Date(event.timestamp).toLocaleString()
                      : '—'}
                  </div>
                  <div className="col-span-1">
                    <span className={`px-1.5 py-0.5 rounded text-xs ${EVENT_TYPE_COLOR[event.eventType]}`}>
                      {event.eventType}
                    </span>
                  </div>
                  <div className="col-span-2 text-slate-300 truncate">
                    {event.actor.user || event.actor.ip || '—'}
                  </div>
                  <div className="col-span-2 text-white truncate">{event.action || '—'}</div>
                  <div className="col-span-2 text-slate-400 truncate">{event.target || '—'}</div>
                  <div className={`col-span-1 font-medium ${STATUS_COLOR[event.status]}`}>
                    {event.status}
                  </div>
                  <div className="col-span-1 flex justify-end">
                    {isExpanded
                      ? <ChevronDown className="w-3 h-3 text-slate-400" />
                      : <ChevronR className="w-3 h-3 text-slate-400" />
                    }
                  </div>
                </div>

                {/* Expanded raw view */}
                {isExpanded && (
                  <div className="px-4 pb-4 bg-[#0f1117]">
                    <pre className="text-xs text-slate-300 bg-[#0a0c12] border border-[#2a2d3a] rounded-lg p-3 overflow-x-auto max-h-48">
                      {JSON.stringify(event.raw, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-[#2a2d3a] bg-[#0f1117]">
            <p className="text-xs text-slate-400">
              Page {page + 1} of {totalPages}
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage(Math.max(0, page - 1))}
                disabled={page === 0}
                className="p-1 rounded hover:bg-[#2a2d3a] disabled:opacity-30 transition-colors"
              >
                <ChevronLeft className="w-4 h-4 text-slate-400" />
              </button>
              <button
                onClick={() => setPage(Math.min(totalPages - 1, page + 1))}
                disabled={page >= totalPages - 1}
                className="p-1 rounded hover:bg-[#2a2d3a] disabled:opacity-30 transition-colors"
              >
                <ChevronRight className="w-4 h-4 text-slate-400" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}