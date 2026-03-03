// FilterBar.tsx - Filters for user, IP, severity, event type

import { FilterState } from '../types/analysis';
import { Filter, X } from 'lucide-react';

interface Props {
  filters: FilterState;
  onFilterChange: (filters: FilterState) => void;
}

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low'];
const EVENT_TYPES = ['', 'auth', 'network', 'iam', 'process', 'unknown'];

export default function FilterBar({ filters, onFilterChange }: Props) {
  const hasActiveFilters = Object.values(filters).some((v) => v !== '');

  function update(key: keyof FilterState, value: string) {
    onFilterChange({ ...filters, [key]: value });
  }

  function clearAll() {
    onFilterChange({ user: '', ip: '', severity: '', eventType: '' });
  }

  return (
    <div className="bg-[#1a1d27] border border-[#2a2d3a] rounded-xl p-4">
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex items-center gap-2 text-slate-400 shrink-0">
          <Filter className="w-4 h-4" />
          <span className="text-sm font-medium">Filters</span>
        </div>

        {/* User filter */}
        <input
          type="text"
          placeholder="User..."
          value={filters.user}
          onChange={(e) => update('user', e.target.value)}
          className="bg-[#0f1117] border border-[#2a2d3a] rounded-lg px-3 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 w-36"
        />

        {/* IP filter */}
        <input
          type="text"
          placeholder="IP address..."
          value={filters.ip}
          onChange={(e) => update('ip', e.target.value)}
          className="bg-[#0f1117] border border-[#2a2d3a] rounded-lg px-3 py-1.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 w-36"
        />

        {/* Severity filter */}
        <select
          value={filters.severity}
          onChange={(e) => update('severity', e.target.value)}
          className="bg-[#0f1117] border border-[#2a2d3a] rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-indigo-500"
        >
          <option value="">All Severities</option>
          {SEVERITIES.filter(Boolean).map((s) => (
            <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
          ))}
        </select>

        {/* Event type filter */}
        <select
          value={filters.eventType}
          onChange={(e) => update('eventType', e.target.value)}
          className="bg-[#0f1117] border border-[#2a2d3a] rounded-lg px-3 py-1.5 text-sm text-white focus:outline-none focus:border-indigo-500"
        >
          <option value="">All Event Types</option>
          {EVENT_TYPES.filter(Boolean).map((t) => (
            <option key={t} value={t}>{t.charAt(0).toUpperCase() + t.slice(1)}</option>
          ))}
        </select>

        {/* Clear button */}
        {hasActiveFilters && (
          <button
            onClick={clearAll}
            className="flex items-center gap-1 text-xs text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-3 h-3" />
            Clear
          </button>
        )}
      </div>
    </div>
  );
}