// ResultTabs.tsx - Updated with Baseline tab

import { useState } from 'react';
import { AnalysisResult, FilterState, NormalizedEvent } from '../types/analysis';
import SummaryTab from './tabs/SummaryTab';
import AnomaliesTab from './tabs/AnomaliesTab';
import SequencesTab from './tabs/SequencesTab';
import IndicatorsTab from './tabs/IndicatorsTab';
import RawEventsTab from './tabs/RawEventsTab';
import BaselineTab from './tabs/BaselineTab';
import Timeline from './Timeline';

interface Props {
  result: AnalysisResult;
  filters: FilterState;
}

const TABS = [
  { id: 'summary', label: 'Summary' },
  { id: 'anomalies', label: 'Anomalies' },
  { id: 'sequences', label: 'Sequences' },
  { id: 'indicators', label: 'Indicators' },
  { id: 'baseline', label: 'Baseline' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'raw', label: 'Raw Events' },
];

function applyFilters(events: NormalizedEvent[], filters: FilterState): NormalizedEvent[] {
  return events.filter((e) => {
    if (filters.user && !e.actor.user?.toLowerCase().includes(filters.user.toLowerCase())) return false;
    if (filters.ip && !e.actor.ip?.includes(filters.ip)) return false;
    if (filters.severity && e.severityHint !== filters.severity) return false;
    if (filters.eventType && e.eventType !== filters.eventType) return false;
    return true;
  });
}

export default function ResultTabs({ result, filters }: Props) {
  const [activeTab, setActiveTab] = useState('summary');
  const filteredEvents = applyFilters(result.events, filters);

  return (
    <div className="space-y-4">
      {/* Tab bar */}
      <div className="flex gap-1 border-b border-[#2a2d3a] overflow-x-auto">
        {TABS.map((tab) => {
          let badge: number | null = null;
          if (tab.id === 'anomalies') badge = result.anomalies.length;
          if (tab.id === 'sequences') badge = result.sequences.length;

          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`
                flex items-center gap-2 px-4 py-3 text-sm font-medium border-b-2 transition-colors whitespace-nowrap
                ${activeTab === tab.id
                  ? 'border-indigo-500 text-indigo-400'
                  : 'border-transparent text-slate-400 hover:text-white'
                }
              `}
            >
              {tab.label}
              {badge !== null && badge > 0 && (
                <span className={`text-xs px-1.5 py-0.5 rounded-full ${
                  activeTab === tab.id ? 'bg-indigo-900 text-indigo-300' : 'bg-[#2a2d3a] text-slate-400'
                }`}>
                  {badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Tab content */}
      <div>
        {activeTab === 'summary' && <SummaryTab summary={result.summary} score={result.score} />}
        {activeTab === 'anomalies' && <AnomaliesTab anomalies={result.anomalies} />}
        {activeTab === 'sequences' && <SequencesTab sequences={result.sequences} />}
        {activeTab === 'indicators' && <IndicatorsTab indicators={result.indicators} />}
        {activeTab === 'baseline' && <BaselineTab baseline={result.baseline} />}
        {activeTab === 'timeline' && <Timeline events={filteredEvents} />}
        {activeTab === 'raw' && <RawEventsTab events={filteredEvents} totalEvents={result.totalEvents} />}
      </div>
    </div>
  );
}