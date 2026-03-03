// IndicatorsTab.tsx - Top indicators with counts and bar charts

import { Indicators } from '../../types/analysis';
import { Monitor, User, Zap, Database } from 'lucide-react';

interface Props {
  indicators: Indicators;
}

function IndicatorList({
  title,
  icon,
  items,
  color,
}: {
  title: string;
  icon: React.ReactNode;
  items: { value: string; count: number }[];
  color: string;
}) {
  const maxCount = items[0]?.count || 1;

  return (
    <div className="bg-[#1a1d27] border border-[#2a2d3a] rounded-xl p-5">
      <div className="flex items-center gap-2 mb-4">
        <div className={`w-7 h-7 rounded-lg flex items-center justify-center ${color}`}>
          {icon}
        </div>
        <h3 className="text-sm font-semibold text-white">{title}</h3>
        <span className="text-xs text-slate-500 ml-auto">{items.length} unique</span>
      </div>

      {items.length === 0 ? (
        <p className="text-slate-500 text-xs">No data</p>
      ) : (
        <div className="space-y-3">
          {items.slice(0, 10).map((item, idx) => (
            <div key={idx} className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-xs text-slate-300 truncate max-w-[70%]" title={item.value}>
                  {item.value || 'unknown'}
                </span>
                <span className="text-xs font-mono text-slate-400 shrink-0 ml-2">
                  {item.count.toLocaleString()}
                </span>
              </div>
              <div className="w-full bg-[#2a2d3a] rounded-full h-1.5">
                <div
                  className={`h-1.5 rounded-full transition-all duration-500 ${color.replace('bg-', 'bg-').replace('/20', '')}`}
                  style={{ width: `${(item.count / maxCount) * 100}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function IndicatorsTab({ indicators }: Props) {
  return (
    <div className="space-y-6">
      {/* Summary stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'Total Events', value: indicators.summary.totalEvents.toLocaleString() },
          { label: 'Unique IPs', value: indicators.summary.uniqueIPs },
          { label: 'Unique Users', value: indicators.summary.uniqueUsers },
          { label: 'Unique Actions', value: indicators.summary.uniqueActions },
          { label: 'Failure Rate', value: indicators.summary.failureRate },
        ].map((stat) => (
          <div key={stat.label} className="bg-[#1a1d27] border border-[#2a2d3a] rounded-xl p-4 text-center">
            <p className="text-lg font-bold text-white">{stat.value}</p>
            <p className="text-xs text-slate-400 mt-1">{stat.label}</p>
          </div>
        ))}
      </div>

      {/* Indicator lists */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <IndicatorList
          title="Top IP Addresses"
          icon={<Monitor className="w-4 h-4 text-blue-300" />}
          items={indicators.ips}
          color="bg-blue-900/20"
        />
        <IndicatorList
          title="Top Users"
          icon={<User className="w-4 h-4 text-indigo-300" />}
          items={indicators.users}
          color="bg-indigo-900/20"
        />
        <IndicatorList
          title="Top Actions"
          icon={<Zap className="w-4 h-4 text-yellow-300" />}
          items={indicators.actions}
          color="bg-yellow-900/20"
        />
        <IndicatorList
          title="Top Resources"
          icon={<Database className="w-4 h-4 text-green-300" />}
          items={indicators.resources}
          color="bg-green-900/20"
        />
      </div>

      {/* Error codes if present */}
      {indicators.errorCodes?.length > 0 && (
        <div className="bg-[#1a1d27] border border-red-900/50 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-red-400 mb-4">Error Codes</h3>
          <div className="flex flex-wrap gap-2">
            {indicators.errorCodes.map((ec, idx) => (
              <div key={idx} className="flex items-center gap-2 bg-red-950/30 border border-red-800/50 rounded-lg px-3 py-1.5">
                <span className="text-xs text-red-300 font-medium">{ec.value}</span>
                <span className="text-xs text-red-400/70">×{ec.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}