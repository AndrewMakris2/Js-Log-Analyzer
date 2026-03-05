// BaselineTab.tsx - Shows normal behavior profile built from the log data

import { BaselineSummary } from '../../types/analysis';
import { Clock, Users, Activity, TrendingUp, Calendar, Shield } from 'lucide-react';

interface Props {
  baseline: BaselineSummary | null;
}

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const HOURS = Array.from({ length: 24 }, (_, i) => i);

export default function BaselineTab({ baseline }: Props) {
  if (!baseline) {
    return (
      <div className="text-center py-12">
        <Shield className="w-12 h-12 text-slate-500 mx-auto mb-3" />
        <p className="text-white font-medium">No baseline data available</p>
        <p className="text-slate-400 text-sm mt-1">Upload a log file to generate a baseline profile</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Overview stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {[
          { label: 'Total Events', value: baseline.totalEvents.toLocaleString(), icon: <Activity className="w-4 h-4 text-indigo-400" /> },
          { label: 'Unique Users', value: baseline.uniqueUsers, icon: <Users className="w-4 h-4 text-indigo-400" /> },
          { label: 'Avg Events/Hour', value: baseline.avgHourlyVolume, icon: <TrendingUp className="w-4 h-4 text-indigo-400" /> },
          { label: 'Normal Failure Rate', value: baseline.normalFailureRate, icon: <Shield className="w-4 h-4 text-indigo-400" /> },
        ].map((stat) => (
          <div key={stat.label} className="bg-[#1a1d27] border border-[#2a2d3a] rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              {stat.icon}
              <p className="text-xs text-slate-400">{stat.label}</p>
            </div>
            <p className="text-xl font-bold text-white">{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Activity heatmap by hour */}
      <div className="bg-[#1a1d27] border border-[#2a2d3a] rounded-xl p-6">
        <div className="flex items-center gap-2 mb-4">
          <Clock className="w-4 h-4 text-indigo-400" />
          <h3 className="text-sm font-semibold text-white">Activity by Hour of Day</h3>
          <span className="text-xs text-slate-500 ml-auto">Normal hours highlighted</span>
        </div>
        <div className="flex gap-1 flex-wrap">
          {HOURS.map((hour) => {
            const isNormal = baseline.normalHours.includes(hour);
            const isMostActive = baseline.mostActiveHours.includes(`${hour}:00`);
            return (
              <div key={hour} className="flex flex-col items-center gap-1">
                <div className={`w-8 h-8 rounded flex items-center justify-center text-xs font-medium transition-colors ${
                  isMostActive ? 'bg-indigo-600 text-white' :
                  isNormal ? 'bg-indigo-900/50 text-indigo-300' :
                  'bg-[#2a2d3a] text-slate-500'
                }`}>
                  {hour}
                </div>
              </div>
            );
          })}
        </div>
        <div className="flex items-center gap-4 mt-3 text-xs text-slate-400">
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded bg-indigo-600" />
            <span>Most active</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded bg-indigo-900/50" />
            <span>Normal hours</span>
          </div>
          <div className="flex items-center gap-1">
            <div className="w-3 h-3 rounded bg-[#2a2d3a]" />
            <span>Low activity</span>
          </div>
        </div>
      </div>

      {/* Normal behavior summary */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Most active day + hours */}
        <div className="bg-[#1a1d27] border border-[#2a2d3a] rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Calendar className="w-4 h-4 text-indigo-400" />
            <h3 className="text-sm font-semibold text-white">Activity Patterns</h3>
          </div>
          <div className="space-y-3">
            <div className="flex justify-between items-center">
              <span className="text-xs text-slate-400">Most Active Day</span>
              <span className="text-sm text-white font-medium">{baseline.mostActiveDay}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-xs text-slate-400">Peak Hours</span>
              <span className="text-sm text-white font-medium">{baseline.mostActiveHours.join(', ')}</span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-xs text-slate-400">Normal Hours Range</span>
              <span className="text-sm text-white font-medium">
                {baseline.normalHours.length > 0
                  ? `${Math.min(...baseline.normalHours)}:00 - ${Math.max(...baseline.normalHours)}:00`
                  : 'N/A'}
              </span>
            </div>
            <div className="flex justify-between items-center">
              <span className="text-xs text-slate-400">Avg Volume/Hour</span>
              <span className="text-sm text-white font-medium">{baseline.avgHourlyVolume} events</span>
            </div>
          </div>
        </div>

        {/* Top normal actions */}
        <div className="bg-[#1a1d27] border border-[#2a2d3a] rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-4 h-4 text-indigo-400" />
            <h3 className="text-sm font-semibold text-white">Top Normal Actions</h3>
          </div>
          <div className="space-y-2">
            {baseline.topActions.slice(0, 6).map((item, idx) => (
              <div key={idx} className="flex items-center justify-between">
                <span className="text-xs text-slate-300 truncate max-w-[70%]">{item.action}</span>
                <span className="text-xs font-mono text-slate-400">{item.count.toLocaleString()}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* User profiles */}
      {Object.keys(baseline.userProfiles).length > 0 && (
        <div className="bg-[#1a1d27] border border-[#2a2d3a] rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Users className="w-4 h-4 text-indigo-400" />
            <h3 className="text-sm font-semibold text-white">User Behavior Profiles</h3>
            <span className="text-xs text-slate-500 ml-auto">{Object.keys(baseline.userProfiles).length} users profiled</span>
          </div>
          <div className="space-y-3">
            {Object.entries(baseline.userProfiles).slice(0, 10).map(([user, profile]) => (
              <div key={user} className="bg-[#0f1117] rounded-lg p-3 border border-[#2a2d3a]">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium text-white">{user}</span>
                  <span className="text-xs text-slate-400">{profile.totalEvents} events</span>
                </div>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-slate-500">Known IPs: </span>
                    <span className="text-slate-300">{profile.ips.slice(0, 2).join(', ') || 'none'}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Failure rate: </span>
                    <span className={profile.failureRate > 0.3 ? 'text-red-400' : 'text-green-400'}>
                      {(profile.failureRate * 100).toFixed(0)}%
                    </span>
                  </div>
                  <div className="col-span-2">
                    <span className="text-slate-500">Normal actions: </span>
                    <span className="text-slate-300">{profile.normalActions.slice(0, 3).join(', ') || 'none'}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}