// StatusBar.tsx - Shows parsing confidence, format, event count, LLM status

import { AnalysisMeta, Score } from '../types/analysis';
import { FileText, Cpu, Shield, Database } from 'lucide-react';

interface Props {
  meta: AnalysisMeta;
  score: Score;
}

const FORMAT_LABELS: Record<string, string> = {
  cloudtrail: 'AWS CloudTrail',
  siem: 'SIEM CSV',
  plaintext: 'Plaintext Log',
  unknown: 'Unknown',
};

const SCORE_COLOR = (val: number) => {
  if (val >= 75) return 'text-red-400';
  if (val >= 50) return 'text-orange-400';
  if (val >= 25) return 'text-yellow-400';
  return 'text-green-400';
};

const SCORE_BG = (val: number) => {
  if (val >= 75) return 'bg-red-950/40 border-red-800';
  if (val >= 50) return 'bg-orange-950/40 border-orange-800';
  if (val >= 25) return 'bg-yellow-950/40 border-yellow-800';
  return 'bg-green-950/40 border-green-800';
};

export default function StatusBar({ meta, score }: Props) {
  const confidencePct = Math.round(meta.parseConfidence * 100);

  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
      {/* Format + File */}
      <div className="bg-[#1a1d27] border border-[#2a2d3a] rounded-xl p-4 flex items-center gap-3">
        <FileText className="w-5 h-5 text-indigo-400 shrink-0" />
        <div className="min-w-0">
          <p className="text-xs text-slate-400">File Format</p>
          <p className="text-sm font-medium text-white truncate">{FORMAT_LABELS[meta.format] || meta.format}</p>
          <p className="text-xs text-slate-500 truncate">{meta.filename}</p>
        </div>
      </div>

      {/* Event Count */}
      <div className="bg-[#1a1d27] border border-[#2a2d3a] rounded-xl p-4 flex items-center gap-3">
        <Database className="w-5 h-5 text-indigo-400 shrink-0" />
        <div>
          <p className="text-xs text-slate-400">Events Parsed</p>
          <p className="text-sm font-medium text-white">{meta.totalEvents.toLocaleString()}</p>
          <p className="text-xs text-slate-500">{meta.chunksProcessed} chunk(s)</p>
        </div>
      </div>

      {/* Parse Confidence */}
      <div className="bg-[#1a1d27] border border-[#2a2d3a] rounded-xl p-4 flex items-center gap-3">
        <Cpu className="w-5 h-5 text-indigo-400 shrink-0" />
        <div className="flex-1 min-w-0">
          <p className="text-xs text-slate-400">Parse Confidence</p>
          <p className="text-sm font-medium text-white">{confidencePct}%</p>
          <div className="w-full bg-[#2a2d3a] rounded-full h-1.5 mt-1">
            <div
              className="h-1.5 rounded-full bg-indigo-500 transition-all"
              style={{ width: `${confidencePct}%` }}
            />
          </div>
        </div>
      </div>

      {/* Severity Score */}
      <div className={`border rounded-xl p-4 flex items-center gap-3 ${SCORE_BG(score.value)}`}>
        <Shield className={`w-5 h-5 shrink-0 ${SCORE_COLOR(score.value)}`} />
        <div>
          <p className="text-xs text-slate-400">Severity Score</p>
          <p className={`text-sm font-bold ${SCORE_COLOR(score.value)}`}>
            {score.value}/100 · {score.label}
          </p>
          <p className="text-xs text-slate-500">
            {meta.llmUsed ? '🤖 LLM Enhanced' : '⚙️ Rule-based'}
          </p>
        </div>
      </div>
    </div>
  );
}