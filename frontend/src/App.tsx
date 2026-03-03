// App.tsx - Root component
// Manages global state: upload, analysis results, filters

import { useState } from 'react';
import { AnalysisResult, FilterState } from './types/analysis';
import { analyzeFile, analyzeSample } from './api/client';
import UploadPanel from './components/UploadPanel';
import StatusBar from './components/StatusBar';
import ResultTabs from './components/ResultTabs';
import FilterBar from './components/FilterBar';

type AppState = 'idle' | 'loading' | 'done' | 'error';

export default function App() {
  const [appState, setAppState] = useState<AppState>('idle');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<FilterState>({
    user: '',
    ip: '',
    severity: '',
    eventType: '',
  });

  async function handleFileUpload(file: File) {
    setAppState('loading');
    setError(null);
    setResult(null);
    try {
      const data = await analyzeFile(file);
      setResult(data);
      setAppState('done');
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Analysis failed';
      setError(message);
      setAppState('error');
    }
  }

  async function handleSampleSelect(sample: 'cloudtrail' | 'authlog' | 'siem') {
    setAppState('loading');
    setError(null);
    setResult(null);
    try {
      const data = await analyzeSample(sample);
      setResult(data);
      setAppState('done');
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Sample analysis failed';
      setError(message);
      setAppState('error');
    }
  }

  function handleReset() {
    setAppState('idle');
    setResult(null);
    setError(null);
    setFilters({ user: '', ip: '', severity: '', eventType: '' });
  }

  const isIdle = appState === 'idle';
  const isLoading = appState === 'loading';
  const isDone = appState === 'done';
  const isError = appState === 'error';

  return (
    <div className="min-h-screen bg-[#0f1117] text-slate-100">
      {/* Header */}
      <header className="border-b border-[#2a2d3a] bg-[#1a1d27] px-6 py-4">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-indigo-600 flex items-center justify-center">
              <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                  d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <div>
              <h1 className="text-lg font-bold text-white">Security Log Summarizer</h1>
              <p className="text-xs text-slate-400">Upload logs for instant threat analysis</p>
            </div>
          </div>
          {isDone && (
            <button
              onClick={handleReset}
              className="text-sm text-slate-400 hover:text-white border border-[#2a2d3a] hover:border-indigo-500 px-4 py-2 rounded-lg transition-colors"
            >
              ← New Analysis
            </button>
          )}
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-6 space-y-6">
        {/* Upload Panel - visible when idle or error */}
        {(isIdle || isError) && (
          <UploadPanel
            onFileUpload={handleFileUpload}
            onSampleSelect={handleSampleSelect}
            isLoading={isLoading}
          />
        )}

        {/* Loading State */}
        {isLoading && (
          <div className="flex flex-col items-center justify-center py-24 gap-4">
            <div className="w-12 h-12 border-4 border-indigo-600 border-t-transparent rounded-full animate-spin" />
            <p className="text-slate-400 text-sm">Analyzing log file...</p>
            <p className="text-slate-500 text-xs">Parsing events, detecting anomalies, generating summary</p>
          </div>
        )}

        {/* Error State */}
        {isError && error && (
          <div className="bg-red-950/30 border border-red-800 rounded-xl p-4 text-red-300 text-sm">
            <strong>Error:</strong> {error}
          </div>
        )}

        {/* Results */}
        {isDone && result && (
          <>
            <StatusBar meta={result.meta} score={result.score} />
            <FilterBar filters={filters} onFilterChange={setFilters} />
            <ResultTabs result={result} filters={filters} />
          </>
        )}
      </main>
    </div>
  );
}