// UploadPanel.tsx - File upload zone + sample selector

import { useCallback, useState } from 'react';
import { Upload, ChevronDown } from 'lucide-react';

interface Props {
  onFileUpload: (file: File) => void;
  onSampleSelect: (sample: 'cloudtrail' | 'authlog' | 'siem') => void;
  isLoading: boolean;
}

const SAMPLES = [
  { id: 'cloudtrail' as const, label: 'AWS CloudTrail Sample', desc: 'IAM + S3 events with suspicious activity' },
  { id: 'authlog' as const, label: 'Linux Auth Log Sample', desc: 'SSH brute force + privilege escalation' },
  { id: 'siem' as const, label: 'SIEM CSV Export Sample', desc: 'Mixed security events in CSV format' },
];

export default function UploadPanel({ onFileUpload, onSampleSelect, isLoading }: Props) {
  const [isDragging, setIsDragging] = useState(false);
  const [showSamples, setShowSamples] = useState(false);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) onFileUpload(file);
    },
    [onFileUpload]
  );

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) onFileUpload(file);
  };

  return (
    <div className="space-y-4">
      {/* Drop Zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={`
          relative border-2 border-dashed rounded-xl p-12 text-center transition-all duration-200
          ${isDragging
            ? 'border-indigo-500 bg-indigo-950/30'
            : 'border-[#2a2d3a] bg-[#1a1d27] hover:border-indigo-700 hover:bg-[#1e2130]'
          }
        `}
      >
        <input
          type="file"
          accept=".log,.txt,.json,.csv"
          onChange={handleFileInput}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          disabled={isLoading}
        />
        <div className="flex flex-col items-center gap-3 pointer-events-none">
          <div className={`w-14 h-14 rounded-full flex items-center justify-center transition-colors ${
            isDragging ? 'bg-indigo-600' : 'bg-[#2a2d3a]'
          }`}>
            <Upload className={`w-6 h-6 ${isDragging ? 'text-white' : 'text-slate-400'}`} />
          </div>
          <div>
            <p className="text-white font-medium">Drop your log file here</p>
            <p className="text-slate-400 text-sm mt-1">or click to browse</p>
          </div>
          <div className="flex gap-2 mt-2">
            {['.log', '.txt', '.json', '.csv'].map((ext) => (
              <span key={ext} className="text-xs bg-[#2a2d3a] text-slate-400 px-2 py-1 rounded">
                {ext}
              </span>
            ))}
          </div>
          <p className="text-slate-500 text-xs">Max 50MB · CloudTrail JSON, SIEM CSV, plaintext logs</p>
        </div>
      </div>

      {/* Sample Logs */}
      <div className="relative">
        <button
          onClick={() => setShowSamples(!showSamples)}
          className="flex items-center gap-2 text-sm text-slate-400 hover:text-white border border-[#2a2d3a] hover:border-indigo-500 px-4 py-2 rounded-lg transition-colors"
        >
          Try a sample log
          <ChevronDown className={`w-4 h-4 transition-transform ${showSamples ? 'rotate-180' : ''}`} />
        </button>

        {showSamples && (
          <div className="absolute top-full left-0 mt-2 w-80 bg-[#1a1d27] border border-[#2a2d3a] rounded-xl shadow-xl z-10 overflow-hidden">
            {SAMPLES.map((sample) => (
              <button
                key={sample.id}
                onClick={() => { onSampleSelect(sample.id); setShowSamples(false); }}
                className="w-full text-left px-4 py-3 hover:bg-[#2a2d3a] transition-colors border-b border-[#2a2d3a] last:border-0"
              >
                <p className="text-sm text-white font-medium">{sample.label}</p>
                <p className="text-xs text-slate-400 mt-0.5">{sample.desc}</p>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}