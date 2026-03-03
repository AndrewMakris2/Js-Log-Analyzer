import { AnalysisResult } from '../types/analysis';

const API_BASE = 'https://YOUR-BACKEND-URL.onrender.com/api';

export async function analyzeFile(file: File): Promise<AnalysisResult> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    body: formData,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Unknown error' }));
    throw new Error(error.message || `Server error: ${response.status}`);
  }

  return response.json();
}

export async function analyzeSample(
  sample: 'cloudtrail' | 'authlog' | 'siem'
): Promise<AnalysisResult> {
  const response = await fetch(`${API_BASE}/analyze/sample`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sample }),
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: 'Unknown error' }));
    throw new Error(error.message || `Server error: ${response.status}`);
  }

  return response.json();
}