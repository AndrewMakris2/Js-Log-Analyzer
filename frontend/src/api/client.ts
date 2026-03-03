// client.ts - API call wrapper for backend communication

import { AnalysisResult } from '../types/analysis';

const API_BASE = 'http://localhost:3001/api';

/**
 * Uploads a file for analysis
 */
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

/**
 * Analyzes a built-in sample log
 */
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