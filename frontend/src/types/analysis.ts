export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';
export type EventType = 'auth' | 'network' | 'iam' | 'process' | 'unknown';
export type EventStatus = 'success' | 'failure' | 'unknown';
export type LogFormat = 'cloudtrail' | 'siem' | 'plaintext' | 'unknown';

export interface NormalizedEvent {
  timestamp: string | null;
  source: LogFormat;
  eventType: EventType;
  actor: {
    user: string | null;
    ip: string | null;
    userAgent: string | null;
  };
  action: string | null;
  target: string | null;
  status: EventStatus;
  severityHint: Severity | null;
  raw: any;
}

export interface Anomaly {
  category: string;
  title: string;
  severity: Severity;
  evidence: NormalizedEvent[];
  explanation: string;
}

export interface SequenceStep {
  label: string;
  event: NormalizedEvent;
  count?: number;
}

export interface Sequence {
  title: string;
  severity: Severity;
  steps: SequenceStep[];
  narrative: string;
}

export interface IndicatorItem {
  value: string;
  count: number;
}

export interface Indicators {
  ips: IndicatorItem[];
  users: IndicatorItem[];
  actions: IndicatorItem[];
  resources: IndicatorItem[];
  errorCodes: IndicatorItem[];
  userAgents: IndicatorItem[];
  summary: {
    totalEvents: number;
    uniqueIPs: number;
    uniqueUsers: number;
    uniqueActions: number;
    failureRate: string;
  };
}

export interface Score {
  value: number;
  reasons: string[];
  label: string;
}

export interface AnalysisMeta {
  filename: string;
  format: LogFormat;
  totalEvents: number;
  parseConfidence: number;
  llmUsed: boolean;
  llmConfidence: number;
  chunksProcessed: number;
}

// NEW - Baseline types
export interface UserProfile {
  totalEvents: number;
  normalActions: string[];
  ips: string[];
  failureRate: number;
  normalHours: number[];
  firstSeen: string | null;
  lastSeen: string | null;
}

export interface BaselineSummary {
  totalEvents: number;
  uniqueUsers: number;
  uniqueIPs: number;
  normalHours: number[];
  mostActiveDay: string;
  mostActiveHours: string[];
  avgHourlyVolume: number;
  normalFailureRate: string;
  topActions: { action: string; count: number }[];
  userCount: number;
  userProfiles: Record<string, UserProfile>;
}

export interface AnalysisResult {
  meta: AnalysisMeta;
  summary: {
    narrative: string;
    keyFindings: string[];
  };
  anomalies: Anomaly[];
  sequences: Sequence[];
  indicators: Indicators;
  score: Score;
  baseline: BaselineSummary | null;
  events: NormalizedEvent[];
  totalEvents: number;
}

export interface FilterState {
  user: string;
  ip: string;
  severity: string;
  eventType: string;
}