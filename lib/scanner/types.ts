export type ThreatLevel = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';

export interface SourceResult {
  source: string;
  isMalicious: boolean;
  riskScore: number;
  details: Record<string, any>;
  responseTimeMs: number;
  error?: string;
}

export interface ComprehensiveScanResult {
  url: string;
  domain: string;
  overallStatus: ThreatLevel;
  finalRiskScore: number;
  sources: Record<string, SourceResult>;
  scannedAt: string;
  executionTimeMs: number;
}
