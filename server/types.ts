export interface CheckResult {
  name: string;
  passed: boolean | 'warning' | 'skipped';
  details: string;
  scoreImpact: number;
  threatFound?: boolean;
  domainAge?: string;
  sslExpiry?: string;
  sslIssuer?: string;
  aiText?: string;
}

export interface DomainInfo {
  age: string | null;
  sslExpiry: string | null;
  sslIssuer: string | null;
}

export interface AnalysisResponse {
  url: string;
  score: number;
  riskLevel: 'SAFE' | 'MODERATE RISK' | 'HIGH RISK';
  riskColor: string;
  checks: CheckResult[];
  warnings: string[];
  positives: string[];
  aiAnalysis: string;
  domainInfo: DomainInfo;
}
