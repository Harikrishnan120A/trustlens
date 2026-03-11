// ============================================================
// Types matching the backend API response
// ============================================================
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

export interface AnalysisResult {
  url: string;
  score: number;
  riskLevel: 'SAFE' | 'MODERATE RISK' | 'HIGH RISK';
  riskColor: string;
  checks: CheckResult[];
  warnings: string[];
  positives: string[];
  aiAnalysis: string;
  domainInfo: DomainInfo;
  error?: string;
}

// ============================================================
// API Client — calls the Express backend
// ============================================================
export async function analyzeUrl(urlInput: string): Promise<AnalysisResult> {
  const trimmed = urlInput.trim();
  if (!trimmed) {
    return {
      url: trimmed,
      score: 0,
      riskLevel: 'HIGH RISK',
      riskColor: '#f85149',
      checks: [],
      warnings: ['URL cannot be empty.'],
      positives: [],
      aiAnalysis: '',
      domainInfo: { age: null, sslExpiry: null, sslIssuer: null },
      error: 'URL cannot be empty.',
    };
  }

  const resp = await fetch('/api/analyze', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: trimmed }),
  });

  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    throw new Error(data.error || `Server error (${resp.status})`);
  }

  return resp.json();
}
