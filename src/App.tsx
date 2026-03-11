/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import {
  Shield, ShieldAlert, ShieldCheck, Search, AlertTriangle, CheckCircle2,
  XCircle, ExternalLink, Info, Lock, Globe, Type, History, Copy, Heart,
  Sparkles, ArrowRight, Bot, Calendar, Fingerprint, Link2, AtSign,
  Hash, FileWarning, Server, Cpu, ShieldX, Wifi, Activity, ShieldEllipsis,
  FileSearch, UserX, Radar, ScanLine,
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { analyzeUrl, type AnalysisResult, type CheckResult } from './utils/analyzer';

const CHECK_ICONS: Record<string, React.ReactNode> = {
  'HTTPS Protocol': <Lock className="w-5 h-5" />,
  'URL Length': <Type className="w-5 h-5" />,
  'Suspicious Keywords': <FileWarning className="w-5 h-5" />,
  'Hyphen Count': <Hash className="w-5 h-5" />,
  'IP as Domain': <Server className="w-5 h-5" />,
  'Subdomain Count': <Link2 className="w-5 h-5" />,
  'Risky TLD': <Globe className="w-5 h-5" />,
  'Typosquatting Check': <AtSign className="w-5 h-5" />,
  'Punycode / Homograph': <Fingerprint className="w-5 h-5" />,
  'Google Safe Browsing': <ShieldCheck className="w-5 h-5" />,
  'VirusTotal Scan': <Radar className="w-5 h-5" />,
  'Domain Age (WHOIS)': <Calendar className="w-5 h-5" />,
  'SSL Certificate': <Lock className="w-5 h-5" />,
  'AI Risk Assessment': <Bot className="w-5 h-5" />,
  'DNS Resolution': <Wifi className="w-5 h-5" />,
  'Live Site Check': <Activity className="w-5 h-5" />,
  'Security Headers': <ShieldEllipsis className="w-5 h-5" />,
  'Page Content Analysis': <FileSearch className="w-5 h-5" />,
  'Brand Impersonation': <UserX className="w-5 h-5" />,
};

function getStatusBadge(passed: boolean | string) {
  if (passed === true) return { label: 'Passed', bg: 'bg-emerald-500/10 text-emerald-400' };
  if (passed === 'warning') return { label: 'Warning', bg: 'bg-amber-500/10 text-amber-400' };
  if (passed === 'skipped') return { label: 'Skipped', bg: 'bg-slate-500/10 text-slate-400' };
  return { label: 'Failed', bg: 'bg-rose-500/10 text-rose-400' };
}

function getImpactText(impact: number) {
  if (impact > 0) return { text: `+${impact}`, color: 'text-emerald-400' };
  if (impact < 0) return { text: `${impact}`, color: 'text-rose-400' };
  return { text: '0', color: 'text-slate-500' };
}

export default function App() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [mounted, setMounted] = useState(false);
  const [recentScans, setRecentScans] = useState<AnalysisResult[]>([]);
  const [showHistory, setShowHistory] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    setMounted(true);
    const saved = localStorage.getItem('trustlens_history');
    if (saved) {
      try { setRecentScans(JSON.parse(saved)); } catch { /* ignore */ }
    }
  }, []);

  const saveScan = (scan: AnalysisResult) => {
    const updated = [scan, ...recentScans.filter(s => s.url !== scan.url)].slice(0, 5);
    setRecentScans(updated);
    localStorage.setItem('trustlens_history', JSON.stringify(updated));
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url || isAnalyzing) return;
    setError(null);
    setResult(null);
    setIsAnalyzing(true);

    try {
      const analysisResult = await analyzeUrl(url);
      if (analysisResult.error) {
        setError(analysisResult.error);
      } else {
        setResult(analysisResult);
        saveScan(analysisResult);
      }
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred during analysis.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const copyReport = () => {
    if (!result) return;
    const lines = [
      'TrustLens Analysis Report',
      `URL: ${result.url}`,
      `Score: ${result.score}/100`,
      `Risk: ${result.riskLevel}`,
      '',
      'Checks:',
      ...result.checks.map(c => `  ${c.passed === true ? '✓' : c.passed === 'skipped' ? '⚠' : '✗'} ${c.name}: ${c.details} (${c.scoreImpact >= 0 ? '+' : ''}${c.scoreImpact})`),
    ];
    if (result.warnings.length) { lines.push('', 'Warnings:', ...result.warnings.map(w => `  • ${w}`)); }
    if (result.positives.length) { lines.push('', 'Positive Signals:', ...result.positives.map(p => `  • ${p}`)); }
    if (result.aiAnalysis) { lines.push('', 'AI Analysis:', result.aiAnalysis); }
    navigator.clipboard.writeText(lines.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getRiskColor = (level: string) => {
    if (level === 'SAFE') return 'text-emerald-500';
    if (level === 'MODERATE RISK') return 'text-amber-500';
    return 'text-rose-500';
  };
  const getRiskBg = (level: string) => {
    if (level === 'SAFE') return 'bg-emerald-500/10 border-emerald-500/20';
    if (level === 'MODERATE RISK') return 'bg-amber-500/10 border-amber-500/20';
    return 'bg-rose-500/10 border-rose-500/20';
  };

  if (!mounted) return <div className="bg-black min-h-screen" />;

  return (
    <div className="min-h-screen bg-[#0A0A0B] text-slate-200 font-sans selection:bg-indigo-500/30 overflow-x-hidden">
      {/* Background Effects */}
      <div className="fixed inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-size-[40px_40px] pointer-events-none" />
      <div className="fixed inset-0 bg-radial-at-t from-indigo-500/5 via-transparent to-transparent pointer-events-none" />

      <main className="relative max-w-5xl mx-auto px-6 py-12 md:py-20">
        {/* History Toggle */}
        <div className="flex justify-end mb-8">
          <button
            onClick={() => setShowHistory(!showHistory)}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-900/50 border border-slate-800 text-slate-400 hover:text-white hover:border-slate-700 transition-all text-sm font-medium"
          >
            <History className="w-4 h-4" />
            {showHistory ? 'Hide History' : 'Recent Scans'}
          </button>
        </div>

        {/* History Panel */}
        <AnimatePresence>
          {showHistory && (
            <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden mb-12">
              <div className="bg-slate-900/30 border border-slate-800/50 rounded-2xl p-6">
                <h3 className="text-xs font-mono text-slate-500 uppercase tracking-widest mb-4 flex items-center gap-2"><History className="w-3 h-3" /> Recent Activity</h3>
                {recentScans.length === 0 ? (
                  <p className="text-slate-600 text-sm italic">No recent scans found.</p>
                ) : (
                  <div className="space-y-3">
                    {recentScans.map((scan, i) => (
                      <button key={i} onClick={() => { setResult(scan); setUrl(scan.url); setShowHistory(false); }}
                        className="w-full flex items-center justify-between p-3 rounded-xl bg-slate-900/50 border border-slate-800/50 hover:border-indigo-500/30 hover:bg-slate-800/50 transition-all group">
                        <div className="flex items-center gap-3">
                          <div className={`w-2 h-2 rounded-full ${getRiskColor(scan.riskLevel).replace('text-', 'bg-')}`} />
                          <span className="text-sm text-slate-300 truncate max-w-50 md:max-w-md">{scan.url}</span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className={`text-xs font-bold ${getRiskColor(scan.riskLevel)}`}>{scan.score}</span>
                          <ArrowRight className="w-3 h-3 text-slate-600 group-hover:text-indigo-400 transition-colors" />
                        </div>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Header */}
        <header className="text-center mb-12">
          <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }}
            className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-500/10 border border-indigo-500/20 text-indigo-400 text-xs font-mono mb-6">
            <Shield className="w-3 h-3" /> V4.0 — 19 REAL-TIME SECURITY CHECKS
          </motion.div>
          <motion.h1 initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
            className="text-5xl md:text-6xl font-bold tracking-tight text-white mb-4">
            Trust<span className="text-indigo-500">Lens</span>
          </motion.h1>
          <motion.p initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
            className="text-slate-400 text-lg max-w-xl mx-auto">
            Professional website security analysis. WHOIS, SSL, Safe Browsing, AI-powered risk assessment — all in one real-time scan.
          </motion.p>
        </header>

        {/* Input */}
        <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} transition={{ delay: 0.3 }} className="relative group mb-12">
          <form onSubmit={handleAnalyze} className="relative">
            <input
              type="text"
              placeholder="Enter website URL (e.g., example.com)"
              value={url}
              onChange={(e) => { setUrl(e.target.value); if (error) setError(null); }}
              className={`w-full bg-slate-900/50 border ${error ? 'border-rose-500/50 focus:border-rose-500' : 'border-slate-800 focus:border-indigo-500'} rounded-2xl py-5 px-6 pl-14 text-lg focus:outline-none focus:ring-2 ${error ? 'focus:ring-rose-500/20' : 'focus:ring-indigo-500/50'} transition-all placeholder:text-slate-600`}
            />
            <Search className={`absolute left-5 top-1/2 -translate-y-1/2 ${error ? 'text-rose-500' : 'text-slate-500 group-focus-within:text-indigo-500'} transition-colors`} />
            <button type="submit" disabled={isAnalyzing || !url}
              className="absolute right-3 top-1/2 -translate-y-1/2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 disabled:text-slate-500 text-white px-6 py-2.5 rounded-xl font-medium transition-all flex items-center gap-2">
              {isAnalyzing ? <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <>Analyze <Search className="w-4 h-4" /></>}
            </button>
          </form>
          <AnimatePresence>
            {error && (
              <motion.p initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -10 }}
                className="absolute left-6 -bottom-8 text-rose-500 text-sm font-medium flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" />{error}
              </motion.p>
            )}
          </AnimatePresence>
        </motion.div>

        {/* Loading State */}
        <AnimatePresence>
          {isAnalyzing && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} className="mb-12">
              <div className="bg-slate-900/40 border border-slate-800/50 rounded-2xl p-8 text-center">
                <div className="w-12 h-12 border-3 border-indigo-500/30 border-t-indigo-500 rounded-full animate-spin mx-auto mb-4" />
                <h3 className="text-white font-semibold mb-2">Analyzing Website Security</h3>
                <p className="text-slate-400 text-sm">Running 19 real-time security checks including content analysis, brand impersonation, VirusTotal, DNS, live probe, headers, WHOIS, SSL & AI analysis...</p>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-6">
                  {['Static Checks', 'Live Probe & Content', 'WHOIS, SSL & VirusTotal', 'AI Analysis'].map((label, i) => (
                    <div key={label} className="bg-slate-800/50 rounded-xl p-3">
                      <motion.div initial={{ width: 0 }} animate={{ width: '100%' }} transition={{ duration: 2 + i * 0.5, ease: 'easeInOut' }}
                        className="h-1 bg-indigo-500/50 rounded-full mb-2" />
                      <span className="text-xs text-slate-500">{label}</span>
                    </div>
                  ))}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Results */}
        <AnimatePresence mode="wait">
          {result && !isAnalyzing && (
            <motion.div key={result.url} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -20 }} className="space-y-8">

              {/* ===== Score Card ===== */}
              <div className={`p-8 rounded-3xl border ${getRiskBg(result.riskLevel)} backdrop-blur-sm relative overflow-hidden`}>
                <div className={`absolute -right-12 -top-12 w-48 h-48 rounded-full blur-3xl opacity-20 ${getRiskColor(result.riskLevel).replace('text-', 'bg-')}`} />
                <div className="flex flex-col md:flex-row items-center justify-between gap-8 relative z-10">
                  <div className="flex items-center gap-6">
                    <div className="relative">
                      <svg className="w-28 h-28 transform -rotate-90">
                        <circle cx="56" cy="56" r="50" fill="transparent" stroke="currentColor" strokeWidth="8" className="text-slate-800" />
                        <motion.circle cx="56" cy="56" r="50" fill="transparent" stroke="currentColor" strokeWidth="8"
                          strokeDasharray={314} initial={{ strokeDashoffset: 314 }} animate={{ strokeDashoffset: 314 - (314 * result.score) / 100 }}
                          transition={{ duration: 1.5, ease: 'easeOut' }} className={getRiskColor(result.riskLevel)} strokeLinecap="round" />
                      </svg>
                      <div className="absolute inset-0 flex items-center justify-center flex-col">
                        <span className="text-3xl font-bold text-white leading-none">{result.score}</span>
                        <span className="text-[10px] font-mono text-slate-500 uppercase mt-1">Score</span>
                      </div>
                    </div>
                    <div>
                      <h2 className="text-sm font-mono text-slate-400 uppercase tracking-widest mb-1">Analysis Result</h2>
                      <div className={`text-3xl font-bold tracking-tight ${getRiskColor(result.riskLevel)} flex items-center gap-2`}>
                        {result.riskLevel}
                        {result.riskLevel === 'SAFE' && <Sparkles className="w-5 h-5" />}
                        {result.riskLevel === 'HIGH RISK' && <ShieldX className="w-5 h-5" />}
                      </div>
                      <div className="flex items-center gap-2 text-slate-400 mt-2 text-sm">
                        <Globe className="w-4 h-4" />
                        <span className="truncate max-w-50 md:max-w-xs">{result.url}</span>
                        <a href={result.url} target="_blank" rel="noopener noreferrer" className="hover:text-white transition-colors"><ExternalLink className="w-3 h-3" /></a>
                      </div>
                    </div>
                  </div>
                  <div className="flex flex-col gap-3 w-full md:w-auto">
                    <div className="flex gap-4">
                      <div className="bg-slate-900/50 p-4 rounded-2xl border border-slate-800 flex-1 md:flex-none md:w-32">
                        <div className="text-xs text-slate-500 uppercase font-mono mb-1">Checks</div>
                        <div className="font-medium text-white">{result.checks.filter(c => c.name !== 'AI Risk Assessment').length} run</div>
                      </div>
                      <div className="bg-slate-900/50 p-4 rounded-2xl border border-slate-800 flex-1 md:flex-none md:w-32">
                        <div className="text-xs text-slate-500 uppercase font-mono mb-1">Passed</div>
                        <div className="font-medium text-emerald-400">{result.checks.filter(c => c.passed === true && c.name !== 'AI Risk Assessment').length}</div>
                      </div>
                    </div>
                    <button onClick={copyReport}
                      className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-white/5 hover:bg-white/10 border border-white/10 text-white text-sm font-medium transition-all">
                      {copied ? <CheckCircle2 className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
                      {copied ? 'Report Copied!' : 'Copy Full Report'}
                    </button>
                  </div>
                </div>
              </div>

              {/* ===== Domain Info ===== */}
              {(result.domainInfo.age || result.domainInfo.sslExpiry || result.domainInfo.sslIssuer) && (
                <div className="bg-slate-900/40 border border-slate-800/50 rounded-2xl p-6">
                  <h3 className="text-xs font-mono text-slate-500 uppercase tracking-widest mb-4 flex items-center gap-2"><Info className="w-3 h-3" /> Domain Information</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    {result.domainInfo.age && (
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400"><Calendar className="w-4 h-4" /></div>
                        <div>
                          <div className="text-xs text-slate-500">Domain Age</div>
                          <div className="text-sm text-white font-medium">{result.domainInfo.age}</div>
                        </div>
                      </div>
                    )}
                    {result.domainInfo.sslIssuer && (
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400"><Lock className="w-4 h-4" /></div>
                        <div>
                          <div className="text-xs text-slate-500">SSL Issuer</div>
                          <div className="text-sm text-white font-medium">{result.domainInfo.sslIssuer}</div>
                        </div>
                      </div>
                    )}
                    {result.domainInfo.sslExpiry && (
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400"><Calendar className="w-4 h-4" /></div>
                        <div>
                          <div className="text-xs text-slate-500">SSL Expiry</div>
                          <div className="text-sm text-white font-medium">{result.domainInfo.sslExpiry}</div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* ===== Checks Breakdown Grid ===== */}
              <div>
                <h3 className="text-xs font-mono text-slate-500 uppercase tracking-widest mb-4 flex items-center gap-2"><Shield className="w-3 h-3" /> Security Checks ({result.checks.filter(c => c.name !== 'AI Risk Assessment').length})</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {result.checks.filter(c => c.name !== 'AI Risk Assessment').map((check, idx) => {
                    const status = getStatusBadge(check.passed);
                    const impact = getImpactText(check.scoreImpact);
                    return (
                      <motion.div key={check.name} initial={{ opacity: 0, x: idx % 2 === 0 ? -10 : 10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.05 * idx }}
                        className="bg-slate-900/40 border border-slate-800/50 p-5 rounded-2xl hover:border-slate-700 transition-colors group">
                        <div className="flex items-start justify-between mb-3">
                          <div className="p-2 rounded-lg bg-slate-800 text-slate-400 group-hover:text-white transition-colors">
                            {CHECK_ICONS[check.name] || <Cpu className="w-5 h-5" />}
                          </div>
                          <div className="flex items-center gap-2">
                            <span className={`text-xs font-bold font-mono ${impact.color}`}>{impact.text}</span>
                            <div className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-tighter ${status.bg}`}>{status.label}</div>
                          </div>
                        </div>
                        <h4 className="text-white font-semibold mb-1 text-sm">{check.name}</h4>
                        <p className="text-slate-400 text-sm leading-relaxed">{check.details}</p>
                        <div className="mt-3 h-1 bg-slate-800 rounded-full overflow-hidden">
                          <motion.div initial={{ width: 0 }} animate={{ width: check.passed === true ? '100%' : check.passed === 'warning' || check.passed === 'skipped' ? '50%' : '15%' }}
                            transition={{ duration: 0.8, delay: 0.05 * idx }}
                            className={`h-full ${check.passed === true ? 'bg-emerald-500' : check.passed === 'warning' || check.passed === 'skipped' ? 'bg-amber-500' : 'bg-rose-500'}`} />
                        </div>
                      </motion.div>
                    );
                  })}
                </div>
              </div>

              {/* ===== Warnings & Positives ===== */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {result.warnings.length > 0 && (
                  <div className="bg-rose-500/5 border border-rose-500/10 p-6 rounded-2xl">
                    <div className="flex items-center gap-3 mb-4">
                      <ShieldAlert className="w-5 h-5 text-rose-400" />
                      <h3 className="text-white font-semibold">Warnings ({result.warnings.length})</h3>
                    </div>
                    <ul className="space-y-2">
                      {result.warnings.map((w, i) => (
                        <li key={i} className="flex items-start gap-3 text-sm text-rose-300/80">
                          <XCircle className="w-4 h-4 text-rose-500 shrink-0 mt-0.5" />
                          {w}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {result.positives.length > 0 && (
                  <div className="bg-emerald-500/5 border border-emerald-500/10 p-6 rounded-2xl">
                    <div className="flex items-center gap-3 mb-4">
                      <ShieldCheck className="w-5 h-5 text-emerald-400" />
                      <h3 className="text-white font-semibold">Positive Signals ({result.positives.length})</h3>
                    </div>
                    <ul className="space-y-2">
                      {result.positives.map((p, i) => (
                        <li key={i} className="flex items-start gap-3 text-sm text-emerald-300/80">
                          <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
                          {p}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* ===== AI Analysis ===== */}
              {result.aiAnalysis && (
                <div className="bg-indigo-500/5 border border-indigo-500/10 p-6 rounded-2xl">
                  <div className="flex items-center gap-3 mb-4">
                    <Bot className="w-5 h-5 text-indigo-400" />
                    <h3 className="text-white font-semibold">AI Risk Assessment</h3>
                    <span className="text-[10px] font-mono bg-indigo-500/10 text-indigo-400 px-2 py-0.5 rounded-full">
                      {result.checks.find(c => c.name === 'AI Risk Assessment')?.details?.includes('Gemini') ? 'Gemini 2.5 Flash' : result.checks.find(c => c.name === 'AI Risk Assessment')?.details?.includes('Groq') ? 'Groq Llama 3.3 70B' : 'Rule-Based Engine'}
                    </span>
                  </div>
                  <p className="text-slate-300 text-sm leading-relaxed whitespace-pre-wrap">{result.aiAnalysis}</p>
                </div>
              )}
              {!result.aiAnalysis && (
                <div className="bg-slate-900/20 border border-slate-800/30 p-6 rounded-2xl">
                  <div className="flex items-center gap-3 mb-2">
                    <Bot className="w-5 h-5 text-slate-500" />
                    <h3 className="text-slate-400 font-semibold">AI Risk Assessment</h3>
                  </div>
                  <p className="text-slate-500 text-sm italic">AI analysis unavailable — configure your Gemini API key in the .env file to enable this feature.</p>
                </div>
              )}

              {/* ===== Recommendations ===== */}
              <div className="bg-indigo-500/5 border border-indigo-500/10 p-6 rounded-2xl">
                <div className="flex items-center gap-3 mb-4">
                  <Info className="w-5 h-5 text-indigo-400" />
                  <h3 className="text-white font-semibold">Safety Recommendations</h3>
                </div>
                <ul className="space-y-3">
                  {result.riskLevel === 'SAFE' ? (
                    <>
                      <li className="flex items-start gap-3 text-sm text-slate-400"><CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />This site appears safe to browse. Use unique passwords for extra protection.</li>
                      <li className="flex items-start gap-3 text-sm text-slate-400"><CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />The connection is encrypted and the domain has been verified through multiple checks.</li>
                    </>
                  ) : (
                    <>
                      <li className="flex items-start gap-3 text-sm text-slate-400"><XCircle className="w-4 h-4 text-rose-500 shrink-0 mt-0.5" />Do not enter sensitive information like passwords or credit card details.</li>
                      <li className="flex items-start gap-3 text-sm text-slate-400"><XCircle className="w-4 h-4 text-rose-500 shrink-0 mt-0.5" />Verify the domain name carefully for typos (e.g., g00gle.com instead of google.com).</li>
                      <li className="flex items-start gap-3 text-sm text-slate-400"><XCircle className="w-4 h-4 text-rose-500 shrink-0 mt-0.5" />If this was a link from an email or SMS, it is likely a phishing attempt.</li>
                    </>
                  )}
                </ul>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Landing Feature Cards */}
        <AnimatePresence>
          {!result && !isAnalyzing && (
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-slate-900/30 border border-slate-800/50 p-6 rounded-2xl">
                <div className="w-10 h-10 rounded-xl bg-indigo-500/10 flex items-center justify-center text-indigo-400 mb-4"><ShieldCheck className="w-5 h-5" /></div>
                <h3 className="text-white font-semibold mb-2">19 Real-Time Checks</h3>
                <p className="text-slate-400 text-sm leading-relaxed">Page content analysis, brand impersonation detection, VirusTotal, DNS, live probe, security headers, WHOIS, SSL, and more.</p>
              </div>
              <div className="bg-slate-900/30 border border-slate-800/50 p-6 rounded-2xl">
                <div className="w-10 h-10 rounded-xl bg-emerald-500/10 flex items-center justify-center text-emerald-400 mb-4"><Sparkles className="w-5 h-5" /></div>
                <h3 className="text-white font-semibold mb-2">AI-Powered Analysis</h3>
                <p className="text-slate-400 text-sm leading-relaxed">Gemini 2.5 Flash + Groq Llama 3.3 70B analyze real page content, headers, and scan results. Always-on rule-based fallback.</p>
              </div>
              <div className="bg-slate-900/30 border border-slate-800/50 p-6 rounded-2xl">
                <div className="w-10 h-10 rounded-xl bg-amber-500/10 flex items-center justify-center text-amber-400 mb-4"><Heart className="w-5 h-5" /></div>
                <h3 className="text-white font-semibold mb-2">Privacy First</h3>
                <p className="text-slate-400 text-sm leading-relaxed">All API calls are server-side. Your browsing data never touches third-party services directly.</p>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Footer */}
        <footer className="mt-24 pt-8 border-t border-slate-800/50 text-center">
          <p className="text-slate-500 text-sm font-mono">&copy; {new Date().getFullYear()} TrustLens Security Engine. Built for a safer web.</p>
        </footer>
      </main>
    </div>
  );
}
