import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Flame,
  FileText,
  Globe,
  Database,
  TrendingUp,
  TrendingDown,
  Minus,
  CheckCircle,
  Clock,
  ArrowRight,
  RefreshCw,
  BellRing,
  Check,
  CreditCard,
  User,
  Key,
  Mail,
  MapPin,
} from 'lucide-react';
import { getDashboardApi, dismissRecommendationApi } from '../services/api';
import { useAuth } from '../context/AuthContext';

const getSeverityStyle = (level) => {
  switch (level?.toUpperCase()) {
    case 'CRITICAL':
      return {
        badge: 'bg-red-500/10 text-red-400 border-red-500/30',
        gauge: '#ef4444',
        text: 'text-red-400',
        icon: Flame,
      };
    case 'HIGH':
      return {
        badge: 'bg-orange-500/10 text-orange-400 border-orange-500/30',
        gauge: '#f97316',
        text: 'text-orange-400',
        icon: AlertTriangle,
      };
    case 'MEDIUM':
      return {
        badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
        gauge: '#f59e0b',
        text: 'text-amber-400',
        icon: AlertTriangle,
      };
    case 'LOW':
    default:
      return {
        badge: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
        gauge: '#10b981',
        text: 'text-emerald-400',
        icon: ShieldCheck,
      };
  }
};

const getTrendIcon = (trend) => {
  switch (trend?.toLowerCase()) {
    case 'increasing':
      return { icon: TrendingUp, text: 'text-red-400', label: 'Elevated Risk Trend' };
    case 'improving':
      return { icon: TrendingDown, text: 'text-emerald-400', label: 'Improving Risk Trend' };
    case 'stable':
    default:
      return { icon: Minus, text: 'text-slate-400', label: 'Stable Risk Posture' };
  }
};

const getCategoryIcon = (cat) => {
  switch (cat?.toLowerCase()) {
    case 'credential':
      return Key;
    case 'financial':
      return CreditCard;
    case 'identity':
      return User;
    case 'contact':
      return Mail;
    case 'location':
      return MapPin;
    default:
      return Globe;
  }
};

export default function DashboardPage() {
  const { user } = useAuth();
  const [data, setData] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMsg, setErrorMsg] = useState(null);

  const fetchDashboard = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const res = await getDashboardApi();
      if (res.data) {
        setData(res.data);
      }
    } catch (err) {
      console.error('Failed to load dashboard:', err);
      setErrorMsg(err.message || 'Failed to fetch threat intelligence summary.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboard();
  }, []);

  const handleDismissRec = async (recId) => {
    try {
      await dismissRecommendationApi(recId);
      setData((prev) => {
        if (!prev) return prev;
        return {
          ...prev,
          active_recommendations: prev.active_recommendations.filter((r) => r.id !== recId),
        };
      });
    } catch (err) {
      console.error('Failed to dismiss recommendation:', err);
    }
  };

  if (isLoading) {
    return (
      <div className="py-24 text-center space-y-3">
        <RefreshCw className="w-8 h-8 text-cyan-400 animate-spin mx-auto" />
        <p className="text-slate-400 text-sm">Aggregating cross-module threat intelligence...</p>
      </div>
    );
  }

  if (errorMsg || !data) {
    return (
      <div className="py-16 text-center space-y-4">
        <AlertTriangle className="w-10 h-10 text-amber-400 mx-auto" />
        <h3 className="text-lg font-bold text-slate-100">Unable to load Threat Dashboard</h3>
        <p className="text-sm text-slate-400 max-w-md mx-auto">{errorMsg}</p>
        <button
          onClick={fetchDashboard}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm rounded-xl font-medium"
        >
          Try Again
        </button>
      </div>
    );
  }

  const overall = data.overall_risk;
  const overallStyle = getSeverityStyle(overall.level);
  const trendInfo = getTrendIcon(overall.trend);

  // SVG Gauge calculations
  const overallScore = overall.score;
  const radius = 72;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (overallScore / 100) * circumference;

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      {/* Page Title */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
            <LayoutDashboard className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-100 tracking-tight">
              Unified Threat Dashboard
            </h1>
            <p className="text-sm text-slate-400">
              Cross-subsystem cybersecurity & privacy threat intelligence posture for @{user?.username}
            </p>
          </div>
        </div>
        <button
          onClick={fetchDashboard}
          className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs rounded-xl font-mono flex items-center gap-2 self-start sm:self-auto transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Sync Telemetry
        </button>
      </div>

      {/* TOP SECTION: Overall Risk Gauge & Core Module Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Overall Composite Score Card */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl flex flex-col items-center justify-center text-center relative overflow-hidden">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">
            Consolidated Risk Score
          </span>
          <div className="relative w-44 h-44 flex items-center justify-center">
            <svg className="w-full h-full -rotate-90">
              <circle
                cx="88"
                cy="88"
                r={radius}
                stroke="currentColor"
                strokeWidth="14"
                className="text-slate-800"
                fill="transparent"
              />
              <circle
                cx="88"
                cy="88"
                r={radius}
                stroke={overallStyle.gauge}
                strokeWidth="14"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                className="transition-all duration-1000 ease-out"
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center">
              <span className="text-4xl font-extrabold text-slate-100 font-mono">
                {overallScore.toFixed(1)}
              </span>
              <span className="text-xs text-slate-500 font-medium">/ 100</span>
            </div>
          </div>

          <div className="mt-4 flex flex-col items-center gap-1.5">
            <span
              className={`px-3 py-1 rounded-full text-xs font-semibold border ${overallStyle.badge}`}
            >
              {overall.level} POSTURE
            </span>
            <div className={`flex items-center gap-1 text-xs font-medium ${trendInfo.text} mt-1`}>
              <trendInfo.icon className="w-3.5 h-3.5" />
              <span>{trendInfo.label}</span>
            </div>
          </div>
        </div>

        {/* 3 Module Breakdown Cards */}
        {/* 1. Document Scanner */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl flex flex-col justify-between hover:border-slate-700 transition-all">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400">
                <FileText className="w-5 h-5" />
              </div>
              <span
                className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
                  getSeverityStyle(data.document_risk.level).badge
                }`}
              >
                {data.document_risk.level}
              </span>
            </div>
            <h3 className="text-base font-bold text-slate-100">Document Privacy</h3>
            <span className="text-2xl font-extrabold font-mono text-slate-200 mt-1 block">
              {data.document_risk.score.toFixed(1)} <span className="text-xs text-slate-500">/ 100</span>
            </span>
            <div className="mt-4 space-y-1.5 text-xs text-slate-400 font-mono">
              <div className="flex justify-between">
                <span>Scanned Documents:</span>
                <span className="text-slate-200 font-bold">{data.document_risk.documents_scanned}</span>
              </div>
              <div className="flex justify-between">
                <span>PII Findings:</span>
                <span className="text-slate-200 font-bold">{data.document_risk.total_pii_findings}</span>
              </div>
              <div className="flex justify-between">
                <span>High-Risk Findings:</span>
                <span className="text-rose-400 font-bold">{data.document_risk.high_risk_findings}</span>
              </div>
            </div>
          </div>
          <Link
            to="/documents"
            className="mt-5 text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-medium group"
          >
            <span>Scan & Review Files</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
          </Link>
        </div>

        {/* 2. Exposure Monitor */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl flex flex-col justify-between hover:border-slate-700 transition-all">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400">
                <Globe className="w-5 h-5" />
              </div>
              <span
                className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
                  getSeverityStyle(data.exposure_risk.level).badge
                }`}
              >
                {data.exposure_risk.level}
              </span>
            </div>
            <h3 className="text-base font-bold text-slate-100">Identity Exposure</h3>
            <span className="text-2xl font-extrabold font-mono text-slate-200 mt-1 block">
              {data.exposure_risk.score.toFixed(1)} <span className="text-xs text-slate-500">/ 100</span>
            </span>
            <div className="mt-4 space-y-1.5 text-xs text-slate-400 font-mono">
              <div className="flex justify-between">
                <span>Analyses Conducted:</span>
                <span className="text-slate-200 font-bold">{data.exposure_risk.analyses_count}</span>
              </div>
              <div className="flex justify-between">
                <span>Anomalies Flagged:</span>
                <span className="text-amber-400 font-bold">{data.exposure_risk.anomalies_detected}</span>
              </div>
              <div className="flex justify-between">
                <span>NER Subsystem:</span>
                <span className="text-slate-200">Active</span>
              </div>
            </div>
          </div>
          <Link
            to="/exposure"
            className="mt-5 text-xs text-indigo-400 hover:text-indigo-300 flex items-center gap-1 font-medium group"
          >
            <span>Run Exposure Intelligence</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
          </Link>
        </div>

        {/* 3. Breach Monitor */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl flex flex-col justify-between hover:border-slate-700 transition-all">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400">
                <Database className="w-5 h-5" />
              </div>
              <span
                className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
                  getSeverityStyle(data.breach_risk.level).badge
                }`}
              >
                {data.breach_risk.level}
              </span>
            </div>
            <h3 className="text-base font-bold text-slate-100">Breach Incidents</h3>
            <span className="text-2xl font-extrabold font-mono text-slate-200 mt-1 block">
              {data.breach_risk.score.toFixed(1)} <span className="text-xs text-slate-500">/ 100</span>
            </span>
            <div className="mt-4 space-y-1.5 text-xs text-slate-400 font-mono">
              <div className="flex justify-between">
                <span>Matched Breaches:</span>
                <span className="text-slate-200 font-bold">{data.breach_risk.total_breaches}</span>
              </div>
              <div className="flex justify-between">
                <span>Exposed Attributes:</span>
                <span className="text-rose-400 font-bold">{data.breach_risk.total_exposures}</span>
              </div>
              <div className="flex justify-between">
                <span>Catalog Provider:</span>
                <span className="text-slate-200">Local Synthetic</span>
              </div>
            </div>
          </div>
          <Link
            to="/breaches"
            className="mt-5 text-xs text-rose-400 hover:text-rose-300 flex items-center gap-1 font-medium group"
          >
            <span>Verify Credentials</span>
            <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
          </Link>
        </div>
      </div>

      {/* MIDDLE SECTION: 5-Category Risk Distribution & Active Remediation */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 5-Category Vector Distribution */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl space-y-5">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-100">5-Vector Threat Exposure</h3>
              <p className="text-xs text-slate-400">
                Calculated exposure distribution across primary cyber vulnerability domains
              </p>
            </div>
          </div>

          <div className="space-y-4 pt-2">
            {Object.entries(data.risk_distribution || {}).map(([cat, val]) => {
              const Icon = getCategoryIcon(cat);
              const isHigh = val >= 50.0;
              return (
                <div key={cat} className="space-y-1.5">
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-slate-300 font-medium capitalize flex items-center gap-1.5">
                      <Icon className="w-3.5 h-3.5 text-slate-400" />
                      {cat}
                    </span>
                    <span className="font-mono text-slate-400">
                      {val.toFixed(1)} / 100
                    </span>
                  </div>
                  <div className="h-2 rounded-full bg-slate-950 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-700 ${
                        val >= 75
                          ? 'bg-rose-500'
                          : val >= 50
                          ? 'bg-orange-500'
                          : val >= 25
                          ? 'bg-amber-500'
                          : 'bg-emerald-500'
                      }`}
                      style={{ width: `${Math.max(4, val)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Actionable Security Recommendations */}
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <BellRing className="w-5 h-5 text-indigo-400" />
                <h3 className="text-base font-bold text-slate-100">
                  Active Remediation Recommendations
                </h3>
              </div>
              <span className="text-xs font-mono text-slate-400">
                {data.active_recommendations?.length || 0} Open
              </span>
            </div>

            {data.active_recommendations?.length === 0 ? (
              <div className="py-12 text-center space-y-2">
                <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto" />
                <p className="text-xs text-slate-400">
                  No active recommendations. Your security hygiene is up to date!
                </p>
              </div>
            ) : (
              <div className="space-y-3 max-h-72 overflow-y-auto pr-1">
                {data.active_recommendations.map((rec) => (
                  <div
                    key={rec.id}
                    className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 text-xs space-y-2 hover:border-slate-700 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                          rec.priority === 'CRITICAL'
                            ? 'bg-red-500/10 text-red-400 border-red-500/30'
                            : rec.priority === 'HIGH'
                            ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                            : 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30'
                        }`}
                      >
                        {rec.priority}
                      </span>
                      <button
                        onClick={() => handleDismissRec(rec.id)}
                        className="text-[11px] text-slate-500 hover:text-slate-300 flex items-center gap-1 transition-colors"
                      >
                        <Check className="w-3 h-3" />
                        Dismiss
                      </button>
                    </div>
                    <h5 className="font-bold text-slate-200">{rec.title}</h5>
                    <p className="text-slate-400 leading-relaxed text-[11px]">
                      {rec.description}
                    </p>
                    {rec.source_modules && rec.source_modules.length > 0 && (
                      <div className="flex items-center gap-1.5 flex-wrap pt-1">
                        <span className="text-[9px] uppercase tracking-wider text-slate-500 font-semibold">Sources:</span>
                        {rec.source_modules.map((mod) => (
                          <span
                            key={mod}
                            className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-[10px] font-mono text-cyan-300"
                          >
                            {mod}
                          </span>
                        ))}
                      </div>
                    )}
                    {rec.reason && (
                      <p className="text-[10px] text-slate-500 italic pt-0.5">
                        <span className="font-semibold text-slate-400">Evidence:</span> {rec.reason}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-xs text-slate-500 flex items-center justify-between">
            <span>Remediation advice derived from threat telemetry</span>
            <Link to="/breaches" className="text-indigo-400 hover:text-indigo-300 font-medium">
              Manage in Breaches
            </Link>
          </div>
        </div>
      </div>

      {/* BOTTOM SECTION: Unified Chronological Activity Feed */}
      <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold text-slate-100">
              Cross-Module Threat Intelligence Timeline
            </h3>
          </div>
          <span className="text-xs text-slate-500 font-mono">
            {data.recent_activity?.length || 0} Recent Events
          </span>
        </div>

        {data.recent_activity?.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-xs">
            No telemetry recorded yet. Upload a document or verify credentials to begin monitoring.
          </div>
        ) : (
          <div className="space-y-3">
            {data.recent_activity.map((item, idx) => {
              const sev = getSeverityStyle(item.level);
              return (
                <div
                  key={item.id || idx}
                  className="p-3.5 rounded-xl bg-slate-950/50 border border-slate-800 flex items-center justify-between gap-4 hover:bg-slate-950 transition-colors"
                >
                  <div className="flex items-center gap-3">
                    <div
                      className={`p-2 rounded-lg ${
                        item.type === 'document_scan'
                          ? 'bg-cyan-500/10 text-cyan-400'
                          : item.type === 'exposure_analysis'
                          ? 'bg-indigo-500/10 text-indigo-400'
                          : 'bg-rose-500/10 text-rose-400'
                      }`}
                    >
                      {item.type === 'document_scan' ? (
                        <FileText className="w-4 h-4" />
                      ) : item.type === 'exposure_analysis' ? (
                        <Globe className="w-4 h-4" />
                      ) : (
                        <Database className="w-4 h-4" />
                      )}
                    </div>
                    <div>
                      <h5 className="text-xs font-bold text-slate-200">{item.title}</h5>
                      <span className="text-[11px] text-slate-400">{item.details}</span>
                    </div>
                  </div>

                  <div className="flex items-center gap-3 flex-shrink-0">
                    <span className={`px-2 py-0.5 rounded text-[11px] font-mono border ${sev.badge}`}>
                      {item.score.toFixed(1)} ({item.level})
                    </span>
                    <span className="text-[11px] text-slate-500 font-mono hidden sm:inline">
                      {item.timestamp ? new Date(item.timestamp).toLocaleDateString() : 'N/A'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
