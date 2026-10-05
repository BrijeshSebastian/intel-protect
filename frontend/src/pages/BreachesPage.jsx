import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  Search,
  CheckCircle,
  XCircle,
  Clock,
  Database,
  Lock,
  CreditCard,
  User,
  Key,
  ExternalLink,
  Trash2,
  Eye,
  RefreshCw,
  BellRing,
  Check,
} from 'lucide-react';
import {
  checkBreachesApi,
  getBreachHistoryApi,
  getBreachByIdApi,
  deleteBreachApi,
  getBreachCatalogApi,
  getRecommendationsApi,
  dismissRecommendationApi,
} from '../services/api';
import { useAuth } from '../context/AuthContext';

const getSeverityStyle = (severity) => {
  switch (severity?.toUpperCase()) {
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

const formatDataTypeBadge = (dtype) => {
  const d = dtype?.toUpperCase();
  if (d.includes('PASS') || d.includes('CREDENTIAL') || d.includes('KEY')) {
    return { label: dtype, color: 'bg-red-500/15 text-red-300 border-red-500/30', icon: Key };
  }
  if (d.includes('CARD') || d.includes('BANK') || d.includes('FINANCIAL')) {
    return { label: dtype, color: 'bg-amber-500/15 text-amber-300 border-amber-500/30', icon: CreditCard };
  }
  if (d.includes('AADHAAR') || d.includes('PAN') || d.includes('PASSPORT') || d.includes('IDENTITY')) {
    return { label: dtype, color: 'bg-purple-500/15 text-purple-300 border-purple-500/30', icon: User };
  }
  return { label: dtype, color: 'bg-blue-500/15 text-blue-300 border-blue-500/30', icon: Database };
};

export default function BreachesPage() {
  const { user } = useAuth();
  const [emailInput, setEmailInput] = useState('');
  const [isChecking, setIsChecking] = useState(false);
  const [activeResult, setActiveResult] = useState(null);
  const [activeBreaches, setActiveBreaches] = useState([]);
  const [recommendations, setRecommendations] = useState([]);
  const [historyRecords, setHistoryRecords] = useState([]);
  const [catalogRecords, setCatalogRecords] = useState([]);
  const [isLoadingHistory, setIsLoadingHistory] = useState(false);
  const [isLoadingCatalog, setIsLoadingCatalog] = useState(false);
  const [activeTab, setActiveTab] = useState('assessment'); // 'assessment' | 'history' | 'catalog'
  const [selectedRecordModal, setSelectedRecordModal] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Initialize with user's email if available
  useEffect(() => {
    if (user?.email) {
      setEmailInput(user.email);
    }
  }, [user]);

  // Load history & recommendations on mount
  const fetchHistory = async () => {
    setIsLoadingHistory(true);
    try {
      const res = await getBreachHistoryApi(1, 10);
      if (res.data?.records) {
        setHistoryRecords(res.data.records);
      }
    } catch (err) {
      console.error('Failed to load breach history:', err);
    } finally {
      setIsLoadingHistory(false);
    }
  };

  const fetchRecommendations = async () => {
    try {
      const res = await getRecommendationsApi(true);
      if (res.data?.recommendations) {
        setRecommendations(res.data.recommendations);
      }
    } catch (err) {
      console.error('Failed to load recommendations:', err);
    }
  };

  const fetchCatalog = async () => {
    setIsLoadingCatalog(true);
    try {
      const res = await getBreachCatalogApi(1, 50);
      if (res.data?.catalog) {
        setCatalogRecords(res.data.catalog);
      }
    } catch (err) {
      console.error('Failed to load breach catalog:', err);
    } finally {
      setIsLoadingCatalog(false);
    }
  };

  useEffect(() => {
    fetchHistory();
    fetchRecommendations();
    fetchCatalog();
  }, []);

  const handleCheckBreaches = async (e) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);

    const targetEmail = emailInput.trim();
    if (!targetEmail) {
      setErrorMsg('Please provide an email address to check.');
      return;
    }

    setIsChecking(true);
    try {
      const res = await checkBreachesApi({ email: targetEmail });
      if (res.success && res.data) {
        setActiveResult(res.data.result);
        setActiveBreaches(res.data.breaches || []);
        setRecommendations(res.data.recommendations || []);
        setSuccessMsg(
          `Breach assessment complete: ${res.data.breaches?.length || 0} breach(es) matched. Risk Score: ${res.data.result.breach_risk_score}/100.`
        );
        fetchHistory();
        setActiveTab('assessment');
      } else {
        throw new Error(res.message || 'Assessment failed.');
      }
    } catch (err) {
      console.error('Breach check error:', err);
      setErrorMsg(err.message || 'Breach check failed. Please verify email address.');
    } finally {
      setIsChecking(false);
    }
  };

  const handleDismissRec = async (recId) => {
    try {
      await dismissRecommendationApi(recId);
      setRecommendations((prev) => prev.filter((r) => r.id !== recId));
    } catch (err) {
      console.error('Failed to dismiss recommendation:', err);
    }
  };

  const handleDeleteHistory = async (id) => {
    if (!window.confirm('Are you sure you want to delete this breach lookup record?')) return;
    try {
      await deleteBreachApi(id);
      setHistoryRecords((prev) => prev.filter((r) => r.id !== id));
      if (activeResult?.id === id) {
        setActiveResult(null);
        setActiveBreaches([]);
      }
    } catch (err) {
      console.error('Failed to delete breach record:', err);
    }
  };

  const handleInspectRecord = async (id) => {
    try {
      const res = await getBreachByIdApi(id);
      if (res.data) {
        setSelectedRecordModal(res.data);
      }
    } catch (err) {
      console.error('Failed to inspect record:', err);
    }
  };

  // SVG Gauge parameters
  const score = activeResult?.breach_risk_score || 0;
  const radius = 64;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;
  const severityStyle = getSeverityStyle(activeResult?.breach_risk_level || 'LOW');

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-100 tracking-tight">Breach Monitor</h1>
            <p className="text-sm text-slate-400">
              Cross-reference email credentials against synthetic intelligence repositories & public leaks
            </p>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-3">
        <button
          onClick={() => setActiveTab('assessment')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
            activeTab === 'assessment'
              ? 'bg-slate-800 text-slate-100 border border-slate-700 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
          }`}
        >
          Active Assessment
        </button>
        <button
          onClick={() => setActiveTab('history')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
            activeTab === 'history'
              ? 'bg-slate-800 text-slate-100 border border-slate-700 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
          }`}
        >
          Check History ({historyRecords.length})
        </button>
        <button
          onClick={() => setActiveTab('catalog')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
            activeTab === 'catalog'
              ? 'bg-slate-800 text-slate-100 border border-slate-700 shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
          }`}
        >
          Monitored Breaches Catalog ({catalogRecords.length})
        </button>
      </div>

      {/* Alerts */}
      {errorMsg && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 flex items-center gap-3 text-red-400 text-sm">
          <XCircle className="w-5 h-5 flex-shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}
      {successMsg && (
        <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex items-center gap-3 text-emerald-400 text-sm">
          <CheckCircle className="w-5 h-5 flex-shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* TAB 1: ASSESSMENT */}
      {activeTab === 'assessment' && (
        <div className="space-y-8">
          {/* Email Search Box */}
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl backdrop-blur-sm">
            <form onSubmit={handleCheckBreaches} className="space-y-4">
              <label className="block text-sm font-medium text-slate-300">
                Email Address to Verify
              </label>
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="relative flex-1">
                  <Search className="w-5 h-5 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
                  <input
                    type="email"
                    value={emailInput}
                    onChange={(e) => setEmailInput(e.target.value)}
                    placeholder="Enter email address (e.g., user@example.com)..."
                    className="w-full pl-11 pr-4 py-3 bg-slate-950/80 border border-slate-800 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/50 transition-all font-mono text-sm"
                    required
                  />
                </div>
                <button
                  type="submit"
                  disabled={isChecking}
                  className="px-6 py-3 bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 disabled:opacity-50 text-white font-medium rounded-xl shadow-lg shadow-red-500/20 flex items-center justify-center gap-2 transition-all flex-shrink-0"
                >
                  {isChecking ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Cross-Referencing...
                    </>
                  ) : (
                    <>
                      <ShieldAlert className="w-4 h-4" />
                      Check Breaches
                    </>
                  )}
                </button>
              </div>
              <p className="text-xs text-slate-500">
                * Strict Privacy Guarantee: Plaintext email is never persisted. Only a salted SHA-256 cryptographic digest is stored.
              </p>
            </form>
          </div>

          {/* Assessment Results Overview */}
          {activeResult && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Risk Gauge Card */}
              <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl flex flex-col items-center justify-center text-center">
                <h3 className="text-sm font-semibold text-slate-400 mb-4 uppercase tracking-wider">
                  Breach Risk Score
                </h3>
                <div className="relative w-44 h-44 flex items-center justify-center">
                  <svg className="w-full h-full -rotate-90">
                    <circle
                      cx="88"
                      cy="88"
                      r={radius}
                      stroke="currentColor"
                      strokeWidth="12"
                      className="text-slate-800"
                      fill="transparent"
                    />
                    <circle
                      cx="88"
                      cy="88"
                      r={radius}
                      stroke={severityStyle.gauge}
                      strokeWidth="12"
                      strokeDasharray={circumference}
                      strokeDashoffset={strokeDashoffset}
                      strokeLinecap="round"
                      fill="transparent"
                      className="transition-all duration-1000 ease-out"
                    />
                  </svg>
                  <div className="absolute flex flex-col items-center justify-center">
                    <span className="text-4xl font-extrabold text-slate-100 font-mono">
                      {score.toFixed(1)}
                    </span>
                    <span className="text-xs text-slate-500 font-medium">/ 100</span>
                  </div>
                </div>

                <div className="mt-4 flex items-center gap-2">
                  <span
                    className={`px-3 py-1 rounded-full text-xs font-semibold border ${severityStyle.badge}`}
                  >
                    {activeResult.breach_risk_level} RISK
                  </span>
                  <span className="px-3 py-1 rounded-full text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">
                    PRIORITY: {activeResult.priority_label}
                  </span>
                </div>
              </div>

              {/* Summary Stats Card */}
              <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl flex flex-col justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-slate-400 mb-4 uppercase tracking-wider">
                    Threat Footprint
                  </h3>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
                      <span className="text-xs text-slate-500 font-medium block">
                        Matched Breaches
                      </span>
                      <span className="text-2xl font-bold text-slate-100 font-mono mt-1 block">
                        {activeResult.breach_count}
                      </span>
                    </div>
                    <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800">
                      <span className="text-xs text-slate-500 font-medium block">
                        Compromised Attributes
                      </span>
                      <span className="text-2xl font-bold text-slate-100 font-mono mt-1 block">
                        {activeResult.total_exposures}
                      </span>
                    </div>
                  </div>

                  <div className="mt-4">
                    <span className="text-xs text-slate-500 font-medium block mb-2">
                      Compromised Data Categories
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {Object.entries(activeResult.exposure_summary || {}).map(([dtype, cnt]) => {
                        const style = formatDataTypeBadge(dtype);
                        return (
                          <span
                            key={dtype}
                            className={`px-2 py-0.5 rounded-md text-xs font-mono font-medium border flex items-center gap-1 ${style.color}`}
                          >
                            <style.icon className="w-3 h-3" />
                            {dtype} ({cnt})
                          </span>
                        );
                      })}
                    </div>
                  </div>
                </div>

                <div className="mt-4 pt-4 border-t border-slate-800/80 text-xs text-slate-500 flex items-center justify-between">
                  <span>ML Confidence: {(activeResult.priority_confidence * 100).toFixed(0)}%</span>
                  <span>Evaluated: {new Date(activeResult.checked_at).toLocaleTimeString()}</span>
                </div>
              </div>

              {/* Explainability Card */}
              <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl">
                <h3 className="text-sm font-semibold text-slate-400 mb-4 uppercase tracking-wider">
                  Risk Factors & Drivers
                </h3>
                <div className="space-y-2.5 max-h-56 overflow-y-auto pr-1">
                  {(activeResult.explanation?.contributing_factors || [
                    'Standard evaluation completed.',
                  ]).map((factor, idx) => (
                    <div
                      key={idx}
                      className="p-3 rounded-xl bg-slate-950/50 border border-slate-800/80 text-xs text-slate-300 flex items-start gap-2.5"
                    >
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-400 flex-shrink-0 mt-0.5" />
                      <span>{factor}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Actionable Recommendations Section */}
          {recommendations.length > 0 && (
            <div className="space-y-4">
              <div className="flex items-center gap-2">
                <BellRing className="w-5 h-5 text-indigo-400" />
                <h2 className="text-lg font-bold text-slate-200">
                  Prioritized Remediation Actions
                </h2>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {recommendations.map((rec) => (
                  <div
                    key={rec.id}
                    className="p-5 rounded-2xl bg-slate-900/70 border border-slate-800 hover:border-slate-700 transition-all shadow-lg flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-start justify-between gap-3 mb-2">
                        <span
                          className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
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
                          className="text-xs text-slate-500 hover:text-slate-300 flex items-center gap-1 transition-colors"
                          title="Dismiss recommendation"
                        >
                          <Check className="w-3.5 h-3.5" />
                          Dismiss
                        </button>
                      </div>
                      <h4 className="text-sm font-bold text-slate-100">{rec.title}</h4>
                      <p className="text-xs text-slate-400 mt-2 leading-relaxed">
                        {rec.description}
                      </p>
                    </div>
                    <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-slate-500">
                      <span className="font-mono">Action: {rec.action_type}</span>
                      <span className="text-slate-500">Module: {rec.source_module}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Matched Breaches Cards Feed */}
          {activeBreaches.length > 0 ? (
            <div className="space-y-4">
              <h2 className="text-lg font-bold text-slate-200 flex items-center gap-2">
                <Database className="w-5 h-5 text-red-400" />
                Confirmed Breach Exposures ({activeBreaches.length})
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {activeBreaches.map((b) => (
                  <div
                    key={b.id || b.name}
                    className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-md space-y-3"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <h4 className="text-base font-bold text-slate-100">{b.name}</h4>
                        <span className="text-xs text-slate-400">{b.organization}</span>
                      </div>
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
                          b.severity === 'CRITICAL'
                            ? 'bg-red-500/10 text-red-400 border-red-500/30'
                            : b.severity === 'HIGH'
                            ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                            : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                        }`}
                      >
                        {b.severity}
                      </span>
                    </div>

                    <p className="text-xs text-slate-400 leading-relaxed">{b.description}</p>

                    <div className="flex items-center gap-4 text-xs text-slate-500 font-mono">
                      <span>Date: {b.breach_date}</span>
                      <span>Affected: {b.affected_count?.toLocaleString()} accounts</span>
                    </div>

                    <div className="pt-2 border-t border-slate-800/60">
                      <span className="text-xs text-slate-500 font-medium block mb-1.5">
                        Exposed Attributes:
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {(b.exposed_data_types || []).map((dtype) => {
                          const style = formatDataTypeBadge(dtype);
                          return (
                            <span
                              key={dtype}
                              className={`px-2 py-0.5 rounded text-[11px] font-mono border ${style.color}`}
                            >
                              {dtype}
                            </span>
                          );
                        })}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : activeResult ? (
            <div className="p-8 rounded-2xl bg-slate-900/40 border border-slate-800 text-center space-y-2">
              <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" />
              <h3 className="text-base font-bold text-slate-200">No Breaches Detected</h3>
              <p className="text-sm text-slate-400">
                This email address does not appear in any known synthetic breaches or leaked paste corpuses.
              </p>
            </div>
          ) : null}
        </div>
      )}

      {/* TAB 2: HISTORY */}
      {activeTab === 'history' && (
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-bold text-slate-100">Past Breach Lookups</h3>
            <button
              onClick={fetchHistory}
              className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Refresh
            </button>
          </div>

          {isLoadingHistory ? (
            <div className="py-12 text-center text-slate-500 text-sm">Loading history...</div>
          ) : historyRecords.length === 0 ? (
            <div className="py-12 text-center text-slate-500 text-sm">
              No previous breach checks recorded.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-slate-800 text-xs text-slate-400 font-mono uppercase">
                    <th className="py-3 px-4">Date</th>
                    <th className="py-3 px-4">Query Hash</th>
                    <th className="py-3 px-4">Breaches</th>
                    <th className="py-3 px-4">Risk Score</th>
                    <th className="py-3 px-4">Priority</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
                  {historyRecords.map((r) => {
                    const sev = getSeverityStyle(r.breach_risk_level);
                    return (
                      <tr key={r.id} className="hover:bg-slate-800/30 transition-colors">
                        <td className="py-3.5 px-4 text-slate-400">
                          {new Date(r.checked_at).toLocaleDateString()}
                        </td>
                        <td className="py-3.5 px-4 text-slate-300">
                          {r.query_email_hash?.substring(0, 12)}...
                        </td>
                        <td className="py-3.5 px-4 text-slate-200 font-bold">{r.breach_count}</td>
                        <td className="py-3.5 px-4">
                          <span className={`px-2 py-0.5 rounded border ${sev.badge}`}>
                            {r.breach_risk_score} ({r.breach_risk_level})
                          </span>
                        </td>
                        <td className="py-3.5 px-4 text-indigo-400 font-medium">
                          {r.priority_label}
                        </td>
                        <td className="py-3.5 px-4 text-right space-x-2">
                          <button
                            onClick={() => handleInspectRecord(r.id)}
                            className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition-colors"
                            title="View details"
                          >
                            <Eye className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDeleteHistory(r.id)}
                            className="p-1.5 rounded-lg text-slate-400 hover:text-red-400 hover:bg-slate-800 transition-colors"
                            title="Delete"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: MONITORED BREACHES CATALOG */}
      {activeTab === 'catalog' && (
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 shadow-xl space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-base font-bold text-slate-100">
                Monitored Incident Repositories
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Security incidents and synthetic threat intelligence leaks cataloged in Intel-Protect
              </p>
            </div>
            <button
              onClick={fetchCatalog}
              className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Refresh
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {catalogRecords.map((b) => (
              <div
                key={b.id}
                className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2.5"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <h4 className="text-sm font-bold text-slate-100">{b.name}</h4>
                    <span className="text-xs text-slate-400">{b.organization}</span>
                  </div>
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${
                      b.severity === 'CRITICAL'
                        ? 'bg-red-500/10 text-red-400 border-red-500/30'
                        : b.severity === 'HIGH'
                        ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                        : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                    }`}
                  >
                    {b.severity}
                  </span>
                </div>
                <p className="text-xs text-slate-400 line-clamp-2">{b.description}</p>
                <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono">
                  <span>Breach: {b.breach_date}</span>
                  <span>{b.affected_count?.toLocaleString()} accounts</span>
                </div>
                <div className="flex flex-wrap gap-1 pt-1">
                  {(b.exposed_data_types || []).map((t) => (
                    <span
                      key={t}
                      className="px-1.5 py-0.5 rounded bg-slate-800 text-[10px] text-slate-300 font-mono"
                    >
                      {t}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Detail Inspection Modal */}
      {selectedRecordModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
          <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-2xl space-y-5 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h3 className="text-lg font-bold text-slate-100">Breach Inspection Record</h3>
                <span className="text-xs text-slate-500 font-mono">
                  ID: {selectedRecordModal.result?.id}
                </span>
              </div>
              <button
                onClick={() => setSelectedRecordModal(null)}
                className="text-slate-400 hover:text-slate-200 text-sm font-semibold p-1"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800">
                <span className="text-slate-500 block">Risk Score</span>
                <span className="text-base font-bold text-slate-200">
                  {selectedRecordModal.result?.breach_risk_score} / 100
                </span>
              </div>
              <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800">
                <span className="text-slate-500 block">Priority Level</span>
                <span className="text-base font-bold text-indigo-400">
                  {selectedRecordModal.result?.priority_label}
                </span>
              </div>
            </div>

            <div>
              <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                Matched Incidents ({selectedRecordModal.breaches?.length || 0})
              </h4>
              <div className="space-y-2">
                {(selectedRecordModal.breaches || []).map((b) => (
                  <div key={b.name} className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 text-xs">
                    <div className="flex justify-between items-center mb-1">
                      <span className="font-bold text-slate-200">{b.name}</span>
                      <span className="text-slate-500">{b.breach_date}</span>
                    </div>
                    <p className="text-slate-400">{b.description}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="text-right pt-3 border-t border-slate-800">
              <button
                onClick={() => setSelectedRecordModal(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm rounded-xl font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
