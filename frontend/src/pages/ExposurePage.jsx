import React, { useState, useEffect } from 'react';
import {
  Globe,
  Search,
  ShieldAlert,
  ShieldCheck,
  AlertCircle,
  Activity,
  Zap,
  User,
  Mail,
  Phone,
  AtSign,
  MapPin,
  FileText,
  CreditCard,
  Key,
  RefreshCw,
  Eye,
  Trash2,
  X,
  ExternalLink,
  Info
} from 'lucide-react';
import {
  analyzeExposureApi,
  getExposureHistoryApi,
  getExposureByIdApi,
  deleteExposureApi
} from '../services/api';
import LoadingSpinner from '../components/common/LoadingSpinner';

const getExposureLevelBadge = (level) => {
  switch (level) {
    case 'CRITICAL':
      return {
        label: 'CRITICAL EXPOSURE',
        color: 'text-red-400 bg-red-950/70 border-red-800/80',
        barColor: 'bg-red-500',
        textColor: 'text-red-400',
        icon: AlertCircle,
      };
    case 'HIGH':
      return {
        label: 'HIGH EXPOSURE',
        color: 'text-amber-400 bg-amber-950/70 border-amber-800/80',
        barColor: 'bg-amber-500',
        textColor: 'text-amber-400',
        icon: AlertCircle,
      };
    case 'MEDIUM':
      return {
        label: 'MEDIUM EXPOSURE',
        color: 'text-yellow-400 bg-yellow-950/70 border-yellow-800/80',
        barColor: 'bg-yellow-400',
        textColor: 'text-yellow-400',
        icon: ShieldAlert,
      };
    default:
      return {
        label: 'LOW EXPOSURE',
        color: 'text-emerald-400 bg-emerald-950/70 border-emerald-800/80',
        barColor: 'bg-emerald-500',
        textColor: 'text-emerald-400',
        icon: ShieldCheck,
      };
  }
};

const getCategoryIcon = (category) => {
  switch (category?.toLowerCase()) {
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

export default function ExposurePage() {
  // Input form state
  const [inputMode, setInputMode] = useState('identifiers'); // 'identifiers' | 'snippet'
  const [identifiers, setIdentifiers] = useState({
    name: '',
    email: '',
    phone: '',
    username: '',
    location: ''
  });
  const [customText, setCustomText] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Active analysis result
  const [activeRecord, setActiveRecord] = useState(null);

  // History state
  const [historyRecords, setHistoryRecords] = useState([]);
  const [totalRecords, setTotalRecords] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize] = useState(10);
  const [isLoadingHistory, setIsLoadingHistory] = useState(true);

  // Inspection modal state
  const [inspectingRecord, setInspectingRecord] = useState(null);
  const [isLoadingInspect, setIsLoadingInspect] = useState(false);

  const fetchHistory = async (page = 1) => {
    setIsLoadingHistory(true);
    try {
      const res = await getExposureHistoryApi(page, pageSize);
      if (res.success && res.data) {
        setHistoryRecords(res.data.records || []);
        setTotalRecords(res.data.total || 0);
        setCurrentPage(res.data.page || 1);
      }
    } catch (err) {
      console.error('Failed to load exposure history:', err);
    } finally {
      setIsLoadingHistory(false);
    }
  };

  useEffect(() => {
    fetchHistory(1);
  }, []);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setIdentifiers((prev) => ({ ...prev, [name]: value }));
  };

  const handleAnalyze = async (e) => {
    e.preventDefault();
    setErrorMsg(null);
    setSuccessMsg(null);

    const payload = {};
    if (inputMode === 'identifiers') {
      const filtered = Object.fromEntries(
        Object.entries(identifiers).filter(([_, v]) => v && v.trim() !== '')
      );
      if (Object.keys(filtered).length === 0) {
        setErrorMsg('Please provide at least one identifier (e.g., email, name, or phone) to analyze.');
        return;
      }
      payload.identifiers = filtered;
    } else {
      if (!customText || !customText.trim()) {
        setErrorMsg('Please enter an exposure text snippet or paste dump to evaluate.');
        return;
      }
      payload.text = customText.trim();
    }

    setIsAnalyzing(true);
    try {
      const res = await analyzeExposureApi(payload);
      if (res.success && res.data?.exposure_record) {
        setActiveRecord(res.data.exposure_record);
        setSuccessMsg(
          `Analysis complete: Composite score ${res.data.exposure_record.exposure_score}/100 (${res.data.exposure_record.exposure_level}).`
        );
        fetchHistory(1);
      } else {
        throw new Error(res.message || 'Analysis failed.');
      }
    } catch (err) {
      console.error('Exposure analysis error:', err);
      setErrorMsg(err.message || 'Exposure analysis failed. Please verify input.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleInspect = async (id) => {
    setIsLoadingInspect(true);
    try {
      const res = await getExposureByIdApi(id);
      if (res.success && res.data?.exposure_record) {
        setInspectingRecord(res.data.exposure_record);
      }
    } catch (err) {
      alert(`Could not load record details: ${err.message || 'Server error'}`);
    } finally {
      setIsLoadingInspect(false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this exposure record?')) {
      return;
    }
    try {
      const res = await deleteExposureApi(id);
      if (res.success) {
        if (activeRecord?.id === id) setActiveRecord(null);
        fetchHistory(currentPage);
      }
    } catch (err) {
      alert(`Failed to delete: ${err.message || 'Server error'}`);
    }
  };

  const renderGaugeCard = (record) => {
    if (!record) return null;
    const score = typeof record.exposure_score === 'number' ? record.exposure_score : 0.0;
    const level = record.exposure_level || 'LOW';
    const badge = getExposureLevelBadge(level);
    const catScores = record.category_scores || {};
    const explanation = record.explanation || {};
    const factors = explanation.contributing_factors || [];

    return (
      <div className={`p-5 rounded-xl border ${badge.color} bg-slate-950/90 space-y-4 shadow-xl transition-all`}>
        {/* Header row */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/70 pb-3">
          <div className="flex items-center gap-3">
            <div className={`p-2.5 rounded-lg bg-slate-900 border border-slate-800 ${badge.textColor}`}>
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[11px] uppercase font-mono tracking-wider text-slate-400">
                Exposure Risk Score (v1.0 Engine)
              </span>
              <div className="flex items-baseline gap-2">
                <span className={`text-3xl font-bold font-mono ${badge.textColor}`}>
                  {score.toFixed(1)}
                </span>
                <span className="text-xs text-slate-500 font-mono">/ 100</span>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {record.is_anomalous && (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-mono font-semibold bg-rose-950/80 text-rose-300 border border-rose-800/70 animate-pulse">
                <Zap className="w-3 h-3 text-rose-400" />
                Isolation Forest Anomaly
              </span>
            )}
            <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold tracking-wide uppercase border ${badge.color}`}>
              {badge.label}
            </span>
          </div>
        </div>

        {/* Meter Gauge */}
        <div className="space-y-1">
          <div className="w-full h-3 bg-slate-900 rounded-full overflow-hidden p-0.5 border border-slate-800">
            <div
              className={`h-full rounded-full transition-all duration-700 ease-out ${badge.barColor}`}
              style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
            />
          </div>
          <div className="flex justify-between text-[10px] font-mono text-slate-500">
            <span>0 LOW</span>
            <span>25 MED</span>
            <span>50 HIGH</span>
            <span>75+ CRITICAL</span>
          </div>
        </div>

        {/* 5-Category Threat Breakdown */}
        <div className="space-y-2 pt-1 border-t border-slate-800/60">
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>Exposure Category Vectors:</span>
            <span>ML Sensitivity: <strong className="text-white">{record.sensitivity_label}</strong></span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
            {['identity', 'contact', 'location', 'financial', 'credential'].map((catKey) => {
              const val = catScores[catKey] || 0;
              const Icon = getCategoryIcon(catKey);
              return (
                <div key={catKey} className="p-2.5 bg-slate-900/80 border border-slate-800 rounded-lg space-y-1">
                  <div className="flex items-center justify-between text-[11px] text-slate-400 capitalize">
                    <span className="flex items-center gap-1">
                      <Icon className="w-3 h-3 text-slate-500" />
                      {catKey}
                    </span>
                    <span className="font-mono font-bold text-white">{val}</span>
                  </div>
                  <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${
                        val >= 75 ? 'bg-rose-500' : val >= 50 ? 'bg-amber-500' : val >= 25 ? 'bg-yellow-400' : 'bg-emerald-500'
                      }`}
                      style={{ width: `${val}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Explainability Breakdown Points */}
        {factors.length > 0 && (
          <div className="space-y-1.5 pt-1 border-t border-slate-800/60">
            <span className="text-[11px] uppercase font-mono font-semibold text-slate-400 tracking-wider">
              Explainability & Contributing Factors:
            </span>
            <ul className="space-y-1 text-xs text-slate-300">
              {factors.map((f, idx) => (
                <li key={idx} className="flex items-start gap-2">
                  <span className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${badge.barColor}`} />
                  <span className="leading-snug">{f}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  };

  const renderEntitiesList = (findings = []) => {
    if (!findings || findings.length === 0) {
      return (
        <div className="p-6 text-center bg-slate-950/60 border border-slate-800 rounded-lg">
          <ShieldCheck className="w-8 h-8 mx-auto text-emerald-400 mb-2 stroke-[1.5]" />
          <p className="text-sm font-semibold text-emerald-300">Zero Sensitive Entities Detected</p>
          <p className="text-xs text-slate-400 mt-1">
            Custom NER extracted zero credentials, cards, national IDs, or direct contact links.
          </p>
        </div>
      );
    }

    return (
      <div className="space-y-2">
        {findings.map((f, idx) => (
          <div
            key={idx}
            className="p-3 bg-slate-950 border border-slate-800/80 rounded-lg flex flex-wrap items-center justify-between gap-2 hover:border-slate-700 transition"
          >
            <div className="flex items-center gap-2">
              <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-slate-800 text-brand-300 border border-slate-700">
                {f.entity_type}
              </span>
              <span className="font-mono text-sm font-bold text-white bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                {f.masked_value}
              </span>
              <span className="text-[11px] text-slate-500 font-mono capitalize">
                ({f.category})
              </span>
            </div>

            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                f.validation_status === 'VALID'
                  ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                  : f.validation_status === 'INVALID'
                  ? 'bg-rose-950 text-rose-300 border-rose-800'
                  : 'bg-slate-800 text-slate-400 border-slate-700'
              }`}>
                {f.validation_status}
              </span>
              <span>Conf: {(f.confidence * 100).toFixed(0)}%</span>
            </div>
          </div>
        ))}
      </div>
    );
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 text-xs font-mono font-medium rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              Phase 7 Subsystem
            </span>
            <span className="text-xs text-slate-500 font-mono">
              Custom NER • TF-IDF + Random Forest • Isolation Forest Anomaly Detection
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white flex items-center gap-2">
            <Globe className="w-8 h-8 text-indigo-400" />
            Exposure Monitor
          </h1>
          <p className="text-sm text-slate-400 mt-1 max-w-3xl">
            Analyze online presence, public directory records, and synthetic exposure logs to assess where personal identity assets appear.
            Distinguishes <strong className="text-slate-300">Exposure Risk</strong> from <strong className="text-slate-300">Document Privacy Risk</strong>.
          </p>
        </div>
      </div>

      {/* Main Grid: Form (5 cols) & Active Result (7 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Form (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          <div className="card space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <Search className="w-4 h-4 text-indigo-400" />
                Analyze Exposure Target
              </h2>
              {/* Tab selector */}
              <div className="flex rounded-lg bg-slate-900 p-0.5 border border-slate-800 text-xs">
                <button
                  type="button"
                  onClick={() => setInputMode('identifiers')}
                  className={`px-2.5 py-1 rounded font-medium transition ${
                    inputMode === 'identifiers'
                      ? 'bg-brand-500 text-white shadow'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Identifiers
                </button>
                <button
                  type="button"
                  onClick={() => setInputMode('snippet')}
                  className={`px-2.5 py-1 rounded font-medium transition ${
                    inputMode === 'snippet'
                      ? 'bg-brand-500 text-white shadow'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  Text Snippet
                </button>
              </div>
            </div>

            {errorMsg && (
              <div className="p-3 rounded-lg bg-rose-950/60 border border-rose-800/80 text-rose-300 text-xs flex items-center justify-between">
                <span>{errorMsg}</span>
                <button onClick={() => setErrorMsg(null)}><X className="w-4 h-4" /></button>
              </div>
            )}

            {successMsg && (
              <div className="p-3 rounded-lg bg-emerald-950/60 border border-emerald-800/80 text-emerald-300 text-xs flex items-center justify-between">
                <span>{successMsg}</span>
                <button onClick={() => setSuccessMsg(null)}><X className="w-4 h-4" /></button>
              </div>
            )}

            <form onSubmit={handleAnalyze} className="space-y-3.5">
              {inputMode === 'identifiers' ? (
                <>
                  <div>
                    <label className="block text-xs font-mono text-slate-400 mb-1">Target Name</label>
                    <div className="relative">
                      <User className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                      <input
                        type="text"
                        name="name"
                        value={identifiers.name}
                        onChange={handleInputChange}
                        placeholder="e.g. Rahul Sharma"
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-brand-500 font-sans"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-mono text-slate-400 mb-1">Email Address</label>
                    <div className="relative">
                      <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                      <input
                        type="email"
                        name="email"
                        value={identifiers.email}
                        onChange={handleInputChange}
                        placeholder="e.g. rahul.sharma@example.com"
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-brand-500 font-mono"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-mono text-slate-400 mb-1">Phone Number</label>
                    <div className="relative">
                      <Phone className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                      <input
                        type="text"
                        name="phone"
                        value={identifiers.phone}
                        onChange={handleInputChange}
                        placeholder="e.g. +91 98765 43210"
                        className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-brand-500 font-mono"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-mono text-slate-400 mb-1">Username / Handle</label>
                      <div className="relative">
                        <AtSign className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                        <input
                          type="text"
                          name="username"
                          value={identifiers.username}
                          onChange={handleInputChange}
                          placeholder="e.g. rahul_s"
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-8 pr-2 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-brand-500 font-mono"
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-xs font-mono text-slate-400 mb-1">City / Location</label>
                      <div className="relative">
                        <MapPin className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                        <input
                          type="text"
                          name="location"
                          value={identifiers.location}
                          onChange={handleInputChange}
                          placeholder="e.g. Mumbai"
                          className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-8 pr-2 py-2 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-brand-500 font-sans"
                        />
                      </div>
                    </div>
                  </div>
                </>
              ) : (
                <div>
                  <label className="block text-xs font-mono text-slate-400 mb-1">
                    Paste Exposure Observation / Log Snippet
                  </label>
                  <textarea
                    rows={6}
                    value={customText}
                    onChange={(e) => setCustomText(e.target.value)}
                    placeholder="Paste log entries, public directory dump, or credential leak text..."
                    className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2.5 text-xs text-white placeholder-slate-600 focus:outline-none focus:border-brand-500 font-mono leading-relaxed"
                  />
                </div>
              )}

              <button
                type="submit"
                disabled={isAnalyzing}
                className="w-full btn btn-primary flex items-center justify-center gap-2 mt-4"
              >
                {isAnalyzing ? (
                  <>
                    <LoadingSpinner size="sm" />
                    <span>Executing NER & Anomaly Models...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4" />
                    <span>Run Exposure Analysis</span>
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Educational Specifications Card */}
          <div className="card space-y-2.5 text-xs text-slate-400">
            <h3 className="font-semibold text-white flex items-center gap-1.5">
              <Info className="w-4 h-4 text-indigo-400" />
              Exposure Engine Architecture
            </h3>
            <ul className="space-y-1.5 list-disc list-inside text-slate-400">
              <li>
                <strong className="text-slate-300">Custom Regex NER:</strong> Scans identity, contact, location, financial, and credential vectors with zero raw PII storage.
              </li>
              <li>
                <strong className="text-slate-300">TF-IDF + Random Forest:</strong> Evaluates exposure sensitivity (LOW / MEDIUM / HIGH / CRITICAL).
              </li>
              <li>
                <strong className="text-slate-300">Isolation Forest:</strong> Identifies anomalous spikes or multi-vector identity asset concentrations.
              </li>
              <li>
                <strong className="text-slate-300">Deterministic 0-100 Score:</strong> Aggregates category threat weights, sensitivity boosts, and anomaly signals.
              </li>
            </ul>
          </div>
        </div>

        {/* Right Column: Active Results (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          <div className="card space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="text-base font-semibold text-white flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-indigo-400" />
                Active Exposure Profile
              </h2>
              {activeRecord && (
                <span className="text-xs font-mono text-slate-400">
                  Target Hash: {activeRecord.query_value_hash?.slice(0, 12)}...
                </span>
              )}
            </div>

            {activeRecord ? (
              <div className="space-y-5 animate-fadeIn">
                {/* Gauge Card */}
                {renderGaugeCard(activeRecord)}

                {/* Masked Entities Found */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                    <span>Detected Entities ({activeRecord.findings?.length || activeRecord.total_entities || 0}):</span>
                    <span>Anomalous: <strong className={activeRecord.is_anomalous ? 'text-rose-400' : 'text-emerald-400'}>
                      {activeRecord.is_anomalous ? 'YES' : 'NO'}
                    </strong></span>
                  </div>
                  {renderEntitiesList(activeRecord.findings || [])}
                </div>
              </div>
            ) : (
              <div className="py-16 text-center text-slate-500 space-y-2">
                <Globe className="w-12 h-12 mx-auto text-slate-700 stroke-[1.5]" />
                <p className="text-sm font-medium text-slate-400">No Target Analyzed in This Session</p>
                <p className="text-xs text-slate-500 max-w-sm mx-auto">
                  Provide an identity target or observation text on the left to evaluate online exposure risk.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* History Table */}
      <div className="card space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-base font-semibold text-white">Exposure Monitoring History</h2>
            <p className="text-xs text-slate-400">Past target scans and anomaly evaluations</p>
          </div>
          <button
            onClick={() => fetchHistory(currentPage)}
            disabled={isLoadingHistory}
            className="btn btn-secondary py-1 px-3 text-xs flex items-center gap-1.5 self-start sm:self-auto"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoadingHistory ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>

        {isLoadingHistory ? (
          <div className="py-10 flex justify-center">
            <LoadingSpinner size="md" />
          </div>
        ) : historyRecords.length === 0 ? (
          <div className="py-10 text-center text-slate-500 text-xs">
            No exposure analyses recorded yet.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/60 text-slate-400 font-mono uppercase text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-3">Query Type</th>
                  <th className="py-3 px-3">Target Hash</th>
                  <th className="py-3 px-3">Total Entities</th>
                  <th className="py-3 px-3">Sensitivity</th>
                  <th className="py-3 px-3">Anomaly</th>
                  <th className="py-3 px-3">Exposure Score</th>
                  <th className="py-3 px-3">Timestamp</th>
                  <th className="py-3 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {historyRecords.map((r) => {
                  const badge = getExposureLevelBadge(r.exposure_level);
                  return (
                    <tr key={r.id} className="hover:bg-slate-900/30 transition">
                      <td className="py-3 px-3 font-mono font-bold text-white capitalize">
                        {r.query_type}
                      </td>
                      <td className="py-3 px-3 font-mono text-slate-400">
                        {r.query_value_hash ? `${r.query_value_hash.slice(0, 10)}...` : '—'}
                      </td>
                      <td className="py-3 px-3 font-mono">
                        {r.total_entities} entities
                      </td>
                      <td className="py-3 px-3">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-800 text-slate-300 border border-slate-700">
                          {r.sensitivity_label}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono">
                        {r.is_anomalous ? (
                          <span className="text-rose-400 font-bold">ANOMALY</span>
                        ) : (
                          <span className="text-slate-500">Normal</span>
                        )}
                      </td>
                      <td className="py-3 px-3">
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded font-mono text-[11px] font-bold border ${badge.color}`}>
                          <span>{(r.exposure_score || 0).toFixed(1)}</span>
                          <span className="text-[9px] uppercase tracking-wider">{r.exposure_level}</span>
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono text-slate-400">
                        {r.created_at ? new Date(r.created_at).toLocaleString() : '—'}
                      </td>
                      <td className="py-3 px-3 text-right space-x-2">
                        <button
                          onClick={() => handleInspect(r.id)}
                          className="btn btn-secondary py-1 px-2 text-[11px] inline-flex items-center gap-1"
                        >
                          <Eye className="w-3 h-3 text-indigo-400" />
                          <span>Inspect</span>
                        </button>
                        <button
                          onClick={() => handleDelete(r.id)}
                          className="p-1 text-slate-500 hover:text-rose-400 transition"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {totalRecords > pageSize && (
          <div className="flex items-center justify-between pt-3 border-t border-slate-800 text-xs text-slate-400">
            <span>Showing {historyRecords.length} of {totalRecords} records</span>
            <div className="flex gap-2">
              <button
                disabled={currentPage <= 1 || isLoadingHistory}
                onClick={() => fetchHistory(currentPage - 1)}
                className="btn btn-secondary py-1 px-2.5 text-xs disabled:opacity-40"
              >
                Previous
              </button>
              <button
                disabled={currentPage * pageSize >= totalRecords || isLoadingHistory}
                onClick={() => fetchHistory(currentPage + 1)}
                className="btn btn-secondary py-1 px-2.5 text-xs disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Inspection Modal */}
      {inspectingRecord && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-3xl w-full p-6 space-y-4 shadow-2xl animate-fadeIn max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-semibold text-white">Exposure Analysis Details</h3>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  ID: {inspectingRecord.id} • Query: {inspectingRecord.query_type}
                </p>
              </div>
              <button onClick={() => setInspectingRecord(null)} className="p-1 text-slate-400 hover:text-white">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto space-y-4 pr-1">
              {renderGaugeCard(inspectingRecord)}
              <div>
                <h4 className="text-xs font-mono font-semibold text-slate-300 uppercase mb-2">
                  Masked Entity Findings ({inspectingRecord.findings?.length || 0})
                </h4>
                {renderEntitiesList(inspectingRecord.findings || [])}
              </div>
            </div>

            <div className="flex justify-end pt-3 border-t border-slate-800">
              <button
                onClick={() => setInspectingRecord(null)}
                className="btn btn-secondary py-1.5 px-4 text-xs"
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
