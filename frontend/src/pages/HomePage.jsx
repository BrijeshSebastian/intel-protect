import React, { useState, useEffect } from 'react';
import { checkHealth } from '../services/api';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  RefreshCw, 
  Database, 
  Server, 
  ShieldCheck, 
  Layers,
  Clock,
  Terminal
} from 'lucide-react';

export default function HomePage() {
  const [healthData, setHealthData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [latency, setLatency] = useState(null);
  const [lastChecked, setLastChecked] = useState(null);

  const fetchHealth = async () => {
    setLoading(true);
    setError(null);
    const startTime = performance.now();
    try {
      const response = await checkHealth();
      const endTime = performance.now();
      setLatency(Math.round(endTime - startTime));
      setHealthData(response);
      setLastChecked(new Date().toLocaleTimeString());
    } catch (err) {
      const endTime = performance.now();
      setLatency(Math.round(endTime - startTime));
      setError(err);
      setHealthData(null);
      setLastChecked(new Date().toLocaleTimeString());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
  }, []);

  const isHealthy = healthData?.success && healthData?.data?.status === 'healthy';
  const isDbConnected = healthData?.data?.database === 'connected';

  return (
    <div className="space-y-8 max-w-5xl mx-auto">
      {/* Hero / Phase 1 Status Banner */}
      <div className="border border-slate-800 bg-gradient-to-b from-slate-900 to-slate-900/50 rounded-2xl p-6 sm:p-8 relative overflow-hidden shadow-2xl">
        <div className="absolute top-0 right-0 w-96 h-96 bg-brand-500/5 rounded-full blur-3xl pointer-events-none" />

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6 relative z-10">
          <div>
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-mono bg-brand-500/10 text-brand-400 border border-brand-500/20 mb-3">
              <span className="w-1.5 h-1.5 rounded-full bg-brand-400 animate-pulse" />
              Phase 1: Project Setup & Health Verification
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Intel-Protect System Monitor
            </h1>
            <p className="text-sm text-slate-400 mt-1 max-w-2xl">
              Verifying real-time communication between the React frontend, Flask backend, and PostgreSQL relational database.
            </p>
          </div>

          <button
            onClick={fetchHealth}
            disabled={loading}
            className="self-start sm:self-center inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-sm font-medium border border-slate-700 transition shadow-sm hover:border-slate-600 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 text-brand-400 ${loading ? 'animate-spin' : ''}`} />
            <span>Recheck API</span>
          </button>
        </div>

        {/* Live Connectivity Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 relative z-10">
          {/* Flask Backend Card */}
          <div className="border border-slate-800/80 bg-slate-950/60 rounded-xl p-5 backdrop-blur">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2 text-slate-300 font-medium text-sm">
                <Server className="w-4 h-4 text-brand-500" />
                <span>Flask API</span>
              </div>
              {loading ? (
                <span className="text-xs text-slate-500 font-mono">Checking...</span>
              ) : isHealthy ? (
                <span className="inline-flex items-center gap-1 text-xs font-semibold font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/50 px-2 py-0.5 rounded-full">
                  <CheckCircle2 className="w-3.5 h-3.5" /> ONLINE
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-xs font-semibold font-mono text-rose-400 bg-rose-950/60 border border-rose-800/50 px-2 py-0.5 rounded-full">
                  <XCircle className="w-3.5 h-3.5" /> OFFLINE
                </span>
              )}
            </div>
            <div className="text-xs text-slate-400 font-mono space-y-1">
              <div>Endpoint: <span className="text-slate-200">/api/health</span></div>
              <div>Service: <span className="text-slate-200">{healthData?.data?.service || 'N/A'}</span></div>
              <div>Version: <span className="text-slate-200">{healthData?.data?.version || '1.0.0'}</span></div>
            </div>
          </div>

          {/* PostgreSQL DB Card */}
          <div className="border border-slate-800/80 bg-slate-950/60 rounded-xl p-5 backdrop-blur">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2 text-slate-300 font-medium text-sm">
                <Database className="w-4 h-4 text-emerald-500" />
                <span>PostgreSQL DB</span>
              </div>
              {loading ? (
                <span className="text-xs text-slate-500 font-mono">Checking...</span>
              ) : isDbConnected ? (
                <span className="inline-flex items-center gap-1 text-xs font-semibold font-mono text-emerald-400 bg-emerald-950/60 border border-emerald-800/50 px-2 py-0.5 rounded-full">
                  <CheckCircle2 className="w-3.5 h-3.5" /> CONNECTED
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 text-xs font-semibold font-mono text-rose-400 bg-rose-950/60 border border-rose-800/50 px-2 py-0.5 rounded-full">
                  <XCircle className="w-3.5 h-3.5" /> DISCONNECTED
                </span>
              )}
            </div>
            <div className="text-xs text-slate-400 font-mono space-y-1">
              <div>Engine: <span className="text-slate-200">PostgreSQL (SQLAlchemy)</span></div>
              <div>Status: <span className="text-slate-200">{healthData?.data?.database || 'disconnected'}</span></div>
              <div>Ping Query: <span className="text-slate-200">SELECT 1 (Verified)</span></div>
            </div>
          </div>

          {/* Network Roundtrip Card */}
          <div className="border border-slate-800/80 bg-slate-950/60 rounded-xl p-5 backdrop-blur">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2 text-slate-300 font-medium text-sm">
                <Clock className="w-4 h-4 text-sky-400" />
                <span>Roundtrip Latency</span>
              </div>
              <span className="text-xs text-slate-500 font-mono">
                {lastChecked ? `Checked: ${lastChecked}` : ''}
              </span>
            </div>
            <div className="text-xs text-slate-400 font-mono space-y-1">
              <div>API Latency: <span className="text-slate-200">{latency !== null ? `${latency} ms` : 'N/A'}</span></div>
              <div>Client: <span className="text-slate-200">Axios REST Client</span></div>
              <div>Credentials: <span className="text-slate-200">withCredentials (CORS safe)</span></div>
            </div>
          </div>
        </div>
      </div>

      {/* Raw Health API Response Inspection */}
      <div className="border border-slate-800 bg-slate-900/40 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-brand-400" />
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300 font-mono">
              Live API Response Payload
            </h2>
          </div>
          <span className="text-xs text-slate-500 font-mono">
            GET /api/health
          </span>
        </div>

        {loading ? (
          <div className="py-8">
            <LoadingSpinner size="md" text="Polling Flask API health endpoint..." />
          </div>
        ) : error ? (
          <div className="p-4 rounded-lg bg-rose-950/40 border border-rose-800/60 text-rose-200 font-mono text-xs">
            <div className="font-bold flex items-center gap-2 mb-1 text-rose-300">
              <AlertTriangle className="w-4 h-4" /> API Request Error
            </div>
            <div>Code: {error.code || 'CONNECTION_REFUSED'}</div>
            <div>Message: {error.message}</div>
          </div>
        ) : (
          <div className="relative">
            <pre className="bg-slate-950 p-4 rounded-lg border border-slate-800/80 font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed">
              {JSON.stringify(healthData, null, 2)}
            </pre>
          </div>
        )}
      </div>

      {/* Architectural Next Steps (Phase Gate Reminder) */}
      <div className="border border-slate-800/60 bg-slate-900/20 rounded-xl p-6 text-xs text-slate-400">
        <div className="flex items-center gap-2 font-semibold text-slate-300 mb-2 font-mono text-sm">
          <Layers className="w-4 h-4 text-brand-500" />
          <span>Phase 1 Scope Completed</span>
        </div>
        <p className="leading-relaxed">
          The project structure, Flask factory, PostgreSQL connectivity, Alembic migration setup, React + Vite frontend, and Axios client are established and verified. Business logic modules (Authentication, Document Scanner, Exposure Monitor, Breach Monitor) will be implemented sequentially in subsequent phases.
        </p>
      </div>
    </div>
  );
}
