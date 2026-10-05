import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { getCurrentUserApi, refreshApi } from '../services/api';
import LoadingSpinner from '../components/common/LoadingSpinner';
import { 
  User, 
  Mail, 
  ShieldCheck, 
  Key, 
  LogOut, 
  RefreshCw, 
  CheckCircle2, 
  Database,
  Lock,
  Calendar,
  AlertCircle
} from 'lucide-react';

export default function ProfilePage() {
  const { user, logout, accessToken } = useAuth();
  const [profileData, setProfileData] = useState(null);
  const [loadingProfile, setLoadingProfile] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshMessage, setRefreshMessage] = useState('');
  const [errorMsg, setErrorMsg] = useState('');

  // Call the protected GET /api/auth/me endpoint using in-memory access token
  const fetchProfile = async () => {
    setLoadingProfile(true);
    setErrorMsg('');
    try {
      const response = await getCurrentUserApi();
      setProfileData(response?.data?.user);
    } catch (err) {
      setErrorMsg(err.message || 'Failed to fetch user profile.');
    } finally {
      setLoadingProfile(false);
    }
  };

  useEffect(() => {
    fetchProfile();
  }, []);

  // Test manual token rotation from frontend
  const handleManualRefresh = async () => {
    setRefreshing(true);
    setRefreshMessage('');
    try {
      const res = await refreshApi();
      setRefreshMessage('Token rotated successfully! New access token issued.');
      fetchProfile();
    } catch (err) {
      setRefreshMessage('Token refresh failed: ' + (err.message || 'Error'));
    } finally {
      setRefreshing(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Profile Header Card */}
      <div className="border border-slate-800 bg-gradient-to-b from-slate-900 to-slate-900/60 rounded-2xl p-6 sm:p-8 backdrop-blur shadow-2xl relative overflow-hidden">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-16 h-16 rounded-2xl bg-brand-500/10 border border-brand-500/30 flex items-center justify-center text-brand-400 font-bold text-2xl shadow-lg shadow-brand-500/5">
              {user?.username?.charAt(0).toUpperCase() || 'U'}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl font-extrabold text-white tracking-tight">
                  {user?.full_name || user?.username}
                </h1>
                <span className="inline-flex items-center gap-1 text-[11px] font-mono font-medium px-2 py-0.5 rounded-full bg-emerald-950/60 text-emerald-400 border border-emerald-800/50">
                  <CheckCircle2 className="w-3 h-3" /> Authenticated
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">@{user?.username} • {user?.email}</p>
            </div>
          </div>

          <div className="flex items-center gap-2.5">
            <button
              onClick={handleManualRefresh}
              disabled={refreshing}
              className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono font-medium border border-slate-700 transition flex items-center gap-1.5 disabled:opacity-50"
              title="Test refresh token rotation flow"
            >
              <RefreshCw className={`w-3.5 h-3.5 text-brand-400 ${refreshing ? 'animate-spin' : ''}`} />
              <span>Rotate Token</span>
            </button>

            <button
              onClick={logout}
              className="px-3.5 py-2 rounded-lg bg-rose-950/50 hover:bg-rose-900/60 text-rose-300 text-xs font-mono font-medium border border-rose-800/60 transition flex items-center gap-1.5"
            >
              <LogOut className="w-3.5 h-3.5 text-rose-400" />
              <span>Sign Out</span>
            </button>
          </div>
        </div>

        {refreshMessage && (
          <div className="mt-4 p-3 rounded-lg bg-brand-950/40 border border-brand-800/50 text-brand-300 text-xs font-mono flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-brand-400 flex-shrink-0" />
            <span>{refreshMessage}</span>
          </div>
        )}
      </div>

      {/* Security Architecture & Token State Inspection */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* User Profile Attributes from /api/auth/me */}
        <div className="border border-slate-800 bg-slate-900/40 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2 text-slate-200 font-semibold text-sm font-mono uppercase tracking-wider border-b border-slate-800 pb-3">
            <ShieldCheck className="w-4 h-4 text-brand-400" />
            <span>Profile Data (GET /api/auth/me)</span>
          </div>

          {loadingProfile ? (
            <LoadingSpinner size="sm" text="Fetching authenticated profile..." />
          ) : errorMsg ? (
            <div className="p-3 rounded bg-rose-950/30 text-rose-400 text-xs font-mono">{errorMsg}</div>
          ) : (
            <div className="space-y-3 text-xs font-mono">
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">User ID (UUID):</span>
                <span className="text-slate-200 font-mono text-[11px]">{profileData?.id}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Email Address:</span>
                <span className="text-slate-200">{profileData?.email}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Username:</span>
                <span className="text-slate-200">{profileData?.username}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/50">
                <span className="text-slate-400">Full Name:</span>
                <span className="text-slate-200">{profileData?.full_name || 'Not provided'}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-400">Member Since:</span>
                <span className="text-slate-200">
                  {profileData?.created_at ? new Date(profileData.created_at).toLocaleDateString() : 'N/A'}
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Token Security Architecture Verification */}
        <div className="border border-slate-800 bg-slate-900/40 rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2 text-slate-200 font-semibold text-sm font-mono uppercase tracking-wider border-b border-slate-800 pb-3">
            <Lock className="w-4 h-4 text-emerald-400" />
            <span>Security Model Verification</span>
          </div>

          <div className="space-y-3 text-xs font-mono text-slate-300">
            <div className="p-2.5 rounded bg-slate-950/80 border border-slate-800/80 flex items-start gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-200">In-Memory Token:</span>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Volatile in-memory storage prevents persistent browser storage of the access token and reduces exposure from token theft through persistent client-side storage, but it does not eliminate XSS risk.
                </p>
              </div>
            </div>

            <div className="p-2.5 rounded bg-slate-950/80 border border-slate-800/80 flex items-start gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-200">HttpOnly Refresh Cookie:</span>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Scoped to /api/auth. Inaccessible to JavaScript, neutralizing XSS credential theft.
                </p>
              </div>
            </div>

            <div className="p-2.5 rounded bg-slate-950/80 border border-slate-800/80 flex items-start gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-slate-200">Argon2id Hashing:</span>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Passwords salted and hashed with OWASP-recommended memory-hard Argon2id parameters.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
