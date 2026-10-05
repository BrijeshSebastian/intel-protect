import { Shield, Activity, Lock, User, LogIn, UserPlus, LogOut, FileText, Globe, ShieldAlert, LayoutDashboard } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function AppLayout({ children }) {
  const location = useLocation();
  const { user, isAuthenticated, logout } = useAuth();

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col font-sans">
      {/* Top Navigation Bar */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center space-x-3 group">
            <div className="w-10 h-10 rounded-lg bg-brand-500/10 border border-brand-500/30 flex items-center justify-center text-brand-500 shadow-lg shadow-brand-500/5 group-hover:border-brand-500/50 transition">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <span className="text-lg font-bold tracking-tight text-white flex items-center gap-1.5">
                INTEL-PROTECT
                <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-brand-500/10 text-brand-400 border border-brand-500/20">
                  v1.0-DocScan
                </span>
              </span>
              <p className="text-xs text-slate-400 font-mono -mt-0.5">Data Exposure & Privacy Risk Monitor</p>
            </div>
          </Link>

          <nav className="flex items-center space-x-1 sm:space-x-3 text-sm font-medium">
            <Link
              to="/"
              className={`px-3 py-1.5 rounded-md transition-colors flex items-center gap-1.5 ${
                location.pathname === '/'
                  ? 'bg-slate-800 text-white border border-slate-700'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
              }`}
            >
              <Activity className="w-4 h-4 text-brand-500" />
              <span>Health</span>
            </Link>

            {isAuthenticated ? (
              <>
                <Link
                  to="/dashboard"
                  className={`px-3 py-1.5 rounded-md transition-colors flex items-center gap-1.5 ${
                    location.pathname === '/dashboard'
                      ? 'bg-slate-800 text-white border border-slate-700'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                  }`}
                >
                  <LayoutDashboard className="w-4 h-4 text-cyan-400" />
                  <span>Dashboard</span>
                </Link>

                <Link
                  to="/documents"
                  className={`px-3 py-1.5 rounded-md transition-colors flex items-center gap-1.5 ${
                    location.pathname === '/documents'
                      ? 'bg-slate-800 text-white border border-slate-700'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                  }`}
                >
                  <FileText className="w-4 h-4 text-brand-400" />
                  <span>Scan Documents</span>
                </Link>

                <Link
                  to="/exposure"
                  className={`px-3 py-1.5 rounded-md transition-colors flex items-center gap-1.5 ${
                    location.pathname === '/exposure'
                      ? 'bg-slate-800 text-white border border-slate-700'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                  }`}
                >
                  <Globe className="w-4 h-4 text-indigo-400" />
                  <span>Exposure Monitor</span>
                </Link>

                <Link
                  to="/breaches"
                  className={`px-3 py-1.5 rounded-md transition-colors flex items-center gap-1.5 ${
                    location.pathname === '/breaches'
                      ? 'bg-slate-800 text-white border border-slate-700'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                  }`}
                >
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <span>Breach Monitor</span>
                </Link>

                <Link
                  to="/profile"
                  className={`px-3 py-1.5 rounded-md transition-colors flex items-center gap-1.5 ${
                    location.pathname === '/profile'
                      ? 'bg-slate-800 text-white border border-slate-700'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                  }`}
                >
                  <User className="w-4 h-4 text-emerald-400" />
                  <span>@{user?.username}</span>
                </Link>

                <button
                  onClick={logout}
                  className="px-3 py-1.5 rounded-md text-slate-400 hover:text-rose-400 hover:bg-rose-950/30 transition flex items-center gap-1.5"
                  title="Sign Out"
                >
                  <LogOut className="w-4 h-4" />
                  <span className="hidden sm:inline">Sign Out</span>
                </button>
              </>
            ) : (
              <>
                <Link
                  to="/login"
                  className={`px-3 py-1.5 rounded-md transition-colors flex items-center gap-1.5 ${
                    location.pathname === '/login'
                      ? 'bg-slate-800 text-white border border-slate-700'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                  }`}
                >
                  <LogIn className="w-4 h-4 text-slate-400" />
                  <span>Sign In</span>
                </Link>

                <Link
                  to="/register"
                  className="px-3 py-1.5 rounded-md bg-brand-600 hover:bg-brand-500 text-slate-950 font-semibold transition flex items-center gap-1.5 shadow-sm shadow-brand-500/20"
                >
                  <UserPlus className="w-4 h-4" />
                  <span>Register</span>
                </Link>
              </>
            )}
          </nav>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {children}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-4 text-center text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <p>Intel-Protect — Privacy Analysis Platform (MCA Major Project)</p>
          <p className="flex items-center gap-1">
            <Lock className="w-3 h-3 text-brand-500" /> Argon2id + Memory JWT + HttpOnly Cookies
          </p>
        </div>
      </footer>
    </div>
  );
}
