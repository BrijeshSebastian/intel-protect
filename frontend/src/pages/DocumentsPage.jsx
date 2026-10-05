import React, { useState, useEffect, useRef } from 'react';
import {
  Upload,
  FileText,
  Image as ImageIcon,
  CheckCircle2,
  AlertCircle,
  Copy,
  Check,
  Trash2,
  Eye,
  RefreshCw,
  FileCode,
  ShieldCheck,
  ShieldAlert,
  FileCheck,
  HardDrive,
  X,
  Download,
  CreditCard,
  Hash,
  Mail,
  Phone,
  Landmark,
  Shield,
  Layers,
  Activity,
  Zap
} from 'lucide-react';
import {
  uploadDocumentApi,
  getDocumentsApi,
  getDocumentByIdApi,
  deleteDocumentApi,
  getDocumentFindingsApi
} from '../services/api';
import LoadingSpinner from '../components/common/LoadingSpinner';

const ALLOWED_EXTENSIONS = ['pdf', 'png', 'jpg', 'jpeg', 'txt'];
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB

// Helper to resolve PII type badge details
const getPiiTypeBadge = (type) => {
  switch (type) {
    case 'AADHAAR':
      return {
        label: 'Aadhaar (UIDAI)',
        icon: Shield,
        color: 'bg-purple-950/60 text-purple-300 border-purple-800/60',
      };
    case 'PAN':
      return {
        label: 'PAN Card',
        icon: Hash,
        color: 'bg-indigo-950/60 text-indigo-300 border-indigo-800/60',
      };
    case 'CARD':
      return {
        label: 'Payment Card',
        icon: CreditCard,
        color: 'bg-rose-950/60 text-rose-300 border-rose-800/60',
      };
    case 'BANK_ACCOUNT':
      return {
        label: 'Bank Account',
        icon: Landmark,
        color: 'bg-amber-950/60 text-amber-300 border-amber-800/60',
      };
    case 'EMAIL':
      return {
        label: 'Email Address',
        icon: Mail,
        color: 'bg-sky-950/60 text-sky-300 border-sky-800/60',
      };
    case 'PHONE':
      return {
        label: 'Phone Number',
        icon: Phone,
        color: 'bg-emerald-950/60 text-emerald-300 border-emerald-800/60',
      };
    default:
      return {
        label: type,
        icon: ShieldAlert,
        color: 'bg-slate-800 text-slate-300 border-slate-700',
      };
  }
};

const getSeverityClass = (severity) => {
  switch (severity) {
    case 'CRITICAL':
      return 'bg-red-500/20 text-red-400 border-red-500/30';
    case 'HIGH':
      return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
    case 'MEDIUM':
      return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
    default:
      return 'bg-blue-500/20 text-blue-400 border-blue-500/30';
  }
};

const getRiskLevelBadge = (level) => {
  switch (level) {
    case 'CRITICAL':
      return {
        label: 'CRITICAL RISK',
        color: 'text-red-400 bg-red-950/70 border-red-800/80',
        barColor: 'bg-red-500',
        textColor: 'text-red-400',
        icon: AlertCircle,
      };
    case 'HIGH':
      return {
        label: 'HIGH RISK',
        color: 'text-amber-400 bg-amber-950/70 border-amber-800/80',
        barColor: 'bg-amber-500',
        textColor: 'text-amber-400',
        icon: AlertCircle,
      };
    case 'MEDIUM':
      return {
        label: 'MEDIUM RISK',
        color: 'text-yellow-400 bg-yellow-950/70 border-yellow-800/80',
        barColor: 'bg-yellow-400',
        textColor: 'text-yellow-400',
        icon: ShieldAlert,
      };
    default:
      return {
        label: 'LOW RISK',
        color: 'text-emerald-400 bg-emerald-950/70 border-emerald-800/80',
        barColor: 'bg-emerald-500',
        textColor: 'text-emerald-400',
        icon: ShieldCheck,
      };
  }
};

export default function DocumentsPage() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadError, setUploadError] = useState(null);
  const [uploadSuccess, setUploadSuccess] = useState(null);

  // Active extracted result
  const [latestDocument, setLatestDocument] = useState(null);
  const [activeTab, setActiveTab] = useState('findings'); // 'findings' | 'text'

  // Document history
  const [documents, setDocuments] = useState([]);
  const [totalDocuments, setTotalDocuments] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize] = useState(10);
  const [isLoadingHistory, setIsLoadingHistory] = useState(true);

  // Modal viewer state
  const [viewingDocument, setViewingDocument] = useState(null);
  const [modalTab, setModalTab] = useState('findings'); // 'findings' | 'text'
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);

  // Copy state
  const [copiedHash, setCopiedHash] = useState(false);
  const [copiedText, setCopiedText] = useState(false);

  const fileInputRef = useRef(null);

  // Load document scan history on mount & page change
  const fetchDocumentHistory = async (page = 1) => {
    setIsLoadingHistory(true);
    try {
      const response = await getDocumentsApi(page, pageSize);
      if (response.success && response.data) {
        setDocuments(response.data.documents || []);
        setTotalDocuments(response.data.total || 0);
        setCurrentPage(response.data.page || 1);
      }
    } catch (err) {
      console.error('Failed to load document history:', err);
    } finally {
      setIsLoadingHistory(false);
    }
  };

  useEffect(() => {
    fetchDocumentHistory(1);
  }, []);

  // Format file size helper
  const formatFileSize = (bytes) => {
    if (!bytes && bytes !== 0) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  // Drag and drop handlers
  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const validateFile = (file) => {
    if (!file) return 'No file selected.';

    const ext = file.name.split('.').pop()?.toLowerCase();
    if (!ext || !ALLOWED_EXTENSIONS.includes(ext)) {
      return `Unsupported file format (.${ext || 'unknown'}). Supported: PDF, PNG, JPG, JPEG, TXT.`;
    }

    if (file.size > MAX_FILE_SIZE_BYTES) {
      return `File size (${formatFileSize(file.size)}) exceeds the 10 MB maximum limit.`;
    }

    if (file.size === 0) {
      return 'The selected file is empty (0 bytes).';
    }

    return null;
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    setUploadError(null);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      const errorMsg = validateFile(file);
      if (errorMsg) {
        setUploadError(errorMsg);
        setSelectedFile(null);
        return;
      }
      setSelectedFile(file);
    }
  };

  const handleFileChange = (e) => {
    setUploadError(null);
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      const errorMsg = validateFile(file);
      if (errorMsg) {
        setUploadError(errorMsg);
        setSelectedFile(null);
        return;
      }
      setSelectedFile(file);
    }
  };

  // Upload handler
  const handleUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile) return;

    const validationErr = validateFile(selectedFile);
    if (validationErr) {
      setUploadError(validationErr);
      return;
    }

    setIsUploading(true);
    setUploadProgress(0);
    setUploadError(null);
    setUploadSuccess(null);

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const response = await uploadDocumentApi(formData, (percent) => {
        setUploadProgress(percent);
      });

      if (response.success && response.data?.document) {
        const doc = response.data.document;
        // Merge findings if returned at top level
        if (response.data.findings && (!doc.findings || doc.findings.length === 0)) {
          doc.findings = response.data.findings;
        }
        setLatestDocument(doc);
        // Default active tab to findings if any detected, else text
        if (doc.findings && doc.findings.length > 0) {
          setActiveTab('findings');
        } else {
          setActiveTab('text');
        }
        setUploadSuccess(
          `Document "${doc.original_filename}" processed: ${doc.pii_count || 0} sensitive PII item(s) detected.`
        );
        setSelectedFile(null);
        if (fileInputRef.current) {
          fileInputRef.current.value = '';
        }
        // Refresh history
        fetchDocumentHistory(1);
      } else {
        throw new Error(response.message || 'Upload failed.');
      }
    } catch (err) {
      console.error('Document upload error:', err);
      setUploadError(err.message || 'Failed to upload and extract document.');
    } finally {
      setIsUploading(false);
    }
  };

  // Delete document handler
  const handleDeleteDocument = async (id, filename) => {
    if (!window.confirm(`Are you sure you want to delete the record for "${filename}"?`)) {
      return;
    }

    try {
      const res = await deleteDocumentApi(id);
      if (res.success) {
        if (latestDocument?.id === id) {
          setLatestDocument(null);
        }
        fetchDocumentHistory(currentPage);
      }
    } catch (err) {
      alert(`Could not delete document: ${err.message || 'Server error'}`);
    }
  };

  // View document details modal
  const handleViewDocument = async (id) => {
    setIsLoadingDetail(true);
    try {
      const res = await getDocumentByIdApi(id);
      if (res.success && res.data?.document) {
        const doc = res.data.document;
        // If findings not attached, fetch from findings endpoint
        if (!doc.findings || doc.findings.length === 0) {
          try {
            const findingsRes = await getDocumentFindingsApi(id);
            if (findingsRes.success && findingsRes.data?.findings) {
              doc.findings = findingsRes.data.findings;
            }
          } catch (fErr) {
            console.warn('Could not fetch findings separately:', fErr);
          }
        }
        setViewingDocument(doc);
        setModalTab(doc.findings && doc.findings.length > 0 ? 'findings' : 'text');
      }
    } catch (err) {
      alert(`Error loading document details: ${err.message || 'Server error'}`);
    } finally {
      setIsLoadingDetail(false);
    }
  };

  // Copy helper
  const handleCopy = (text, type = 'text') => {
    navigator.clipboard.writeText(text);
    if (type === 'hash') {
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    } else {
      setCopiedText(true);
      setTimeout(() => setCopiedText(false), 2000);
    }
  };

  // Download extracted text as file
  const handleDownloadText = (filename, text) => {
    const element = document.createElement('a');
    const file = new Blob([text], { type: 'text/plain;charset=utf-8' });
    element.href = URL.createObjectURL(file);
    element.download = `${filename.replace(/\.[^/.]+$/, '')}_extracted.txt`;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
  };

  // Sub-component: Renders PII Findings Cards
  const renderFindingsList = (findings = []) => {
    if (!findings || findings.length === 0) {
      return (
        <div className="p-8 text-center bg-slate-950/60 border border-slate-800 rounded-lg">
          <ShieldCheck className="w-10 h-10 mx-auto text-emerald-400 mb-2 stroke-[1.5]" />
          <p className="text-sm font-semibold text-emerald-300">No Sensitive PII Detected</p>
          <p className="text-xs text-slate-400 max-w-md mx-auto mt-1">
            Deterministic validation evaluated all patterns (Aadhaar Verhoeff, Payment Card Luhn, Bank Account, PAN, Email, Phone) and found zero matches.
          </p>
        </div>
      );
    }

    return (
      <div className="space-y-3">
        {findings.map((f, idx) => {
          const typeBadge = getPiiTypeBadge(f.pii_type);
          const TypeIcon = typeBadge.icon;

          // Checksum status text & color
          let checksumBadge = null;
          if (f.checksum_valid === true) {
            const algoName = f.pii_type === 'AADHAAR' ? 'Verhoeff (D5)' : f.pii_type === 'CARD' ? 'Luhn (Mod-10)' : 'Valid';
            checksumBadge = (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/60 text-emerald-300 border border-emerald-800/60">
                <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                {algoName} Valid
              </span>
            );
          } else if (f.checksum_valid === false) {
            checksumBadge = (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-950/60 text-rose-300 border border-rose-800/60">
                <AlertCircle className="w-3 h-3 text-rose-400" />
                Checksum Failed
              </span>
            );
          } else {
            checksumBadge = (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-slate-800/80 text-slate-400 border border-slate-700/60">
                Context / Structural
              </span>
            );
          }

          return (
            <div
              key={f.id || idx}
              className="p-3.5 bg-slate-950 border border-slate-800/80 rounded-lg space-y-2 hover:border-slate-700 transition"
            >
              {/* Top row: Type Badge, Masked Value, Severity, Checksum */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span
                    className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-semibold border ${typeBadge.color}`}
                  >
                    <TypeIcon className="w-3.5 h-3.5" />
                    {typeBadge.label}
                  </span>
                  <span className="font-mono text-sm font-bold text-white bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                    {f.masked_value}
                  </span>
                </div>

                <div className="flex items-center gap-2">
                  {checksumBadge}
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${getSeverityClass(
                      f.severity
                    )}`}
                  >
                    {f.severity}
                  </span>
                </div>
              </div>

              {/* Middle row: Context Snippet */}
              {f.context_snippet && (
                <div className="text-xs text-slate-300 font-mono bg-slate-900/80 p-2 rounded border border-slate-800/60 leading-relaxed">
                  <span className="text-slate-500 text-[10px] uppercase font-sans font-semibold mr-1.5 block sm:inline">
                    Context:
                  </span>
                  <span>"{f.context_snippet}"</span>
                </div>
              )}

              {/* Bottom row: Detection details & confidence */}
              <div className="flex items-center justify-between text-[11px] text-slate-500 font-mono pt-1">
                <span>
                  Method: <strong className="text-slate-400">{f.detection_method}</strong>
                </span>
                <div className="flex items-center gap-2">
                  <span>Confidence:</span>
                  <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-brand-500 rounded-full"
                      style={{ width: `${Math.round((f.confidence || 0.9) * 100)}%` }}
                    />
                  </div>
                  <span className="text-brand-400 font-bold">
                    {Math.round((f.confidence || 0.9) * 100)}%
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    );
  };

  // Sub-component: Renders Deterministic Privacy Risk Gauge & Breakdown Card
  const renderRiskScoreCard = (doc) => {
    if (!doc) return null;
    const score = typeof doc.risk_score === 'number' ? doc.risk_score : 0.0;
    const level = doc.risk_level || (score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW');
    const badge = getRiskLevelBadge(level);
    const explanation = doc.score_explanation || {};
    const factors = explanation.contributing_factors || [];
    const compoundBoost = explanation.compound_boost_percentage || 0;

    return (
      <div className={`p-4 rounded-xl border ${badge.color} bg-slate-950/90 space-y-3.5 transition-all`}>
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/60 pb-3">
          <div className="flex items-center gap-2.5">
            <div className={`p-2 rounded-lg bg-slate-900 border border-slate-800 ${badge.textColor}`}>
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[11px] uppercase font-mono tracking-wider text-slate-400">
                Deterministic Privacy Risk Score (v{doc.scoring_version || '1.0'})
              </span>
              <div className="flex items-baseline gap-2">
                <span className={`text-2xl font-bold font-mono ${badge.textColor}`}>
                  {score.toFixed(1)}
                </span>
                <span className="text-xs text-slate-500 font-mono">/ 100</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {compoundBoost > 0 && (
              <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-mono font-semibold bg-rose-950/80 text-rose-300 border border-rose-800/70">
                <Zap className="w-3 h-3 text-rose-400" />
                +{compoundBoost}% Compound Boost
              </span>
            )}
            <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold tracking-wide uppercase border ${badge.color}`}>
              {badge.label}
            </span>
          </div>
        </div>

        {/* Progress Bar Gauge */}
        <div className="space-y-1">
          <div className="w-full h-2.5 bg-slate-800/90 rounded-full overflow-hidden p-0.5">
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

        {/* Contributing Factors & Explanations */}
        {factors.length > 0 && (
          <div className="space-y-1.5 pt-1 border-t border-slate-800/50">
            <span className="text-[11px] uppercase font-mono font-semibold text-slate-400 tracking-wider">
              Explainability Breakdown:
            </span>
            <ul className="space-y-1 text-xs text-slate-300">
              {factors.map((factor, fIdx) => (
                <li key={fIdx} className="flex items-start gap-2">
                  <span className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${badge.barColor}`} />
                  <span className="leading-snug">{factor}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 border-b border-slate-800 pb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="px-2 py-0.5 text-xs font-mono font-medium rounded bg-brand-500/10 text-brand-400 border border-brand-500/20">
              Phase 4 Engine
            </span>
            <span className="text-xs text-slate-500 font-mono">
              Verhoeff (D5) • Luhn (Mod-10) • Contextual Validation • Centralized Masking
            </span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white flex items-center gap-2">
            <FileText className="w-8 h-8 text-brand-500" />
            Document Upload & PII Detection
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Extract document content, detect sensitive PII, run mathematical checksum validation, and protect identity data with centralized masking.
          </p>
        </div>

        {/* Ephemeral Guarantee Badge */}
        <div className="flex items-center gap-3 p-3 bg-slate-900/80 border border-slate-800 rounded-lg text-xs text-slate-300">
          <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0" />
          <div>
            <p className="font-semibold text-white">Ephemeral Storage Guarantee</p>
            <p className="text-slate-400">Source files unlinked immediately via `finally` block.</p>
          </div>
        </div>
      </div>

      {/* Main Grid: Upload Zone & Latest Extracted Document */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Upload Column (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          <div className="card space-y-4">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <Upload className="w-5 h-5 text-brand-400" />
              Upload Source Document
            </h2>

            {/* Error / Success Notifications */}
            {uploadError && (
              <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/60 text-rose-300 text-xs flex items-start gap-2 animate-fadeIn">
                <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
                <div className="flex-1">
                  <p className="font-semibold">Validation / Extraction Error</p>
                  <p className="mt-0.5">{uploadError}</p>
                </div>
                <button onClick={() => setUploadError(null)} className="text-rose-400 hover:text-white">
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}

            {uploadSuccess && (
              <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-xs flex items-start gap-2 animate-fadeIn">
                <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5 text-emerald-400" />
                <div className="flex-1">
                  <p className="font-semibold">Detection Complete</p>
                  <p className="mt-0.5">{uploadSuccess}</p>
                </div>
                <button onClick={() => setUploadSuccess(null)} className="text-emerald-400 hover:text-white">
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            )}

            {/* Drag & Drop Form */}
            <form onSubmit={handleUpload} className="space-y-4">
              <div
                className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-all ${
                  dragActive
                    ? 'border-brand-500 bg-brand-500/10 scale-[1.01]'
                    : 'border-slate-700 hover:border-slate-600 bg-slate-900/40'
                }`}
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  className="hidden"
                  accept=".pdf,.png,.jpg,.jpeg,.txt"
                  onChange={handleFileChange}
                  disabled={isUploading}
                />

                <div className="flex flex-col items-center justify-center space-y-3">
                  <div className="w-12 h-12 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-brand-400 shadow-md">
                    <Upload className="w-6 h-6" />
                  </div>
                  <div>
                    <p className="text-sm font-medium text-slate-200">
                      Click to upload or drag & drop file
                    </p>
                    <p className="text-xs text-slate-500 mt-1">
                      PDF, PNG, JPG, JPEG, or TXT (Max 10 MB)
                    </p>
                  </div>
                  <div className="flex flex-wrap justify-center gap-1.5 pt-2">
                    {['PDF', 'PNG', 'JPG', 'TXT'].map((ext) => (
                      <span
                        key={ext}
                        className="px-2 py-0.5 text-[10px] font-mono font-medium rounded bg-slate-800 text-slate-300 border border-slate-700"
                      >
                        .{ext.toLowerCase()}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Selected File Details Bar */}
              {selectedFile && (
                <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg flex items-center justify-between gap-3 animate-fadeIn">
                  <div className="flex items-center gap-2.5 overflow-hidden">
                    <div className="p-2 rounded bg-brand-500/10 text-brand-400 shrink-0">
                      {selectedFile.type.includes('image') ? (
                        <ImageIcon className="w-4 h-4" />
                      ) : (
                        <FileText className="w-4 h-4" />
                      )}
                    </div>
                    <div className="overflow-hidden">
                      <p className="text-xs font-medium text-white truncate">{selectedFile.name}</p>
                      <p className="text-[10px] text-slate-400 font-mono">
                        {formatFileSize(selectedFile.size)} • {selectedFile.name.split('.').pop()?.toUpperCase()}
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedFile(null);
                      if (fileInputRef.current) fileInputRef.current.value = '';
                    }}
                    disabled={isUploading}
                    className="p-1 text-slate-400 hover:text-rose-400 transition"
                  >
                    <X className="w-4 h-4" />
                  </button>
                </div>
              )}

              {/* Upload Progress Bar */}
              {isUploading && (
                <div className="space-y-1.5 animate-fadeIn">
                  <div className="flex justify-between text-xs text-slate-400 font-mono">
                    <span className="flex items-center gap-1.5">
                      <RefreshCw className="w-3.5 h-3.5 animate-spin text-brand-400" />
                      Extracting text & analyzing PII...
                    </span>
                    <span>{uploadProgress}%</span>
                  </div>
                  <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-brand-500 transition-all duration-300 rounded-full"
                      style={{ width: `${uploadProgress}%` }}
                    />
                  </div>
                </div>
              )}

              {/* Submit Button */}
              <button
                type="submit"
                disabled={!selectedFile || isUploading}
                className="w-full btn btn-primary flex items-center justify-center gap-2"
              >
                {isUploading ? (
                  <>
                    <LoadingSpinner size="sm" />
                    <span>Analyzing Sensitive Data...</span>
                  </>
                ) : (
                  <>
                    <FileCheck className="w-4 h-4" />
                    <span>Scan Document for PII</span>
                  </>
                )}
              </button>
            </form>
          </div>

          {/* Validation Engine Specifications Card */}
          <div className="card space-y-3 text-xs text-slate-400">
            <h3 className="font-semibold text-white flex items-center gap-1.5">
              <HardDrive className="w-4 h-4 text-brand-400" />
              PII Validation Engine Rules
            </h3>
            <ul className="space-y-2 list-disc list-inside text-slate-400">
              <li>
                <strong className="text-slate-300">Aadhaar (UIDAI):</strong> Dihedral group $D_5$ Verhoeff checksum algorithm; rejects non-conforming 12-digit integers.
              </li>
              <li>
                <strong className="text-slate-300">Payment Cards:</strong> Mod-10 Luhn checksum algorithm across Visa, Mastercard, RuPay, and Amex formats.
              </li>
              <li>
                <strong className="text-slate-300">Bank Accounts:</strong> Mandatory contextual keyword gating (A/C, account, IFSC) to avoid false positives.
              </li>
              <li>
                <strong className="text-slate-300">PAN Cards:</strong> Indian tax structure evaluation with 4th-character entity verification (Person, Company, etc.).
              </li>
              <li>
                <strong className="text-slate-300">Zero Raw PII Storage:</strong> All detected values masked before database persistence, logs, or UI delivery.
              </li>
            </ul>
          </div>
        </div>

        {/* Extracted Text & Active Result Column (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          <div className="card space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <FileCode className="w-5 h-5 text-brand-400" />
                <h2 className="text-lg font-semibold text-white">Active Document Analysis</h2>
              </div>

              {latestDocument && (
                <div className="flex items-center gap-2">
                  {/* Tabs toggle */}
                  <div className="flex rounded-lg bg-slate-900 p-0.5 border border-slate-800 text-xs">
                    <button
                      onClick={() => setActiveTab('findings')}
                      className={`px-3 py-1 rounded-md font-medium transition flex items-center gap-1.5 ${
                        activeTab === 'findings'
                          ? 'bg-brand-500 text-white shadow'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      <ShieldAlert className="w-3.5 h-3.5" />
                      <span>PII Findings ({latestDocument.findings?.length || latestDocument.pii_count || 0})</span>
                    </button>
                    <button
                      onClick={() => setActiveTab('text')}
                      className={`px-3 py-1 rounded-md font-medium transition flex items-center gap-1.5 ${
                        activeTab === 'text'
                          ? 'bg-brand-500 text-white shadow'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      <FileText className="w-3.5 h-3.5" />
                      <span>Extracted Text</span>
                    </button>
                  </div>

                  <button
                    onClick={() =>
                      handleDownloadText(
                        latestDocument.original_filename,
                        latestDocument.extracted_text || latestDocument.extracted_text_preview || ''
                      )
                    }
                    className="btn btn-secondary py-1 px-2 text-xs flex items-center gap-1"
                    title="Download Extracted Text"
                  >
                    <Download className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>

            {latestDocument ? (
              <div className="space-y-4 animate-fadeIn">
                {/* Metadata Pill Bar */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-slate-500 block">Filename</span>
                    <span className="font-medium text-white truncate block" title={latestDocument.original_filename}>
                      {latestDocument.original_filename}
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-slate-500 block">Total PII Items</span>
                    <span className="font-bold text-white block flex items-center gap-1.5">
                      <span className={`w-2 h-2 rounded-full ${latestDocument.pii_count > 0 ? 'bg-amber-400' : 'bg-emerald-400'}`} />
                      {latestDocument.pii_count || latestDocument.findings?.length || 0} findings
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-slate-500 block">High/Critical Risk</span>
                    <span className="font-bold text-rose-400 block">
                      {latestDocument.high_risk_count || 0} critical/high
                    </span>
                  </div>
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                    <span className="text-slate-500 block">Extraction Method</span>
                    <span
                      className={`inline-flex items-center gap-1 font-mono text-[11px] font-semibold ${
                        latestDocument.ocr_applied ? 'text-cyan-400' : 'text-emerald-400'
                      }`}
                    >
                      {latestDocument.ocr_applied ? 'OCR Pipeline' : 'Direct Text'}
                    </span>
                  </div>
                </div>

                {/* SHA-256 Hash Row */}
                <div className="p-2.5 rounded bg-slate-900 border border-slate-800 flex items-center justify-between gap-2 text-xs font-mono">
                  <div className="flex items-center gap-2 overflow-hidden">
                    <span className="text-slate-500 shrink-0">SHA-256:</span>
                    <span className="text-slate-300 truncate" title={latestDocument.file_hash}>
                      {latestDocument.file_hash}
                    </span>
                  </div>
                  <button
                    onClick={() => handleCopy(latestDocument.file_hash, 'hash')}
                    className="p-1 text-slate-400 hover:text-white transition shrink-0"
                    title="Copy full hash"
                  >
                    {copiedHash ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>

                {/* Deterministic Privacy Risk Score Gauge Card */}
                {renderRiskScoreCard(latestDocument)}

                {/* Tab Body: Findings vs Extracted Text */}
                {activeTab === 'findings' ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                      <span>Detected Sensitive Entities (Masked for Storage):</span>
                      <span>{latestDocument.findings?.length || 0} item(s)</span>
                    </div>
                    {renderFindingsList(latestDocument.findings || [])}
                  </div>
                ) : (
                  <div>
                    <div className="flex justify-between items-center text-xs text-slate-400 mb-1.5 font-mono">
                      <span>Extracted Content:</span>
                      <span>
                        {(latestDocument.extracted_text || latestDocument.extracted_text_preview || '').length} characters
                      </span>
                    </div>
                    <div className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg max-h-80 overflow-y-auto font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed select-all">
                      {latestDocument.extracted_text || latestDocument.extracted_text_preview || (
                        <span className="italic text-slate-600">No textual content was detected in this document.</span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="py-16 text-center text-slate-500 space-y-2">
                <FileText className="w-12 h-12 mx-auto stroke-[1.2] text-slate-600" />
                <p className="text-sm font-medium text-slate-400">No document currently active</p>
                <p className="text-xs max-w-sm mx-auto text-slate-500">
                  Select a PDF, PNG, JPG, or TXT file on the left and click "Scan Document for PII" to extract content and detect sensitive data.
                </p>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Scanned Documents History Table */}
      <div className="card space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 border-b border-slate-800 pb-3">
          <div>
            <h2 className="text-lg font-semibold text-white flex items-center gap-2">
              <FileCheck className="w-5 h-5 text-brand-400" />
              Scanned Documents History
            </h2>
            <p className="text-xs text-slate-400">
              Isolated user history of scanned documents with persistent PII finding counts. Total documents: {totalDocuments}
            </p>
          </div>
          <button
            onClick={() => fetchDocumentHistory(currentPage)}
            disabled={isLoadingHistory}
            className="btn btn-secondary py-1 px-3 text-xs flex items-center gap-1.5 self-start sm:self-auto"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoadingHistory ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>

        {isLoadingHistory ? (
          <div className="py-12 flex justify-center">
            <LoadingSpinner size="md" />
          </div>
        ) : documents.length === 0 ? (
          <div className="py-12 text-center text-slate-500 text-sm">
            No scanned documents found in your account history.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-900/60 text-slate-400 font-mono uppercase text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-3">Filename</th>
                  <th className="py-3 px-3">Format</th>
                  <th className="py-3 px-3">Size</th>
                  <th className="py-3 px-3">PII Findings</th>
                  <th className="py-3 px-3">Privacy Risk</th>
                  <th className="py-3 px-3">Uploaded</th>
                  <th className="py-3 px-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {documents.map((doc) => {
                  const score = typeof doc.risk_score === 'number' ? doc.risk_score : 0.0;
                  const level = doc.risk_level || (score >= 75 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 25 ? 'MEDIUM' : 'LOW');
                  const badge = getRiskLevelBadge(level);

                  return (
                    <tr key={doc.id} className="hover:bg-slate-900/30 transition">
                      <td className="py-3 px-3 font-medium text-white max-w-[200px] truncate" title={doc.original_filename}>
                        {doc.original_filename}
                      </td>
                      <td className="py-3 px-3">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 border border-slate-700 uppercase">
                          {doc.file_type}
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono text-slate-400">{formatFileSize(doc.file_size)}</td>
                      <td className="py-3 px-3">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-mono text-[11px] font-semibold border ${
                            (doc.pii_count || 0) > 0
                              ? 'bg-amber-950/60 text-amber-300 border-amber-800/50'
                              : 'bg-emerald-950/60 text-emerald-300 border-emerald-800/50'
                          }`}
                        >
                          <ShieldAlert className="w-3 h-3" />
                          {doc.pii_count || 0} detected
                        </span>
                      </td>
                      <td className="py-3 px-3">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-mono text-[11px] font-bold border ${badge.color}`}
                        >
                          <span>{score.toFixed(1)}</span>
                          <span className="text-[9px] uppercase tracking-wider">{level}</span>
                        </span>
                      </td>
                      <td className="py-3 px-3 font-mono text-slate-400">
                        {doc.created_at ? new Date(doc.created_at).toLocaleString() : '—'}
                      </td>
                    <td className="py-3 px-3 text-right space-x-2">
                      <button
                        onClick={() => handleViewDocument(doc.id)}
                        className="btn btn-secondary py-1 px-2 text-[11px] inline-flex items-center gap-1"
                        title="View PII findings and document text"
                      >
                        <Eye className="w-3 h-3 text-brand-400" />
                        <span>Inspect</span>
                      </button>
                      <button
                        onClick={() => handleDeleteDocument(doc.id, doc.original_filename)}
                        className="p-1 text-slate-500 hover:text-rose-400 transition"
                        title="Delete document record"
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

        {/* Pagination controls */}
        {totalDocuments > pageSize && (
          <div className="flex items-center justify-between pt-3 border-t border-slate-800 text-xs text-slate-400">
            <span>
              Showing {documents.length} of {totalDocuments} documents
            </span>
            <div className="flex gap-2">
              <button
                disabled={currentPage <= 1 || isLoadingHistory}
                onClick={() => fetchDocumentHistory(currentPage - 1)}
                className="btn btn-secondary py-1 px-2.5 text-xs disabled:opacity-40"
              >
                Previous
              </button>
              <button
                disabled={currentPage * pageSize >= totalDocuments || isLoadingHistory}
                onClick={() => fetchDocumentHistory(currentPage + 1)}
                className="btn btn-secondary py-1 px-2.5 text-xs disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Modal: Document Detail Viewer with Findings & Text Tabs */}
      {viewingDocument && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-2xl animate-fadeIn max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <h3 className="text-base font-semibold text-white">{viewingDocument.original_filename}</h3>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  SHA-256: {viewingDocument.file_hash}
                </p>
              </div>
              <button
                onClick={() => setViewingDocument(null)}
                className="p-1 text-slate-400 hover:text-white transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Quick Metrics Bar */}
            <div className="grid grid-cols-3 gap-2 text-xs font-mono text-slate-400 bg-slate-950 p-2.5 rounded border border-slate-800">
              <div>
                PII Count: <span className="text-white font-bold">{viewingDocument.pii_count || viewingDocument.findings?.length || 0}</span>
              </div>
              <div>
                High Risk: <span className="text-rose-400 font-bold">{viewingDocument.high_risk_count || 0}</span>
              </div>
              <div>
                Method: <span className="text-white">{viewingDocument.ocr_applied ? 'OCR' : 'Direct Text'}</span>
              </div>
            </div>

            {/* Deterministic Privacy Risk Score Gauge Card */}
            {renderRiskScoreCard(viewingDocument)}

            {/* Tab selector */}
            <div className="flex border-b border-slate-800 text-xs">
              <button
                onClick={() => setModalTab('findings')}
                className={`py-2 px-4 border-b-2 font-medium flex items-center gap-1.5 transition ${
                  modalTab === 'findings'
                    ? 'border-brand-500 text-white font-semibold'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>Detected Findings ({viewingDocument.findings?.length || viewingDocument.pii_count || 0})</span>
              </button>
              <button
                onClick={() => setModalTab('text')}
                className={`py-2 px-4 border-b-2 font-medium flex items-center gap-1.5 transition ${
                  modalTab === 'text'
                    ? 'border-brand-500 text-white font-semibold'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Extracted Text</span>
              </button>
            </div>

            {/* Modal Scrollable Body */}
            <div className="flex-1 overflow-y-auto space-y-3 pr-1">
              {modalTab === 'findings' ? (
                renderFindingsList(viewingDocument.findings || [])
              ) : (
                <div className="space-y-1.5">
                  <div className="flex justify-between items-center text-xs text-slate-400 font-mono">
                    <span>Extracted Text Content:</span>
                    <span>
                      {(viewingDocument.extracted_text || viewingDocument.extracted_text_preview || '').length} characters
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg max-h-72 overflow-y-auto font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed select-all">
                    {viewingDocument.extracted_text || viewingDocument.extracted_text_preview || (
                      <span className="italic text-slate-600">No textual content detected.</span>
                    )}
                  </div>
                </div>
              )}
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-slate-800">
              <button
                onClick={() =>
                  handleDownloadText(
                    viewingDocument.original_filename,
                    viewingDocument.extracted_text || viewingDocument.extracted_text_preview || ''
                  )
                }
                className="btn btn-secondary py-1.5 px-3 text-xs flex items-center gap-1.5"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download .txt</span>
              </button>
              <button
                onClick={() =>
                  handleCopy(viewingDocument.extracted_text || viewingDocument.extracted_text_preview || '')
                }
                className="btn btn-primary py-1.5 px-3 text-xs flex items-center gap-1.5"
              >
                <Copy className="w-3.5 h-3.5" />
                <span>Copy Text</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
