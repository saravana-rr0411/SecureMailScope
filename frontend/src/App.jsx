import React, { useState, useEffect, useMemo, useRef } from 'react';
import TopAppBar from './components/TopAppBar';
import SidebarNav from './components/SidebarNav';
import ExecutiveDashboard from './components/ExecutiveDashboard';
import OverviewScreen from './components/OverviewScreen';
import ForensicsScreen from './components/ForensicsScreen';
import { exportJSON, exportXLSX, exportPDF, exportHTML } from './reportGenerator';
import { deriveSecurityStats } from './utils/securityStats';

const API_BASE = import.meta.env.VITE_API_BASE ?? "";
const STORAGE_VERSION = "v4.0_canonical_sync";

// Safely initialize / migrate localStorage
try {
  if (typeof window !== 'undefined' && window.localStorage) {
    if (localStorage.getItem('sms_storage_version') !== STORAGE_VERSION) {
      // Clear obsolete pre-sync demo caches, preserving storage version
      localStorage.removeItem('sms_current_capture');
      localStorage.removeItem('sms_recent_captures');
      // If analyzed_pcaps contains stale August 31 demo captures, clean them
      const raw = localStorage.getItem('sms_analyzed_pcaps');
      if (raw) {
        try {
          const parsed = JSON.parse(raw);
          if (Array.isArray(parsed)) {
            const sanitized = parsed.filter((p) => {
              const str = JSON.stringify(p);
              return !str.includes('2026-08-31') && !str.includes('tls_test_email.pcap');
            });
            if (sanitized.length > 0) {
              localStorage.setItem('sms_analyzed_pcaps', JSON.stringify(sanitized));
            } else {
              localStorage.removeItem('sms_analyzed_pcaps');
            }
          }
        } catch {
          localStorage.removeItem('sms_analyzed_pcaps');
        }
      }
      localStorage.setItem('sms_storage_version', STORAGE_VERSION);
    }
  }
} catch {
  // Ignore localStorage errors
}

export default function App() {
  const [activeTab, setActiveTab] = useState('executive'); // 'executive' | 'overview' | 'forensics'

  // CANONICAL STATE: analyzedPcaps[] is the single source of truth for the PCAP collection
  const [analyzedPcaps, setAnalyzedPcaps] = useState(() => {
    try {
      const saved = localStorage.getItem('sms_analyzed_pcaps');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          // Filter out any obsolete stale August 31 or mock demo records
          return parsed.filter((p) => {
            const str = JSON.stringify(p);
            return !str.includes('2026-08-31') && !str.includes('tls_test_email.pcap');
          });
        }
      }
    } catch {
      // Ignore parse failure
    }
    return [];
  });

  // CANONICAL STATE: ID of the currently selected capture
  const [currentCaptureId, setCurrentCaptureId] = useState(() => {
    try {
      const savedId = localStorage.getItem('sms_current_capture_id');
      if (savedId) return savedId;
      const savedList = localStorage.getItem('sms_analyzed_pcaps');
      if (savedList) {
        const parsed = JSON.parse(savedList);
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed[0].capture_id || parsed[0].id || parsed[0].filename || null;
        }
      }
    } catch {}
    return null;
  });

  // DERIVED STATE: currentCapture derived strictly from analyzedPcaps[] and currentCaptureId
  const currentCapture = useMemo(() => {
    if (analyzedPcaps.length === 0) return null;
    if (currentCaptureId) {
      const found = analyzedPcaps.find(
        (p) => (p.capture_id || p.id || p.filename) === currentCaptureId
      );
      if (found) return found;
    }
    return analyzedPcaps[0] || null;
  }, [analyzedPcaps, currentCaptureId]);

  // Selected session within the current capture
  const [selectedSessionId, setSelectedSessionId] = useState(null);
  const activeSessionId = useMemo(() => {
    if (!currentCapture?.sessions?.length) return null;
    if (selectedSessionId && currentCapture.sessions.some((s) => s.session_id === selectedSessionId)) {
      return selectedSessionId;
    }
    return currentCapture.sessions[0]?.session_id || null;
  }, [currentCapture, selectedSessionId]);

  // DERIVED STATE: Shared single-source security statistics
  const securityStats = useMemo(() => deriveSecurityStats(analyzedPcaps), [analyzedPcaps]);

  // Dark mode theme state with localStorage persistence & system preference fallback
  const [theme, setTheme] = useState(() => {
    try {
      const savedTheme = localStorage.getItem('sms_theme');
      if (savedTheme === 'dark' || savedTheme === 'light') {
        return savedTheme;
      }
      if (typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
        return 'dark';
      }
    } catch {
      // Ignore localStorage errors
    }
    return 'light';
  });

  useEffect(() => {
    try {
      if (theme === 'dark') {
        document.documentElement.classList.add('dark');
        document.body.classList.add('dark');
      } else {
        document.documentElement.classList.remove('dark');
        document.body.classList.remove('dark');
      }
      localStorage.setItem('sms_theme', theme);
    } catch {
      // Ignore storage errors
    }
  }, [theme]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState(null);
  const [toastMessage, setToastMessage] = useState(null);
  const [isExportOpen, setIsExportOpen] = useState(false);
  const [dragOver, setDragOver] = useState(false);

  const fileInputRef = useRef(null);
  const exportRef = useRef(null);

  // Show temporary toast notification
  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage(null);
    }, 3500);
  };

  // Close export dropdown when clicking outside
  useEffect(() => {
    function handleClickOutside(event) {
      if (exportRef.current && !exportRef.current.contains(event.target)) {
        setIsExportOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleSelectCapture = (cap) => {
    if (!cap) return;
    const capId = cap.capture_id || cap.id || cap.filename;
    setCurrentCaptureId(capId);
    try {
      localStorage.setItem('sms_current_capture_id', capId);
    } catch {
      // Storage quota exceeded or unavailable
    }
    if (cap.sessions && cap.sessions.length > 0) {
      setSelectedSessionId(cap.sessions[0].session_id);
    }
  };

  const handleFileUpload = async (file) => {
    if (!file) return;
    const name = file.name.toLowerCase();
    if (!name.endsWith('.pcap') && !name.endsWith('.pcapng')) {
      setError("Unsupported file format. Please upload a standard .pcap or .pcapng network capture.");
      return;
    }

    setIsAnalyzing(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      let res;
      try {
        res = await fetch(`${API_BASE}/api/pcap/analyze`, {
          method: 'POST',
          body: formData
        });
      } catch (primaryErr) {
        // If relative URL via Vite proxy was unreachable and API_BASE was empty, fallback to direct port 8000
        if (!API_BASE) {
          res = await fetch("http://127.0.0.1:8000/api/pcap/analyze", {
            method: 'POST',
            body: formData
          });
        } else {
          throw primaryErr;
        }
      }

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Analysis failed with HTTP ${res.status}`);
      }

      const data = await res.json();
      const captureId = data.capture_id || data.id || data.filename || `pcap_${Date.now()}`;
      const analyzedAt = data.analyzed_at || new Date().toISOString();

      const newCapture = {
        ...data,
        capture_id: captureId,
        analyzed_at: analyzedAt
      };

      setAnalyzedPcaps((prev) => {
        // Replace existing capture if same ID or filename, otherwise prepend
        const filtered = prev.filter((p) => {
          const pId = p.capture_id || p.id;
          const pName = (p.filename || '').toLowerCase();
          const newName = (newCapture.filename || '').toLowerCase();
          if (pId && captureId && pId === captureId) return false;
          if (pName && newName && pName === newName) return false;
          return true;
        });
        const updatedList = [newCapture, ...filtered];
        try {
          localStorage.setItem('sms_analyzed_pcaps', JSON.stringify(updatedList));
        } catch (err) {
          console.warn("Storage quota exceeded saving analyzed PCAPs:", err);
        }
        return updatedList;
      });

      setCurrentCaptureId(captureId);
      try {
        localStorage.setItem('sms_current_capture_id', captureId);
        localStorage.setItem('sms_current_capture', JSON.stringify(newCapture));
      } catch {}

      showToast(`PCAP analyzed: ${newCapture.filename} (${newCapture.sessions?.length || 0} sessions)`);
    } catch (err) {
      const msg = err?.message || '';
      if (
        msg.toLowerCase().includes('load failed') ||
        msg.toLowerCase().includes('failed to fetch') ||
        msg.toLowerCase().includes('networkerror')
      ) {
        setError("Failed to connect to SecureMailScope backend at http://127.0.0.1:8000. Please verify that the backend server is running.");
      } else {
        setError(msg || "Failed to analyze PCAP capture. Is the backend server running?");
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleExport = (type) => {
    if (!currentCapture) {
      setError("No analysis data available to export.");
      return;
    }
    try {
      if (type === 'json') {
        exportJSON(currentCapture);
      } else if (type === 'xlsx') {
        exportXLSX(currentCapture);
      } else if (type === 'pdf') {
        exportPDF(currentCapture);
      } else if (type === 'html') {
        exportHTML(currentCapture);
      }
      showToast(`Exported ${type.toUpperCase()} forensic report.`);
    } catch (err) {
      setError(`Export failed: ${err.message || err}`);
    } finally {
      setIsExportOpen(false);
    }
  };

  const triggerUpload = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  // Drag and drop handlers
  const handleDragOver = (e) => {
    e.preventDefault();
    setDragOver(true);
  };
  const handleDragLeave = () => setDragOver(false);
  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  return (
    <div
      className="min-h-screen bg-[#F4F7FB] dark:bg-[#0b1320] text-[#0b1c30] dark:text-slate-100 font-sans antialiased transition-colors duration-150"
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* Hidden File Input */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".pcap,.pcapng"
        className="hidden"
        onChange={(e) => {
          if (e.target.files && e.target.files[0]) {
            handleFileUpload(e.target.files[0]);
          }
        }}
      />

      {/* Drag & Drop Overlay */}
      {dragOver && (
        <div className="fixed inset-0 z-50 bg-[#006591]/20 dark:bg-sky-950/40 backdrop-blur-xs border-4 border-dashed border-[#006591] dark:border-sky-500 flex items-center justify-center pointer-events-none">
          <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-6 rounded-2xl shadow-xl flex items-center gap-3">
            <span className="material-symbols-outlined text-4xl text-[#006591] dark:text-sky-400">cloud_upload</span>
            <div>
              <div className="font-bold text-slate-900 dark:text-white text-base">Drop PCAP file here</div>
              <div className="text-xs text-slate-500 dark:text-slate-400">Passive network capture ingestion</div>
            </div>
          </div>
        </div>
      )}

      {/* Top Application Bar */}
      <TopAppBar theme={theme} onToggleTheme={toggleTheme} />

      {/* Left Sidebar Navigation */}
      <SidebarNav activeTab={activeTab} onTabChange={setActiveTab} />

      {/* Main Viewport Content */}
      <div className="pl-60 pt-16 min-h-screen bg-[#F4F7FB] dark:bg-[#0b1320] transition-colors duration-150">
        <main className="max-w-7xl mx-auto p-6 sm:p-8">
          {/* Toast Message Notification */}
          {toastMessage && (
            <div className="fixed bottom-6 right-6 z-50 bg-slate-900 dark:bg-slate-800 text-white border border-slate-800 dark:border-slate-700 px-4 py-3 rounded-xl shadow-lg flex items-center gap-2.5 text-xs animate-in fade-in slide-in-from-bottom-2">
              <span className="material-symbols-outlined text-[18px] text-emerald-400">check_circle</span>
              <span>{toastMessage}</span>
            </div>
          )}

          {/* Error Banner */}
          {error && (
            <div className="mb-6 p-4 rounded-xl bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900/60 text-rose-800 dark:text-rose-300 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2.5">
                <span className="material-symbols-outlined text-rose-600 dark:text-rose-400 text-[20px]">error</span>
                <span className="font-medium">{error}</span>
              </div>
              <button
                onClick={() => setError(null)}
                className="text-rose-600 dark:text-rose-400 hover:text-rose-800 dark:hover:text-rose-200 font-bold ml-4 cursor-pointer"
              >
                ✕
              </button>
            </div>
          )}

          {/* Analyzing / Uploading Overlay State */}
          {isAnalyzing && (
            <div className="mb-6 p-6 rounded-xl bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col sm:flex-row items-center justify-between gap-4">
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-xl bg-blue-50 dark:bg-slate-800 border border-blue-200 dark:border-slate-700 flex items-center justify-center text-[#006591] dark:text-sky-400">
                  <span className="material-symbols-outlined text-2xl animate-spin">refresh</span>
                </div>
                <div>
                  <div className="font-bold text-slate-900 dark:text-white text-sm">
                    Analyzing PCAP...
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400 font-sans mt-0.5 font-normal">
                    Reconstructing TCP streams • Parsing STARTTLS / TLS records • Evaluating AI Risk
                  </div>
                </div>
              </div>
              <span className="font-sans text-xs text-[#006591] dark:text-sky-400 bg-blue-50 dark:bg-slate-800 px-3 py-1.5 rounded-lg border border-blue-200 dark:border-slate-700 font-semibold animate-pulse">
                Passive Forensics Active
              </span>
            </div>
          )}

          {/* Screen 1: Executive Security Dashboard */}
          {activeTab === 'executive' && (
            <ExecutiveDashboard
              capture={currentCapture}
              analyzedPcaps={analyzedPcaps}
              stats={securityStats}
              onSelectCapture={handleSelectCapture}
              onNavigate={setActiveTab}
              onTriggerUpload={triggerUpload}
              theme={theme}
            />
          )}

          {/* Screen 2: Overview Screen */}
          {activeTab === 'overview' && (
            <OverviewScreen
              capture={currentCapture}
              analyzedPcaps={analyzedPcaps}
              stats={securityStats}
              onSelectCapture={handleSelectCapture}
              onNavigate={setActiveTab}
              onTriggerUpload={triggerUpload}
              theme={theme}
            />
          )}

          {/* Screen 3: Unified Forensics & AI Risk Screen */}
          {(activeTab === 'forensics' || activeTab === 'sessions' || activeTab === 'ai_risk') && (
            <ForensicsScreen
              capture={currentCapture}
              selectedSessionId={activeSessionId}
              onSelectSession={setSelectedSessionId}
              onExport={handleExport}
              isExportOpen={isExportOpen}
              setIsExportOpen={setIsExportOpen}
              exportRef={exportRef}
              theme={theme}
            />
          )}
        </main>
      </div>
    </div>
  );
}
