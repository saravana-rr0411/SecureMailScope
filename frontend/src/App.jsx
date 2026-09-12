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

  // Authoritative Backend Synchronization: Load stored analysis history from Supabase
  useEffect(() => {
    let isMounted = true;
    async function syncCapturesFromBackend() {
      try {
        const res = await fetch(`${API_BASE}/api/captures`);
        if (res.ok) {
          const backendCaptures = await res.json();
          if (isMounted && Array.isArray(backendCaptures) && backendCaptures.length > 0) {
            setAnalyzedPcaps(backendCaptures);
            setCurrentCaptureId((prevId) => {
              // Preserve current selection if it exists in backend results, otherwise default to first
              if (prevId && backendCaptures.some((c) => (c.capture_id || c.id || c.filename) === prevId)) {
                return prevId;
              }
              return backendCaptures[0].capture_id || backendCaptures[0].id || backendCaptures[0].filename || null;
            });
            // Update local cache without treating it as authoritative
            try {
              localStorage.setItem('sms_analyzed_pcaps', JSON.stringify(backendCaptures));
            } catch {}
          }
        }
      } catch (err) {
        console.warn("Backend captures synchronization skipped:", err);
      }
    }
    syncCapturesFromBackend();
    return () => {
      isMounted = false;
    };
  }, []);

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
        if (API_BASE) {
          res = await fetch("/api/pcap/analyze", {
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
        setError("Failed to connect to SecureMailScope backend. Please verify that the backend server is running.");
      } else {
        setError(msg || "Failed to analyze PCAP capture. Is the backend server running?");
      }
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleGenerateAuthenticCapture = async (onStepChange, options = {}) => {
    setIsAnalyzing(true);
    setError(null);

    const updateStep = (step) => {
      if (typeof onStepChange === 'function') onStepChange(step);
    };

    const isGmail = options.profile === 'gmail';
    const payload = isGmail ? {
      protocol: 'SMTP',
      profile: 'gmail',
      port: 587,
      target_host: 'smtp.gmail.com',
      duration_seconds: options.duration_seconds || 40
    } : {
      protocol: 'SMTP',
      profile: 'secure_tls12'
    };

    try {
      if (isGmail) {
        updateStep('listening'); // "Capture started. Send your Gmail email through Outlook now."
      } else {
        updateStep('traffic'); // "Generating Authentic Traffic..."
      }

      // All capture requests go through the backend, which routes to the agent
      // via WebSocket Bridge (production) or direct HTTP (local dev fallback).
      // This avoids the HTTPS→HTTP localhost block in Safari/Chrome.
      const urls = [];
      if (API_BASE) urls.push(`${API_BASE}/api/capture/generate-authentic`);
      urls.push("/api/capture/generate-authentic");
      if (typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')) {
        urls.push("http://127.0.0.1:8000/api/capture/generate-authentic");
      }

      let res = null;
      let lastErr = null;

      let timerCapturing = null;
      let timerAnalyzing = null;
      if (!isGmail) {
        timerCapturing = setTimeout(() => updateStep('capturing'), 600);
        timerAnalyzing = setTimeout(() => updateStep('analyzing'), 1400);
      }

      for (const url of urls) {
        try {
          res = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          });
          // An HTTP response was received (e.g. 200, 400, 404, 500).
          // Do NOT retry fallback URLs — the endpoint is reachable.
          if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            lastErr = new Error(errData.detail || `Server returned HTTP ${res.status}`);
          }
          break;
        } catch (fetchErr) {
          // Network / transport error (e.g. connection refused, network failure).
          // Retry the next fallback URL.
          lastErr = fetchErr;
        }
      }

      if (timerCapturing) clearTimeout(timerCapturing);
      if (timerAnalyzing) clearTimeout(timerAnalyzing);

      if (!res || !res.ok) {
        throw lastErr || new Error("Failed to generate authentic PCAP from Capture Agent.");
      }

      updateStep('analyzing');
      const data = await res.json();

      const captureId = data.capture_id || data.id || data.filename || `pcap_${Date.now()}`;
      const analyzedAt = data.analyzed_at || new Date().toISOString();

      const newCapture = {
        ...data,
        capture_id: captureId,
        analyzed_at: analyzedAt
      };

      // Automatically trigger browser download for the genuine PCAP generated by tcpdump
      let downloadedFilename = null;
      if (data.pcap_base64) {
        try {
          const binaryString = window.atob(data.pcap_base64);
          const len = binaryString.length;
          const bytes = new Uint8Array(len);
          for (let i = 0; i < len; i++) {
            bytes[i] = binaryString.charCodeAt(i);
          }
          const blob = new Blob([bytes], { type: 'application/vnd.tcpdump.pcap' });
          const downloadUrl = window.URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = downloadUrl;
          downloadedFilename = data.pcap_filename || data.filename || `authentic_smtp_tls_${Date.now()}.pcap`;
          link.download = downloadedFilename;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          setTimeout(() => window.URL.revokeObjectURL(downloadUrl), 2000);
        } catch (dlErr) {
          console.error("Automatic PCAP download failed:", dlErr);
        }
      } else if (data.pcap_download_url) {
        try {
          const dlUrl = data.pcap_download_url.startsWith('http')
            ? data.pcap_download_url
            : `${API_BASE || ''}${data.pcap_download_url}`;
          const dlRes = await fetch(dlUrl);
          if (dlRes.ok) {
            const blob = await dlRes.blob();
            const downloadUrl = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = downloadUrl;
            downloadedFilename = data.pcap_filename || data.filename || `authentic_smtp_tls_${Date.now()}.pcap`;
            link.download = downloadedFilename;
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            setTimeout(() => window.URL.revokeObjectURL(downloadUrl), 2000);
          }
        } catch (dlErr) {
          console.error("Fallback PCAP download failed:", dlErr);
        }
      }

      setAnalyzedPcaps((prev) => {
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
          // Omit large binary base64 from localStorage to prevent quota exhaustion
          const storageList = updatedList.map(({ pcap_base64, ...rest }) => rest);
          localStorage.setItem('sms_analyzed_pcaps', JSON.stringify(storageList));
        } catch (err) {
          console.warn("Storage quota exceeded saving analyzed PCAPs:", err);
        }
        return updatedList;
      });

      setCurrentCaptureId(captureId);
      try {
        const { pcap_base64, ...storageCapture } = newCapture;
        localStorage.setItem('sms_current_capture_id', captureId);
        localStorage.setItem('sms_current_capture', JSON.stringify(storageCapture));
      } catch {}

      updateStep('complete');
      showToast(
        downloadedFilename
          ? `Authentic PCAP downloaded (${downloadedFilename}) & analysis complete!`
          : `Authentic PCAP captured & analyzed: ${newCapture.filename} (${newCapture.sessions?.length || 0} sessions)`
      );
      return newCapture;
    } catch (err) {
      updateStep('ready');
      const msg = err?.message || '';
      if (
        msg.toLowerCase().includes('load failed') ||
        msg.toLowerCase().includes('failed to fetch') ||
        msg.toLowerCase().includes('networkerror')
      ) {
        setError("Failed to connect to SecureMailScope backend. Please verify that the backend server is running.");
      } else if (
        msg.toLowerCase().includes('contains no packets') ||
        msg.toLowerCase().includes('no smtp submission packets') ||
        msg.toLowerCase().includes('empty or invalid pcap')
      ) {
        setError("No SMTP submission packets detected on TCP port 587 during the capture window. Verify Outlook is configured to send Gmail SMTP through port 587.");
      } else {
        setError(msg || "Failed to generate authentic PCAP.");
      }
      throw err;
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleCaptureGmail = async (onStepChange) => {
    return handleGenerateAuthenticCapture(onStepChange, {
      profile: 'gmail',
      protocol: 'SMTP',
      port: 587,
      target_host: 'smtp.gmail.com',
      duration_seconds: 40
    });
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
              onGenerateAuthenticCapture={handleGenerateAuthenticCapture}
              onCaptureGmail={handleCaptureGmail}
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
