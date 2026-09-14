import React, { useState, useEffect } from 'react';
import { deriveSecurityStats, getPcapSecurityPosture, scoreToRiskTier, getAiRiskTier } from '../utils/securityStats';

const NPCAP_OFFICIAL_URL = "https://npcap.com/#download";

function getAgentDownloadUrl(platform) {
  const apiBase = import.meta.env.VITE_API_BASE ?? '';
  if (platform === 'windows') {
    return apiBase ? `${apiBase}/api/agent/download/windows` : '/api/agent/download/windows';
  }
  return apiBase ? `${apiBase}/api/agent/download/macos` : '/api/agent/download/macos';
}

function detectClientOS() {
  if (typeof window === 'undefined') return 'windows';
  const ua = (navigator.userAgent || '').toLowerCase();
  const plat = (navigator.platform || '').toLowerCase();
  if (ua.includes('win') || plat.includes('win')) return 'windows';
  if (ua.includes('mac') || plat.includes('mac')) return 'macos';
  return 'windows';
}

export default function OverviewScreen({
  capture,
  analyzedPcaps = [],
  stats,
  onSelectCapture,
  onNavigate,
  onTriggerUpload,
  onGenerateAuthenticCapture,
  onCaptureGmail,
  theme = 'light'
}) {
  const [hoveredPoint, setHoveredPoint] = useState(null);
  const [captureStep, setCaptureStep] = useState('ready'); // 'ready' | 'traffic' | 'capturing' | 'analyzing' | 'complete'
  const [gmailCaptureStep, setGmailCaptureStep] = useState('ready'); // 'ready' | 'listening' | 'analyzing' | 'complete'
  const [gmailCountdown, setGmailCountdown] = useState(40);

  // Local Capture Agent connectivity state (checked live against GET http://127.0.0.1:9000/health)
  const [agentStatus, setAgentStatus] = useState('checking'); // 'checking' | 'connected' | 'not_detected'
  const [agentInfo, setAgentInfo] = useState(null);
  const [showAgentModal, setShowAgentModal] = useState(false);
  const [isRetryingAgent, setIsRetryingAgent] = useState(false);
  const clientOS = detectClientOS();
  const [selectedOsTab, setSelectedOsTab] = useState(() => detectClientOS());

  // Determine connected agent OS and check for mismatch with browser platform
  const connectedOs = agentInfo?.os ? (
    agentInfo.os.toLowerCase().includes('mac') || agentInfo.os === 'darwin'
      ? 'macOS'
      : (agentInfo.os.toLowerCase().includes('win') ? 'Windows' : agentInfo.os)
  ) : null;
  const isOsMismatch = agentStatus === 'connected' && connectedOs && (
    (clientOS === 'windows' && connectedOs !== 'Windows') ||
    (clientOS === 'macos' && connectedOs !== 'macOS')
  );

  // Countdown timer effect for Gmail live capture window
  useEffect(() => {
    let timer = null;
    if (gmailCaptureStep === 'listening') {
      timer = setInterval(() => {
        setGmailCountdown((prev) => {
          if (prev <= 1) {
            clearInterval(timer);
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [gmailCaptureStep]);

  // Check agent connectivity:
  // 1. Authoritative check: Local Capture Agent on http://127.0.0.1:9000/health
  //    (This directly probes the Capture Agent running on the same PC as the browser)
  // 2. Fallback check: Backend AgentHub (/api/agent/status?client_os=...)
  //    (Only accepted if the remote agent matches the client browser OS)
  const checkAgentHealth = async () => {
    // Priority 1: Probe local machine Capture Agent at http://127.0.0.1:9000/health
    try {
      const localController = new AbortController();
      const localTimeoutId = setTimeout(() => localController.abort(), 2000);
      const res = await fetch('http://127.0.0.1:9000/health', {
        method: 'GET',
        signal: localController.signal
      });
      clearTimeout(localTimeoutId);
      if (res.ok) {
        const data = await res.json();
        if (data && (data.status === 'OK' || data.can_capture !== undefined)) {
          setAgentStatus('connected');
          setAgentInfo(data);
          return true;
        }
      }
    } catch {
      // Local agent on 127.0.0.1:9000 not reachable or blocked by browser policy
    }

    // Priority 2: Fallback to backend WebSocket Hub status for matching OS agent
    const apiBase = import.meta.env.VITE_API_BASE ?? '';
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      const backendUrls = [];
      const queryParam = `?client_os=${encodeURIComponent(clientOS)}`;
      if (apiBase) backendUrls.push(`${apiBase}/api/agent/status${queryParam}`);
      backendUrls.push(`/api/agent/status${queryParam}`);
      if (typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')) {
        backendUrls.push(`http://127.0.0.1:8000/api/agent/status${queryParam}`);
      }

      for (const url of backendUrls) {
        try {
          const res = await fetch(url, {
            method: 'GET',
            headers: {
              'X-Client-OS': clientOS,
            },
            signal: controller.signal
          });
          clearTimeout(timeoutId);
          if (res.ok) {
            const data = await res.json();
            // Only accept remote agent status if it matches our client OS!
            // Do NOT let an unrelated remote agent override local availability.
            if (data && data.status === 'connected' && data.matched_client_os) {
              setAgentStatus('connected');
              setAgentInfo({
                version: data.version || '1.0.0',
                os: data.os,
                can_capture: data.can_capture,
                status: 'OK',
              });
              return true;
            }
          }
        } catch {
          // Try next URL
        }
      }
      clearTimeout(timeoutId);
    } catch {
      // Silently handle errors
    }

    setAgentStatus('not_detected');
    setAgentInfo(null);
    return false;
  };

  // Check agent health on initial mount, on window focus, and periodically
  useEffect(() => {
    checkAgentHealth();

    const handleFocus = () => {
      checkAgentHealth();
    };
    window.addEventListener('focus', handleFocus);

    const interval = setInterval(() => {
      checkAgentHealth();
    }, 15000);

    return () => {
      window.removeEventListener('focus', handleFocus);
      clearInterval(interval);
    };
  }, []);

  // SINGLE SOURCE OF TRUTH: All metrics derive directly from analyzedPcaps[]
  const pcapList = Array.isArray(analyzedPcaps) && analyzedPcaps.length > 0
    ? analyzedPcaps
    : (capture ? [capture] : []);
  const securityStats = stats || deriveSecurityStats(pcapList);

  const totalReports = securityStats.total;
  const secureReports = securityStats.secure;
  const insecureReports = securityStats.insecure;
  const securePct = securityStats.securePct;
  const insecurePct = securityStats.insecurePct;
  const fleetAvgRisk = securityStats.fleetAvgRisk;

  // Authoritative Selected Capture: explicitly passed `capture` or the first from pcapList
  const activeCapture = capture || (pcapList.length > 0 ? pcapList[0] : null);
  const activeSession = activeCapture?.sessions?.[0] || null;

  // Selected Capture AI Risk Score & Classification (Centralized Thresholds)
  const currentScoreVal = activeCapture?.ai_risk?.score != null
    ? Number(activeCapture.ai_risk.score)
    : (activeSession?.ai_risk?.score != null
      ? Number(activeSession.ai_risk.score)
      : null);
  const currentScore = currentScoreVal != null ? currentScoreVal.toFixed(1) : "—";
  const currentScoreNum = currentScoreVal != null ? currentScoreVal : 0;

  const currentLabel = activeCapture?.ai_risk
    ? getAiRiskTier(activeCapture.ai_risk)
    : (activeSession?.ai_risk
      ? getAiRiskTier(activeSession.ai_risk)
      : (currentScoreVal != null ? scoreToRiskTier(currentScoreNum) : "NONE"));

  // Selected Capture Security Posture & Status
  const pcapPosture = activeCapture ? getPcapSecurityPosture(activeCapture) : null;
  const isSecureCapture = pcapPosture === 'SECURE';
  const isIncompleteCapture = pcapPosture === 'INCOMPLETE';
  const postureScore = activeCapture?.posture?.score
    ?? activeSession?.posture?.score
    ?? (activeCapture ? (isSecureCapture ? 100 : (isIncompleteCapture ? 100 : (currentScoreNum > 50 ? 25 : 75))) : null);
  const statusText = isSecureCapture ? 'SECURE' : (isIncompleteCapture ? 'INCOMPLETE' : (pcapPosture ? 'INSECURE' : '—'));

  let riskBadgeColor = "bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800";
  let riskDotColor = "bg-emerald-500";
  let riskGaugeColor = "#059669";
  let postureLabel = "MINIMAL RISK DETECTED";

  if (!activeCapture || currentScoreVal == null) {
    riskBadgeColor = "bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border-slate-200 dark:border-slate-700";
    riskDotColor = "bg-slate-400";
    riskGaugeColor = theme === 'dark' ? '#334155' : '#cbd5e1';
    postureLabel = "NO CAPTURE SELECTED";
  } else if (currentLabel === "CRITICAL") {
    riskBadgeColor = "bg-rose-100 dark:bg-rose-950/60 text-rose-800 dark:text-rose-300 border-rose-300 dark:border-rose-800";
    riskDotColor = "bg-rose-700";
    riskGaugeColor = "#991b1b";
    postureLabel = "CRITICAL RISK DETECTED";
  } else if (currentLabel === "HIGH") {
    riskBadgeColor = "bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-800";
    riskDotColor = "bg-rose-600";
    riskGaugeColor = "#dc2626";
    postureLabel = "HIGH RISK DETECTED";
  } else if (currentLabel === "MODERATE") {
    riskBadgeColor = "bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800";
    riskDotColor = "bg-amber-500";
    riskGaugeColor = "#d97706";
    postureLabel = "MODERATE RISK DETECTED";
  }

  // Circular gauge for Current Capture AI Risk: r=66, circumference = 2 * PI * 66 ≈ 414.69
  const circumference = 414.69;
  const clampedScore = activeCapture && currentScoreVal != null ? Math.max(0, Math.min(100, currentScoreNum)) : 0;
  const dashOffset = Number((circumference - (circumference * clampedScore) / 100).toFixed(2));

  // Build Chronological Trend Data (oldest to newest capture)
  const trendData = [...pcapList].reverse().map((p, idx) => {
    const pSessions = p.sessions || [];
    const pScoreVal = p.ai_risk?.score != null
      ? Number(p.ai_risk.score)
      : (pSessions[0]?.ai_risk?.score != null
        ? Number(pSessions[0].ai_risk.score)
        : (pSessions.length > 0
          ? Number((pSessions.reduce((acc, s) => acc + (s.ai_risk?.score ?? 0), 0) / pSessions.length).toFixed(1))
          : 0));
    const pScore = pScoreVal != null ? Number(pScoreVal).toFixed(1) : "0.0";
    const pNum = Number(pScore) || 0;
    const pLabel = p.ai_risk ? getAiRiskTier(p.ai_risk) : scoreToRiskTier(pNum);

    return {
      captureRef: p,
      filename: p.filename || `Capture #${idx + 1}`,
      order: idx + 1,
      score: pScore,
      label: pLabel,
      packets: p.total_packets ?? (pSessions.length * 148),
      sessionsCount: pSessions.length,
      protocol: pSessions[0]?.protocol || "SMTP"
    };
  });

  // SVG Chart Geometry with dynamic horizontal scaling for arbitrary PCAP counts
  const numPoints = trendData.length;
  const minPointWidth = 68;
  const basePlotW = 660; // default plot width when few captures exist
  const isScrollable = numPoints > 1 && (numPoints - 1) * minPointWidth > basePlotW;
  const plotW = numPoints <= 1
    ? basePlotW
    : Math.max(basePlotW, (numPoints - 1) * minPointWidth);

  const padLeft = 55;
  const padRight = 45;
  const padTop = 28;
  const padBottom = 38;
  const chartW = padLeft + plotW + padRight;
  const chartH = 190;
  const plotH = chartH - padTop - padBottom;

  const getY = (val) => padTop + (1 - Math.max(0, Math.min(100, val)) / 100) * plotH;

  const points = trendData.map((d, i) => {
    const x = numPoints === 1
      ? Math.round(padLeft + plotW / 2)
      : Math.round(padLeft + (i / (numPoints - 1)) * plotW);
    const y = Math.round(getY(d.score));
    return { ...d, x, y };
  });

  const linePath = points.length > 1
    ? points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x.toFixed(1)} ${p.y.toFixed(1)}`).join(' ')
    : '';

  const areaPath = points.length > 1
    ? `${linePath} L ${points[points.length - 1].x.toFixed(1)} ${getY(0).toFixed(1)} L ${points[0].x.toFixed(1)} ${getY(0).toFixed(1)} Z`
    : '';

  return (
    <div className="w-full max-w-6xl mx-auto flex flex-col gap-6">
      {/* ==================================================================== */}
      {/* PAGE HEADER: TITLE & TOOLBAR CONTROLS                                */}
      {/* ==================================================================== */}
      <header className="bg-white dark:bg-slate-900 rounded-xl p-5 sm:p-6 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-colors duration-150">
        <div className="flex flex-col gap-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="material-symbols-outlined text-[18px] text-[#006591] dark:text-sky-400">analytics</span>
            <span className="text-[11px] font-bold uppercase tracking-wider text-[#006591] dark:text-sky-400">Enterprise Telemetry</span>
            <span className="text-slate-300 dark:text-slate-600 hidden sm:inline">·</span>
            {agentStatus === 'connected' ? (
              <div
                id="local-agent-status-badge"
                title={isOsMismatch ? `Connected agent is on ${connectedOs}, but your browser is on ${clientOS === 'windows' ? 'Windows' : 'macOS'}. Install local agent to capture from this PC.` : `SecureMailScope Capture Agent v${agentInfo?.version || '1.0'} active on ${connectedOs || 'this computer'}`}
                className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border font-sans text-[10px] font-semibold tracking-wider uppercase transition-colors ${
                  isOsMismatch
                    ? 'bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-800 text-amber-700 dark:text-amber-300'
                    : 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800 text-emerald-700 dark:text-emerald-300'
                }`}
              >
                <span className={`w-1.5 h-1.5 rounded-full ${isOsMismatch ? 'bg-amber-500' : 'bg-emerald-500'} animate-pulse`}></span>
                <span>
                  {clientOS === 'windows'
                    ? (connectedOs === 'Windows' ? 'AGENT CONNECTED (WINDOWS)' : 'WINDOWS AGENT NEEDED')
                    : clientOS === 'macos'
                    ? (connectedOs === 'macOS' ? 'AGENT CONNECTED (MACOS)' : 'MACOS AGENT NEEDED')
                    : (isOsMismatch ? `${clientOS.toUpperCase()} AGENT NEEDED` : `AGENT CONNECTED (${(connectedOs || 'ACTIVE').toUpperCase()})`)}
                </span>
              </div>
            ) : agentStatus === 'checking' ? (
              <div
                id="local-agent-status-badge"
                className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 font-sans text-[10px] font-semibold text-slate-500 dark:text-slate-400 tracking-wider uppercase transition-colors"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-slate-400 animate-pulse"></span>
                <span>Checking Agent...</span>
              </div>
            ) : (
              <button
                id="local-agent-status-badge"
                type="button"
                onClick={() => setShowAgentModal(true)}
                title="Local capture agent is not running. Click to view setup guidance."
                className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-100 dark:bg-slate-800/80 border border-slate-200 dark:border-slate-700 font-sans text-[10px] font-medium text-slate-500 dark:text-slate-400 tracking-wider uppercase hover:bg-slate-200 dark:hover:bg-slate-700 hover:text-slate-700 dark:hover:text-slate-200 transition-colors cursor-pointer"
              >
                <span className="w-1.5 h-1.5 rounded-full bg-slate-400"></span>
                <span>{clientOS === 'windows' ? 'WINDOWS AGENT NEEDED' : clientOS === 'macos' ? 'MACOS AGENT NEEDED' : 'LOCAL AGENT NEEDED'}</span>
              </button>
            )}
          </div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">Cryptographic Security Overview</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400">Cross-capture cryptographic security posture and AI risk trajectory</p>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto flex-wrap">
          <button
            onClick={onTriggerUpload}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 dark:bg-slate-800 text-white hover:bg-slate-800 dark:hover:bg-slate-700 active:bg-slate-950 dark:active:bg-slate-600 text-xs font-semibold shadow-xs transition-all duration-150 cursor-pointer"
          >
            <span className="material-symbols-outlined text-[16px]">upload_file</span>
            <span>Upload PCAP</span>
          </button>
          {onGenerateAuthenticCapture && (
            <button
              id="btn-generate-authentic-pcap"
              onClick={async () => {
                if (captureStep !== 'ready' && captureStep !== 'complete') return;
                // If local agent is not detected, check one more time before prompting modal
                if (agentStatus === 'not_detected') {
                  const isOnline = await checkAgentHealth();
                  if (!isOnline) {
                    setShowAgentModal(true);
                    return;
                  }
                }
                try {
                  await onGenerateAuthenticCapture(setCaptureStep);
                  setTimeout(() => setCaptureStep('ready'), 3000);
                } catch {
                  setCaptureStep('ready');
                }
              }}
              disabled={captureStep !== 'ready' && captureStep !== 'complete'}
              title="Trigger dedicated Capture Agent to generate real SMTP + TLS traffic and capture genuine packets via tcpdump"
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-[#006591] hover:bg-[#005174] active:bg-[#003d57] text-white text-xs font-semibold shadow-xs transition-all duration-150 cursor-pointer disabled:opacity-75 disabled:cursor-not-allowed"
            >
              <span className={`material-symbols-outlined text-[16px] ${captureStep !== 'ready' && captureStep !== 'complete' ? 'animate-spin' : ''}`}>
                {captureStep === 'traffic' && 'sync'}
                {captureStep === 'capturing' && 'sensors'}
                {captureStep === 'analyzing' && 'query_stats'}
                {captureStep === 'complete' && 'check_circle'}
                {(captureStep === 'ready' || (!['traffic', 'capturing', 'analyzing', 'complete'].includes(captureStep))) && 'network_check'}
              </span>
              <span>
                {captureStep === 'traffic' && 'Generating Authentic Traffic...'}
                {captureStep === 'capturing' && 'Capturing Packets...'}
                {captureStep === 'analyzing' && 'Analyzing PCAP...'}
                {captureStep === 'complete' && 'PCAP Downloaded & Complete!'}
                {captureStep === 'ready' && 'Generate Authentic PCAP'}
              </span>
            </button>
          )}

          {onCaptureGmail && (
            <button
              id="btn-capture-real-gmail"
              onClick={async () => {
                if (gmailCaptureStep !== 'ready' && gmailCaptureStep !== 'complete') return;
                setGmailCountdown(40);
                if (agentStatus === 'not_detected') {
                  const isOnline = await checkAgentHealth();
                  if (!isOnline) {
                    setShowAgentModal(true);
                    return;
                  }
                }
                try {
                  await onCaptureGmail(setGmailCaptureStep);
                  setTimeout(() => {
                    setGmailCaptureStep('ready');
                    setGmailCountdown(0);
                  }, 4000);
                } catch {
                  setGmailCaptureStep('ready');
                  setGmailCountdown(0);
                }
              }}
              disabled={gmailCaptureStep !== 'ready' && gmailCaptureStep !== 'complete'}
              title="Start live TCP ports 587 / 465 capture on active network interface and send email via your configured desktop mail client"
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-[#ea4335] hover:bg-[#d93025] active:bg-[#c5221f] text-white text-xs font-semibold shadow-xs transition-all duration-150 cursor-pointer disabled:opacity-75 disabled:cursor-not-allowed"
            >
              <span className={`material-symbols-outlined text-[16px] ${gmailCaptureStep !== 'ready' && gmailCaptureStep !== 'complete' ? 'animate-spin' : ''}`}>
                {gmailCaptureStep === 'listening' && 'sensors'}
                {gmailCaptureStep === 'analyzing' && 'query_stats'}
                {gmailCaptureStep === 'complete' && 'check_circle'}
                {(gmailCaptureStep === 'ready' || (!['listening', 'analyzing', 'complete'].includes(gmailCaptureStep))) && 'mail'}
              </span>
              <span>
                {gmailCaptureStep === 'listening' && `Listening on ports 587 / 465 (${gmailCountdown}s)...`}
                {gmailCaptureStep === 'analyzing' && 'Analyzing Gmail Traffic...'}
                {gmailCaptureStep === 'complete' && 'Gmail PCAP Complete!'}
                {gmailCaptureStep === 'ready' && 'Capture Real Gmail SMTP'}
              </span>
            </button>
          )}
        </div>
      </header>

      {/* OS MISMATCH WARNING BANNER (Shown when connected agent OS differs from client browser OS) */}
      {isOsMismatch && (
        <div
          id="agent-os-mismatch-banner"
          className="p-4 sm:p-5 rounded-xl border border-amber-300 dark:border-amber-700/60 bg-amber-50/90 dark:bg-amber-950/40 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-xs text-xs text-amber-950 dark:text-amber-200 transition-colors"
        >
          <div className="flex items-start gap-3">
            <span className="material-symbols-outlined text-[22px] text-amber-600 dark:text-amber-400 shrink-0 mt-0.5">warning</span>
            <div>
              <p className="font-bold text-sm text-slate-900 dark:text-white">
                Connected Agent is on {connectedOs} — {clientOS === 'windows' ? 'Windows' : 'macOS'} Agent Needed
              </p>
              <p className="text-slate-600 dark:text-slate-300 text-xs mt-0.5 leading-relaxed">
                The SecureMailScope hub detects an active Capture Agent connected from <strong>{connectedOs}</strong>, but your browser is running on <strong>{clientOS === 'windows' ? 'Windows' : 'macOS'}</strong>. To sniff genuine SMTP packets from this PC, install and run the local {clientOS === 'windows' ? 'Windows' : 'macOS'} Capture Agent.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <a
              href={getAgentDownloadUrl(clientOS)}
              download={clientOS === 'windows' ? 'SecureMailScopeCaptureAgent-1.0.1-Setup.exe' : 'SecureMailScopeCaptureAgent-1.0.0.pkg'}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#006591] hover:bg-[#005174] text-white text-xs font-semibold shadow-2xs transition-all cursor-pointer"
            >
              <span className="material-symbols-outlined text-[15px]">download</span>
              <span>Download {clientOS === 'windows' ? 'Windows' : 'macOS'} Agent</span>
            </a>
            <button
              type="button"
              onClick={() => {
                setSelectedOsTab(clientOS);
                setShowAgentModal(true);
              }}
              className="px-2.5 py-1.5 rounded-lg bg-amber-200/80 dark:bg-amber-800 text-amber-950 dark:text-amber-100 font-semibold text-xs hover:bg-amber-300 transition-colors cursor-pointer"
            >
              Setup Guide
            </button>
          </div>
        </div>
      )}

      {/* CAPTURE AGENT SETUP GUIDANCE BANNER (Shown when agent is not detected) */}
      {agentStatus === 'not_detected' && (
        <div
          id="agent-setup-guidance-banner"
          className="p-4 sm:p-5 rounded-xl border border-amber-200 dark:border-amber-800/70 bg-amber-50/80 dark:bg-amber-950/30 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xs transition-colors"
        >
          <div className="flex items-start gap-3.5">
            <div className="w-9 h-9 rounded-xl bg-amber-100 dark:bg-amber-900/50 border border-amber-200 dark:border-amber-700/60 flex items-center justify-center text-amber-700 dark:text-amber-400 shrink-0 mt-0.5">
              <span className="material-symbols-outlined text-[20px]">sensors_off</span>
            </div>
            <div className="flex flex-col gap-1">
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-xs sm:text-sm font-bold text-slate-900 dark:text-white">
                  {clientOS === 'windows' ? 'Windows Capture Agent Required' : 'macOS Capture Agent Required'}
                </h2>
                <span className="px-1.5 py-0.5 text-[10px] font-semibold uppercase rounded bg-amber-200/80 dark:bg-amber-900/70 text-amber-900 dark:text-amber-300">
                  {clientOS === 'windows' ? 'Windows' : 'macOS'}
                </span>
              </div>
              <p className="text-xs text-slate-600 dark:text-slate-300 max-w-2xl leading-relaxed">
                {clientOS === 'windows'
                  ? 'Npcap is required for genuine Windows packet capture. Download and install Npcap first, then run the SecureMailScope Capture Agent installer.'
                  : 'Install the SecureMailScope Capture Agent background service to record genuine email packets on port 587 and 2525.'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap shrink-0">
            {clientOS === 'windows' ? (
              <>
                <a
                  id="btn-download-npcap"
                  href={NPCAP_OFFICIAL_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                  title="Download official Npcap packet capture driver for Windows (npcap.com)"
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 active:bg-amber-800 text-white text-xs font-semibold shadow-2xs transition-all cursor-pointer"
                >
                  <span className="material-symbols-outlined text-[15px]">open_in_new</span>
                  <span>Download Npcap</span>
                </a>
                <a
                  id="btn-download-windows-agent"
                  href={getAgentDownloadUrl('windows')}
                  download="SecureMailScopeCaptureAgent-1.0.1-Setup.exe"
                  title="Download SecureMailScope Capture Agent for Windows (.exe)"
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#006591] hover:bg-[#005174] active:bg-[#003d57] text-white text-xs font-semibold shadow-2xs transition-all cursor-pointer"
                >
                  <span className="material-symbols-outlined text-[15px]">download</span>
                  <span>Download Windows Capture Agent</span>
                </a>
              </>
            ) : (
              <a
                id="btn-download-macos-agent"
                href={getAgentDownloadUrl('macos')}
                download="SecureMailScopeCaptureAgent-1.0.0.pkg"
                title="Download SecureMailScope Capture Agent for macOS (.pkg)"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#006591] hover:bg-[#005174] active:bg-[#003d57] text-white text-xs font-semibold shadow-2xs transition-all cursor-pointer"
              >
                <span className="material-symbols-outlined text-[15px]">download</span>
                <span>Download macOS Agent (.pkg)</span>
              </a>
            )}
            <button
              id="btn-check-agent-connection"
              type="button"
              onClick={async () => {
                setIsRetryingAgent(true);
                await checkAgentHealth();
                setIsRetryingAgent(false);
              }}
              disabled={isRetryingAgent}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 border border-slate-300 dark:border-slate-700 text-xs font-medium shadow-2xs transition-all cursor-pointer disabled:opacity-60"
            >
              <span className={`material-symbols-outlined text-[15px] ${isRetryingAgent ? 'animate-spin' : ''}`}>
                {isRetryingAgent ? 'progress_activity' : 'refresh'}
              </span>
              <span>Check Connection</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setSelectedOsTab(clientOS);
                setShowAgentModal(true);
              }}
              className="px-2.5 py-1.5 text-xs text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200 font-medium underline underline-offset-2 cursor-pointer"
            >
              Setup Guide
            </button>
          </div>
        </div>
      )}

      {/* Active Live Gmail Capture Notification Banner */}
      {gmailCaptureStep === 'listening' && (
        <div id="gmail-capture-active-banner" className="mb-4 p-4 rounded-xl border border-red-300 dark:border-red-700/60 bg-red-50/90 dark:bg-red-950/40 flex items-center justify-between gap-4 shadow-sm animate-pulse">
          <div className="flex items-center gap-3">
            <span className="relative flex h-3.5 w-3.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-3.5 w-3.5 bg-red-500"></span>
            </span>
            <div>
              <p className="text-xs font-bold text-red-950 dark:text-red-200">
                Capture started. Send an email using your configured desktop mail client now.
              </p>
              <p className="text-[11px] text-red-700 dark:text-red-300">
                Actively filtering TCP ports 587 and 465 for outbound Gmail SMTP submission traffic.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-1.5 font-mono text-xs font-bold px-3 py-1.5 rounded-lg bg-white dark:bg-red-900/60 text-red-700 dark:text-red-200 border border-red-200 dark:border-red-700 shadow-xs">
            <span className="material-symbols-outlined text-[15px] animate-spin">timer</span>
            <span>{gmailCountdown}s window</span>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TOP / FIRST HALF: OVERALL SECURITY RISK & KEY METRICS                */}
      {/* ==================================================================== */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 sm:p-6 shadow-xs flex flex-col xl:flex-row items-stretch xl:items-center justify-between gap-6 xl:gap-8 transition-colors duration-150 max-w-full">
        {/* Left: Visually Dominant Overall Risk Score & Selected PCAP */}
        <div className="flex items-center gap-5 sm:gap-6 min-w-0 shrink">
          <div className="relative w-32 h-32 sm:w-36 sm:h-36 flex items-center justify-center shrink-0">
            <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 160 160">
              <circle cx="80" cy="80" fill="transparent" r="66" stroke={theme === 'dark' ? '#1e293b' : '#F1F5F9'} strokeWidth="10" />
              <circle
                cx="80"
                cy="80"
                fill="transparent"
                r="66"
                stroke={riskGaugeColor}
                strokeDasharray={circumference}
                strokeDashoffset={dashOffset}
                strokeLinecap="round"
                strokeWidth="10"
                className="transition-all duration-700 ease-out"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className="font-sans text-3xl sm:text-4xl font-bold text-slate-900 dark:text-white tracking-tight leading-none tabular-nums">
                {currentScore}
              </span>
              <span className="font-sans font-medium text-[10px] text-slate-400 dark:text-slate-500 mt-1">/ 100</span>
            </div>
          </div>

          <div className="flex flex-col gap-2 min-w-0">
            <div className="flex flex-col gap-0.5">
              <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 font-sans">
                Selected PCAP AI Risk
              </span>
              <span className="text-[10.5px] text-slate-500 dark:text-slate-400 font-normal font-sans">
                Secondary ML risk signal; does not override deterministic security findings.
              </span>
            </div>
            <div className="flex flex-wrap items-baseline gap-2">
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border tracking-wider uppercase font-sans inline-flex items-center gap-1.5 shadow-2xs ${riskBadgeColor}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${riskDotColor}`}></span>
                {activeCapture ? `${currentLabel} RISK` : 'NO CAPTURE'}
              </span>
              {activeCapture && (
                <span className={`px-2.5 py-0.5 rounded-full text-xs font-semibold border tracking-wider uppercase font-sans inline-flex items-center gap-1.5 shadow-2xs ${
                  isSecureCapture
                    ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800'
                    : 'bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-800'
                }`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${isSecureCapture ? 'bg-emerald-600' : 'bg-rose-600'}`}></span>
                  {statusText} {postureScore != null ? `(${postureScore}/100)` : ''}
                </span>
              )}
            </div>
            <div className="text-xs font-semibold text-slate-700 dark:text-slate-300 font-sans">
              {postureLabel}
            </div>
            <div className="flex items-center gap-2 flex-wrap min-w-0">
              <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 font-mono text-xs font-semibold text-slate-900 dark:text-white max-w-[200px] sm:max-w-xs truncate" title={activeCapture?.filename}>
                <span className="material-symbols-outlined text-[15px] text-[#006591] dark:text-sky-400 shrink-0">description</span>
                <span className="truncate">{activeCapture?.filename || 'No capture selected'}</span>
              </div>
              {(activeCapture?.pcap_base64 || activeCapture?.pcap_download_url || (activeCapture?.capture_source === 'AUTHENTIC_AUTO_CAPTURE' && activeCapture?.capture_id)) && (
                <button
                  type="button"
                  id="btn-download-selected-pcap"
                  onClick={() => {
                    const apiBase = import.meta.env.VITE_API_BASE ?? '';
                    if (activeCapture.pcap_base64) {
                      const binaryString = window.atob(activeCapture.pcap_base64);
                      const bytes = new Uint8Array(binaryString.length);
                      for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
                      const blob = new Blob([bytes], { type: 'application/vnd.tcpdump.pcap' });
                      const url = window.URL.createObjectURL(blob);
                      const a = document.createElement('a');
                      a.href = url;
                      a.download = activeCapture.pcap_filename || activeCapture.filename || 'authentic_capture.pcap';
                      document.body.appendChild(a);
                      a.click();
                      document.body.removeChild(a);
                      setTimeout(() => window.URL.revokeObjectURL(url), 1500);
                    } else {
                      const dlUrl = activeCapture.pcap_download_url
                        ? (activeCapture.pcap_download_url.startsWith('http') ? activeCapture.pcap_download_url : `${apiBase}${activeCapture.pcap_download_url}`)
                        : `${apiBase}/api/capture/download/${activeCapture.capture_id || activeCapture.filename}`;
                      window.open(dlUrl, '_blank');
                    }
                  }}
                  title="Download genuine .pcap file"
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 text-xs font-medium transition-colors cursor-pointer border border-slate-200 dark:border-slate-700 shadow-2xs"
                >
                  <span className="material-symbols-outlined text-[15px] text-[#006591] dark:text-sky-400">download</span>
                  <span>Download PCAP</span>
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Right: Clean Grid of 4 Key Metrics */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 sm:gap-3 w-full xl:max-w-2xl min-w-0">
          {/* Metric 1: Captures Analyzed */}
          <div className="p-3.5 sm:p-4 rounded-xl bg-slate-50/80 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 shadow-2xs hover:border-slate-300 dark:hover:border-slate-600 transition-all duration-150 flex flex-col justify-between min-w-0 h-full min-h-[112px] box-border">
            <div className="flex items-center gap-1.5 min-w-0">
              <span className="material-symbols-outlined text-[15px] text-slate-500 dark:text-slate-400 shrink-0">swap_calls</span>
              <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider font-sans truncate">
                Captures
              </span>
            </div>
            <div className="my-1.5 min-w-0">
              <span className="text-2xl sm:text-3xl font-bold text-slate-900 dark:text-white font-sans tabular-nums leading-tight tracking-tight">
                {totalReports}
              </span>
            </div>
            <div className="text-[11px] text-slate-400 dark:text-slate-500 font-sans font-medium truncate">
              Analysed
            </div>
          </div>

          {/* Metric 2: Secure Captures */}
          <div className="p-3.5 sm:p-4 rounded-xl bg-emerald-50/40 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-800/50 shadow-2xs hover:border-emerald-300 dark:hover:border-emerald-700 transition-all duration-150 flex flex-col justify-between min-w-0 h-full min-h-[112px] box-border">
            <div className="flex items-center gap-1.5 min-w-0">
              <span className="material-symbols-outlined text-[15px] text-emerald-700 dark:text-emerald-400 shrink-0">verified_user</span>
              <span className="text-[11px] font-semibold text-emerald-800 dark:text-emerald-400 uppercase tracking-wider font-sans truncate">
                Secure
              </span>
            </div>
            <div className="my-1.5 min-w-0">
              <span className="text-2xl sm:text-3xl font-bold text-emerald-700 dark:text-emerald-400 font-sans tabular-nums leading-tight tracking-tight">
                {secureReports}
              </span>
            </div>
            <div className="flex items-center gap-1.5 min-w-0">
              <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-100 dark:bg-emerald-900/60 text-emerald-800 dark:text-emerald-300 font-sans tabular-nums shrink-0">
                {securePct}%
              </span>
              <span className="text-[11px] text-emerald-700/80 dark:text-emerald-400/80 font-sans font-medium truncate">
                of total
              </span>
            </div>
          </div>

          {/* Metric 3: Insecure Captures */}
          <div className="p-3.5 sm:p-4 rounded-xl bg-rose-50/35 dark:bg-rose-950/20 border border-rose-200 dark:border-rose-800/50 shadow-2xs hover:border-rose-300 dark:hover:border-rose-700 transition-all duration-150 flex flex-col justify-between min-w-0 h-full min-h-[112px] box-border">
            <div className="flex items-center gap-1.5 min-w-0">
              <span className="material-symbols-outlined text-[15px] text-rose-700 dark:text-rose-400 shrink-0">gpp_maybe</span>
              <span className="text-[11px] font-semibold text-rose-800 dark:text-rose-400 uppercase tracking-wider font-sans truncate">
                Insecure
              </span>
            </div>
            <div className="my-1.5 min-w-0">
              <span className="text-2xl sm:text-3xl font-bold text-rose-700 dark:text-rose-400 font-sans tabular-nums leading-tight tracking-tight">
                {insecureReports}
              </span>
            </div>
            <div className="flex items-center gap-1.5 min-w-0">
              <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-rose-100 dark:bg-rose-900/60 text-rose-800 dark:text-rose-300 font-sans tabular-nums shrink-0">
                {insecurePct}%
              </span>
              <span className="text-[11px] text-rose-700/80 dark:text-rose-400/80 font-sans font-medium truncate">
                of total
              </span>
            </div>
          </div>

          {/* Metric 4: Historical Fleet Average AI Risk */}
          <div className="p-3.5 sm:p-4 rounded-xl bg-slate-50/80 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 shadow-2xs hover:border-slate-300 dark:hover:border-slate-600 transition-all duration-150 flex flex-col justify-between min-w-0 h-full min-h-[112px] box-border">
            <div className="flex items-center gap-1.5 min-w-0">
              <span className="material-symbols-outlined text-[15px] text-slate-500 dark:text-slate-400 shrink-0">hub</span>
              <span className="text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider font-sans truncate">
                Fleet Avg Risk
              </span>
            </div>
            <div className="my-1.5 min-w-0">
              <span className="text-2xl sm:text-3xl font-bold text-slate-900 dark:text-white font-sans tabular-nums leading-tight tracking-tight">
                {fleetAvgRisk != null ? fleetAvgRisk : "—"}
              </span>
            </div>
            <div className="text-[11px] text-slate-400 dark:text-slate-500 font-sans font-medium truncate">
              {totalReports} PCAPs
            </div>
          </div>
        </div>
      </section>

      {/* ==================================================================== */}
      {/* SECOND HALF: SECURITY RISK TREND (Dynamic SVG Line Chart)            */}
      {/* ==================================================================== */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 sm:p-6 shadow-xs flex flex-col gap-4 transition-colors duration-150 max-w-full overflow-hidden">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-100 dark:border-slate-800 gap-3">
          <div className="flex flex-col gap-0.5">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="material-symbols-outlined text-[18px] text-[#006591] dark:text-sky-400">trending_up</span>
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">Security Risk Trend</h2>
              {isScrollable && (
                <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700 shrink-0">
                  <span className="material-symbols-outlined text-[12px]">swap_horiz</span>
                  <span>{numPoints} Captures · Scroll</span>
                </span>
              )}
            </div>
            <span className="text-xs text-slate-500 dark:text-slate-400 font-normal">
              Chronological AI risk trajectory across analyzed captures
            </span>
          </div>

          {/* Trend Axis Guidance Legend */}
          <div className="flex items-center gap-4 text-xs font-medium shrink-0">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-600"></span>
              <span className="text-slate-700 dark:text-slate-300 text-[11px]">Low Risk (0–20)</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
              <span className="text-slate-700 dark:text-slate-300 text-[11px]">Moderate (21–50)</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-600"></span>
              <span className="text-slate-700 dark:text-slate-300 text-[11px]">High / Critical (&gt;50)</span>
            </div>
          </div>
        </div>

        {/* Dynamic SVG Chart or Empty State */}
        {trendData.length === 0 ? (
          <div className="h-48 flex flex-col items-center justify-center gap-1.5 text-slate-400 dark:text-slate-500 text-xs font-sans font-normal">
            <span className="material-symbols-outlined text-slate-300 dark:text-slate-600 text-2xl">query_stats</span>
            <span>No analyzed PCAP capture data available yet</span>
          </div>
        ) : (
          <div className="w-full overflow-x-auto overflow-y-hidden select-none custom-scrollbar rounded-lg pb-1">
            <div
              className="relative"
              style={{
                width: isScrollable ? `${chartW}px` : '100%',
                minWidth: '100%',
                height: `${chartH + 8}px`
              }}
            >
              <svg
                viewBox={`0 0 ${chartW} ${chartH}`}
                preserveAspectRatio={isScrollable ? 'none' : 'xMidYMid meet'}
                style={{
                  width: isScrollable ? `${chartW}px` : '100%',
                  height: `${chartH}px`
                }}
                className="select-none block"
              >
                <defs>
                  <linearGradient id="trendGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#006591" stopOpacity="0.22" />
                    <stop offset="100%" stopColor="#006591" stopOpacity="0.0" />
                  </linearGradient>
                </defs>

                {/* Y-Axis Gridlines & Ticks (100, 75, 50, 25, 0) */}
                {[100, 75, 50, 25, 0].map((v) => {
                  const y = getY(v);
                  return (
                    <g key={`grid-${v}`}>
                      <line
                        x1={padLeft}
                        y1={y}
                        x2={chartW - padRight}
                        y2={y}
                        stroke={theme === 'dark' ? '#1e293b' : '#f1f5f9'}
                        strokeDasharray={v === 0 || v === 100 ? "0" : "3 3"}
                        strokeWidth="1"
                      />
                      <text
                        x={padLeft - 10}
                        y={y + 3.5}
                        textAnchor="end"
                        fill="currentColor"
                        className="text-[10px] font-sans text-slate-400 dark:text-slate-500 font-medium tabular-nums"
                      >
                        {v}
                      </text>
                    </g>
                  );
                })}

                {/* Subtle Risk Threshold Guidelines (80, 50, 20) */}
                <line x1={padLeft} y1={getY(80)} x2={chartW - padRight} y2={getY(80)} stroke="#f43f5e" strokeOpacity="0.22" strokeDasharray="3 3" strokeWidth="1" />
                <line x1={padLeft} y1={getY(50)} x2={chartW - padRight} y2={getY(50)} stroke="#f59e0b" strokeOpacity="0.22" strokeDasharray="3 3" strokeWidth="1" />
                <line x1={padLeft} y1={getY(20)} x2={chartW - padRight} y2={getY(20)} stroke="#10b981" strokeOpacity="0.22" strokeDasharray="3 3" strokeWidth="1" />

                {/* Multi-point Trend Line & Area Fill */}
                {points.length > 1 && (
                  <>
                    <path d={areaPath} fill="url(#trendGradient)" />
                    <path
                      d={linePath}
                      fill="none"
                      stroke={theme === 'dark' ? '#38bdf8' : '#006591'}
                      strokeWidth="2.5"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </>
                )}

                {/* Points & Labels */}
                {points.map((p, idx) => {
                  const dotColor = p.score <= 20 ? "#059669" : p.score <= 50 ? "#d97706" : "#dc2626";
                  const isHovered = hoveredPoint?.order === p.order;
                  return (
                    <g
                      key={`point-${idx}`}
                      className="cursor-pointer group"
                      onMouseEnter={() => setHoveredPoint(p)}
                      onMouseLeave={() => setHoveredPoint(null)}
                      onClick={() => {
                        if (onSelectCapture && p.captureRef) {
                          onSelectCapture(p.captureRef);
                        }
                        onNavigate('forensics');
                      }}
                    >
                      <title>{`Capture #${p.order}\nFilename: ${p.filename}\nAI Risk Score: ${p.score}\nRisk Level: ${p.label}`}</title>

                      {/* Pulsing ring for single point or hovered point */}
                      {(points.length === 1 || isHovered) && (
                        <circle
                          cx={p.x}
                          cy={p.y}
                          r={isHovered ? "10" : "12"}
                          fill={dotColor}
                          fillOpacity={isHovered ? "0.3" : "0.2"}
                          className={points.length === 1 ? "animate-pulse" : ""}
                        />
                      )}

                      {/* Point Marker */}
                      <circle
                        cx={p.x}
                        cy={p.y}
                        r={isHovered ? "7" : "5.5"}
                        fill={dotColor}
                        stroke={theme === 'dark' ? '#0f172a' : '#ffffff'}
                        strokeWidth="2"
                        className="transition-all duration-150"
                      />

                      {/* Score Value Label */}
                      <text
                        x={p.x}
                        y={p.y - 11}
                        textAnchor="middle"
                        fill="currentColor"
                        className="text-[11px] font-sans font-bold text-slate-900 dark:text-white tabular-nums"
                      >
                        {p.score}
                      </text>

                      {/* Compact X-Axis Capture Identifier (#1, #2, #3...) */}
                      <text
                        x={p.x}
                        y={getY(0) + 20}
                        textAnchor="middle"
                        fill="currentColor"
                        className="text-[10px] font-mono text-slate-500 dark:text-slate-400 font-semibold"
                      >
                        #{p.order}
                      </text>
                    </g>
                  );
                })}
              </svg>

              {/* Floating Interactive Tooltip */}
              {hoveredPoint && (
                <div
                  className="absolute pointer-events-none z-20 px-3 py-2 rounded-lg bg-slate-900/95 dark:bg-slate-800/95 text-white border border-slate-700/80 shadow-lg text-xs font-sans -translate-x-1/2 -translate-y-full transition-all duration-75"
                  style={{
                    left: `${(hoveredPoint.x / chartW) * 100}%`,
                    top: `${Math.max(6, (hoveredPoint.y / chartH) * 100 - 8)}%`
                  }}
                >
                  <div className="font-bold font-mono text-sky-400 text-[11px]">Capture #{hoveredPoint.order}</div>
                  <div className="font-mono text-slate-300 text-[10px] truncate max-w-[220px]" title={hoveredPoint.filename}>
                    {hoveredPoint.filename}
                  </div>
                  <div className="flex items-center gap-2 mt-1 pt-1 border-t border-slate-700/60 text-[10px]">
                    <span>AI Risk Score: <strong className="tabular-nums text-white font-bold">{hoveredPoint.score}</strong></span>
                    <span className="text-slate-400">·</span>
                    <span>Risk Level: <strong className={
                      hoveredPoint.label === 'CRITICAL' || hoveredPoint.label === 'HIGH'
                        ? 'text-rose-400'
                        : hoveredPoint.label === 'MODERATE'
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                    }>{hoveredPoint.label}</strong></span>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Empty State Banner if only 1 capture */}
        {trendData.length === 1 && (
          <div className="flex items-center justify-between gap-2 p-3 rounded-lg bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-xs text-slate-600 dark:text-slate-300">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[17px] text-[#006591] dark:text-sky-400">info</span>
              <span>Analyze additional PCAP captures to view the risk trend across multiple uploads.</span>
            </div>
            <button
              onClick={onTriggerUpload}
              className="text-xs font-semibold text-[#006591] dark:text-sky-400 hover:underline cursor-pointer"
            >
              + Upload New PCAP
            </button>
          </div>
        )}
      </section>

      {/* ==================================================================== */}
      {/* THIRD PART: PCAP CAPTURE HISTORY (All Analyzed PCAPs)                */}
      {/* ==================================================================== */}
      <section className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xs overflow-hidden transition-colors duration-150">
        <div className="p-5 sm:p-6 border-b border-slate-100 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[18px] text-[#006591] dark:text-sky-400">history</span>
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">PCAP Capture History</h2>
          </div>
          <span className="font-sans text-xs text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-slate-800 px-2.5 py-1 rounded-lg border border-slate-200 dark:border-slate-700 font-medium self-start sm:self-auto">
            {pcapList.length} {pcapList.length === 1 ? 'Capture' : 'Captures'} Logged
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-50/80 dark:bg-slate-800/80 text-slate-500 dark:text-slate-400 font-semibold border-b border-slate-200 dark:border-slate-800 text-[11px] uppercase tracking-wider font-sans">
                <th className="py-3 px-4 sm:px-6">Filename</th>
                <th className="py-3 px-4">Total Packets</th>
                <th className="py-3 px-4">AI Risk Score</th>
                <th className="py-3 px-4">Risk Level</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 sm:px-6 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-sans">
              {pcapList.length === 0 ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400 dark:text-slate-500 text-xs font-medium">
                    No PCAP captures analyzed yet. Upload a capture to begin forensic analysis.
                  </td>
                </tr>
              ) : (
                pcapList.map((pcap, idx) => {
                  const pSessions = pcap.sessions || [];
                  const pScoreVal = pcap.ai_risk?.score != null
                    ? Number(pcap.ai_risk.score)
                    : (pSessions[0]?.ai_risk?.score != null
                      ? Number(pSessions[0].ai_risk.score)
                      : (pSessions.length > 0
                        ? Number((pSessions.reduce((acc, s) => acc + (s.ai_risk?.score ?? 0), 0) / pSessions.length).toFixed(1))
                        : 0));
                  const pScore = pScoreVal != null ? Number(pScoreVal).toFixed(1) : "0.0";
                  const pScoreNum = Number(pScore) || 0;

                  const pLabel = pcap.ai_risk
                    ? getAiRiskTier(pcap.ai_risk)
                    : (pSessions[0]?.ai_risk
                      ? getAiRiskTier(pSessions[0].ai_risk)
                      : scoreToRiskTier(pScoreNum));
                  const isHighOrCritical = pLabel === "CRITICAL" || pLabel === "HIGH";
                  const isModerate = pLabel === "MODERATE";

                  const badgeClass = isHighOrCritical
                    ? 'bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-800'
                    : isModerate
                    ? 'bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800'
                    : 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800';

                  const badgeDotClass = isHighOrCritical
                    ? 'bg-rose-600'
                    : isModerate
                    ? 'bg-amber-500'
                    : 'bg-emerald-600';

                  const pcapStatus = getPcapSecurityPosture(pcap);
                  const isSecure = pcapStatus === 'SECURE';
                  const isIncomplete = pcapStatus === 'INCOMPLETE';
                  const statusBadgeClass = isSecure
                    ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800'
                    : isIncomplete
                    ? 'bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800'
                    : 'bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-800';
                  const statusDotClass = isSecure ? 'bg-emerald-600' : isIncomplete ? 'bg-amber-500' : 'bg-rose-600';
                  const statusText = isSecure ? 'SECURE' : isIncomplete ? 'INCOMPLETE' : 'INSECURE';

                  const totalPackets = pcap?.total_packets ?? (pSessions.length * 148);
                  const isActive = (pcap?.capture_id && activeCapture?.capture_id && pcap.capture_id === activeCapture.capture_id)
                    || (pcap?.filename && activeCapture?.filename && pcap.filename.toLowerCase() === activeCapture.filename.toLowerCase());

                  return (
                    <tr
                      key={pcap.capture_id || pcap.filename || `pcap-${idx}`}
                      onClick={() => {
                        if (onSelectCapture) onSelectCapture(pcap);
                        onNavigate('forensics');
                      }}
                      className={`hover:bg-slate-50/80 dark:hover:bg-slate-800/50 transition-all duration-150 cursor-pointer ${
                        isActive ? 'bg-sky-50/50 dark:bg-sky-950/30 font-medium' : ''
                      }`}
                    >
                      {/* Filename with Active indicator */}
                      <td className="py-3.5 px-4 sm:px-6">
                        <div className="flex items-center gap-2">
                          <span className="material-symbols-outlined text-[16px] text-[#006591] dark:text-sky-400">description</span>
                          <span className="font-mono text-xs font-semibold text-slate-900 dark:text-white truncate max-w-xs">
                            {pcap.filename || "capture.pcap"}
                          </span>
                          {isActive && (
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-sans font-semibold bg-sky-100 dark:bg-sky-900/60 text-[#006591] dark:text-sky-300 border border-sky-200 dark:border-sky-700 uppercase tracking-wider">
                              Active
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Total Packets */}
                      <td className="py-3.5 px-4 font-sans font-medium tabular-nums text-slate-600 dark:text-slate-400 text-xs">
                        {totalPackets.toLocaleString()}
                      </td>

                      {/* AI Risk Score */}
                      <td className="py-3.5 px-4 font-sans font-bold tabular-nums text-slate-900 dark:text-white text-xs">
                        {pScore}/100
                      </td>

                      {/* Risk Level Badge */}
                      <td className="py-3.5 px-4">
                        <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold border tracking-wider uppercase font-sans inline-flex items-center gap-1.5 ${badgeClass}`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${badgeDotClass}`}></span>
                          {pLabel}
                        </span>
                      </td>

                      {/* Status Badge */}
                      <td className="py-3.5 px-4">
                        <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold border tracking-wider uppercase font-sans inline-flex items-center gap-1.5 ${statusBadgeClass}`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${statusDotClass}`}></span>
                          {statusText}
                        </span>
                      </td>

                      {/* Investigate Action Button */}
                      <td className="py-3.5 px-4 sm:px-6 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            if (onSelectCapture) onSelectCapture(pcap);
                            onNavigate('forensics');
                          }}
                          className="inline-flex items-center gap-1 text-xs font-semibold text-slate-900 dark:text-slate-100 hover:text-white dark:hover:text-white bg-slate-100 dark:bg-slate-800 hover:bg-slate-900 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 px-3 py-1.5 rounded-lg transition-all duration-150 shadow-2xs cursor-pointer"
                        >
                          <span>Investigate</span>
                          <span className="material-symbols-outlined text-[14px]">arrow_forward</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* LOCAL CAPTURE AGENT REQUIRED GUIDANCE MODAL */}
      {showAgentModal && (
        <div
          className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 animate-in fade-in duration-150"
          role="dialog"
          aria-modal="true"
          aria-labelledby="agent-modal-title"
        >
          <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-2xl max-w-xl w-full p-6 flex flex-col gap-4 text-slate-800 dark:text-slate-100 animate-in zoom-in-95 duration-150 max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="flex items-start justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-amber-50 dark:bg-amber-950/50 border border-amber-200 dark:border-amber-800 flex items-center justify-center text-amber-600 dark:text-amber-400 shrink-0">
                  <span className="material-symbols-outlined text-[24px]">sensors_off</span>
                </div>
                <div>
                  <h3 id="agent-modal-title" className="text-base font-bold text-slate-900 dark:text-white">
                    Capture Agent Setup &amp; Prerequisite Guide
                  </h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    Authentic network packet recording requires the agent service
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowAgentModal(false)}
                className="p-1 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors cursor-pointer"
                aria-label="Close"
              >
                <span className="material-symbols-outlined text-[20px]">close</span>
              </button>
            </div>

            {/* Operating System Selection Tabs */}
            <div className="flex items-center gap-2 p-1 bg-slate-100 dark:bg-slate-800/80 rounded-xl border border-slate-200 dark:border-slate-700/60 text-xs">
              <button
                type="button"
                onClick={() => setSelectedOsTab('windows')}
                className={`flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-lg font-semibold transition-all cursor-pointer ${
                  selectedOsTab === 'windows'
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs'
                    : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
                }`}
              >
                <span className="material-symbols-outlined text-[16px]">desktop_windows</span>
                <span>Windows</span>
                {clientOS === 'windows' && (
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-sky-100 dark:bg-sky-950/70 text-sky-700 dark:text-sky-300 uppercase font-bold tracking-wider">
                    Detected
                  </span>
                )}
              </button>
              <button
                type="button"
                onClick={() => setSelectedOsTab('macos')}
                className={`flex-1 flex items-center justify-center gap-2 py-2 px-3 rounded-lg font-semibold transition-all cursor-pointer ${
                  selectedOsTab === 'macos'
                    ? 'bg-white dark:bg-slate-900 text-slate-900 dark:text-white shadow-xs'
                    : 'text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-200'
                }`}
              >
                <span className="material-symbols-outlined text-[16px]">laptop_mac</span>
                <span>macOS</span>
                {clientOS === 'macos' && (
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-sky-100 dark:bg-sky-950/70 text-sky-700 dark:text-sky-300 uppercase font-bold tracking-wider">
                    Detected
                  </span>
                )}
              </button>
            </div>

            {/* Modal Content Based on Selected OS */}
            {selectedOsTab === 'windows' ? (
              <div className="text-xs text-slate-600 dark:text-slate-300 flex flex-col gap-3.5">
                <p>
                  SecureMailScope records genuine, non-synthetic PCAP captures by sniffing live SMTP traffic (port 587 and 2525) directly on your Windows PC.
                </p>

                {/* Step 1: Npcap Prerequisite */}
                <div className="p-3.5 rounded-xl border border-amber-200 dark:border-amber-800/60 bg-amber-50/70 dark:bg-amber-950/20 flex flex-col gap-2">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <span className="font-bold text-amber-950 dark:text-amber-300 text-xs flex items-center gap-1.5">
                      <span className="w-5 h-5 rounded-full bg-amber-200 dark:bg-amber-900/80 text-amber-900 dark:text-amber-200 flex items-center justify-center text-[10px] font-bold">1</span>
                      Install Npcap Driver (Prerequisite)
                    </span>
                    <a
                      href={NPCAP_OFFICIAL_URL}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-700 text-white font-semibold text-[11px] shadow-2xs transition-all cursor-pointer"
                    >
                      <span className="material-symbols-outlined text-[14px]">open_in_new</span>
                      <span>Download Npcap (npcap.com)</span>
                    </a>
                  </div>
                  <p className="text-[11px] text-amber-900/90 dark:text-amber-300/90 leading-relaxed">
                    Npcap is required for genuine Windows packet capture. Download the official installer from npcap.com. During installation, make sure to check:
                  </p>
                  <div className="p-2 rounded bg-white dark:bg-slate-900 border border-amber-200 dark:border-amber-800/60 font-mono text-[11px] text-amber-950 dark:text-amber-200 font-semibold">
                    ✓ &quot;Install Npcap in WinPcap API-compatible Mode&quot;
                  </div>
                </div>

                {/* Step 2: Windows Capture Agent Installer */}
                <div className="p-3.5 rounded-xl border border-sky-200 dark:border-sky-800/60 bg-sky-50/70 dark:bg-sky-950/20 flex flex-col gap-2">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <span className="font-bold text-sky-950 dark:text-sky-300 text-xs flex items-center gap-1.5">
                      <span className="w-5 h-5 rounded-full bg-sky-200 dark:bg-sky-900/80 text-sky-900 dark:text-sky-200 flex items-center justify-center text-[10px] font-bold">2</span>
                      Install SecureMailScope Capture Agent
                    </span>
                    <a
                      href={getAgentDownloadUrl('windows')}
                      download="SecureMailScopeCaptureAgent-1.0.1-Setup.exe"
                      className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-[#006591] hover:bg-[#005174] text-white font-semibold text-[11px] shadow-2xs transition-all cursor-pointer"
                    >
                      <span className="material-symbols-outlined text-[14px]">download</span>
                      <span>Download Windows Capture Agent</span>
                    </a>
                  </div>
                  <p className="text-[11px] text-sky-900/90 dark:text-sky-300/90 leading-relaxed">
                    Run <span className="font-mono font-semibold">SecureMailScopeCaptureAgent-1.0.1-Setup.exe</span> once. It installs to <span className="font-mono text-[10px]">C:\Program Files\SecureMailScope\CaptureAgent</span>, registers the <span className="font-mono text-[10px]">SecureMailScopeCaptureAgent</span> Windows Service, and starts capture automatically.
                  </p>
                </div>

                {/* Step 3: Check Connection */}
                <div className="flex items-center gap-2 p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 text-slate-600 dark:text-slate-400 text-[11px]">
                  <span className="material-symbols-outlined text-[16px] text-emerald-500 shrink-0">verified</span>
                  <span>Once installed, click &quot;Check Connection&quot; below to verify readiness and enable authentic capture controls.</span>
                </div>
              </div>
            ) : (
              <div className="text-xs text-slate-600 dark:text-slate-300 flex flex-col gap-3.5">
                <p>
                  SecureMailScope records genuine, non-synthetic PCAP captures by executing authentic email protocol exchanges directly on your Mac.
                </p>

                {/* macOS Installer Package (.pkg) */}
                <div className="p-3.5 rounded-xl border border-sky-200 dark:border-sky-800/60 bg-sky-50/70 dark:bg-sky-950/20 flex flex-col gap-2">
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <span className="font-bold text-sky-950 dark:text-sky-300 text-xs flex items-center gap-1.5">
                      <span className="w-5 h-5 rounded-full bg-sky-200 dark:bg-sky-900/80 text-sky-900 dark:text-sky-200 flex items-center justify-center text-[10px] font-bold">1</span>
                      Download macOS Installer (.pkg)
                    </span>
                    <a
                      href={getAgentDownloadUrl('macos')}
                      download="SecureMailScopeCaptureAgent-1.0.0.pkg"
                      className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-[#006591] hover:bg-[#005174] text-white font-semibold text-[11px] shadow-2xs transition-all cursor-pointer"
                    >
                      <span className="material-symbols-outlined text-[14px]">download</span>
                      <span>Download macOS Agent (.pkg)</span>
                    </a>
                  </div>
                  <p className="text-[11px] text-sky-900/90 dark:text-sky-300/90 leading-relaxed">
                    Double-click the .pkg package to install. Registers the <span className="font-mono text-[10px]">com.securemailscope.captureagent</span> LaunchDaemon and starts listening strictly on 127.0.0.1:9000.
                  </p>
                </div>

                {/* Terminal Alternative for macOS */}
                <div className="bg-slate-950 text-slate-200 rounded-xl p-3.5 font-mono text-[11px] flex flex-col gap-1.5 border border-slate-800">
                  <div className="text-slate-400 text-[10px] font-sans font-semibold uppercase tracking-wider">
                    Terminal Quick Command (Run Locally)
                  </div>
                  <div className="text-sky-300 select-all font-semibold">
                    cd capture_agent/macos &amp;&amp; sudo ./install.sh
                  </div>
                  <div className="text-slate-400 text-[10px] font-sans mt-0.5">
                    Or launch standalone: <span className="font-mono text-slate-300">sudo .venv/bin/python capture_agent/main.py</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 p-2.5 rounded-lg bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700/60 text-slate-600 dark:text-slate-400 text-[11px]">
                  <span className="material-symbols-outlined text-[16px] text-sky-500 shrink-0">info</span>
                  <span>The agent runs as a native system daemon, binds strictly to 127.0.0.1:9000, and captures only authorized mail ports.</span>
                </div>
              </div>
            )}

            {/* Modal Actions */}
            <div className="flex items-center justify-between gap-2 pt-3 border-t border-slate-100 dark:border-slate-800 flex-wrap">
              <button
                type="button"
                onClick={async () => {
                  setIsRetryingAgent(true);
                  const isOnline = await checkAgentHealth();
                  setIsRetryingAgent(false);
                  if (isOnline) {
                    setShowAgentModal(false);
                  }
                }}
                disabled={isRetryingAgent}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-[#006591] hover:bg-[#005174] text-white text-xs font-semibold shadow-2xs transition-all cursor-pointer disabled:opacity-60"
              >
                <span className={`material-symbols-outlined text-[16px] ${isRetryingAgent ? 'animate-spin' : ''}`}>
                  {isRetryingAgent ? 'progress_activity' : 'refresh'}
                </span>
                <span>{isRetryingAgent ? 'Checking...' : 'Check Connection'}</span>
              </button>

              <div className="flex items-center gap-2">
                {onGenerateAuthenticCapture && (
                  <button
                    type="button"
                    onClick={async () => {
                      setShowAgentModal(false);
                      try {
                        await onGenerateAuthenticCapture(setCaptureStep);
                        setTimeout(() => setCaptureStep('ready'), 3000);
                      } catch {
                        setCaptureStep('ready');
                      }
                    }}
                    title="Attempt capture via backend server proxy"
                    className="px-3 py-2 rounded-lg text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 text-xs font-medium transition-colors cursor-pointer"
                  >
                    Continue via Server
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setShowAgentModal(false)}
                  className="px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 text-xs font-medium transition-colors cursor-pointer"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
