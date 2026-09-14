import React, { useState, useEffect, useRef, useMemo } from 'react';
import { exportJSON, exportXLSX, exportPDF, exportHTML } from '../reportGenerator';
import {
  getPcapSecurityPosture,
  deriveSecurityStats,
  deriveDailyTrends,
  parsePcapTimestamp,
  getPcapDateKey
} from '../utils/securityStats';
import ExecutiveDatePicker from './ExecutiveDatePicker';

export default function ExecutiveDashboard({
  capture,
  analyzedPcaps = [],
  stats,
  onSelectCapture,
  onNavigate,
  onTriggerUpload,
  theme = 'light',
  userRole = 'EXECUTIVE'
}) {
  const displayPcaps = useMemo(() => Array.isArray(analyzedPcaps) ? analyzedPcaps : [], [analyzedPcaps]);

  const [hoveredStatusIdx, setHoveredStatusIdx] = useState(null);
  const [hoveredRiskIdx, setHoveredRiskIdx] = useState(null);
  const [openReportMenuPcap, setOpenReportMenuPcap] = useState(null);
  const [generatingPcapKey, setGeneratingPcapKey] = useState(null);
  const [exportFeedback, setExportFeedback] = useState(null);
  const reportMenuRef = useRef(null);

  // Set of all dates that have recorded PCAP data in local time
  const availableDateSet = useMemo(() => {
    const set = new Set();
    displayPcaps.forEach((p) => {
      const key = getPcapDateKey(p);
      if (key) set.add(key);
    });
    return set;
  }, [displayPcaps]);

  // Calendar Date Range Filter State (empty strings represent "All Dates")
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [activePreset, setActivePreset] = useState('all'); // 'all' | 'today' | '7d' | '30d' | 'custom'

  const hasActiveFilter = Boolean(startDate || endDate);

  // Helper to format Date object into local YYYY-MM-DD
  const formatLocalYMD = (date) => {
    if (!date) return '';
    const d = date instanceof Date ? date : new Date(date);
    if (isNaN(d.getTime())) return '';
    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  };

  // Quick preset selector: sets start/end dates and marks active preset
  const handleSelectPreset = (presetKey) => {
    if (presetKey === 'all') {
      setActivePreset('all');
      setStartDate('');
      setEndDate('');
    } else if (presetKey === 'today') {
      const now = new Date();
      const todayStr = formatLocalYMD(now);
      setActivePreset('today');
      setStartDate(todayStr);
      setEndDate(todayStr);
    } else if (presetKey === '7d') {
      const now = new Date();
      const endStr = formatLocalYMD(now);
      // Current local day and previous 6 local calendar days = exactly 7 days
      const startD = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 6);
      const startStr = formatLocalYMD(startD);
      setActivePreset('7d');
      setStartDate(startStr);
      setEndDate(endStr);
    } else if (presetKey === '30d') {
      const now = new Date();
      const endStr = formatLocalYMD(now);
      // Current local day and previous 29 local calendar days = exactly 30 days
      const startD = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 29);
      const startStr = formatLocalYMD(startD);
      setActivePreset('30d');
      setStartDate(startStr);
      setEndDate(endStr);
    }
  };

  // Custom calendar date range change handler
  const handleCustomDateRangeChange = ({ startDate: newStart, endDate: newEnd, isCustom }) => {
    if (newStart && newEnd && newStart > newEnd) {
      return; // prevent applying invalid range
    }
    setStartDate(newStart || '');
    setEndDate(newEnd || '');
    if (!newStart && !newEnd) {
      setActivePreset('all');
    } else if (isCustom) {
      setActivePreset('custom');
    }
  };

  // Close report format dropdown when clicking outside or pressing Escape
  useEffect(() => {
    const handleClickOutside = (e) => {
      if (reportMenuRef.current && !reportMenuRef.current.contains(e.target)) {
        setOpenReportMenuPcap(null);
      }
    };
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        setOpenReportMenuPcap(null);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    document.addEventListener('keydown', handleKeyDown);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.removeEventListener('keydown', handleKeyDown);
    };
  }, []);

  // Per-PCAP report download handler
  const handleDownloadReport = (pcapItem, format = 'pdf') => {
    setOpenReportMenuPcap(null);
    if (!pcapItem) {
      setExportFeedback({
        type: 'error',
        message: 'No capture data available to generate report.'
      });
      setTimeout(() => setExportFeedback(null), 4000);
      return;
    }
    const pcapKey = pcapItem.capture_id || pcapItem.filename || 'pcap';
    const filename = pcapItem.filename || 'Executive-Report';
    setGeneratingPcapKey(pcapKey);

    // Yield execution briefly so UI can render the "Generating..." loading affordance
    setTimeout(() => {
      try {
        if (format === 'pdf') {
          exportPDF(pcapItem);
        } else if (format === 'json') {
          exportJSON(pcapItem);
        } else if (format === 'html') {
          exportHTML(pcapItem);
        } else if (format === 'xlsx') {
          exportXLSX(pcapItem);
        }
        setExportFeedback({
          type: 'success',
          message: `Exported ${format.toUpperCase()} report for ${filename}`
        });
        setTimeout(() => setExportFeedback(null), 3500);
      } catch (err) {
        console.error('Report export error:', err);
        setExportFeedback({
          type: 'error',
          message: `Failed to export ${format.toUpperCase()} report: ${err.message || err}`
        });
        setTimeout(() => setExportFeedback(null), 5000);
      } finally {
        setGeneratingPcapKey(null);
      }
    }, 60);
  };

  // Precise safe half-open local boundaries:
  // start >= selectedStartDate at 00:00:00.000 local time
  // timestamp < dayAfterSelectedEndDate at 00:00:00.000 local time
  const filterBoundaries = useMemo(() => {
    let startBoundaryMs = null;
    let endBoundaryMs = null;

    if (startDate) {
      const [sY, sM, sD] = startDate.split('-').map(Number);
      if (sY && sM && sD) {
        startBoundaryMs = new Date(sY, sM - 1, sD, 0, 0, 0, 0).getTime();
      }
    }

    if (endDate) {
      const [eY, eM, eD] = endDate.split('-').map(Number);
      if (eY && eM && eD) {
        // Exclusive upper boundary at start of the day after endDate
        endBoundaryMs = new Date(eY, eM - 1, eD + 1, 0, 0, 0, 0).getTime();
      }
    }

    return { startBoundaryMs, endBoundaryMs };
  }, [startDate, endDate]);

  // SINGLE SOURCE OF TRUTH: Filter PCAPs strictly using timestamp epoch ms within the boundary
  const filteredPcaps = useMemo(() => {
    const { startBoundaryMs, endBoundaryMs } = filterBoundaries;

    if (startBoundaryMs === null && endBoundaryMs === null) {
      return displayPcaps;
    }

    return displayPcaps.filter((p) => {
      const pMs = parsePcapTimestamp(p);
      if (pMs === null) return false;

      if (startBoundaryMs !== null && pMs < startBoundaryMs) {
        return false;
      }
      if (endBoundaryMs !== null && pMs >= endBoundaryMs) {
        return false;
      }
      return true;
    });
  }, [displayPcaps, filterBoundaries]);

  // SINGLE SOURCE OF TRUTH: All metrics derive directly from filtered PCAPs
  const securityStats = useMemo(() => {
    if (!hasActiveFilter && stats) {
      return stats;
    }
    return deriveSecurityStats(filteredPcaps);
  }, [filteredPcaps, hasActiveFilter, stats]);

  const totalReports = securityStats.total;
  const secureReports = securityStats.secure;
  const insecureReports = securityStats.insecure;
  const securePct = securityStats.securePct;
  const insecurePct = securityStats.insecurePct;
  const totalSessions = securityStats.totalSessions;

  // Helper to extract clean, non-technical executive summary for each PCAP
  const getPcapExecutiveSummary = (pcapItem) => {
    const pSessions = pcapItem?.sessions || [];
    const pTotal = pSessions.length;

    if (pTotal === 0) {
      return {
        filename: pcapItem?.filename || "capture.pcap",
        score: 0,
        status: "INSECURE",
        statusClass: "bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-800",
        dotClass: "bg-rose-600",
        keyFinding: "No active network sessions observed",
        recommendedAction: "Verify network capture"
      };
    }

    const postureStatus = getPcapSecurityPosture(pcapItem);
    const secure = postureStatus === 'SECURE';
    const incomplete = postureStatus === 'INCOMPLETE';

    // Deterministic posture score (strictly separate from AI risk score)
    const pPostureScore = typeof pcapItem?.posture?.score === 'number'
      ? pcapItem.posture.score
      : Math.round(
          pSessions.reduce((acc, s) => acc + (s.posture?.score ?? 100), 0) / pTotal
        );

    const primarySession = pSessions[0];
    const explanation = pcapItem?.posture?.explanation || primarySession?.posture?.explanation;

    let keyFinding = "Cryptographic baseline compliant";
    let recommendedAction = "No action required";

    if (incomplete) {
      keyFinding = "Insufficient capture data / Incomplete session";
      recommendedAction = "Capture complete TLS handshake";
    } else if (!secure) {
      const findings = primarySession?.assessment?.findings || [];
      const correlations = primarySession?.posture?.correlations || [];
      if (correlations.length > 0 && correlations[0].title) {
        keyFinding = correlations[0].title;
      } else if (findings.length > 0 && findings[0].title) {
        keyFinding = findings[0].title;
      } else if (explanation) {
        keyFinding = explanation.length > 60 ? explanation.slice(0, 57) + "..." : explanation;
      } else {
        keyFinding = "Security posture non-compliant";
      }
      recommendedAction = "Review cryptographic configuration";
    }

    return {
      filename: pcapItem?.filename || "capture.pcap",
      score: pPostureScore,
      status: secure ? "SECURE" : incomplete ? "INCOMPLETE" : "INSECURE",
      statusClass: secure
        ? "bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800"
        : incomplete
        ? "bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800"
        : "bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-800",
      dotClass: secure ? "bg-emerald-600" : incomplete ? "bg-amber-500" : "bg-rose-600",
      keyFinding,
      recommendedAction
    };
  };

  // SINGLE SOURCE OF TRUTH: Derive date-wise points dynamically from filteredPcaps
  const dayTrendPoints = useMemo(() => {
    return deriveDailyTrends(filteredPcaps);
  }, [filteredPcaps]);
  const numDays = dayTrendPoints.length;

  // Chart layout metrics for crisp enterprise SOC charts with independent horizontal scrolling
  const chartH = 210;
  const padLeft = 44;
  const padRight = 28;
  const padTop = 26;
  const padBottom = 38;
  const baselineY = padTop + (chartH - padTop - padBottom); // 172
  const plotH = baselineY - padTop; // 146

  // Sensible slot width per data point to prevent bars and labels from crowding
  const minSlotWidth = 68;
  const basePlotW = 520;

  // Dynamic plot width: expands when points exceed base width, fits 100% when few
  const isScrollable = numDays * minSlotWidth > basePlotW;
  const plotW = Math.max(basePlotW, numDays * minSlotWidth);
  const chartW = padLeft + plotW + padRight;

  const slotWidth = numDays > 0 ? plotW / numDays : plotW;
  const getX = (idx) => {
    if (numDays <= 1) return Math.round(padLeft + plotW / 2);
    return Math.round(padLeft + (idx + 0.5) * slotWidth);
  };

  // --- CHART 1: DAILY SECURITY STATUS COORDINATES ---
  const maxStatusCount = numDays > 0
    ? Math.max(1, ...dayTrendPoints.map((d) => Math.max(d.secureReports, d.insecureReports)))
    : 1;

  const statusAxisMax = maxStatusCount <= 2
    ? 4
    : maxStatusCount <= 5
      ? maxStatusCount + 1
      : Math.ceil(maxStatusCount * 1.25);

  const statusTicks = Array.from(
    new Set([statusAxisMax, Math.round((statusAxisMax * 2) / 3), Math.round(statusAxisMax / 3), 0])
  ).sort((a, b) => b - a);

  const getYStatus = (count) => {
    const clamped = Math.max(0, Math.min(statusAxisMax, count));
    return Math.round(padTop + (1 - clamped / statusAxisMax) * plotH);
  };

  const barPairWidth = Math.min(56, Math.max(24, slotWidth * 0.50));
  const barGap = 4;
  const singleBarWidth = Math.floor((barPairWidth - barGap) / 2);

  const statusChartPoints = dayTrendPoints.map((d, i) => {
    const x = getX(i);
    const secY = getYStatus(d.secureReports);
    const secHeight = Math.max(d.secureReports > 0 ? 3 : 0, baselineY - secY);
    const secX = Math.round(x - barPairWidth / 2);

    const insecY = getYStatus(d.insecureReports);
    const insecHeight = Math.max(d.insecureReports > 0 ? 3 : 0, baselineY - insecY);
    const insecX = Math.round(secX + singleBarWidth + barGap);

    return {
      ...d,
      idx: i,
      x,
      secX,
      secY,
      secHeight,
      insecX,
      insecY,
      insecHeight
    };
  });

  const hoveredStatusPoint = hoveredStatusIdx !== null && statusChartPoints[hoveredStatusIdx]
    ? statusChartPoints[hoveredStatusIdx]
    : null;

  // --- CHART 2: DAILY RISK SCORE TREND COORDINATES ---
  const getYRisk = (score) => {
    if (score == null || isNaN(score)) return baselineY;
    const clamped = Math.max(0, Math.min(100, score));
    return Math.round(padTop + (1 - clamped / 100) * plotH);
  };

  // Trajectory delta (derived strictly from existing chronological day scores)
  const trendTrajectory = (() => {
    const validDays = dayTrendPoints.filter((d) => d.hasValidRisk);
    if (validDays.length < 2) return null;
    const latest = validDays[validDays.length - 1].avgRisk;
    const prior = validDays[validDays.length - 2].avgRisk;
    const delta = latest - prior;
    if (delta > 0) {
      return {
        label: `+${delta} pts risk increase`,
        icon: 'trending_up',
        colorClass: 'text-rose-700 dark:text-rose-400 bg-rose-50 dark:bg-rose-950/40 border-rose-200 dark:border-rose-800'
      };
    }
    if (delta < 0) {
      return {
        label: `${Math.abs(delta)} pts risk reduction`,
        icon: 'trending_down',
        colorClass: 'text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800'
      };
    }
    return {
      label: 'Stable risk level',
      icon: 'trending_flat',
      colorClass: 'text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-slate-800 border-slate-200 dark:border-slate-700'
    };
  })();

  const riskChartPoints = dayTrendPoints.map((d, i) => {
    const x = getX(i);
    const riskY = d.hasValidRisk && d.avgRisk != null ? getYRisk(d.avgRisk) : null;
    return {
      ...d,
      idx: i,
      x,
      riskY
    };
  });

  const validRiskPoints = riskChartPoints.filter((p) => p.hasValidRisk && p.riskY != null);

  const getSmoothRiskPath = (pts) => {
    if (!pts || pts.length === 0) return '';
    if (pts.length === 1) return `M ${pts[0].x} ${pts[0].riskY}`;
    if (pts.length === 2) return `M ${pts[0].x} ${pts[0].riskY} L ${pts[1].x} ${pts[1].riskY}`;

    let d = `M ${pts[0].x} ${pts[0].riskY}`;
    const tension = 0.15;
    for (let i = 0; i < pts.length - 1; i++) {
      const p0 = pts[i === 0 ? 0 : i - 1];
      const p1 = pts[i];
      const p2 = pts[i + 1];
      const p3 = pts[i + 2] || p2;

      const cp1x = p1.x + (p2.x - p0.x) * tension;
      const cp1y = p1.riskY + (p2.riskY - p0.riskY) * tension;
      const cp2x = p2.x - (p3.x - p1.x) * tension;
      const cp2y = p2.riskY + (p3.riskY - p1.riskY) * tension;

      d += ` C ${cp1x.toFixed(1)} ${cp1y.toFixed(1)}, ${cp2x.toFixed(1)} ${cp2y.toFixed(1)}, ${p2.x.toFixed(1)} ${p2.riskY.toFixed(1)}`;
    }
    return d;
  };

  const smoothLinePath = getSmoothRiskPath(validRiskPoints);

  const hoveredRiskPoint = hoveredRiskIdx !== null && riskChartPoints[hoveredRiskIdx]
    ? riskChartPoints[hoveredRiskIdx]
    : null;

  return (
    <div className="w-full max-w-6xl mx-auto flex flex-col gap-6 overflow-x-clip">
      {/* DASHBOARD HEADER */}
      <header className="bg-white dark:bg-slate-900 rounded-xl p-5 sm:p-6 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col sm:flex-row sm:items-center justify-between gap-4 transition-colors duration-150">
        <div className="flex flex-col gap-1.5">
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="flex items-center gap-1.5">
              <span className="material-symbols-outlined text-[18px] text-[#006591] dark:text-sky-400">shield</span>
              <span className="text-[11px] font-bold uppercase tracking-wider text-[#006591] dark:text-sky-400">Executive Telemetry</span>
            </div>
            <span className="text-slate-300 dark:text-slate-600 hidden sm:inline">·</span>
            <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 font-sans text-[10px] font-semibold text-slate-700 dark:text-slate-300 tracking-wider uppercase">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
              <span>Analysis Engine Ready</span>
            </div>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900 dark:text-white">Executive Security Dashboard</h1>
          <p className="text-xs text-slate-500 dark:text-slate-400">Fleet security posture and risk telemetry</p>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-auto flex-wrap">
          {onTriggerUpload && (
            <button
              onClick={onTriggerUpload}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-900 dark:bg-slate-800 text-white hover:bg-slate-800 dark:hover:bg-slate-700 active:bg-slate-950 dark:active:bg-slate-600 text-xs font-semibold shadow-2xs transition-all duration-150 cursor-pointer"
            >
              <span className="material-symbols-outlined text-[16px]">upload_file</span>
              <span>Upload PCAP</span>
            </button>
          )}
          {(capture || filteredPcaps.length > 0 || displayPcaps.length > 0) && (
            <button
              type="button"
              onClick={() => handleDownloadReport(capture || filteredPcaps[0] || displayPcaps[0], 'pdf')}
              disabled={generatingPcapKey !== null}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-white dark:bg-slate-800/90 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 hover:border-slate-300 dark:hover:border-slate-600 active:bg-slate-100 dark:active:bg-slate-700 transition-all duration-150 shadow-2xs text-xs font-semibold cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed"
              title="Download Executive Report"
            >
              {generatingPcapKey !== null ? (
                <>
                  <span className="material-symbols-outlined text-[16px] animate-spin text-[#006591] dark:text-sky-400">
                    progress_activity
                  </span>
                  <span>Generating Report...</span>
                </>
              ) : (
                <>
                  <span className="material-symbols-outlined text-[16px] text-slate-500 dark:text-slate-400">
                    download
                  </span>
                  <span>Download Report</span>
                </>
              )}
            </button>
          )}
          {userRole !== 'EXECUTIVE' && (
            <button
              onClick={() => onNavigate('forensics')}
              className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-white dark:bg-slate-800/90 border border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 hover:border-slate-300 dark:hover:border-slate-600 active:bg-slate-100 dark:active:bg-slate-700 transition-all duration-150 shadow-2xs text-xs font-semibold cursor-pointer"
            >
              <span>Open SOC Forensics</span>
              <span className="material-symbols-outlined text-[16px]">arrow_forward</span>
            </button>
          )}
        </div>
      </header>

      {/* 1. SECURITY POSTURE SUMMARY (Total, Secure, Insecure Captures) */}
      <section className="flex flex-col gap-3">
        <div className="flex items-center justify-between px-1">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[18px] text-[#006591] dark:text-sky-400">monitoring</span>
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">
              Security Posture Summary
            </h2>
          </div>
          <span className="text-[11px] font-sans font-medium text-slate-500 dark:text-slate-400">
            {totalReports} total capture{totalReports === 1 ? '' : 's'} • {totalSessions} session{totalSessions === 1 ? '' : 's'}
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Total Captures */}
          <div className="bg-white dark:bg-slate-900 rounded-xl p-5 sm:p-6 border border-slate-200 dark:border-slate-800 shadow-xs hover:border-slate-300 dark:hover:border-slate-700 transition-all duration-150 flex items-center justify-between">
            <div className="flex flex-col gap-1">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                Total Captures
              </span>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl sm:text-4xl font-bold text-slate-900 dark:text-white tracking-tight font-sans tabular-nums">
                  {totalReports}
                </span>
              </div>
              <span className="text-[11px] text-slate-400 dark:text-slate-500 font-normal">
                {totalSessions} session{totalSessions === 1 ? '' : 's'} recorded
              </span>
            </div>
            <div className="w-11 h-11 rounded-xl bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center text-slate-700 dark:text-slate-300 shrink-0">
              <span className="material-symbols-outlined text-[22px]">mark_email_read</span>
            </div>
          </div>

          {/* Secure Captures */}
          <div className="bg-emerald-50/40 dark:bg-emerald-950/20 rounded-xl p-5 sm:p-6 border border-emerald-200 dark:border-emerald-800/60 shadow-xs hover:border-emerald-300 dark:hover:border-emerald-700 transition-all duration-150 flex items-center justify-between">
            <div className="flex flex-col gap-1">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-emerald-800 dark:text-emerald-400">
                Secure Captures
              </span>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl sm:text-4xl font-bold text-emerald-700 dark:text-emerald-400 tracking-tight font-sans tabular-nums">
                  {secureReports}
                </span>
                <span className="text-xs font-semibold text-emerald-700/90 dark:text-emerald-400/90 font-sans tabular-nums">
                  ({securePct}%)
                </span>
              </div>
              <span className="text-[11px] text-emerald-700/70 dark:text-emerald-400/70 font-sans font-normal">Compliant with cryptographic baseline</span>
            </div>
            <div className="w-11 h-11 rounded-xl bg-emerald-100/70 dark:bg-emerald-900/40 border border-emerald-200 dark:border-emerald-800 flex items-center justify-center text-emerald-700 dark:text-emerald-400 shrink-0">
              <span className="material-symbols-outlined text-[22px]">verified_user</span>
            </div>
          </div>

          {/* Insecure Captures */}
          <div className="bg-rose-50/35 dark:bg-rose-950/20 rounded-xl p-5 sm:p-6 border border-rose-200 dark:border-rose-800/60 shadow-xs hover:border-rose-300 dark:hover:border-rose-700 transition-all duration-150 flex items-center justify-between">
            <div className="flex flex-col gap-1">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-rose-800 dark:text-rose-400">
                Insecure Captures
              </span>
              <div className="flex items-baseline gap-2">
                <span className="text-3xl sm:text-4xl font-bold text-rose-700 dark:text-rose-400 tracking-tight font-sans tabular-nums">
                  {insecureReports}
                </span>
                <span className="text-xs font-semibold text-rose-700/90 dark:text-rose-400/90 font-sans tabular-nums">
                  ({insecurePct}%)
                </span>
              </div>
              <span className="text-[11px] text-rose-700/70 dark:text-rose-400/70 font-sans font-normal">Vulnerabilities or anomalies observed</span>
            </div>
            <div className="w-11 h-11 rounded-xl bg-rose-100/70 dark:bg-rose-900/40 border border-rose-200 dark:border-rose-800 flex items-center justify-center text-rose-700 dark:text-rose-400 shrink-0">
              <span className="material-symbols-outlined text-[22px]">warning</span>
            </div>
          </div>
        </div>
      </section>

      {/* FILTER CONTROLS: QUICK DATE OPTIONS & CALENDAR DATE RANGE PICKER */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-white dark:bg-slate-900 rounded-xl px-5 py-3.5 border border-slate-200 dark:border-slate-800 shadow-xs transition-colors duration-150">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="material-symbols-outlined text-[18px] text-[#006591] dark:text-sky-400">tune</span>
          <span className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">
            Dashboard Period Filter
          </span>
          {hasActiveFilter && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-sky-50 dark:bg-sky-950/50 text-[#006591] dark:text-sky-300 border border-sky-200 dark:border-sky-800">
              <span className="w-1.5 h-1.5 rounded-full bg-sky-500 animate-pulse"></span>
              <span>Filtered ({filteredPcaps.length} PCAP{filteredPcaps.length === 1 ? '' : 's'})</span>
            </span>
          )}
        </div>

        {/* SINGLE CLEAN ROW: 4 Quick Options + Calendar Date Picker */}
        <div className="flex items-center gap-2 sm:gap-3 flex-wrap">
          {/* 4 Quick Date Options */}
          <div className="inline-flex items-center gap-1 p-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/80">
            <button
              type="button"
              onClick={() => handleSelectPreset('all')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all duration-150 cursor-pointer ${
                activePreset === 'all'
                  ? 'bg-[#006591] text-white shadow-xs'
                  : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-200/60 dark:hover:bg-slate-700/60'
              }`}
            >
              All Dates
            </button>
            <button
              type="button"
              onClick={() => handleSelectPreset('today')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all duration-150 cursor-pointer ${
                activePreset === 'today'
                  ? 'bg-[#006591] text-white shadow-xs'
                  : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-200/60 dark:hover:bg-slate-700/60'
              }`}
            >
              Today
            </button>
            <button
              type="button"
              onClick={() => handleSelectPreset('7d')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all duration-150 cursor-pointer ${
                activePreset === '7d'
                  ? 'bg-[#006591] text-white shadow-xs'
                  : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-200/60 dark:hover:bg-slate-700/60'
              }`}
            >
              Last 7 Days
            </button>
            <button
              type="button"
              onClick={() => handleSelectPreset('30d')}
              className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all duration-150 cursor-pointer ${
                activePreset === '30d'
                  ? 'bg-[#006591] text-white shadow-xs'
                  : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-200/60 dark:hover:bg-slate-700/60'
              }`}
            >
              Last 30 Days
            </button>
          </div>

          {/* Date calendar/range picker */}
          <ExecutiveDatePicker
            startDate={startDate}
            endDate={endDate}
            onChange={handleCustomDateRangeChange}
            availableDateSet={availableDateSet}
            isCustomActive={activePreset === 'custom'}
          />
        </div>
      </div>

      {/* 2. TREND SECTION: TWO SEPARATE DATE-WISE CHARTS */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* CHART 1: SECURITY STATUS DISTRIBUTION */}
        <div className="bg-white dark:bg-slate-900 rounded-xl p-5 sm:p-6 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col gap-4 transition-colors duration-150 max-w-full overflow-hidden">
          {/* Card Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-3">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="material-symbols-outlined text-[18px] text-[#006591] dark:text-sky-400">verified_user</span>
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">
                Security Status Distribution
              </h2>
              {isScrollable && (
                <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700 shrink-0">
                  <span className="material-symbols-outlined text-[12px]">swap_horiz</span>
                  <span>{numDays} points · Scroll</span>
                </span>
              )}
            </div>

            {/* Legend for Chart 1 */}
            <div className="flex items-center gap-3 text-xs font-medium shrink-0">
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-xs bg-emerald-500"></span>
                <span className="text-slate-700 dark:text-slate-300 text-[11px] font-semibold">Secure</span>
              </div>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-xs bg-rose-500"></span>
                <span className="text-slate-700 dark:text-slate-300 text-[11px] font-semibold">Insecure</span>
              </div>
            </div>
          </div>

          {/* Chart 1 Container with independent horizontal scroll */}
          <div className="w-full flex flex-col pt-1">
            {numDays === 0 ? (
              <div className="h-52 flex flex-col items-center justify-center gap-1.5 text-slate-400 dark:text-slate-500 text-xs font-sans font-normal">
                <span className="material-symbols-outlined text-slate-300 dark:text-slate-600 text-2xl">analytics</span>
                <span>No analyzed session or PCAP report data available</span>
              </div>
            ) : (
              <div className="w-full overflow-x-auto overflow-y-hidden select-none custom-scrollbar rounded-lg pb-1">
                <div
                  style={{
                    width: isScrollable ? `${chartW}px` : '100%',
                    minWidth: '100%',
                    height: `${chartH + 8}px`
                  }}
                  className="relative"
                >
                  <svg className="w-full h-full" preserveAspectRatio="none" viewBox={`0 0 ${chartW} ${chartH}`}>
                    <defs>
                      <linearGradient id="secureBarGradient" x1="0" x2="0" y1="0" y2="1">
                        <stop offset="0%" stopColor="#10b981" stopOpacity="0.85" />
                        <stop offset="100%" stopColor="#059669" stopOpacity="0.65" />
                      </linearGradient>
                      <linearGradient id="insecureBarGradient" x1="0" x2="0" y1="0" y2="1">
                        <stop offset="0%" stopColor="#f43f5e" stopOpacity="0.85" />
                        <stop offset="100%" stopColor="#e11d48" stopOpacity="0.65" />
                      </linearGradient>
                      <linearGradient id="secureBarHoverGradient" x1="0" x2="0" y1="0" y2="1">
                        <stop offset="0%" stopColor="#059669" stopOpacity="1" />
                        <stop offset="100%" stopColor="#047857" stopOpacity="0.85" />
                      </linearGradient>
                      <linearGradient id="insecureBarHoverGradient" x1="0" x2="0" y1="0" y2="1">
                        <stop offset="0%" stopColor="#e11d48" stopOpacity="1" />
                        <stop offset="100%" stopColor="#be123c" stopOpacity="0.85" />
                      </linearGradient>
                    </defs>

                    {/* Y-axis Metric Title */}
                    <text x={padLeft} y={15} textAnchor="start" fill="currentColor" className="text-[9px] font-sans font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                      Reports
                    </text>

                    {/* Y-axis Gridlines & Labels */}
                    {statusTicks.map((val) => {
                      const y = getYStatus(val);
                      const isBaseline = val === 0;
                      return (
                        <g key={`y-axis-status-${val}`}>
                          <line
                            x1={padLeft}
                            x2={chartW - padRight}
                            y1={y}
                            y2={y}
                            stroke={isBaseline ? (theme === 'dark' ? '#475569' : '#cbd5e1') : (theme === 'dark' ? '#1e293b' : '#f1f5f9')}
                            strokeWidth={isBaseline ? '1.25' : '1'}
                          />
                          <text
                            x={padLeft - 8}
                            y={y + 3.5}
                            textAnchor="end"
                            fill="currentColor"
                            className="text-[10px] font-sans text-slate-400 dark:text-slate-500 font-semibold tabular-nums"
                          >
                            {val}
                          </text>
                        </g>
                      );
                    })}

                    {/* Y-axis Spine Line */}
                    <line x1={padLeft} y1={padTop} x2={padLeft} y2={baselineY} stroke={theme === 'dark' ? '#475569' : '#cbd5e1'} strokeWidth="1" />

                    {/* BARS: Secure & Insecure per Date */}
                    {statusChartPoints.map((p, i) => {
                      const isHovered = hoveredStatusIdx === i;
                      return (
                        <g key={`bars-${p.key}`}>
                          {/* Secure Bar */}
                          <rect
                            x={p.secX}
                            y={p.secY}
                            width={singleBarWidth}
                            height={p.secHeight}
                            rx="2"
                            ry="2"
                            fill={isHovered ? 'url(#secureBarHoverGradient)' : 'url(#secureBarGradient)'}
                            stroke="#059669"
                            strokeWidth={isHovered ? '1.5' : '1'}
                            className="transition-all duration-150"
                          />
                          {/* Insecure Bar */}
                          <rect
                            x={p.insecX}
                            y={p.insecY}
                            width={singleBarWidth}
                            height={p.insecHeight}
                            rx="2"
                            ry="2"
                            fill={isHovered ? 'url(#insecureBarHoverGradient)' : 'url(#insecureBarGradient)'}
                            stroke="#e11d48"
                            strokeWidth={isHovered ? '1.5' : '1'}
                            className="transition-all duration-150"
                          />
                          {/* Secure count above bar if > 0 */}
                          {p.secureReports > 0 && (
                            <text
                              x={p.secX + singleBarWidth / 2}
                              y={Math.min(baselineY - 4, p.secY - 4)}
                              textAnchor="middle"
                              fill="currentColor"
                              className={`text-[9px] font-sans font-bold tabular-nums ${isHovered ? 'text-emerald-800 dark:text-emerald-300' : 'text-emerald-600 dark:text-emerald-400'}`}
                            >
                              {p.secureReports}
                            </text>
                          )}
                          {/* Insecure count above bar if > 0 */}
                          {p.insecureReports > 0 && (
                            <text
                              x={p.insecX + singleBarWidth / 2}
                              y={Math.min(baselineY - 4, p.insecY - 4)}
                              textAnchor="middle"
                              fill="currentColor"
                              className={`text-[9px] font-sans font-bold tabular-nums ${isHovered ? 'text-rose-800 dark:text-rose-300' : 'text-rose-600 dark:text-rose-400'}`}
                            >
                              {p.insecureReports}
                            </text>
                          )}
                        </g>
                      );
                    })}

                    {/* X-AXIS LABELS AND TICKS */}
                    {statusChartPoints.map((p, i) => {
                      const isHovered = hoveredStatusIdx === i;
                      return (
                        <g key={`x-axis-status-${p.key}`} className="pointer-events-none">
                          <line x1={p.x} y1={baselineY} x2={p.x} y2={baselineY + 5} stroke={theme === 'dark' ? '#475569' : '#cbd5e1'} strokeWidth="1" />
                          <text
                            x={p.x}
                            y={baselineY + 18}
                            textAnchor="middle"
                            fill="currentColor"
                            className={`text-[11px] ${isHovered ? 'font-bold text-slate-900 dark:text-white' : 'font-semibold text-slate-700 dark:text-slate-300'}`}
                          >
                            {p.label}
                          </text>
                        </g>
                      );
                    })}

                    {/* Interactive Slices for Hover */}
                    {statusChartPoints.map((p, i) => {
                      const colX = p.x - slotWidth / 2;
                      return (
                        <rect
                          key={`hover-col-status-${p.key}`}
                          x={Math.max(padLeft, colX)}
                          y={padTop}
                          width={slotWidth}
                          height={plotH + padBottom}
                          fill="transparent"
                          className="cursor-pointer"
                          onMouseEnter={() => setHoveredStatusIdx(i)}
                          onMouseLeave={() => setHoveredStatusIdx(null)}
                        />
                      );
                    })}
                  </svg>

                  {/* Chart 1 Tooltip */}
                  {hoveredStatusPoint && (
                    <div
                      className="absolute pointer-events-none z-30 transition-all duration-75"
                      style={{
                        left: `${hoveredStatusPoint.x}px`,
                        top: `${Math.min(hoveredStatusPoint.secY, hoveredStatusPoint.insecY)}px`,
                        transform: hoveredStatusPoint.x < 140
                          ? 'translate(10px, -50%)'
                          : hoveredStatusPoint.x > chartW - 140
                            ? 'translate(calc(-100% - 10px), -50%)'
                            : 'translate(-50%, calc(-100% - 16px))'
                      }}
                    >
                      <div className="bg-slate-950/95 backdrop-blur-md text-white rounded-lg shadow-xl border border-slate-800 p-2.5 min-w-[150px] flex flex-col gap-1.5">
                        <div className="text-xs font-semibold text-slate-200 border-b border-slate-800 pb-1">
                          {hoveredStatusPoint.label}
                        </div>
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-slate-400 flex items-center gap-1.5 font-sans">
                            <span className="w-2 h-2 rounded-xs bg-emerald-500"></span>
                            Secure:
                          </span>
                          <span className="font-sans font-bold text-emerald-400 tabular-nums">{hoveredStatusPoint.secureReports}</span>
                        </div>
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-slate-400 flex items-center gap-1.5 font-sans">
                            <span className="w-2 h-2 rounded-xs bg-rose-500"></span>
                            Insecure:
                          </span>
                          <span className="font-sans font-bold text-rose-400 tabular-nums">{hoveredStatusPoint.insecureReports}</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* CHART 2: RISK SCORE TREND */}
        <div className="bg-white dark:bg-slate-900 rounded-xl p-5 sm:p-6 border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col gap-4 transition-colors duration-150 max-w-full overflow-hidden">
          {/* Card Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800 pb-3">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="material-symbols-outlined text-[18px] text-[#006591] dark:text-sky-400">query_stats</span>
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">
                Risk Score Trend
              </h2>
              {trendTrajectory && (
                <span className={`inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full border ${trendTrajectory.colorClass}`}>
                  <span className="material-symbols-outlined text-[12px]">{trendTrajectory.icon}</span>
                  {trendTrajectory.label}
                </span>
              )}
              {isScrollable && (
                <span className="inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700 shrink-0">
                  <span className="material-symbols-outlined text-[12px]">swap_horiz</span>
                  <span>{numDays} points · Scroll</span>
                </span>
              )}
            </div>

            {/* Legend for Chart 2 */}
            <div className="flex items-center gap-3 text-xs font-medium shrink-0">
              <div className="flex items-center gap-1.5">
                <span className="flex items-center">
                  <span className="w-2 h-0.5 bg-slate-800 dark:bg-slate-300"></span>
                  <span className="w-2 h-2 rounded-full border-2 border-slate-800 dark:border-slate-300 bg-white dark:bg-slate-900"></span>
                  <span className="w-2 h-0.5 bg-slate-800 dark:bg-slate-300"></span>
                </span>
                <span className="text-slate-700 dark:text-slate-300 text-[11px] font-semibold">Average Risk Score</span>
              </div>
              {/* Reference dots */}
              <div className="flex items-center gap-2 border-l border-slate-200 dark:border-slate-700 pl-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" title="0–20 Low Risk"></span>
                <span className="w-1.5 h-1.5 rounded-full bg-amber-500" title="21–50 Moderate Risk"></span>
                <span className="w-1.5 h-1.5 rounded-full bg-rose-500" title=">50 High/Critical Risk"></span>
              </div>
            </div>
          </div>

          {/* Chart 2 Container with independent horizontal scroll */}
          <div className="w-full flex flex-col pt-1">
            {numDays === 0 ? (
              <div className="h-52 flex flex-col items-center justify-center gap-1.5 text-slate-400 dark:text-slate-500 text-xs font-sans font-normal">
                <span className="material-symbols-outlined text-slate-300 dark:text-slate-600 text-2xl">analytics</span>
                <span>No analyzed session or PCAP report data available</span>
              </div>
            ) : (
              <div className="w-full overflow-x-auto overflow-y-hidden select-none custom-scrollbar rounded-lg pb-1">
                <div
                  style={{
                    width: isScrollable ? `${chartW}px` : '100%',
                    minWidth: '100%',
                    height: `${chartH + 8}px`
                  }}
                  className="relative"
                >
                  <svg className="w-full h-full" preserveAspectRatio="none" viewBox={`0 0 ${chartW} ${chartH}`}>
                    {/* Y-axis Metric Title */}
                    <text x={padLeft} y={15} textAnchor="start" fill="currentColor" className="text-[9px] font-sans font-semibold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                      Average Risk (0–100)
                    </text>

                    {/* Understated SOC Risk Zone Background Bands */}
                    {/* 80–100: CRITICAL */}
                    <rect
                      x={padLeft}
                      y={getYRisk(100)}
                      width={plotW}
                      height={getYRisk(80) - getYRisk(100)}
                      fill="#f43f5e"
                      fillOpacity="0.025"
                    />
                    {/* 50–80: HIGH */}
                    <rect
                      x={padLeft}
                      y={getYRisk(80)}
                      width={plotW}
                      height={getYRisk(50) - getYRisk(80)}
                      fill="#fb923c"
                      fillOpacity="0.02"
                    />
                    {/* 20–50: MODERATE */}
                    <rect
                      x={padLeft}
                      y={getYRisk(50)}
                      width={plotW}
                      height={getYRisk(20) - getYRisk(50)}
                      fill="#f59e0b"
                      fillOpacity="0.015"
                    />
                    {/* 0–20: LOW */}
                    <rect
                      x={padLeft}
                      y={getYRisk(20)}
                      width={plotW}
                      height={getYRisk(0) - getYRisk(20)}
                      fill="#10b981"
                      fillOpacity="0.02"
                    />

                    {/* Risk Zone Threshold Boundary Lines */}
                    <line
                      x1={padLeft}
                      x2={chartW - padRight}
                      y1={getYRisk(80)}
                      y2={getYRisk(80)}
                      stroke="#f43f5e"
                      strokeOpacity="0.25"
                      strokeDasharray="3 3"
                      strokeWidth="1"
                    />
                    <line
                      x1={padLeft}
                      x2={chartW - padRight}
                      y1={getYRisk(50)}
                      y2={getYRisk(50)}
                      stroke="#fb923c"
                      strokeOpacity="0.22"
                      strokeDasharray="3 3"
                      strokeWidth="1"
                    />
                    <line
                      x1={padLeft}
                      x2={chartW - padRight}
                      y1={getYRisk(20)}
                      y2={getYRisk(20)}
                      stroke="#10b981"
                      strokeOpacity="0.22"
                      strokeDasharray="3 3"
                      strokeWidth="1"
                    />

                    {/* Right Edge Zone Badges */}
                    <text x={chartW - padRight - 4} y={getYRisk(90) + 3} textAnchor="end" className="text-[7.5px] font-sans font-semibold uppercase fill-rose-400/80 pointer-events-none">
                      CRITICAL
                    </text>
                    <text x={chartW - padRight - 4} y={getYRisk(65) + 3} textAnchor="end" className="text-[7.5px] font-sans font-semibold uppercase fill-orange-400/80 pointer-events-none">
                      HIGH
                    </text>
                    <text x={chartW - padRight - 4} y={getYRisk(35) + 3} textAnchor="end" className="text-[7.5px] font-sans font-semibold uppercase fill-amber-400/80 pointer-events-none">
                      MODERATE
                    </text>
                    <text x={chartW - padRight - 4} y={getYRisk(10) + 3} textAnchor="end" className="text-[7.5px] font-sans font-semibold uppercase fill-emerald-400/80 pointer-events-none">
                      LOW
                    </text>

                    {/* Y-axis Gridlines & Labels: 0, 25, 50, 75, 100 */}
                    {[100, 75, 50, 25, 0].map((tick) => {
                      const y = getYRisk(tick);
                      const isBaseline = tick === 0;
                      return (
                        <g key={`y-axis-risk-${tick}`}>
                          <line
                            x1={padLeft}
                            x2={chartW - padRight}
                            y1={y}
                            y2={y}
                            stroke={isBaseline ? (theme === 'dark' ? '#475569' : '#cbd5e1') : (theme === 'dark' ? '#1e293b' : '#f1f5f9')}
                            strokeWidth={isBaseline ? '1.25' : '1'}
                          />
                          <text
                            x={padLeft - 8}
                            y={y + 3.5}
                            textAnchor="end"
                            fill="currentColor"
                            className="text-[10px] font-sans text-slate-400 dark:text-slate-500 font-semibold tabular-nums"
                          >
                            {tick}
                          </text>
                        </g>
                      );
                    })}

                    {/* Left Spine Line */}
                    <line x1={padLeft} y1={padTop} x2={padLeft} y2={baselineY} stroke={theme === 'dark' ? '#475569' : '#cbd5e1'} strokeWidth="1" />

                    {/* LINE SERIES: Average Risk connecting line */}
                    {validRiskPoints.length > 1 && (
                      <path
                        d={smoothLinePath}
                        fill="none"
                        stroke={theme === 'dark' ? '#38bdf8' : '#0f172a'}
                        strokeWidth="2.5"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    )}

                    {/* Single Point vertical drop line if only 1 valid day */}
                    {validRiskPoints.length === 1 && (
                      <line
                        x1={validRiskPoints[0].x}
                        y1={baselineY}
                        x2={validRiskPoints[0].x}
                        y2={validRiskPoints[0].riskY}
                        stroke={theme === 'dark' ? '#38bdf8' : '#0f172a'}
                        strokeDasharray="3 3"
                        strokeWidth="1.5"
                      />
                    )}

                    {/* Hover Vertical Crosshair */}
                    {hoveredRiskPoint && (
                      <line
                        x1={hoveredRiskPoint.x}
                        y1={padTop}
                        x2={hoveredRiskPoint.x}
                        y2={baselineY}
                        stroke="#64748b"
                        strokeWidth="1"
                        strokeDasharray="2 2"
                        strokeOpacity="0.55"
                      />
                    )}

                    {/* LINE SERIES NODES & SCORE LABELS */}
                    {riskChartPoints.map((p, i) => {
                      if (!p.hasValidRisk || p.riskY == null) return null;
                      const isHovered = hoveredRiskIdx === i;
                      return (
                        <g key={`risk-node-${p.key}`} className="pointer-events-none">
                          {isHovered && (
                            <circle cx={p.x} cy={p.riskY} r="8" fill={p.riskDotColor} fillOpacity="0.25" />
                          )}
                          <circle
                            cx={p.x}
                            cy={p.riskY}
                            r={isHovered ? 5.5 : 4}
                            fill={theme === 'dark' ? '#0f172a' : '#ffffff'}
                            stroke={p.riskDotColor}
                            strokeWidth={isHovered ? 2.5 : 2}
                          />
                          <text
                            x={p.x}
                            y={Math.max(16, p.riskY - 8)}
                            textAnchor="middle"
                            fill="currentColor"
                            className={`text-[10px] font-sans font-bold tabular-nums ${isHovered ? 'text-slate-900 dark:text-white' : 'text-slate-700 dark:text-slate-300'}`}
                          >
                            {p.avgRisk}
                          </text>
                        </g>
                      );
                    })}

                    {/* X-AXIS LABELS AND TICKS */}
                    {riskChartPoints.map((p, i) => {
                      const isHovered = hoveredRiskIdx === i;
                      return (
                        <g key={`x-axis-risk-${p.key}`} className="pointer-events-none">
                          <line x1={p.x} y1={baselineY} x2={p.x} y2={baselineY + 5} stroke={theme === 'dark' ? '#475569' : '#cbd5e1'} strokeWidth="1" />
                          <text
                            x={p.x}
                            y={baselineY + 18}
                            textAnchor="middle"
                            fill="currentColor"
                            className={`text-[11px] ${isHovered ? 'font-bold text-slate-900 dark:text-white' : 'font-semibold text-slate-700 dark:text-slate-300'}`}
                          >
                            {p.label}
                          </text>
                        </g>
                      );
                    })}

                    {/* Interactive Slices for Hover */}
                    {riskChartPoints.map((p, i) => {
                      const colX = p.x - slotWidth / 2;
                      return (
                        <rect
                          key={`hover-col-risk-${p.key}`}
                          x={Math.max(padLeft, colX)}
                          y={padTop}
                          width={slotWidth}
                          height={plotH + padBottom}
                          fill="transparent"
                          className="cursor-pointer"
                          onMouseEnter={() => setHoveredRiskIdx(i)}
                          onMouseLeave={() => setHoveredRiskIdx(null)}
                        />
                      );
                    })}
                  </svg>

                  {/* Chart 2 Tooltip */}
                  {hoveredRiskPoint && (
                    <div
                      className="absolute pointer-events-none z-30 transition-all duration-75"
                      style={{
                        left: `${hoveredRiskPoint.x}px`,
                        top: `${hoveredRiskPoint.riskY}px`,
                        transform: hoveredRiskPoint.x < 140
                          ? 'translate(10px, -50%)'
                          : hoveredRiskPoint.x > chartW - 140
                            ? 'translate(calc(-100% - 10px), -50%)'
                            : 'translate(-50%, calc(-100% - 16px))'
                      }}
                    >
                      <div className="bg-slate-950 text-white rounded-lg shadow-xl border border-slate-800 p-2.5 min-w-[170px] max-w-xs flex flex-col gap-1.5 font-sans">
                        <div className="flex items-center justify-between gap-2 border-b border-slate-800 pb-1">
                          <span className="text-[11px] font-mono text-slate-300 font-semibold truncate max-w-[120px]" title={hoveredRiskPoint.pcapsList || hoveredRiskPoint.label}>
                            {hoveredRiskPoint.pcapsList || hoveredRiskPoint.label}
                          </span>
                          <span className="text-[10px] font-mono text-slate-400 shrink-0">
                            {hoveredRiskPoint.label}
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-slate-400 font-sans">AI Risk:</span>
                          <span className="font-bold text-white font-sans tabular-nums">
                            {hoveredRiskPoint.hasValidRisk ? hoveredRiskPoint.avgRisk : 'N/A'}
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-slate-400 font-sans">Risk Level:</span>
                          <span className={`font-semibold px-1.5 py-0.5 rounded text-[10px] uppercase font-sans ${hoveredRiskPoint.riskBadgeClass}`}>
                            {hoveredRiskPoint.riskLevel}
                          </span>
                        </div>
                        <div className="flex items-center justify-between text-xs">
                          <span className="text-slate-400 font-sans">Status:</span>
                          <span className={`font-semibold text-[10px] uppercase font-sans ${hoveredRiskPoint.insecureReports > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                            {hoveredRiskPoint.insecureReports > 0 ? 'INSECURE' : 'SECURE'}
                          </span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* 3. ALL PCAP CAPTURES / CAPTURE HISTORY */}
      <section className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-xs flex flex-col overflow-hidden transition-colors duration-150">
        <div className="p-5 sm:p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 dark:border-slate-800">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[18px] text-[#006591] dark:text-sky-400">history</span>
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">All PCAP Captures</h2>
          </div>
          <span className="font-sans text-xs text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-slate-800 px-2.5 py-1 rounded-lg border border-slate-200 dark:border-slate-700 self-start sm:self-auto font-medium">
            {filteredPcaps.length} {filteredPcaps.length === 1 ? 'Capture' : 'Captures'} {hasActiveFilter ? 'Filtered' : 'Logged'}
          </span>
        </div>

        <div className="overflow-x-auto min-h-[220px]">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-50/80 dark:bg-slate-800/80 text-slate-500 dark:text-slate-400 font-semibold border-b border-slate-200 dark:border-slate-800 text-[11px] uppercase tracking-wider font-sans">
                <th className="py-3 px-4 sm:px-6">File Name</th>
                <th className="py-3 px-4">Security Score</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Key Finding</th>
                <th className="py-3 px-4 sm:px-6 text-right sm:text-center">Report</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {filteredPcaps.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-400 dark:text-slate-500 font-sans font-normal">
                    {displayPcaps.length === 0 ? (
                      <span>No PCAP captures loaded.</span>
                    ) : (
                      <span>
                        No PCAP captures found for the selected date filter.
                        <button
                          type="button"
                          onClick={() => handleSelectPreset('all')}
                          className="ml-2 text-[#006591] dark:text-sky-400 underline font-semibold cursor-pointer"
                        >
                          Reset date filter
                        </button>
                      </span>
                    )}
                  </td>
                </tr>
              ) : (
                filteredPcaps.map((pcapItem, idx) => {
                  const summary = getPcapExecutiveSummary(pcapItem);
                  const isCurrent = (pcapItem.capture_id && capture?.capture_id && pcapItem.capture_id === capture.capture_id)
                    || (pcapItem.filename && capture?.filename && pcapItem.filename.toLowerCase() === capture.filename.toLowerCase());
                  const pcapKey = pcapItem.capture_id || pcapItem.filename || `pcap-${idx}`;
                  const isMenuOpen = openReportMenuPcap === pcapKey;
                  const isGenerating = generatingPcapKey === pcapKey;

                  return (
                    <tr
                      key={pcapItem.capture_id || pcapItem.filename || `pcap-${idx}`}
                      onClick={() => onSelectCapture && onSelectCapture(pcapItem)}
                      className={`transition-all duration-150 cursor-pointer ${
                        isCurrent
                          ? 'bg-sky-50/50 dark:bg-sky-950/30 font-medium'
                          : 'hover:bg-slate-50/80 dark:hover:bg-slate-800/50'
                      }`}
                      title="Click to view details"
                    >
                      <td className="py-3.5 px-4 sm:px-6 font-mono text-slate-900 dark:text-white flex items-center gap-2">
                        <span className="material-symbols-outlined text-[16px] text-[#006591] dark:text-sky-400">description</span>
                        <span className="truncate max-w-xs font-semibold">{summary.filename}</span>
                        {isCurrent && (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-sans font-semibold bg-sky-100 dark:bg-sky-900/60 text-[#006591] dark:text-sky-300 border border-sky-200 dark:border-sky-700 uppercase tracking-wider">
                            Active
                          </span>
                        )}
                      </td>
                      <td className="py-3.5 px-4 font-sans font-bold tabular-nums text-slate-900 dark:text-white">
                        {summary.score}/100
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`px-2.5 py-0.5 rounded-full text-[10px] font-semibold border tracking-wider uppercase font-sans inline-flex items-center gap-1.5 ${summary.statusClass}`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${summary.dotClass}`}></span>
                          {summary.status}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-slate-800 dark:text-slate-200 font-medium">
                        {summary.keyFinding}
                      </td>
                      <td
                        className="py-3.5 px-4 sm:px-6 text-right sm:text-center"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <div className="relative inline-flex items-stretch text-left align-middle" ref={isMenuOpen ? reportMenuRef : null}>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              handleDownloadReport(pcapItem, 'pdf');
                            }}
                            disabled={isGenerating}
                            aria-label={`Download report for ${summary.filename}`}
                            className="inline-flex items-center gap-1.5 px-2.5 h-7 rounded-l-lg border border-r-0 text-xs font-medium transition-all duration-150 cursor-pointer bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 border-slate-200 dark:border-slate-700 shadow-2xs disabled:opacity-60 disabled:cursor-not-allowed"
                            title="Download Report (PDF)"
                          >
                            {isGenerating ? (
                              <>
                                <span className="material-symbols-outlined text-[15px] animate-spin text-[#006591] dark:text-sky-400 leading-none">
                                  progress_activity
                                </span>
                                <span className="font-sans text-[11px] font-medium leading-none">Generating...</span>
                              </>
                            ) : (
                              <>
                                <span className="material-symbols-outlined text-[15px] text-slate-500 dark:text-slate-400 leading-none">
                                  download
                                </span>
                                <span className="leading-none">Download</span>
                              </>
                            )}
                          </button>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setOpenReportMenuPcap(isMenuOpen ? null : pcapKey);
                            }}
                            disabled={isGenerating}
                            aria-label={`Select report format for ${summary.filename}`}
                            aria-expanded={isMenuOpen}
                            aria-haspopup="true"
                            className={`inline-flex items-center justify-center px-1.5 h-7 rounded-r-lg border text-xs font-medium transition-all duration-150 cursor-pointer shadow-2xs ${
                              isMenuOpen
                                ? 'bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 border-slate-900 dark:border-slate-100'
                                : 'bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 border-slate-200 dark:border-slate-700'
                            } disabled:opacity-60 disabled:cursor-not-allowed`}
                            title="Select Report Format"
                          >
                            <span className="material-symbols-outlined text-[14px] leading-none">
                              {isMenuOpen ? 'expand_less' : 'expand_more'}
                            </span>
                          </button>

                          {isMenuOpen && (
                            <div
                              className="absolute right-0 top-full mt-1.5 w-44 bg-white dark:bg-slate-800 rounded-lg shadow-xl border border-slate-200 dark:border-slate-700 py-1.5 z-50 text-xs font-sans animate-in fade-in zoom-in-95 duration-100"
                              role="menu"
                              aria-orientation="vertical"
                              onClick={(e) => e.stopPropagation()}
                            >
                              <div className="px-3 py-1 text-[10px] font-semibold font-sans uppercase tracking-wider text-slate-400 dark:text-slate-500 border-b border-slate-100 dark:border-slate-700/60 mb-1">
                                Download Report
                              </div>
                              <button
                                type="button"
                                onClick={() => handleDownloadReport(pcapItem, 'pdf')}
                                className="w-full px-3 py-2 text-left text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700/70 flex items-center gap-2 cursor-pointer transition-colors"
                                role="menuitem"
                              >
                                <span className="material-symbols-outlined text-[16px] text-rose-600 dark:text-rose-400">
                                  picture_as_pdf
                                </span>
                                <span className="font-medium">PDF Document</span>
                              </button>
                              <button
                                type="button"
                                onClick={() => handleDownloadReport(pcapItem, 'json')}
                                className="w-full px-3 py-2 text-left text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700/70 flex items-center gap-2 cursor-pointer transition-colors"
                                role="menuitem"
                              >
                                <span className="material-symbols-outlined text-[16px] text-blue-600 dark:text-sky-400">
                                  data_object
                                </span>
                                <span className="font-medium">JSON Data</span>
                              </button>
                              <button
                                type="button"
                                onClick={() => handleDownloadReport(pcapItem, 'html')}
                                className="w-full px-3 py-2 text-left text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700/70 flex items-center gap-2 cursor-pointer transition-colors"
                                role="menuitem"
                              >
                                <span className="material-symbols-outlined text-[16px] text-indigo-600 dark:text-indigo-400">
                                  html
                                </span>
                                <span className="font-medium">HTML Standalone</span>
                              </button>
                              <button
                                type="button"
                                onClick={() => handleDownloadReport(pcapItem, 'xlsx')}
                                className="w-full px-3 py-2 text-left text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700/70 flex items-center gap-2 cursor-pointer transition-colors"
                                role="menuitem"
                              >
                                <span className="material-symbols-outlined text-[16px] text-emerald-600 dark:text-emerald-400">
                                  table_chart
                                </span>
                                <span className="font-medium">XLSX Workbook</span>
                              </button>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Floating Export Feedback Notification */}
      {exportFeedback && (
        <div
          className={`fixed bottom-6 right-6 z-50 px-4 py-3 rounded-xl shadow-lg border text-xs flex items-center gap-2.5 animate-in fade-in slide-in-from-bottom-2 ${
            exportFeedback.type === 'error'
              ? 'bg-rose-50 dark:bg-rose-950/80 border-rose-200 dark:border-rose-800 text-rose-800 dark:text-rose-200'
              : 'bg-slate-900 dark:bg-slate-800 border-slate-800 dark:border-slate-700 text-white'
          }`}
        >
          <span className={`material-symbols-outlined text-[18px] ${
            exportFeedback.type === 'error' ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-400'
          }`}>
            {exportFeedback.type === 'error' ? 'error' : 'check_circle'}
          </span>
          <span>{exportFeedback.message}</span>
        </div>
      )}

    </div>
  );
}
