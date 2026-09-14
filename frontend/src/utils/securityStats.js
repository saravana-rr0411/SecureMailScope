/**
 * Canonical Security Statistics and Daily Trend Derivation
 * Single Source of Truth helper for SecureMailScope.
 */

/**
 * Resolves the deterministic security posture for a PCAP capture.
 * Returns 'SECURE', 'AT_RISK', or 'INCOMPLETE'.
 * Strictly separates confirmed deterministic vulnerabilities from incomplete captures.
 *
 * @param {Object} pcap
 * @returns {'SECURE' | 'AT_RISK' | 'INCOMPLETE'}
 */
export function getPcapSecurityPosture(pcap) {
  if (!pcap) return 'INCOMPLETE';

  const rawTopPosture = (
    pcap.posture?.security_posture ??
    pcap.security_posture ??
    pcap.posture?.status ??
    ""
  );
  const topStatus = String(rawTopPosture).trim().toUpperCase();

  const sessions = pcap.sessions || [];
  if (sessions.length === 0) {
    if (topStatus === 'SECURE') return 'SECURE';
    if (topStatus === 'AT_RISK' || topStatus === 'COMPROMISED') return 'AT_RISK';
    return 'INCOMPLETE';
  }

  // Check if any session has confirmed vulnerabilities
  const hasConfirmedVulnerabilities = sessions.some((s) => {
    const findings = s.assessment?.findings || s.findings || [];
    const crit = findings.filter((f) => f.severity === 'CRITICAL').length;
    const high = findings.filter((f) => f.severity === 'HIGH').length;
    const med = findings.filter((f) => f.severity === 'MEDIUM').length;
    const sStatus = String(s.posture?.security_posture ?? "").trim().toUpperCase();
    return crit > 0 || high > 0 || (med > 0 && sStatus === 'AT_RISK') || sStatus === 'COMPROMISED' || (sStatus === 'AT_RISK' && hasConfirmedPlaintextPayload(s));
  });

  if (hasConfirmedVulnerabilities) {
    return 'AT_RISK';
  }

  // If at least one session has verified SECURE posture, the capture is SECURE
  const hasSecureSession = sessions.some((s) => {
    const sStatus = String(s.posture?.security_posture ?? "").trim().toUpperCase();
    return sStatus === 'SECURE';
  });

  if (hasSecureSession) {
    return 'SECURE';
  }

  if (topStatus === 'SECURE') {
    return 'SECURE';
  }

  if (topStatus === 'AT_RISK' || topStatus === 'COMPROMISED') {
    // Only classify as AT_RISK if there are confirmed findings or confirmed plaintext
    if (sessions.some((s) => (s.assessment?.findings || s.findings || []).length > 0 || hasConfirmedPlaintextPayload(s))) {
      return 'AT_RISK';
    }
  }

  return 'INCOMPLETE';
}

/**
 * Determine if a PCAP capture has a canonical SECURE status.
 * Evaluates the capture's canonical security posture field and multi-session contexts.
 * SECURE -> true.
 * Confirmed vulnerabilities (AT_RISK / COMPROMISED) -> false.
 * Multi-session captures with verified TLS sessions are not penalized by incomplete connection stubs.
 * Does NOT infer status from numerical AI risk scores.
 *
 * @param {Object} pcap
 * @returns {boolean}
 */
export function isPcapSecure(pcap) {
  return getPcapSecurityPosture(pcap) === 'SECURE';
}

/**
 * Verifies whether a session genuinely contains confirmed plaintext email application data.
 * Arbitrary single bytes (e.g. 0x00), ACK-only payloads, TCP window probes, or padding
 * are NOT classified as plaintext application data.
 *
 * @param {Object} session
 * @returns {boolean}
 */
export function hasConfirmedPlaintextPayload(session) {
  if (!session) return false;
  if (session.tls?.detected === true) return false;

  const evidence = session.evidence || [];
  if (evidence.some((e) => ['banner', 'payload', 'command', 'response'].includes(e.type))) {
    return true;
  }

  const findings = session.assessment?.findings || session.findings || [];
  if (findings.some((f) => {
    const t = String(f.title || '').toLowerCase();
    return t.includes('plaintext') || t.includes('unencrypted');
  })) {
    return true;
  }

  const cPayload = String(session.client_payload || '');
  const sPayload = String(session.server_payload || '');
  const combined = (cPayload + '\n' + sPayload).trim();

  if (combined.length <= 3) return false;
  // eslint-disable-next-line no-control-regex
  const printable = combined.replace(/[\x00-\x08\x0e-\x1f\x7f]/g, '').trim();
  if (printable.length <= 3) return false;

  const emailTokens = /\b(EHLO|HELO|MAIL FROM:|RCPT TO:|DATA\b|QUIT\b|AUTH\s|STARTTLS|STLS|USER\s|PASS\s|STAT\b|LIST\b|RETR\b|DELE\b|UIDL\b|CAPA\b|\* OK\b|\* PREAUTH\b|\+OK\b|-ERR\b|220\s|250\s|354\s|A\d+\s+LOGIN|A\d+\s+CAPABILITY|A\d+\s+SELECT)/i;
  return emailTokens.test(combined);
}

/**
 * Parse PCAP timestamp safely into epoch milliseconds in local time.
 * Handles ISO timestamps with tz offsets, numeric timestamps, and bare YYYY-MM-DD dates without shifting.
 *
 * @param {Object} pcap
 * @returns {number | null}
 */
export function parsePcapTimestamp(pcap) {
  if (!pcap) return null;
  const raw = pcap.analyzed_at || pcap.analyzedAt || pcap.timestamp;
  if (!raw) return null;

  if (raw instanceof Date) {
    const t = raw.getTime();
    return isNaN(t) ? null : t;
  }

  if (typeof raw === 'number') {
    const ms = raw < 1e11 ? raw * 1000 : raw;
    return isNaN(ms) ? null : ms;
  }

  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    if (!trimmed) return null;

    // Bare date YYYY-MM-DD without time or timezone: treat as local midnight
    if (/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
      const [y, m, d] = trimmed.split('-').map(Number);
      return new Date(y, m - 1, d, 0, 0, 0, 0).getTime();
    }

    const dt = new Date(trimmed);
    const ms = dt.getTime();
    if (!isNaN(ms)) return ms;
  }

  return null;
}

/**
 * Extract canonical YYYY-MM-DD local date key from PCAP item.
 *
 * @param {Object} pcap
 * @returns {string}
 */
export function getPcapDateKey(pcap) {
  const ms = parsePcapTimestamp(pcap);
  if (ms == null) return '';
  const d = new Date(ms);
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

/**
 * Extract the analysis/capture timestamp for calendar grouping as a local Date object.
 * Prioritizes analyzed_at, followed by analyzedAt or timestamp.
 * Defaults to current date if missing.
 *
 * @param {Object} pcap
 * @returns {Date}
 */
export function getCaptureDate(pcap) {
  const ms = parsePcapTimestamp(pcap);
  if (ms != null) return new Date(ms);
  return new Date();
}

/**
 * Derive shared security statistics from an array of analyzed PCAPs.
 * Total = analyzed PCAP count
 * Secure = number of analyzed PCAPs with canonical SECURE status
 * Insecure = Total - Secure
 * Total = Secure + Insecure
 *
 * @param {Array<Object>} analyzedPcaps
 * @returns {Object}
 */
export function deriveSecurityStats(analyzedPcaps = []) {
  const pcaps = Array.isArray(analyzedPcaps) ? analyzedPcaps : [];
  const total = pcaps.length;
  let secure = 0;

  pcaps.forEach((p) => {
    if (isPcapSecure(p)) {
      secure++;
    }
  });

  const insecure = total - secure;
  const securePct = total > 0 ? Math.round((secure / total) * 100) : 0;
  const insecurePct = total > 0 ? Math.round((insecure / total) * 100) : 0;

  // Explicit session counts across all PCAPs
  let totalSessions = 0;
  let secureSessions = 0;
  let insecureSessions = 0;
  let incompleteSessions = 0;

  pcaps.forEach((p) => {
    const sessions = p.sessions || [];
    totalSessions += sessions.length;
    sessions.forEach((s) => {
      const sStatus = String(
        s.posture?.security_posture ??
        s.security_posture ??
        s.posture?.status ??
        ""
      ).trim().toUpperCase();
      if (sStatus === "SECURE") {
        secureSessions++;
      } else if (sStatus === "INCOMPLETE" || sStatus === "NOT_OBSERVABLE") {
        incompleteSessions++;
      } else {
        insecureSessions++;
      }
    });
  });

  // Fleet AI risk average across all PCAPs using capture.ai_risk.score
  const validAiScores = [];
  pcaps.forEach((p) => {
    const score = p.ai_risk?.score != null
      ? Number(p.ai_risk.score)
      : (p.sessions?.[0]?.ai_risk?.score != null
        ? Number(p.sessions[0].ai_risk.score)
        : null);
    if (typeof score === 'number' && !isNaN(score) && isFinite(score)) {
      validAiScores.push(score);
    }
  });

  const fleetAvgRisk = validAiScores.length > 0
    ? Number((validAiScores.reduce((sum, v) => sum + v, 0) / validAiScores.length).toFixed(1))
    : null;

  return {
    total,
    secure,
    insecure,
    securePct,
    insecurePct,
    totalSessions,
    secureSessions,
    insecureSessions,
    incompleteSessions,
    fleetAvgRisk
  };
}

/**
 * Canonical centralized threshold function for AI Risk tier.
 * 0–20.0       → LOW
 * 20.1–50.0    → MODERATE
 * 50.1–80.0    → HIGH
 * 80.1–100     → CRITICAL
 *
 * @param {number|string} score
 * @returns {"LOW" | "MODERATE" | "HIGH" | "CRITICAL"}
 */
export function scoreToRiskTier(score) {
  if (score == null || score === '') return 'LOW';
  const num = Number(score);
  if (isNaN(num)) return 'LOW';
  if (num <= 20.0) return 'LOW';
  if (num <= 50.0) return 'MODERATE';
  if (num <= 80.0) return 'HIGH';
  return 'CRITICAL';
}

/**
 * Returns canonical operational risk tier from an AI risk object or score.
 *
 * @param {Object|number|string} aiRiskOrScore
 * @returns {"LOW" | "MODERATE" | "HIGH" | "CRITICAL"}
 */
export function getAiRiskTier(aiRiskOrScore) {
  if (aiRiskOrScore == null) return 'LOW';
  if (typeof aiRiskOrScore === 'number' || typeof aiRiskOrScore === 'string') {
    return scoreToRiskTier(aiRiskOrScore);
  }
  if (aiRiskOrScore.operational_risk_tier) {
    const tier = String(aiRiskOrScore.operational_risk_tier).toUpperCase();
    if (['LOW', 'MODERATE', 'HIGH', 'CRITICAL'].includes(tier)) return tier;
  }
  if (aiRiskOrScore.label) {
    const label = String(aiRiskOrScore.label).toUpperCase();
    if (['LOW', 'MODERATE', 'HIGH', 'CRITICAL'].includes(label)) return label;
  }
  if (aiRiskOrScore.score != null) {
    return scoreToRiskTier(aiRiskOrScore.score);
  }
  return 'LOW';
}

/**
 * Derive chronological daily trends from analyzed PCAPs.
 * For each calendar date:
 * - count analyzed reports/PCAPs
 * - count Secure
 * - count Insecure
 * - average AI risk scores (capture.ai_risk.score)
 *
 * @param {Array<Object>} analyzedPcaps
 * @returns {Array<Object>}
 */
export function deriveDailyTrends(analyzedPcaps = []) {
  const pcaps = Array.isArray(analyzedPcaps) ? analyzedPcaps : [];
  if (pcaps.length === 0) return [];

  const dayMap = new Map();

  pcaps.forEach((pcap) => {
    const dayKey = getPcapDateKey(pcap);
    if (!dayKey) return;
    const d = getCaptureDate(pcap);
    const label = d.toLocaleDateString('en-US', { month: 'short', day: '2-digit' });

    if (!dayMap.has(dayKey)) {
      dayMap.set(dayKey, {
        dayKey,
        label,
        dateObj: d,
        pcaps: []
      });
    }

    dayMap.get(dayKey).pcaps.push(pcap);
  });

  // Sort chronologically
  const dayList = Array.from(dayMap.values()).sort((a, b) => a.dayKey.localeCompare(b.dayKey));

  return dayList.map((day) => {
    let secureReports = 0;
    const validAiScores = [];
    let totalSessions = 0;

    day.pcaps.forEach((p) => {
      if (isPcapSecure(p)) {
        secureReports++;
      }
      const score = p.ai_risk?.score != null
        ? Number(p.ai_risk.score)
        : (p.sessions?.[0]?.ai_risk?.score != null
          ? Number(p.sessions[0].ai_risk.score)
          : null);
      if (typeof score === 'number' && !isNaN(score) && isFinite(score)) {
        validAiScores.push(score);
      }
      totalSessions += (p.sessions?.length || 0);
    });

    const totalReports = day.pcaps.length;
    const insecureReports = totalReports - secureReports;

    const hasValidRisk = validAiScores.length > 0;
    const avgRisk = hasValidRisk
      ? Math.round(validAiScores.reduce((sum, v) => sum + v, 0) / validAiScores.length)
      : null;

    const riskTier = avgRisk != null ? scoreToRiskTier(avgRisk) : null;
    const riskLevel = riskTier != null ? riskTier : 'Unscored';

    const riskDotColor = riskTier != null
      ? (riskTier === 'LOW'
          ? '#10b981'
          : riskTier === 'MODERATE'
            ? '#f59e0b'
            : riskTier === 'HIGH'
              ? '#f43f5e'
              : '#991b1b')
      : '#94a3b8';

    const riskBadgeClass = riskTier != null
      ? (riskTier === 'LOW'
          ? 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10'
          : riskTier === 'MODERATE'
            ? 'text-amber-400 border-amber-500/30 bg-amber-500/10'
            : riskTier === 'HIGH'
              ? 'text-rose-400 border-rose-500/30 bg-rose-500/10'
              : 'text-rose-300 border-rose-600/40 bg-rose-950/40')
      : 'text-slate-400 border-slate-700 bg-slate-800';

    return {
      key: `day-${day.dayKey}`,
      dayKey: day.dayKey,
      label: day.label,
      secureReports,
      insecureReports,
      totalReports,
      reports: totalReports,
      avgRisk,
      hasValidRisk,
      riskLevel,
      riskTier,
      riskDotColor,
      riskBadgeClass,
      totalSessions,
      pcapsList: day.pcaps.map((p) => p.filename || 'capture.pcap').join(', ')
    };
  });
}
