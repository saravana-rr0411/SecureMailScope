import React, { useState } from 'react';
import { getAiRiskTier, hasConfirmedPlaintextPayload } from '../utils/securityStats';

const PIPELINE_STAGE_METADATA = {
  1: { num: '01', name: 'PCAP' },
  2: { num: '02', name: 'Protocol Detection' },
  3: { num: '03', name: 'TCP Stream Reconstruction' },
  4: { num: '04', name: 'STARTTLS Detection' },
  5: { num: '05', name: 'TLS Handshake Analysis' },
  6: { num: '06', name: 'Certificate / Chain Validation' },
  7: { num: '07', name: 'Security Assessment' },
  8: { num: '08', name: 'AI Risk Analysis' },
  9: { num: '09', name: 'Final Result' }
};

/**
 * Maps a security finding to the forensic processing pipeline stage (01-09)
 * that evaluated and detected that condition.
 */
function getPipelineStageForFinding(finding) {
  if (!finding) return PIPELINE_STAGE_METADATA[7];
  const category = (finding.category || '').toUpperCase();
  const id = (finding.id || finding.finding_id || '').toLowerCase();
  const text = `${finding.label || ''} ${finding.title || ''} ${finding.reason || ''} ${finding.description || ''}`.toLowerCase();

  // Stage 01: PCAP
  if (category === 'PCAP' || category === 'CAPTURE' || text.includes('pcap') || text.includes('packet capture')) {
    return PIPELINE_STAGE_METADATA[1];
  }
  // Stage 02: Protocol Detection
  if (category === 'PROTOCOL' || category === 'PROTOCOL_DETECTION' || id.includes('proto') || text.includes('protocol detection')) {
    return PIPELINE_STAGE_METADATA[2];
  }
  // Stage 03: TCP Stream Reconstruction
  if (category === 'RECONSTRUCTION' || category === 'TCP' || id.includes('tcp') || text.includes('stream reconstruction') || text.includes('tcp stream')) {
    return PIPELINE_STAGE_METADATA[3];
  }
  // Stage 04: STARTTLS Detection
  if (
    category === 'PROTOCOL_NEGOTIATION' ||
    category === 'STARTTLS' ||
    id.includes('starttls') ||
    id.includes('stls') ||
    id.includes('plaintext') ||
    text.includes('starttls') ||
    text.includes('stls') ||
    text.includes('cleartext') ||
    text.includes('plaintext') ||
    text.includes('unencrypted application')
  ) {
    return PIPELINE_STAGE_METADATA[4];
  }
  // Stage 06: Certificate / Chain Validation
  if (
    category === 'CERTIFICATE' ||
    category === 'CERTIFICATE_CHAIN' ||
    id.includes('cert') ||
    id.includes('chain') ||
    id.includes('san') ||
    text.includes('cert') ||
    text.includes('chain') ||
    text.includes('expired') ||
    text.includes('hostname') ||
    text.includes('self-signed') ||
    text.includes('ca ') ||
    text.includes('x.509') ||
    text.includes('san/cn')
  ) {
    return PIPELINE_STAGE_METADATA[6];
  }
  // Stage 05: TLS Handshake Analysis
  if (
    category === 'TLS_CONFIGURATION' ||
    category === 'CIPHER_SUITE' ||
    category === 'KEY_EXCHANGE' ||
    id.includes('tls') ||
    id.includes('cipher') ||
    id.includes('pfs') ||
    text.includes('tls') ||
    text.includes('ssl') ||
    text.includes('cipher') ||
    text.includes('forward secrecy') ||
    text.includes('pfs') ||
    text.includes('encryption not established')
  ) {
    return PIPELINE_STAGE_METADATA[5];
  }
  // Stage 08: AI Risk Analysis
  if (
    category === 'AI_RISK' ||
    category === 'ML' ||
    id.includes('ai') ||
    /\bai\b/.test(text) ||
    text.includes('risk score') ||
    text.includes('anomaly') ||
    text.includes('random forest') ||
    text.includes('isolation forest')
  ) {
    return PIPELINE_STAGE_METADATA[8];
  }
  // Stage 09: Final Result
  if (category === 'FINAL_RESULT' || text.includes('overall posture') || text.includes('final result')) {
    return PIPELINE_STAGE_METADATA[9];
  }
  // Stage 07: Security Assessment (default deterministic assessment finding)
  return PIPELINE_STAGE_METADATA[7];
}

export default function ForensicsScreen({
  capture,
  selectedSessionId,
  onSelectSession,
  onExport,
  isExportOpen,
  setIsExportOpen,
  exportRef,
  theme = 'light'
}) {
  const [showSessionBrowser, setShowSessionBrowser] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [isDownloadingPcap, setIsDownloadingPcap] = useState(false);
  const [pcapDownloadError, setPcapDownloadError] = useState(null);

  const sessions = capture?.sessions || [];
  const totalSessions = sessions.length;
  const filename = capture?.filename || "capture.pcap";
  const totalPackets = capture?.total_packets ?? (totalSessions * 148);

  const handleDownloadPcap = async () => {
    if (!capture || isDownloadingPcap) return;
    const targetId = capture.capture_id || capture.id || capture.filename;
    if (!targetId) return;

    setIsDownloadingPcap(true);
    setPcapDownloadError(null);

    const apiBase = import.meta.env.VITE_API_BASE ?? '';
    const candidateUrls = [];
    if (capture.pcap_download_url) {
      candidateUrls.push(
        capture.pcap_download_url.startsWith('http')
          ? capture.pcap_download_url
          : `${apiBase}${capture.pcap_download_url}`
      );
    }
    if (apiBase) {
      candidateUrls.push(`${apiBase}/api/capture/download/${encodeURIComponent(targetId)}`);
      if (capture.filename && capture.filename !== targetId) {
        candidateUrls.push(`${apiBase}/api/capture/download/${encodeURIComponent(capture.filename)}`);
      }
    }
    candidateUrls.push(`/api/capture/download/${encodeURIComponent(targetId)}`);
    if (capture.filename && capture.filename !== targetId) {
      candidateUrls.push(`/api/capture/download/${encodeURIComponent(capture.filename)}`);
    }
    if (typeof window !== 'undefined' && (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')) {
      candidateUrls.push(`http://127.0.0.1:8000/api/capture/download/${encodeURIComponent(targetId)}`);
      if (capture.filename && capture.filename !== targetId) {
        candidateUrls.push(`http://127.0.0.1:8000/api/capture/download/${encodeURIComponent(capture.filename)}`);
      }
    }

    // Deduplicate candidate URLs
    const uniqueUrls = [...new Set(candidateUrls)];

    let downloaded = false;
    for (const url of uniqueUrls) {
      try {
        const res = await fetch(url);
        if (res.ok) {
          const blob = await res.blob();
          const downloadUrl = window.URL.createObjectURL(blob);
          const link = document.createElement('a');
          link.href = downloadUrl;
          link.download = capture.pcap_filename || capture.filename || `${targetId}.pcap`;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          setTimeout(() => window.URL.revokeObjectURL(downloadUrl), 2000);
          downloaded = true;
          break;
        }
      } catch (fetchErr) {
        console.warn(`Failed to download PCAP from ${url}:`, fetchErr);
      }
    }

    setIsDownloadingPcap(false);
    if (!downloaded) {
      setPcapDownloadError("Raw PCAP file is not available on backend or has expired from cache.");
      setTimeout(() => setPcapDownloadError(null), 4000);
    }
  };

  if (!capture || sessions.length === 0) {
    return (
      <div className="w-full max-w-6xl mx-auto flex flex-col items-center justify-center min-h-[400px] bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-8 text-center">
        <span className="material-symbols-outlined text-4xl text-slate-400 dark:text-slate-600 mb-3">biotech</span>
        <h3 className="text-base font-bold text-slate-900 dark:text-white">No Capture Loaded for Forensics</h3>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1 max-w-md">
          Upload or select a PCAP capture from the Executive Dashboard to view detailed cryptographic reconstruction and forensic analysis.
        </p>
      </div>
    );
  }

  // Selected session lookup (or fallback to first)
  const selectedSession = sessions.find(s => s.session_id === selectedSessionId) || sessions[0] || {};
  const sessId = selectedSession.session_id || "TCP-001";
  const protocol = selectedSession.protocol || "UNKNOWN";
  const srcIp = selectedSession.source_ip || "0.0.0.0";
  const srcPort = selectedSession.source_port || 0;
  const dstIp = selectedSession.destination_ip || "0.0.0.0";
  const dstPort = selectedSession.destination_port || 0;

  const c2sBytes = selectedSession.client_to_server_bytes || 0;
  const s2cBytes = selectedSession.server_to_client_bytes || 0;
  const formatBytes = (bytes) => {
    if (!bytes || bytes === 0) return "0 B";
    return bytes > 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${bytes} B`;
  };

  // Filtered session list for session browser
  const filteredSessions = sessions.filter((s) => {
    const matchesProto = protocolFilter === 'ALL' || s.protocol === protocolFilter;
    const query = searchTerm.toLowerCase();
    const matchesSearch = !searchTerm ||
      s.session_id?.toLowerCase().includes(query) ||
      s.source_ip?.toLowerCase().includes(query) ||
      s.destination_ip?.toLowerCase().includes(query) ||
      s.protocol?.toLowerCase().includes(query);
    return matchesProto && matchesSearch;
  });

  // ============================================================================
  // SECTION 2: PRIMARY SECURITY RESULT (Strictly from Backend Data)
  // ============================================================================
  const aiRisk = selectedSession.ai_risk || {};
  const aiScore = aiRisk.score != null ? Number(aiRisk.score).toFixed(1) : "—";
  const aiScoreNum = aiRisk.score != null ? Number(aiRisk.score) : 0;
  const operationalRiskTier = getAiRiskTier(aiRisk);
  const aiLabel = operationalRiskTier;
  const modelPredictedClass = aiRisk.model_predicted_class || aiRisk.predicted_class;
  const aiConfidence = aiRisk.confidence != null ? Math.round(aiRisk.confidence * 100) : 95;

  const postureData = selectedSession.posture || {};
  const tls = selectedSession.tls || {};
  const isTlsObserved = tls.detected === true || (tls.version && tls.version !== 'None' && tls.version !== 'Plaintext');
  const postureStatus = postureData.security_posture || selectedSession.security_posture || (isTlsObserved ? "SECURE" : "AT_RISK");
  const postureScore = postureData.score != null ? postureData.score : (postureStatus === 'SECURE' ? 100 : 25);

  const anomalyData = selectedSession.ai_analysis || {};
  const isAnomaly = anomalyData.anomaly_detected === true;
  const anomalyStatus = isAnomaly ? "OUTLIER" : "NORMAL";
  const anomalyScore = anomalyData.anomaly_score != null ? Number(anomalyData.anomaly_score).toFixed(2) : "0.00";

  // Score Badge & Color Mapping (Standard AI Risk: 0-20 Low Risk [Emerald], 21-50 Moderate [Amber], >50 High/Crit [Rose])
  let riskBadgeColor = "bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-400 border-emerald-200 dark:border-emerald-800";
  let riskDotColor = "bg-emerald-500";
  let riskGaugeColor = "#059669";
  if (aiLabel === "CRITICAL" || aiLabel === "HIGH") {
    riskBadgeColor = "bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-800";
    riskDotColor = "bg-rose-600";
    riskGaugeColor = "#dc2626";
  } else if (aiLabel === "MODERATE") {
    riskBadgeColor = "bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800";
    riskDotColor = "bg-amber-500";
    riskGaugeColor = "#d97706";
  }

  // Circular gauge calculations (r=54, circumference = 2 * PI * 54 = 339.29)
  const circumference = 339.29;
  const clampedScore = Math.max(0, Math.min(100, aiScoreNum));
  const dashOffset = Number((circumference - (circumference * clampedScore) / 100).toFixed(2));

  // ============================================================================
  // OBSERVED FORENSIC STATE & PROTOCOL ATTRIBUTES
  // ============================================================================
  const cert = tls.certificate || {};
  const chainValidation = tls.certificate_chain_validation || cert.certificate_chain || {};
  const starttls = selectedSession.starttls || {};

  // ============================================================================
  // SECTION 3: "WHAT IS WRONG?" (Security Findings from Backend Assessment Engine)
  // Strictly consumes the actual backend finding array (selectedSession.assessment.findings)
  // ============================================================================
  const assessmentFindings = selectedSession.assessment?.findings || selectedSession.findings || [];

  const rawFindings = [];

  // Map deterministic findings directly from backend assessment engine
  assessmentFindings.forEach((f) => {
    const isNegative = f.severity !== 'INFO' && f.severity !== 'PASS';
    rawFindings.push({
      id: f.finding_id || f.title,
      label: f.title,
      isFail: isNegative,
      severity: f.severity || 'HIGH',
      category: f.category || 'ASSESSMENT',
      reason: f.reason || '',
      description: f.description || f.reason || '',
      evidence: f.evidence || [],
      recommendation: f.recommendation || ''
    });
  });

  // Deduplicate findings by label
  const findingsList = [];
  const seenLabels = new Set();
  rawFindings.forEach(f => {
    if (!seenLabels.has(f.label)) {
      seenLabels.add(f.label);
      findingsList.push(f);
    }
  });


  // ============================================================================
  // SECTION E: RECOMMENDED ACTIONS (Concise Administrator Remediation)
  // Answers: What should the administrator do?
  // Recommendations strictly use existing findings & state. Does NOT alter AI risk.
  // ============================================================================
  const recommendedActions = [];

  const isConfirmedPlaintext = hasConfirmedPlaintextPayload(selectedSession);
  const isIncompleteSession = (postureStatus === 'INCOMPLETE' || (!isTlsObserved && !isConfirmedPlaintext)) && assessmentFindings.length === 0;

  const hasCriticalOrHighIssues = (!isTlsObserved && isConfirmedPlaintext) ||
    aiLabel === 'CRITICAL' ||
    aiLabel === 'HIGH' ||
    postureStatus === 'COMPROMISED' ||
    postureStatus === 'AT_RISK' ||
    assessmentFindings.some(f => f.severity === 'CRITICAL' || f.severity === 'HIGH' || f.severity === 'MEDIUM');

  if (isIncompleteSession) {
    recommendedActions.push("Insufficient capture data to fully evaluate session. Capture a complete TLS handshake to verify cipher and certificate parameters.");
  } else if (!hasCriticalOrHighIssues && isTlsObserved) {
    // Secure TLS session: show ONLY standard monitoring
    recommendedActions.push("No immediate action required. Continue standard security monitoring.");
  } else {
    const hasPlaintext = (!isTlsObserved && isConfirmedPlaintext) ||
      assessmentFindings.some(f => f.title?.toLowerCase().includes('plaintext') || f.title?.toLowerCase().includes('unencrypted'));

    const hasStarttlsIssue = starttls.status === 'INCOMPLETE' ||
      (starttls.upgrade_supported && !starttls.accepted) ||
      assessmentFindings.some(f => f.title?.toLowerCase().includes('starttls') || f.title?.toLowerCase().includes('stls'));

    const hasCert = Boolean(cert.subject || cert.issuer || cert.common_name);
    const certExpired = hasCert && (cert.expired === true || cert.expiration_status === 'EXPIRED' || assessmentFindings.some(f => f.title?.toLowerCase().includes('expired')));
    const hostnameMismatch = hasCert && (cert.hostname_match === false || assessmentFindings.some(f => f.title?.toLowerCase().includes('hostname')));
    const chainIssue = hasCert && (chainValidation.chain_valid === false || assessmentFindings.some(f => f.title?.toLowerCase().includes('chain')));
    const isSelfSigned = hasCert && (cert.self_signed === true || assessmentFindings.some(f => f.title?.toLowerCase().includes('self-signed')));
    const weakTlsOrCipher = (isTlsObserved && (tls.version === 'TLS 1.0' || tls.version === 'TLS 1.1' || tls.version === 'SSLv3' || tls.version === 'SSLv2')) ||
      assessmentFindings.some(f => f.title?.toLowerCase().includes('cipher') || f.title?.toLowerCase().includes('deprecated') || f.title?.toLowerCase().includes('weak tls'));
    const noForwardSecrecy = isTlsObserved && tls.forward_secrecy === false && !weakTlsOrCipher;

    // Prioritized remediation actions: first include recommendations directly from backend findings
    assessmentFindings.forEach(f => {
      if (f.recommendation && !recommendedActions.includes(f.recommendation)) {
        recommendedActions.push(f.recommendation);
      }
    });

    if (hasStarttlsIssue) {
      recommendedActions.push("Enable STARTTLS and enforce TLS before authentication.");
    }
    if (hasPlaintext) {
      recommendedActions.push("Disable plaintext authentication and require encrypted mail transport.");
    }
    if (!isTlsObserved && !hasStarttlsIssue && isConfirmedPlaintext) {
      recommendedActions.push("Require TLS for mail sessions and prevent plaintext fallback.");
    }
    if (certExpired) {
      recommendedActions.push("Renew the expired certificate and redeploy the valid certificate chain.");
    }
    if (hostnameMismatch) {
      recommendedActions.push("Correct the certificate SAN/CN to match the mail server hostname.");
    }
    if (chainIssue) {
      recommendedActions.push("Install and serve the complete valid certificate chain.");
    }
    if (isSelfSigned) {
      recommendedActions.push("Deploy a certificate issued by a trusted Certificate Authority (CA).");
    }
    if (weakTlsOrCipher) {
      recommendedActions.push("Upgrade to supported TLS versions and modern AEAD cipher suites.");
    }
    if (noForwardSecrecy) {
      recommendedActions.push("Prefer ECDHE/DHE-based key exchange to provide forward secrecy.");
    }

    if (recommendedActions.length === 0) {
      recommendedActions.push("No immediate action required. Continue standard security monitoring.");
    }
  }

  // Deduplicate and constrain to concise 1-4 actions
  const displayActions = Array.from(new Set(recommendedActions)).slice(0, 4);

  // ============================================================================
  // SECTION F: KEY SECURITY DETAILS (Compact Forensic Attributes)
  // ============================================================================
  const hasCert = Boolean(cert.subject || cert.issuer);
  const tlsVersionValue = isTlsObserved ? (tls.version || "TLS") : "NOT OBSERVED";
  const cipherSuiteValue = isTlsObserved && tls.cipher_suite ? tls.cipher_suite : "NOT OBSERVED";

  // Handshake completion evidence
  const isHandshakeComplete = tls.handshake_status === 'COMPLETE' || tls.handshake_complete === true;
  const isHandshakeIncomplete = isTlsObserved && !isHandshakeComplete;
  const handshakeStatusValue = isTlsObserved
    ? (isHandshakeComplete ? "TLS handshake complete" : "TLS handshake incomplete")
    : "NOT OBSERVED";

  // Ephemeral Key Exchange & PFS
  const isKexEphemeral = tls.forward_secrecy === true || (tls.cipher_suite && (tls.cipher_suite.includes('ECDHE') || tls.cipher_suite.includes('DHE')));
  const kexName = tls.key_exchange || (tls.cipher_suite?.includes('ECDHE') ? 'ECDHE' : tls.cipher_suite?.includes('DHE') ? 'DHE' : null);
  const isKexCompleted = tls.ephemeral_key_exchange_verified === true ||
    (isKexEphemeral && (isHandshakeComplete || tls.encrypted_application_data_observed || (tls.handshake_messages?.includes('ClientKeyExchange') && tls.handshake_messages?.includes('ServerKeyExchange'))));

  const keyExchangeValue = isTlsObserved
    ? (isKexEphemeral
        ? (isKexCompleted ? `${kexName || 'ECDHE'} (PFS verified)` : `${kexName || 'ECDHE'} (PFS indicated)`)
        : (kexName ? `${kexName} (No PFS)` : "PFS not determinable"))
    : "NOT OBSERVED / INSUFFICIENT EVIDENCE";

  // Certificate Status & Chain (strictly separating leaf from root CA self-signature)
  const isLeafSelfSigned = cert.self_signed === true;
  const isCertExpired = cert.expired === true || cert.expiration_status === 'EXPIRED';
  const isCertNotYetValid = cert.not_yet_valid === true || cert.expiration_status === 'NOT_YET_VALID';
  const certStatusValue = hasCert
    ? (isCertExpired
        ? "Leaf certificate expired"
        : (isCertNotYetValid
            ? "Leaf certificate not yet valid"
            : (isLeafSelfSigned
                ? "Leaf certificate self-signed"
                : (cert.hostname_match === false
                    ? "Hostname mismatch"
                    : "Leaf certificate valid"))))
    : "NOT OBSERVED";

  const isChainValid = chainValidation.chain_status === 'VALID' || chainValidation.chain_valid === true;
  const certChainValue = hasCert
    ? (chainValidation.chain_complete && isChainValid
        ? "Certificate chain verified"
        : (chainValidation.chain_status === 'INVALID' || chainValidation.chain_valid === false
            ? "Certificate chain invalid"
            : (chainValidation.chain_status === 'INCOMPLETE' || chainValidation.issues?.length > 0
                ? "Certificate chain incomplete"
                : "Chain verification not determinable")))
    : "NOT OBSERVED";

  // STARTTLS Status
  const isImplicitTlsPort = dstPort === 465 || dstPort === 993 || dstPort === 995 || srcPort === 465 || srcPort === 993 || srcPort === 995;
  const starttlsStatusValue = (() => {
    if (!['SMTP', 'POP3', 'IMAP'].includes(protocol)) {
      return isImplicitTlsPort ? "Direct TLS (Implicit)" : "Not applicable";
    }
    if (starttls.status === 'SECURE_TRANSITION' || (starttls.upgrade_accepted && starttls.tls_transition_observed)) {
      if (isHandshakeComplete && tls.encrypted_application_data_observed) {
        return "STARTTLS accepted; TLS handshake complete";
      }
      if (isHandshakeIncomplete) {
        return "STARTTLS accepted; TLS handshake incomplete";
      }
      return "STARTTLS accepted; TLS transition observed";
    }
    if (starttls.status === 'INCOMPLETE' || (starttls.upgrade_accepted && !starttls.tls_transition_observed)) {
      return "STARTTLS accepted; transition not observed";
    }
    if (starttls.upgrade_requested && !starttls.upgrade_accepted) {
      return "STARTTLS upgrade rejected";
    }
    if (starttls.upgrade_supported && !starttls.upgrade_requested) {
      return "STARTTLS advertised; upgrade not requested";
    }
    if (isImplicitTlsPort) {
      return "Direct TLS (Implicit)";
    }
    if (starttls.upgrade_supported === false) {
      return "STARTTLS not offered by server";
    }
    return "NOT DETERMINABLE FROM CAPTURE";
  })();

  // Payload Security
  const isAead = tls.cipher_suite && (tls.cipher_suite.includes('GCM') || tls.cipher_suite.includes('POLY1305') || tls.cipher_suite.includes('CCM'));
  const isCbc = tls.cipher_suite && tls.cipher_suite.includes('CBC');
  const hasEncryptedAppData = Boolean(tls.encrypted_application_data_observed);

  const encryptionValue = isTlsObserved
    ? (hasEncryptedAppData
        ? (isAead ? "Encrypted application data observed (AEAD)" : isCbc ? "Encrypted application data observed (CBC Mode)" : "Encrypted application data observed (TLS)")
        : (isAead ? "AEAD cipher negotiated; encrypted payload not observed" : isCbc ? "CBC cipher negotiated; encrypted payload not observed" : "TLS cipher negotiated; encrypted payload not observed"))
    : (isConfirmedPlaintext ? "Plaintext application payload observed" : "UNCLASSIFIED / INSUFFICIENT EVIDENCE");

  const topRiskFactors = aiRisk.top_risk_factors || [];

  // ============================================================================
  // FORENSIC PROCESSING PIPELINE EVALUATION (Strictly Data-Driven)
  // Stages: PCAP -> Protocol Detection -> TCP Stream Reconstruction ->
  //         STARTTLS Detection -> TLS Handshake Analysis -> Certificate / Chain Validation ->
  //         Security Assessment -> AI Risk Analysis -> Final Result
  // ============================================================================
  const pcapLoaded = totalPackets > 0 || sessions.length > 0;
  const stagePcap = {
    name: "PCAP",
    status: pcapLoaded ? "PASS" : "FAIL",
    color: pcapLoaded ? "green" : "red",
    label: `${totalPackets} pkts`,
    desc: pcapLoaded ? "Capture loaded & indexed" : "Empty capture"
  };

  const hasKnownProtocol = protocol && protocol !== "UNKNOWN";
  const protoConfidence = selectedSession.protocol_confidence || "HIGH";
  const isPortInferred = selectedSession.protocol_detection_method === 'PORT_INFERRED' || protoConfidence === 'MEDIUM';
  const isProtoConfirmed = selectedSession.protocol_detection_method === 'APPLICATION_DATA' || (hasKnownProtocol && protoConfidence === 'HIGH');
  const stageProto = {
    name: "Protocol Detection",
    status: hasKnownProtocol ? (isPortInferred ? "INFO" : (protoConfidence === "LOW" ? "WARN" : "PASS")) : "FAIL",
    color: hasKnownProtocol ? (isPortInferred ? "amber" : (protoConfidence === "LOW" ? "amber" : "green")) : "red",
    label: protocol,
    desc: isProtoConfirmed ? `${protocol} (Confirmed from data)` : (isPortInferred ? `${protocol} (Inferred from port)` : `${protocol} (${protoConfidence})`)
  };

  const streamReconstructed = Boolean(selectedSession.session_id && (c2sBytes + s2cBytes > 0 || selectedSession.packet_count > 0));
  const stageTcp = {
    name: "TCP Stream Reconstruction",
    status: streamReconstructed ? "PASS" : "WARN",
    color: streamReconstructed ? "green" : "amber",
    label: formatBytes(c2sBytes + s2cBytes),
    desc: streamReconstructed ? "Stream reconstructed" : "Partial stream"
  };

  let stageStarttls;
  if (isImplicitTlsPort && isTlsObserved) {
    stageStarttls = {
      name: "STARTTLS Detection",
      status: "INFO",
      color: "amber",
      label: "Direct TLS",
      desc: "Implicit TLS (No STARTTLS required)"
    };
  } else if (starttls.status === 'SECURE_TRANSITION' || (starttls.upgrade_accepted && starttls.tls_transition_observed)) {
    stageStarttls = {
      name: "STARTTLS Detection",
      status: "PASS",
      color: "green",
      label: isHandshakeIncomplete ? "Transitioned" : "Negotiated",
      desc: isHandshakeIncomplete ? "STARTTLS accepted; TLS handshake incomplete" : "Upgrade accepted & transition observed"
    };
  } else if (starttls.status === 'INCOMPLETE' || (starttls.upgrade_supported && !starttls.upgrade_accepted) || (starttls.upgrade_accepted && !starttls.tls_transition_observed)) {
    stageStarttls = {
      name: "STARTTLS Detection",
      status: "FAIL",
      color: "red",
      label: "Incomplete",
      desc: starttls.upgrade_accepted ? "Accepted but no TLS transition" : "Transition failed"
    };
  } else if (!isTlsObserved) {
    if (isImplicitTlsPort) {
      stageStarttls = {
        name: "STARTTLS Detection",
        status: "INFO",
        color: "amber",
        label: "Direct TLS",
        desc: "Implicit TLS port; STARTTLS not applicable"
      };
    } else if (starttls.upgrade_supported === true) {
      stageStarttls = {
        name: "STARTTLS Detection",
        status: "FAIL",
        color: "red",
        label: "Not Requested",
        desc: "Plaintext session without TLS upgrade"
      };
    } else if (starttls.upgrade_supported === false) {
      stageStarttls = {
        name: "STARTTLS Detection",
        status: "FAIL",
        color: "red",
        label: "Not Offered",
        desc: "Server did not advertise STARTTLS capability"
      };
    } else {
      stageStarttls = {
        name: "STARTTLS Detection",
        status: "INFO",
        color: "amber",
        label: "NOT DETERMINABLE",
        desc: "NOT DETERMINABLE FROM CAPTURE"
      };
    }
  } else {
    stageStarttls = {
      name: "STARTTLS Detection",
      status: "INFO",
      color: "amber",
      label: "Direct TLS",
      desc: "Direct TLS transport"
    };
  }

  let stageTls;
  if (isTlsObserved) {
    const isLegacy = tls.version === 'TLS 1.0' || tls.version === 'TLS 1.1' || tls.version === 'SSLv3' || tls.version === 'SSLv2';
    if (isLegacy) {
      stageTls = {
        name: "TLS Handshake Analysis",
        status: "FAIL",
        color: "red",
        label: `${tls.version}`,
        desc: "Deprecated legacy TLS version"
      };
    } else if (tls.forward_secrecy === false) {
      stageTls = {
        name: "TLS Handshake Analysis",
        status: "WARN",
        color: "amber",
        label: `${tls.version}`,
        desc: isHandshakeIncomplete ? "Negotiated without PFS (Incomplete)" : "Established without PFS"
      };
    } else if (isHandshakeIncomplete) {
      stageTls = {
        name: "TLS Handshake Analysis",
        status: "PASS",
        color: "green",
        label: `${tls.version}`,
        desc: "Modern TLS negotiated; handshake incomplete"
      };
    } else {
      stageTls = {
        name: "TLS Handshake Analysis",
        status: "PASS",
        color: "green",
        label: `${tls.version}`,
        desc: "Modern TLS established & verified"
      };
    }
  } else {
    if (isConfirmedPlaintext) {
      stageTls = {
        name: "TLS Handshake Analysis",
        status: "FAIL",
        color: "red",
        label: "Not Established",
        desc: "Plaintext email session; no TLS handshake"
      };
    } else {
      stageTls = {
        name: "TLS Handshake Analysis",
        status: "INFO",
        color: "amber",
        label: "NOT OBSERVED",
        desc: "TLS handshake not observed in capture"
      };
    }
  }

  let stageCert;
  if (!isTlsObserved) {
    if (isConfirmedPlaintext) {
      stageCert = {
        name: "Certificate / Chain Validation",
        status: "FAIL",
        color: "red",
        label: "Missing",
        desc: "No certificate presented (Plaintext session)"
      };
    } else {
      stageCert = {
        name: "Certificate / Chain Validation",
        status: "INFO",
        color: "amber",
        label: "NOT OBSERVED",
        desc: "Certificate not observed in capture"
      };
    }
  } else if (!hasCert) {
    stageCert = {
      name: "Certificate / Chain Validation",
      status: "INFO",
      color: "amber",
      label: "NOT OBSERVED",
      desc: "Certificate not observed in capture"
    };
  } else {
    const isExpired = cert.expired === true || cert.expiration_status === 'EXPIRED';
    const isHostnameFail = cert.hostname_match === false;
    const isChainInvalid = chainValidation.chain_status === 'INVALID' || chainValidation.chain_valid === false;
    if (isExpired || isHostnameFail || isChainInvalid || isLeafSelfSigned) {
      stageCert = {
        name: "Certificate / Chain Validation",
        status: isExpired || isChainInvalid ? "FAIL" : "WARN",
        color: isExpired || isChainInvalid ? "red" : "amber",
        label: isExpired ? "Expired" : (isHostnameFail ? "Host Mismatch" : (isLeafSelfSigned ? "Self-Signed" : "Chain Invalid")),
        desc: isExpired ? "Leaf certificate expired" : (isHostnameFail ? "Hostname SAN/CN mismatch" : (isLeafSelfSigned ? "Self-signed leaf certificate" : "Trust chain validation failed"))
      };
    } else if (chainValidation.chain_complete && isChainValid) {
      stageCert = {
        name: "Certificate / Chain Validation",
        status: "PASS",
        color: "green",
        label: "Chain Verified",
        desc: "Valid leaf & complete chain"
      };
    } else {
      stageCert = {
        name: "Certificate / Chain Validation",
        status: "PASS",
        color: "green",
        label: "Valid Leaf",
        desc: cert.common_name || "Leaf cert presented"
      };
    }
  }

  const critCount = selectedSession.assessment?.critical_count || assessmentFindings.filter(f => f.severity === 'CRITICAL').length;
  const highCount = selectedSession.assessment?.high_count || assessmentFindings.filter(f => f.severity === 'HIGH').length;
  const medCount = selectedSession.assessment?.medium_count || assessmentFindings.filter(f => f.severity === 'MEDIUM').length;
  let stageAssessment;
  if (critCount > 0 || highCount > 0) {
    stageAssessment = {
      name: "Security Assessment",
      status: "FAIL",
      color: "red",
      label: `${critCount + highCount} Issues`,
      desc: `${critCount} Critical, ${highCount} High findings`
    };
  } else if (medCount > 0) {
    stageAssessment = {
      name: "Security Assessment",
      status: "WARN",
      color: "amber",
      label: `${medCount} Warnings`,
      desc: "Minor deprecations / warnings"
    };
  } else {
    stageAssessment = {
      name: "Security Assessment",
      status: "PASS",
      color: "green",
      label: "Zero Findings",
      desc: "Conforms to security baseline"
    };
  }

  // Stage 08: AI Risk Analysis (Secondary ML Signal)
  let stageAi;
  if (aiLabel === 'CRITICAL' || aiLabel === 'HIGH') {
    stageAi = {
      name: "AI Risk (ML)",
      status: "FAIL",
      color: "red",
      label: `${aiLabel} (${aiScore})`,
      desc: "Secondary ML Signal: Elevated risk"
    };
  } else if (aiLabel === 'MODERATE') {
    stageAi = {
      name: "AI Risk (ML)",
      status: "WARN",
      color: "amber",
      label: `${aiLabel} (${aiScore})`,
      desc: "Secondary ML Signal: Moderate risk"
    };
  } else {
    stageAi = {
      name: "AI Risk (ML)",
      status: "PASS",
      color: "green",
      label: `LOW (${aiScore})`,
      desc: "Secondary ML Signal: Low risk"
    };
  }

  // Stage 09: Final Result (Strictly follows deterministic security posture and findings, NOT AI risk score)
  let stageFinal;
  const normPosture = String(postureStatus).trim().toUpperCase();
  const isConfirmedIssue = normPosture === 'AT_RISK' || normPosture === 'COMPROMISED' || critCount > 0 || highCount > 0 || (!isTlsObserved && isConfirmedPlaintext);
  const isIncomplete = normPosture === 'INCOMPLETE' || (!isTlsObserved && !isConfirmedPlaintext);

  if (isConfirmedIssue) {
    stageFinal = {
      name: "Final Result",
      status: "FAIL",
      color: "red",
      label: "AT_RISK",
      desc: "Deterministic security issue detected"
    };
  } else if (isIncomplete) {
    stageFinal = {
      name: "Final Result",
      status: "WARN",
      color: "amber",
      label: "INCOMPLETE",
      desc: "Incomplete capture; insufficient evidence to confirm security baseline"
    };
  } else {
    // 100/100 SECURE + 0 findings -> Stage 09 = SECURE CONFIG / VERIFIED
    stageFinal = {
      name: "Final Result",
      status: "PASS",
      color: "green",
      label: isHandshakeIncomplete || !hasEncryptedAppData ? "SECURE CONFIG" : "SECURE",
      desc: isHandshakeIncomplete || !hasEncryptedAppData ? "Secure configuration; capture incomplete" : "Encrypted mail session completed"
    };
  }

  const row1Stages = [
    { ...stagePcap, stepNum: '01' },
    { ...stageProto, stepNum: '02' },
    { ...stageTcp, stepNum: '03' },
    { ...stageStarttls, stepNum: '04' },
    { ...stageTls, stepNum: '05' }
  ];

  const row2Stages = [
    { ...stageCert, stepNum: '06' },
    { ...stageAssessment, stepNum: '07' },
    { ...stageAi, stepNum: '08' },
    { ...stageFinal, stepNum: '09' }
  ];

  // ============================================================================
  return (
    <div className="w-full max-w-6xl mx-auto flex flex-col gap-6">
      {/* ==================================================================== */}
      {/* SECTION 1: CAPTURE / SESSION HEADER                                 */}
      {/* ==================================================================== */}
      <header className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-5 sm:p-6 shadow-xs flex flex-col gap-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Capture Summary */}
          <div className="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-[18px] text-[#006591] dark:text-sky-400">manage_search</span>
                <span className="text-[11px] font-bold uppercase tracking-wider text-[#006591] dark:text-sky-400">Forensic Investigation</span>
              </div>
              <div className="flex items-center gap-2 mt-0.5">
                <h1 className="text-lg sm:text-xl font-bold font-mono text-slate-900 dark:text-white truncate max-w-xs sm:max-w-md">
                  {filename}
                </h1>
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400 font-sans mt-0.5">
                {totalPackets.toLocaleString()} packets · {totalSessions} session{totalSessions === 1 ? '' : 's'} · {protocol}
              </div>
            </div>

            <div className="h-8 w-px bg-slate-200 dark:bg-slate-700 hidden sm:block"></div>

            {/* Selected Session Identifier */}
            <div className="flex items-center gap-2 bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 px-3 py-1.5 rounded-lg">
              <span className="font-mono text-xs font-bold text-slate-900 dark:text-white bg-white dark:bg-slate-800 px-2 py-0.5 rounded border border-slate-200 dark:border-slate-700">
                {sessId}
              </span>
              <span className="font-mono text-xs text-slate-600 dark:text-slate-300">
                {srcIp}:{srcPort} → {dstIp}:{dstPort}
              </span>
            </div>
          </div>

          {/* Quick Actions & Session Browser Toggle */}
          <div className="flex flex-wrap items-center gap-2 shrink-0" ref={exportRef}>
            {totalSessions > 1 && (
              <button
                onClick={() => setShowSessionBrowser(!showSessionBrowser)}
                className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-semibold transition-colors cursor-pointer ${
                  showSessionBrowser
                    ? 'bg-slate-900 dark:bg-slate-100 text-white dark:text-slate-900 border-slate-900 dark:border-slate-100 shadow-xs'
                    : 'bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 border-slate-200 dark:border-slate-700'
                }`}
              >
                <span className="material-symbols-outlined text-[16px]">
                  {showSessionBrowser ? 'close' : 'swap_horiz'}
                </span>
                <span>{showSessionBrowser ? 'Close Sessions' : `Switch Session (${totalSessions})`}</span>
              </button>
            )}

            {/* Download Raw Genuine PCAP Button */}
            <button
              id="btn-forensics-download-pcap"
              onClick={handleDownloadPcap}
              disabled={isDownloadingPcap}
              title={`Download raw genuine PCAP packet capture (${filename})`}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-[#006591] hover:bg-[#005174] active:bg-[#003d57] text-white border border-transparent text-xs font-semibold transition-all shrink-0 shadow-xs cursor-pointer disabled:opacity-60 disabled:cursor-not-allowed"
            >
              <span className={`material-symbols-outlined text-[16px] ${isDownloadingPcap ? 'animate-spin' : ''}`}>
                {isDownloadingPcap ? 'sync' : 'sim_card_download'}
              </span>
              <span>{isDownloadingPcap ? 'Downloading PCAP...' : 'Download PCAP'}</span>
            </button>

            {/* Export Report Dropdown */}
            <div className="relative">
              <button
                onClick={() => setIsExportOpen(!isExportOpen)}
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-slate-900 dark:bg-slate-800 text-white hover:bg-slate-800 dark:hover:bg-slate-700 border border-transparent dark:border-slate-700 text-xs font-medium transition-colors shrink-0 shadow-xs cursor-pointer"
              >
                <span className="material-symbols-outlined text-[16px]">download</span>
                <span>Export Report</span>
                <span className="material-symbols-outlined text-[14px]">expand_more</span>
              </button>

              {isExportOpen && (
                <div className="absolute right-0 mt-1 w-44 bg-white dark:bg-slate-800 rounded-lg shadow-lg border border-slate-200 dark:border-slate-700 py-1 z-30 font-sans text-xs">
                  <button
                    onClick={() => onExport('pdf')}
                    className="w-full px-3 py-2 text-left text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 flex items-center gap-2 cursor-pointer"
                  >
                    <span className="material-symbols-outlined text-[16px] text-rose-600">picture_as_pdf</span>
                    <span>PDF</span>
                  </button>
                  <button
                    onClick={() => onExport('json')}
                    className="w-full px-3 py-2 text-left text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 flex items-center gap-2 cursor-pointer"
                  >
                    <span className="material-symbols-outlined text-[16px] text-blue-600">data_object</span>
                    <span>JSON</span>
                  </button>
                  <button
                    onClick={() => onExport('xlsx')}
                    className="w-full px-3 py-2 text-left text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 flex items-center gap-2 cursor-pointer"
                  >
                    <span className="material-symbols-outlined text-[16px] text-emerald-600">table_chart</span>
                    <span>XLSX</span>
                  </button>
                  <button
                    onClick={() => onExport('html')}
                    className="w-full px-3 py-2 text-left text-slate-700 dark:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 flex items-center gap-2 cursor-pointer"
                  >
                    <span className="material-symbols-outlined text-[16px] text-indigo-600">html</span>
                    <span>HTML</span>
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* PCAP Download Error Feedback Alert */}
        {pcapDownloadError && (
          <div className="mx-6 mb-3 p-3 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-800 text-rose-700 dark:text-rose-300 text-xs flex items-center justify-between gap-2 animate-fadeIn">
            <div className="flex items-center gap-2">
              <span className="material-symbols-outlined text-[16px] text-rose-600 dark:text-rose-400 shrink-0">error</span>
              <span>{pcapDownloadError}</span>
            </div>
            <button
              onClick={() => setPcapDownloadError(null)}
              className="text-rose-500 hover:text-rose-700 dark:hover:text-rose-200 cursor-pointer"
            >
              <span className="material-symbols-outlined text-[14px]">close</span>
            </button>
          </div>
        )}

        {/* Optional Collapsible Session Browser Drawer (For multi-session captures) */}
        {showSessionBrowser && (
          <div className="pt-3 border-t border-slate-100 dark:border-slate-800 flex flex-col gap-2.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-1 text-[11px] font-medium bg-slate-100 dark:bg-slate-800 p-0.5 rounded-lg border border-slate-200 dark:border-slate-700">
                {['ALL', 'SMTP', 'IMAP', 'POP3'].map((p) => (
                  <button
                    key={p}
                    onClick={() => setProtocolFilter(p)}
                    className={`px-2 py-0.5 rounded-md transition-colors cursor-pointer ${
                      protocolFilter === p
                        ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-white font-bold shadow-xs'
                        : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                    }`}
                  >
                    {p}
                  </button>
                ))}
              </div>

              <div className="relative">
                <input
                  type="text"
                  placeholder="Filter sessions..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-7 pr-3 py-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs font-sans text-slate-800 dark:text-slate-200 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-[#006591] dark:focus:border-sky-400"
                />
                <span className="material-symbols-outlined absolute left-1.5 top-1.5 text-[15px] text-slate-400 pointer-events-none">
                  search
                </span>
              </div>
            </div>

            <div className="overflow-x-auto max-h-48 overflow-y-auto border border-slate-200 dark:border-slate-800 rounded-lg">
              <table className="w-full text-left border-collapse text-xs">
                <thead className="bg-slate-50 dark:bg-slate-800/80 text-[11px] font-semibold text-slate-500 dark:text-slate-400 uppercase sticky top-0 border-b border-slate-200 dark:border-slate-700">
                  <tr>
                    <th className="py-2 px-3">Session</th>
                    <th className="py-2 px-3">Protocol</th>
                    <th className="py-2 px-3">Source → Destination</th>
                    <th className="py-2 px-3">TLS</th>
                    <th className="py-2 px-3">AI Risk</th>
                    <th className="py-2 px-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 dark:divide-slate-800 font-sans text-[11px]">
                  {filteredSessions.map((s) => {
                    const isSelected = s.session_id === sessId;
                    const sScore = s.ai_risk?.score != null ? Number(s.ai_risk.score).toFixed(1) : (s.posture?.score ?? 0);
                    const sLabel = getAiRiskTier(s.ai_risk);
                    const sTls = s.tls?.version || (s.starttls?.status === 'SECURE' ? 'TLS' : 'Plaintext');

                    return (
                      <tr
                        key={s.session_id}
                        onClick={() => {
                          onSelectSession(s.session_id);
                          setShowSessionBrowser(false);
                        }}
                        className={`transition-colors cursor-pointer ${
                          isSelected ? 'bg-blue-50 dark:bg-sky-950/40 font-semibold' : 'hover:bg-slate-50 dark:hover:bg-slate-800/50'
                        }`}
                      >
                        <td className="py-2 px-3 text-slate-900 dark:text-white font-mono font-bold">{s.session_id}</td>
                        <td className="py-2 px-3 text-slate-700 dark:text-slate-300 font-mono">{s.protocol}</td>
                        <td className="py-2 px-3 text-slate-600 dark:text-slate-400 font-mono">
                          {s.source_ip}:{s.source_port} → {s.destination_ip}:{s.destination_port}
                        </td>
                        <td className="py-2 px-3 text-slate-700 dark:text-slate-300 font-mono">{sTls}</td>
                        <td className="py-2 px-3">
                          <span className={`font-bold tabular-nums ${sLabel === 'CRITICAL' || sLabel === 'HIGH' ? 'text-rose-700 dark:text-rose-400' : sLabel === 'MODERATE' ? 'text-amber-700 dark:text-amber-400' : 'text-emerald-700 dark:text-emerald-400'}`}>
                            {sScore}/100 [{sLabel}]
                          </span>
                        </td>
                        <td className="py-2 px-3 font-sans text-slate-700 dark:text-slate-300 font-medium">
                          {s.posture?.security_posture || "Analyzed"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </header>

      {/* ==================================================================== */}
      {/* SECTION 2: PRIMARY SECURITY RESULT                                  */}
      {/* ==================================================================== */}
      <section className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-5 sm:p-6 shadow-xs flex flex-col sm:flex-row items-center justify-between gap-6">
        {/* Left: AI Risk Gauge & Label */}
        <div className="flex items-center gap-5">
          <div className="relative w-24 h-24 sm:w-28 sm:h-28 shrink-0 flex items-center justify-center">
            <svg className="w-full h-full -rotate-90 transform" viewBox="0 0 130 130">
              <circle cx="65" cy="65" fill="transparent" r="54" stroke={theme === 'dark' ? '#1e293b' : '#f1f5f9'} strokeWidth="10" />
              <circle
                cx="65"
                cy="65"
                fill="transparent"
                r="54"
                stroke={riskGaugeColor}
                strokeDasharray={circumference}
                strokeDashoffset={dashOffset}
                strokeLinecap="round"
                strokeWidth="10"
                className="transition-all duration-700 ease-out"
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
              <span className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white font-sans tabular-nums leading-none">
                {aiScore}
              </span>
              <span className="text-[10px] text-slate-400 dark:text-slate-500 font-sans font-medium mt-0.5">/ 100</span>
            </div>
          </div>

          <div className="flex flex-col gap-1">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 font-sans">
              AI Risk Score
            </span>
            <div className="flex items-baseline gap-2">
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border tracking-wider uppercase inline-flex items-center gap-1.5 ${riskBadgeColor}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${riskDotColor}`}></span>
                {aiLabel}
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-xs text-slate-500 dark:text-slate-400 mt-1">
              <span>AI Confidence: <strong className="text-slate-800 dark:text-slate-200 font-sans font-bold tabular-nums">{aiConfidence}%</strong></span>
              {modelPredictedClass && modelPredictedClass !== aiLabel && (
                <span className="text-slate-500 dark:text-slate-400 font-sans text-[11px] border-l border-slate-200 dark:border-slate-700 pl-2.5" title="Random Forest argmax class probability">
                  ML Argmax: <strong className="text-slate-700 dark:text-slate-200 font-semibold">{modelPredictedClass}</strong>
                </span>
              )}
            </div>
            <span className="text-[10px] text-slate-400 dark:text-slate-500 font-sans mt-0.5">
              Secondary ML risk signal; does not override deterministic security findings.
            </span>
          </div>
        </div>

        {/* Right: Security Posture & Anomaly Badges */}
        <div className="grid grid-cols-2 gap-3 w-full sm:w-auto">
          {/* Security Posture Card */}
          <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 flex flex-col justify-between min-w-[140px]">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 font-sans">
              Security Posture · Deterministic
            </span>
            <span className={`text-sm font-bold mt-1 uppercase font-sans ${postureStatus === 'SECURE' ? 'text-emerald-700 dark:text-emerald-400' : (postureStatus === 'INCOMPLETE' ? 'text-amber-700 dark:text-amber-400' : 'text-rose-700 dark:text-rose-400')}`}>
              {postureStatus === 'NEEDS ATTENTION' ? 'INSECURE' : postureStatus}
            </span>
            <span className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 font-sans">
              {postureStatus === 'INCOMPLETE' ? 'Insufficient Evidence' : (
                <>Score: <strong className="text-slate-800 dark:text-slate-200 font-sans font-bold tabular-nums">{postureScore}/100</strong></>
              )}
            </span>
          </div>

          {/* Anomaly Detection Card */}
          <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 flex flex-col justify-between min-w-[140px]">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400 font-sans">
              Anomaly Status
            </span>
            <span className={`text-sm font-bold mt-1 font-sans uppercase ${isAnomaly ? 'text-rose-600 dark:text-rose-400' : 'text-emerald-700 dark:text-emerald-400'}`}>
              {anomalyStatus}
            </span>
            <span className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 font-sans">
              Score: <strong className="font-semibold tabular-nums">{anomalyScore}</strong>
            </span>
          </div>
        </div>
      </section>

      {/* ==================================================================== */}
      {/* SECTION 3: FORENSIC PROCESSING PIPELINE (9 Major Analysis Stages)    */}
      {/* ==================================================================== */}
      <section className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-4 sm:p-5 shadow-xs flex flex-col gap-2.5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 border-b border-slate-100 dark:border-slate-800 pb-2">
          <div className="flex items-center gap-2">
            <span className="material-symbols-outlined text-[16px] text-[#006591] dark:text-sky-400">account_tree</span>
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">
              Forensic Security Pipeline
            </h2>
          </div>
          <div className="flex items-center gap-3 text-[10px] font-medium text-slate-500 dark:text-slate-400">
            <div className="flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
              <span>Verified / Secure</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-500"></span>
              <span>Indeterminate</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-rose-500"></span>
              <span>Issue Detected</span>
            </div>
          </div>
        </div>

        {/* 9 Analysis Stages in Compact Enterprise SOC Continuous Flow */}
        <div className="flex flex-col gap-1 pt-0.5">
          {(() => {
            const renderNode = (stage, isFinal = false) => {
              const isGreen = stage.color === 'green';
              const isAmber = stage.color === 'amber';

              // Subtle borders and restrained left accents
              const borderClass = isFinal
                ? (isGreen
                    ? 'border-emerald-200 dark:border-emerald-800/60 border-l-[3px] border-l-emerald-600 dark:border-l-emerald-500 bg-emerald-50/15 dark:bg-emerald-950/20'
                    : isAmber
                    ? 'border-amber-200 dark:border-amber-800/60 border-l-[3px] border-l-amber-600 dark:border-l-amber-500 bg-amber-50/15 dark:bg-amber-950/20'
                    : 'border-rose-200 dark:border-rose-800/60 border-l-[3px] border-l-rose-600 dark:border-l-rose-500 bg-rose-50/15 dark:bg-rose-950/20')
                : (isGreen
                    ? 'border-slate-200 dark:border-slate-800 border-l-[3px] border-l-emerald-500 bg-slate-50/70 dark:bg-slate-800/70 hover:border-slate-300 dark:hover:border-slate-700'
                    : isAmber
                    ? 'border-slate-200 dark:border-slate-800 border-l-[3px] border-l-amber-500 bg-slate-50/70 dark:bg-slate-800/70 hover:border-slate-300 dark:hover:border-slate-700'
                    : 'border-slate-200 dark:border-slate-800 border-l-[3px] border-l-rose-500 bg-slate-50/70 dark:bg-slate-800/70 hover:border-slate-300 dark:hover:border-slate-700');

              const dotClass = isGreen
                ? 'bg-emerald-500'
                : isAmber
                ? 'bg-amber-500'
                : 'bg-rose-500';

              const textClass = isGreen
                ? 'text-emerald-700 dark:text-emerald-400'
                : isAmber
                ? 'text-amber-700 dark:text-amber-400'
                : 'text-rose-700 dark:text-rose-400';

              // Status indicator according to Section 7:
              // ● VERIFIED, ● SECURE, ● INDETERMINATE, ● ISSUE DETECTED
              let statusText = isGreen ? 'VERIFIED' : isAmber ? 'INDETERMINATE' : 'ISSUE DETECTED';
              if (isFinal) {
                statusText = isGreen ? 'VERIFIED' : 'ISSUE DETECTED';
              } else if (stage.name === 'PCAP' && !pcapLoaded) {
                statusText = 'NO DATA';
              }

              return (
                <div
                  className={`flex-1 min-w-0 rounded-lg border px-2.5 py-1.5 sm:py-2 flex flex-col justify-between h-[52px] sm:h-[54px] transition-all duration-150 shadow-2xs ${borderClass} hover:shadow-xs`}
                  title={stage.desc ? `${stage.name} (${stage.stepNum}): ${stage.desc}` : stage.name}
                >
                  <div className="flex items-center justify-between gap-1 leading-none">
                    <span className="font-sans text-[9px] font-semibold text-slate-400 dark:text-slate-500">
                      #{stage.stepNum}
                    </span>
                    <div className="flex items-center gap-1 leading-none overflow-hidden">
                      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotClass}`}></span>
                      <span
                        className={`font-sans text-[8.5px] font-semibold tracking-wider uppercase truncate ${textClass}`}
                        title={statusText}
                      >
                        {statusText}
                      </span>
                    </div>
                  </div>
                  <div className="mt-0.5 flex flex-col overflow-hidden">
                    <span
                      className={`block text-[11px] sm:text-[11.5px] font-bold tracking-tight truncate leading-tight ${
                        isFinal ? 'text-slate-950 dark:text-white font-extrabold' : 'text-slate-900 dark:text-slate-100'
                      }`}
                      title={stage.name}
                    >
                      {stage.name}
                    </span>
                    <span className="font-sans text-[9px] text-slate-500 dark:text-slate-400 font-normal truncate leading-tight" title={stage.desc || stage.label}>
                      {stage.label || stage.desc}
                    </span>
                  </div>
                </div>
              );
            };

            return (
              <>
                {/* ROW 1: Stages 01 to 05 */}
                <div className="flex flex-col md:flex-row items-stretch md:items-center gap-1">
                  {row1Stages.map((stage, idx) => (
                    <React.Fragment key={`r1-${stage.name}`}>
                      {renderNode(stage, false)}
                      {idx < row1Stages.length - 1 && (
                        <>
                          {/* Desktop horizontal flow arrow */}
                          <div className="hidden md:flex items-center justify-center shrink-0 w-2.5 text-slate-400 dark:text-slate-600">
                            <svg width="10" height="8" viewBox="0 0 10 8" fill="none">
                              <line x1="0" y1="4" x2="6" y2="4" stroke={theme === 'dark' ? '#475569' : '#94a3b8'} strokeWidth="1.25" />
                              <path d="M5 1.5L7.5 4L5 6.5" stroke={theme === 'dark' ? '#64748b' : '#64748b'} strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round" />
                            </svg>
                          </div>
                          {/* Mobile vertical flow arrow */}
                          <div className="flex md:hidden items-center justify-center py-0.5 text-slate-400 dark:text-slate-600">
                            <svg width="8" height="10" viewBox="0 0 8 10" fill="none">
                              <line x1="4" y1="0" x2="4" y2="6" stroke={theme === 'dark' ? '#475569' : '#94a3b8'} strokeWidth="1.25" />
                              <path d="M1.5 5L4 7.5L6.5 5" stroke={theme === 'dark' ? '#64748b' : '#64748b'} strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round" />
                            </svg>
                          </div>
                        </>
                      )}
                    </React.Fragment>
                  ))}
                </div>

                {/* CONTINUOUS ZIG-ZAG CONNECTOR (Row 1 -> Row 2) */}
                <div className="hidden md:block w-full py-0.5">
                  <svg
                    className="w-full h-3.5 overflow-visible"
                    viewBox="0 0 1000 14"
                    preserveAspectRatio="none"
                    fill="none"
                  >
                    {/* Continuous circuit line dropping from Stage 05 (x=906), traveling across to Stage 06 (x=119), and dropping down */}
                    <path
                      d="M 906 0 L 906 6 Q 906 8 900 8 L 125 8 Q 119 8 119 10 L 119 14"
                      stroke={theme === 'dark' ? '#475569' : '#94a3b8'}
                      strokeWidth="1.25"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                    {/* Midpoint flow direction indicator */}
                    <path
                      d="M 512 5 L 506 8 L 512 11"
                      stroke={theme === 'dark' ? '#64748b' : '#64748b'}
                      strokeWidth="1.25"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                    {/* Terminal downward arrow pointing directly into Stage 06 */}
                    <polygon points="116,9 119,14 122,9" fill={theme === 'dark' ? '#64748b' : '#64748b'} />
                  </svg>
                </div>

                {/* Mobile connector between Row 1 and Row 2 */}
                <div className="flex md:hidden items-center justify-center py-0.5 text-slate-400 dark:text-slate-600">
                  <svg width="8" height="10" viewBox="0 0 8 10" fill="none">
                    <line x1="4" y1="0" x2="4" y2="6" stroke={theme === 'dark' ? '#475569' : '#94a3b8'} strokeWidth="1.25" />
                    <path d="M1.5 5L4 7.5L6.5 5" stroke={theme === 'dark' ? '#64748b' : '#64748b'} strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </div>

                {/* ROW 2: Stages 06 to 09 */}
                <div className="flex flex-col md:flex-row items-stretch md:items-center gap-1">
                  {row2Stages.map((stage, idx) => (
                    <React.Fragment key={`r2-${stage.name}`}>
                      {renderNode(stage, stage.stepNum === '09')}
                      {idx < row2Stages.length - 1 && (
                        <>
                          {/* Desktop horizontal flow arrow */}
                          <div className="hidden md:flex items-center justify-center shrink-0 w-2.5 text-slate-400 dark:text-slate-600">
                            <svg width="10" height="8" viewBox="0 0 10 8" fill="none">
                              <line x1="0" y1="4" x2="6" y2="4" stroke={theme === 'dark' ? '#475569' : '#94a3b8'} strokeWidth="1.25" />
                              <path d="M5 1.5L7.5 4L5 6.5" stroke={theme === 'dark' ? '#64748b' : '#64748b'} strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round" />
                            </svg>
                          </div>
                          {/* Mobile vertical flow arrow */}
                          <div className="flex md:hidden items-center justify-center py-0.5 text-slate-400 dark:text-slate-600">
                            <svg width="8" height="10" viewBox="0 0 8 10" fill="none">
                              <line x1="4" y1="0" x2="4" y2="6" stroke={theme === 'dark' ? '#475569' : '#94a3b8'} strokeWidth="1.25" />
                              <path d="M1.5 5L4 7.5L6.5 5" stroke={theme === 'dark' ? '#64748b' : '#64748b'} strokeWidth="1.25" strokeLinecap="round" strokeLinejoin="round" />
                            </svg>
                          </div>
                        </>
                      )}
                    </React.Fragment>
                  ))}
                </div>
              </>
            );
          })()}
        </div>
      </section>

      {/* ==================================================================== */}
      {/* 2-COLUMN MAIN INVESTIGATION WORKFLOW                                 */}
      {/* Left (8 cols): What's Wrong, Recommended Actions, Key Security Details */}
      {/* Right (4 cols): AI Risk Factors, Verification Signals                */}
      {/* ==================================================================== */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* LEFT COLUMN: FORENSIC INVESTIGATION FLOW */}
        <div className="lg:col-span-8 flex flex-col gap-5">
          {/* ================================================================ */}
          {/* SECTION C: WHAT'S WRONG (Security Findings)                       */}
          {/* ================================================================ */}
          <section className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-4 sm:p-5 shadow-xs flex flex-col gap-3">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-2.5">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-[16px] text-[#006591] dark:text-sky-400">gpp_maybe</span>
                <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">Security Findings</h2>
                <span className="text-[11px] text-slate-400 dark:text-slate-500 font-medium">· Observed from PCAP</span>
              </div>
              <span className="text-[11px] font-sans text-slate-400 dark:text-slate-500">
                {findingsList.filter(f => f.isFail).length > 0
                  ? `${findingsList.filter(f => f.isFail).length} issue${findingsList.filter(f => f.isFail).length === 1 ? '' : 's'} detected`
                  : '0 issues detected'}
              </span>
            </div>

            <div className="flex flex-col gap-2">
              {findingsList.filter(f => f.isFail).length === 0 ? (
                <div className="flex items-center gap-2.5 p-3 rounded-lg bg-emerald-50/40 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-800/60 text-emerald-900 dark:text-emerald-200 text-xs font-medium">
                  <span className="material-symbols-outlined text-[18px] text-emerald-600 dark:text-emerald-400 shrink-0">verified</span>
                  <div className="flex flex-col gap-0.5">
                    <span className="font-bold text-emerald-950 dark:text-emerald-200">No significant security findings detected</span>
                    <span className="text-[11px] text-emerald-700 dark:text-emerald-400 font-sans">
                      Session conforms to cryptographic baselines with no protocol negotiation or certificate defects.
                    </span>
                  </div>
                </div>
              ) : (
                findingsList.filter(f => f.isFail).map((f, i) => {
                  const stageRef = getPipelineStageForFinding(f);
                  const severity = f.severity || 'HIGH';
                  const isCritical = severity === 'CRITICAL';
                  const isHigh = severity === 'HIGH';
                  const isMedium = severity === 'MEDIUM';

                  const borderClass = isCritical
                    ? 'border-slate-200 dark:border-slate-800 border-l-[3px] border-l-rose-600'
                    : isHigh
                    ? 'border-slate-200 dark:border-slate-800 border-l-[3px] border-l-rose-500'
                    : isMedium
                    ? 'border-slate-200 dark:border-slate-800 border-l-[3px] border-l-amber-500'
                    : 'border-slate-200 dark:border-slate-800 border-l-[3px] border-l-sky-500';

                  const severityBadgeClass = isCritical
                    ? 'bg-rose-600 text-white border-rose-700'
                    : isHigh
                    ? 'bg-rose-50 dark:bg-rose-950/50 text-rose-700 dark:text-rose-400 border-rose-200 dark:border-rose-800'
                    : isMedium
                    ? 'bg-amber-50 dark:bg-amber-950/50 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800'
                    : 'bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-700';

                  const desc = f.description || f.reason;

                  return (
                    <div
                      key={`${f.id}-${i}`}
                      className={`p-2.5 sm:px-3 sm:py-2 rounded-lg border ${borderClass} bg-slate-50/60 dark:bg-slate-800/60 flex flex-col gap-1 transition-colors hover:bg-slate-100/60 dark:hover:bg-slate-800 shadow-2xs`}
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
                        <div className="flex items-center gap-2 min-w-0">
                          <span
                            className={`shrink-0 font-sans text-[9px] font-semibold uppercase tracking-wider px-1.5 py-0.5 rounded border ${severityBadgeClass}`}
                          >
                            {severity}
                          </span>
                          <span className="text-xs font-bold text-slate-900 dark:text-white truncate" title={f.label}>
                            {f.label}
                          </span>
                        </div>

                        {stageRef && (
                          <div className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-[10px] font-sans font-medium text-slate-600 dark:text-slate-300 shrink-0 self-start sm:self-auto">
                            <span className="font-bold text-[#006591] dark:text-sky-400">Stage {stageRef.num}</span>
                            <span className="text-slate-300 dark:text-slate-600">·</span>
                            <span className="font-sans text-slate-600 dark:text-slate-300 font-medium truncate max-w-[170px]" title={stageRef.name}>
                              {stageRef.name}
                            </span>
                          </div>
                        )}
                      </div>

                      {desc && (
                        <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-normal truncate" title={desc}>
                          {desc}
                        </p>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </section>


          {/* ================================================================ */}
          {/* SECTION E: RECOMMENDED ACTIONS (Remediation)                     */}
          {/* ================================================================ */}
          <section className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-5 sm:p-6 shadow-xs flex flex-col gap-4">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-[18px] text-[#006591] dark:text-sky-400">assignment_turned_in</span>
                <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">Recommended Actions</h2>
                <span className="text-[11px] text-slate-400 dark:text-slate-500 font-medium">· Remediation</span>
              </div>
              <span className="text-[11px] font-sans text-slate-400 dark:text-slate-500">
                {displayActions.length} action{displayActions.length === 1 ? '' : 's'}
              </span>
            </div>

            <div className="flex flex-col gap-2">
              {displayActions.map((action, idx) => (
                <div
                  key={`rec-${idx}`}
                  className="flex items-start gap-3 p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 text-xs text-slate-800 dark:text-slate-200 font-medium"
                >
                  <span className="w-5 h-5 rounded-full bg-[#006591] text-white flex items-center justify-center font-bold text-[10px] shrink-0 font-sans mt-0.5">
                    {idx + 1}
                  </span>
                  <span className="leading-relaxed">{action}</span>
                </div>
              ))}
            </div>
          </section>

          {/* ================================================================ */}
          {/* SECTION F: KEY SECURITY DETAILS (Technical Attributes)            */}
          {/* ================================================================ */}
          <section className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-5 sm:p-6 shadow-xs flex flex-col gap-4">
            <div className="flex items-center justify-between border-b border-slate-100 dark:border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-[18px] text-[#006591] dark:text-sky-400">terminal</span>
                <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">Key Security Details</h2>
                <span className="text-[11px] text-slate-400 dark:text-slate-500 font-medium">· Technical Attributes</span>
              </div>
              <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-800 px-2 py-0.5 rounded border border-slate-200 dark:border-slate-700">
                {protocol} · Port {dstPort}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1.5 text-xs font-mono py-1">
              {(() => {
                const isPortInferred = selectedSession.protocol_detection_method === 'PORT_INFERRED' || selectedSession.protocol_confidence === 'MEDIUM';
                const isProtoConfirmed = selectedSession.protocol_detection_method === 'APPLICATION_DATA' || (hasKnownProtocol && selectedSession.protocol_confidence === 'HIGH');
                const protocolEvidenceTag = isProtoConfirmed ? "VERIFIED" : (isPortInferred ? "INFERRED" : (hasKnownProtocol ? "OBSERVED" : "INCOMPLETE"));
                const protocolTooltip = isProtoConfirmed ? "Protocol confirmed from application data" : (isPortInferred ? "Protocol inferred from port" : (hasKnownProtocol ? "Protocol observed" : "Protocol unknown"));

                const tlsVersionEvidenceTag = !isTlsObserved ? "NOT OBSERVED" : (tls.version && tls.version !== "None" ? "VERIFIED" : "OBSERVED");
                const cipherSuiteEvidenceTag = !isTlsObserved ? "NOT OBSERVED" : (tls.cipher_suite ? "VERIFIED" : "INCOMPLETE");
                const kexEvidenceTag = !isTlsObserved ? "NOT OBSERVED" : (isKexCompleted ? "VERIFIED" : (isKexEphemeral ? "INFERRED" : "OBSERVED"));
                const certStatusEvidenceTag = !hasCert ? "NOT OBSERVED" : (isCertExpired || isCertNotYetValid || isLeafSelfSigned || cert.hostname_match === false ? "ISSUE DETECTED" : "VERIFIED");
                const certChainEvidenceTag = !hasCert ? "NOT OBSERVED" : (chainValidation.chain_complete && isChainValid ? "VERIFIED" : (chainValidation.chain_status === 'INCOMPLETE' ? "INCOMPLETE" : (chainValidation.chain_status === 'INVALID' || chainValidation.chain_valid === false ? "ISSUE DETECTED" : "INCOMPLETE")));
                const starttlsEvidenceTag = isImplicitTlsPort ? "OBSERVED" : (starttls.status === 'SECURE_TRANSITION' || (starttls.upgrade_accepted && starttls.tls_transition_observed) ? (isHandshakeComplete ? "VERIFIED" : "INCOMPLETE") : (starttls.status === 'INCOMPLETE' || (starttls.upgrade_supported && !starttls.upgrade_accepted) ? "ISSUE DETECTED" : (isTlsObserved ? "OBSERVED" : (starttls.upgrade_supported === false ? "OBSERVED" : "NOT OBSERVED"))));
                const payloadEvidenceTag = hasEncryptedAppData ? "VERIFIED" : (isTlsObserved ? "INFERRED" : (isConfirmedPlaintext ? "OBSERVED" : "NOT OBSERVED"));
                const handshakeEvidenceTag = !isTlsObserved ? "NOT OBSERVED" : (isHandshakeComplete ? "VERIFIED" : (isHandshakeIncomplete ? "INCOMPLETE" : "OBSERVED"));

                const renderEvidenceChip = (tag) => {
                  let chipStyle = "bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border-slate-200 dark:border-slate-700";
                  if (tag === 'VERIFIED') {
                    chipStyle = "bg-emerald-50 dark:bg-emerald-950/50 text-emerald-800 dark:text-emerald-300 border-emerald-200/80 dark:border-emerald-800";
                  } else if (tag === 'OBSERVED') {
                    chipStyle = "bg-sky-50 dark:bg-sky-950/50 text-sky-800 dark:text-sky-300 border-sky-200/80 dark:border-sky-800";
                  } else if (tag === 'INFERRED') {
                    chipStyle = "bg-indigo-50 dark:bg-indigo-950/50 text-indigo-800 dark:text-indigo-300 border-indigo-200/80 dark:border-indigo-800";
                  } else if (tag === 'INCOMPLETE') {
                    chipStyle = "bg-amber-50 dark:bg-amber-950/50 text-amber-800 dark:text-amber-300 border-amber-200/80 dark:border-amber-800";
                  } else if (tag === 'ISSUE DETECTED') {
                    chipStyle = "bg-rose-50 dark:bg-rose-950/50 text-rose-800 dark:text-rose-300 border-rose-200/80 dark:border-rose-800";
                  } else if (tag === 'NOT OBSERVED') {
                    chipStyle = "bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 border-slate-200 dark:border-slate-700";
                  }
                  return (
                    <span className={`px-1.5 py-0.2 rounded font-sans text-[8.5px] font-semibold uppercase tracking-wider border shrink-0 ${chipStyle}`}>
                      {tag}
                    </span>
                  );
                };

                return (
                  <>
                    <div className="flex items-center justify-between py-1.5 border-b border-slate-100 dark:border-slate-800 gap-2">
                      <div className="flex items-center gap-1.5 shrink-0" title={protocolTooltip}>
                        <span className="text-slate-500 dark:text-slate-400 font-sans text-[11px] font-medium">Protocol:</span>
                        {renderEvidenceChip(protocolEvidenceTag)}
                      </div>
                      <span className="font-semibold text-slate-900 dark:text-white truncate max-w-[190px]" title={`${protocol} (${protocolTooltip})`}>{protocol}</span>
                    </div>

                    <div className="flex items-center justify-between py-1.5 border-b border-slate-100 dark:border-slate-800 gap-2">
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="text-slate-500 dark:text-slate-400 font-sans text-[11px] font-medium">TLS Version:</span>
                        {renderEvidenceChip(tlsVersionEvidenceTag)}
                      </div>
                      <span className={isTlsObserved ? "font-semibold text-emerald-700 dark:text-emerald-400 truncate max-w-[190px]" : "font-semibold text-slate-500 dark:text-slate-400 truncate max-w-[190px]"} title={tlsVersionValue}>
                        {tlsVersionValue}
                      </span>
                    </div>

                    <div className="flex items-center justify-between py-1.5 border-b border-slate-100 dark:border-slate-800 gap-2">
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="text-slate-500 dark:text-slate-400 font-sans text-[11px] font-medium">Cipher Suite:</span>
                        {renderEvidenceChip(cipherSuiteEvidenceTag)}
                      </div>
                      <span className={isTlsObserved && tls.cipher_suite ? "font-semibold text-slate-800 dark:text-slate-200 truncate max-w-[190px]" : "font-semibold text-slate-500 dark:text-slate-400 truncate max-w-[190px]"} title={cipherSuiteValue}>
                        {cipherSuiteValue}
                      </span>
                    </div>

                    <div className="flex items-center justify-between py-1.5 border-b border-slate-100 dark:border-slate-800 gap-2">
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="text-slate-500 dark:text-slate-400 font-sans text-[11px] font-medium">Key Exchange / PFS:</span>
                        {renderEvidenceChip(kexEvidenceTag)}
                      </div>
                      <span className={isKexCompleted ? "font-semibold text-emerald-700 dark:text-emerald-400 truncate max-w-[190px]" : (isKexEphemeral ? "font-semibold text-sky-700 dark:text-sky-400 truncate max-w-[190px]" : (isTlsObserved ? "font-semibold text-slate-600 dark:text-slate-400 truncate max-w-[190px]" : "font-semibold text-slate-500 dark:text-slate-400 truncate max-w-[190px]"))} title={keyExchangeValue}>
                        {keyExchangeValue}
                      </span>
                    </div>

                    <div className="flex items-center justify-between py-1.5 border-b border-slate-100 dark:border-slate-800 gap-2">
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="text-slate-500 dark:text-slate-400 font-sans text-[11px] font-medium">Certificate Status:</span>
                        {renderEvidenceChip(certStatusEvidenceTag)}
                      </div>
                      <span className={hasCert ? (isCertExpired || isCertNotYetValid ? "font-semibold text-rose-700 dark:text-rose-400 truncate max-w-[190px]" : (isLeafSelfSigned ? "font-semibold text-amber-700 dark:text-amber-400 truncate max-w-[190px]" : "font-semibold text-emerald-700 dark:text-emerald-400 truncate max-w-[190px]")) : "font-semibold text-slate-500 dark:text-slate-400 truncate max-w-[190px]"} title={certStatusValue}>
                        {certStatusValue}
                      </span>
                    </div>

                    <div className="flex items-center justify-between py-1.5 border-b border-slate-100 dark:border-slate-800 gap-2">
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="text-slate-500 dark:text-slate-400 font-sans text-[11px] font-medium">Certificate Chain:</span>
                        {renderEvidenceChip(certChainEvidenceTag)}
                      </div>
                      <span className={hasCert ? (chainValidation.chain_complete && isChainValid ? "font-semibold text-emerald-700 dark:text-emerald-400 truncate max-w-[190px]" : (chainValidation.chain_status === 'INVALID' ? "font-semibold text-rose-700 dark:text-rose-400 truncate max-w-[190px]" : "font-semibold text-amber-700 dark:text-amber-400 truncate max-w-[190px]")) : "font-semibold text-slate-500 dark:text-slate-400 truncate max-w-[190px]"} title={certChainValue}>
                        {certChainValue}
                      </span>
                    </div>

                    <div className="flex items-center justify-between py-1.5 border-b border-slate-100 dark:border-slate-800 gap-2">
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="text-slate-500 dark:text-slate-400 font-sans text-[11px] font-medium">STARTTLS Status:</span>
                        {renderEvidenceChip(starttlsEvidenceTag)}
                      </div>
                      <span className={starttlsStatusValue.includes('complete') ? "font-semibold text-emerald-700 dark:text-emerald-400 truncate max-w-[190px]" : (starttlsStatusValue.includes('accepted') || starttlsStatusValue.includes('transition') ? "font-semibold text-sky-700 dark:text-sky-400 truncate max-w-[190px]" : (starttlsStatusValue.includes('not offered') || starttlsStatusValue.includes('rejected') ? "font-semibold text-rose-700 dark:text-rose-400 truncate max-w-[190px]" : "font-semibold text-slate-500 dark:text-slate-400 truncate max-w-[190px]"))} title={starttlsStatusValue}>
                        {starttlsStatusValue}
                      </span>
                    </div>

                    <div className="flex items-center justify-between py-1.5 border-b border-slate-100 dark:border-slate-800 gap-2">
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="text-slate-500 dark:text-slate-400 font-sans text-[11px] font-medium">Payload Security:</span>
                        {renderEvidenceChip(payloadEvidenceTag)}
                      </div>
                      <span className={hasEncryptedAppData ? "font-semibold text-emerald-700 dark:text-emerald-400 truncate max-w-[190px]" : (isTlsObserved ? "font-semibold text-slate-700 dark:text-slate-300 truncate max-w-[190px]" : (isConfirmedPlaintext ? "font-semibold text-rose-700 dark:text-rose-400 truncate max-w-[190px]" : "font-semibold text-slate-500 dark:text-slate-400 truncate max-w-[190px]"))} title={encryptionValue}>
                        {encryptionValue}
                      </span>
                    </div>

                    <div className="flex items-center justify-between py-1.5 border-b border-slate-100 dark:border-slate-800 gap-2">
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="text-slate-500 dark:text-slate-400 font-sans text-[11px] font-medium">Handshake Status:</span>
                        {renderEvidenceChip(handshakeEvidenceTag)}
                      </div>
                      <span className={isHandshakeComplete ? "font-semibold text-emerald-700 dark:text-emerald-400 truncate max-w-[190px]" : (isHandshakeIncomplete ? "font-semibold text-amber-700 dark:text-amber-400 truncate max-w-[190px]" : "font-semibold text-slate-500 dark:text-slate-400 truncate max-w-[190px]")} title={handshakeStatusValue}>
                        {handshakeStatusValue}
                      </span>
                    </div>

                    <div className="flex items-center justify-between py-1.5 border-b border-slate-100 dark:border-slate-800 gap-2">
                      <div className="flex items-center gap-1.5 shrink-0">
                        <span className="text-slate-500 dark:text-slate-400 font-sans text-[11px] font-medium">Session Traffic:</span>
                        {renderEvidenceChip("OBSERVED")}
                      </div>
                      <span className="font-semibold text-slate-700 dark:text-slate-300 truncate max-w-[190px]" title={`C→S: ${formatBytes(c2sBytes)} · S→C: ${formatBytes(s2cBytes)}`}>
                        C→S: {formatBytes(c2sBytes)} · S→C: {formatBytes(s2cBytes)}
                      </span>
                    </div>
                  </>
                );
              })()}
            </div>
          </section>
        </div>

        {/* RIGHT COLUMN: AI RISK FACTORS & VERIFICATION SIGNALS */}
        <div className="lg:col-span-4 flex flex-col gap-5">
          {/* AI Risk Assessment Card */}
          <section className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-5 sm:p-6 shadow-xs flex flex-col gap-4">
            <div className="flex flex-col gap-1 border-b border-slate-100 dark:border-slate-800 pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="material-symbols-outlined text-[18px] text-[#006591] dark:text-sky-400">psychology</span>
                  <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">AI Risk Assessment</h2>
                </div>
                <span className="text-[10px] font-sans font-medium text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-800 px-2 py-0.5 rounded border border-slate-200 dark:border-slate-700">
                  Risk Factors
                </span>
              </div>
              <span className="text-[10px] text-slate-400 dark:text-slate-500 font-sans">
                Secondary ML risk signal; does not override deterministic security findings.
              </span>
            </div>

            <div className="flex flex-col gap-2.5 py-1">
              {topRiskFactors.length === 0 ? (
                <div className="text-slate-400 dark:text-slate-500 text-xs py-3 text-center">
                  No significant risk factors observed
                </div>
              ) : (
                topRiskFactors.map((factor, idx) => {
                  const contribVal = factor.contribution != null ? Number(factor.contribution) : 0;
                  const isNegative = factor.observed === true && factor.feature !== 'none';

                  if (factor.feature === 'none') {
                    return (
                      <div key={`factor-${idx}`} className="text-emerald-700 dark:text-emerald-400 font-medium text-xs py-2">
                        ✓ {factor.label}
                      </div>
                    );
                  }

                  return (
                    <div key={`factor-${factor.feature}-${idx}`} className="flex flex-col gap-1 border-b border-slate-100 dark:border-slate-800 last:border-0 pb-2.5 last:pb-0">
                      <div className="flex items-start justify-between gap-2 text-xs">
                        <div className="flex items-start gap-1.5">
                          <span className={`w-1.5 h-1.5 rounded-full mt-1 shrink-0 ${isNegative ? 'bg-rose-500' : 'bg-emerald-500'}`}></span>
                          <span className="font-medium text-slate-800 dark:text-slate-200">{factor.label}</span>
                        </div>
                      </div>
                      <div className="text-[11px] font-sans text-slate-500 dark:text-slate-400 pl-3">
                        Risk Weight: <span className="font-semibold tabular-nums">{contribVal.toFixed(2)}</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </section>

          {/* Verification Signals Card */}
          <section className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-5 sm:p-6 shadow-xs flex flex-col gap-4">
            <div className="border-b border-slate-100 dark:border-slate-800 pb-3 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="material-symbols-outlined text-[18px] text-[#006591] dark:text-sky-400">verified_user</span>
                <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">Verification Signals</h2>
              </div>
            </div>

            <div className="flex flex-col gap-2.5 text-xs font-sans">
              {/* Deterministic Posture */}
              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 flex items-center justify-between">
                <div>
                  <div className="font-semibold text-slate-800 dark:text-slate-200">Security Posture</div>
                  <div className="text-[10px] text-slate-500 dark:text-slate-400">Deterministic Rules (RFC 8446 / NIST)</div>
                </div>
                <span className="font-bold tabular-nums text-slate-900 dark:text-white">{postureScore}/100</span>
              </div>

              {/* Anomaly Detection */}
              <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-slate-800/60 border border-slate-200 dark:border-slate-700 flex items-center justify-between">
                <div>
                  <div className="font-semibold text-slate-800 dark:text-slate-200">Anomaly Detection</div>
                  <div className="text-[10px] text-slate-500 dark:text-slate-400">Isolation Forest</div>
                </div>
                <span className={`font-bold ${isAnomaly ? 'text-rose-700 dark:text-rose-400' : 'text-emerald-700 dark:text-emerald-400'}`}>
                  {anomalyStatus}
                </span>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
