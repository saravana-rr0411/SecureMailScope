import * as XLSX from 'xlsx';
import _jsPDF from 'jspdf';
import _autoTable from 'jspdf-autotable';
import { getAiRiskTier, hasConfirmedPlaintextPayload } from './utils/securityStats.js';

const jsPDF = _jsPDF.jsPDF || _jsPDF.default || _jsPDF;
const autoTable = _autoTable.default || _autoTable;

/**
 * Generates a clean, sanitized filename based on the PCAP name.
 * e.g. "01_secure_smtp_tls12.pcap" -> "01_secure_smtp_tls12_report.pdf"
 */
export function getReportFilename(captureData, extension) {
  const cleanExt = extension.startsWith('.') ? extension.slice(1) : extension;
  if (captureData?.reportFilename) {
    return captureData.reportFilename.endsWith(`.${cleanExt}`)
      ? captureData.reportFilename
      : `${captureData.reportFilename}.${cleanExt}`;
  }
  const rawName = captureData?.filename;
  if (!rawName || rawName === 'capture' || rawName === 'pcap') {
    return `SecureMailScope-Executive-Report.${cleanExt}`;
  }
  const withoutExt = String(rawName).replace(/\.(pcapng|pcap|cap)$/i, '');
  const sanitized = withoutExt.trim().replace(/[^a-zA-Z0-9_-]/g, '_').replace(/_+/g, '_');
  if (sanitized.toLowerCase().startsWith('securemailscope-executive-report')) {
    return `${sanitized}.${cleanExt}`;
  }
  return `SecureMailScope-Executive-Report-${sanitized}.${cleanExt}`;
}

/**
 * Formats byte counts into human-readable strings.
 */
function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  return bytes > 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${bytes} B`;
}

/**
 * Escapes HTML entities for safe template insertion.
 */
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Maps security findings to one of the 9 forensic pipeline stages (01-09).
 */
export const PIPELINE_STAGE_METADATA = {
  1: { num: '01', name: 'PCAP Ingestion' },
  2: { num: '02', name: 'Protocol Detection' },
  3: { num: '03', name: 'TCP Stream Reconstruction' },
  4: { num: '04', name: 'STARTTLS Detection' },
  5: { num: '05', name: 'TLS Handshake Analysis' },
  6: { num: '06', name: 'Certificate / Chain Validation' },
  7: { num: '07', name: 'Security Assessment' },
  8: { num: '08', name: 'AI Risk Analysis' },
  9: { num: '09', name: 'Final Result' }
};

export function getPipelineStageForFinding(finding) {
  if (!finding) return PIPELINE_STAGE_METADATA[7];
  const category = (finding.category || '').toUpperCase();
  const id = (finding.id || finding.finding_id || finding.rule_id || '').toLowerCase();
  const text = `${finding.label || ''} ${finding.title || ''} ${finding.reason || ''} ${finding.description || ''}`.toLowerCase();

  if (category === 'PCAP' || category === 'CAPTURE' || text.includes('pcap') || text.includes('packet capture')) {
    return PIPELINE_STAGE_METADATA[1];
  }
  if (category === 'PROTOCOL' || category === 'PROTOCOL_DETECTION' || id.includes('proto') || text.includes('protocol detection')) {
    return PIPELINE_STAGE_METADATA[2];
  }
  if (category === 'RECONSTRUCTION' || category === 'TCP' || id.includes('tcp') || text.includes('stream reconstruction') || text.includes('tcp stream')) {
    return PIPELINE_STAGE_METADATA[3];
  }
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
  if (category === 'FINAL_RESULT' || text.includes('overall posture') || text.includes('final result')) {
    return PIPELINE_STAGE_METADATA[9];
  }
  return PIPELINE_STAGE_METADATA[7];
}

/**
 * Extracts comprehensive, synchronized telemetry for the report matching ForensicsScreen.jsx.
 */
export function extractCaptureReportContext(captureData) {
  const sessions = captureData?.sessions || [];
  const totalSessions = sessions.length;
  const s0 = sessions[0] || {};
  const filename = captureData?.filename || 'capture.pcap';
  const totalPackets = captureData?.total_packets ?? (totalSessions * 148);

  const sessId = s0.session_id || 'TCP-001';
  const protocol = s0.protocol || 'UNKNOWN';
  const srcIp = s0.source_ip || '0.0.0.0';
  const srcPort = s0.source_port ?? 0;
  const dstIp = s0.destination_ip || '0.0.0.0';
  const dstPort = s0.destination_port ?? 0;
  const c2sBytes = s0.client_to_server_bytes || 0;
  const s2cBytes = s0.server_to_client_bytes || 0;
  const totalBytes = c2sBytes + s2cBytes;
  const duration = s0.duration_seconds ?? 0;

  // Primary AI Risk
  const aiRisk = s0.ai_risk || captureData?.ai_risk || {};
  const aiScoreNum = aiRisk.score != null ? Number(aiRisk.score) : 0;
  const aiScore = aiRisk.score != null ? Number(aiRisk.score).toFixed(1) : '—';
  const aiLabel = getAiRiskTier(aiRisk);
  const aiConfidence = aiRisk.confidence != null ? Math.round(aiRisk.confidence * 100) : 95;
  const topRiskFactors = aiRisk.top_risk_factors || [];

  // Protocol & TLS Attributes
  const tls = s0.tls || {};
  const isTlsObserved = tls.detected === true || (tls.version && tls.version !== 'None' && tls.version !== 'Plaintext');
  const cert = tls.certificate || {};
  const chainValidation = tls.certificate_chain_validation || cert.certificate_chain || {};
  const starttls = s0.starttls || {};
  const isImplicitTlsPort = dstPort === 465 || dstPort === 993 || dstPort === 995 || srcPort === 465 || srcPort === 993 || srcPort === 995;
  const starttlsStatus = starttls.status || (isImplicitTlsPort ? 'DIRECT_TLS' : 'NOT_OBSERVED');
  const isHandshakeComplete = tls.handshake_status === 'COMPLETE' || tls.handshake_complete === true;
  const isHandshakeIncomplete = isTlsObserved && !isHandshakeComplete;
  const isKexEphemeral = tls.forward_secrecy === true || (tls.cipher_suite && (tls.cipher_suite.includes('ECDHE') || tls.cipher_suite.includes('DHE')));
  const kexName = tls.key_exchange || (tls.cipher_suite?.includes('ECDHE') ? 'ECDHE' : tls.cipher_suite?.includes('DHE') ? 'DHE' : null);
  const isKexCompleted = tls.ephemeral_key_exchange_verified === true ||
    (isKexEphemeral && (isHandshakeComplete || tls.encrypted_application_data_observed || (tls.handshake_messages?.includes('ClientKeyExchange') && tls.handshake_messages?.includes('ServerKeyExchange'))));
  const hasEncryptedAppData = Boolean(tls.encrypted_application_data_observed);
  const isConfirmedPlaintext = hasConfirmedPlaintextPayload(s0);
  const hasCert = Boolean(cert.subject || cert.issuer || cert.common_name);
  const isCertExpired = cert.expired === true || cert.expiration_status === 'EXPIRED';
  const isCertNotYetValid = cert.not_yet_valid === true || cert.expiration_status === 'NOT_YET_VALID';
  const isLeafSelfSigned = cert.self_signed === true;
  const isChainValid = chainValidation.chain_status === 'VALID' || chainValidation.chain_valid === true;

  // Deterministic Posture
  const postureData = s0.posture || captureData?.posture || {};
  const postureStatus = postureData.security_posture || (isTlsObserved ? 'SECURE' : 'AT_RISK');
  const postureScore = postureData.score != null ? postureData.score : (isTlsObserved ? 100 : 0);
  const postureRiskLevel = postureData.risk_level || (postureScore >= 80 ? 'LOW' : postureScore >= 50 ? 'MODERATE' : 'HIGH');

  // Isolation Forest Anomaly
  const anomalyData = s0.ai_analysis || captureData?.ai_analysis || {};
  const isAnomaly = anomalyData.anomaly_detected === true;
  const anomalyStatus = isAnomaly ? 'OUTLIER' : 'NORMAL';
  const anomalyScore = anomalyData.anomaly_score != null ? Number(anomalyData.anomaly_score).toFixed(2) : '0.00';

  // Findings
  const assessmentFindings = s0.assessment?.findings || s0.findings || [];
  const findingsList = [];
  const seenLabels = new Set();
  assessmentFindings.forEach((f) => {
    const title = f.title || f.label || f.finding_id || 'Security Finding';
    if (!seenLabels.has(title)) {
      seenLabels.add(title);
      findingsList.push({
        id: f.finding_id || f.id || f.rule_id || 'FINDING',
        title,
        severity: f.severity || 'HIGH',
        category: f.category || 'ASSESSMENT',
        reason: f.reason || f.description || '',
        description: f.description || f.reason || '',
        evidence: f.evidence || [],
        recommendation: f.recommendation || '',
        stage: getPipelineStageForFinding(f)
      });
    }
  });

  const critCount = findingsList.filter(f => f.severity === 'CRITICAL').length;
  const highCount = findingsList.filter(f => f.severity === 'HIGH').length;
  const medCount = findingsList.filter(f => f.severity === 'MEDIUM').length;
  const lowCount = findingsList.filter(f => f.severity === 'LOW').length;

  // Recommended Remediation Actions matching ForensicsScreen.jsx
  const recommendedActions = [];
  const isIncompleteSession = (postureStatus === 'INCOMPLETE' || (!isTlsObserved && !isConfirmedPlaintext)) && findingsList.length === 0;
  const hasCriticalOrHighIssues = (!isTlsObserved && isConfirmedPlaintext) ||
    postureStatus === 'COMPROMISED' ||
    postureStatus === 'AT_RISK' ||
    critCount > 0 || highCount > 0;

  if (isIncompleteSession) {
    recommendedActions.push("Insufficient capture data to fully evaluate session. Capture a complete TLS handshake to verify cipher and certificate parameters.");
  } else if (!hasCriticalOrHighIssues && isTlsObserved) {
    recommendedActions.push("No immediate action required. Continue standard security monitoring.");
  } else {
    findingsList.forEach(f => {
      if (f.recommendation && !recommendedActions.includes(f.recommendation)) {
        recommendedActions.push(f.recommendation);
      }
    });

    const hasStarttlsIssue = starttls.status === 'INCOMPLETE' ||
      (starttls.upgrade_supported && !starttls.accepted) ||
      findingsList.some(f => f.title?.toLowerCase().includes('starttls') || f.title?.toLowerCase().includes('stls'));

    const hasPlaintext = (!isTlsObserved && isConfirmedPlaintext) ||
      findingsList.some(f => f.title?.toLowerCase().includes('plaintext') || f.title?.toLowerCase().includes('unencrypted'));

    const certExpired = hasCert && (isCertExpired || findingsList.some(f => f.title?.toLowerCase().includes('expired')));
    const hostnameMismatch = hasCert && (cert.hostname_match === false || findingsList.some(f => f.title?.toLowerCase().includes('hostname')));
    const chainIssue = hasCert && (!isChainValid || chainValidation.chain_status === 'INVALID' || findingsList.some(f => f.title?.toLowerCase().includes('chain')));
    const selfSigned = hasCert && (isLeafSelfSigned || findingsList.some(f => f.title?.toLowerCase().includes('self-signed')));
    const weakTlsOrCipher = (isTlsObserved && (tls.version === 'TLS 1.0' || tls.version === 'TLS 1.1' || tls.version === 'SSLv3' || tls.version === 'SSLv2')) ||
      findingsList.some(f => f.title?.toLowerCase().includes('cipher') || f.title?.toLowerCase().includes('deprecated') || f.title?.toLowerCase().includes('weak tls'));
    const noForwardSecrecy = isTlsObserved && tls.forward_secrecy === false && !weakTlsOrCipher;

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
    if (selfSigned) {
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
  const displayActions = Array.from(new Set(recommendedActions)).slice(0, 4);

  // 9-Stage Forensic Processing Pipeline Nodes
  const pcapLoaded = totalPackets > 0 || totalSessions > 0;
  const stagePcap = {
    stepNum: '01',
    name: 'PCAP Ingestion',
    status: pcapLoaded ? 'VERIFIED' : 'NO DATA',
    color: pcapLoaded ? 'green' : 'red',
    label: `${totalPackets} pkts`,
    desc: pcapLoaded ? 'Capture loaded & indexed' : 'Empty capture'
  };

  const hasKnownProtocol = protocol && protocol !== 'UNKNOWN';
  const protoConfidence = s0.protocol_confidence || 'HIGH';
  const isPortInferred = s0.protocol_detection_method === 'PORT_INFERRED' || protoConfidence === 'MEDIUM';
  const isProtoConfirmed = s0.protocol_detection_method === 'APPLICATION_DATA' || (hasKnownProtocol && protoConfidence === 'HIGH');
  const stageProto = {
    stepNum: '02',
    name: 'Protocol Detection',
    status: hasKnownProtocol ? (isPortInferred ? 'INFERRED' : (protoConfidence === 'LOW' ? 'INDETERMINATE' : 'VERIFIED')) : 'ISSUE DETECTED',
    color: hasKnownProtocol ? (isPortInferred ? 'amber' : (protoConfidence === 'LOW' ? 'amber' : 'green')) : 'red',
    label: protocol,
    desc: isProtoConfirmed ? `${protocol} (Confirmed from data)` : (isPortInferred ? `${protocol} (Inferred from port)` : `${protocol} (${protoConfidence})`)
  };

  const streamReconstructed = Boolean(s0.session_id && (c2sBytes + s2cBytes > 0 || s0.packet_count > 0));
  const stageTcp = {
    stepNum: '03',
    name: 'TCP Stream Reconstruction',
    status: streamReconstructed ? 'VERIFIED' : 'INDETERMINATE',
    color: streamReconstructed ? 'green' : 'amber',
    label: formatBytes(c2sBytes + s2cBytes),
    desc: streamReconstructed ? 'Stream reconstructed' : 'Partial stream'
  };

  let stageStarttls;
  if (isImplicitTlsPort && isTlsObserved) {
    stageStarttls = {
      stepNum: '04',
      name: 'STARTTLS Detection',
      status: 'VERIFIED',
      color: 'green',
      label: 'Direct TLS',
      desc: 'Implicit TLS (No STARTTLS required)'
    };
  } else if (starttls.status === 'SECURE_TRANSITION' || (starttls.upgrade_accepted && starttls.tls_transition_observed)) {
    stageStarttls = {
      stepNum: '04',
      name: 'STARTTLS Detection',
      status: 'VERIFIED',
      color: 'green',
      label: isHandshakeIncomplete ? 'Transitioned' : 'Negotiated',
      desc: isHandshakeIncomplete ? 'STARTTLS accepted; TLS handshake incomplete' : 'Upgrade accepted & transition observed'
    };
  } else if (starttls.status === 'INCOMPLETE' || (starttls.upgrade_supported && !starttls.upgrade_accepted) || (starttls.upgrade_accepted && !starttls.tls_transition_observed)) {
    stageStarttls = {
      stepNum: '04',
      name: 'STARTTLS Detection',
      status: 'ISSUE DETECTED',
      color: 'red',
      label: 'Incomplete',
      desc: starttls.upgrade_accepted ? 'Accepted but no TLS transition' : 'Transition failed'
    };
  } else if (!isTlsObserved) {
    if (isImplicitTlsPort) {
      stageStarttls = {
        stepNum: '04',
        name: 'STARTTLS Detection',
        status: 'VERIFIED',
        color: 'green',
        label: 'Direct TLS',
        desc: 'Implicit TLS port; STARTTLS not applicable'
      };
    } else if (starttls.upgrade_supported === true) {
      stageStarttls = {
        stepNum: '04',
        name: 'STARTTLS Detection',
        status: 'ISSUE DETECTED',
        color: 'red',
        label: 'Not Requested',
        desc: 'Plaintext session without TLS upgrade'
      };
    } else if (starttls.upgrade_supported === false) {
      stageStarttls = {
        stepNum: '04',
        name: 'STARTTLS Detection',
        status: 'ISSUE DETECTED',
        color: 'red',
        label: 'Not Offered',
        desc: 'Server did not advertise STARTTLS capability'
      };
    } else {
      stageStarttls = {
        stepNum: '04',
        name: 'STARTTLS Detection',
        status: 'INDETERMINATE',
        color: 'amber',
        label: 'NOT DETERMINABLE',
        desc: 'NOT DETERMINABLE FROM CAPTURE'
      };
    }
  } else {
    stageStarttls = {
      stepNum: '04',
      name: 'STARTTLS Detection',
      status: 'VERIFIED',
      color: 'green',
      label: 'Direct TLS',
      desc: 'Direct TLS transport'
    };
  }

  let stageTls;
  if (isTlsObserved) {
    const isLegacy = tls.version === 'TLS 1.0' || tls.version === 'TLS 1.1' || tls.version === 'SSLv3' || tls.version === 'SSLv2';
    if (isLegacy) {
      stageTls = {
        stepNum: '05',
        name: 'TLS Handshake Analysis',
        status: 'ISSUE DETECTED',
        color: 'red',
        label: `${tls.version}`,
        desc: 'Deprecated legacy TLS version'
      };
    } else if (tls.forward_secrecy === false) {
      stageTls = {
        stepNum: '05',
        name: 'TLS Handshake Analysis',
        status: 'INDETERMINATE',
        color: 'amber',
        label: `${tls.version}`,
        desc: isHandshakeIncomplete ? 'Negotiated without PFS (Incomplete)' : 'Established without PFS'
      };
    } else {
      stageTls = {
        stepNum: '05',
        name: 'TLS Handshake Analysis',
        status: 'VERIFIED',
        color: 'green',
        label: `${tls.version}`,
        desc: isHandshakeIncomplete ? 'Modern TLS negotiated; handshake incomplete' : 'Modern TLS established & verified'
      };
    }
  } else {
    if (isConfirmedPlaintext) {
      stageTls = {
        stepNum: '05',
        name: 'TLS Handshake Analysis',
        status: 'ISSUE DETECTED',
        color: 'red',
        label: 'Not Established',
        desc: 'Plaintext email session; no TLS handshake'
      };
    } else {
      stageTls = {
        stepNum: '05',
        name: 'TLS Handshake Analysis',
        status: 'INDETERMINATE',
        color: 'amber',
        label: 'NOT OBSERVED',
        desc: 'TLS handshake not observed in capture'
      };
    }
  }

  let stageCert;
  if (!isTlsObserved) {
    if (isConfirmedPlaintext) {
      stageCert = {
        stepNum: '06',
        name: 'Certificate / Chain Validation',
        status: 'ISSUE DETECTED',
        color: 'red',
        label: 'Missing',
        desc: 'No certificate presented (Plaintext session)'
      };
    } else {
      stageCert = {
        stepNum: '06',
        name: 'Certificate / Chain Validation',
        status: 'INDETERMINATE',
        color: 'amber',
        label: 'NOT OBSERVED',
        desc: 'Certificate not observed in capture'
      };
    }
  } else if (!hasCert) {
    stageCert = {
      stepNum: '06',
      name: 'Certificate / Chain Validation',
      status: 'INDETERMINATE',
      color: 'amber',
      label: 'NOT OBSERVED',
      desc: 'Certificate not observed in capture'
    };
  } else {
    const isExpired = cert.expired === true || cert.expiration_status === 'EXPIRED';
    const isHostnameFail = cert.hostname_match === false;
    const isChainInvalid = chainValidation.chain_status === 'INVALID' || chainValidation.chain_valid === false;
    if (isExpired || isHostnameFail || isChainInvalid || isLeafSelfSigned) {
      stageCert = {
        stepNum: '06',
        name: 'Certificate / Chain Validation',
        status: isExpired || isChainInvalid ? 'ISSUE DETECTED' : 'INDETERMINATE',
        color: isExpired || isChainInvalid ? 'red' : 'amber',
        label: isExpired ? 'Expired' : (isHostnameFail ? 'Host Mismatch' : (isLeafSelfSigned ? 'Self-Signed' : 'Chain Invalid')),
        desc: isExpired ? 'Leaf certificate expired' : (isHostnameFail ? 'Hostname SAN/CN mismatch' : (isLeafSelfSigned ? 'Self-signed leaf certificate' : 'Trust chain validation failed'))
      };
    } else if (chainValidation.chain_complete && isChainValid) {
      stageCert = {
        stepNum: '06',
        name: 'Certificate / Chain Validation',
        status: 'VERIFIED',
        color: 'green',
        label: 'Chain Verified',
        desc: 'Valid leaf & complete chain'
      };
    } else {
      stageCert = {
        stepNum: '06',
        name: 'Certificate / Chain Validation',
        status: 'VERIFIED',
        color: 'green',
        label: 'Valid Leaf',
        desc: cert.common_name || 'Leaf cert presented'
      };
    }
  }

  let stageAssessment;
  if (critCount > 0 || highCount > 0) {
    stageAssessment = {
      stepNum: '07',
      name: 'Security Assessment',
      status: 'ISSUE DETECTED',
      color: 'red',
      label: `${critCount + highCount} Issues`,
      desc: `${critCount} Critical, ${highCount} High findings`
    };
  } else if (medCount > 0) {
    stageAssessment = {
      stepNum: '07',
      name: 'Security Assessment',
      status: 'INDETERMINATE',
      color: 'amber',
      label: `${medCount} Warnings`,
      desc: 'Minor deprecations / warnings'
    };
  } else {
    stageAssessment = {
      stepNum: '07',
      name: 'Security Assessment',
      status: 'VERIFIED',
      color: 'green',
      label: 'Zero Findings',
      desc: 'Conforms to security baseline'
    };
  }

  let stageAi;
  if (aiLabel === 'CRITICAL' || aiLabel === 'HIGH') {
    stageAi = {
      stepNum: '08',
      name: 'AI Risk (ML)',
      status: 'ISSUE DETECTED',
      color: 'red',
      label: `${aiLabel} (${aiScore})`,
      desc: 'Secondary ML Signal: Elevated risk'
    };
  } else if (aiLabel === 'MODERATE') {
    stageAi = {
      stepNum: '08',
      name: 'AI Risk (ML)',
      status: 'INDETERMINATE',
      color: 'amber',
      label: `${aiLabel} (${aiScore})`,
      desc: 'Secondary ML Signal: Moderate risk'
    };
  } else {
    stageAi = {
      stepNum: '08',
      name: 'AI Risk (ML)',
      status: 'VERIFIED',
      color: 'green',
      label: `LOW (${aiScore})`,
      desc: 'Secondary ML Signal: Low risk'
    };
  }

  // Stage 09: Final Result (Strictly follows deterministic security posture and findings, NOT AI risk score)
  let stageFinal;
  const normPosture = String(postureStatus).trim().toUpperCase();
  const isConfirmedIssue = normPosture === 'AT_RISK' || normPosture === 'COMPROMISED' || critCount > 0 || highCount > 0 || (!isTlsObserved && isConfirmedPlaintext);
  const isIncomplete = normPosture === 'INCOMPLETE' || (!isTlsObserved && !isConfirmedPlaintext);

  if (isConfirmedIssue) {
    stageFinal = {
      stepNum: '09',
      name: 'Final Result',
      status: 'ISSUE DETECTED',
      color: 'red',
      label: 'AT_RISK',
      desc: 'Deterministic security issue detected'
    };
  } else if (isIncomplete) {
    stageFinal = {
      stepNum: '09',
      name: 'Final Result',
      status: 'INDETERMINATE',
      color: 'amber',
      label: 'INCOMPLETE',
      desc: 'Incomplete capture; insufficient evidence to confirm security baseline'
    };
  } else {
    // 100/100 SECURE + 0 findings -> Stage 09 = SECURE CONFIG / VERIFIED
    stageFinal = {
      stepNum: '09',
      name: 'Final Result',
      status: 'VERIFIED',
      color: 'green',
      label: isHandshakeIncomplete || !hasEncryptedAppData ? 'SECURE CONFIG' : 'SECURE',
      desc: isHandshakeIncomplete || !hasEncryptedAppData ? 'Secure configuration; capture incomplete' : 'Encrypted mail session completed'
    };
  }

  const pipelineStages = [
    stagePcap,
    stageProto,
    stageTcp,
    stageStarttls,
    stageTls,
    stageCert,
    stageAssessment,
    stageAi,
    stageFinal
  ];

  // Specific 02 STARTTLS Attributes
  const starttlsDetails = [
    { label: 'Negotiation Status', value: isImplicitTlsPort ? 'DIRECT_TLS' : (starttls.status || 'NOT DETERMINABLE FROM CAPTURE'), tag: isImplicitTlsPort ? 'OBSERVED' : (starttls.status === 'SECURE_TRANSITION' ? 'VERIFIED' : starttls.status === 'INCOMPLETE' ? 'ISSUE DETECTED' : (starttls.status ? 'OBSERVED' : 'NOT OBSERVED')) },
    { label: 'Transport Mode', value: isImplicitTlsPort ? 'Direct TLS (Implicit SSL)' : 'Explicit STARTTLS Upgrade', tag: 'OBSERVED' },
    { label: 'Upgrade Supported / Advertised', value: starttls.upgrade_supported === true ? 'YES' : (starttls.upgrade_supported === false ? 'NO' : 'NOT DETERMINABLE'), tag: starttls.upgrade_supported === true ? 'OBSERVED' : (starttls.upgrade_supported === false ? 'OBSERVED' : 'NOT OBSERVED') },
    { label: 'Upgrade Requested', value: starttls.upgrade_requested === true ? 'YES' : (starttls.upgrade_requested === false ? 'NO' : 'NOT DETERMINABLE'), tag: starttls.upgrade_requested === true ? 'OBSERVED' : (starttls.upgrade_requested === false ? 'OBSERVED' : 'NOT OBSERVED') },
    { label: 'Upgrade Accepted', value: starttls.upgrade_accepted === true ? 'YES' : (starttls.upgrade_accepted === false ? 'NO' : 'NOT DETERMINABLE'), tag: starttls.upgrade_accepted === true ? 'VERIFIED' : (starttls.upgrade_accepted === false ? 'ISSUE DETECTED' : 'NOT OBSERVED') },
    { label: 'TLS Transition Observed', value: starttls.tls_transition_observed === true ? 'YES' : (starttls.tls_transition_observed === false ? 'NO' : 'NOT DETERMINABLE'), tag: starttls.tls_transition_observed === true ? 'VERIFIED' : (starttls.tls_transition_observed === false ? 'ISSUE DETECTED' : 'NOT OBSERVED') }
  ];

  // Specific 03 TLS Attributes
  const tlsDetails = [
    { label: 'TLS Version', value: isTlsObserved ? (tls.version || 'TLS') : 'NOT OBSERVED', tag: !isTlsObserved ? 'NOT OBSERVED' : (tls.version && tls.version !== 'None' ? 'VERIFIED' : 'OBSERVED') },
    { label: 'Negotiated Cipher Suite', value: isTlsObserved && tls.cipher_suite ? tls.cipher_suite : 'NOT OBSERVED', tag: !isTlsObserved ? 'NOT OBSERVED' : (tls.cipher_suite ? 'VERIFIED' : 'INCOMPLETE') },
    { label: 'Key Exchange & PFS', value: isTlsObserved ? (isKexEphemeral ? (isKexCompleted ? `${kexName || 'ECDHE'} (PFS verified)` : `${kexName || 'ECDHE'} (PFS indicated)`) : (kexName ? `${kexName} (No PFS)` : 'PFS not determinable')) : 'NOT OBSERVED / INSUFFICIENT EVIDENCE', tag: !isTlsObserved ? 'NOT OBSERVED' : (isKexCompleted ? 'VERIFIED' : (isKexEphemeral ? 'INFERRED' : 'OBSERVED')) },
    { label: 'Handshake Completion', value: isTlsObserved ? (isHandshakeComplete ? 'TLS handshake complete' : 'TLS handshake incomplete') : 'NOT OBSERVED', tag: !isTlsObserved ? 'NOT OBSERVED' : (isHandshakeComplete ? 'VERIFIED' : (isHandshakeIncomplete ? 'INCOMPLETE' : 'OBSERVED')) },
    { label: 'Application Payload Encryption', value: isTlsObserved ? (hasEncryptedAppData ? 'Encrypted application data observed (TLS)' : 'TLS cipher negotiated; encrypted payload not observed') : (isConfirmedPlaintext ? 'Plaintext application payload observed' : 'UNCLASSIFIED / INSUFFICIENT EVIDENCE'), tag: hasEncryptedAppData ? 'VERIFIED' : (isTlsObserved ? 'INFERRED' : (isConfirmedPlaintext ? 'OBSERVED' : 'NOT OBSERVED')) },
    { label: 'Server Name Indication (SNI)', value: tls.client_hello?.server_name || cert.common_name || 'Not observable', tag: tls.client_hello?.server_name ? 'OBSERVED' : 'NOT OBSERVED' }
  ];

  // Specific 04 Certificate Attributes
  const certDetails = [
    { label: 'Certificate Presented', value: hasCert ? 'YES' : 'NO', tag: hasCert ? 'VERIFIED' : 'NOT OBSERVED' },
    { label: 'Common Name (CN)', value: cert.common_name || (hasCert ? 'None presented' : 'NOT OBSERVED'), tag: cert.common_name ? 'OBSERVED' : 'NOT OBSERVED' },
    { label: 'Subject DN', value: cert.subject || (hasCert ? 'Not observable' : 'NOT OBSERVED'), tag: cert.subject ? 'OBSERVED' : 'NOT OBSERVED' },
    { label: 'Issuer DN', value: cert.issuer || (hasCert ? 'Not observable' : 'NOT OBSERVED'), tag: cert.issuer ? 'OBSERVED' : 'NOT OBSERVED' },
    { label: 'Expiration Status', value: hasCert ? (isCertExpired ? 'EXPIRED' : (isCertNotYetValid ? 'NOT YET VALID' : 'VALID')) : 'NOT OBSERVED', tag: !hasCert ? 'NOT OBSERVED' : (isCertExpired || isCertNotYetValid ? 'ISSUE DETECTED' : 'VERIFIED') },
    { label: 'Days Until Expiry', value: cert.days_until_expiry !== undefined ? `${cert.days_until_expiry} days` : 'NOT OBSERVED', tag: cert.days_until_expiry !== undefined ? (cert.days_until_expiry <= 0 ? 'ISSUE DETECTED' : 'VERIFIED') : 'NOT OBSERVED' },
    { label: 'Public Key & Size', value: hasCert ? `${cert.public_key_algorithm || 'RSA'} ${cert.public_key_length ? `${cert.public_key_length}-bit` : ''}`.trim() : 'NOT OBSERVED', tag: hasCert ? 'VERIFIED' : 'NOT OBSERVED' },
    { label: 'Signature Algorithm', value: hasCert ? (cert.signature_algorithm || 'Not observable') : 'NOT OBSERVED', tag: hasCert ? 'VERIFIED' : 'NOT OBSERVED' },
    { label: 'Hostname Match', value: cert.hostname_match !== undefined ? (cert.hostname_match ? 'VALID MATCH' : 'HOSTNAME MISMATCH') : (hasCert ? 'Not observable' : 'NOT OBSERVED'), tag: cert.hostname_match !== undefined ? (cert.hostname_match ? 'VERIFIED' : 'ISSUE DETECTED') : 'NOT OBSERVED' },
    { label: 'Self-Signed Status', value: cert.self_signed !== undefined ? (cert.self_signed ? 'TRUE (Self-Signed)' : 'FALSE (CA-Signed)') : (hasCert ? 'Not observable' : 'NOT OBSERVED'), tag: cert.self_signed ? 'ISSUE DETECTED' : (hasCert ? 'VERIFIED' : 'NOT OBSERVED') }
  ];

  // Specific 05 Certificate Chain Attributes
  const chainDetails = [
    { label: 'Chain Validation Status', value: hasCert ? (chainValidation.chain_complete && isChainValid ? 'VERIFIED' : (chainValidation.chain_status === 'INVALID' || chainValidation.chain_valid === false ? 'INVALID' : (chainValidation.chain_status === 'INCOMPLETE' ? 'INCOMPLETE' : 'INDETERMINATE'))) : 'NOT OBSERVED', tag: !hasCert ? 'NOT OBSERVED' : (chainValidation.chain_complete && isChainValid ? 'VERIFIED' : (chainValidation.chain_status === 'INCOMPLETE' ? 'INCOMPLETE' : 'ISSUE DETECTED')) },
    { label: 'Chain Completeness', value: chainValidation.chain_complete !== undefined ? (chainValidation.chain_complete ? 'COMPLETE' : 'INCOMPLETE') : (hasCert ? 'Not observable' : 'NOT OBSERVED'), tag: chainValidation.chain_complete ? 'VERIFIED' : (hasCert ? 'INCOMPLETE' : 'NOT OBSERVED') },
    { label: 'Trust Anchor / Root CA', value: chainValidation.trust_anchor || cert.issuer || (hasCert ? 'Not observed' : 'NOT OBSERVED'), tag: chainValidation.trust_anchor ? 'VERIFIED' : (hasCert ? 'OBSERVED' : 'NOT OBSERVED') },
    { label: 'Intermediate Certificates', value: chainValidation.intermediate_count !== undefined ? `${chainValidation.intermediate_count} intermediate(s)` : (hasCert ? '1 leaf certificate' : 'NOT OBSERVED'), tag: hasCert ? 'OBSERVED' : 'NOT OBSERVED' },
    { label: 'Chain Issues Detected', value: chainValidation.issues?.length > 0 ? chainValidation.issues.join('; ') : (hasCert ? 'Zero validation issues detected' : 'NOT OBSERVED'), tag: chainValidation.issues?.length > 0 ? 'ISSUE DETECTED' : (hasCert ? 'VERIFIED' : 'NOT OBSERVED') }
  ];

  return {
    filename,
    totalPackets,
    totalSessions,
    totalBytes,
    duration,
    sessions,
    s0,
    sessId,
    protocol,
    srcIp,
    srcPort,
    dstIp,
    dstPort,
    c2sBytes,
    s2cBytes,
    aiRisk,
    aiScoreNum,
    aiScore,
    aiLabel,
    aiConfidence,
    topRiskFactors,
    postureData,
    postureScore,
    postureRiskLevel,
    postureStatus,
    anomalyData,
    isAnomaly,
    anomalyStatus,
    anomalyScore,
    tls,
    isTlsObserved,
    cert,
    chainValidation,
    starttls,
    starttlsStatus,
    findingsList,
    critCount,
    highCount,
    medCount,
    lowCount,
    displayActions,
    pipelineStages,
    starttlsDetails,
    tlsDetails,
    certDetails,
    chainDetails
  };
}

/**
 * Downloads raw analysis JSON file with full forensic fidelity.
 */
export function exportJSON(captureData) {
  if (!captureData) return null;
  const ctx = extractCaptureReportContext(captureData);
  const filename = getReportFilename(captureData, 'json');

  const exportPayload = {
    filename: ctx.filename,
    sessions: ctx.sessions,
    metadata: {
      application: "SecureMailScope",
      version: "1.4",
      classification: "CONFIDENTIAL FORENSIC EVIDENCE",
      generated_at: new Date().toISOString(),
      target_filename: ctx.filename
    },
    executive_summary: {
      ai_risk_score: ctx.aiScoreNum,
      ai_risk_tier: ctx.aiLabel,
      ai_model: "CryptoRisk-RandomForestClassifier",
      ai_confidence: ctx.aiConfidence,
      security_posture: ctx.postureStatus,
      posture_score: ctx.postureScore,
      total_sessions: ctx.totalSessions,
      total_packets: ctx.totalPackets,
      protocol: ctx.protocol,
      isolation_forest_anomaly: ctx.anomalyStatus,
      anomaly_score: ctx.anomalyScore
    },
    sections: {
      "01_pcap_session": {
        session_id: ctx.sessId,
        protocol: ctx.protocol,
        source: `${ctx.srcIp}:${ctx.srcPort}`,
        destination: `${ctx.dstIp}:${ctx.dstPort}`,
        duration_seconds: ctx.duration,
        total_bytes: ctx.totalBytes,
        client_to_server_bytes: ctx.c2sBytes,
        server_to_client_bytes: ctx.s2cBytes
      },
      "02_starttls_analysis": ctx.starttlsDetails,
      "03_tls_analysis": ctx.tlsDetails,
      "04_certificate_analysis": ctx.certDetails,
      "05_certificate_chain": ctx.chainDetails,
      "06_security_findings": ctx.findingsList,
      "07_ai_risk_assessment": {
        score: ctx.aiScoreNum,
        label: ctx.aiLabel,
        confidence: ctx.aiConfidence,
        top_risk_factors: ctx.topRiskFactors,
        anomaly_detected: ctx.isAnomaly,
        anomaly_score: ctx.anomalyScore
      },
      "08_forensic_pipeline": ctx.pipelineStages,
      "09_recommendations": ctx.displayActions
    },
    raw_sessions: ctx.sessions
  };

  const jsonStr = JSON.stringify(exportPayload, null, 2);

  if (typeof document !== 'undefined') {
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }
  return jsonStr;
}

/**
 * Generates and downloads multi-sheet XLSX forensic workbook.
 */
export function exportXLSX(captureData) {
  if (!captureData) return null;
  const ctx = extractCaptureReportContext(captureData);
  const wb = XLSX.utils.book_new();

  // 1. Executive Summary Sheet
  const execSummary = [
    ["SecureMailScope - Enterprise SOC Forensic Workbook"],
    ["Generated At", new Date().toUTCString()],
    ["Target PCAP Filename", ctx.filename],
    ["Total Frames / Packets", ctx.totalPackets],
    ["Total Reconstructed Sessions", ctx.totalSessions],
    ["Protocol Evaluated", ctx.protocol],
    ["Overall AI Crypto Risk Score", `${ctx.aiScore} / 100`],
    ["Overall AI Crypto Risk Tier", ctx.aiLabel],
    ["AI Model Engine", "CryptoRisk-RandomForestClassifier (54 ML Features)"],
    ["Model Confidence", `${ctx.aiConfidence}%`],
    ["Security Posture Evaluation", ctx.postureStatus],
    ["Deterministic Posture Score", `${ctx.postureScore} / 100`],
    ["Total Security Findings", ctx.findingsList.length],
    ["Critical Severity Findings", ctx.critCount],
    ["High Severity Findings", ctx.highCount],
    ["Medium Severity Findings", ctx.medCount],
    ["Low Severity Findings", ctx.lowCount],
    ["Isolation Forest Anomaly Status", ctx.anomalyStatus],
    ["Isolation Forest Anomaly Score", ctx.anomalyScore]
  ];
  const wsExec = XLSX.utils.aoa_to_sheet(execSummary);
  XLSX.utils.book_append_sheet(wb, wsExec, "Executive Summary");

  // 2. 01 PCAP & Sessions Sheet
  const sessionsHeader = [
    "Session ID", "Protocol", "Confidence", "Source IP", "Source Port", 
    "Destination IP", "Destination Port", "Packets", "Client Bytes", "Server Bytes",
    "Security Posture", "Posture Score", "AI Risk Score", "AI Risk Tier"
  ];
  const sessionsData = [sessionsHeader];
  ctx.sessions.forEach(s => {
    const sScore = s.ai_risk?.score != null ? Number(s.ai_risk.score).toFixed(1) : (s.posture?.score ?? "N/A");
    const sLabel = getAiRiskTier(s.ai_risk);
    sessionsData.push([
      s.session_id || "N/A",
      s.protocol || "N/A",
      s.protocol_confidence || "HIGH",
      s.source_ip || "N/A",
      s.source_port ?? 0,
      s.destination_ip || "N/A",
      s.destination_port ?? 0,
      s.packet_count ?? "N/A",
      s.client_to_server_bytes ?? 0,
      s.server_to_client_bytes ?? 0,
      s.posture?.security_posture || ctx.postureStatus,
      s.posture?.score ?? ctx.postureScore,
      sScore,
      sLabel
    ]);
  });
  const wsSessions = XLSX.utils.aoa_to_sheet(sessionsData);
  XLSX.utils.book_append_sheet(wb, wsSessions, "01 PCAP & Sessions");

  // 3. 02 STARTTLS Analysis Sheet
  const starttlsHeader = ["Attribute", "Observed Value", "Forensic Interpretation"];
  const starttlsData = [starttlsHeader];
  ctx.starttlsDetails.forEach(d => {
    starttlsData.push([d.label, d.value, d.tag]);
  });
  const wsStarttls = XLSX.utils.aoa_to_sheet(starttlsData);
  XLSX.utils.book_append_sheet(wb, wsStarttls, "02 STARTTLS");

  // 4. 03 TLS Analysis Sheet
  const tlsHeader = [
    "Session ID", "TLS Observed", "Negotiated Version", "Cipher Suite", 
    "Key Exchange", "Perfect Forward Secrecy (PFS)", "Handshake Status", "Encrypted Payload Verified", "STARTTLS Status"
  ];
  const tlsData = [tlsHeader];
  ctx.sessions.forEach(s => {
    const t = s.tls || {};
    const isPfs = t.forward_secrecy;
    const pfsLabel = isPfs !== undefined ? (isPfs ? (t.ephemeral_key_exchange_verified ? "VERIFIED" : "INDICATED") : "DISABLED") : "Not Observable";
    tlsData.push([
      s.session_id || "N/A",
      t.detected ? "YES" : "NO",
      t.version || "Plaintext",
      t.cipher_suite || "None",
      t.key_exchange || "None",
      pfsLabel,
      t.handshake_status || (t.detected ? "COMPLETE" : "NOT OBSERVED"),
      t.encrypted_application_data_observed ? "VERIFIED" : "NOT OBSERVED",
      s.starttls?.status || "N/A"
    ]);
  });
  const wsTls = XLSX.utils.aoa_to_sheet(tlsData);
  XLSX.utils.book_append_sheet(wb, wsTls, "03 TLS Analysis");

  // 5. 04 Certificates Sheet
  const certHeader = [
    "Session ID", "Cert Present", "Common Name (CN)", "Subject", "Issuer", 
    "Expiration Status", "Days to Expiry", "Public Key", "Signature Algo", "Hostname Match", "Trust Validation"
  ];
  const certData = [certHeader];
  ctx.sessions.forEach(s => {
    const c = s.tls?.certificate || {};
    certData.push([
      s.session_id || "N/A",
      c.certificate_present || c.common_name ? "YES" : "NO",
      c.common_name || "None",
      c.subject || "None",
      c.issuer || "None",
      c.expiration_status || (c.expired ? "EXPIRED" : "VALID"),
      c.days_until_expiry ?? "N/A",
      `${c.public_key_algorithm || "RSA"} ${c.public_key_length ? `${c.public_key_length}-bit` : ""}`.trim(),
      c.signature_algorithm || "N/A",
      c.hostname_match !== undefined ? (c.hostname_match ? "MATCH" : "MISMATCH") : "N/A",
      c.trust_validation || (c.self_signed ? "SELF-SIGNED" : "VALID")
    ]);
  });
  const wsCert = XLSX.utils.aoa_to_sheet(certData);
  XLSX.utils.book_append_sheet(wb, wsCert, "04 Certificates");

  // 6. 05 Certificate Chain Sheet
  const chainHeader = ["Chain Property", "Observed Value", "Validation Status"];
  const chainData = [chainHeader];
  ctx.chainDetails.forEach(d => {
    chainData.push([d.label, d.value, d.tag]);
  });
  const wsChain = XLSX.utils.aoa_to_sheet(chainData);
  XLSX.utils.book_append_sheet(wb, wsChain, "05 Certificate Chain");

  // 7. 06 Security Findings Sheet
  const findingsHeader = ["Session ID", "Pipeline Stage", "Finding ID", "Severity", "Finding Title", "Technical Reason", "Remediation"];
  const findingsData = [findingsHeader];
  ctx.sessions.forEach(s => {
    (s.assessment?.findings || []).forEach(f => {
      const stage = getPipelineStageForFinding(f);
      findingsData.push([
        s.session_id || "N/A",
        `Stage ${stage.num} (${stage.name})`,
        f.finding_id || f.rule_id || "RULE",
        f.severity || "HIGH",
        f.title || "Security Finding",
        f.reason || f.description || "",
        f.recommendation || ""
      ]);
    });
  });
  if (findingsData.length === 1) {
    findingsData.push(["All", "Stage 07", "BASELINE", "SECURE", "Zero Security Findings", "Conforms to modern cryptographic baseline.", "Continue regular security telemetry monitoring."]);
  }
  const wsFindings = XLSX.utils.aoa_to_sheet(findingsData);
  XLSX.utils.book_append_sheet(wb, wsFindings, "06 Security Findings");

  // 8. 07 AI Risk Sheet
  const aiHeader = ["Metric", "Value", "Notes"];
  const aiData = [
    aiHeader,
    ["Model Architecture", "RandomForestClassifier (54 ML Features)", "Supervised tabular cryptanalysis"],
    ["Cryptographic Risk Score", `${ctx.aiScore} / 100`, ctx.aiLabel],
    ["Operational Risk Tier", ctx.aiLabel, `Threshold: ${ctx.aiScoreNum <= 20 ? '0-20 Low' : ctx.aiScoreNum <= 50 ? '21-50 Moderate' : ctx.aiScoreNum <= 80 ? '51-80 High' : '81-100 Critical'}`],
    ["Model Confidence", `${ctx.aiConfidence}%`, "Confidence score"],
    ["Isolation Forest Status", ctx.anomalyStatus, `Score: ${ctx.anomalyScore}`],
    ["Top Observed Risk Factors", ctx.topRiskFactors.map(f => typeof f === 'object' ? (f.label || f.feature) : f).join('; ') || "None", "Model feature contribution"]
  ];
  const wsAi = XLSX.utils.aoa_to_sheet(aiData);
  XLSX.utils.book_append_sheet(wb, wsAi, "07 AI Risk");

  // 9. 08 Forensic Pipeline Sheet
  const pipeHeader = ["Stage Number", "Pipeline Checkpoint", "Verification Status", "Observed Value", "Forensic Assessment"];
  const pipeData = [pipeHeader];
  ctx.pipelineStages.forEach(st => {
    pipeData.push([
      `Stage ${st.stepNum}`,
      st.name,
      st.status,
      st.label || "-",
      st.desc || "-"
    ]);
  });
  const wsPipe = XLSX.utils.aoa_to_sheet(pipeData);
  XLSX.utils.book_append_sheet(wb, wsPipe, "08 Forensic Pipeline");

  // 10. 09 Recommendations Sheet
  const remHeader = ["Priority", "Recommended Remediation Step", "Implementation Baseline"];
  const remData = [remHeader];
  ctx.displayActions.forEach((act, idx) => {
    remData.push([`Priority ${idx + 1}`, act, "RFC 8446 / NIST SP 800-52r2"]);
  });
  const wsRem = XLSX.utils.aoa_to_sheet(remData);
  XLSX.utils.book_append_sheet(wb, wsRem, "09 Recommendations");

  const filename = getReportFilename(captureData, 'xlsx');
  if (typeof document !== 'undefined') {
    XLSX.writeFile(wb, filename);
  }
  return wb;
}

/**
 * Generates and downloads a multi-page PDF forensic investigation report
 * matching the SecureMailScope Enterprise SOC visual design language.
 */
export function exportPDF(captureData) {
  if (!captureData) return null;
  const ctx = extractCaptureReportContext(captureData);
  const doc = new jsPDF('p', 'pt', 'a4');
  const filename = getReportFilename(captureData, 'pdf');

  // Exact SOC Design Tokens from web app
  const navyHeader = [15, 23, 42];       // #0F172A (Deep Slate Header)
  const brandBlue = [0, 101, 145];       // #006591 (SecureMailScope Brand Blue)
  const canvasBg = [244, 247, 251];      // #F4F7FB (Page Canvas)
  const cardBg = [255, 255, 255];        // #FFFFFF (Card Surface)
  const cardBorder = [226, 232, 240];    // #E2E8F0 (Border Line)
  const textPrimary = [11, 28, 48];      // #0B1C30 (Primary Text)
  const textMuted = [100, 116, 139];     // #64748B (Secondary Text)
  const emeraldGreen = [16, 185, 129];   // #10B981 (Verified / Secure)
  const amberWarning = [245, 158, 11];   // #F59E0B (Indeterminate / Warning)
  const roseCritical = [220, 38, 38];    // #DC2626 (Issue / Critical)

  const pageWidth = 595.28;
  const pageHeight = 841.89;
  const margin = 32;
  const contentWidth = pageWidth - margin * 2;

  // Function to fill canvas background on current page
  const paintCanvasBackground = () => {
    doc.setFillColor(...canvasBg);
    doc.rect(0, 0, pageWidth, pageHeight, 'F');
  };

  // Paint Page 1 canvas background
  paintCanvasBackground();

  // Header Banner Card
  doc.setFillColor(...navyHeader);
  doc.roundedRect(margin, 14, contentWidth, 64, 8, 8, 'F');
  doc.setDrawColor(...cardBorder);
  doc.setLineWidth(0.5);
  doc.roundedRect(margin, 14, contentWidth, 64, 8, 8, 'S');

  // Vector Brand Emblem
  doc.setFillColor(30, 41, 59);
  doc.roundedRect(margin + 12, 24, 34, 34, 6, 6, 'F');
  doc.setDrawColor(99, 102, 241);
  doc.setLineWidth(1.25);
  doc.line(margin + 20, 37, margin + 29, 44);
  doc.line(margin + 29, 44, margin + 38, 37);
  doc.setFillColor(...emeraldGreen);
  doc.circle(margin + 29, 44, 2.5, 'FD');

  // Brand Title & Version Pill
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(15);
  doc.setTextColor(255, 255, 255);
  doc.text("SecureMailScope", margin + 54, 40);

  doc.setFillColor(30, 41, 59);
  doc.roundedRect(margin + 180, 29, 28, 14, 3, 3, 'F');
  doc.setFontSize(8);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(203, 213, 225);
  doc.text("v1.4", margin + 186, 39);

  // Header Subtitle
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(148, 163, 184);
  doc.text("ENTERPRISE SOC FORENSICS • CRYPTOGRAPHIC SECURITY POSTURE REPORT", margin + 54, 54);

  // Top Right: SOC Workstation & Target File
  doc.setFillColor(30, 41, 59);
  doc.roundedRect(pageWidth - margin - 150, 22, 140, 18, 4, 4, 'F');
  doc.setFillColor(...emeraldGreen);
  doc.circle(pageWidth - margin - 141, 31, 3, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(241, 245, 249);
  doc.text("SOC WORKSTATION ACTIVE", pageWidth - margin - 133, 34);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(148, 163, 184);
  doc.text(`Capture: ${ctx.filename}`, pageWidth - margin - 150, 49);
  doc.text(`Time: ${new Date().toISOString().replace('T', ' ').slice(0, 19)} UTC`, pageWidth - margin - 150, 60);

  let currentY = 88;

  // =========================================================================
  // EXECUTIVE SUMMARY / KPI CARDS (4 Cards Grid)
  // =========================================================================
  const cardGap = 8;
  const cardCount = 4;
  const cardW = (contentWidth - cardGap * (cardCount - 1)) / cardCount;
  const cardH = 56;

  const drawKpiCard = (x, y, w, h, label, value, subtext, tagColor, tagText) => {
    doc.setFillColor(...cardBg);
    doc.roundedRect(x, y, w, h, 6, 6, 'F');
    doc.setDrawColor(...cardBorder);
    doc.setLineWidth(0.75);
    doc.roundedRect(x, y, w, h, 6, 6, 'S');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(...textMuted);
    doc.text(label.toUpperCase(), x + 8, y + 13);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(...textPrimary);
    doc.text(String(value), x + 8, y + 31);

    if (subtext) {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7);
      doc.setTextColor(...textMuted);
      doc.text(subtext, x + 8, y + 46);
    }

    if (tagText) {
      doc.setFillColor(...tagColor);
      const tagW = doc.getTextWidth(tagText) + 8;
      doc.roundedRect(x + w - tagW - 6, y + 6, tagW, 12, 3, 3, 'F');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.5);
      doc.setTextColor(255, 255, 255);
      doc.text(tagText, x + w - tagW - 2, y + 15);
    }
  };

  const riskTagColor = ctx.aiLabel === 'CRITICAL' || ctx.aiLabel === 'HIGH' ? roseCritical : ctx.aiLabel === 'MODERATE' ? amberWarning : emeraldGreen;
  const postureTagColor = ctx.postureStatus === 'SECURE' ? emeraldGreen : ctx.postureStatus === 'COMPROMISED' ? roseCritical : amberWarning;

  // 1. AI Risk Score
  drawKpiCard(margin, currentY, cardW, cardH, "AI Risk Score", `${ctx.aiScore} / 100`, `Confidence: ${ctx.aiConfidence}%`, riskTagColor, ctx.aiLabel);

  // 2. Security Posture
  drawKpiCard(margin + (cardW + cardGap), currentY, cardW, cardH, "Security Posture", ctx.postureStatus, `Score: ${ctx.postureScore} / 100`, postureTagColor, ctx.postureRiskLevel);

  // 3. Sessions Analyzed
  drawKpiCard(margin + (cardW + cardGap) * 2, currentY, cardW, cardH, "Sessions Analyzed", `${ctx.totalSessions} Session${ctx.totalSessions === 1 ? '' : 's'}`, `${ctx.totalPackets.toLocaleString()} Frames`, [71, 85, 105], "PASSIVE");

  // 4. Protocol & TLS
  drawKpiCard(margin + (cardW + cardGap) * 3, currentY, cardW, cardH, "Protocol Telemetry", ctx.protocol, `Port ${ctx.dstPort} • ${ctx.isTlsObserved ? ctx.tls.version || 'TLS' : 'Plaintext'}`, ctx.isTlsObserved ? emeraldGreen : roseCritical, ctx.isTlsObserved ? "ENCRYPTED" : "PLAINTEXT");

  currentY += cardH + 16;

  // Page break check helper
  const checkPageBreak = (neededHeight) => {
    if (currentY + neededHeight > pageHeight - 50) {
      doc.addPage();
      paintCanvasBackground();
      // Continuation Header
      doc.setFillColor(...navyHeader);
      doc.rect(0, 0, pageWidth, 28, 'F');
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(8);
      doc.setTextColor(255, 255, 255);
      doc.text(`SecureMailScope • SOC Forensic Report • ${ctx.filename}`, margin, 18);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(148, 163, 184);
      doc.text("CONFIDENTIAL FORENSIC EVIDENCE", pageWidth - margin - 150, 18);
      currentY = 44;
    }
  };

  // Section Header helper
  const drawSectionHeader = (numberStr, titleStr, badgeStr) => {
    doc.setFillColor(...brandBlue);
    doc.rect(margin, currentY, 3.5, 13, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10);
    doc.setTextColor(...textPrimary);
    doc.text(`${numberStr}  ${titleStr.toUpperCase()}`, margin + 8, currentY + 10);
    if (badgeStr) {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(...textMuted);
      doc.text(badgeStr, pageWidth - margin, currentY + 10, { align: 'right' });
    }
    currentY += 16;
  };

  // =========================================================================
  // SECTION 01: PCAP & SESSION
  // =========================================================================
  checkPageBreak(110);
  drawSectionHeader("01", "PCAP & Session Telemetry", `${ctx.totalSessions} Session(s) Observed`);

  const sessionTableRows = ctx.sessions.map(s => {
    const sScore = s.ai_risk?.score != null ? Number(s.ai_risk.score).toFixed(1) : (s.posture?.score ?? "N/A");
    const sLabel = getAiRiskTier(s.ai_risk);
    return [
      s.session_id || "TCP-001",
      s.protocol || "UNKNOWN",
      `${s.source_ip}:${s.source_port}`,
      `${s.destination_ip}:${s.destination_port}`,
      s.tls?.version || (s.tls?.detected ? "TLS" : "Plaintext"),
      s.starttls?.status || "N/A",
      `${s.posture?.score ?? ctx.postureScore}/100`,
      `${sScore} [${sLabel}]`,
      s.posture?.security_posture || ctx.postureStatus
    ];
  });

  autoTable(doc, {
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'plain',
    head: [["Session ID", "Protocol", "Client Source", "Server Destination", "TLS Version", "STARTTLS", "Posture", "AI Risk", "Status"]],
    body: sessionTableRows,
    headStyles: {
      fillColor: [248, 250, 252],
      textColor: [71, 85, 105],
      fontSize: 7.5,
      fontStyle: 'bold',
      cellPadding: 4,
      lineWidth: 0.5,
      lineColor: cardBorder
    },
    bodyStyles: {
      fontSize: 7.5,
      textColor: textPrimary,
      cellPadding: 4,
      lineWidth: 0.5,
      lineColor: cardBorder
    },
    columnStyles: {
      0: { cellWidth: 48, fontStyle: 'bold' },
      1: { cellWidth: 44, fontStyle: 'bold' },
      2: { cellWidth: 94 },
      3: { cellWidth: 94 },
      4: { cellWidth: 54 },
      5: { cellWidth: 54 },
      6: { cellWidth: 44 },
      7: { cellWidth: 48, fontStyle: 'bold' },
      8: { cellWidth: 'auto', fontStyle: 'bold' }
    }
  });

  currentY = doc.lastAutoTable.finalY + 16;

  // =========================================================================
  // SECTION 02: STARTTLS ANALYSIS
  // =========================================================================
  checkPageBreak(90);
  drawSectionHeader("02", "STARTTLS Analysis", ctx.starttlsStatus);

  const starttlsRows = [
    ["STARTTLS Negotiation Status", ctx.starttls.status || (ctx.isImplicitTlsPort ? "DIRECT_TLS" : "NOT_OBSERVED"), "Transport Mode", ctx.isImplicitTlsPort ? "Direct TLS (Implicit SSL)" : "Explicit STARTTLS Upgrade"],
    ["Upgrade Advertised / Supported", ctx.starttls.upgrade_supported ? "YES" : "NO", "Upgrade Requested", ctx.starttls.upgrade_requested ? "YES" : "NO"],
    ["Upgrade Accepted", ctx.starttls.upgrade_accepted ? "YES" : "NO", "TLS Transition Observed", ctx.starttls.tls_transition_observed ? "YES" : "NO"]
  ];

  autoTable(doc, {
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'plain',
    body: starttlsRows,
    bodyStyles: {
      fontSize: 7.5,
      textColor: textPrimary,
      cellPadding: 4,
      lineWidth: 0.5,
      lineColor: cardBorder
    },
    columnStyles: {
      0: { cellWidth: 140, fontStyle: 'bold', fillColor: [248, 250, 252] },
      1: { cellWidth: 125 },
      2: { cellWidth: 140, fontStyle: 'bold', fillColor: [248, 250, 252] },
      3: { cellWidth: 'auto' }
    }
  });

  currentY = doc.lastAutoTable.finalY + 16;

  // =========================================================================
  // SECTION 03: TLS ANALYSIS
  // =========================================================================
  checkPageBreak(110);
  drawSectionHeader("03", "TLS Analysis", ctx.isTlsObserved ? ctx.tls.version || "TLS" : "Plaintext");

  const tlsRows = ctx.sessions.map(s => {
    const t = s.tls || {};
    const isPfs = t.forward_secrecy;
    const pfsLabel = isPfs !== undefined ? (isPfs ? (t.ephemeral_key_exchange_verified ? "Verified" : "Indicated") : "No PFS") : "N/A";

    return [
      s.session_id || "TCP-001",
      t.version || "Plaintext",
      t.cipher_suite || "None",
      t.key_exchange || "None",
      pfsLabel,
      t.handshake_status || (t.detected ? "Complete" : "Not Observed"),
      t.encrypted_application_data_observed ? "Verified" : "Not Observed"
    ];
  });

  autoTable(doc, {
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'plain',
    head: [["Session", "TLS Version", "Negotiated Cipher Suite", "Key Exchange", "PFS", "Handshake", "Encrypted Data"]],
    body: tlsRows,
    headStyles: {
      fillColor: [248, 250, 252],
      textColor: [71, 85, 105],
      fontSize: 7.5,
      fontStyle: 'bold',
      cellPadding: 4,
      lineWidth: 0.5,
      lineColor: cardBorder
    },
    bodyStyles: {
      fontSize: 7.5,
      textColor: textPrimary,
      cellPadding: 4,
      lineWidth: 0.5,
      lineColor: cardBorder
    },
    columnStyles: {
      0: { cellWidth: 46, fontStyle: 'bold' },
      1: { cellWidth: 55 },
      2: { cellWidth: 160 },
      3: { cellWidth: 65 },
      4: { cellWidth: 60 },
      5: { cellWidth: 65 },
      6: { cellWidth: 'auto' }
    }
  });

  currentY = doc.lastAutoTable.finalY + 16;

  // =========================================================================
  // SECTION 04: CERTIFICATE ANALYSIS
  // =========================================================================
  checkPageBreak(100);
  drawSectionHeader("04", "Certificate Analysis", ctx.cert.common_name || "Leaf Certificate");

  const certRows = [
    ["Common Name (CN)", ctx.cert.common_name || "Not Presented", "Subject DN", ctx.cert.subject || "Not Observable"],
    ["Issuer Organization", ctx.cert.issuer || "Not Observable", "Expiration Status", ctx.cert.expiration_status || (ctx.cert.expired ? "EXPIRED" : "VALID")],
    ["Public Key Algorithm", `${ctx.cert.public_key_algorithm || "RSA"} ${ctx.cert.public_key_length ? `${ctx.cert.public_key_length}-bit` : ""}`.trim(), "Signature Algorithm", ctx.cert.signature_algorithm || "Not Observable"],
    ["Hostname Validation", ctx.cert.hostname_match !== undefined ? (ctx.cert.hostname_match ? "VALID MATCH" : "HOSTNAME MISMATCH") : "Not Observable", "Self-Signed Status", ctx.cert.self_signed ? "TRUE (Self-Signed)" : "FALSE (CA-Signed)"]
  ];

  autoTable(doc, {
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'plain',
    body: certRows,
    bodyStyles: {
      fontSize: 7.5,
      textColor: textPrimary,
      cellPadding: 4,
      lineWidth: 0.5,
      lineColor: cardBorder
    },
    columnStyles: {
      0: { cellWidth: 120, fontStyle: 'bold', fillColor: [248, 250, 252] },
      1: { cellWidth: 145 },
      2: { cellWidth: 110, fontStyle: 'bold', fillColor: [248, 250, 252] },
      3: { cellWidth: 'auto' }
    }
  });

  currentY = doc.lastAutoTable.finalY + 16;

  // =========================================================================
  // SECTION 05: CERTIFICATE CHAIN
  // =========================================================================
  checkPageBreak(80);
  drawSectionHeader("05", "Certificate Chain Validation", ctx.chainValidation.chain_valid ? "Chain Verified" : "Chain Incomplete");

  const chainRows = [
    ["Chain Validation Status", ctx.chainValidation.chain_complete && ctx.chainValidation.chain_valid ? "CHAIN VERIFIED" : (ctx.chainValidation.chain_status || "INCOMPLETE"), "Chain Completeness", ctx.chainValidation.chain_complete ? "COMPLETE" : "INCOMPLETE"],
    ["Trust Anchor / Root CA", ctx.chainValidation.trust_anchor || ctx.cert.issuer || "Not Observable", "Intermediate Certs", ctx.chainValidation.intermediate_count !== undefined ? `${ctx.chainValidation.intermediate_count} intermediate(s)` : (ctx.hasCert ? "1 leaf certificate" : "None")],
    ["Validation Issues", ctx.chainValidation.issues?.length > 0 ? ctx.chainValidation.issues.join('; ') : "Zero trust chain issues detected", "SAN Verification", ctx.cert.subject_alternative_names?.join(', ') || ctx.cert.common_name || "None"]
  ];

  autoTable(doc, {
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'plain',
    body: chainRows,
    bodyStyles: {
      fontSize: 7.5,
      textColor: textPrimary,
      cellPadding: 4,
      lineWidth: 0.5,
      lineColor: cardBorder
    },
    columnStyles: {
      0: { cellWidth: 120, fontStyle: 'bold', fillColor: [248, 250, 252] },
      1: { cellWidth: 145 },
      2: { cellWidth: 110, fontStyle: 'bold', fillColor: [248, 250, 252] },
      3: { cellWidth: 'auto' }
    }
  });

  currentY = doc.lastAutoTable.finalY + 16;

  // =========================================================================
  // SECTION 06: SECURITY FINDINGS
  // =========================================================================
  checkPageBreak(110);
  drawSectionHeader("06", "Security Findings", `${ctx.findingsList.length} Finding(s) Detected`);

  const findingsRows = [];
  ctx.findingsList.forEach(f => {
    findingsRows.push([
      `Stage ${f.stage.num}`,
      f.severity,
      f.title,
      f.reason,
      f.recommendation || "Remediate per RFC 8446 baseline."
    ]);
  });

  if (findingsRows.length === 0) {
    findingsRows.push(["Stage 07", "SECURE", "Zero Security Findings", "Cryptographic baseline satisfied. All observed parameters conform to standard policy.", "Maintain modern TLS 1.2+ configuration."]);
  }

  autoTable(doc, {
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'plain',
    head: [["Stage", "Severity", "Finding Title", "Technical Reason", "Actionable Recommendation"]],
    body: findingsRows,
    headStyles: {
      fillColor: [248, 250, 252],
      textColor: [71, 85, 105],
      fontSize: 7.5,
      fontStyle: 'bold',
      cellPadding: 4,
      lineWidth: 0.5,
      lineColor: cardBorder
    },
    bodyStyles: {
      fontSize: 7.5,
      textColor: textPrimary,
      cellPadding: 4,
      lineWidth: 0.5,
      lineColor: cardBorder
    },
    columnStyles: {
      0: { cellWidth: 44, fontStyle: 'bold', textColor: brandBlue },
      1: { cellWidth: 54, fontStyle: 'bold' },
      2: { cellWidth: 104, fontStyle: 'bold' },
      3: { cellWidth: 158 },
      4: { cellWidth: 'auto' }
    },
    didParseCell: function(data) {
      if (data.section === 'body' && data.column.index === 1) {
        const sev = String(data.cell.raw).toUpperCase();
        if (sev === 'CRITICAL') {
          data.cell.styles.textColor = [153, 27, 27];
          data.cell.styles.fillColor = [254, 226, 226];
        } else if (sev === 'HIGH') {
          data.cell.styles.textColor = [154, 52, 18];
          data.cell.styles.fillColor = [255, 237, 213];
        } else if (sev === 'MEDIUM') {
          data.cell.styles.textColor = [146, 64, 14];
          data.cell.styles.fillColor = [254, 243, 199];
        } else if (sev === 'SECURE' || sev === 'PASS' || sev === 'LOW') {
          data.cell.styles.textColor = [22, 101, 52];
          data.cell.styles.fillColor = [220, 252, 231];
        }
      }
    }
  });

  currentY = doc.lastAutoTable.finalY + 16;

  // =========================================================================
  // SECTION 07: AI RISK ASSESSMENT
  // =========================================================================
  checkPageBreak(90);
  drawSectionHeader("07", "AI Risk Assessment", "Whole-Session Random Forest");

  const aiSummaryRows = [
    ["Model Architecture", "RandomForestClassifier (54 ML Features)", "Cryptographic Risk Score", `${ctx.aiScore} / 100 [${ctx.aiLabel}]`],
    ["Model Classification Confidence", `${ctx.aiConfidence}%`, "Isolation Forest Anomaly", `${ctx.anomalyStatus} (Score: ${ctx.anomalyScore})`],
    ["Top Observed Risk Factors", ctx.topRiskFactors.map(f => typeof f === 'object' ? (f.label || f.feature) : f).join('; ') || "Conforms to modern cryptographic baseline.", "Argmax Model Class", ctx.aiRisk.model_predicted_class || ctx.aiLabel]
  ];

  autoTable(doc, {
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'plain',
    body: aiSummaryRows,
    bodyStyles: {
      fontSize: 7.5,
      textColor: textPrimary,
      cellPadding: 4,
      lineWidth: 0.5,
      lineColor: cardBorder
    },
    columnStyles: {
      0: { cellWidth: 120, fontStyle: 'bold', fillColor: [248, 250, 252] },
      1: { cellWidth: 142 },
      2: { cellWidth: 110, fontStyle: 'bold', fillColor: [248, 250, 252] },
      3: { cellWidth: 'auto' }
    }
  });

  currentY = doc.lastAutoTable.finalY + 16;

  // =========================================================================
  // SECTION 08: FORENSIC PIPELINE
  // =========================================================================
  checkPageBreak(150);
  drawSectionHeader("08", "Forensic Pipeline", "Stages 01–09 Checkpoint Matrix");

  const pipeRows = ctx.pipelineStages.map(st => {
    return [
      `Stage ${st.stepNum}`,
      st.name,
      st.status,
      st.label || "-",
      st.desc || "-"
    ];
  });

  autoTable(doc, {
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'plain',
    head: [["Stage", "Pipeline Checkpoint", "Status", "Observed Value", "Forensic Evidence & Findings"]],
    body: pipeRows,
    headStyles: {
      fillColor: [248, 250, 252],
      textColor: [71, 85, 105],
      fontSize: 7.5,
      fontStyle: 'bold',
      cellPadding: 4,
      lineWidth: 0.5,
      lineColor: cardBorder
    },
    bodyStyles: {
      fontSize: 7.5,
      textColor: textPrimary,
      cellPadding: 4,
      lineWidth: 0.5,
      lineColor: cardBorder
    },
    columnStyles: {
      0: { cellWidth: 46, fontStyle: 'bold', textColor: brandBlue },
      1: { cellWidth: 118, fontStyle: 'bold' },
      2: { cellWidth: 68, fontStyle: 'bold' },
      3: { cellWidth: 84, fontStyle: 'bold' },
      4: { cellWidth: 'auto' }
    },
    didParseCell: function(data) {
      if (data.section === 'body' && data.column.index === 2) {
        const val = data.cell.raw;
        if (val === 'VERIFIED' || val === 'SECURE') {
          data.cell.styles.textColor = emeraldGreen;
        } else if (val === 'INDETERMINATE' || val === 'WARNING') {
          data.cell.styles.textColor = amberWarning;
        } else {
          data.cell.styles.textColor = roseCritical;
        }
      }
    }
  });

  currentY = doc.lastAutoTable.finalY + 16;

  // =========================================================================
  // SECTION 09: RECOMMENDATIONS
  // =========================================================================
  checkPageBreak(80);
  drawSectionHeader("09", "Recommendations", `${ctx.displayActions.length} Action(s)`);

  const recRows = ctx.displayActions.map((act, idx) => [
    `#${idx + 1}`,
    act
  ]);

  autoTable(doc, {
    startY: currentY,
    margin: { left: margin, right: margin },
    theme: 'plain',
    body: recRows,
    bodyStyles: {
      fontSize: 8,
      textColor: textPrimary,
      cellPadding: 5,
      lineWidth: 0.5,
      lineColor: cardBorder
    },
    columnStyles: {
      0: { cellWidth: 30, fontStyle: 'bold', textColor: brandBlue, fillColor: [241, 245, 249] },
      1: { cellWidth: 'auto' }
    }
  });

  // Footer on all pages
  const totalPages = doc.internal.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);
    doc.setDrawColor(...cardBorder);
    doc.setLineWidth(0.5);
    doc.line(margin, pageHeight - 24, pageWidth - margin, pageHeight - 24);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(...textMuted);
    doc.text(`SecureMailScope Automated Forensics • Capture: ${ctx.filename}`, margin, pageHeight - 13);
    doc.text(`Page ${i} of ${totalPages}`, pageWidth / 2 - 12, pageHeight - 13);
    doc.setFont('helvetica', 'bold');
    doc.text("CONFIDENTIAL FORENSIC EVIDENCE", pageWidth - margin - 150, pageHeight - 13);
  }

  if (typeof document !== 'undefined') {
    doc.save(filename);
  }
  return doc;
}

/**
 * Generates and downloads a standalone HTML forensic investigation report
 * visually matching the SecureMailScope Enterprise SOC Web UI (including light/dark theme switch).
 */
export function exportHTML(captureData) {
  if (!captureData) return null;
  const ctx = extractCaptureReportContext(captureData);
  const filename = getReportFilename(captureData, 'html');
  const generatedAt = new Date().toUTCString();

  const riskGaugeColor = ctx.aiLabel === 'CRITICAL' || ctx.aiLabel === 'HIGH' ? '#dc2626' : ctx.aiLabel === 'MODERATE' ? '#d97706' : '#059669';
  const riskBadgeClass = ctx.aiLabel === 'CRITICAL' || ctx.aiLabel === 'HIGH' ? 'badge-critical' : ctx.aiLabel === 'MODERATE' ? 'badge-warning' : 'badge-secure';
  const postureBadgeClass = ctx.postureStatus === 'SECURE' ? 'badge-secure' : ctx.postureStatus === 'COMPROMISED' ? 'badge-critical' : 'badge-warning';

  const circumference = 339.29;
  const clampedScore = Math.max(0, Math.min(100, ctx.aiScoreNum));
  const dashOffset = Number((circumference - (circumference * clampedScore) / 100).toFixed(2));

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureMailScope Forensic Report - ${escapeHtml(ctx.filename)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-app: #F4F7FB;
      --bg-surface: #ffffff;
      --bg-card: #ffffff;
      --bg-card-subtle: #F8FAFC;
      --bg-secondary: #F1F5F9;
      --border-main: #E2E8F0;
      --border-subtle: #edf2f7;
      --text-primary: #0b1c30;
      --text-secondary: #475569;
      --text-muted: #64748b;
      --primary-brand: #006591;
      
      --color-secure: #10b981;
      --color-secure-bg: #ecfdf5;
      --color-secure-border: #a7f3d0;
      --color-secure-text: #047857;

      --color-warning: #f59e0b;
      --color-warning-bg: #fffbeb;
      --color-warning-border: #fde68a;
      --color-warning-text: #b45309;

      --color-danger: #dc2626;
      --color-danger-bg: #fef2f2;
      --color-danger-border: #fca5a5;
      --color-danger-text: #b91c1c;

      --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      --font-mono: 'JetBrains Mono', monospace;
      --shadow-card: 0 1px 3px rgba(15, 23, 42, 0.05);
    }

    html.dark {
      --bg-app: #0b1320;
      --bg-surface: #0f172a;
      --bg-card: #0f172a;
      --bg-card-subtle: #1e293b;
      --bg-secondary: #172033;
      --border-main: #1e293b;
      --border-subtle: #334155;
      --text-primary: #f8fafc;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --primary-brand: #38bdf8;
      
      --color-secure-bg: rgba(16, 185, 129, 0.15);
      --color-secure-border: rgba(16, 185, 129, 0.35);
      --color-secure-text: #34d399;

      --color-warning-bg: rgba(245, 158, 11, 0.15);
      --color-warning-border: rgba(245, 158, 11, 0.35);
      --color-warning-text: #fbbf24;

      --color-danger-bg: rgba(244, 63, 94, 0.15);
      --color-danger-border: rgba(244, 63, 94, 0.35);
      --color-danger-text: #fb7185;

      --shadow-card: 0 1px 3px rgba(0, 0, 0, 0.3);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-app);
      color: var(--text-primary);
      font-family: var(--font-sans);
      font-size: 13px;
      line-height: 1.5;
      padding: 24px 16px;
      transition: background-color 150ms ease, color 150ms ease;
    }

    .report-container {
      max-width: 1120px;
      margin: 0 auto;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }

    /* Top App Bar Header */
    .top-app-bar {
      background: var(--bg-surface);
      border: 1px solid var(--border-main);
      border-radius: 12px;
      padding: 16px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-shadow: var(--shadow-card);
      flex-wrap: wrap;
      gap: 12px;
    }
    .brand-group {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .brand-emblem {
      width: 36px;
      height: 36px;
      border-radius: 8px;
      background: #0F172A;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 1px 2px rgba(0,0,0,0.2);
    }
    .brand-title {
      font-size: 16px;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .version-pill {
      font-family: var(--font-sans);
      font-size: 11px;
      font-weight: 600;
      padding: 1px 6px;
      border-radius: 4px;
      background: var(--bg-card-subtle);
      border: 1px solid var(--border-main);
      color: var(--text-secondary);
    }
    .brand-sub {
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 1px;
    }
    .top-controls {
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .workstation-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 6px;
      background: var(--bg-card-subtle);
      border: 1px solid var(--border-main);
      font-family: var(--font-sans);
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-secondary);
    }
    .dot-green {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: #10b981;
    }
    .theme-btn {
      background: var(--bg-card-subtle);
      border: 1px solid var(--border-main);
      color: var(--text-primary);
      padding: 6px 12px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .theme-btn:hover {
      background: var(--border-main);
    }

    /* Cards / Surfaces */
    .card {
      background: var(--bg-card);
      border: 1px solid var(--border-main);
      border-radius: 12px;
      padding: 20px 24px;
      box-shadow: var(--shadow-card);
    }
    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border-subtle);
      padding-bottom: 12px;
      margin-bottom: 16px;
    }
    .card-title {
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-primary);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .card-title::before {
      content: '';
      display: inline-block;
      width: 3px;
      height: 12px;
      background: var(--primary-brand);
      border-radius: 2px;
    }

    /* Hero / KPI Grid */
    .hero-grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 16px;
    }
    @media (min-width: 900px) {
      .hero-grid {
        grid-template-columns: 320px 1fr;
      }
    }
    .risk-dial-card {
      background: var(--bg-card);
      border: 1px solid var(--border-main);
      border-radius: 12px;
      padding: 24px;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      box-shadow: var(--shadow-card);
      text-align: center;
    }
    .dial-svg-box {
      position: relative;
      width: 130px;
      height: 130px;
      margin-bottom: 12px;
    }
    .dial-svg {
      width: 100%;
      height: 100%;
      transform: rotate(-90deg);
    }
    .dial-center {
      position: absolute;
      inset: 0;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
    }
    .dial-score {
      font-family: var(--font-sans);
      font-size: 32px;
      font-weight: 700;
      font-feature-settings: 'tnum';
      font-variant-numeric: tabular-nums;
      line-height: 1;
      color: var(--text-primary);
    }
    .dial-max {
      font-family: var(--font-sans);
      font-size: 11px;
      font-weight: 500;
      color: var(--text-muted);
      margin-top: 2px;
    }
    .kpi-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
    }
    .kpi-cell {
      background: var(--bg-card-subtle);
      border: 1px solid var(--border-main);
      border-radius: 10px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .kpi-label {
      font-size: 10px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-muted);
      margin-bottom: 8px;
    }
    .kpi-value {
      font-family: var(--font-sans);
      font-size: 24px;
      font-weight: 700;
      font-feature-settings: 'tnum';
      font-variant-numeric: tabular-nums;
      color: var(--text-primary);
      line-height: 1.1;
    }
    .kpi-sub {
      font-size: 11px;
      color: var(--text-muted);
      margin-top: 4px;
      font-family: var(--font-sans);
      font-weight: 400;
    }

    /* Forensic Pipeline 9-stage Flow */
    .pipeline-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
      gap: 8px;
      margin-top: 8px;
    }
    .pipe-node {
      background: var(--bg-card-subtle);
      border: 1px solid var(--border-main);
      border-radius: 8px;
      padding: 10px 8px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      min-height: 70px;
      border-left-width: 3px;
    }
    .pipe-node.node-green { border-left-color: #10b981; }
    .pipe-node.node-amber { border-left-color: #f59e0b; }
    .pipe-node.node-red { border-left-color: #dc2626; }
    .pipe-node-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 4px;
    }
    .pipe-num {
      font-family: var(--font-sans);
      font-size: 9px;
      font-weight: 600;
      color: var(--text-muted);
    }
    .pipe-status {
      font-family: var(--font-sans);
      font-size: 8.5px;
      font-weight: 600;
      text-transform: uppercase;
    }
    .status-green { color: var(--color-secure-text); }
    .status-amber { color: var(--color-warning-text); }
    .status-red { color: var(--color-danger-text); }
    .pipe-name {
      font-size: 11px;
      font-weight: 700;
      color: var(--text-primary);
      line-height: 1.2;
    }
    .pipe-desc {
      font-family: var(--font-sans);
      font-size: 9px;
      font-weight: 400;
      color: var(--text-muted);
      margin-top: 4px;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    /* Tables */
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }
    th, td {
      padding: 10px 12px;
      text-align: left;
      border-bottom: 1px solid var(--border-subtle);
    }
    th {
      background: var(--bg-card-subtle);
      font-size: 10.5px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-secondary);
      border-top: 1px solid var(--border-main);
      border-bottom: 1px solid var(--border-main);
    }
    td code, td .mono {
      font-family: var(--font-mono);
      font-size: 11.5px;
    }

    /* Badges & Chips */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 2px 8px;
      border-radius: 4px;
      font-family: var(--font-sans);
      font-size: 10.5px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      border: 1px solid transparent;
    }
    .badge-secure {
      background: var(--color-secure-bg);
      color: var(--color-secure-text);
      border-color: var(--color-secure-border);
    }
    .badge-warning {
      background: var(--color-warning-bg);
      color: var(--color-warning-text);
      border-color: var(--color-warning-border);
    }
    .badge-critical {
      background: var(--color-danger-bg);
      color: var(--color-danger-text);
      border-color: var(--color-danger-border);
    }

    /* Evidence Chips */
    .chip-evidence {
      padding: 2px 6px;
      border-radius: 4px;
      font-family: var(--font-sans);
      font-size: 9px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      border: 1px solid var(--border-main);
      background: var(--bg-card-subtle);
      color: var(--text-muted);
    }
    .chip-verified {
      background: var(--color-secure-bg);
      color: var(--color-secure-text);
      border-color: var(--color-secure-border);
    }
    .chip-issue {
      background: var(--color-danger-bg);
      color: var(--color-danger-text);
      border-color: var(--color-danger-border);
    }
    .chip-observed {
      background: rgba(2, 132, 199, 0.12);
      color: #0284c7;
      border-color: rgba(2, 132, 199, 0.3);
    }
    .chip-incomplete {
      background: var(--color-warning-bg);
      color: var(--color-warning-text);
      border-color: var(--color-warning-border);
    }

    /* Technical Details Grid */
    .tech-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 12px;
    }
    .tech-cell {
      background: var(--bg-card-subtle);
      border: 1px solid var(--border-main);
      border-radius: 8px;
      padding: 10px 14px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
    }
    .tech-label {
      font-size: 11px;
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .tech-val {
      font-family: var(--font-mono);
      font-size: 11px;
      font-weight: 700;
      color: var(--text-primary);
      text-align: right;
    }

    /* Remediation List */
    .remediation-list {
      display: flex;
      flex-direction: column;
      gap: 8px;
    }
    .remediation-item {
      display: flex;
      align-items: flex-start;
      gap: 12px;
      padding: 12px 16px;
      border-radius: 8px;
      background: var(--bg-card-subtle);
      border: 1px solid var(--border-main);
      font-weight: 500;
      font-size: 12.5px;
    }
    .rec-num {
      width: 20px;
      height: 20px;
      border-radius: 50%;
      background: var(--primary-brand);
      color: #ffffff;
      font-family: var(--font-sans);
      font-size: 10px;
      font-weight: 700;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
      margin-top: 1px;
    }

    /* Footer */
    .report-footer {
      border-top: 1px solid var(--border-main);
      padding: 16px 0 8px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 11px;
      color: var(--text-muted);
      font-family: var(--font-sans);
      flex-wrap: wrap;
      gap: 8px;
    }

    @media print {
      body { background: #ffffff; padding: 0; }
      .top-controls { display: none; }
      .card { box-shadow: none; border-color: #E2E8F0; }
    }
  </style>
</head>
<body>
  <div class="report-container">
    <!-- Top App Bar Header -->
    <header class="top-app-bar">
      <div class="brand-group">
        <div class="brand-emblem">
          <svg width="22" height="22" viewBox="0 0 40 40" fill="none">
            <rect width="40" height="40" rx="8" fill="#0F172A" />
            <path d="M10 14C10 12.8954 10.8954 12 12 12H28C29.1046 12 30 12.8954 30 14V26C30 27.1046 29.1046 28 28 28H12C10.8954 28 10 27.1046 10 26V14Z" stroke="#94A3B8" stroke-width="1.5" stroke-linecap="round" />
            <path d="M10 14L20 21L30 14" stroke="#6366F1" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" />
            <circle cx="20" cy="21" r="3.5" fill="#0F172A" stroke="#10B981" stroke-width="1.5" />
          </svg>
        </div>
        <div>
          <div class="brand-title">
            <span>SecureMailScope</span>
            <span class="version-pill">v1.4</span>
          </div>
          <div class="brand-sub">Enterprise SOC Telemetry • Passive Cryptographic Forensics</div>
        </div>
      </div>

      <div class="top-controls">
        <div class="workstation-chip">
          <span class="dot-green"></span>
          <span>SOC Workstation</span>
        </div>
        <button id="themeToggle" class="theme-btn" onclick="toggleReportTheme()">
          <span id="themeIcon">☾</span>
          <span id="themeText">Theme</span>
        </button>
      </div>
    </header>

    <!-- Top KPI Grid -->
    <div class="hero-grid">
      <!-- Dominant AI Risk Dial -->
      <div class="risk-dial-card">
        <div class="dial-svg-box">
          <svg class="dial-svg" viewBox="0 0 130 130">
            <circle cx="65" cy="65" fill="transparent" r="54" stroke="var(--border-main)" stroke-width="10" />
            <circle cx="65" cy="65" fill="transparent" r="54" stroke="${riskGaugeColor}" stroke-dasharray="${circumference}" stroke-dashoffset="${dashOffset}" stroke-linecap="round" stroke-width="10" />
          </svg>
          <div class="dial-center">
            <span class="dial-score">${ctx.aiScore}</span>
            <span class="dial-max">/ 100</span>
          </div>
        </div>
        <span class="badge ${riskBadgeClass}">
          ${escapeHtml(ctx.aiLabel)} RISK
        </span>
        <div style="font-size: 11px; font-family: var(--font-sans); color: var(--text-muted); margin-top: 8px;">
          Model Confidence: <strong>${ctx.aiConfidence}%</strong>
        </div>
        <div style="font-size: 11px; font-family: var(--font-mono); color: var(--text-secondary); margin-top: 4px; word-break: break-all;">
          ${escapeHtml(ctx.filename)}
        </div>
      </div>

      <!-- Secondary KPI 4-cell Grid -->
      <div class="kpi-grid">
        <div class="kpi-cell">
          <span class="kpi-label">Security Posture</span>
          <div class="kpi-value">
            <span class="badge ${postureBadgeClass}">${escapeHtml(ctx.postureStatus)}</span>
          </div>
          <span class="kpi-sub">Score: ${ctx.postureScore} / 100 (${escapeHtml(ctx.postureRiskLevel)})</span>
        </div>

        <div class="kpi-cell">
          <span class="kpi-label">Reconstructed Sessions</span>
          <div class="kpi-value">${ctx.totalSessions}</div>
          <span class="kpi-sub">${ctx.totalPackets.toLocaleString()} Total Frames</span>
        </div>

        <div class="kpi-cell">
          <span class="kpi-label">Protocol Telemetry</span>
          <div class="kpi-value">${escapeHtml(ctx.protocol)}</div>
          <span class="kpi-sub">Port ${ctx.dstPort} • ${ctx.isTlsObserved ? escapeHtml(ctx.tls.version || 'TLS') : 'Plaintext'}</span>
        </div>

        <div class="kpi-cell">
          <span class="kpi-label">Anomaly Evaluation</span>
          <div class="kpi-value" style="font-size: 18px; color: ${ctx.isAnomaly ? '#dc2626' : '#10b981'};">
            ${escapeHtml(ctx.anomalyStatus)}
          </div>
          <span class="kpi-sub">Isolation Forest: ${ctx.anomalyScore}</span>
        </div>
      </div>
    </div>

    <!-- Section 01: PCAP & Session Telemetry -->
    <section class="card">
      <div class="card-header">
        <h2 class="card-title">01 PCAP & Session Telemetry</h2>
        <span style="font-family: var(--font-sans); font-size: 11px; color: var(--text-muted);">${ctx.totalSessions} Session(s) Observed</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Session ID</th>
            <th>Protocol</th>
            <th>Client Endpoint</th>
            <th>Server Endpoint</th>
            <th>TLS Version</th>
            <th>Posture Score</th>
            <th>AI Risk</th>
            <th>Security Status</th>
          </tr>
        </thead>
        <tbody>
          ${ctx.sessions.map(s => {
            const sScore = s.ai_risk?.score != null ? Number(s.ai_risk.score).toFixed(1) : (s.posture?.score ?? 'N/A');
            const sLabel = getAiRiskTier(s.ai_risk);
            const sBadgeClass = sLabel === 'CRITICAL' || sLabel === 'HIGH' ? 'badge-critical' : sLabel === 'MODERATE' ? 'badge-warning' : 'badge-secure';
            return `
              <tr>
                <td><code>${escapeHtml(s.session_id || 'TCP-001')}</code></td>
                <td><strong>${escapeHtml(s.protocol || 'N/A')}</strong></td>
                <td><span class="mono">${escapeHtml(s.source_ip)}:${escapeHtml(s.source_port)}</span></td>
                <td><span class="mono">${escapeHtml(s.destination_ip)}:${escapeHtml(s.destination_port)}</span></td>
                <td>${escapeHtml(s.tls?.version || (s.tls?.detected ? 'TLS' : 'Plaintext'))}</td>
                <td><span class="mono">${s.posture?.score ?? ctx.postureScore}/100</span></td>
                <td><span class="badge ${sBadgeClass}">${sScore} [${escapeHtml(sLabel)}]</span></td>
                <td><strong>${escapeHtml(s.posture?.security_posture || ctx.postureStatus)}</strong></td>
              </tr>
            `;
          }).join('')}
        </tbody>
      </table>
    </section>

    <!-- Section 02: STARTTLS Analysis -->
    <section class="card">
      <div class="card-header">
        <h2 class="card-title">02 STARTTLS Analysis</h2>
        <span style="font-family: var(--font-sans); font-size: 11px; color: var(--text-muted);">${escapeHtml(ctx.starttlsStatus)}</span>
      </div>
      <div class="tech-grid">
        ${ctx.starttlsDetails.map(d => {
          let chipClass = 'chip-evidence';
          if (d.tag === 'VERIFIED') chipClass += ' chip-verified';
          else if (d.tag === 'ISSUE DETECTED') chipClass += ' chip-issue';
          else if (d.tag === 'OBSERVED') chipClass += ' chip-observed';
          else if (d.tag === 'INCOMPLETE') chipClass += ' chip-incomplete';
          return `
            <div class="tech-cell">
              <div>
                <div class="tech-label">${escapeHtml(d.label)}</div>
                <div class="tech-val" style="text-align: left; margin-top: 2px;">${escapeHtml(d.value)}</div>
              </div>
              <span class="${chipClass}">${escapeHtml(d.tag)}</span>
            </div>
          `;
        }).join('')}
      </div>
    </section>

    <!-- Section 03: TLS Analysis -->
    <section class="card">
      <div class="card-header">
        <h2 class="card-title">03 TLS Analysis</h2>
        <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${escapeHtml(ctx.tls.version || (ctx.isTlsObserved ? 'TLS' : 'Plaintext'))}</span>
      </div>
      <div class="tech-grid">
        ${ctx.tlsDetails.map(d => {
          let chipClass = 'chip-evidence';
          if (d.tag === 'VERIFIED') chipClass += ' chip-verified';
          else if (d.tag === 'ISSUE DETECTED') chipClass += ' chip-issue';
          else if (d.tag === 'OBSERVED') chipClass += ' chip-observed';
          else if (d.tag === 'INCOMPLETE') chipClass += ' chip-incomplete';
          return `
            <div class="tech-cell">
              <div>
                <div class="tech-label">${escapeHtml(d.label)}</div>
                <div class="tech-val" style="text-align: left; margin-top: 2px;">${escapeHtml(d.value)}</div>
              </div>
              <span class="${chipClass}">${escapeHtml(d.tag)}</span>
            </div>
          `;
        }).join('')}
      </div>
    </section>

    <!-- Section 04: Certificate Analysis -->
    <section class="card">
      <div class="card-header">
        <h2 class="card-title">04 Certificate Analysis</h2>
        <span style="font-family: var(--font-mono); font-size: 11px; color: var(--text-muted);">${escapeHtml(ctx.cert.common_name || 'Leaf Certificate')}</span>
      </div>
      <div class="tech-grid">
        ${ctx.certDetails.map(d => {
          let chipClass = 'chip-evidence';
          if (d.tag === 'VERIFIED') chipClass += ' chip-verified';
          else if (d.tag === 'ISSUE DETECTED') chipClass += ' chip-issue';
          else if (d.tag === 'OBSERVED') chipClass += ' chip-observed';
          else if (d.tag === 'INCOMPLETE') chipClass += ' chip-incomplete';
          return `
            <div class="tech-cell">
              <div>
                <div class="tech-label">${escapeHtml(d.label)}</div>
                <div class="tech-val" style="text-align: left; margin-top: 2px;">${escapeHtml(d.value)}</div>
              </div>
              <span class="${chipClass}">${escapeHtml(d.tag)}</span>
            </div>
          `;
        }).join('')}
      </div>
    </section>

    <!-- Section 05: Certificate Chain Validation -->
    <section class="card">
      <div class="card-header">
        <h2 class="card-title">05 Certificate Chain Validation</h2>
        <span style="font-family: var(--font-sans); font-size: 11px; color: var(--text-muted);">${escapeHtml(ctx.chainValidation.chain_valid ? 'Chain Verified' : 'Chain Incomplete')}</span>
      </div>
      <div class="tech-grid">
        ${ctx.chainDetails.map(d => {
          let chipClass = 'chip-evidence';
          if (d.tag === 'VERIFIED') chipClass += ' chip-verified';
          else if (d.tag === 'ISSUE DETECTED') chipClass += ' chip-issue';
          else if (d.tag === 'OBSERVED') chipClass += ' chip-observed';
          else if (d.tag === 'INCOMPLETE') chipClass += ' chip-incomplete';
          return `
            <div class="tech-cell">
              <div>
                <div class="tech-label">${escapeHtml(d.label)}</div>
                <div class="tech-val" style="text-align: left; margin-top: 2px;">${escapeHtml(d.value)}</div>
              </div>
              <span class="${chipClass}">${escapeHtml(d.tag)}</span>
            </div>
          `;
        }).join('')}
      </div>
    </section>

    <!-- Section 06: Deterministic Security Findings -->
    <section class="card">
      <div class="card-header">
        <h2 class="card-title">06 Security Findings</h2>
        <span style="font-family: var(--font-sans); font-size: 11px; color: var(--text-muted);">${ctx.findingsList.length} Finding(s) Detected</span>
      </div>
      ${ctx.findingsList.length > 0 ? `
        <table>
          <thead>
            <tr>
              <th>Stage</th>
              <th>Severity</th>
              <th>Finding Title</th>
              <th>Technical Reason</th>
              <th>Recommended Remediation</th>
            </tr>
          </thead>
          <tbody>
            ${ctx.findingsList.map(f => {
              const sevClass = f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'badge-critical' : f.severity === 'MEDIUM' ? 'badge-warning' : 'badge-secure';
              return `
                <tr>
                  <td><span class="mono" style="color: var(--primary-brand); font-weight: bold;">Stage ${f.stage.num}</span></td>
                  <td><span class="badge ${sevClass}">${escapeHtml(f.severity)}</span></td>
                  <td><strong>${escapeHtml(f.title)}</strong></td>
                  <td style="color: var(--text-secondary); font-size: 11.5px;">${escapeHtml(f.reason || f.description)}</td>
                  <td style="color: var(--text-primary); font-size: 11.5px;">${escapeHtml(f.recommendation || 'Remediate per RFC 8446 baseline.')}</td>
                </tr>
              `;
            }).join('')}
          </tbody>
        </table>
      ` : `
        <div style="padding: 16px; background: var(--bg-card-subtle); border-radius: 8px; border: 1px solid var(--border-main); color: var(--color-secure-text); font-weight: 600;">
          Zero deterministic security findings. Session satisfies the baseline cryptographic security policy.
        </div>
      `}
    </section>

    <!-- Section 07: AI Risk Assessment -->
    <section class="card">
      <div class="card-header">
        <h2 class="card-title">07 AI Risk Assessment</h2>
        <span style="font-family: var(--font-sans); font-size: 11px; color: var(--text-muted);">Whole-Session Random Forest</span>
      </div>
      <div class="tech-grid" style="margin-bottom: 12px;">
        <div class="tech-cell">
          <span class="tech-label">Model Architecture</span>
          <span class="tech-val">RandomForestClassifier (54 Features)</span>
        </div>
        <div class="tech-cell">
          <span class="tech-label">Cryptographic Risk Score</span>
          <span class="tech-val">${ctx.aiScore} / 100</span>
        </div>
        <div class="tech-cell">
          <span class="tech-label">Operational Risk Tier</span>
          <span class="tech-val"><span class="badge ${riskBadgeClass}">${escapeHtml(ctx.aiLabel)}</span></span>
        </div>
        <div class="tech-cell">
          <span class="tech-label">Inference Confidence</span>
          <span class="tech-val">${ctx.aiConfidence}%</span>
        </div>
      </div>
      <div style="padding: 12px 16px; background: var(--bg-card-subtle); border-radius: 8px; border: 1px solid var(--border-main); font-size: 12px;">
        <span style="font-weight: 700; text-transform: uppercase; font-size: 10px; color: var(--text-muted); display: block; margin-bottom: 4px;">Top Observed Risk Factors</span>
        <span style="font-family: var(--font-sans); color: var(--text-primary);">
          ${escapeHtml(ctx.topRiskFactors.map(f => typeof f === 'object' ? (f.label || f.feature) : f).join('; ') || 'Cryptographic parameters conform to modern secure mail standards.')}
        </span>
      </div>
    </section>

    <!-- Section 08: Forensic Processing Pipeline (Stages 01-09) -->
    <section class="card">
      <div class="card-header">
        <h2 class="card-title">08 Forensic Pipeline (Stages 01–09)</h2>
        <span style="font-family: var(--font-sans); font-size: 11px; color: var(--text-muted);">Continuous SOC Flow</span>
      </div>
      <div class="pipeline-grid">
        ${ctx.pipelineStages.map(st => {
          const nodeColorClass = st.color === 'green' ? 'node-green' : st.color === 'amber' ? 'node-amber' : 'node-red';
          const statusColorClass = st.color === 'green' ? 'status-green' : st.color === 'amber' ? 'status-amber' : 'status-red';
          return `
            <div class="pipe-node ${nodeColorClass}">
              <div class="pipe-node-header">
                <span class="pipe-num">#${st.stepNum}</span>
                <span class="pipe-status ${statusColorClass}">● ${escapeHtml(st.status)}</span>
              </div>
              <div class="pipe-name">${escapeHtml(st.name)}</div>
              <div class="pipe-desc" title="${escapeHtml(st.desc)}">${escapeHtml(st.label || st.desc)}</div>
            </div>
          `;
        }).join('')}
      </div>
    </section>

    <!-- Section 09: Actionable Recommendations -->
    <section class="card">
      <div class="card-header">
        <h2 class="card-title">09 Recommendations</h2>
        <span style="font-family: var(--font-sans); font-size: 11px; color: var(--text-muted);">${ctx.displayActions.length} Action(s)</span>
      </div>
      <div class="remediation-list">
        ${ctx.displayActions.map((act, idx) => `
          <div class="remediation-item">
            <span class="rec-num">${idx + 1}</span>
            <span>${escapeHtml(act)}</span>
          </div>
        `).join('')}
      </div>
    </section>

    <!-- Report Footer -->
    <footer class="report-footer">
      <span>SecureMailScope Automated Forensic Platform • RFC 8446 / NIST Baseline</span>
      <span>Generated: ${escapeHtml(generatedAt)}</span>
      <span style="font-weight: bold;">CONFIDENTIAL FORENSIC EVIDENCE</span>
    </footer>
  </div>

  <script>
    function toggleReportTheme() {
      const isDark = document.documentElement.classList.toggle('dark');
      try {
        localStorage.setItem('sms_report_theme', isDark ? 'dark' : 'light');
      } catch (e) {}
      updateThemeIcon(isDark);
    }
    function updateThemeIcon(isDark) {
      const icon = document.getElementById('themeIcon');
      const txt = document.getElementById('themeText');
      if (icon && txt) {
        icon.textContent = isDark ? '☼' : '☾';
        txt.textContent = isDark ? 'Light' : 'Dark';
      }
    }
    // Initialize theme from preference
    (function() {
      try {
        const saved = localStorage.getItem('sms_report_theme');
        if (saved === 'dark' || (!saved && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)) {
          document.documentElement.classList.add('dark');
          updateThemeIcon(true);
        } else {
          updateThemeIcon(false);
        }
      } catch(e) {}
    })();
  </script>
</body>
</html>`;

  if (typeof document !== 'undefined') {
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }
  return html;
}
