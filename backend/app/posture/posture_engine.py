import re
from typing import List, Dict, Any, Optional

def correlate_session_evidence(session: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Performs cross-layer correlation across protocol, STARTTLS, TLS, and X.509 certificate evidence.
    Identifies high-level security patterns and preserves underlying evidence references.
    """
    correlations = []
    protocol = session.get("protocol", "UNKNOWN")
    starttls_info = session.get("starttls", {})
    tls_info = session.get("tls", {})
    cert_info = tls_info.get("certificate", {})

    st_status = starttls_info.get("status")
    st_supported = starttls_info.get("upgrade_supported")
    st_requested = starttls_info.get("upgrade_requested")
    st_accepted = starttls_info.get("upgrade_accepted")
    
    tls_detected = tls_info.get("detected", False)
    tls_version = tls_info.get("version")
    cipher_suite = tls_info.get("cipher_suite")
    forward_secrecy = tls_info.get("forward_secrecy")

    cert_present = cert_info.get("certificate_present", False)
    exp_status = cert_info.get("expiration_status")
    hostname_match = cert_info.get("hostname_match")

    # CORRELATION-001: STARTTLS accepted but TLS handshake not observed
    if (st_status == "INCOMPLETE" and not tls_detected) or (st_accepted is True and not tls_detected):
        correlations.append({
            "correlation_id": "CORRELATION-001",
            "title": "STARTTLS Accepted without Handshake Execution",
            "layers_involved": ["APPLICATION_PROTOCOL", "STARTTLS_NEGOTIATION", "TLS_RECORD_LAYER"],
            "description": "The mail server acknowledged STARTTLS with 220 Ready, but no TLS cryptographic handshake frames were transmitted. Traffic remained unencrypted.",
            "evidence": starttls_info.get("evidence", [])
        })

    # CORRELATION-002: STARTTLS advertised but no upgrade request observed
    if st_supported is True and st_requested is False and not tls_detected:
        correlations.append({
            "correlation_id": "CORRELATION-002",
            "title": "Unencrypted Session Despite Advertised STARTTLS Capability",
            "layers_involved": ["APPLICATION_PROTOCOL", "STARTTLS_NEGOTIATION"],
            "description": "The mail server advertised STARTTLS capability in response to EHLO/CAPA, but the client continued communicating in plaintext without requesting encryption.",
            "evidence": starttls_info.get("evidence", [])
        })

    # CORRELATION-003: TLS established but deprecated TLS version negotiated
    if tls_detected and tls_version in ("SSLv3", "TLSv1.0", "TLSv1.1"):
        correlations.append({
            "correlation_id": "CORRELATION-003",
            "title": "Encrypted Session Operating Over Deprecated TLS Protocol",
            "layers_involved": ["TLS_RECORD_LAYER", "TLS_HANDSHAKE"],
            "description": f"The session established encryption using obsolete protocol {tls_version}, which lacks modern cryptographic protections.",
            "evidence": [e for e in tls_info.get("evidence", []) if e.get("type") == "handshake_message" and e.get("message") == "ServerHello"]
        })

    # CORRELATION-004: TLS established but weak cipher negotiated
    if tls_detected and cipher_suite:
        c_upper = cipher_suite.upper()
        if any(weak in c_upper for weak in ("NULL", "EXPORT", "RC4", "3DES", "_DES_", "_ANON_")):
            correlations.append({
                "correlation_id": "CORRELATION-004",
                "title": "Encrypted Session Negotiated Deprecated/Weak Cipher Suite",
                "layers_involved": ["TLS_HANDSHAKE", "CIPHER_SUITE"],
                "description": f"The session established encryption using {cipher_suite}, which is vulnerable to known cryptographic attacks.",
                "evidence": [e for e in tls_info.get("evidence", []) if "cipher" in str(e).lower()]
            })

    # CORRELATION-005: TLS established but Forward Secrecy absent
    if tls_detected and forward_secrecy is False:
        correlations.append({
            "correlation_id": "CORRELATION-005",
            "title": "TLS Encryption Active Without Perfect Forward Secrecy",
            "layers_involved": ["TLS_HANDSHAKE", "KEY_EXCHANGE"],
            "description": "The session established encryption using static RSA key exchange. Prior recorded sessions are vulnerable to retrospective decryption if the server private key is compromised.",
            "evidence": [e for e in tls_info.get("evidence", []) if "ServerHello" in str(e) or "KeyExchange" in str(e)]
        })

    # CORRELATION-006: TLS certificate hostname does not match observed SNI
    if cert_present and hostname_match is False:
        correlations.append({
            "correlation_id": "CORRELATION-006",
            "title": "Certificate SAN / SNI Hostname Mismatch",
            "layers_involved": ["TLS_HANDSHAKE", "X509_CERTIFICATE"],
            "description": f"Client requested SNI '{tls_info.get('client_hello', {}).get('server_name')}' which does not match certificate SANs ({cert_info.get('subject_alternative_names', [])}) or CN '{cert_info.get('common_name')}'.",
            "evidence": cert_info.get("evidence", [])
        })

    # CORRELATION-007: TLS certificate is expired/not-yet-valid while encrypted communication is observed
    if tls_detected and cert_present and exp_status in ("EXPIRED", "NOT_YET_VALID"):
        correlations.append({
            "correlation_id": "CORRELATION-007",
            "title": "Encrypted Communication Over Invalid/Expired Certificate",
            "layers_involved": ["TLS_HANDSHAKE", "X509_CERTIFICATE"],
            "description": f"The session completed a TLS handshake using a certificate that is {exp_status} (Validity: {cert_info.get('valid_from')} to {cert_info.get('valid_to')}).",
            "evidence": cert_info.get("evidence", [])
        })

    # CORRELATION-009: TLS certificate is self-signed
    if tls_detected and cert_present and cert_info.get("self_signed") is True:
        correlations.append({
            "correlation_id": "CORRELATION-009",
            "title": "Encrypted Communication Using Self-Signed Certificate",
            "layers_involved": ["TLS_HANDSHAKE", "X509_CERTIFICATE"],
            "description": f"The session established TLS encryption with a self-signed certificate (Subject: '{cert_info.get('subject')}', Issuer: '{cert_info.get('issuer')}'). Identity cannot be verified against trusted authorities.",
            "evidence": cert_info.get("evidence", [])
        })

    # CORRELATION-008: Multiple cryptographic weaknesses occur in the same session
    if len(correlations) >= 2 or len(session.get("assessment", {}).get("findings", [])) >= 2:
        correlations.append({
            "correlation_id": "CORRELATION-008",
            "title": "Compound Multi-Layer Cryptographic Weaknesses",
            "layers_involved": ["CROSS_LAYER_SYNTHESIS"],
            "description": "Multiple independent cryptographic weaknesses were detected across the protocol, TLS negotiation, and certificate layers in the same conversation.",
            "evidence": [{"type": "compound_count", "total_correlations": len(correlations)}]
        })

    return correlations


def is_confirmed_plaintext_payload(session: Dict[str, Any]) -> bool:
    """
    Determines if session genuinely exchanged plaintext application-layer email data.
    Single-byte probes (e.g. 0x00), padding, TCP window probes, or tiny binary noise
    must NOT be classified as plaintext application data.
    """
    if session.get("tls", {}).get("detected"):
        return False

    # Check if protocol detector discovered actual application payload evidence
    evidence = session.get("evidence", [])
    if any(e.get("type") in ("banner", "payload", "command", "response") for e in evidence):
        return True

    # Check assessment findings for explicit plaintext findings
    findings = session.get("assessment", {}).get("findings", [])
    if any("plaintext" in f.get("title", "").lower() or "unencrypted" in f.get("title", "").lower() for f in findings):
        return True

    c_payload = str(session.get("client_payload") or "")
    s_payload = str(session.get("server_payload") or "")
    combined = (c_payload + "\n" + s_payload).strip()

    # Reject empty, whitespace, or tiny uninterpretable payloads (e.g. single 0x00 byte)
    if len(combined) <= 3:
        return False
    clean_chars = [c for c in combined if ord(c) >= 32 or c in '\r\n\t']
    if len(clean_chars) <= 3:
        return False

    # Check for recognizable email application tokens (SMTP, IMAP, POP3)
    email_app_tokens = re.compile(
        r'\b(EHLO|HELO|MAIL FROM:|RCPT TO:|DATA\b|QUIT\b|AUTH\s|STARTTLS|STLS|USER\s|PASS\s|STAT\b|LIST\b|RETR\b|DELE\b|UIDL\b|CAPA\b|\* OK\b|\* PREAUTH\b|\+OK\b|\-ERR\b|220\s|250\s|354\s|A\d+\s+LOGIN|A\d+\s+CAPABILITY|A\d+\s+SELECT)',
        re.IGNORECASE
    )
    return bool(email_app_tokens.search(combined))


def calculate_security_posture(session: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes a transparent 0-100 security posture score, calculates dimensional security ratings,
    and maps the final risk level with deterministic override constraints.
    """
    session_id = session.get("session_id", "UNKNOWN")
    protocol = session.get("protocol", "UNKNOWN")
    starttls_info = session.get("starttls", {})
    tls_info = session.get("tls", {})
    cert_info = tls_info.get("certificate", {})
    assessment = session.get("assessment", {})

    findings = assessment.get("findings", [])
    correlations = correlate_session_evidence(session)

    critical_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings if f.get("severity") == "LOW")

    finding_summary = {
        "critical": critical_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count
    }

    tls_detected = tls_info.get("detected", False)
    st_status = starttls_info.get("status")
    has_confirmed_plaintext = is_confirmed_plaintext_payload(session)

    # Determine baseline score and confidence
    score_confidence = "HIGH"
    if protocol == "UNKNOWN" and not tls_detected:
        base_score = 0
        score_confidence = "LOW"
        security_posture = "NOT_OBSERVABLE"
    elif not tls_detected and st_status == "INCOMPLETE":
        base_score = 100
        security_posture = "INCOMPLETE"
    elif not tls_detected and not has_confirmed_plaintext:
        # Incomplete capture / insufficient evidence: no TLS observed and no confirmed plaintext email data
        base_score = 100
        score_confidence = "LOW"
        security_posture = "INCOMPLETE"
    elif not tls_detected:
        base_score = 25  # Confirmed plain unencrypted email baseline
        security_posture = "AT_RISK"
    else:
        base_score = 100
        security_posture = "SECURE" if len(findings) == 0 else "AT_RISK"

    # Transparent Deductions
    deductions = (
        (critical_count * 35) +
        (high_count * 25) +
        (medium_count * 15) +
        (low_count * 5)
    )

    final_score = max(0, min(100, base_score - deductions))

    # Evaluate Dimensions (0 - 100)
    # 1. Protocol Security
    if protocol in ("SMTP", "IMAP", "POP3"):
        dim_protocol = 100
    else:
        dim_protocol = 0

    # 2. STARTTLS Security
    if tls_detected and st_status == "SECURE_TRANSITION":
        dim_starttls = 100
    elif tls_detected:
        dim_starttls = 100  # Direct TLS (e.g. SMTPS on 465)
    elif st_status == "INCOMPLETE":
        dim_starttls = 30
    elif starttls_info.get("upgrade_supported") and not starttls_info.get("upgrade_requested"):
        dim_starttls = 20
    elif starttls_info.get("upgrade_accepted") is False:
        dim_starttls = 10
    else:
        dim_starttls = 40 if protocol in ("SMTP", "IMAP", "POP3") else 0

    # 3. TLS Security
    if tls_detected:
        ver = tls_info.get("version")
        cipher = str(tls_info.get("cipher_suite", "")).upper()
        if ver == "TLSv1.3":
            dim_tls = 100
        elif ver == "TLSv1.2":
            dim_tls = 90 if "_GCM_" in cipher or "_POLY1305" in cipher else 75
        elif ver in ("TLSv1.0", "TLSv1.1"):
            dim_tls = 40
        else:
            dim_tls = 10
        if "NULL" in cipher or "EXPORT" in cipher or "RC4" in cipher:
            dim_tls = min(dim_tls, 15)
    else:
        dim_tls = 0

    # 4. Certificate Security
    if cert_info.get("certificate_present"):
        dim_cert = 100
        if cert_info.get("expiration_status") in ("EXPIRED", "NOT_YET_VALID"):
            dim_cert -= 60
        elif cert_info.get("expiration_status") == "EXPIRING_SOON":
            dim_cert -= 20
        if cert_info.get("public_key_algorithm") == "RSA" and (cert_info.get("public_key_length") or 0) < 2048:
            dim_cert -= 40
        if cert_info.get("hostname_match") is False:
            dim_cert -= 30
        if cert_info.get("self_signed") is True:
            dim_cert -= 40
        dim_cert = max(0, min(100, dim_cert))
    else:
        dim_cert = 0 if tls_detected else 0

    # 5. Forward Secrecy
    if tls_detected and tls_info.get("forward_secrecy") is True:
        dim_fs = 100
    elif tls_detected and tls_info.get("forward_secrecy") is False:
        dim_fs = 0
    else:
        dim_fs = 0

    dimensions = {
        "protocol_security": dim_protocol,
        "starttls_security": dim_starttls,
        "tls_security": dim_tls,
        "certificate_security": dim_cert,
        "forward_secrecy": dim_fs
    }

    # Map Risk Level with Critical Override Rules
    if final_score >= 90:
        risk_level = "LOW_RISK"
    elif final_score >= 70:
        risk_level = "MODERATE_RISK"
    elif final_score >= 40:
        risk_level = "HIGH_RISK"
    else:
        risk_level = "CRITICAL_RISK"

    # Explicit Safety Constraint Overrides
    if critical_count > 0 and risk_level in ("LOW_RISK", "MODERATE_RISK"):
        risk_level = "CRITICAL_RISK"
    elif high_count > 0 and risk_level == "LOW_RISK":
        risk_level = "HIGH_RISK"

    hs_status = tls_info.get("handshake_status") or tls_info.get("tls_handshake_status")
    app_data_obs = bool(tls_info.get("encrypted_application_data_observed", False))
    session_completion = "COMPLETE" if (hs_status == "COMPLETE" and app_data_obs) else ("INCOMPLETE" if tls_detected else "NOT_OBSERVED")
    configuration_posture = "SECURE" if (security_posture == "SECURE" or final_score >= 90) else ("NEEDS_ATTENTION" if final_score >= 70 else "COMPROMISED")

    # Generate Human-Readable Explanation
    if security_posture == "SECURE" and final_score >= 90:
        if hs_status == "INCOMPLETE" or not app_data_obs:
            explanation = (
                f"Session {session_id} demonstrates a strong cryptographic configuration "
                f"({tls_info.get('version')}, {tls_info.get('cipher_suite')}, valid certificate), "
                f"but the captured TLS handshake is incomplete (encrypted application data was not observed). "
                f"Zero cryptographic vulnerabilities were identified in the observed parameters."
            )
        else:
            explanation = (
                f"Session {session_id} demonstrates a strong cryptographic security posture with active "
                f"{tls_info.get('version')} encryption, {tls_info.get('cipher_suite')}, verified forward secrecy, "
                f"and a valid certificate. Encrypted application communication was observed with zero vulnerabilities."
            )
    elif security_posture == "INCOMPLETE":
        if st_status == "INCOMPLETE":
            explanation = f"Session {session_id} negotiated STARTTLS with the mail server, but the capture concluded before the TLS handshake executed. The session is categorized as {risk_level} due to incomplete encryption transition."
        else:
            explanation = f"Session {session_id} contains insufficient captured packets to observe a TLS handshake or verify email application data (Payload Security: UNCLASSIFIED / INSUFFICIENT EVIDENCE). Zero cryptographic vulnerabilities confirmed."
    elif not tls_detected:
        explanation = f"Session {session_id} transmitted unencrypted {protocol} email traffic over plaintext TCP. Communication is categorized as {risk_level}."
    else:
        explanation = f"Session {session_id} established TLS encryption but exhibits {len(findings)} security finding(s) (Critical: {critical_count}, High: {high_count}, Medium: {medium_count}), resulting in a score of {final_score}/100 and risk level {risk_level}."

    # Collect consolidated evidence items
    all_evidence: List[Dict[str, Any]] = []
    for c in correlations:
        all_evidence.extend(c.get("evidence") or [])
    for f in findings:
        all_evidence.extend(f.get("evidence") or [])

    # Deduplicate evidence references
    unique_evidence = []
    seen_evidence = set()
    for ev in all_evidence:
        ev_str = str(ev)
        if ev_str not in seen_evidence:
            seen_evidence.add(ev_str)
            unique_evidence.append(ev)

    return {
        "session_id": session_id,
        "protocol": protocol,
        "security_posture": security_posture,
        "configuration_posture": configuration_posture,
        "session_completion": session_completion,
        "score": final_score,
        "risk_level": risk_level,
        "score_confidence": score_confidence,
        "dimensions": dimensions,
        "correlations": correlations,
        "finding_summary": finding_summary,
        "explanation": explanation,
        "evidence": unique_evidence
    }
