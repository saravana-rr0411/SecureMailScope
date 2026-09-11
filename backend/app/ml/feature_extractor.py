from typing import Dict, Any, Optional

TLS_VERSION_NUMERIC_MAP = {
    "SSLv3": 0.3,
    "TLSv1.0": 1.0,
    "TLSv1.1": 1.1,
    "TLSv1.2": 1.2,
    "TLSv1.3": 1.3
}


def extract_session_features(session: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts deterministic numeric and encoded features from an analyzed email session.
    Provides structured feature vectors alongside observability metadata for machine learning.
    """
    session_id = session.get("session_id", "UNKNOWN")
    protocol = session.get("protocol", "UNKNOWN")
    proto_conf = session.get("protocol_confidence", "LOW")

    starttls_info = session.get("starttls", {})
    if not isinstance(starttls_info, dict):
        starttls_info = {}
    tls_info = session.get("tls", {})
    if not isinstance(tls_info, dict):
        tls_info = {}
    cert_info = tls_info.get("certificate", {})
    if not isinstance(cert_info, dict):
        cert_info = {}
    assessment = session.get("assessment", {})
    if not isinstance(assessment, dict):
        assessment = {}
    posture = session.get("posture", {})
    if not isinstance(posture, dict):
        posture = {}

    features: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}

    # 1. Protocol Layer Features
    features["protocol_is_smtp"] = 1 if protocol == "SMTP" else 0
    features["protocol_is_imap"] = 1 if protocol == "IMAP" else 0
    features["protocol_is_pop3"] = 1 if protocol == "POP3" else 0
    features["protocol_is_other"] = 1 if protocol not in ("SMTP", "IMAP", "POP3") else 0
    features["protocol_confidence_score"] = 1.0 if proto_conf == "HIGH" else (0.5 if proto_conf == "MEDIUM" else 0.0)

    metadata["protocol"] = {
        "source": "Application Payload / Ports",
        "observable": protocol != "UNKNOWN",
        "raw_value": protocol
    }

    # 2. STARTTLS Layer Features
    st_supported = starttls_info.get("upgrade_supported")
    st_requested = starttls_info.get("upgrade_requested")
    st_accepted = starttls_info.get("upgrade_accepted")
    st_transition = starttls_info.get("tls_transition_observed")
    st_status = starttls_info.get("status", "NOT_OBSERVABLE")

    features["starttls_upgrade_supported"] = 1 if st_supported is True else 0
    features["starttls_upgrade_requested"] = 1 if st_requested is True else 0
    features["starttls_upgrade_accepted"] = 1 if st_accepted is True else 0
    features["starttls_transition_observed"] = 1 if st_transition is True else 0
    features["starttls_is_incomplete"] = 1 if st_status == "INCOMPLETE" else 0
    features["starttls_status_secure"] = 1 if st_status == "SECURE_TRANSITION" else 0
    features["starttls_status_direct_tls"] = 1 if st_status == "DIRECT_TLS" else 0
    features["starttls_status_none"] = 1 if st_status in ("NOT_OBSERVABLE", "NOT_USED", "NO_STARTTLS", "INCOMPLETE") and not tls_info.get("detected") else 0

    metadata["starttls_status"] = {
        "source": "STARTTLS Negotiation State Machine",
        "observable": st_status != "NOT_OBSERVABLE",
        "raw_value": st_status
    }

    # 3. TLS Handshake & Cryptographic Layer Features
    tls_detected = tls_info.get("detected", False)
    tls_version_str = str(tls_info.get("version") or "")
    cipher_suite_str = tls_info.get("cipher_suite")
    key_exchange_str = tls_info.get("key_exchange")
    fs_val = tls_info.get("forward_secrecy")
    app_data_obs = tls_info.get("encrypted_application_data_observed", False)

    features["tls_detected"] = 1 if tls_detected else 0
    # Backward compatible numeric version representation
    features["tls_version_numeric"] = TLS_VERSION_NUMERIC_MAP.get(tls_version_str, 0.0) if tls_detected else 0.0

    # Categorical One-Hot TLS Version Indicators (Representation, not arbitrary score)
    features["tls_version_is_1_3"] = 1 if (tls_detected and "1.3" in tls_version_str) else 0
    features["tls_version_is_1_2"] = 1 if (tls_detected and "1.2" in tls_version_str) else 0
    features["tls_version_is_1_1"] = 1 if (tls_detected and "1.1" in tls_version_str) else 0
    features["tls_version_is_1_0"] = 1 if (tls_detected and "1.0" in tls_version_str) else 0
    features["tls_version_is_ssl3"] = 1 if (tls_detected and ("SSLv3" in tls_version_str or "SSLv2" in tls_version_str or "0.3" in tls_version_str)) else 0
    features["tls_version_is_none"] = 1 if not tls_detected else 0

    # Cipher suite characteristics
    cipher_upper = str(cipher_suite_str or "").upper()
    is_aead = 1 if any(aead in cipher_upper for aead in ("_GCM_", "_POLY1305", "_CCM")) else 0
    is_weak = 1 if any(w in cipher_upper for w in ("NULL", "EXPORT", "RC4", "3DES", "_DES_", "_ANON_")) else 0
    is_cbc = 1 if "_CBC_" in cipher_upper else 0

    features["cipher_is_aead"] = is_aead
    features["cipher_is_cbc"] = is_cbc
    features["cipher_is_weak"] = is_weak
    features["cipher_is_modern"] = 1 if (is_aead == 1 and is_weak == 0) else 0

    # Key exchange & Forward Secrecy
    kex_upper = str(key_exchange_str or "").upper()
    features["key_exchange_is_ephemeral"] = 1 if any(e in kex_upper for e in ("ECDHE", "DHE")) else 0
    features["kex_is_ecdhe"] = 1 if "ECDHE" in kex_upper else 0
    features["kex_is_dhe"] = 1 if ("DHE" in kex_upper and "ECDHE" not in kex_upper) else 0
    features["kex_is_static_rsa"] = 1 if ("RSA" in kex_upper and not any(e in kex_upper for e in ("ECDHE", "DHE"))) else 0

    features["forward_secrecy"] = 1 if fs_val is True else (0 if fs_val is False else -1)
    features["forward_secrecy_present"] = 1 if fs_val is True else 0
    features["forward_secrecy_absent"] = 1 if (tls_detected and fs_val is False) else 0

    features["encrypted_application_data_observed"] = 1 if app_data_obs else 0
    features["plaintext_payload_observed"] = 1 if (not tls_detected and (session.get("client_payload") or session.get("server_payload") or session.get("packet_count", 0) > 0)) else 0

    metadata["tls_version"] = {
        "source": "TLS ServerHello",
        "observable": tls_detected and bool(tls_version_str),
        "raw_value": tls_version_str
    }
    metadata["cipher_suite"] = {
        "source": "TLS ServerHello",
        "observable": tls_detected and bool(cipher_suite_str),
        "raw_value": cipher_suite_str
    }
    metadata["forward_secrecy"] = {
        "source": "TLS Handshake Key Exchange Resolution",
        "observable": fs_val is not None,
        "raw_value": fs_val
    }

    # 4. X.509 Certificate Features
    cert_present = cert_info.get("certificate_present", False)
    exp_status = cert_info.get("expiration_status")
    days_left = cert_info.get("days_until_expiry")
    pk_algo = cert_info.get("public_key_algorithm")
    pk_len = cert_info.get("public_key_length")
    sig_algo = str(cert_info.get("signature_algorithm") or "")
    self_signed = cert_info.get("self_signed")
    hostname_match = cert_info.get("hostname_match")

    features["certificate_present"] = 1 if cert_present else 0
    features["certificate_is_valid"] = 1 if exp_status == "VALID" else 0
    features["certificate_is_expired"] = 1 if exp_status == "EXPIRED" else 0
    features["days_until_expiry"] = days_left if (cert_present and days_left is not None) else 0
    features["days_until_expiry_norm"] = round(days_left / 365.0, 4) if (cert_present and days_left is not None) else 0.0

    pk_is_rsa = 1 if (pk_algo == "RSA") else 0
    pk_is_ec = 1 if (pk_algo and "EC" in pk_algo) else 0
    features["public_key_is_rsa"] = pk_is_rsa
    features["public_key_is_ec"] = pk_is_ec
    features["public_key_length"] = pk_len if (cert_present and pk_len is not None) else 0

    pk_substandard = 1 if (cert_present and pk_len is not None and ((pk_is_rsa and pk_len < 2048) or (pk_is_ec and pk_len < 256))) else 0
    features["public_key_is_substandard"] = pk_substandard

    features["signature_is_weak"] = 1 if any(w in sig_algo.lower() for w in ("md5", "md2", "sha1")) else 0
    features["self_signed"] = 1 if self_signed is True else (0 if self_signed is False else -1)
    features["certificate_is_self_signed"] = 1 if self_signed is True else 0

    features["hostname_match"] = 1 if hostname_match is True else (0 if hostname_match is False else -1)
    features["hostname_matches"] = 1 if hostname_match is True else 0
    features["hostname_mismatch"] = 1 if hostname_match is False else 0

    # 4b. X.509 Certificate Chain Features
    chain_info = cert_info.get("certificate_chain", {})
    if not isinstance(chain_info, dict):
        chain_info = {}
    chain_obs = chain_info.get("chain_observable", False)
    chain_comp = chain_info.get("chain_complete", False)
    chain_stat = chain_info.get("chain_status", "UNDETERMINED")
    cert_cnt = chain_info.get("certificate_count", 0)
    val_details = chain_info.get("validation_details", {})
    if not isinstance(val_details, dict):
        val_details = {}
    sigs_ver = val_details.get("signatures_verified", False)
    ca_ver = val_details.get("ca_constraints_verified", False)
    validity_ver = val_details.get("validity_periods_verified", False)
    issuer_subj_linked = val_details.get("issuer_subject_linked", False)

    features["chain_observable"] = 1 if chain_obs else 0
    features["chain_complete"] = 1 if chain_comp else 0
    features["chain_status_valid"] = 1 if chain_stat == "VALID" else 0
    features["chain_status_invalid"] = 1 if chain_stat == "INVALID" else 0
    features["chain_status_incomplete"] = 1 if chain_stat == "INCOMPLETE" else 0
    features["certificate_count"] = cert_cnt
    features["certificate_count_norm"] = round(min(cert_cnt, 5) / 5.0, 2)
    features["chain_signatures_verified"] = 1 if sigs_ver else 0
    features["chain_ca_constraints_verified"] = 1 if ca_ver else 0
    features["chain_validity_periods_verified"] = 1 if validity_ver else 0
    features["chain_issuer_subject_linked"] = 1 if (issuer_subj_linked or sigs_ver) else 0

    metadata["certificate"] = {
        "source": "TLS Handshake Certificate Chain",
        "observable": cert_present,
        "raw_value": cert_info.get("subject")
    }
    metadata["certificate_chain"] = {
        "source": "Passive X.509 Chain Graph Validation",
        "observable": chain_obs,
        "raw_value": f"Count: {cert_cnt}, Status: {chain_stat}, Complete: {chain_comp}"
    }

    # 5. Network Flow Metrics
    pkt_count = session.get("packet_count", 0)
    duration = session.get("duration_seconds", 0.0)
    c2s_bytes = session.get("client_to_server_bytes", 0)
    s2c_bytes = session.get("server_to_client_bytes", 0)
    total_bytes = c2s_bytes + s2c_bytes

    features["packet_count"] = pkt_count
    features["packet_count_norm"] = round(min(pkt_count, 100) / 100.0, 2)
    features["duration_seconds"] = duration
    features["duration_norm"] = round(min(duration, 30.0) / 30.0, 2)
    features["client_to_server_bytes"] = c2s_bytes
    features["server_to_client_bytes"] = s2c_bytes
    features["client_bytes_ratio"] = round(c2s_bytes / total_bytes, 4) if total_bytes > 0 else 0.0

    metadata["flow_metrics"] = {
        "source": "TCP Session Reassembly",
        "observable": pkt_count > 0,
        "raw_value": f"Total Packets: {pkt_count}, Duration: {duration}s"
    }

    # 6. Deterministic Assessment & Posture Metrics
    features["finding_count"] = assessment.get("finding_count", 0)
    features["critical_count"] = assessment.get("critical_count", 0)
    features["high_count"] = assessment.get("high_count", 0)
    features["medium_count"] = assessment.get("medium_count", 0)
    features["low_count"] = assessment.get("low_count", 0)
    features["posture_score"] = posture.get("score", 0)

    metadata["posture"] = {
        "source": "Security Posture Engine",
        "observable": "score" in posture,
        "raw_value": f"Score: {posture.get('score')}, Posture: {posture.get('security_posture')}"
    }

    return {
        "session_id": session_id,
        "features": features,
        "feature_metadata": metadata
    }
