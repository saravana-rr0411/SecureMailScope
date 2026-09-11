import pytest
from app.tls.tls_parser import analyze_tls_session
from app.assessment.assessor import assess_session_security
from app.posture.posture_engine import calculate_security_posture
from app.capture.pcap_reader import analyze_pcap


def test_scenario_a_complete_handshake_and_encrypted_app_data():
    """A. Complete TLS handshake + encrypted application data -> PFS verified, payload observed."""
    res = analyze_pcap("dataset/tls_test_email.pcap")
    assert len(res["sessions"]) > 0
    s = res["sessions"][0]
    tls = s["tls"]

    assert tls["detected"] is True
    assert tls["handshake_status"] == "COMPLETE"
    assert tls["handshake_complete"] is True
    assert tls["encrypted_application_data_observed"] is True
    assert tls["ephemeral_key_exchange_verified"] is True
    assert s["posture"]["security_posture"] == "SECURE"
    assert s["posture"]["session_completion"] == "COMPLETE"


def test_scenario_b_c_ecdhe_aead_but_incomplete_handshake():
    """
    B & C. ECDHE cipher + AEAD negotiated, but incomplete handshake (01_secure_smtp_tls12.pcap)
    -> PFS indicated (not verified), payload not observed, handshake INCOMPLETE, score preserved (100).
    """
    res = analyze_pcap("dataset/01_secure_smtp_tls12.pcap")
    assert len(res["sessions"]) > 0
    s = res["sessions"][0]
    tls = s["tls"]

    assert tls["detected"] is True
    assert tls["version"] == "TLSv1.2"
    assert tls["cipher_suite"] == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    assert tls["handshake_status"] == "INCOMPLETE"
    assert tls["handshake_complete"] is False
    assert tls["encrypted_application_data_observed"] is False
    assert tls["ephemeral_key_exchange_verified"] is False
    # Cryptographic score is preserved without artificial deduction
    assert s["posture"]["score"] == 100
    assert s["posture"]["configuration_posture"] == "SECURE"
    assert s["posture"]["session_completion"] == "INCOMPLETE"
    assert "captured TLS handshake is incomplete" in s["posture"]["explanation"]


def test_scenario_d_valid_leaf_plus_self_signed_root():
    """D. Valid leaf + self-signed root -> Root CA self-signature must NOT create SELF_SIGNED finding on leaf."""
    res = analyze_pcap("dataset/01_secure_smtp_tls12.pcap")
    s = res["sessions"][0]
    cert = s["tls"]["certificate"]

    assert cert["certificate_present"] is True
    assert cert["self_signed"] is False  # Leaf is NOT self-signed
    assert cert["certificate_chain"]["chain_status"] == "VALID"
    # Verify no SELF_SIGNED_CERTIFICATE finding is attributed to leaf
    findings = [f["title"] for f in s["assessment"]["findings"]]
    assert not any("self-signed" in f.lower() for f in findings)


def test_scenario_e_actually_self_signed_leaf():
    """E. Actually self-signed leaf -> SELF_SIGNED finding generated."""
    res = analyze_pcap("dataset/05_self_signed_certificate.pcap")
    s = res["sessions"][0]
    cert = s["tls"]["certificate"]

    assert cert["certificate_present"] is True
    assert cert["self_signed"] is True  # Leaf is self-signed
    findings = [f["title"] for f in s["assessment"]["findings"]]
    assert any("self-signed" in f.lower() for f in findings)


def test_scenario_f_expired_certificate():
    """F. Expired certificate -> correct certificate finding."""
    res = analyze_pcap("dataset/06_expired_certificate.pcap")
    s = res["sessions"][0]
    cert = s["tls"]["certificate"]

    assert cert["expiration_status"] == "EXPIRED"
    findings = [f["title"] for f in s["assessment"]["findings"]]
    assert any("expired" in f.lower() for f in findings)


def test_scenario_g_incomplete_chain():
    """G. Incomplete chain -> INCOMPLETE chain status when issuer is missing."""
    # Synthesize certificate info with missing issuer
    cert_info = {
        "certificate_present": True,
        "certificate_chain": {
            "chain_observable": True,
            "chain_status": "INCOMPLETE",
            "issuer_relationships": [
                {
                    "child_subject": "CN=mail.example.com",
                    "child_common_name": "mail.example.com",
                    "issuer_subject": "CN=Missing Intermediate CA",
                    "issuer_common_name": "Missing Intermediate CA",
                    "issuer_found": False,
                    "is_self_signed": False
                }
            ]
        }
    }
    from app.assessment.rules import evaluate_certificate_chain_rule
    findings = evaluate_certificate_chain_rule(cert_info)
    assert any("incomplete" in f["title"].lower() for f in findings)


def test_scenario_h_invalid_chain():
    """H. Invalid chain -> INVALID chain status when signature fails."""
    res = analyze_pcap("dataset/09_sha1_signature_certificate.pcap")
    s = res["sessions"][0]
    cert = s["tls"]["certificate"]
    assert cert["certificate_chain"]["chain_status"] == "INVALID"


def test_scenario_i_starttls_accepted_but_handshake_incomplete():
    """I. STARTTLS accepted but TLS handshake incomplete -> status reflects reality."""
    res = analyze_pcap("dataset/01_secure_smtp_tls12.pcap")
    s = res["sessions"][0]
    st = s["starttls"]
    tls = s["tls"]

    assert st["upgrade_accepted"] is True
    assert st["tls_transition_observed"] is True
    assert tls["handshake_status"] == "INCOMPLETE"


def test_scenario_j_secure_completed_session():
    """J. Secure completed session -> existing secure behavior preserved."""
    res = analyze_pcap("dataset/tls_test_email.pcap")
    s = res["sessions"][0]
    assert s["posture"]["score"] == 100
    assert s["posture"]["security_posture"] == "SECURE"
    assert s["posture"]["session_completion"] == "COMPLETE"
    assert len(s["assessment"]["findings"]) == 0
