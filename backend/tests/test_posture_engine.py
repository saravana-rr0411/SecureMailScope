import pytest
from app.posture.posture_engine import calculate_security_posture, correlate_session_evidence

def test_modern_secure_tls_session():
    session = {
        "session_id": "TCP-001",
        "protocol": "SMTP",
        "starttls": {"status": "SECURE_TRANSITION", "upgrade_supported": True, "upgrade_accepted": True, "tls_transition_observed": True},
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "key_exchange": "ECDHE",
            "forward_secrecy": True,
            "client_hello": {"server_name": "mail.example.com"},
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "days_until_expiry": 200,
                "public_key_algorithm": "RSA",
                "public_key_length": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "hostname_match": True,
                "subject_alternative_names": ["mail.example.com"]
            },
            "evidence": [{"type": "handshake_message", "message": "ServerHello"}]
        },
        "assessment": {
            "security_status": "SECURE",
            "finding_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "findings": []
        }
    }
    res = calculate_security_posture(session)
    assert res["score"] == 100
    assert res["risk_level"] == "LOW_RISK"
    assert res["security_posture"] == "SECURE"
    assert res["score_confidence"] == "HIGH"
    assert len(res["correlations"]) == 0
    assert res["dimensions"]["tls_security"] >= 90
    assert res["dimensions"]["forward_secrecy"] == 100


def test_incomplete_starttls_session():
    session = {
        "session_id": "TCP-002",
        "protocol": "SMTP",
        "starttls": {
            "status": "INCOMPLETE",
            "upgrade_supported": True,
            "upgrade_requested": True,
            "upgrade_accepted": True,
            "tls_transition_observed": False,
            "evidence": [{"type": "response", "value": "220 Ready to start TLS"}]
        },
        "tls": {"detected": False},
        "assessment": {
            "security_status": "AT_RISK",
            "finding_count": 1,
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
            "findings": [{
                "finding_id": "SEC-001",
                "category": "PROTOCOL_NEGOTIATION",
                "title": "Incomplete STARTTLS Transition",
                "severity": "HIGH",
                "reason": "Handshake missing",
                "evidence": [{"type": "response", "value": "220 Ready"}]
            }]
        }
    }
    res = calculate_security_posture(session)
    assert res["security_posture"] == "INCOMPLETE"
    assert res["score"] == 75  # 100 - 25 (High)
    assert res["risk_level"] == "MODERATE_RISK"
    assert any(c["correlation_id"] == "CORRELATION-001" for c in res["correlations"])


def test_deprecated_tls_version():
    session = {
        "session_id": "TCP-003",
        "protocol": "SMTP",
        "starttls": {"status": "SECURE_TRANSITION"},
        "tls": {
            "detected": True,
            "version": "TLSv1.0",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "forward_secrecy": True,
            "evidence": [{"type": "handshake_message", "message": "ServerHello"}]
        },
        "assessment": {
            "security_status": "AT_RISK",
            "finding_count": 1,
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
            "findings": [{
                "finding_id": "SEC-001",
                "category": "TLS_CONFIGURATION",
                "title": "Deprecated Protocol Version (TLSv1.0)",
                "severity": "HIGH",
                "evidence": []
            }]
        }
    }
    res = calculate_security_posture(session)
    assert res["score"] == 75  # 100 - 25
    assert res["risk_level"] == "MODERATE_RISK"
    assert any(c["correlation_id"] == "CORRELATION-003" for c in res["correlations"])


def test_weak_cipher_suite():
    session = {
        "session_id": "TCP-004",
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA",
            "forward_secrecy": False,
            "evidence": [{"type": "cipher_suite", "value": "RC4"}]
        },
        "assessment": {
            "security_status": "AT_RISK",
            "finding_count": 2,
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 1,
            "low_count": 0,
            "findings": [
                {"finding_id": "SEC-001", "severity": "HIGH", "title": "Insecure RC4 Stream Cipher", "evidence": []},
                {"finding_id": "SEC-002", "severity": "MEDIUM", "title": "Lack of Forward Secrecy", "evidence": []}
            ]
        }
    }
    res = calculate_security_posture(session)
    assert res["score"] == 60  # 100 - 25 (High RC4) - 15 (Medium FS)
    assert res["risk_level"] == "HIGH_RISK"
    assert any(c["correlation_id"] == "CORRELATION-004" for c in res["correlations"])
    assert any(c["correlation_id"] == "CORRELATION-005" for c in res["correlations"])


def test_no_forward_secrecy():
    session = {
        "session_id": "TCP-005",
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "forward_secrecy": False,
            "evidence": []
        },
        "assessment": {
            "security_status": "AT_RISK",
            "finding_count": 1,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 1,
            "low_count": 0,
            "findings": [
                {"finding_id": "SEC-001", "severity": "MEDIUM", "title": "Lack of Forward Secrecy", "evidence": []}
            ]
        }
    }
    res = calculate_security_posture(session)
    assert res["score"] == 85  # 100 - 15
    assert res["risk_level"] == "MODERATE_RISK"
    assert any(c["correlation_id"] == "CORRELATION-005" for c in res["correlations"])
    assert res["dimensions"]["forward_secrecy"] == 0


def test_certificate_expired_problem():
    session = {
        "session_id": "TCP-006",
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "forward_secrecy": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "EXPIRED",
                "valid_from": "2020-01-01T00:00:00Z",
                "valid_to": "2021-01-01T00:00:00Z",
                "evidence": [{"type": "validity", "status": "EXPIRED"}]
            }
        },
        "assessment": {
            "security_status": "AT_RISK",
            "finding_count": 1,
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0,
            "findings": [
                {"finding_id": "SEC-001", "severity": "HIGH", "title": "Expired X.509 Certificate", "evidence": []}
            ]
        }
    }
    res = calculate_security_posture(session)
    assert res["score"] == 75  # 100 - 25
    assert res["risk_level"] == "MODERATE_RISK"
    assert any(c["correlation_id"] == "CORRELATION-007" for c in res["correlations"])


def test_hostname_mismatch():
    session = {
        "session_id": "TCP-007",
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "forward_secrecy": True,
            "client_hello": {"server_name": "mail.target.com"},
            "certificate": {
                "certificate_present": True,
                "hostname_match": False,
                "common_name": "mail.spoofed.com",
                "subject_alternative_names": ["mail.spoofed.com"],
                "evidence": []
            }
        },
        "assessment": {
            "security_status": "AT_RISK",
            "finding_count": 1,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 1,
            "low_count": 0,
            "findings": [
                {"finding_id": "SEC-001", "severity": "MEDIUM", "title": "Certificate Hostname Mismatch", "evidence": []}
            ]
        }
    }
    res = calculate_security_posture(session)
    assert res["score"] == 85  # 100 - 15
    assert any(c["correlation_id"] == "CORRELATION-006" for c in res["correlations"])


def test_multiple_simultaneous_weaknesses():
    session = {
        "session_id": "TCP-008",
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.0",
            "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "forward_secrecy": False,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "EXPIRED",
                "evidence": []
            }
        },
        "assessment": {
            "security_status": "AT_RISK",
            "finding_count": 3,
            "critical_count": 0,
            "high_count": 2,
            "medium_count": 1,
            "low_count": 0,
            "findings": [
                {"finding_id": "SEC-001", "severity": "HIGH", "title": "Deprecated Protocol (TLS 1.0)", "evidence": []},
                {"finding_id": "SEC-002", "severity": "HIGH", "title": "Expired Certificate", "evidence": []},
                {"finding_id": "SEC-003", "severity": "MEDIUM", "title": "Weak 3DES Cipher", "evidence": []}
            ]
        }
    }
    res = calculate_security_posture(session)
    # Deductions: 25 (High) + 25 (High) + 15 (Medium) = 65 -> Score 35
    assert res["score"] == 35
    assert res["risk_level"] == "CRITICAL_RISK"
    assert any(c["correlation_id"] == "CORRELATION-008" for c in res["correlations"])


def test_missing_unobservable_evidence():
    session = {
        "session_id": "TCP-009",
        "protocol": "UNKNOWN",
        "starttls": {"status": "NOT_OBSERVABLE"},
        "tls": {"detected": False},
        "assessment": {"findings": []}
    }
    res = calculate_security_posture(session)
    assert res["score"] == 0
    assert res["score_confidence"] == "LOW"
    assert res["security_posture"] == "NOT_OBSERVABLE"


def test_critical_finding_score_override():
    session = {
        "session_id": "TCP-010",
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_RSA_WITH_NULL_SHA",
            "forward_secrecy": False
        },
        "assessment": {
            "security_status": "AT_RISK",
            "finding_count": 1,
            "critical_count": 1,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "findings": [
                {"finding_id": "SEC-001", "severity": "CRITICAL", "title": "NULL Encryption", "evidence": []}
            ]
        }
    }
    res = calculate_security_posture(session)
    # Score is 100 - 35 = 65 (which would numerically be HIGH_RISK, but critical override guarantees critical/high)
    assert res["score"] == 65
    assert res["risk_level"] in ("CRITICAL_RISK", "HIGH_RISK")
    assert res["risk_level"] != "LOW_RISK"
    assert res["risk_level"] != "MODERATE_RISK"


def test_score_boundaries_clamp():
    # Massive amount of findings that exceed 100 deduction
    session = {
        "session_id": "TCP-011",
        "protocol": "SMTP",
        "tls": {"detected": True},
        "assessment": {
            "finding_count": 5,
            "critical_count": 3,  # 3 * 35 = 105
            "high_count": 2,      # 2 * 25 = 50 -> total 155 deduction
            "medium_count": 0,
            "low_count": 0,
            "findings": [{"finding_id": f"SEC-{i}", "severity": "CRITICAL", "evidence": []} for i in range(3)]
        }
    }
    res = calculate_security_posture(session)
    assert res["score"] == 0  # Clamped at 0, not negative


def test_evidence_preservation():
    raw_ev = {"type": "pcap_frame", "packet_number": 12, "detail": "ClientHello observed"}
    session = {
        "session_id": "TCP-012",
        "protocol": "SMTP",
        "starttls": {"status": "SECURE_TRANSITION"},
        "tls": {
            "detected": True,
            "version": "TLSv1.0",
            "evidence": [raw_ev]
        },
        "assessment": {
            "findings": [{"finding_id": "SEC-001", "severity": "HIGH", "evidence": [raw_ev]}]
        }
    }
    res = calculate_security_posture(session)
    assert raw_ev in res["evidence"]


def test_double_counting_prevention():
    # Single high finding yields exactly -25 deduction
    session = {
        "session_id": "TCP-013",
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.0",
            "forward_secrecy": True
        },
        "assessment": {
            "findings": [
                {"finding_id": "SEC-001", "severity": "HIGH", "title": "Deprecated TLS 1.0", "evidence": []}
            ]
        }
    }
    res = calculate_security_posture(session)
    assert res["score"] == 75
