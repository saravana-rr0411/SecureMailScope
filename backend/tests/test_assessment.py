import pytest
from app.assessment.assessor import assess_session_security

def test_secure_tls12_ecdhe_aes_gcm_valid_cert():
    session = {
        "protocol": "SMTP",
        "starttls": {"status": "SECURE_TRANSITION", "upgrade_supported": True, "upgrade_accepted": True},
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "key_exchange": "ECDHE",
            "forward_secrecy": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "days_until_expiry": 300,
                "public_key_algorithm": "RSA",
                "public_key_length": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "hostname_match": True,
                "trust_validation": "NOT_OBSERVABLE",
                "self_signed": False
            }
        }
    }
    res = assess_session_security(session)
    assert res["security_status"] == "SECURE"
    assert res["finding_count"] == 0
    assert res["critical_count"] == 0
    assert res["high_count"] == 0
    assert res["medium_count"] == 0


def test_deprecated_tls_version():
    session = {
        "protocol": "SMTP",
        "starttls": {"status": "SECURE_TRANSITION"},
        "tls": {
            "detected": True,
            "version": "TLSv1.0",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "key_exchange": "ECDHE",
            "forward_secrecy": True,
            "certificate": {"certificate_present": True, "expiration_status": "VALID", "public_key_length": 2048}
        }
    }
    res = assess_session_security(session)
    assert res["security_status"] == "AT_RISK"
    assert res["high_count"] >= 1
    assert any(f["category"] == "TLS_CONFIGURATION" and "Deprecated Protocol Version" in f["title"] for f in res["findings"])


def test_weak_cipher_rc4_and_3des():
    session_rc4 = {
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_RSA_WITH_RC4_128_SHA",
            "key_exchange": "RSA",
            "forward_secrecy": False,
            "certificate": {"certificate_present": False}
        }
    }
    res_rc4 = assess_session_security(session_rc4)
    assert res_rc4["security_status"] == "AT_RISK"
    assert any(f["category"] == "CIPHER_SUITE" and "RC4" in f["title"] for f in res_rc4["findings"])


def test_no_forward_secrecy():
    session_static_rsa = {
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_RSA_WITH_AES_128_GCM_SHA256",
            "key_exchange": "RSA",
            "forward_secrecy": False,
            "certificate": {"certificate_present": True, "expiration_status": "VALID", "public_key_length": 2048}
        }
    }
    res = assess_session_security(session_static_rsa)
    assert res["security_status"] == "AT_RISK"
    assert any(f["category"] == "KEY_EXCHANGE" and "Lack of Forward Secrecy" in f["title"] for f in res["findings"])


def test_expired_certificate():
    session = {
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "key_exchange": "ECDHE",
            "forward_secrecy": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "EXPIRED",
                "valid_to": "2024-01-01T00:00:00Z",
                "days_until_expiry": -100
            }
        }
    }
    res = assess_session_security(session)
    assert res["security_status"] == "AT_RISK"
    assert any(f["category"] == "CERTIFICATE" and "Expired" in f["title"] for f in res["findings"])


def test_weak_rsa_key_length():
    session = {
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "key_exchange": "ECDHE",
            "forward_secrecy": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "public_key_algorithm": "RSA",
                "public_key_length": 1024
            }
        }
    }
    res = assess_session_security(session)
    assert res["security_status"] == "AT_RISK"
    assert any(f["category"] == "CERTIFICATE" and "Weak RSA Key Length" in f["title"] for f in res["findings"])


def test_weak_signature_algorithm():
    session = {
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "key_exchange": "ECDHE",
            "forward_secrecy": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "public_key_length": 2048,
                "signature_algorithm": "sha1WithRSAEncryption"
            }
        }
    }
    res = assess_session_security(session)
    assert res["security_status"] == "AT_RISK"
    assert any(f["category"] == "CERTIFICATE" and "Deprecated Certificate Signature" in f["title"] for f in res["findings"])


def test_hostname_mismatch():
    session = {
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "key_exchange": "ECDHE",
            "forward_secrecy": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "public_key_length": 2048,
                "hostname_match": False,
                "subject_alternative_names": ["mail.other.com"],
                "common_name": "mail.other.com"
            }
        }
    }
    res = assess_session_security(session)
    assert res["security_status"] == "AT_RISK"
    assert any(f["category"] == "CERTIFICATE" and "Hostname Mismatch" in f["title"] for f in res["findings"])


def test_starttls_incomplete():
    session = {
        "protocol": "SMTP",
        "starttls": {
            "status": "INCOMPLETE",
            "upgrade_supported": True,
            "upgrade_requested": True,
            "upgrade_accepted": True,
            "tls_transition_observed": False
        },
        "tls": {
            "detected": False
        }
    }
    res = assess_session_security(session)
    assert res["security_status"] == "AT_RISK"
    assert any(f["category"] == "PROTOCOL_NEGOTIATION" and "Incomplete STARTTLS" in f["title"] for f in res["findings"])


def test_starttls_rejected():
    session = {
        "protocol": "SMTP",
        "starttls": {
            "status": "NOT_USED",
            "upgrade_supported": True,
            "upgrade_requested": True,
            "upgrade_accepted": False
        },
        "tls": {
            "detected": False
        }
    }
    res = assess_session_security(session)
    assert res["security_status"] == "AT_RISK"
    assert any(f["category"] == "PROTOCOL_NEGOTIATION" and "Rejected" in f["title"] for f in res["findings"])


def test_starttls_not_requested():
    session = {
        "protocol": "SMTP",
        "starttls": {
            "status": "NOT_USED",
            "upgrade_supported": True,
            "upgrade_requested": False
        },
        "tls": {
            "detected": False
        }
    }
    res = assess_session_security(session)
    assert res["security_status"] == "AT_RISK"
    assert any(f["category"] == "PROTOCOL_NEGOTIATION" and "Not Utilized" in f["title"] for f in res["findings"])


def test_unavailable_certificate_trust_validation():
    # Passively captured certificate with trust_validation = NOT_OBSERVABLE
    session = {
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "key_exchange": "ECDHE",
            "forward_secrecy": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "public_key_length": 2048,
                "self_signed": False,
                "trust_validation": "NOT_OBSERVABLE",
                "hostname_match": True
            }
        }
    }
    res = assess_session_security(session)
    assert res["security_status"] == "SECURE"
    # Ensure no false un-trusted finding was generated
    assert not any("Trust" in f["title"] or "Untrusted" in f["title"] for f in res["findings"])


def test_self_signed_certificate_finding():
    """Verify genuinely self-signed certificate generates HIGH severity finding in Stage 06."""
    session = {
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "key_exchange": "ECDHE",
            "forward_secrecy": True,
            "certificate": {
                "certificate_present": True,
                "common_name": "mail.example.test",
                "subject": "CN=mail.example.test",
                "issuer": "CN=mail.example.test",
                "expiration_status": "VALID",
                "days_until_expiry": 365,
                "public_key_algorithm": "RSA",
                "public_key_length": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "hostname_match": True,
                "trust_validation": "NOT_OBSERVABLE",
                "self_signed": True
            }
        }
    }
    res = assess_session_security(session)
    assert res["security_status"] == "AT_RISK"
    assert res["high_count"] >= 1
    assert any(f["category"] == "CERTIFICATE" and f["title"] == "Self-Signed Certificate" and f["severity"] == "HIGH" for f in res["findings"])

