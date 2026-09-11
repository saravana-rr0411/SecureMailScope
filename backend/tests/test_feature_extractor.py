import pytest
from app.ml.feature_extractor import extract_session_features

def test_extract_secure_tls_session():
    session = {
        "session_id": "TCP-001",
        "protocol": "SMTP",
        "protocol_confidence": "HIGH",
        "starttls": {
            "status": "SECURE_TRANSITION",
            "upgrade_supported": True,
            "upgrade_requested": True,
            "upgrade_accepted": True,
            "tls_transition_observed": True
        },
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "key_exchange": "ECDHE (x25519)",
            "forward_secrecy": True,
            "encrypted_application_data_observed": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "days_until_expiry": 364,
                "public_key_algorithm": "RSA",
                "public_key_length": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "self_signed": True,
                "hostname_match": True,
                "subject": "CN=mail.example.test"
            }
        },
        "packet_count": 18,
        "duration_seconds": 0.05,
        "client_to_server_bytes": 1000,
        "server_to_client_bytes": 2000,
        "assessment": {
            "finding_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0
        },
        "posture": {
            "score": 100,
            "security_posture": "SECURE"
        }
    }

    res = extract_session_features(session)
    feats = res["features"]
    meta = res["feature_metadata"]

    assert res["session_id"] == "TCP-001"
    assert feats["protocol_is_smtp"] == 1
    assert feats["protocol_is_imap"] == 0
    assert feats["starttls_upgrade_supported"] == 1
    assert feats["starttls_transition_observed"] == 1
    assert feats["tls_detected"] == 1
    assert feats["tls_version_numeric"] == 1.2
    assert feats["cipher_is_aead"] == 1
    assert feats["cipher_is_weak"] == 0
    assert feats["key_exchange_is_ephemeral"] == 1
    assert feats["forward_secrecy"] == 1
    assert feats["encrypted_application_data_observed"] == 1
    assert feats["certificate_present"] == 1
    assert feats["certificate_is_valid"] == 1
    assert feats["days_until_expiry"] == 364
    assert feats["public_key_is_rsa"] == 1
    assert feats["public_key_length"] == 2048
    assert feats["signature_is_weak"] == 0
    assert feats["self_signed"] == 1
    assert feats["hostname_match"] == 1
    assert feats["packet_count"] == 18
    assert feats["posture_score"] == 100

    assert meta["tls_version"]["observable"] is True
    assert meta["tls_version"]["raw_value"] == "TLSv1.2"


def test_extract_incomplete_starttls_session():
    session = {
        "session_id": "TCP-002",
        "protocol": "SMTP",
        "protocol_confidence": "HIGH",
        "starttls": {
            "status": "INCOMPLETE",
            "upgrade_supported": True,
            "upgrade_requested": True,
            "upgrade_accepted": True,
            "tls_transition_observed": False
        },
        "tls": {"detected": False},
        "packet_count": 8,
        "duration_seconds": 0.02,
        "client_to_server_bytes": 200,
        "server_to_client_bytes": 400,
        "assessment": {
            "finding_count": 1,
            "critical_count": 0,
            "high_count": 1,
            "medium_count": 0,
            "low_count": 0
        },
        "posture": {
            "score": 75,
            "security_posture": "INCOMPLETE"
        }
    }

    res = extract_session_features(session)
    feats = res["features"]

    assert feats["starttls_is_incomplete"] == 1
    assert feats["tls_detected"] == 0
    assert feats["tls_version_numeric"] == 0.0
    assert feats["certificate_present"] == 0
    assert feats["finding_count"] == 1
    assert feats["high_count"] == 1
    assert feats["posture_score"] == 75


def test_extract_missing_tls_information():
    session = {
        "session_id": "TCP-003",
        "protocol": "POP3",
        "protocol_confidence": "MEDIUM",
        "starttls": {"status": "NOT_USED", "upgrade_supported": False},
        "tls": {"detected": False},
        "packet_count": 6,
        "duration_seconds": 0.01,
        "client_to_server_bytes": 150,
        "server_to_client_bytes": 300,
        "assessment": {},
        "posture": {"score": 25}
    }

    res = extract_session_features(session)
    feats = res["features"]

    assert feats["protocol_is_pop3"] == 1
    assert feats["protocol_is_smtp"] == 0
    assert feats["tls_detected"] == 0
    assert feats["forward_secrecy"] == -1
    assert feats["hostname_match"] == -1
    assert feats["certificate_present"] == 0


def test_extract_certificate_edge_cases():
    session = {
        "session_id": "TCP-004",
        "protocol": "IMAP",
        "tls": {
            "detected": True,
            "version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "forward_secrecy": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "EXPIRED",
                "days_until_expiry": -45,
                "public_key_algorithm": "EC (secp256r1)",
                "public_key_length": 256,
                "signature_algorithm": "md5WithRSAEncryption",
                "self_signed": False,
                "hostname_match": False
            }
        }
    }

    res = extract_session_features(session)
    feats = res["features"]

    assert feats["protocol_is_imap"] == 1
    assert feats["tls_version_numeric"] == 1.3
    assert feats["certificate_is_valid"] == 0
    assert feats["days_until_expiry"] == -45
    assert feats["public_key_is_rsa"] == 0
    assert feats["public_key_is_ec"] == 1
    assert feats["public_key_length"] == 256
    assert feats["signature_is_weak"] == 1
    assert feats["self_signed"] == 0
    assert feats["hostname_match"] == 0


def test_extract_unknown_unobservable_session():
    session = {
        "session_id": "TCP-005",
        "protocol": "UNKNOWN"
    }

    res = extract_session_features(session)
    feats = res["features"]
    meta = res["feature_metadata"]

    assert feats["protocol_is_smtp"] == 0
    assert feats["protocol_is_imap"] == 0
    assert feats["protocol_is_pop3"] == 0
    assert feats["protocol_confidence_score"] == 0.0
    assert feats["tls_detected"] == 0
    assert meta["protocol"]["observable"] is False
