import pytest
from app.ml.anomaly_detector import (
    CryptographicAnomalyDetector,
    create_synthetic_development_baseline
)


@pytest.fixture
def clean_detector():
    """Provides a fresh, untrained detector instance for each test."""
    return CryptographicAnomalyDetector(contamination="auto", random_state=42)


def test_no_trained_model(clean_detector):
    """Predicting without training returns BASELINE_NOT_TRAINED status without fake predictions."""
    sample_session = {
        "session_id": "TCP-TEST",
        "protocol": "SMTP",
        "tls": {"detected": True}
    }
    res = clean_detector.predict(sample_session)
    assert res["status"] == "BASELINE_NOT_TRAINED"
    assert res["anomaly_detected"] is None
    assert res["anomaly_score"] is None
    assert res["prediction"] == "NOT_EVALUATED"
    assert res["confidence"] == "LOW"
    assert res["data_quality"] == "LIMITED"
    assert res["model_metadata"]["trained"] is False


def test_empty_baseline(clean_detector):
    """Attempting to train on empty baseline fails gracefully."""
    res = clean_detector.train_baseline([])
    assert res["success"] is False
    assert res["error"] == "INSUFFICIENT_BASELINE"
    assert clean_detector.is_trained is False


def test_insufficient_baseline(clean_detector):
    """Attempting to train on fewer than 5 baseline samples fails gracefully."""
    few_sessions = create_synthetic_development_baseline(count=3)
    res = clean_detector.train_baseline(few_sessions)
    assert res["success"] is False
    assert res["error"] == "INSUFFICIENT_BASELINE"
    assert clean_detector.is_trained is False


def test_baseline_training(clean_detector):
    """Baseline training on 20 synthetic normal sessions succeeds and updates model metadata."""
    baseline = create_synthetic_development_baseline(count=20)
    res = clean_detector.train_baseline(baseline)
    assert res["success"] is True
    assert res["baseline_size"] == 20
    assert clean_detector.is_trained is True
    assert clean_detector.model is not None


def test_normal_prediction(clean_detector):
    """A normal session matching baseline distribution is predicted as NORMAL."""
    baseline = create_synthetic_development_baseline(count=25)
    clean_detector.train_baseline(baseline)

    # Normal sample conforming to baseline profile
    normal_sample = {
        "session_id": "TCP-NORM-01",
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
            "client_hello": {"server_name": "mail.example.test"},
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "days_until_expiry": 350,
                "public_key_algorithm": "RSA",
                "public_key_length": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "self_signed": True,
                "hostname_match": True
            }
        },
        "packet_count": 20,
        "duration_seconds": 0.3,
        "client_to_server_bytes": 450,
        "server_to_client_bytes": 1800,
        "assessment": {"finding_count": 0, "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0},
        "posture": {"score": 100, "security_posture": "SECURE"}
    }

    res = clean_detector.predict(normal_sample)
    assert res["status"] == "COMPLETED"
    assert res["prediction"] == "NORMAL"
    assert res["anomaly_detected"] is False
    assert res["data_quality"] == "GOOD"
    assert res["confidence"] in ("HIGH", "MEDIUM")


def test_anomalous_prediction(clean_detector):
    """An intentionally modified session (SSLv3, RC4, static RSA, missing cert) is detected as ANOMALOUS."""
    baseline = create_synthetic_development_baseline(count=25)
    clean_detector.train_baseline(baseline)

    anomalous_sample = {
        "session_id": "TCP-ANOM-01",
        "protocol": "SMTP",
        "protocol_confidence": "HIGH",
        "starttls": {
            "status": "NOT_USED",
            "upgrade_supported": True,
            "upgrade_requested": False,
            "upgrade_accepted": False,
            "tls_transition_observed": False
        },
        "tls": {
            "detected": True,
            "version": "SSLv3",
            "cipher_suite": "TLS_RSA_WITH_RC4_128_MD5",
            "key_exchange": "RSA",
            "forward_secrecy": False,
            "encrypted_application_data_observed": False,
            "certificate": {
                "certificate_present": False,
                "expiration_status": "EXPIRED",
                "hostname_match": False
            }
        },
        "packet_count": 4,
        "duration_seconds": 0.01,
        "client_to_server_bytes": 50,
        "server_to_client_bytes": 100,
        "assessment": {"finding_count": 4, "critical_count": 1, "high_count": 2, "medium_count": 1, "low_count": 0},
        "posture": {"score": 15, "security_posture": "AT_RISK"}
    }

    res = clean_detector.predict(anomalous_sample)
    assert res["status"] == "COMPLETED"
    assert res["prediction"] == "ANOMALOUS"
    assert res["anomaly_detected"] is True
    assert res["anomaly_score"] < 0.0


def test_explanation_generation(clean_detector):
    """Feature deviation explanation layer generates factual, explainable strings."""
    baseline = create_synthetic_development_baseline(count=25)
    clean_detector.train_baseline(baseline)

    deviated_sample = {
        "session_id": "TCP-DEV-01",
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.0",
            "cipher_suite": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            "forward_secrecy": False,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "EXPIRED",
                "hostname_match": False
            }
        },
        "posture": {"score": 35}
    }

    res = clean_detector.predict(deviated_sample)
    explanations = res["explanation"]
    assert len(explanations) > 0
    assert any("Forward Secrecy" in exp for exp in explanations)
    assert any("TLS version" in exp or "Cipher family" in exp or "Certificate" in exp for exp in explanations)


def test_missing_features_handling(clean_detector):
    """Sessions with unobservable or missing features return LIMITED data_quality without failure."""
    baseline = create_synthetic_development_baseline(count=25)
    clean_detector.train_baseline(baseline)

    sparse_session = {
        "session_id": "TCP-SPARSE",
        "protocol": "UNKNOWN"
    }

    res = clean_detector.predict(sparse_session)
    assert res["status"] == "COMPLETED"
    assert res["data_quality"] == "LIMITED"
    assert "packet_count" in res["features_used"]


def test_deterministic_random_state():
    """Two detector instances with same random_state produce identical scores on the same data."""
    baseline = create_synthetic_development_baseline(count=20)

    det1 = CryptographicAnomalyDetector(contamination="auto", random_state=42)
    det1.train_baseline(baseline)

    det2 = CryptographicAnomalyDetector(contamination="auto", random_state=42)
    det2.train_baseline(baseline)

    test_sample = create_synthetic_development_baseline(count=1)[0]

    res1 = det1.predict(test_sample)
    res2 = det2.predict(test_sample)

    assert res1["anomaly_score"] == res2["anomaly_score"]
    assert res1["prediction"] == res2["prediction"]


def test_model_metadata(clean_detector):
    """Model status reflects configuration, training state, and baseline size."""
    status_before = clean_detector.get_model_status()
    assert status_before["trained"] is False
    assert status_before["baseline_size"] == 0

    clean_detector.train_baseline(create_synthetic_development_baseline(count=15))
    status_after = clean_detector.get_model_status()
    assert status_after["trained"] is True
    assert status_after["baseline_size"] == 15
    assert status_after["model"] == "IsolationForest"
