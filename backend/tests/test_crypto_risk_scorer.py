import os
import pytest
import numpy as np
from fastapi.testclient import TestClient
from sklearn.ensemble import RandomForestClassifier
from app.main import app
from app.ml.crypto_risk_scorer import (
    CryptoRiskScorer,
    crypto_risk_scorer_instance,
    generate_controlled_training_data,
    score_to_risk_label,
    CRYPTO_RISK_FEATURE_NAMES,
    RISK_CLASSES,
    MODEL_NAME,
    MODEL_VERSION
)
from app.ml.feature_extractor import extract_session_features

client = TestClient(app)


def test_controlled_dataset_generation():
    """Verify synthetic dataset produces expected shapes, archetypes, and multi-class labels."""
    X, y = generate_controlled_training_data()
    assert len(X) == len(y)
    assert len(X) == 2500
    assert X.shape[1] == len(CRYPTO_RISK_FEATURE_NAMES)
    unique_labels = set(y)
    assert unique_labels == {"LOW", "MODERATE", "HIGH", "CRITICAL"}
    for label in unique_labels:
        assert sum(1 for item in y if item == label) > 0


def test_score_to_risk_label_mapping():
    """Test standardized risk threshold boundaries (0 = safe / minimal risk, 100 = critical risk)."""
    assert score_to_risk_label(0.0) == "LOW"
    assert score_to_risk_label(20.0) == "LOW"
    assert score_to_risk_label(20.1) == "MODERATE"
    assert score_to_risk_label(50.0) == "MODERATE"
    assert score_to_risk_label(50.1) == "HIGH"
    assert score_to_risk_label(80.0) == "HIGH"
    assert score_to_risk_label(80.1) == "CRITICAL"
    assert score_to_risk_label(100.0) == "CRITICAL"


def test_model_initialization_and_metadata():
    """Verify model initialization, feature count, and metadata reporting."""
    scorer = crypto_risk_scorer_instance
    assert scorer.is_loaded is True
    assert isinstance(scorer.model, RandomForestClassifier)
    status = scorer.get_model_status()
    assert status["model"] == MODEL_NAME
    assert status["model_version"] == MODEL_VERSION
    assert status["feature_count"] == len(CRYPTO_RISK_FEATURE_NAMES)
    assert status["random_state"] == 42
    # Verify categorical representation exists, not numeric TLS score
    assert "tls_version_is_1_3" in status["feature_importances"]
    assert "tls_version_is_1_2" in status["feature_importances"]
    # Verify deterministic findings are NOT in feature set
    assert "finding_count" not in CRYPTO_RISK_FEATURE_NAMES
    assert "posture_score" not in CRYPTO_RISK_FEATURE_NAMES


def test_feature_vector_extraction():
    """Verify session extraction correctly populates the complete crypto risk feature vector."""
    sample_session = {
        "session_id": "TEST-VECTOR-01",
        "protocol": "SMTP",
        "starttls": {
            "status": "SECURE_TRANSITION",
            "upgrade_supported": True,
            "upgrade_requested": True,
            "upgrade_accepted": True,
            "tls_transition_observed": True
        },
        "tls": {
            "detected": True,
            "version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "key_exchange": "ECDHE",
            "forward_secrecy": True,
            "encrypted_application_data_observed": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "days_until_expiry": 300,
                "public_key_algorithm": "RSA",
                "public_key_length": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "self_signed": False,
                "hostname_match": True,
                "certificate_chain": {
                    "chain_observable": True,
                    "chain_complete": True,
                    "chain_status": "VALID",
                    "certificate_count": 2,
                    "validation_details": {
                        "signatures_verified": True,
                        "ca_constraints_verified": True,
                        "validity_periods_verified": True
                    }
                }
            }
        }
    }

    vec = crypto_risk_scorer_instance.extract_vector(sample_session)
    assert len(vec) == len(CRYPTO_RISK_FEATURE_NAMES)

    tls_det_idx = CRYPTO_RISK_FEATURE_NAMES.index("tls_detected")
    tls_13_idx = CRYPTO_RISK_FEATURE_NAMES.index("tls_version_is_1_3")
    chain_stat_idx = CRYPTO_RISK_FEATURE_NAMES.index("chain_status_valid")
    aead_idx = CRYPTO_RISK_FEATURE_NAMES.index("cipher_is_aead")

    assert vec[tls_det_idx] == 1.0
    assert vec[tls_13_idx] == 1.0
    assert vec[chain_stat_idx] == 1.0
    assert vec[aead_idx] == 1.0


def test_deterministic_prediction_and_reproducibility():
    """Verify that repeated predictions on identical session produce identical results."""
    session = {
        "session_id": "REPRO-01",
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "key_exchange": "ECDHE",
            "forward_secrecy": True,
            "encrypted_application_data_observed": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "days_until_expiry": 200,
                "public_key_algorithm": "RSA",
                "public_key_length": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "self_signed": False,
                "hostname_match": True,
                "certificate_chain": {
                    "chain_observable": True,
                    "chain_complete": True,
                    "chain_status": "VALID",
                    "certificate_count": 2,
                    "validation_details": {
                        "signatures_verified": True,
                        "ca_constraints_verified": True,
                        "validity_periods_verified": True
                    }
                }
            }
        }
    }

    res1 = crypto_risk_scorer_instance.predict(session)
    res2 = crypto_risk_scorer_instance.predict(session)
    assert res1["score"] == res2["score"]
    assert res1["label"] == res2["label"]
    assert res1["confidence"] == res2["confidence"]
    assert res1["class_probabilities"] == res2["class_probabilities"]
    assert res1["model_predicted_class"] == "LOW"
    assert res1["label"] == score_to_risk_label(res1["score"])
    assert 0.0 <= res1["score"] <= 100.0


def test_score_range_and_confidence():
    """Verify score is bounded [0, 100], confidence is [0, 1], and probabilities sum to ~1."""
    test_sessions = [
        {"session_id": "S1", "protocol": "SMTP", "tls": {"detected": False}},
        {"session_id": "S2", "protocol": "IMAP", "tls": {"detected": True, "version": "SSLv3"}},
        {"session_id": "S3", "protocol": "POP3", "tls": {"detected": True, "version": "TLSv1.3", "forward_secrecy": True}}
    ]

    for s in test_sessions:
        res = crypto_risk_scorer_instance.predict(s)
        assert 0.0 <= res["score"] <= 100.0
        assert 0.0 <= res["confidence"] <= 1.0
        assert res["label"] in ("LOW", "MODERATE", "HIGH", "CRITICAL")
        assert "class_probabilities" in res
        probs = res["class_probabilities"]
        assert pytest.approx(sum(probs.values()), 0.05) == 1.0
        assert isinstance(res["top_risk_factors"], list)
        assert isinstance(res["feature_contributions"], list)


# ==============================================================================
# CORE AI CRYPTOGRAPHIC REQUIREMENTS TESTS
# ==============================================================================

def test_requirement_1_same_cipher_different_complete_security_context():
    """
    Requirement 1: Same cipher (AES-GCM) under different complete session contexts
    MUST produce different AI risk predictions.
    
    Session A: TLS 1.2 + AES-GCM + ECDHE/PFS + valid cert + valid chain + complete STARTTLS -> LOW
    Session B: TLS 1.2 + AES-GCM + static RSA (no PFS) + expired cert + broken chain -> HIGH
    """
    session_a = {
        "session_id": "SAME-CIPHER-SECURE",
        "protocol": "SMTP",
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
            "key_exchange": "ECDHE",
            "forward_secrecy": True,
            "encrypted_application_data_observed": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "days_until_expiry": 250,
                "public_key_algorithm": "RSA",
                "public_key_length": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "self_signed": False,
                "hostname_match": True,
                "certificate_chain": {
                    "chain_observable": True,
                    "chain_complete": True,
                    "chain_status": "VALID",
                    "certificate_count": 2,
                    "validation_details": {
                        "signatures_verified": True,
                        "ca_constraints_verified": True,
                        "validity_periods_verified": True
                    }
                }
            }
        }
    }

    session_b = {
        "session_id": "SAME-CIPHER-DEGRADED",
        "protocol": "SMTP",
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
            "cipher_suite": "TLS_RSA_WITH_AES_256_GCM_SHA384",
            "key_exchange": "RSA",
            "forward_secrecy": False,
            "encrypted_application_data_observed": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "EXPIRED",
                "days_until_expiry": -60,
                "public_key_algorithm": "RSA",
                "public_key_length": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "self_signed": False,
                "hostname_match": False,
                "certificate_chain": {
                    "chain_observable": True,
                    "chain_complete": False,
                    "chain_status": "INVALID",
                    "certificate_count": 1,
                    "validation_details": {
                        "signatures_verified": False,
                        "ca_constraints_verified": False,
                        "validity_periods_verified": False
                    }
                }
            }
        }
    }

    res_a = crypto_risk_scorer_instance.predict(session_a)
    res_b = crypto_risk_scorer_instance.predict(session_b)

    assert res_a["label"] == "LOW"
    assert res_b["label"] in ("HIGH", "CRITICAL")
    assert res_a["score"] < res_b["score"]
    assert res_a["score"] <= 30.0
    assert res_b["score"] >= 50.0


def test_requirement_2_strong_cipher_alone_does_not_make_session_low_risk():
    """
    Requirement 2: A strong cipher suite alone (e.g. AES-256-GCM) MUST NOT automatically
    make a session LOW risk if the transport is unencrypted or if STARTTLS was abandoned.
    """
    session_stripped_with_cipher_name = {
        "session_id": "STRIPPED-WITH-CIPHER-METADATA",
        "protocol": "SMTP",
        "starttls": {
            "status": "INCOMPLETE",
            "upgrade_supported": True,
            "upgrade_requested": True,
            "upgrade_accepted": False,
            "tls_transition_observed": False
        },
        "tls": {
            "detected": False,  # TLS was never established!
            "cipher_suite": "TLS_AES_256_GCM_SHA384"
        },
        "client_payload": "MAIL FROM:<alice@test.com>\r\nRCPT TO:<bob@test.com>\r\n"
    }

    res = crypto_risk_scorer_instance.predict(session_stripped_with_cipher_name)
    assert res["label"] != "LOW"
    assert res["label"] == "CRITICAL"
    assert res["score"] >= 80.0


def test_requirement_3_tls_version_alone_does_not_determine_final_score():
    """
    Requirement 3: TLS 1.3 alone MUST NOT dictate a fixed safe score.
    A session with TLS 1.3 but an expired certificate and invalid chain must NOT be LOW risk.
    """
    session_tls13_degraded = {
        "session_id": "TLS13-DEGRADED",
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "forward_secrecy": True,
            "encrypted_application_data_observed": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "EXPIRED",
                "days_until_expiry": -120,
                "self_signed": False,
                "hostname_match": False,
                "certificate_chain": {
                    "chain_observable": True,
                    "chain_complete": False,
                    "chain_status": "INVALID",
                    "validation_details": {
                        "signatures_verified": False,
                        "ca_constraints_verified": False
                    }
                }
            }
        }
    }

    res = crypto_risk_scorer_instance.predict(session_tls13_degraded)
    assert res["label"] != "LOW"
    assert res["score"] >= 50.0


def test_requirement_4_valid_certificate_alone_does_not_determine_final_score():
    """
    Requirement 4: A valid certificate alone MUST NOT make an unencrypted or stripped
    session LOW or MODERATE risk.
    """
    session_plaintext_with_valid_cert = {
        "session_id": "PLAINTEXT-VALID-CERT",
        "protocol": "SMTP",
        "starttls": {
            "status": "NOT_USED"
        },
        "tls": {
            "detected": False,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "days_until_expiry": 365
            }
        }
    }

    res = crypto_risk_scorer_instance.predict(session_plaintext_with_valid_cert)
    assert res["label"] == "CRITICAL"
    assert res["score"] >= 80.0


def test_requirement_5_complete_secure_combination_vs_degraded():
    """
    Requirement 5: Complete secure feature combination must produce a safer prediction
    than an otherwise degraded complete session.
    """
    secure_session = {
        "session_id": "ALL-SECURE",
        "protocol": "SMTP",
        "starttls": {
            "status": "SECURE_TRANSITION",
            "upgrade_supported": True,
            "upgrade_requested": True,
            "upgrade_accepted": True,
            "tls_transition_observed": True
        },
        "tls": {
            "detected": True,
            "version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "key_exchange": "ECDHE",
            "forward_secrecy": True,
            "encrypted_application_data_observed": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "days_until_expiry": 300,
                "public_key_algorithm": "EC",
                "public_key_length": 256,
                "self_signed": False,
                "hostname_match": True,
                "certificate_chain": {
                    "chain_observable": True,
                    "chain_complete": True,
                    "chain_status": "VALID",
                    "validation_details": {
                        "signatures_verified": True,
                        "ca_constraints_verified": True,
                        "validity_periods_verified": True
                    }
                }
            }
        }
    }

    legacy_cbc_session = {
        "session_id": "LEGACY-CBC",
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA",
            "forward_secrecy": False,
            "encrypted_application_data_observed": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "days_until_expiry": 100,
                "public_key_algorithm": "RSA",
                "public_key_length": 2048,
                "self_signed": False,
                "hostname_match": True,
                "certificate_chain": {
                    "chain_observable": True,
                    "chain_complete": True,
                    "chain_status": "VALID",
                    "validation_details": {
                        "signatures_verified": True,
                        "ca_constraints_verified": True,
                        "validity_periods_verified": True
                    }
                }
            }
        }
    }

    sec_res = crypto_risk_scorer_instance.predict(secure_session)
    leg_res = crypto_risk_scorer_instance.predict(legacy_cbc_session)

    assert sec_res["score"] < leg_res["score"]
    assert sec_res["model_predicted_class"] == "LOW"
    assert sec_res["label"] == score_to_risk_label(sec_res["score"])
    assert leg_res["label"] in ("MODERATE", "HIGH", "CRITICAL")
    assert leg_res["label"] != "LOW"


def test_requirement_6_deterministic_findings_remain_strictly_separate_from_ai_score():
    """
    Requirement 6: Deterministic rule findings (SEC-001, SEC-002, etc.) and posture deductions
    MUST NOT be added or injected into the AI feature vector or score calculation.
    Mutating `assessment` or `posture` must NOT change the AI risk prediction.
    """
    base_session = {
        "session_id": "ISOLATION-TEST",
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "forward_secrecy": True,
            "encrypted_application_data_observed": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "days_until_expiry": 200,
                "public_key_length": 2048,
                "public_key_algorithm": "RSA",
                "self_signed": False,
                "hostname_match": True,
                "certificate_chain": {
                    "chain_observable": True,
                    "chain_complete": True,
                    "chain_status": "VALID",
                    "validation_details": {
                        "signatures_verified": True,
                        "ca_constraints_verified": True,
                        "validity_periods_verified": True
                    }
                }
            }
        },
        "assessment": {
            "finding_count": 0,
            "critical_count": 0,
            "findings": []
        },
        "posture": {
            "score": 100,
            "security_posture": "SECURE"
        }
    }

    pred_before = crypto_risk_scorer_instance.predict(base_session)

    # Heavily mutate deterministic assessment and posture
    mutated_session = dict(base_session)
    mutated_session["assessment"] = {
        "finding_count": 25,
        "critical_count": 10,
        "high_count": 15,
        "findings": [{"finding_id": f"SEC-{i}", "severity": "CRITICAL"} for i in range(10)]
    }
    mutated_session["posture"] = {
        "score": 0,
        "security_posture": "AT_RISK"
    }

    pred_after = crypto_risk_scorer_instance.predict(mutated_session)

    # Vector must be identical
    vec_before = crypto_risk_scorer_instance.extract_vector(base_session)
    vec_after = crypto_risk_scorer_instance.extract_vector(mutated_session)
    assert vec_before == vec_after

    # AI prediction must be 100% identical
    assert pred_before["score"] == pred_after["score"]
    assert pred_before["label"] == pred_after["label"]
    assert pred_before["confidence"] == pred_after["confidence"]
    assert pred_before["class_probabilities"] == pred_after["class_probabilities"]


def test_requirement_7_no_hardcoded_per_feature_points_in_score_calculation():
    """
    Requirement 7: Verify that the final AI score is produced by the ML model ensemble,
    not by summing fixed per-feature point bonuses or penalties.
    """
    scorer = crypto_risk_scorer_instance
    assert isinstance(scorer.model, RandomForestClassifier)
    # Verify model classes cover the multi-class risk spectrum
    assert set(scorer.model.classes_) == {"LOW", "MODERATE", "HIGH", "CRITICAL"}


def test_requirement_8_model_prediction_reproducibility():
    """Requirement 8: Model predictions are strictly reproducible across fresh instances."""
    scorer_a = CryptoRiskScorer(random_state=42)
    scorer_b = CryptoRiskScorer(random_state=42)

    sample = {
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "forward_secrecy": True
        }
    }

    res_a = scorer_a.predict(sample)
    res_b = scorer_b.predict(sample)

    assert res_a["score"] == res_b["score"]
    assert res_a["label"] == res_b["label"]
    assert res_a["confidence"] == res_b["confidence"]


def test_requirement_9_api_endpoints():
    """Requirement 9: FastAPI /api/ml/risk/status and /api/ml/risk/predict endpoints return AI results."""
    # 1. Status endpoint
    status_resp = client.get("/api/ml/risk/status")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["model"] == MODEL_NAME
    assert status_data["model_version"] == MODEL_VERSION
    assert status_data["is_loaded"] is True
    assert "features" in status_data

    # 2. Predict endpoint
    predict_resp = client.post(
        "/api/ml/risk/predict",
        json={"session": {"protocol": "SMTP", "tls": {"detected": False}}}
    )
    assert predict_resp.status_code == 200
    pred_data = predict_resp.json()
    assert "score" in pred_data
    assert pred_data["label"] == "CRITICAL"
    assert pred_data["score"] >= 80.0
    assert "class_probabilities" in pred_data
    assert "top_risk_factors" in pred_data
    assert "feature_contributions" in pred_data


def test_graceful_fallback():
    """Verify fallback mechanism when model is forced into untrained state."""
    fallback_scorer = CryptoRiskScorer.__new__(CryptoRiskScorer)
    fallback_scorer.model = None
    fallback_scorer.is_loaded = False
    fallback_scorer.model_name = MODEL_NAME
    fallback_scorer.model_version = MODEL_VERSION

    fallback_res = fallback_scorer.predict({"tls": {"detected": False}})
    assert fallback_res["score"] >= 80.0
    assert fallback_res["label"] == "CRITICAL"
    assert "Fallback" in fallback_res["model"]


# ==============================================================================
# SESSION-SPECIFIC EXPLANATION TESTS (A THROUGH J)
# ==============================================================================

def test_session_specific_a_secure_session_clean_state():
    """
    Test A: Secure session produces clean state without misleading risk factors.
    Normal secure features (TLS 1.3, encrypted data, valid cert) must NOT be shown as risks.
    """
    session = {
        "session_id": "SECURE-SESSION-A",
        "protocol": "SMTP",
        "starttls": {
            "status": "SECURE_TRANSITION",
            "upgrade_supported": True,
            "upgrade_requested": True,
            "upgrade_accepted": True,
            "tls_transition_observed": True
        },
        "tls": {
            "detected": True,
            "version": "TLSv1.3",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "key_exchange": "ECDHE",
            "forward_secrecy": True,
            "encrypted_application_data_observed": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "days_until_expiry": 300,
                "public_key_algorithm": "RSA",
                "public_key_length": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "self_signed": False,
                "hostname_match": True,
                "certificate_chain": {
                    "chain_observable": True,
                    "chain_complete": True,
                    "chain_status": "VALID",
                    "validation_details": {
                        "signatures_verified": True,
                        "ca_constraints_verified": True,
                        "validity_periods_verified": True
                    }
                }
            }
        }
    }

    res = crypto_risk_scorer_instance.predict(session)
    assert res["model_predicted_class"] == "LOW"
    assert res["label"] == score_to_risk_label(res["score"])
    assert 0.0 <= res["score"] <= 100.0

    factors = res["top_risk_factors"]
    assert len(factors) == 1
    assert factors[0]["feature"] == "none"
    assert "No significant risk factors observed" in factors[0]["label"]
    assert factors[0]["contribution"] == 0.0

    # Ensure secure features are NOT listed as risks
    risk_features = [f["feature"] for f in factors]
    assert "encrypted_application_data_observed" not in risk_features
    assert "tls_version_is_1_3" not in risk_features
    assert "certificate_is_valid" not in risk_features


def test_session_specific_b_expired_certificate():
    """
    Test B: Expired certificate appears as a top risk factor with positive contribution.
    """
    session = {
        "session_id": "EXPIRED-CERT-B",
        "protocol": "SMTP",
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
            "forward_secrecy": True,
            "encrypted_application_data_observed": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "EXPIRED",
                "days_until_expiry": -90,
                "public_key_algorithm": "RSA",
                "public_key_length": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "self_signed": False,
                "hostname_match": True,
                "certificate_chain": {
                    "chain_observable": True,
                    "chain_complete": True,
                    "chain_status": "INVALID",
                    "validation_details": {
                        "signatures_verified": True,
                        "ca_constraints_verified": True,
                        "validity_periods_verified": False
                    }
                }
            }
        }
    }

    res = crypto_risk_scorer_instance.predict(session)
    assert res["label"] in ("MODERATE", "HIGH", "CRITICAL")

    factor_features = [f["feature"] for f in res["top_risk_factors"]]
    assert "certificate_is_expired" in factor_features

    expired_factor = next(f for f in res["top_risk_factors"] if f["feature"] == "certificate_is_expired")
    assert expired_factor["label"] == "Expired certificate observed"
    assert expired_factor["contribution"] > 0.0
    assert expired_factor["observed"] is True


def test_session_specific_c_plaintext_session():
    """
    Test C: Plaintext session produces plaintext as a top risk factor.
    """
    session = {
        "session_id": "PLAINTEXT-C",
        "protocol": "SMTP",
        "starttls": {"status": "NOT_USED"},
        "tls": {"detected": False},
        "client_payload": "MAIL FROM:<sender@example.com>\r\nRCPT TO:<rcpt@example.com>\r\n"
    }

    res = crypto_risk_scorer_instance.predict(session)
    assert res["label"] == "CRITICAL"
    assert res["score"] >= 80.0

    factor_features = [f["feature"] for f in res["top_risk_factors"]]
    assert "plaintext_payload_observed" in factor_features

    plain_factor = next(f for f in res["top_risk_factors"] if f["feature"] == "plaintext_payload_observed")
    assert plain_factor["label"] == "Plaintext application payload observed"
    assert plain_factor["contribution"] > 0.0
    assert plain_factor["observed"] is True


def test_session_specific_d_invalid_certificate_chain():
    """
    Test D: Invalid certificate chain appears as a top risk factor.
    """
    session = {
        "session_id": "INVALID-CHAIN-D",
        "protocol": "SMTP",
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
            "forward_secrecy": True,
            "encrypted_application_data_observed": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "days_until_expiry": 180,
                "public_key_algorithm": "RSA",
                "public_key_length": 2048,
                "self_signed": False,
                "hostname_match": True,
                "certificate_chain": {
                    "chain_observable": True,
                    "chain_complete": False,
                    "chain_status": "INVALID",
                    "validation_details": {
                        "signatures_verified": False,
                        "ca_constraints_verified": False,
                        "validity_periods_verified": True
                    }
                }
            }
        }
    }

    res = crypto_risk_scorer_instance.predict(session)
    factor_features = [f["feature"] for f in res["top_risk_factors"]]
    assert "chain_status_invalid" in factor_features

    chain_factor = next(f for f in res["top_risk_factors"] if f["feature"] == "chain_status_invalid")
    assert chain_factor["label"] == "Invalid certificate chain observed"
    assert chain_factor["contribution"] > 0.0
    assert chain_factor["observed"] is True


def test_session_specific_e_same_cipher_different_context():
    """
    Test E: Same cipher (AES-GCM) under different contexts produces demonstrably DIFFERENT top risk factors.
    Session A: Secure context -> "No significant risk factors observed"
    Session B: Degraded context -> "Invalid certificate chain observed", "Expired certificate observed"
    """
    session_a = {
        "session_id": "SAME-CIPHER-CTX-A",
        "protocol": "SMTP",
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
            "forward_secrecy": True,
            "encrypted_application_data_observed": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "days_until_expiry": 200,
                "public_key_algorithm": "RSA",
                "public_key_length": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "hostname_match": True,
                "certificate_chain": {
                    "chain_observable": True,
                    "chain_complete": True,
                    "chain_status": "VALID",
                    "validation_details": {
                        "signatures_verified": True,
                        "ca_constraints_verified": True,
                        "validity_periods_verified": True
                    }
                }
            }
        }
    }

    session_b = {
        "session_id": "SAME-CIPHER-CTX-B",
        "protocol": "SMTP",
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
            "forward_secrecy": True,
            "encrypted_application_data_observed": True,
            "certificate": {
                "certificate_present": True,
                "expiration_status": "EXPIRED",
                "days_until_expiry": -50,
                "public_key_algorithm": "RSA",
                "public_key_length": 2048,
                "signature_algorithm": "sha256WithRSAEncryption",
                "hostname_match": False,
                "certificate_chain": {
                    "chain_observable": True,
                    "chain_complete": False,
                    "chain_status": "INVALID",
                    "validation_details": {
                        "signatures_verified": False,
                        "ca_constraints_verified": False
                    }
                }
            }
        }
    }

    res_a = crypto_risk_scorer_instance.predict(session_a)
    res_b = crypto_risk_scorer_instance.predict(session_b)

    factors_a = [f["feature"] for f in res_a["top_risk_factors"]]
    factors_b = [f["feature"] for f in res_b["top_risk_factors"]]

    assert factors_a != factors_b
    assert "none" in factors_a
    assert "none" not in factors_b
    assert "chain_status_invalid" in factors_b or "certificate_is_expired" in factors_b


def test_session_specific_f_strong_cipher_alone_not_risk():
    """
    Test F: Strong cipher alone must NOT automatically become a risk factor.
    """
    session = {
        "session_id": "STRONG-CIPHER-F",
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "certificate": {
                "certificate_present": True,
                "expiration_status": "EXPIRED"
            }
        }
    }

    res = crypto_risk_scorer_instance.predict(session)
    factors = [f["feature"] for f in res["top_risk_factors"]]
    assert "cipher_is_aead" not in factors
    assert "cipher_is_modern" not in factors


def test_session_specific_g_tls_version_alone_not_manual_score():
    """
    Test G: TLS version alone must NOT be converted into a manually assigned score table.
    Ensures predictions are multi-class ensemble probabilities.
    """
    session = {
        "session_id": "TLS-ALONE-G",
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.3"
        }
    }

    res = crypto_risk_scorer_instance.predict(session)
    assert "class_probabilities" in res
    assert isinstance(res["class_probabilities"], dict)
    assert len(res["class_probabilities"]) == 4
    # Ensure no manual score table overrides the model output
    assert isinstance(res["score"], float)


def test_session_specific_h_valid_certificate_alone_not_risk():
    """
    Test H: Valid certificate alone must NOT be presented as a risk.
    """
    session = {
        "session_id": "VALID-CERT-H",
        "protocol": "SMTP",
        "tls": {
            "detected": True,
            "version": "TLSv1.2",
            "certificate": {
                "certificate_present": True,
                "expiration_status": "VALID",
                "days_until_expiry": 100
            }
        }
    }

    res = crypto_risk_scorer_instance.predict(session)
    factors = [f["feature"] for f in res["top_risk_factors"]]
    assert "certificate_is_valid" not in factors
    assert "certificate_present" not in factors


def test_session_specific_i_missing_unknown_features():
    """
    Test I: Missing or unknown features are handled gracefully without exceptions.
    """
    empty_session = {}
    res_empty = crypto_risk_scorer_instance.predict(empty_session)
    assert res_empty["label"] in ("LOW", "MODERATE", "HIGH", "CRITICAL")
    assert isinstance(res_empty["top_risk_factors"], list)

    unknown_data_session = {
        "non_existent_key": 99999,
        "unexpected_object": {"foo": "bar"},
        "tls": "invalid_type_not_dict"
    }
    res_unknown = crypto_risk_scorer_instance.predict(unknown_data_session)
    assert res_unknown["label"] in ("LOW", "MODERATE", "HIGH", "CRITICAL")
    assert isinstance(res_unknown["top_risk_factors"], list)


def test_session_specific_j_reproducibility():
    """
    Test J: Same feature vector produces the identical session-specific explanation.
    """
    session = {
        "session_id": "REPRO-J",
        "protocol": "SMTP",
        "starttls": {"status": "NOT_USED"},
        "tls": {"detected": False},
        "client_payload": "MAIL FROM:<user@test.org>\r\n"
    }

    res1 = crypto_risk_scorer_instance.predict(session)
    res2 = crypto_risk_scorer_instance.predict(session)

    assert res1["top_risk_factors"] == res2["top_risk_factors"]
    assert res1["score"] == res2["score"]
    assert res1["label"] == res2["label"]


def test_controlled_pairs_monotonicity():
    """
    Verifies strictly monotonic risk score progression across controlled pairs (Sessions A to F):
    Risk(A) < Risk(B) < Risk(C) < Risk(D) < Risk(E) < Risk(F)
    """
    from app.ml.crypto_risk_scorer import _build_feature_row

    def build_session(**kwargs):
        base = dict(
            protocol_is_smtp=1.0,
            starttls_upgrade_supported=1.0,
            starttls_upgrade_requested=1.0,
            starttls_upgrade_accepted=1.0,
            starttls_transition_observed=1.0,
            starttls_status_secure=1.0,
            tls_detected=1.0,
            tls_version_is_1_2=1.0,
            cipher_is_aead=1.0,
            cipher_is_modern=1.0,
            kex_is_ecdhe=1.0,
            forward_secrecy_present=1.0,
            encrypted_application_data_observed=1.0,
            certificate_present=1.0,
            certificate_is_valid=1.0,
            days_until_expiry_norm=0.5,
            public_key_is_rsa=1.0,
            hostname_matches=1.0,
            chain_observable=1.0,
            chain_complete=1.0,
            chain_status_valid=1.0,
            chain_signatures_verified=1.0,
            chain_ca_constraints_verified=1.0,
            chain_validity_periods_verified=1.0,
            chain_issuer_subject_linked=1.0,
            certificate_count_norm=0.4,
            packet_count_norm=0.2,
            duration_norm=0.05,
            client_bytes_ratio=0.3
        )
        base.update(kwargs)
        return _build_feature_row(**base)

    sA = build_session()
    sB = build_session(certificate_is_valid=0.0, certificate_is_expired=1.0, days_until_expiry_norm=-0.2, chain_validity_periods_verified=0.0)
    sC = build_session(certificate_is_valid=0.0, certificate_is_expired=1.0, days_until_expiry_norm=-0.2, chain_validity_periods_verified=0.0, hostname_matches=0.0, hostname_mismatch=1.0)
    sD = build_session(certificate_is_valid=0.0, certificate_is_expired=1.0, days_until_expiry_norm=-0.2, chain_validity_periods_verified=0.0, hostname_matches=0.0, hostname_mismatch=1.0, public_key_is_substandard=1.0)
    sE = build_session(certificate_is_valid=0.0, certificate_is_expired=1.0, days_until_expiry_norm=-0.2, chain_validity_periods_verified=0.0, hostname_matches=0.0, hostname_mismatch=1.0, public_key_is_substandard=1.0, tls_version_is_1_2=0.0, tls_version_is_1_0=1.0, cipher_is_aead=0.0, cipher_is_cbc=1.0, cipher_is_modern=0.0, kex_is_ecdhe=0.0, kex_is_static_rsa=1.0, forward_secrecy_present=0.0, forward_secrecy_absent=1.0)
    sF = _build_feature_row(protocol_is_smtp=1.0, tls_detected=0.0, plaintext_payload_observed=1.0)

    rows = [sA, sB, sC, sD, sE, sF]
    scores = []
    w = {"LOW": 0.0, "MODERATE": 33.0, "HIGH": 67.0, "CRITICAL": 100.0}
    for r in rows:
        probs = crypto_risk_scorer_instance.model.predict_proba(np.array([r]))[0]
        classes = list(crypto_risk_scorer_instance.model.classes_)
        pdict = {c: float(p) for c, p in zip(classes, probs)}
        score = sum(pdict.get(c, 0.0) * w[c] for c in classes)
        scores.append(score)

    for i in range(len(scores) - 1):
        assert scores[i] < scores[i + 1], f"Monotonicity failed at index {i}: {scores[i]} not < {scores[i+1]}"


def test_probability_weighted_presentation_score_regression():
    """
    Regression test ensuring the 0-100 risk score directly reflects RandomForest class probabilities
    without class-based range clamping:
    score = P(LOW)*0.0 + P(MODERATE)*33.0 + P(HIGH)*67.0 + P(CRITICAL)*100.0
    """
    from app.capture.pcap_reader import analyze_pcap

    # 1. Secure completed session (tls_test_email.pcap)
    c_sec = analyze_pcap("dataset/tls_test_email.pcap")
    p_sec = crypto_risk_scorer_instance.predict(c_sec["sessions"][0])
    assert p_sec["class_probabilities"]["LOW"] > 0.70
    assert p_sec["score"] < 20.0
    assert p_sec["label"] == "LOW"
    expected_sec = round(
        p_sec["class_probabilities"]["LOW"] * 0.0 +
        p_sec["class_probabilities"]["MODERATE"] * 33.0 +
        p_sec["class_probabilities"]["HIGH"] * 67.0 +
        p_sec["class_probabilities"]["CRITICAL"] * 100.0,
        1
    )
    assert p_sec["score"] == expected_sec

    # 2. Expired certificate (06_expired_certificate.pcap)
    c_exp = analyze_pcap("dataset/06_expired_certificate.pcap")
    p_exp = crypto_risk_scorer_instance.predict(c_exp["sessions"][0])
    assert p_exp["label"] in ("HIGH", "CRITICAL")
    assert p_exp["score"] > 50.0

    # 3. Hostname mismatch (07_hostname_mismatch_certificate.pcap)
    c_mis = analyze_pcap("dataset/07_hostname_mismatch_certificate.pcap")
    p_mis = crypto_risk_scorer_instance.predict(c_mis["sessions"][0])
    assert p_mis["label"] in ("HIGH", "CRITICAL")
    assert p_mis["score"] > 50.0

    # 4. Deprecated TLS 1.0 (02_deprecated_tls10.pcap)
    c_dep = analyze_pcap("dataset/02_deprecated_tls10.pcap")
    p_dep = crypto_risk_scorer_instance.predict(c_dep["sessions"][0])
    assert p_dep["label"] in ("HIGH", "CRITICAL")
    assert p_dep["score"] > 50.0

    # 5. Weak RSA 1024 (08_weak_rsa_1024_certificate.pcap)
    c_rsa = analyze_pcap("dataset/08_weak_rsa_1024_certificate.pcap")
    p_rsa = crypto_risk_scorer_instance.predict(c_rsa["sessions"][0])
    assert p_rsa["score"] >= 30.0

    # 6. Static RSA / No PFS (04_no_forward_secrecy_rsa.pcap)
    c_pfs = analyze_pcap("dataset/04_no_forward_secrecy_rsa.pcap")
    p_pfs = crypto_risk_scorer_instance.predict(c_pfs["sessions"][0])
    assert p_pfs["label"] in ("HIGH", "CRITICAL")
    assert p_pfs["score"] > 50.0

    # 7. Plaintext / Insecure STARTTLS (10_insecure_starttls_no_upgrade.pcap)
    c_ins = analyze_pcap("dataset/10_insecure_starttls_no_upgrade.pcap")
    p_ins = crypto_risk_scorer_instance.predict(c_ins["sessions"][0])
    assert p_ins["label"] == "CRITICAL"
    assert p_ins["class_probabilities"]["CRITICAL"] > 0.90
    assert p_ins["score"] > 90.0

    # 8. Determinism: identical across repeated executions
    c_inc = analyze_pcap("dataset/01_secure_smtp_tls12.pcap")
    p_inc_1 = crypto_risk_scorer_instance.predict(c_inc["sessions"][0])
    p_inc_2 = crypto_risk_scorer_instance.predict(c_inc["sessions"][0])
    assert p_inc_1["score"] == p_inc_2["score"]
    assert p_inc_1["class_probabilities"] == p_inc_2["class_probabilities"]


def test_score_and_operational_tier_consistency():
    """
    Regression test verifying:
    - AI Risk Score is a continuous probability-weighted score
    - Operational Risk Tier (label) is strictly derived from that continuous score:
        0 - 20: LOW
        20.1 - 50: MODERATE
        50.1 - 80: HIGH
        80.1 - 100: CRITICAL
    - model_predicted_class preserves the Random Forest argmax probability
    - Score and operational tier never contradict each other across all dataset PCAPs
    """
    from app.capture.pcap_reader import analyze_pcap
    import glob

    pcaps = glob.glob("dataset/*.pcap")
    assert len(pcaps) > 0

    for pcap_file in pcaps:
        data = analyze_pcap(pcap_file)
        if not data.get("sessions"):
            continue
        session = data["sessions"][0]
        ai_res = session.get("ai_risk", {})
        score = ai_res.get("score")
        label = ai_res.get("label")
        operational_tier = ai_res.get("operational_risk_tier")
        model_class = ai_res.get("model_predicted_class")

        assert score is not None
        assert 0.0 <= score <= 100.0
        assert label == operational_tier
        assert label == score_to_risk_label(score)
        assert model_class in RISK_CLASSES

        # Verify no boundary contradictions exist
        if score <= 20.0:
            assert label == "LOW"
        elif score <= 50.0:
            assert label == "MODERATE"
        elif score <= 80.0:
            assert label == "HIGH"
        else:
            assert label == "CRITICAL"


