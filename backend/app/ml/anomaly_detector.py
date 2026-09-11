import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from sklearn.ensemble import IsolationForest
from app.ml.feature_extractor import extract_session_features

MODEL_FEATURE_NAMES = [
    "tls_detected",
    "tls_version_numeric",
    "cipher_is_aead",
    "cipher_is_weak",
    "key_exchange_is_ephemeral",
    "forward_secrecy",
    "encrypted_application_data_observed",
    "certificate_present",
    "certificate_is_valid",
    "days_until_expiry",
    "public_key_length",
    "signature_is_weak",
    "hostname_match",
    "starttls_upgrade_supported",
    "starttls_upgrade_requested",
    "starttls_upgrade_accepted",
    "starttls_transition_observed",
    "packet_count",
    "duration_seconds",
    "client_bytes_ratio",
    "finding_count",
    "posture_score"
]


class CryptographicAnomalyDetector:
    """
    Isolation Forest-based cryptographic behaviour anomaly detection engine.
    Compares observable cryptographic session behaviour against an established normal baseline.
    """

    def __init__(self, contamination: Any = "auto", random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.is_trained: bool = False
        self.baseline_size: int = 0
        self.baseline_stats: Dict[str, Dict[str, float]] = {}

    def extract_vector(self, session: Dict[str, Any]) -> Tuple[List[float], List[str], List[str]]:
        """Extracts numerical feature vector for the model, tracking used and missing features."""
        ml_data = session.get("ml_features")
        if not ml_data or "features" not in ml_data:
            ml_data = extract_session_features(session)

        feat_dict = ml_data.get("features", {})

        vector = []
        features_used = []
        features_missing = []

        for f_name in MODEL_FEATURE_NAMES:
            if f_name in feat_dict:
                vector.append(float(feat_dict[f_name]))
                features_used.append(f_name)
            else:
                vector.append(0.0)
                features_missing.append(f_name)

        return vector, features_used, features_missing

    def train_baseline(self, normal_sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Trains the Isolation Forest anomaly detection model on a collection of normal sessions.
        Computes baseline feature statistics for transparent deviation explanations.
        """
        if not normal_sessions or len(normal_sessions) < 5:
            return {
                "success": False,
                "error": "INSUFFICIENT_BASELINE",
                "message": f"A minimum of 5 normal baseline sessions is required to train the model (provided: {len(normal_sessions)}).",
                "baseline_size": len(normal_sessions)
            }

        vectors = []
        for s in normal_sessions:
            vec, _, _ = self.extract_vector(s)
            vectors.append(vec)

        X = np.array(vectors)

        # Compute baseline feature statistics (mean, min, max, std)
        self.baseline_stats = {}
        for idx, f_name in enumerate(MODEL_FEATURE_NAMES):
            col = X[:, idx]
            self.baseline_stats[f_name] = {
                "mean": float(np.mean(col)),
                "std": float(np.std(col)),
                "min": float(np.min(col)),
                "max": float(np.max(col))
            }

        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state
        )
        self.model.fit(X)
        self.is_trained = True
        self.baseline_size = len(normal_sessions)

        return {
            "success": True,
            "model": "IsolationForest",
            "model_version": "mvp-1",
            "baseline_size": self.baseline_size,
            "feature_count": len(MODEL_FEATURE_NAMES),
            "message": f"Successfully trained baseline model with {self.baseline_size} normal sessions."
        }

    def generate_explanations(self, feat_dict: Dict[str, Any]) -> List[str]:
        """
        Compares session features against baseline distribution to generate
        factual, explainable deviation descriptions.
        """
        explanations = []
        if not self.baseline_stats:
            return explanations

        # 1. TLS Version Deviation
        tls_ver = feat_dict.get("tls_version_numeric", 0.0)
        base_ver_mean = self.baseline_stats.get("tls_version_numeric", {}).get("mean", 1.2)
        if tls_ver > 0 and tls_ver < 1.2 and base_ver_mean >= 1.2:
            explanations.append("TLS version differs from the normal baseline.")

        # 2. Forward Secrecy Deviation
        fs = feat_dict.get("forward_secrecy", -1)
        base_fs_mean = self.baseline_stats.get("forward_secrecy", {}).get("mean", 1.0)
        if fs == 0 and base_fs_mean > 0.7:
            explanations.append("Forward Secrecy is absent while the baseline normally uses ephemeral key exchange.")

        # 3. Cipher Weakness Deviation
        cipher_weak = feat_dict.get("cipher_is_weak", 0)
        cipher_aead = feat_dict.get("cipher_is_aead", 0)
        base_aead_mean = self.baseline_stats.get("cipher_is_aead", {}).get("mean", 1.0)
        if cipher_weak == 1 or (cipher_aead == 0 and base_aead_mean > 0.7):
            explanations.append("Cipher family is uncommon in the baseline.")

        # 4. STARTTLS Transition Deviation
        st_trans = feat_dict.get("starttls_transition_observed", 0)
        st_accept = feat_dict.get("starttls_upgrade_accepted", 0)
        if st_accept == 1 and st_trans == 0:
            explanations.append("STARTTLS transition behaviour is unusual.")

        # 5. Hostname Matching Deviation
        host_match = feat_dict.get("hostname_match", -1)
        base_host_mean = self.baseline_stats.get("hostname_match", {}).get("mean", 1.0)
        if host_match == 0 and base_host_mean > 0.7:
            explanations.append("Certificate hostname matching differs from the normal baseline.")

        # 6. Certificate Validity Deviation
        cert_val = feat_dict.get("certificate_is_valid", 0)
        cert_pres = feat_dict.get("certificate_present", 0)
        base_val_mean = self.baseline_stats.get("certificate_is_valid", {}).get("mean", 1.0)
        if cert_pres == 1 and cert_val == 0 and base_val_mean > 0.7:
            explanations.append("Certificate validity status deviates from the normal baseline.")

        # 7. Posture Score Deviation
        score = feat_dict.get("posture_score", 100)
        base_score_mean = self.baseline_stats.get("posture_score", {}).get("mean", 95.0)
        if score < (base_score_mean - 20):
            explanations.append(f"Session security posture score ({score}) is significantly lower than the baseline standard ({round(base_score_mean, 1)}).")

        return explanations

    def predict(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates a session against the learned baseline using Isolation Forest.
        Returns anomaly status, numeric anomaly score, prediction, confidence, and explanations.
        """
        if not self.is_trained or self.model is None:
            return {
                "status": "BASELINE_NOT_TRAINED",
                "anomaly_detected": None,
                "anomaly_score": None,
                "prediction": "NOT_EVALUATED",
                "confidence": "LOW",
                "data_quality": "LIMITED",
                "features_used": [],
                "features_missing": [],
                "explanation": ["Baseline model has not been trained yet. Train baseline using known normal sessions."],
                "model_metadata": self.get_model_status()
            }

        vec, features_used, features_missing = self.extract_vector(session)
        X = np.array([vec])

        # IsolationForest decision_function: lower means more anomalous
        raw_score = float(self.model.decision_function(X)[0])
        pred_label = int(self.model.predict(X)[0])  # -1 for anomaly, 1 for normal

        # Generate feature deviation explanations
        ml_data = session.get("ml_features")
        if not ml_data or "features" not in ml_data:
            ml_data = extract_session_features(session)
        feat_dict = ml_data.get("features", {})
        explanations = self.generate_explanations(feat_dict)

        # Cross-evaluate Isolation Forest and feature deviations
        has_deviations = len(explanations) > 0
        posture_score = feat_dict.get("posture_score", 100)
        
        is_anomaly = has_deviations or (pred_label == -1 and posture_score < 80)
        prediction_str = "ANOMALOUS" if is_anomaly else "NORMAL"

        if not is_anomaly:
            anomaly_score = round(abs(raw_score) if raw_score != 0 else 0.05, 4)
            confidence = "HIGH" if posture_score >= 90 else "MEDIUM"
            if not explanations:
                explanations.append("Session cryptographic parameters conform to the learned baseline profile.")
        else:
            anomaly_score = -round(abs(raw_score) + (0.05 * len(explanations)), 4)
            confidence = "HIGH" if len(explanations) >= 2 else "MEDIUM"
            if not explanations:
                explanations.append("Session exhibits multi-dimensional statistical deviation from the baseline profile.")

        # Determine data quality
        data_quality = "LIMITED" if len(features_missing) > 0 or session.get("protocol") == "UNKNOWN" else "GOOD"

        return {
            "status": "COMPLETED",
            "anomaly_detected": is_anomaly,
            "anomaly_score": anomaly_score,
            "prediction": prediction_str,
            "confidence": confidence,
            "data_quality": data_quality,
            "features_used": features_used,
            "features_missing": features_missing,
            "explanation": explanations,
            "model_metadata": self.get_model_status()
        }

    def get_model_status(self) -> Dict[str, Any]:
        """Returns the current state and metadata of the anomaly detector."""
        return {
            "model": "IsolationForest",
            "model_version": "mvp-1",
            "trained": self.is_trained,
            "baseline_size": self.baseline_size,
            "contamination": str(self.contamination),
            "random_state": self.random_state
        }

    def reset_baseline(self) -> None:
        """Resets the model to an untrained state."""
        self.model = None
        self.is_trained = False
        self.baseline_size = 0
        self.baseline_stats = {}


# Global detector instance
detector_instance = CryptographicAnomalyDetector()


def create_synthetic_development_baseline(count: int = 20) -> List[Dict[str, Any]]:
    """
    Generates a controlled synthetic development baseline collection of normal TLS email sessions.
    Clearly labeled as 'synthetic development baseline' for testing and demonstration.
    """
    baseline_sessions = []
    for i in range(count):
        session_id = f"SYNTH-NORM-{i + 1:03d}"
        session = {
            "session_id": session_id,
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
                "version": "TLSv1.2" if i % 3 != 0 else "TLSv1.3",
                "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" if i % 2 == 0 else "TLS_AES_256_GCM_SHA384",
                "key_exchange": "ECDHE (x25519)" if i % 3 != 0 else "ECDHE/DHE (TLS 1.3)",
                "forward_secrecy": True,
                "encrypted_application_data_observed": True,
                "client_hello": {"server_name": f"mail{i}.example.test"},
                "certificate": {
                    "certificate_present": True,
                    "expiration_status": "VALID",
                    "days_until_expiry": 300 + (i * 2),
                    "public_key_algorithm": "RSA",
                    "public_key_length": 2048,
                    "signature_algorithm": "sha256WithRSAEncryption",
                    "self_signed": True,
                    "hostname_match": True,
                    "subject": f"CN=mail{i}.example.test"
                }
            },
            "packet_count": 18 + (i % 5),
            "duration_seconds": 0.2 + (i * 0.01),
            "client_to_server_bytes": 400 + (i * 10),
            "server_to_client_bytes": 1800 + (i * 20),
            "assessment": {
                "finding_count": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "findings": []
            },
            "posture": {
                "score": 100,
                "security_posture": "SECURE",
                "risk_level": "LOW_RISK"
            }
        }
        # Pre-extract ML features
        session["ml_features"] = extract_session_features(session)
        baseline_sessions.append(session)

    return baseline_sessions
