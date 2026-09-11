import os
import joblib
import numpy as np
from typing import Dict, Any, List, Tuple, Optional
from sklearn.ensemble import RandomForestClassifier
from app.ml.feature_extractor import extract_session_features

# ==============================================================================
# SECUREMAILSCOPE - AI CRYPTOGRAPHIC RISK SCORING ENGINE
# Architecture: Supervised Multi-Class Random Forest Classifier
# Evaluates whole-session cryptographic and protocol feature vectors to predict
# overall session security posture (LOW, MODERATE, HIGH, CRITICAL).
# ==============================================================================

CRYPTO_RISK_FEATURE_NAMES = [
    # 1. Protocol Layer Features
    "protocol_is_smtp",
    "protocol_is_imap",
    "protocol_is_pop3",
    "protocol_is_other",
    # 2. STARTTLS Layer Features
    "starttls_upgrade_supported",
    "starttls_upgrade_requested",
    "starttls_upgrade_accepted",
    "starttls_transition_observed",
    "starttls_is_incomplete",
    "starttls_status_secure",
    "starttls_status_direct_tls",
    "starttls_status_none",
    # 3. TLS Handshake & Version Indicators (Categorical representations, not scores)
    "tls_detected",
    "tls_version_is_1_3",
    "tls_version_is_1_2",
    "tls_version_is_1_1",
    "tls_version_is_1_0",
    "tls_version_is_ssl3",
    "tls_version_is_none",
    # 4. Cipher Suite Characteristics
    "cipher_is_aead",
    "cipher_is_cbc",
    "cipher_is_weak",
    "cipher_is_modern",
    # 5. Key Exchange & Forward Secrecy
    "kex_is_ecdhe",
    "kex_is_dhe",
    "kex_is_static_rsa",
    "forward_secrecy_present",
    "forward_secrecy_absent",
    # 6. Data Transport Observability
    "encrypted_application_data_observed",
    "plaintext_payload_observed",
    # 7. Leaf Certificate Features
    "certificate_present",
    "certificate_is_valid",
    "certificate_is_expired",
    "days_until_expiry_norm",
    "public_key_is_rsa",
    "public_key_is_ec",
    "public_key_is_substandard",
    "signature_is_weak",
    "certificate_is_self_signed",
    "hostname_matches",
    "hostname_mismatch",
    # 8. Certificate Chain Features
    "chain_observable",
    "chain_complete",
    "chain_status_valid",
    "chain_status_invalid",
    "chain_status_incomplete",
    "certificate_count_norm",
    "chain_signatures_verified",
    "chain_ca_constraints_verified",
    "chain_validity_periods_verified",
    "chain_issuer_subject_linked",
    # 9. Session Behavior & Flow Metrics
    "packet_count_norm",
    "duration_norm",
    "client_bytes_ratio"
]

RISK_CLASSES = ["LOW", "MODERATE", "HIGH", "CRITICAL"]

# Presentation score weights (0 = safe / minimal risk, 100 = critical risk)
CLASS_PRESENTATION_WEIGHTS = {
    "LOW": 0.0,
    "MODERATE": 33.0,
    "HIGH": 67.0,
    "CRITICAL": 100.0
}

RISK_THRESHOLDS = {
    "LOW": (0.0, 20.0),
    "MODERATE": (20.01, 50.0),
    "HIGH": (50.01, 80.0),
    "CRITICAL": (80.01, 100.0)
}

MODEL_VERSION = "3.0.0"
MODEL_NAME = "CryptoRisk-RandomForestClassifier"


def score_to_risk_label(score: float) -> str:
    """
    Standard presentation boundary mapping: 0-100 risk score to risk category.
    0 = safe / minimal risk, 100 = critical risk.
    """
    if score <= 20.0:
        return "LOW"
    elif score <= 50.0:
        return "MODERATE"
    elif score <= 80.0:
        return "HIGH"
    else:
        return "CRITICAL"


def _build_feature_row(**kwargs) -> List[float]:
    """Helper to construct a feature vector with default 0.0 values."""
    return [float(kwargs.get(f, 0.0)) for f in CRYPTO_RISK_FEATURE_NAMES]


def generate_controlled_training_data(n_samples: int = 2500, seed: int = 42) -> Tuple[np.ndarray, np.ndarray]:
    """
    Generates a reproducible, controlled synthetic training dataset composed of
    WHOLE-SESSION email security archetypes with rich multi-issue permutations.
    
    IMPORTANT ARCHITECTURAL NOTE:
    Labels (LOW, MODERATE, HIGH, CRITICAL) describe the OVERALL SESSION SECURITY POSTURE
    of the complete observed feature combination, NOT individual point values.
    No real-world labeled PCAPs are claimed; controlled archetypes provide transparent,
    defensible training baselines that model multi-feature interactions.
    """
    rng = np.random.RandomState(seed)
    X_list: List[List[float]] = []
    y_list: List[str] = []
    protocols = ["smtp", "imap", "pop3"]

    for _ in range(n_samples):
        proto = rng.choice(protocols)

        # 1. Plaintext or Stripped STARTTLS (Critical risk exposures)
        is_plaintext = rng.rand() < 0.20
        if is_plaintext:
            is_stripped = rng.rand() < 0.35
            row = _build_feature_row(
                protocol_is_smtp=1.0 if proto == "smtp" else 0.0,
                protocol_is_imap=1.0 if proto == "imap" else 0.0,
                protocol_is_pop3=1.0 if proto == "pop3" else 0.0,
                starttls_upgrade_supported=1.0 if is_stripped else 0.0,
                starttls_upgrade_requested=1.0 if is_stripped else 0.0,
                starttls_is_incomplete=1.0 if is_stripped else 0.0,
                starttls_status_secure=0.0,
                tls_detected=0.0,
                plaintext_payload_observed=1.0,
                packet_count_norm=float(rng.uniform(0.05, 0.4)),
                client_bytes_ratio=float(rng.uniform(0.2, 0.7)),
                duration_norm=float(rng.uniform(0.01, 0.2))
            )
            X_list.append(row)
            y_list.append("CRITICAL")
            continue

        # 2. Encrypted TLS Sessions across varied cryptographic combinations
        tls_detected = 1.0

        # TLS Version
        v_roll = rng.rand()
        if v_roll < 0.35:
            tls_version = "1.3"
        elif v_roll < 0.75:
            tls_version = "1.2"
        else:
            tls_version = "1.0"  # Deprecated TLS (High flaw)

        # Cipher Suite
        c_roll = rng.rand()
        if tls_version == "1.3":
            cipher = "aead"
        elif c_roll < 0.55:
            cipher = "aead"
        elif c_roll < 0.88:
            cipher = "cbc"   # Moderate flaw
        else:
            cipher = "weak"  # 3DES / RC4 / DES (Critical flaw)

        # Key Exchange
        k_roll = rng.rand()
        if tls_version == "1.3":
            kex = "ecdhe"
        elif k_roll < 0.65:
            kex = "ecdhe"
        elif k_roll < 0.85:
            kex = "dhe"
        else:
            kex = "static_rsa"  # Moderate flaw (no PFS)

        # Certificate Validity
        cert_roll = rng.rand()
        is_expired = False
        is_self_signed = False
        days_expiry = float(rng.uniform(0.2, 2.0))
        if cert_roll < 0.65:
            cert_valid = True
        elif cert_roll < 0.85:
            cert_valid = False
            is_expired = True   # High flaw
            days_expiry = float(rng.uniform(-0.8, -0.1))
        else:
            cert_valid = True
            is_self_signed = True  # Moderate flaw

        # Public Key Architecture
        pk_roll = rng.rand()
        if pk_roll < 0.50:
            pk_type = "rsa_2048"
        elif pk_roll < 0.80:
            pk_type = "ec_p256"
        else:
            pk_type = "rsa_1024"  # High flaw

        # Signature Algorithm
        sig_roll = rng.rand()
        is_sha1 = (sig_roll < 0.15)  # High flaw

        # Hostname Verification
        hn_roll = rng.rand()
        hostname_mismatch = (hn_roll < 0.20) and not is_self_signed  # High flaw

        # Certificate Chain Validation
        chain_roll = rng.rand()
        if is_self_signed:
            chain_status = "incomplete"
        elif chain_roll < 0.75:
            chain_status = "valid"
        elif chain_roll < 0.90:
            chain_status = "incomplete"  # Moderate flaw
        else:
            chain_status = "invalid"     # High flaw

        has_app_data = rng.rand() > 0.35

        # Cumulative Cryptographic Severity
        severity = 0
        if cipher == "weak":
            severity += 4
        if tls_version == "1.0":
            severity += 2
        if is_expired:
            severity += 2
        if hostname_mismatch:
            severity += 2
        if pk_type == "rsa_1024":
            severity += 2
        if is_sha1:
            severity += 2
        if chain_status == "invalid":
            severity += 2
        if cipher == "cbc":
            severity += 1
        if kex == "static_rsa":
            severity += 1
        if chain_status == "incomplete":
            severity += 1
        if is_self_signed:
            severity += 1

        if severity == 0:
            label = "LOW"
        elif severity == 1:
            label = "MODERATE"
        elif severity <= 3:
            label = "HIGH"
        else:
            label = "CRITICAL"

        is_tls13 = (tls_version == "1.3")
        is_tls12 = (tls_version == "1.2")
        is_tls10 = (tls_version == "1.0")
        is_aead = (cipher == "aead")
        is_cbc = (cipher == "cbc")
        is_weak_cipher = (cipher == "weak")
        is_ecdhe = (kex == "ecdhe")
        is_dhe = (kex == "dhe")
        is_static_rsa = (kex == "static_rsa")
        has_pfs = (is_ecdhe or is_dhe)
        is_rsa = (pk_type in ("rsa_2048", "rsa_1024"))
        is_ec = (pk_type == "ec_p256")
        is_weak_key = (pk_type == "rsa_1024")

        row = _build_feature_row(
            protocol_is_smtp=1.0 if proto == "smtp" else 0.0,
            protocol_is_imap=1.0 if proto == "imap" else 0.0,
            protocol_is_pop3=1.0 if proto == "pop3" else 0.0,
            starttls_upgrade_supported=1.0,
            starttls_upgrade_requested=1.0,
            starttls_upgrade_accepted=1.0,
            starttls_transition_observed=1.0,
            starttls_status_secure=1.0,
            tls_detected=1.0,
            tls_version_is_1_3=1.0 if is_tls13 else 0.0,
            tls_version_is_1_2=1.0 if is_tls12 else 0.0,
            tls_version_is_1_0=1.0 if is_tls10 else 0.0,
            cipher_is_aead=1.0 if is_aead else 0.0,
            cipher_is_cbc=1.0 if is_cbc else 0.0,
            cipher_is_weak=1.0 if is_weak_cipher else 0.0,
            cipher_is_modern=1.0 if is_aead else 0.0,
            kex_is_ecdhe=1.0 if is_ecdhe else 0.0,
            kex_is_dhe=1.0 if is_dhe else 0.0,
            kex_is_static_rsa=1.0 if is_static_rsa else 0.0,
            forward_secrecy_present=1.0 if has_pfs else 0.0,
            forward_secrecy_absent=0.0 if has_pfs else 1.0,
            encrypted_application_data_observed=1.0 if has_app_data else 0.0,
            certificate_present=1.0,
            certificate_is_valid=1.0 if cert_valid else 0.0,
            certificate_is_expired=1.0 if is_expired else 0.0,
            certificate_is_self_signed=1.0 if is_self_signed else 0.0,
            days_until_expiry_norm=days_expiry,
            public_key_is_rsa=1.0 if is_rsa else 0.0,
            public_key_is_ec=1.0 if is_ec else 0.0,
            public_key_is_substandard=1.0 if is_weak_key else 0.0,
            signature_is_weak=1.0 if is_sha1 else 0.0,
            hostname_matches=0.0 if (hostname_mismatch or is_self_signed) else 1.0,
            hostname_mismatch=1.0 if hostname_mismatch else 0.0,
            chain_observable=1.0,
            chain_complete=1.0 if chain_status in ("valid", "incomplete") else 0.0,
            chain_status_valid=1.0 if chain_status == "valid" else 0.0,
            chain_status_incomplete=1.0 if chain_status == "incomplete" else 0.0,
            chain_status_invalid=1.0 if chain_status == "invalid" else 0.0,
            certificate_count_norm=0.4 if chain_status == "valid" else 0.2,
            chain_signatures_verified=1.0 if chain_status in ("valid", "incomplete") else 0.0,
            chain_ca_constraints_verified=1.0 if chain_status in ("valid", "incomplete") else 0.0,
            chain_validity_periods_verified=0.0 if is_expired else 1.0,
            chain_issuer_subject_linked=1.0 if chain_status == "valid" else 0.0,
            packet_count_norm=float(rng.uniform(0.1, 0.5)),
            duration_norm=float(rng.uniform(0.01, 0.1)),
            client_bytes_ratio=float(rng.uniform(0.1, 0.6))
        )
        X_list.append(row)
        y_list.append(label)

    return np.array(X_list, dtype=np.float32), np.array(y_list)


RISK_FEATURE_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "certificate_is_expired": {
        "label": "Expired certificate observed",
        "neutralize": {
            "certificate_is_expired": 0.0,
            "days_until_expiry_norm": 0.5,
            "certificate_is_valid": 1.0
        }
    },
    "chain_status_invalid": {
        "label": "Invalid certificate chain observed",
        "neutralize": {
            "chain_status_invalid": 0.0,
            "chain_status_valid": 1.0,
            "chain_signatures_verified": 1.0,
            "chain_ca_constraints_verified": 1.0
        }
    },
    "chain_status_incomplete": {
        "label": "Incomplete certificate chain observed",
        "neutralize": {
            "chain_status_incomplete": 0.0,
            "chain_complete": 1.0,
            "chain_status_valid": 1.0
        }
    },
    "starttls_is_incomplete": {
        "label": "Incomplete STARTTLS transition observed",
        "neutralize": {
            "starttls_is_incomplete": 0.0,
            "starttls_status_secure": 1.0
        }
    },
    "plaintext_payload_observed": {
        "label": "Plaintext application payload observed",
        "neutralize": {
            "plaintext_payload_observed": 0.0,
            "encrypted_application_data_observed": 1.0
        }
    },
    "forward_secrecy_absent": {
        "label": "Forward secrecy not observed",
        "neutralize": {
            "forward_secrecy_absent": 0.0,
            "forward_secrecy_present": 1.0,
            "kex_is_static_rsa": 0.0,
            "kex_is_ecdhe": 1.0
        }
    },
    "cipher_is_weak": {
        "label": "Weak cipher characteristics observed",
        "neutralize": {
            "cipher_is_weak": 0.0,
            "cipher_is_aead": 1.0,
            "cipher_is_modern": 1.0
        }
    },
    "cipher_is_cbc": {
        "label": "CBC-mode cipher observed",
        "neutralize": {
            "cipher_is_cbc": 0.0,
            "cipher_is_aead": 1.0,
            "cipher_is_modern": 1.0
        }
    },
    "tls_version_is_none": {
        "label": "Unencrypted session (no TLS observed)",
        "neutralize": {
            "tls_version_is_none": 0.0,
            "tls_detected": 1.0,
            "tls_version_is_1_2": 1.0
        }
    },
    "tls_version_is_ssl3": {
        "label": "Obsolete SSL protocol observed",
        "neutralize": {
            "tls_version_is_ssl3": 0.0,
            "tls_version_is_1_2": 1.0
        }
    },
    "tls_version_is_1_0": {
        "label": "TLS 1.0 observed",
        "neutralize": {
            "tls_version_is_1_0": 0.0,
            "tls_version_is_1_2": 1.0
        }
    },
    "tls_version_is_1_1": {
        "label": "TLS 1.1 observed",
        "neutralize": {
            "tls_version_is_1_1": 0.0,
            "tls_version_is_1_2": 1.0
        }
    },
    "certificate_is_self_signed": {
        "label": "Self-signed certificate observed",
        "neutralize": {
            "certificate_is_self_signed": 0.0,
            "chain_status_valid": 1.0
        }
    },
    "hostname_mismatch": {
        "label": "Certificate hostname mismatch observed",
        "neutralize": {
            "hostname_mismatch": 0.0,
            "hostname_matches": 1.0
        }
    },
    "public_key_is_substandard": {
        "label": "Substandard public-key characteristics observed",
        "neutralize": {
            "public_key_is_substandard": 0.0
        }
    },
    "signature_is_weak": {
        "label": "Weak certificate signature algorithm observed",
        "neutralize": {
            "signature_is_weak": 0.0
        }
    },
    "starttls_status_none": {
        "label": "Unencrypted session without STARTTLS observed",
        "neutralize": {
            "starttls_status_none": 0.0,
            "starttls_status_secure": 1.0
        }
    }
}


class CryptoRiskScorer:
    """
    ML-based cryptographic risk evaluation engine using a supervised RandomForestClassifier.
    Learns patterns from complete whole-session feature combinations.
    
    Predictions:
      - label: Overall session risk classification (LOW, MODERATE, HIGH, CRITICAL)
      - class_probabilities: Multi-class probabilities predicted by the ensemble
      - score: Continuous probability-weighted score (0-100) mapped from class-probability estimates
      - confidence: Ensemble confidence for the predicted class
      - top_risk_factors: Descriptive observed security characteristics
      - feature_contributions: Top model-important features actively observed in the session
    """

    def __init__(self, model_dir: Optional[str] = None, random_state: int = 42):
        self.random_state = random_state
        self.model: Optional[RandomForestClassifier] = None
        self.is_loaded: bool = False
        self.model_version: str = MODEL_VERSION
        self.model_name: str = MODEL_NAME
        self.training_samples_count: int = 0
        self.feature_importances: Dict[str, float] = {}
        self.is_persisted: bool = False

        if model_dir is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.model_dir = os.path.join(base_dir, "..", "models")
        else:
            self.model_dir = model_dir

        self.model_path = os.path.join(self.model_dir, "crypto_risk_model.joblib")
        self.train_or_load()

    def train_or_load(self) -> None:
        """
        Loads the persisted model artifact from disk if valid; otherwise trains
        on the reproducible controlled dataset and persists the artifact.
        """
        if os.path.exists(self.model_path):
            try:
                bundle = joblib.load(self.model_path)
                if isinstance(bundle, dict) and "model" in bundle and bundle.get("model_version") == MODEL_VERSION:
                    self.model = bundle["model"]
                    self.model_name = bundle.get("model_name", MODEL_NAME)
                    self.model_version = bundle.get("model_version", MODEL_VERSION)
                    self.training_samples_count = bundle.get("training_samples_count", 0)
                    self.feature_importances = bundle.get("feature_importances", {})
                    self.is_loaded = True
                    self.is_persisted = True
                    return
            except Exception:
                pass

        self.train_model()

    def train_model(self) -> None:
        """
        Trains RandomForestClassifier on whole-session cryptographic security configurations.
        """
        X, y = generate_controlled_training_data()
        rf = RandomForestClassifier(
            n_estimators=100,
            max_depth=8,
            min_samples_split=2,
            class_weight="balanced",
            random_state=self.random_state
        )
        rf.fit(X, y)

        self.model = rf
        self.is_loaded = True
        self.training_samples_count = len(X)
        self.feature_importances = {
            f_name: round(float(imp), 4)
            for f_name, imp in zip(CRYPTO_RISK_FEATURE_NAMES, rf.feature_importances_)
        }

        try:
            os.makedirs(self.model_dir, exist_ok=True)
            bundle = {
                "model": self.model,
                "model_name": self.model_name,
                "model_version": self.model_version,
                "training_dataset": "controlled-whole-session-cryptographic-archetypes-v2",
                "training_samples_count": self.training_samples_count,
                "feature_names": CRYPTO_RISK_FEATURE_NAMES,
                "feature_importances": self.feature_importances,
                "classes": list(rf.classes_),
                "random_state": self.random_state
            }
            joblib.dump(bundle, self.model_path)
            self.is_persisted = True
        except Exception:
            self.is_persisted = False

    def extract_vector(self, session: Dict[str, Any]) -> List[float]:
        """
        Extracts the numerical feature vector for CRYPTO_RISK_FEATURE_NAMES from session.
        Excludes any deterministic rule findings or posture scores.
        """
        ml_data = session.get("ml_features")
        if not ml_data or "features" not in ml_data:
            ml_data = extract_session_features(session)

        feat_dict = ml_data.get("features", {})
        vector = []
        for f in CRYPTO_RISK_FEATURE_NAMES:
            val = feat_dict.get(f, 0.0)
            try:
                vector.append(float(val))
            except (ValueError, TypeError):
                vector.append(0.0)
        return vector



    def _explain_prediction(
        self, feat_dict: Dict[str, Any], X: np.ndarray, predicted_label: str
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        Generates session-specific explanations using per-sample feature perturbation.
        
        Evaluates the current session feature vector X against the trained model:
        1. Measures predicted probability P_base for the predicted class.
        2. Perturbs/neutralizes each active risk feature while holding others constant.
        3. Measures the probability drop (delta P = P_base - P_masked).
        4. Identifies features that materially contributed to the current prediction.
        
        Zero hardcoded points (+10, -20) are used.
        """
        top_risk_factors: List[Dict[str, Any]] = []
        contributions: List[Dict[str, Any]] = []

        if not self.is_loaded or self.model is None:
            return top_risk_factors, contributions

        classes = list(self.model.classes_)
        if predicted_label not in classes:
            return top_risk_factors, contributions

        class_idx = classes.index(predicted_label)
        base_probs = self.model.predict_proba(X)[0]
        base_p = float(base_probs[class_idx])

        # ----------------------------------------------------------------------
        # 1. Session-Specific Top Observed Risk Factors (via Perturbation)
        # ----------------------------------------------------------------------
        if predicted_label in ("MODERATE", "HIGH", "CRITICAL"):
            for feat_name, defn in RISK_FEATURE_DEFINITIONS.items():
                if feat_name not in CRYPTO_RISK_FEATURE_NAMES:
                    continue
                feat_idx = CRYPTO_RISK_FEATURE_NAMES.index(feat_name)
                val = float(X[0, feat_idx])
                if val > 0:
                    # Perturb / neutralize this specific feature
                    X_masked = X.copy()
                    for k, v in defn["neutralize"].items():
                        if k in CRYPTO_RISK_FEATURE_NAMES:
                            X_masked[0, CRYPTO_RISK_FEATURE_NAMES.index(k)] = v

                    masked_probs = self.model.predict_proba(X_masked)[0]
                    p_masked = float(masked_probs[class_idx])
                    delta = base_p - p_masked

                    # If directly contributing to predicted class probability
                    if delta > 0.005:
                        top_risk_factors.append({
                            "feature": feat_name,
                            "label": defn["label"],
                            "contribution": round(float(delta), 4),
                            "observed": True
                        })
                    else:
                        # Also check contribution across the entire risk spectrum (MODERATE + HIGH + CRITICAL)
                        p_risk_base = sum(base_probs[classes.index(c)] for c in ("MODERATE", "HIGH", "CRITICAL") if c in classes)
                        p_risk_masked = sum(masked_probs[classes.index(c)] for c in ("MODERATE", "HIGH", "CRITICAL") if c in classes)
                        delta_risk = p_risk_base - p_risk_masked
                        if delta_risk > 0.005:
                            top_risk_factors.append({
                                "feature": feat_name,
                                "label": defn["label"],
                                "contribution": round(float(delta_risk), 4),
                                "observed": True
                            })

            # Sort strictly descending by contribution
            top_risk_factors.sort(key=lambda item: item["contribution"], reverse=True)

        # For secure sessions (LOW) or when no active risk factors contributed:
        if not top_risk_factors:
            top_risk_factors = [{
                "feature": "none",
                "label": "No significant risk factors observed",
                "contribution": 0.0,
                "observed": False
            }]

        # ----------------------------------------------------------------------
        # 2. Session-Specific Feature Influences (Perturbation-based ranking)
        # ----------------------------------------------------------------------
        feature_descriptions = {
            "tls_detected": ("TLS Handshake Negotiation", "TLS encryption established on transport stream"),
            "tls_version_is_1_3": ("TLS 1.3 Protocol Version", "Modern TLS 1.3 protocol handshake negotiated"),
            "tls_version_is_1_2": ("TLS 1.2 Protocol Version", "Standard TLS 1.2 protocol handshake negotiated"),
            "tls_version_is_1_0": ("Legacy TLS 1.0 Protocol", "Deprecated TLS 1.0 protocol version negotiated"),
            "tls_version_is_ssl3": ("Deprecated SSL Protocol", "Obsolete SSLv3 protocol version negotiated"),
            "cipher_is_aead": ("AEAD Cipher Mode", "Authenticated Encryption with Associated Data (AEAD) negotiated"),
            "cipher_is_weak": ("Weak Cipher Suite", "Insecure or broken cipher suite negotiated"),
            "cipher_is_modern": ("Modern Cipher Family", "Modern cipher algorithms in use"),
            "forward_secrecy_present": ("Perfect Forward Secrecy", "Ephemeral key exchange providing Perfect Forward Secrecy"),
            "forward_secrecy_absent": ("Static Key Exchange", "Missing Perfect Forward Secrecy (static key exchange)"),
            "starttls_is_incomplete": ("STARTTLS Upgrade State", "Incomplete STARTTLS negotiation transition"),
            "starttls_status_secure": ("STARTTLS Secure Transition", "STARTTLS state machine completed secure upgrade"),
            "certificate_is_valid": ("Certificate Validity", "Leaf certificate is within active validity period"),
            "certificate_is_expired": ("Certificate Expiration", "Leaf certificate validity period has expired"),
            "certificate_is_self_signed": ("Self-Signed Certificate", "Leaf certificate is self-signed"),
            "hostname_matches": ("Hostname Verification", "Certificate CN/SAN matches destination host"),
            "hostname_mismatch": ("Hostname Mismatch", "Certificate CN/SAN does not match destination host"),
            "chain_status_valid": ("Certificate Chain Validation", "Full valid certificate chain path with verified cryptographic signatures"),
            "chain_status_invalid": ("Chain Verification Failure", "Cryptographic signature or constraint failure in certificate chain"),
            "chain_complete": ("Certificate Chain Completeness", "Complete certificate chain presented by mail server"),
            "chain_signatures_verified": ("Chain Signatures", "Parent-child cryptographic signatures verified along certificate chain"),
            "plaintext_payload_observed": ("Plaintext Transport", "Unencrypted application payload observed on wire"),
            "encrypted_application_data_observed": ("Encrypted Application Data", "Application payload observed within encrypted TLS records")
        }

        active_influences = []
        for feat_name, (title, desc) in feature_descriptions.items():
            if feat_name in CRYPTO_RISK_FEATURE_NAMES:
                feat_idx = CRYPTO_RISK_FEATURE_NAMES.index(feat_name)
                val = float(X[0, feat_idx])
                if val > 0:
                    # Measure marginal contribution
                    X_m = X.copy()
                    X_m[0, feat_idx] = 0.0
                    p_m = float(self.model.predict_proba(X_m)[0][class_idx])
                    delta = base_p - p_m
                    imp = self.feature_importances.get(feat_name, 0.0)
                    active_influences.append((delta, imp, feat_name, title, desc))

        # Sort by session-specific contribution first, breaking ties with model importance
        active_influences.sort(key=lambda x: (x[0], x[1]), reverse=True)

        for delta, imp, feat_name, title, desc in active_influences[:6]:
            is_safe = any(s in feat_name for s in ("valid", "modern", "1_3", "1_2", "present", "matches", "secure", "complete", "verified")) and not any(r in feat_name for r in ("invalid", "absent", "weak", "expired", "mismatch", "substandard"))
            contributions.append({
                "feature": feat_name,
                "importance": round(imp, 4),
                "contribution": round(delta, 4),
                "direction": "RISK_REDUCING" if is_safe else "RISK_INCREASING",
                "description": f"{title}: {desc}"
            })

        return top_risk_factors, contributions

    def predict(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates an email session using the trained Random Forest Classifier.
        
        Returns:
            {
                "score": float (0.0 - 100.0 presentation score),
                "label": "LOW" | "MODERATE" | "HIGH" | "CRITICAL",
                "confidence": float (0.0 - 1.0),
                "model": "CryptoRisk-RandomForestClassifier",
                "model_version": "2.0.0",
                "class_probabilities": {"LOW": float, "MODERATE": float, "HIGH": float, "CRITICAL": float},
                "top_risk_factors": list[str],
                "feature_contributions": list[dict]
            }
        """
        if not self.is_loaded or self.model is None:
            return self._fallback_rule_prediction(session)

        try:
            vec = self.extract_vector(session)
            X = np.array([vec], dtype=float)

            # 1. Direct ML Multi-Class Probabilities
            raw_probs = self.model.predict_proba(X)[0]
            classes = list(self.model.classes_)
            class_probs: Dict[str, float] = {
                cls: round(float(prob), 4) for cls, prob in zip(classes, raw_probs)
            }

            # Ensure all canonical classes are present in dictionary
            for c in RISK_CLASSES:
                if c not in class_probs:
                    class_probs[c] = 0.0

            # 2. Predicted ML Class (Random Forest argmax probability)
            model_predicted_class = str(self.model.predict(X)[0])
            confidence = round(float(class_probs.get(model_predicted_class, 0.5)), 2)

            # 3. Probability-Weighted Continuous AI Risk Score (0.0 - 100.0)
            # Directly computed from class-probability estimates without class-based range clamping.
            weighted_score = (
                class_probs.get("LOW", 0.0) * CLASS_PRESENTATION_WEIGHTS["LOW"] +
                class_probs.get("MODERATE", 0.0) * CLASS_PRESENTATION_WEIGHTS["MODERATE"] +
                class_probs.get("HIGH", 0.0) * CLASS_PRESENTATION_WEIGHTS["HIGH"] +
                class_probs.get("CRITICAL", 0.0) * CLASS_PRESENTATION_WEIGHTS["CRITICAL"]
            )
            score = round(max(0.0, min(100.0, weighted_score)), 1)

            # 4. User-Facing Operational Risk Tier
            # Derived strictly from continuous score using documented score bands:
            # 0–20: LOW, 20.1–50: MODERATE, 50.1–80: HIGH, 80.1–100: CRITICAL
            operational_risk_tier = score_to_risk_label(score)

            # 5. Feature Influences and Observations (No manual points)
            ml_data = session.get("ml_features")
            if not ml_data or "features" not in ml_data:
                ml_data = extract_session_features(session)
            feat_dict = ml_data.get("features", {})

            top_risk_factors, contributions = self._explain_prediction(feat_dict, X, model_predicted_class)

            return {
                "score": score,
                "label": operational_risk_tier,
                "operational_risk_tier": operational_risk_tier,
                "model_predicted_class": model_predicted_class,
                "predicted_class": model_predicted_class,
                "confidence": confidence,
                "model": self.model_name,
                "model_version": self.model_version,
                "class_probabilities": class_probs,
                "top_risk_factors": top_risk_factors,
                "feature_contributions": contributions
            }

        except Exception:
            return self._fallback_rule_prediction(session)

    def _fallback_rule_prediction(self, session: Dict[str, Any]) -> Dict[str, Any]:
        """
        Heuristic fallback maintaining schema stability if ML model artifact is missing.
        Clearly designated as Fallback.
        """
        tls_info = session.get("tls", {})
        if not isinstance(tls_info, dict):
            tls_info = {}
        tls_detected = tls_info.get("detected", False)
        starttls_info = session.get("starttls", {})
        if not isinstance(starttls_info, dict):
            starttls_info = {}
        st_status = starttls_info.get("status", "")

        if not tls_detected:
            score = 95.0 if st_status == "INCOMPLETE" else 90.0
            label = "CRITICAL"
            top_factors = [{
                "feature": "plaintext_payload_observed",
                "label": "Unencrypted plaintext transmission observed",
                "contribution": 0.80,
                "observed": True
            }]
        elif tls_info.get("forward_secrecy") and tls_info.get("version") in ("TLSv1.2", "TLSv1.3"):
            score = 10.0
            label = "LOW"
            top_factors = [{
                "feature": "none",
                "label": "No significant risk factors observed",
                "contribution": 0.0,
                "observed": False
            }]
        else:
            score = 35.0
            label = "MODERATE"
            top_factors = [{
                "feature": "cipher_is_cbc",
                "label": "Acceptable TLS session with legacy or unverified parameters",
                "contribution": 0.20,
                "observed": True
            }]

        operational_tier = score_to_risk_label(score)
        return {
            "score": score,
            "label": operational_tier,
            "operational_risk_tier": operational_tier,
            "model_predicted_class": label,
            "predicted_class": label,
            "confidence": 0.70,
            "model": f"{self.model_name}-Fallback",
            "model_version": self.model_version,
            "class_probabilities": {label: 0.70},
            "top_risk_factors": top_factors,
            "feature_contributions": []
        }

    def get_model_status(self) -> Dict[str, Any]:
        """Returns metadata regarding the AI Cryptographic Risk model."""
        return {
            "model": self.model_name,
            "model_version": self.model_version,
            "is_loaded": self.is_loaded,
            "is_persisted": self.is_persisted,
            "model_path": self.model_path,
            "training_samples_count": self.training_samples_count,
            "feature_count": len(CRYPTO_RISK_FEATURE_NAMES),
            "features": CRYPTO_RISK_FEATURE_NAMES,
            "feature_importances": self.feature_importances,
            "random_state": self.random_state
        }


# Global singleton instance
crypto_risk_scorer_instance = CryptoRiskScorer()
