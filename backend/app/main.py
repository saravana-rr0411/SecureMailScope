from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
import os
import shutil
import tempfile
from app.capture.pcap_reader import analyze_pcap
from app.ml.anomaly_detector import detector_instance, create_synthetic_development_baseline
from app.ml.crypto_risk_scorer import crypto_risk_scorer_instance

app = FastAPI(title="SecureMailScope MVP")

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_origin_regex=r".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Explicit whitelist mapping for built-in demo captures
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DATASET_DIR = os.path.join(PROJECT_ROOT, "dataset")

DEMO_CAPTURES_WHITELIST = {
    "secure_tls": "tls_test_email.pcap",
    "incomplete_starttls": "test_email.pcap",
    "pop3_stls": "09_pop3_stls.pcap",
    "self_signed": "05_self_signed_certificate.pcap"
}

# Auto-initialize development baseline on module load
if not detector_instance.is_trained:
    synth_baseline = create_synthetic_development_baseline(20)
    detector_instance.train_baseline(synth_baseline)

# Ensure AI Cryptographic Risk Scorer is loaded/trained
if not crypto_risk_scorer_instance.is_loaded:
    crypto_risk_scorer_instance.train_or_load()


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "service": "SecureMailScope"
    }


@app.post("/api/pcap/analyze")
async def analyze_pcap_endpoint(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(('.pcap', '.pcapng')):
        raise HTTPException(status_code=400, detail="Unsupported file extension. Only .pcap and .pcapng are allowed.")
    
    try:
        # Create a temporary file
        file.file.seek(0)
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(file.filename)[1]) as tmp:
            shutil.copyfileobj(file.file, tmp)
            tmp_path = tmp.name

        # Process the PCAP file
        result = analyze_pcap(tmp_path)
        
        # We replace the tmp filename with the original filename for the output
        result["filename"] = file.filename
        
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    finally:
        # Cleanup temp file
        if 'tmp_path' in locals() and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


@app.post("/api/pcap/demo/{demo_name}")
def analyze_demo_pcap_endpoint(demo_name: str):
    """
    Executes forensic analysis on verified built-in demonstration PCAP files.
    Strictly whitelisted to prevent arbitrary path traversal.
    """
    if demo_name not in DEMO_CAPTURES_WHITELIST:
        raise HTTPException(
            status_code=404, 
            detail=f"Demo capture '{demo_name}' not found. Allowed demos: {list(DEMO_CAPTURES_WHITELIST.keys())}"
        )

    filename = DEMO_CAPTURES_WHITELIST[demo_name]
    file_path = os.path.join(DATASET_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail=f"Demo capture file '{filename}' is missing from the dataset directory.")

    try:
        result = analyze_pcap(file_path)
        result["filename"] = filename
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred during demo analysis: {str(e)}")


@app.post("/api/ml/baseline/train")
def train_baseline_endpoint(payload: Optional[Dict[str, Any]] = Body(None)):
    """
    Trains the Isolation Forest baseline anomaly model.
    Accepts custom normal sessions or uses the controlled synthetic development baseline.
    """
    sessions = []
    if payload and "sessions" in payload and payload["sessions"]:
        sessions = payload["sessions"]
    elif payload and payload.get("use_synthetic_dev_baseline"):
        count = payload.get("count", 20)
        sessions = create_synthetic_development_baseline(count)
    else:
        # Default to synthetic development baseline if no sessions supplied
        sessions = create_synthetic_development_baseline(20)

    result = detector_instance.train_baseline(sessions)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("message", "Training failed"))
    return result


@app.post("/api/ml/anomaly/predict")
def predict_anomaly_endpoint(payload: Dict[str, Any] = Body(...)):
    """Evaluates an analyzed session against the trained baseline anomaly model."""
    session = payload.get("session") if "session" in payload else payload
    if not session:
        raise HTTPException(status_code=400, detail="Session data is required for anomaly prediction.")
    return detector_instance.predict(session)


@app.get("/api/ml/model/status")
def get_model_status_endpoint():
    """Returns the current anomaly detection model metadata and training status."""
    return detector_instance.get_model_status()


@app.get("/api/ml/risk/status")
def get_crypto_risk_status_endpoint():
    """Returns the AI Cryptographic Risk model metadata and status."""
    return crypto_risk_scorer_instance.get_model_status()


@app.post("/api/ml/risk/predict")
def predict_crypto_risk_endpoint(payload: Dict[str, Any] = Body(...)):
    """Evaluates an analyzed session against the AI Cryptographic Risk model."""
    session = payload.get("session") if "session" in payload else payload
    if not session:
        raise HTTPException(status_code=400, detail="Session data is required for cryptographic risk evaluation.")
    return crypto_risk_scorer_instance.predict(session)
