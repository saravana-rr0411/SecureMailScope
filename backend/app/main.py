from fastapi import FastAPI, UploadFile, File, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional
import os
import shutil
import tempfile
import datetime
import logging
from app.capture.pcap_reader import analyze_pcap
from app.ml.anomaly_detector import detector_instance, create_synthetic_development_baseline
from app.ml.crypto_risk_scorer import crypto_risk_scorer_instance
from app.storage.supabase_client import is_supabase_configured
from app.storage.repository import (
    save_analysis_result,
    get_analysis_results,
    get_analysis_result,
    delete_analysis_result,
    get_available_periods,
    get_dashboard_trends,
)

logger = logging.getLogger("securemailscope")

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
        
        # Canonical metadata
        result["filename"] = file.filename
        result["capture_id"] = f"pcap_{file.filename}"
        result["analyzed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Persist into Supabase persistent storage
        if is_supabase_configured():
            try:
                saved = save_analysis_result(result)
                logger.info(f"Analysis successfully persisted to Supabase for capture_id: {saved.get('capture_id')}")
            except Exception as storage_err:
                logger.warning(f"Supabase storage error during PCAP analysis: {storage_err}")
        else:
            logger.info("Supabase storage skipped: SUPABASE_URL or SUPABASE_KEY not configured in environment.")

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
        result["capture_id"] = f"pcap_{filename}"
        result["analyzed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Persist into Supabase persistent storage
        if is_supabase_configured():
            try:
                save_analysis_result(result)
            except Exception as storage_err:
                logger.warning(f"Supabase storage error during demo analysis: {storage_err}")

        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred during demo analysis: {str(e)}")


@app.get("/api/captures")
def get_captures_endpoint():
    """
    Retrieves stored analysis history from Supabase table 'analysis_results'.
    Returns stored analysis results in format compatible with frontend state.
    """
    if not is_supabase_configured():
        logger.info("GET /api/captures: Supabase storage is not configured; returning empty list.")
        return []
    try:
        return get_analysis_results()
    except Exception as e:
        logger.error(f"Failed to fetch captures from Supabase: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve captures: {str(e)}")


@app.get("/api/captures/{capture_id}")
def get_capture_endpoint(capture_id: str):
    """
    Retrieves a single stored analysis result by capture_id from Supabase.
    """
    if not is_supabase_configured():
        raise HTTPException(status_code=503, detail="Supabase storage is not configured.")
    try:
        capture = get_analysis_result(capture_id)
        if not capture:
            raise HTTPException(status_code=404, detail=f"Capture '{capture_id}' not found.")
        return capture
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to fetch capture '{capture_id}': {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve capture: {str(e)}")


@app.delete("/api/captures/{capture_id}")
def delete_capture_endpoint(capture_id: str):
    """
    Deletes a stored analysis result by capture_id from Supabase.
    """
    if not is_supabase_configured():
        raise HTTPException(status_code=503, detail="Supabase storage is not configured.")
    try:
        deleted = delete_analysis_result(capture_id)
        if not deleted:
            raise HTTPException(status_code=404, detail=f"Capture '{capture_id}' not found or already deleted.")
        return {"status": "deleted", "capture_id": capture_id}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete capture '{capture_id}': {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete capture: {str(e)}")


@app.get("/api/dashboard/periods")
def get_dashboard_periods_endpoint():
    """
    Retrieves available filter periods (dates and months) generated dynamically
    from actual 'analysis_results.analyzed_at' values in Supabase.
    Credentials remain backend-only.
    """
    if not is_supabase_configured():
        return {"dates": [], "months": []}
    try:
        return get_available_periods()
    except Exception as e:
        logger.error(f"Failed to fetch dashboard periods from Supabase: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve dashboard periods: {str(e)}")


@app.get("/api/dashboard/trends")
def get_dashboard_trends_endpoint(
    period: str = "daily",
    date: Optional[str] = None,
    month: Optional[str] = None
):
    """
    Retrieves trend and security status aggregation points for the Executive Dashboard graphs
    filtered strictly by Daily or Monthly period from Supabase 'analysis_results'.
    Performs careful date/time boundary queries against timestamptz analyzed_at.
    """
    if period not in ("daily", "monthly"):
        raise HTTPException(status_code=400, detail="Invalid period type. Must be 'daily' or 'monthly'.")
    if not is_supabase_configured():
        return {
            "period": period,
            "date": date,
            "month": month,
            "points": [],
            "summary": {
                "total": 0, "secure": 0, "insecure": 0,
                "securePct": 0, "insecurePct": 0, "avgRisk": None, "totalSessions": 0
            }
        }
    try:
        return get_dashboard_trends(period=period, date_str=date, month_str=month)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to fetch dashboard trends from Supabase: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve dashboard trends: {str(e)}")



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
