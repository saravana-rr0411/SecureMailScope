from fastapi import FastAPI, UploadFile, File, HTTPException, Body, WebSocket, WebSocketDisconnect, Request, Query, status as http_status
from fastapi.responses import Response, FileResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any, Optional, Tuple
import os
import shutil
import tempfile
import datetime
import json
import uuid
import logging
import base64
import re
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
from app.capture.agent_client import (
    request_authentic_pcap,
    get_capture_agent_status,
    is_capture_agent_configured,
)
from app.capture.agent_hub import agent_hub, normalize_os

logger = logging.getLogger("securemailscope")


def detect_client_os(request: Request, client_os_query: Optional[str] = None) -> str:
    """
    Detects client operating system with priority:
    1. Explicit query parameter (?client_os=windows)
    2. X-Client-OS request header
    3. User-Agent header inspection
    """
    if client_os_query:
        norm = normalize_os(client_os_query)
        if norm != "unknown":
            return norm

    header_os = request.headers.get("x-client-os") or request.headers.get("x-os")
    if header_os:
        norm = normalize_os(header_os)
        if norm != "unknown":
            return norm

    ua = request.headers.get("user-agent", "").lower()
    if "windows" in ua or "win32" in ua or "win64" in ua:
        return "windows"
    if "macintosh" in ua or "mac os" in ua or "darwin" in ua:
        return "macos"
    if "linux" in ua and "android" not in ua:
        return "linux"

    return "unknown"

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
    try:
        return get_dashboard_trends(period=period, date_str=date, month_str=month)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to fetch dashboard trends from Supabase: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve dashboard trends: {str(e)}")


@app.get("/api/capture/status")
async def capture_status_endpoint():
    """Returns status, configuration state, and readiness of the Authentic Capture Agent."""
    return await get_capture_agent_status()


@app.get("/api/agent/status")
async def agent_status_endpoint(request: Request, client_os: Optional[str] = Query(None)):
    """
    Returns the live connectivity status of the Capture Agent.
    Matches the connected agent to the browser client OS when possible.
    This works across all browsers (Safari, Chrome) because the frontend
    only makes HTTPS requests to this backend, not to localhost.
    """
    detected_os = detect_client_os(request, client_os)
    info = agent_hub.get_agent_info(client_os=detected_os)
    if info["online"]:
        selected = info.get("selected_agent") or (info["agents"][0] if info["agents"] else {})
        health = selected.get("health", {})
        agent_os = health.get("os") or selected.get("os", "unknown")
        return {
            "status": "connected",
            "agent": "SecureMailScope Capture Agent",
            "version": health.get("version", "1.0.0"),
            "os": agent_os,
            "platform": selected.get("os", "unknown"),
            "can_capture": health.get("can_capture", True),
            "is_busy": selected.get("is_busy", False),
            "matched_client_os": info.get("matched_client_os", False),
            "available_platforms": info.get("available_platforms", []),
            "total_agents": info.get("agent_count", 0),
        }
    else:
        return {
            "status": "not_detected",
            "agent": None,
            "message": "No Capture Agent is currently connected.",
        }


GITHUB_RELEASE_DOWNLOAD_BASE = "https://github.com/saravana-rr0411/SecureMailScope/releases/latest/download"
WINDOWS_INSTALLER_FILENAME = "SecureMailScopeCaptureAgent-1.0.2-Setup.exe"
MACOS_INSTALLER_FILENAME = "SecureMailScopeCaptureAgent-1.0.0.pkg"


@app.get("/api/agent/download/{platform_name}")
async def download_agent_package(platform_name: str):
    """
    Serves the prebuilt Capture Agent installer package for Windows or macOS.
    Serves local file from dist/ if present; otherwise fetches/streams the official
    release artifact directly to the client with caching, ensuring end users download
    the executable directly from the SecureMailScope website without visiting GitHub.
    """
    from pathlib import Path
    target = platform_name.lower().strip()
    dist_dir = Path(__file__).resolve().parent.parent.parent / "dist"

    if target in ("win", "windows", "exe"):
        filename = WINDOWS_INSTALLER_FILENAME
        exe_path = dist_dir / filename
        # If local cached binary exists and is valid (> 1MB), serve it immediately
        if exe_path.exists() and exe_path.stat().st_size > 1048576:
            return FileResponse(
                path=str(exe_path),
                media_type="application/vnd.microsoft.portable-executable",
                filename=filename,
                headers={"Content-Disposition": f'attachment; filename="{filename}"'}
            )

        remote_url = os.environ.get(
            "WINDOWS_AGENT_INSTALLER_URL",
            f"{GITHUB_RELEASE_DOWNLOAD_BASE}/{filename}"
        )

        # In cloud environments (e.g. Render / Heroku / Container), avoid buffering 60MB+ on
        # ephemeral disks which frequently leads to gateway timeouts, partial writes, and 0-byte files.
        # Direct 302 redirect ensures fast, reliable, full-speed download directly from GitHub / Azure CDN.
        if os.environ.get("STREAM_AGENT_INSTALLER", "1").lower() not in ("1", "true", "yes"):
            return RedirectResponse(url=remote_url, status_code=302)

        # Optional streaming mode with validation:
        try:
            import httpx
            async with httpx.AsyncClient(follow_redirects=True, timeout=httpx.Timeout(60.0, connect=10.0)) as http_client:
                async with http_client.stream("GET", remote_url) as stream_resp:
                    if stream_resp.status_code == 200:
                        dist_dir.mkdir(parents=True, exist_ok=True)
                        temp_path = dist_dir / f"{filename}.tmp"
                        with open(temp_path, "wb") as f:
                            async for chunk in stream_resp.aiter_bytes(chunk_size=65536):
                                f.write(chunk)
                        if temp_path.stat().st_size > 1000:
                            temp_path.replace(exe_path)
                            return FileResponse(
                                path=str(exe_path),
                                media_type="application/vnd.microsoft.portable-executable",
                                filename=filename,
                                headers={"Content-Disposition": f'attachment; filename="{filename}"'}
                            )
                        temp_path.unlink(missing_ok=True)
        except Exception as e:
            logger.warning(f"Could not stream Windows installer from {remote_url}: {e}")

        return RedirectResponse(
            url=remote_url,
            status_code=302
        )

    if target in ("mac", "macos", "darwin", "pkg"):
        filename = MACOS_INSTALLER_FILENAME
        pkg_path = dist_dir / filename
        if pkg_path.exists():
            return FileResponse(
                path=str(pkg_path),
                media_type="application/octet-stream",
                filename=filename,
                headers={"Content-Disposition": f'attachment; filename="{filename}"'}
            )
        return RedirectResponse(
            url=f"{GITHUB_RELEASE_DOWNLOAD_BASE}/{filename}",
            status_code=307
        )

    raise HTTPException(status_code=400, detail="Invalid platform. Expected 'windows' or 'macos'.")


@app.websocket("/ws/agent")
async def agent_websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for Capture Agents to establish persistent connections.
    The agent connects outbound from the user's machine to this backend.
    Authentication is via ?token= query parameter validated against CAPTURE_AGENT_API_KEY.
    """
    # Extract token from query parameters or Authorization header
    token = websocket.query_params.get("token", "")
    agent_os = websocket.query_params.get("os", "unknown")
    if not token:
        auth_header = websocket.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split("Bearer ", 1)[1].strip()
        elif auth_header:
            token = auth_header.strip()

    if not token:
        await websocket.close(code=4001, reason="Missing authentication token")
        return

    # Authenticate before accepting
    is_valid = await agent_hub.authenticate_agent(websocket, token)
    if not is_valid:
        await websocket.close(code=4003, reason="Invalid authentication token")
        return

    await websocket.accept()

    # Generate unique agent ID for this connection
    agent_id = f"agent-{uuid.uuid4().hex[:12]}"
    agent = await agent_hub.register_agent(websocket, agent_id, client_os=agent_os)

    try:
        while True:
            message = await websocket.receive()

            if message.get("type") == "websocket.receive":
                if "text" in message:
                    try:
                        data = json.loads(message["text"])
                        await agent_hub.handle_agent_message(agent_id, data)
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON from agent {agent_id}")
                elif "bytes" in message:
                    await agent_hub.handle_agent_binary(agent_id, message["bytes"])

            elif message.get("type") == "websocket.disconnect":
                break

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.warning(f"Agent {agent_id} connection error: {e}")
    finally:
        await agent_hub.unregister_agent(agent_id)


# Storage for recently generated authentic PCAPs and whitelisted captures for download
_recent_pcaps: Dict[str, Tuple[bytes, str]] = {}


def store_pcap_for_download(capture_id: str, filename: str, pcap_bytes: bytes) -> None:
    """Stores authentic PCAP binary in memory for direct download endpoint."""
    if len(_recent_pcaps) > 100:
        oldest_key = next(iter(_recent_pcaps))
        _recent_pcaps.pop(oldest_key, None)
    _recent_pcaps[capture_id] = (pcap_bytes, filename)
    _recent_pcaps[filename] = (pcap_bytes, filename)


@app.post("/api/capture/generate-authentic")
async def generate_authentic_capture_endpoint(
    request: Request,
    payload: Optional[Dict[str, Any]] = Body(None),
    client_os: Optional[str] = Query(None),
):
    """
    Triggers an authentic live network packet capture via the dedicated Capture Agent.

    Priority order:
    1. WebSocket Bridge — if an agent is connected via WS, relay the command
    2. Direct HTTP — fallback to direct HTTP call to CAPTURE_AGENT_URL

    Streams the genuine PCAP binary, executes the existing forensic analysis pipeline,
    persists the analysis in Supabase, and returns the result with PCAP download data.
    """
    protocol = "SMTP"
    profile = "secure_tls12"
    port = None
    target_host = None
    duration_seconds = None
    interface = None

    body_client_os = (payload.get("client_os") or payload.get("os")) if payload else None
    effective_client_os = detect_client_os(request, client_os or body_client_os)

    ports = None
    if payload:
        protocol = payload.get("protocol", "SMTP")
        profile = payload.get("profile", "secure_tls12")
        port = payload.get("port")
        ports = payload.get("ports")
        target_host = payload.get("target_host")
        duration_seconds = payload.get("duration_seconds")
        interface = payload.get("interface")

    if (profile and profile.lower() in ("gmail", "submission")) or port in (587, 465) or (ports and any(p in (587, 465) for p in ports)):
        profile = "gmail"
        protocol = "SMTP"
        port = port or 587
        ports = ports or [587, 465]
        target_host = target_host if (target_host and target_host != "smtp.gmail.com") else None
        duration_seconds = float(duration_seconds or 40.0)

    tmp_path = None
    filename = None
    pcap_raw_bytes = None
    try:
        # Path 1: Try WebSocket Bridge (agent connected outbound to this backend)
        if agent_hub.is_agent_online(client_os=effective_client_os):
            try:
                logger.info(f"Attempting capture via WebSocket Bridge (profile={profile}, port={port}, ports={ports}, client_os={effective_client_os})...")
                pending = await agent_hub.request_capture(
                    protocol=protocol,
                    profile=profile,
                    port=port,
                    ports=ports,
                    target_host=target_host,
                    duration_seconds=duration_seconds,
                    interface=interface,
                    client_os=effective_client_os,
                )
                wait_timeout = (duration_seconds + 20) if duration_seconds else 60
                pcap_bytes, filename = await agent_hub.await_capture_result(pending, timeout=wait_timeout)
                pcap_raw_bytes = pcap_bytes

                # Write PCAP bytes to temp file for analysis
                tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap", prefix="sms_ws_cap_")
                tmp_file.write(pcap_bytes)
                tmp_file.close()
                tmp_path = tmp_file.name

                logger.info(f"Received PCAP via WebSocket Bridge: {filename} ({len(pcap_bytes)} bytes)")
            except Exception as ws_err:
                logger.error(f"WebSocket Bridge capture failed on agent: {ws_err}")
                # Do not fallback to 127.0.0.1 on Render server; raise the real error
                is_sub_err = (
                    "No SMTP submission packets" in str(ws_err) or
                    "No Gmail SMTP submission traffic" in str(ws_err)
                )
                raise HTTPException(
                    status_code=400 if is_sub_err else 500,
                    detail=f"Capture Agent error: {str(ws_err)}"
                )

        # Path 2: Direct HTTP to Capture Agent (fallback / local development)
        if not tmp_path:
            tmp_path, filename = await request_authentic_pcap(
                protocol=protocol,
                profile=profile,
                port=port,
                ports=ports,
                target_host=target_host,
                duration_seconds=duration_seconds,
                interface=interface,
            )
            try:
                with open(tmp_path, "rb") as f:
                    pcap_raw_bytes = f.read()
            except Exception as read_err:
                logger.warning(f"Could not read raw PCAP bytes from {tmp_path}: {read_err}")

        # Process through the existing analyze_pcap forensic pipeline
        result = analyze_pcap(tmp_path)

        result["filename"] = filename
        result["capture_id"] = f"pcap_{filename}"
        result["analyzed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result["capture_source"] = "AUTHENTIC_AUTO_CAPTURE"

        # Attach genuine PCAP binary download metadata and base64 payload
        if pcap_raw_bytes:
            result["pcap_base64"] = base64.b64encode(pcap_raw_bytes).decode("ascii")
            result["pcap_filename"] = filename
            result["pcap_size_bytes"] = len(pcap_raw_bytes)
            result["pcap_download_url"] = f"/api/capture/download/{result['capture_id']}"
            store_pcap_for_download(result["capture_id"], filename, pcap_raw_bytes)

        # Persist into Supabase persistent storage
        if is_supabase_configured():
            try:
                save_analysis_result(result)
                logger.info(f"Authentic capture analysis persisted to Supabase: {result['capture_id']}")
            except Exception as storage_err:
                logger.warning(f"Supabase storage warning during authentic capture: {storage_err}")

        return result
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to generate authentic capture: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to generate authentic capture: {str(e)}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


@app.get("/api/capture/download/{capture_id}")
def download_capture_endpoint(capture_id: str):
    """
    Downloads genuine PCAP binary for a generated authentic capture or whitelisted demo.
    Validates capture_id against directory traversal attacks.
    """
    # Strict validation: alphanumeric, dashes, underscores, dots only; reject path traversal
    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", capture_id) or ".." in capture_id:
        raise HTTPException(status_code=400, detail="Invalid capture identifier.")

    # 1. Check in-memory store for recently captured PCAPs
    if capture_id in _recent_pcaps:
        pcap_bytes, filename = _recent_pcaps[capture_id]
        return Response(
            content=pcap_bytes,
            media_type="application/vnd.tcpdump.pcap",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Length": str(len(pcap_bytes)),
            }
        )

    # 2. Check demo captures whitelist fallback
    for demo_key, demo_file in DEMO_CAPTURES_WHITELIST.items():
        if capture_id in (demo_key, demo_file, f"pcap_{demo_file}"):
            pcap_path = os.path.join(DATASET_DIR, demo_file)
            if os.path.exists(pcap_path):
                with open(pcap_path, "rb") as f:
                    pcap_bytes = f.read()
                return Response(
                    content=pcap_bytes,
                    media_type="application/vnd.tcpdump.pcap",
                    headers={
                        "Content-Disposition": f'attachment; filename="{demo_file}"',
                        "Content-Length": str(len(pcap_bytes)),
                    }
                )

    raise HTTPException(status_code=404, detail="Capture file not found or expired.")



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
