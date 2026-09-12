import os
import hmac
import time
import secrets
import asyncio
import logging
import datetime
from pathlib import Path
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, BackgroundTasks, status, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from capture_agent.config import (
    CAPTURE_AGENT_SECRET_KEY,
    AGENT_HOST,
    AGENT_PORT,
    LOCAL_ONLY,
    TEST_SMTP_HOST,
    TEST_SMTP_PORT,
    PCAP_STORAGE_DIR,
    HANDSHAKE_TOKEN_TTL_SECONDS,
    BACKEND_WS_URL,
    WS_HEARTBEAT_INTERVAL,
    WS_RECONNECT_MAX_DELAY,
    get_allowed_origins,
    is_origin_allowed,
    detect_loopback_interface,
    get_tcpdump_binary,
    check_capture_capabilities,
    get_current_os,
    get_capture_interface,
    detect_active_interface
)
from capture_agent.certs.cert_manager import generate_test_certificate
from capture_agent.traffic.smtp_server import AuthenticSmtpServer
from capture_agent.traffic.smtp_client import AuthenticSmtpClient
from capture_agent.recorder.packet_capturer import PacketCapturer

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("capture_agent")


@asynccontextmanager
async def lifespan(app):
    """Manage WebSocket Bridge lifecycle."""
    from capture_agent.ws_bridge import start_ws_bridge, stop_ws_bridge
    if BACKEND_WS_URL and CAPTURE_AGENT_SECRET_KEY:
        logger.info(f"Starting WebSocket bridge to {BACKEND_WS_URL}...")
        await start_ws_bridge(
            backend_ws_url=BACKEND_WS_URL,
            api_key=CAPTURE_AGENT_SECRET_KEY,
            heartbeat_interval=WS_HEARTBEAT_INTERVAL,
            reconnect_max_delay=WS_RECONNECT_MAX_DELAY,
        )
    elif not CAPTURE_AGENT_SECRET_KEY:
        logger.info("WebSocket bridge disabled: CAPTURE_AGENT_SECRET_KEY not configured.")
    else:
        logger.info("WebSocket bridge disabled: BACKEND_WS_URL not configured.")
    yield
    await stop_ws_bridge()
    logger.info("WebSocket bridge stopped.")


app = FastAPI(
    title="SecureMailScope Capture Agent",
    description="Dedicated user-local background agent for authentic packet capture of real email traffic",
    version="1.0.0",
    lifespan=lifespan,
)

# Strict Whitelist of Allowed Web Origins (NO WILDCARD)
ALLOWED_ORIGINS = get_allowed_origins()

# Enable CORS strictly for authorized SecureMailScope frontend origins and support Private Network Access (PNA)
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"^https:\/\/secure-mail-scope(?:-[a-z0-9-]+)?\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    allow_private_network=True,
    expose_headers=[
        "X-Capture-Filename",
        "X-Capture-Source",
        "X-Capture-Protocol",
        "Content-Disposition"
    ]
)


@app.middleware("http")
async def enforce_localhost_and_origin(request: Request, call_next):
    """
    Security Middleware:
    1. Localhost IP Enforcement: Rejects connections not originating from loopback.
    2. DNS Rebinding Protection: Validates that the Host header is localhost/127.0.0.1.
    3. Origin Whitelist Enforcement: For browser cross-origin requests, strictly enforces
       the SecureMailScope origin whitelist.
    """
    # 1. Localhost Client IP enforcement
    if LOCAL_ONLY:
        client_host = request.client.host if request.client else ""
        if client_host and client_host not in ("127.0.0.1", "::1", "localhost", "testclient", "testserver"):
            logger.warning(f"Rejected non-local connection attempt from client IP: {client_host}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "Forbidden: Capture Agent only accepts connections originating from localhost."}
            )

    # 2. Host Header Validation (DNS Rebinding protection)
    raw_host = request.headers.get("host", "").split(":")[0].lower()
    if raw_host and raw_host not in ("127.0.0.1", "localhost", "::1", "testclient", "testserver"):
        logger.warning(f"Rejected request with unauthorized Host header (DNS rebinding attempt): {raw_host}")
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": "Forbidden: Invalid Host header."}
        )

    # 3. Origin Whitelist Validation for browser requests
    origin = request.headers.get("origin")
    if origin and not is_origin_allowed(origin):
        logger.warning(f"Rejected request from disallowed Origin: {origin}")
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": f"Forbidden: Cross-origin access from '{origin}' is not permitted."}
        )

    response = await call_next(request)
    if origin and is_origin_allowed(origin):
        response.headers["Access-Control-Allow-Private-Network"] = "true"
    return response


# Global mutex ensuring only one capture runs at a time
capture_lock = asyncio.Lock()

# Ephemeral handshake token storage: token -> expiration_timestamp (float)
ephemeral_tokens: Dict[str, float] = {}
tokens_lock = asyncio.Lock()


async def create_ephemeral_token(ttl_seconds: int = HANDSHAKE_TOKEN_TTL_SECONDS) -> str:
    """Generates a cryptographically strong, single-use ephemeral token with TTL."""
    async with tokens_lock:
        now = time.time()
        # Prune expired tokens
        expired = [t for t, exp in ephemeral_tokens.items() if exp < now]
        for t in expired:
            ephemeral_tokens.pop(t, None)

        token = secrets.token_urlsafe(32)
        ephemeral_tokens[token] = now + ttl_seconds
        return token


async def consume_ephemeral_token(token: str) -> bool:
    """
    Verifies and immediately consumes (pops) an ephemeral token.
    Returns True if the token was valid, unexpired, and successfully consumed.
    Returns False otherwise. Single-use consumption guarantees replay protection.
    """
    async with tokens_lock:
        now = time.time()
        if token in ephemeral_tokens:
            exp = ephemeral_tokens.pop(token)
            if exp >= now:
                return True
            logger.warning("Attempted use of expired ephemeral capture token.")
            return False
        return False


class HandshakeResponse(BaseModel):
    token: str
    token_type: str = "Bearer"
    expires_in: int
    status: str = "ready"


class CaptureRequest(BaseModel):
    protocol: str = "SMTP"
    profile: str = "secure_tls12"
    timeout_seconds: float = 15.0
    port: Optional[int] = None
    ports: Optional[List[int]] = None
    interface: Optional[str] = None
    target_host: Optional[str] = None
    duration_seconds: Optional[float] = None


@app.post("/api/v1/auth/handshake", response_model=HandshakeResponse)
async def auth_handshake(request: Request):
    """
    Secure Localhost Handshake Endpoint:
    1. Validates that request originated from an authorized SecureMailScope Origin.
    2. Validates custom 'X-Requested-With: SecureMailScope' header.
    3. Issues a cryptographically random, 60s single-use ephemeral token.
    Zero shared secrets or long-lived keys are exposed to the client bundle.
    """
    origin = request.headers.get("origin")
    if not origin or not is_origin_allowed(origin):
        logger.warning(f"Handshake rejected: missing or unauthorized Origin: {origin}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: Origin '{origin}' is not authorized to interact with this Capture Agent."
        )

    requested_with = request.headers.get("x-requested-with")
    if requested_with != "SecureMailScope":
        logger.warning("Handshake rejected: missing or invalid X-Requested-With header.")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bad Request: Missing or invalid 'X-Requested-With: SecureMailScope' header."
        )

    token = await create_ephemeral_token(HANDSHAKE_TOKEN_TTL_SECONDS)
    logger.info(f"Issued ephemeral handshake token for origin: {origin}")
    return {
        "token": token,
        "token_type": "Bearer",
        "expires_in": HANDSHAKE_TOKEN_TTL_SECONDS,
        "status": "ready"
    }


async def verify_bearer_auth(authorization: Optional[str] = Header(None)) -> str:
    """
    Verifies incoming Bearer authorization using dual-authentication:
    1. Ephemeral Single-Use Token: Issued via /api/v1/auth/handshake (used by Web Frontend).
       Immediately consumed upon verification (replay protection).
    2. Server-to-Server Secret Key: Configured in backend environment via CAPTURE_AGENT_SECRET_KEY
       (used by Backend Proxy, automated Pytest, CLI tools).
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Expected: Bearer <token>"
        )

    provided_token = authorization.split("Bearer ", 1)[1].strip()
    if not provided_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Empty Bearer token provided."
        )

    # Check 1: Try consuming as an ephemeral single-use session token
    is_valid_ephemeral = await consume_ephemeral_token(provided_token)
    if is_valid_ephemeral:
        logger.info("Authenticated request via valid ephemeral handshake token.")
        return provided_token

    # Check 2: Try verifying against server secret key (constant-time comparison)
    expected_secret = CAPTURE_AGENT_SECRET_KEY.strip()
    if expected_secret and hmac.compare_digest(provided_token.encode("utf-8"), expected_secret.encode("utf-8")):
        logger.info("Authenticated request via server secret key.")
        return provided_token

    logger.warning("Rejected unauthorized request to Capture Agent.")
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired capture agent authorization token."
    )


def cleanup_file_safely(file_path: str):
    """Safely removes a file from disk in a background task."""
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.debug(f"Cleaned up temporary capture file: {file_path}")
    except Exception as e:
        logger.warning(f"Error cleaning up file {file_path}: {e}")


@app.get("/health")
def health_check():
    """Returns agent readiness, OS diagnostics, interface, and capture capability status."""
    can_cap, diag, req_sudo = check_capture_capabilities()
    return {
        "status": "OK",
        "agent": "SecureMailScope Capture Agent",
        "version": "1.0.0",
        "os": get_current_os(),
        "interface": detect_loopback_interface(),
        "tcpdump_path": get_tcpdump_binary(),
        "can_capture": can_cap,
        "capability_diagnostic": diag,
        "requires_sudo": req_sudo,
        "is_busy": capture_lock.locked()
    }


@app.post("/api/v1/capture/generate")
async def generate_authentic_capture(
    request: CaptureRequest = CaptureRequest(),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    authorization: Optional[str] = Header(None)
):
    """
    Executes an authentic packet capture of real email traffic:
    1. Authenticates request via Bearer token (ephemeral handshake token or server secret)
    2. Generates real X.509 certificate
    3. Starts tcpdump packet sniffer on controlled interface and test port
    4. Launches authentic SMTP server with TLS 1.2
    5. Executes authentic SMTP client through operating system TCP stack
    6. Stops tcpdump and verifies the generated PCAP
    7. Streams raw PCAP binary to caller
    """
    await verify_bearer_auth(authorization)

    # Check if a capture is already in progress
    if capture_lock.locked():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Another packet capture is currently in progress. Captures are strictly serialized."
        )

    async with capture_lock:
        is_gmail_mode = (
            request.port in (587, 465) or
            (request.ports and any(p in (587, 465) for p in request.ports)) or
            (request.profile and request.profile.lower() in ("gmail", "submission", "port_587", "port_465")) or
            (request.protocol and request.protocol.upper() in ("GMAIL", "SUBMISSION"))
        )
        timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = (
            f"authentic_gmail_smtp_submission_{timestamp_str}.pcap"
            if is_gmail_mode
            else f"authentic_{request.protocol.lower()}_tls_{timestamp_str}.pcap"
        )
        output_dir = PCAP_STORAGE_DIR
        output_dir.mkdir(parents=True, exist_ok=True)
        output_pcap_path = str(output_dir / filename)

        cert_material = None
        server = None
        capturer = None

        try:
            logger.info(f"Starting authentic {request.protocol} capture sequence (profile={request.profile}, port={request.port})...")

            if is_gmail_mode:
                # Live external Gmail / mail submission capture mode (e.g. from desktop mail client)
                gmail_ports = request.ports or ([request.port] if request.port in (587, 465) else [587, 465])
                capturer = PacketCapturer(
                    output_pcap_path=output_pcap_path,
                    ports=gmail_ports,
                    interface=request.interface or get_capture_interface(gmail_ports),
                    host=request.target_host
                )
                duration = request.duration_seconds or request.timeout_seconds or 40.0
                logger.info(f"Capturing live Gmail SMTP submission traffic on {capturer.bpf_filter} ({capturer.interface}) for {duration}s...")
                capturer.start(settle_delay=0.2)
                await asyncio.sleep(duration)
                capturer.stop()

                pcap_path = Path(output_pcap_path)
                if not pcap_path.exists() or pcap_path.stat().st_size <= 24:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="No Gmail SMTP submission traffic detected during the capture window. Send an email using your configured desktop mail client while capture is active."
                    )
            else:
                # 1. Generate real X.509 certificate
                cert_material = generate_test_certificate(
                    common_name="mail.securemailscope.test",
                    validity_days=365,
                    key_size=2048
                )

                # 2. Initialize & Start Real SMTP Server (must be listening before tcpdump starts)
                server = AuthenticSmtpServer(
                    host=TEST_SMTP_HOST,
                    port=TEST_SMTP_PORT,
                    cert_path=cert_material.cert_path,
                    key_path=cert_material.key_path
                )
                server.start()
                logger.info(f"Authentic SMTP Server listening on {TEST_SMTP_HOST}:{server.actual_port}")

                # 3. Initialize & Start Packet Capturer (ensures tcpdump is listening before client connects)
                capturer = PacketCapturer(
                    output_pcap_path=output_pcap_path,
                    port=server.actual_port
                )
                capturer.start(settle_delay=0.2)

                # 4. Execute Real SMTP Client in a thread pool to avoid blocking the async event loop
                def run_client_task():
                    client = AuthenticSmtpClient(
                        host=TEST_SMTP_HOST,
                        port=server.actual_port,
                        local_hostname="client.securemailscope.test",
                        timeout=8.0
                    )
                    return client.execute_session()

                loop = asyncio.get_running_loop()
                await loop.run_in_executor(None, run_client_task)

                # Settle delay to ensure all TCP teardown packets (FIN/ACK) are captured on the wire
                await asyncio.sleep(0.5)

                # 5. Stop Capturer and Server cleanly
                capturer.stop()
                server.stop()
                server = None

        except HTTPException:
            raise
        except PermissionError as pe:
            logger.error(f"Capture permission error: {pe}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Capture Agent permission error: {str(pe)}"
            )
        except Exception as e:
            logger.error(f"Error during authentic capture generation: {e}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Authentic capture execution failed: {str(e)}"
            )
        finally:
            if server:
                try:
                    server.stop()
                except Exception:
                    pass
            if cert_material:
                cert_material.cleanup()

        # Schedule cleanup of the temporary PCAP file after response is transmitted
        background_tasks.add_task(cleanup_file_safely, output_pcap_path)

        # 6. Stream authentic PCAP binary back to caller
        return FileResponse(
            path=output_pcap_path,
            media_type="application/vnd.tcpdump.pcap",
            filename=filename,
            headers={
                "X-Capture-Source": "AUTHENTIC_PACKET_CAPTURE",
                "X-Capture-Protocol": request.protocol,
                "X-Capture-Filename": filename
            }
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("capture_agent.main:app", host=AGENT_HOST, port=AGENT_PORT, reload=False)
