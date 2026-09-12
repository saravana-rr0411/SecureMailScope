import os
import hmac
import time
import asyncio
import logging
import datetime
from pathlib import Path
from typing import Optional, Dict, Any

from fastapi import FastAPI, Header, HTTPException, BackgroundTasks, status
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from capture_agent.config import (
    CAPTURE_AGENT_SECRET_KEY,
    AGENT_HOST,
    AGENT_PORT,
    TEST_SMTP_HOST,
    TEST_SMTP_PORT,
    PCAP_STORAGE_DIR,
    detect_loopback_interface,
    get_tcpdump_binary,
    check_capture_capabilities,
    get_current_os
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

app = FastAPI(
    title="SecureMailScope Capture Agent",
    description="Dedicated agent service for authentic packet capture of real email traffic",
    version="1.0.0"
)

# Global mutex ensuring only one capture runs at a time
capture_lock = asyncio.Lock()


class CaptureRequest(BaseModel):
    protocol: str = "SMTP"
    profile: str = "secure_tls12"
    timeout_seconds: float = 15.0


def verify_bearer_auth(authorization: Optional[str] = Header(None)):
    """Verifies incoming Bearer authorization token using constant-time comparison."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or malformed Authorization header. Expected: Bearer <secret>"
        )

    provided_token = authorization.split("Bearer ", 1)[1].strip()
    expected_token = CAPTURE_AGENT_SECRET_KEY.strip()

    if not hmac.compare_digest(provided_token.encode("utf-8"), expected_token.encode("utf-8")):
        logger.warning("Rejected unauthorized request to Capture Agent.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid capture agent authorization key"
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
    1. Authenticates request via Bearer token
    2. Generates real X.509 certificate
    3. Starts tcpdump packet sniffer on controlled interface and test port
    4. Launches authentic SMTP server with TLS 1.2
    5. Executes authentic SMTP client through operating system TCP stack
    6. Stops tcpdump and verifies the generated PCAP
    7. Streams raw PCAP binary to caller
    """
    verify_bearer_auth(authorization)

    # Check if a capture is already in progress
    if capture_lock.locked():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Another packet capture is currently in progress. Captures are strictly serialized."
        )

    async with capture_lock:
        timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"authentic_{request.protocol.lower()}_tls_{timestamp_str}.pcap"
        output_dir = PCAP_STORAGE_DIR
        output_dir.mkdir(parents=True, exist_ok=True)
        output_pcap_path = str(output_dir / filename)

        cert_material = None
        server = None
        capturer = None

        try:
            logger.info(f"Starting authentic {request.protocol} capture sequence...")

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
