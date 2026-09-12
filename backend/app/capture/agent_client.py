import os
import logging
import tempfile
import httpx
from typing import Dict, Any, Tuple, Optional

logger = logging.getLogger("securemailscope.agent_client")

CAPTURE_AGENT_URL = os.environ.get("CAPTURE_AGENT_URL", "").rstrip("/")
CAPTURE_AGENT_API_KEY = os.environ.get("CAPTURE_AGENT_API_KEY", "")
CAPTURE_AGENT_TIMEOUT = float(os.environ.get("CAPTURE_AGENT_TIMEOUT_SECONDS", "30.0"))


def is_capture_agent_configured() -> bool:
    """Checks if Capture Agent URL is configured in environment."""
    return bool(CAPTURE_AGENT_URL)


async def get_capture_agent_status() -> Dict[str, Any]:
    """Queries health and readiness of the remote Capture Agent."""
    if not is_capture_agent_configured():
        return {
            "configured": False,
            "status": "NOT_CONFIGURED",
            "message": "CAPTURE_AGENT_URL is not set in the backend environment."
        }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{CAPTURE_AGENT_URL}/health")
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "configured": True,
                    "status": "ONLINE",
                    "agent_details": data
                }
            return {
                "configured": True,
                "status": "UNHEALTHY",
                "message": f"Agent responded with HTTP {resp.status_code}: {resp.text}"
            }
    except Exception as e:
        logger.warning(f"Failed to reach Capture Agent at {CAPTURE_AGENT_URL}: {e}")
        return {
            "configured": True,
            "status": "OFFLINE",
            "message": f"Could not connect to Capture Agent: {str(e)}"
        }


async def request_authentic_pcap(
    protocol: str = "SMTP",
    profile: str = "secure_tls12"
) -> Tuple[str, str]:
    """
    Calls the Capture Agent to execute a live, authentic packet capture session.
    Streams the raw PCAP binary response to a temporary file on the Render filesystem.
    Returns (temp_pcap_path, filename).
    Caller is responsible for removing temp_pcap_path after analysis.
    """
    if not is_capture_agent_configured():
        raise ValueError(
            "Authentic Auto-PCAP capture is not configured. "
            "Please configure CAPTURE_AGENT_URL and CAPTURE_AGENT_API_KEY in the backend environment."
        )

    headers = {
        "Content-Type": "application/json"
    }
    if CAPTURE_AGENT_API_KEY:
        headers["Authorization"] = f"Bearer {CAPTURE_AGENT_API_KEY}"

    payload = {
        "protocol": protocol,
        "profile": profile,
        "timeout_seconds": CAPTURE_AGENT_TIMEOUT
    }

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap", prefix="sms_auth_cap_")
    tmp_path = tmp_file.name

    try:
        async with httpx.AsyncClient(timeout=CAPTURE_AGENT_TIMEOUT) as client:
            logger.info(f"Dispatching authentic capture request to {CAPTURE_AGENT_URL}/api/v1/capture/generate...")
            async with client.stream(
                "POST",
                f"{CAPTURE_AGENT_URL}/api/v1/capture/generate",
                json=payload,
                headers=headers
            ) as response:
                if response.status_code == 401:
                    raise PermissionError(
                        "Capture Agent rejected authentication. Check CAPTURE_AGENT_API_KEY."
                    )
                if response.status_code == 409:
                    raise RuntimeError(
                        "Another packet capture is currently active on the Capture Agent. Please wait a few seconds and try again."
                    )
                if response.status_code != 200:
                    err_text = await response.aread()
                    raise RuntimeError(
                        f"Capture Agent error ({response.status_code}): {err_text.decode('utf-8', errors='replace')}"
                    )

                # Extract filename from header or fallback
                filename = response.headers.get("X-Capture-Filename")
                if not filename:
                    disposition = response.headers.get("Content-Disposition", "")
                    if "filename=" in disposition:
                        filename = disposition.split("filename=", 1)[1].strip('"').strip("'")
                    else:
                        filename = f"authentic_{protocol.lower()}_capture.pcap"

                # Stream response bytes directly to disk
                async for chunk in response.aiter_bytes():
                    tmp_file.write(chunk)

        tmp_file.close()

        file_size = os.path.getsize(tmp_path)
        logger.info(f"Authentic PCAP streamed successfully ({file_size} bytes): {filename}")

        if file_size < 24:
            raise RuntimeError(f"Received empty or corrupted PCAP from Capture Agent ({file_size} bytes).")

        return tmp_path, filename

    except Exception as e:
        tmp_file.close()
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass
        logger.error(f"Error requesting authentic PCAP: {e}")
        raise
