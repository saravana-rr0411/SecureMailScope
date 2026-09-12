import os
import json
import logging
import tempfile
import httpx
from typing import Dict, Any, Tuple, Optional

logger = logging.getLogger("securemailscope.agent_client")

from dotenv import load_dotenv
load_dotenv()

CAPTURE_AGENT_URL = os.environ.get("CAPTURE_AGENT_URL", "")
CAPTURE_AGENT_API_KEY = os.environ.get("CAPTURE_AGENT_API_KEY", "")
CAPTURE_AGENT_TIMEOUT = float(os.environ.get("CAPTURE_AGENT_TIMEOUT_SECONDS", "30.0"))

def get_capture_agent_url() -> str:
    # If explicitly patched or set to empty in tests/env, respect empty string
    if "CAPTURE_AGENT_URL" in os.environ and os.environ["CAPTURE_AGENT_URL"] == "":
        return ""
    if not CAPTURE_AGENT_URL and "CAPTURE_AGENT_URL" in os.environ and os.environ["CAPTURE_AGENT_URL"] == "":
        return ""
    return (CAPTURE_AGENT_URL or os.environ.get("CAPTURE_AGENT_URL") or "http://127.0.0.1:9000").rstrip("/")

def get_capture_agent_api_key() -> str:
    return (CAPTURE_AGENT_API_KEY or os.environ.get("CAPTURE_AGENT_API_KEY", "")).strip()

def get_capture_agent_timeout() -> float:
    return float(os.environ.get("CAPTURE_AGENT_TIMEOUT_SECONDS", str(CAPTURE_AGENT_TIMEOUT or 30.0)))

def is_capture_agent_configured() -> bool:
    """Checks if Capture Agent URL is configured in environment."""
    return bool(get_capture_agent_url())


async def get_capture_agent_status() -> Dict[str, Any]:
    """Queries health and readiness of the remote Capture Agent."""
    agent_url = get_capture_agent_url()
    if not agent_url:
        return {
            "configured": False,
            "status": "NOT_CONFIGURED",
            "message": "CAPTURE_AGENT_URL is not set in the backend environment."
        }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{agent_url}/health")
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
        logger.warning(f"Failed to reach Capture Agent at {agent_url}: {e}")
        return {
            "configured": True,
            "status": "OFFLINE",
            "message": f"Could not connect to Capture Agent: {str(e)}"
        }


async def request_authentic_pcap(
    protocol: str = "SMTP",
    profile: str = "secure_tls12",
    port: Optional[int] = None,
    ports: Optional[list[int]] = None,
    target_host: Optional[str] = None,
    duration_seconds: Optional[float] = None,
    interface: Optional[str] = None,
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

    agent_url = get_capture_agent_url()
    api_key = get_capture_agent_api_key()
    timeout_sec = (duration_seconds + 15.0) if duration_seconds else get_capture_agent_timeout()

    headers = {
        "Content-Type": "application/json"
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload: Dict[str, Any] = {
        "protocol": protocol,
        "profile": profile,
        "timeout_seconds": timeout_sec
    }
    if port is not None:
        payload["port"] = port
    if ports is not None:
        payload["ports"] = ports
    if target_host is not None:
        payload["target_host"] = target_host
    if duration_seconds is not None:
        payload["duration_seconds"] = duration_seconds
    if interface is not None:
        payload["interface"] = interface

    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap", prefix="sms_auth_cap_")
    tmp_path = tmp_file.name

    try:
        async with httpx.AsyncClient(timeout=timeout_sec) as client:
            logger.info(f"Dispatching authentic capture request to {agent_url}/api/v1/capture/generate...")
            async with client.stream(
                "POST",
                f"{agent_url}/api/v1/capture/generate",
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
                    detail_msg = err_text.decode('utf-8', errors='replace')
                    try:
                        err_json = json.loads(detail_msg)
                        if isinstance(err_json, dict) and "detail" in err_json:
                            detail_msg = str(err_json["detail"])
                    except Exception:
                        pass
                    if response.status_code == 400:
                        raise ValueError(detail_msg)
                    raise RuntimeError(f"Capture Agent error ({response.status_code}): {detail_msg}")

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
