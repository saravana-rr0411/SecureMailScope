import os
import shutil
import tempfile
import pytest
from unittest.mock import patch, AsyncMock
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

SAMPLE_PCAP = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "dataset", "01_secure_smtp_tls12.pcap")


def test_capture_status_endpoint_unconfigured():
    """Verify /api/capture/status reports NOT_CONFIGURED when CAPTURE_AGENT_URL is not set."""
    with patch.dict(os.environ, {"CAPTURE_AGENT_URL": ""}, clear=False):
        with patch("app.capture.agent_client.CAPTURE_AGENT_URL", ""):
            resp = client.get("/api/capture/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["configured"] is False
            assert data["status"] == "NOT_CONFIGURED"


def test_capture_status_endpoint_online():
    """Verify /api/capture/status reports ONLINE when agent returns 200."""
    mock_agent_data = {
        "status": "OK",
        "agent": "SecureMailScope Capture Agent",
        "version": "1.0.0",
        "can_capture": True
    }
    with patch("app.capture.agent_client.is_capture_agent_configured", return_value=True):
        with patch("httpx.AsyncClient.get") as mock_get:
            mock_resp = AsyncMock()
            mock_resp.status_code = 200
            mock_resp.json = lambda: mock_agent_data
            mock_get.return_value = mock_resp

            resp = client.get("/api/capture/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["configured"] is True
            assert data["status"] == "ONLINE"
            assert data["agent_details"]["can_capture"] is True


def test_generate_authentic_capture_unconfigured():
    """Verify /api/capture/generate-authentic returns 400 when agent is unconfigured."""
    with patch("app.capture.agent_client.is_capture_agent_configured", return_value=False):
        resp = client.post("/api/capture/generate-authentic", json={"protocol": "SMTP"})
        assert resp.status_code == 400
        assert "not configured" in resp.json()["detail"].lower()


def test_generate_authentic_capture_unauthorized():
    """Verify /api/capture/generate-authentic returns 403 when agent rejects token."""
    with patch(
        "app.main.request_authentic_pcap",
        side_effect=PermissionError("Capture Agent rejected authentication.")
    ):
        resp = client.post("/api/capture/generate-authentic", json={"protocol": "SMTP"})
        assert resp.status_code == 403
        assert "rejected authentication" in resp.json()["detail"].lower()


def test_generate_authentic_capture_busy_conflict():
    """Verify /api/capture/generate-authentic returns 503 when another capture is in progress."""
    with patch(
        "app.main.request_authentic_pcap",
        side_effect=RuntimeError("Another packet capture is currently active")
    ):
        resp = client.post("/api/capture/generate-authentic", json={"protocol": "SMTP"})
        assert resp.status_code == 503
        assert "another packet capture is currently active" in resp.json()["detail"].lower()


def test_generate_authentic_capture_success_flow():
    """
    Verify complete flow:
    Agent returns PCAP -> analyze_pcap() parses it -> metadata attached -> persisted to Supabase -> returned.
    """
    # Create temporary copy of sample PCAP
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    shutil.copyfile(SAMPLE_PCAP, tmp.name)
    tmp.close()

    mock_filename = "authentic_smtp_tls_20260912_120000.pcap"

    async def mock_request(*args, **kwargs):
        return tmp.name, mock_filename

    with patch("app.main.request_authentic_pcap", side_effect=mock_request):
        with patch("app.main.save_analysis_result") as mock_save:
            resp = client.post(
                "/api/capture/generate-authentic",
                json={"protocol": "SMTP", "profile": "secure_tls12"}
            )
            assert resp.status_code == 200
            data = resp.json()

            # Verify filename and capture_id
            assert data["filename"] == mock_filename
            assert data["capture_id"] == f"pcap_{mock_filename}"
            assert data["capture_source"] == "AUTHENTIC_AUTO_CAPTURE"
            assert "analyzed_at" in data

            # Verify analyzer extracted protocol and TLS parameters
            assert any(p["protocol"] == "SMTP" for p in data.get("protocols", []))
            assert len(data.get("sessions", [])) > 0

            s0 = data["sessions"][0]
            assert s0.get("protocol") == "SMTP"
            assert s0.get("tls", {}).get("detected") is True

            # Verify save_analysis_result was called
            if mock_save.called:
                saved_arg = mock_save.call_args[0][0]
                assert saved_arg["capture_id"] == f"pcap_{mock_filename}"

            # Verify temporary file was cleaned up
            assert not os.path.exists(tmp.name)
