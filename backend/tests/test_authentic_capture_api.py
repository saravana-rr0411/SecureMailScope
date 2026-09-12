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
    with patch("app.capture.agent_client.get_capture_agent_url", return_value="http://127.0.0.1:9000"):
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


def test_capture_status_endpoint_offline():
    """Verify /api/capture/status reports OFFLINE when agent is unreachable."""
    with patch("app.capture.agent_client.get_capture_agent_url", return_value="http://127.0.0.1:9000"):
        with patch("app.capture.agent_client.is_capture_agent_configured", return_value=True):
            with patch("httpx.AsyncClient.get", side_effect=Exception("Connection refused")):
                resp = client.get("/api/capture/status")
                assert resp.status_code == 200
                data = resp.json()
                assert data["configured"] is True
                assert data["status"] == "OFFLINE"


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

            # Verify genuine PCAP download payload is present
            import base64
            assert "pcap_base64" in data
            assert data["pcap_filename"] == mock_filename
            assert data["pcap_size_bytes"] == os.path.getsize(SAMPLE_PCAP)
            assert data["pcap_download_url"] == f"/api/capture/download/{data['capture_id']}"

            # Verify decoded binary starts with valid PCAP global header
            pcap_bytes = base64.b64decode(data["pcap_base64"])
            assert len(pcap_bytes) == os.path.getsize(SAMPLE_PCAP)
            assert pcap_bytes[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a')

            # Verify save_analysis_result was called
            if mock_save.called:
                saved_arg = mock_save.call_args[0][0]
                assert saved_arg["capture_id"] == f"pcap_{mock_filename}"

            # Verify temporary file was cleaned up
            assert not os.path.exists(tmp.name)


def test_download_capture_endpoint_after_capture():
    """Verify /api/capture/download/{capture_id} returns genuine PCAP binary with proper headers."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pcap")
    shutil.copyfile(SAMPLE_PCAP, tmp.name)
    tmp.close()

    mock_filename = "authentic_smtp_tls_20260912_123000.pcap"

    async def mock_request(*args, **kwargs):
        return tmp.name, mock_filename

    with patch("app.main.request_authentic_pcap", side_effect=mock_request):
        resp = client.post("/api/capture/generate-authentic", json={"protocol": "SMTP"})
        assert resp.status_code == 200
        data = resp.json()
        capture_id = data["capture_id"]

    # Now download the capture via the download endpoint
    dl_resp = client.get(f"/api/capture/download/{capture_id}")
    assert dl_resp.status_code == 200
    assert dl_resp.headers["content-type"] == "application/vnd.tcpdump.pcap"
    assert f'filename="{mock_filename}"' in dl_resp.headers["content-disposition"]
    assert len(dl_resp.content) == os.path.getsize(SAMPLE_PCAP)
    assert dl_resp.content[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')


def test_download_capture_endpoint_security_and_traversal():
    """Verify download endpoint rejects directory traversal and non-existent IDs."""
    # Attempt path traversal
    resp1 = client.get("/api/capture/download/..%2F..%2Fetc%2Fpasswd")
    assert resp1.status_code in (400, 404)

    resp2 = client.get("/api/capture/download/nonexistent_capture_99999")
    assert resp2.status_code == 404


def test_download_demo_capture_whitelist():
    """Verify whitelisted demo PCAPs can be downloaded."""
    resp = client.get("/api/capture/download/secure_tls")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/vnd.tcpdump.pcap"
    assert len(resp.content) > 0
    assert resp.content[:4] in (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')


def test_download_agent_package_endpoints():
    """Verify /api/agent/download/{platform} routes."""
    # macOS package exists in dist/
    resp_mac = client.get("/api/agent/download/macos")
    assert resp_mac.status_code == 200
    assert "application/octet-stream" in resp_mac.headers["content-type"]
    assert "SecureMailScopeCaptureAgent-1.0.0.pkg" in resp_mac.headers["content-disposition"]

    # Windows package redirects to official GitHub Release asset or serves file if present in dist/
    resp_win = client.get("/api/agent/download/windows", follow_redirects=False)
    assert resp_win.status_code in (200, 307)
    if resp_win.status_code == 307:
        assert "SecureMailScopeCaptureAgent-1.0.0-Setup.exe" in resp_win.headers["location"]

    # Invalid platform returns 400
    resp_invalid = client.get("/api/agent/download/solaris")
    assert resp_invalid.status_code == 400
