import os
import time
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

# Ensure test environment key for testability
os.environ.setdefault("CAPTURE_AGENT_SECRET_KEY", "test-agent-secret-key")

from capture_agent.main import app, capture_lock
from capture_agent.config import (
    CAPTURE_AGENT_SECRET_KEY,
    detect_loopback_interface,
    detect_active_interface,
    get_capture_interface,
    get_capture_ports,
    get_tcpdump_binary,
    check_capture_capabilities,
    get_current_os
)
from capture_agent.certs.cert_manager import generate_test_certificate
from capture_agent.traffic.smtp_server import AuthenticSmtpServer
from capture_agent.traffic.smtp_client import AuthenticSmtpClient
from capture_agent.recorder.packet_capturer import PacketCapturer, build_bpf_filter

client = TestClient(app)


def test_health_check_endpoint():
    """Verify health endpoint returns status, OS diagnostics, and loopback interface."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "OK"
    assert "agent" in data
    assert "os" in data
    assert "interface" in data
    assert isinstance(data["can_capture"], bool)
    assert data["is_busy"] is False


def test_auth_missing_header():
    """Verify /api/v1/capture/generate rejects request when Authorization header is missing."""
    resp = client.post("/api/v1/capture/generate", json={"protocol": "SMTP"})
    assert resp.status_code == 401
    assert "missing or malformed" in resp.json()["detail"].lower()


def test_auth_invalid_token():
    """Verify /api/v1/capture/generate rejects request when Bearer token is wrong."""
    resp = client.post(
        "/api/v1/capture/generate",
        json={"protocol": "SMTP"},
        headers={"Authorization": "Bearer wrong-secret-key-12345"}
    )
    assert resp.status_code == 401
    assert "invalid or expired" in resp.json()["detail"].lower()


def test_concurrent_capture_prevention():
    """Verify that when a capture is active, concurrent requests return 409 Conflict."""
    async def lock_and_test():
        async with capture_lock:
            resp = client.post(
                "/api/v1/capture/generate",
                json={"protocol": "SMTP"},
                headers={"Authorization": f"Bearer {CAPTURE_AGENT_SECRET_KEY}"}
            )
            assert resp.status_code == 409
            assert "currently in progress" in resp.json()["detail"].lower()

    import asyncio
    asyncio.run(lock_and_test())


def test_certificate_generator_validity_and_cleanup():
    """Verify X.509 certificate generator produces genuine RSA 2048-bit certificate and key files."""
    cert_material = generate_test_certificate(
        common_name="mail.securemailscope.test",
        validity_days=30,
        key_size=2048
    )

    assert os.path.exists(cert_material.cert_path)
    assert os.path.exists(cert_material.key_path)

    with open(cert_material.cert_path, "r") as f:
        cert_text = f.read()
        assert "-----BEGIN CERTIFICATE-----" in cert_text

    with open(cert_material.key_path, "r") as f:
        key_text = f.read()
        assert "-----BEGIN RSA PRIVATE KEY-----" in key_text or "-----BEGIN PRIVATE KEY-----" in key_text

    # Test cleanup
    cert_material.cleanup()
    assert not os.path.exists(cert_material.cert_path)
    assert not os.path.exists(cert_material.key_path)


def test_packet_capturer_command_construction():
    """Verify PacketCapturer builds accurate BPF filter and arguments."""
    capturer = PacketCapturer(
        output_pcap_path="/tmp/test_output.pcap",
        port=2525,
        interface="lo0"
    )
    assert capturer.port == 2525
    assert capturer.interface == "lo0"
    assert capturer.output_pcap_path == "/tmp/test_output.pcap"
    assert capturer.bpf_filter == "tcp and port 2525 and host 127.0.0.1"


def test_packet_capturer_bpf_filter_generation():
    """Verify build_bpf_filter generates strict, accurate BPF filters for various configurations."""
    # 1. Default port 2525 on loopback
    f1 = build_bpf_filter(port=2525)
    assert f1 == "tcp and port 2525 and host 127.0.0.1"

    # 2. Port 587 (Gmail SMTP submission)
    f2 = build_bpf_filter(port=587)
    assert f2 == "tcp and port 587"

    # 3. Port 587 targeting specific Gmail host
    f3 = build_bpf_filter(port=587, host="smtp.gmail.com")
    assert f3 == "tcp and port 587 and host smtp.gmail.com"

    # 4. Dual ports [2525, 587]
    f4 = build_bpf_filter(ports=[2525, 587])
    assert f4 == "tcp and ((port 2525 and host 127.0.0.1) or port 587)"

    # 5. Non-standard port with host
    f5 = build_bpf_filter(port=1025, host="127.0.0.1")
    assert f5 == "tcp and port 1025 and host 127.0.0.1"

    # 6. Explicit custom filter override
    f6 = build_bpf_filter(custom_filter="tcp and port 587 and host 142.250.185.109")
    assert f6 == "tcp and port 587 and host 142.250.185.109"

    # 7. Environment variable override
    with patch.dict(os.environ, {"CAPTURE_BPF_FILTER": "tcp and port 587"}):
        f7 = build_bpf_filter()
        assert f7 == "tcp and port 587"


def test_packet_capturer_interface_selection():
    """Verify interface selection logic accurately picks loopback or active internet interface."""
    # Port 2525 should use loopback
    lo = get_capture_interface([2525])
    assert lo in ("lo0", "lo", "127.0.0.1")

    # Port 587 should use active interface
    active_iface = get_capture_interface([587])
    assert active_iface is not None
    assert len(active_iface) > 0


def test_get_capture_ports_configuration():
    """Verify get_capture_ports parses CAPTURE_PORTS environment variable."""
    with patch.dict(os.environ, {"CAPTURE_PORTS": "2525, 587, 465"}):
        ports = get_capture_ports()
        assert ports == [2525, 587, 465]

    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("CAPTURE_PORTS", None)
        default_ports = get_capture_ports()
        assert default_ports == [2525, 587]


def test_authentic_smtp_server_and_client_real_sockets():
    """
    Test authentic socket communication between AuthenticSmtpServer and AuthenticSmtpClient.
    Binds to an ephemeral OS loopback port (port 0), performs real TCP connection,
    EHLO, STARTTLS with TLS 1.2, real X.509 cert presentation, mail transmission, and clean QUIT.
    """
    cert_material = generate_test_certificate(
        common_name="mail.securemailscope.test",
        validity_days=1,
        key_size=2048
    )

    server = AuthenticSmtpServer(
        host="127.0.0.1",
        port=0, # Ephemeral available port
        cert_path=cert_material.cert_path,
        key_path=cert_material.key_path
    )

    try:
        server.start()
        actual_port = server.actual_port
        assert actual_port > 0

        client = AuthenticSmtpClient(
            host="127.0.0.1",
            port=actual_port,
            local_hostname="client.securemailscope.test",
            timeout=5.0
        )

        success = client.execute_session(
            sender="auditor@securemailscope.test",
            recipient="admin@securemailscope.test",
            subject="Automated Test Session"
        )
        assert success is True

    finally:
        server.stop()
        cert_material.cleanup()


def test_cors_preflight_and_headers():
    """Verify CORS preflight OPTIONS request returns valid access-control headers for web clients."""
    headers = {
        "Origin": "http://localhost:5173",
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "authorization,content-type,x-requested-with"
    }
    resp = client.options("/api/v1/capture/generate", headers=headers)
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert "POST" in resp.headers.get("access-control-allow-methods", "")


def test_localhost_only_enforcement():
    """Verify localhost middleware permits local test clients."""
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "OK"


def test_health_endpoint_cors_headers_for_browser():
    """Verify GET /health returns valid CORS headers for browser dashboard origins."""
    headers = {"Origin": "http://localhost:5173"}
    resp = client.get("/health", headers=headers)
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_health_endpoint_dashboard_contract():
    """Verify GET /health response matches frontend ExecutiveDashboard contract requirements."""
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("status") == "OK"
    assert "version" in data
    assert isinstance(data.get("can_capture"), bool)
    assert data.get("is_busy") is False


def test_handshake_endpoint_success_allowed_origin():
    """Verify POST /api/v1/auth/handshake issues an ephemeral token for allowed web origins."""
    headers = {
        "Origin": "http://localhost:5173",
        "X-Requested-With": "SecureMailScope"
    }
    resp = client.post("/api/v1/auth/handshake", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "token" in data
    assert len(data["token"]) >= 32
    assert data["token_type"] == "Bearer"
    assert data["expires_in"] == 60
    assert data["status"] == "ready"


def test_handshake_endpoint_rejected_disallowed_origin():
    """Verify POST /api/v1/auth/handshake rejects untrusted origins with 403 Forbidden."""
    headers = {
        "Origin": "https://malicious-site.com",
        "X-Requested-With": "SecureMailScope"
    }
    resp = client.post("/api/v1/auth/handshake", headers=headers)
    assert resp.status_code == 403
    assert "not permitted" in resp.json()["detail"].lower() or "not authorized" in resp.json()["detail"].lower()


def test_handshake_endpoint_missing_custom_header():
    """Verify POST /api/v1/auth/handshake rejects requests missing X-Requested-With."""
    headers = {
        "Origin": "http://localhost:5173"
    }
    resp = client.post("/api/v1/auth/handshake", headers=headers)
    assert resp.status_code == 400
    assert "x-requested-with" in resp.json()["detail"].lower()


@pytest.mark.anyio
async def test_ephemeral_token_authentication_and_single_use_consumption():
    """
    Verify ephemeral handshake token grants access on first use,
    and is IMMEDIATELY CONSUMED so replay attempts are rejected with 401.
    """
    from capture_agent.main import create_ephemeral_token, verify_bearer_auth
    from fastapi import HTTPException

    token = await create_ephemeral_token(ttl_seconds=60)
    auth_header = f"Bearer {token}"

    # First use: must succeed and return the token
    result = await verify_bearer_auth(auth_header)
    assert result == token

    # Second use (replay attack): must raise 401 Unauthorized
    with pytest.raises(HTTPException) as exc_info:
        await verify_bearer_auth(auth_header)
    assert exc_info.value.status_code == 401
    assert "invalid or expired" in exc_info.value.detail.lower()


@pytest.mark.anyio
async def test_ephemeral_token_expiration():
    """Verify expired ephemeral tokens are rejected with 401 Unauthorized."""
    import time
    from capture_agent.main import ephemeral_tokens, tokens_lock, verify_bearer_auth
    from fastapi import HTTPException

    expired_token = "test_expired_token_abc123"
    async with tokens_lock:
        # Inject token that expired 10 seconds ago
        ephemeral_tokens[expired_token] = time.time() - 10

    with pytest.raises(HTTPException) as exc_info:
        await verify_bearer_auth(f"Bearer {expired_token}")
    assert exc_info.value.status_code == 401
    assert "invalid or expired" in exc_info.value.detail.lower()


@pytest.mark.anyio
async def test_server_secret_authenticated_request():
    """Verify backend proxy / CLI server-to-server secret key remains valid."""
    from capture_agent.main import verify_bearer_auth
    result = await verify_bearer_auth(f"Bearer {CAPTURE_AGENT_SECRET_KEY}")
    assert result == CAPTURE_AGENT_SECRET_KEY


def test_dns_rebinding_protection():
    """Verify requests with rebinded external Host headers are rejected with 403 Forbidden."""
    headers = {"Host": "evil.attacker.com:9000"}
    resp = client.get("/health", headers=headers)
    assert resp.status_code == 403
    assert "invalid host header" in resp.json()["detail"].lower()


def test_cors_disallowed_origin():
    """Verify browser cross-origin requests from disallowed origins are rejected with 403 Forbidden."""
    headers = {"Origin": "https://evil.attacker.com"}
    resp = client.get("/health", headers=headers)
    assert resp.status_code == 403
    assert "not permitted" in resp.json()["detail"].lower()


def test_production_vercel_origin_and_private_network_preflight():
    """Verify production Vercel origin and W3C Private Network Access preflight are supported."""
    headers = {
        "Origin": "https://secure-mail-scope-eight.vercel.app",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Private-Network": "true"
    }
    resp = client.options("/health", headers=headers)
    assert resp.status_code == 200
    assert resp.headers.get("access-control-allow-origin") == "https://secure-mail-scope-eight.vercel.app"
    assert resp.headers.get("access-control-allow-private-network") == "true"

    # Test handshake from production Vercel origin
    handshake_headers = {
        "Origin": "https://secure-mail-scope-eight.vercel.app",
        "X-Requested-With": "SecureMailScope"
    }
    h_resp = client.post("/api/v1/auth/handshake", headers=handshake_headers)
    assert h_resp.status_code == 200
    assert "token" in h_resp.json()


def test_gmail_capture_endpoint_dispatch():
    """Verify /api/v1/capture/generate correctly identifies Gmail submission mode on port 587."""
    fake_pcap_header = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"

    created_capturers = []
    original_init = PacketCapturer.__init__

    def tracking_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        created_capturers.append(self)

    def fake_start(*args, **kwargs):
        if created_capturers:
            with open(created_capturers[-1].output_pcap_path, "wb") as f:
                f.write(fake_pcap_header)

    with patch.object(PacketCapturer, "__init__", tracking_init), \
         patch.object(PacketCapturer, "start", side_effect=fake_start) as mock_start, \
         patch.object(PacketCapturer, "stop") as mock_stop:

        resp = client.post(
            "/api/v1/capture/generate",
            json={
                "protocol": "SMTP",
                "port": 587,
                "duration_seconds": 0.05
            },
            headers={"Authorization": f"Bearer {CAPTURE_AGENT_SECRET_KEY}"}
        )

        assert resp.status_code == 200
        assert resp.headers.get("content-type") == "application/vnd.tcpdump.pcap"
        assert len(resp.content) >= 24
        assert mock_start.called
        assert mock_stop.called
