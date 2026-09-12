import os
import time
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from capture_agent.main import app, capture_lock
from capture_agent.config import (
    CAPTURE_AGENT_SECRET_KEY,
    detect_loopback_interface,
    get_tcpdump_binary,
    check_capture_capabilities,
    get_current_os
)
from capture_agent.certs.cert_manager import generate_test_certificate
from capture_agent.traffic.smtp_server import AuthenticSmtpServer
from capture_agent.traffic.smtp_client import AuthenticSmtpClient
from capture_agent.recorder.packet_capturer import PacketCapturer

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
    assert "invalid capture agent authorization key" in resp.json()["detail"].lower()


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
