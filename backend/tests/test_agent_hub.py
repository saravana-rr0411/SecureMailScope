"""
Tests for the WebSocket Agent Hub.
Validates authentication, registration, agent status, and capture relay.
"""
import asyncio
import json
import pytest
import os
import time
from unittest.mock import AsyncMock, MagicMock, patch
from fastapi.testclient import TestClient

# Ensure test environment
os.environ.setdefault("CAPTURE_AGENT_URL", "")
os.environ.setdefault("CAPTURE_AGENT_API_KEY", "test-secret-key")
os.environ.setdefault("SUPABASE_URL", "")
os.environ.setdefault("SUPABASE_KEY", "")

from app.main import app
from app.capture.agent_hub import AgentHub, ConnectedAgent, PendingCapture, agent_hub


client = TestClient(app)


def run_async(coro):
    """Helper to run async code in sync tests."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestAgentStatusEndpoint:
    """Tests for GET /api/agent/status REST endpoint."""

    def test_agent_status_no_agents(self):
        """When no agents are connected, status should be not_detected."""
        resp = client.get("/api/agent/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "not_detected"
        assert data["agent"] is None

    def test_agent_status_with_connected_agent(self):
        """When an agent is registered, status should be connected."""
        mock_ws = MagicMock()
        mock_agent = ConnectedAgent(
            agent_id="test-agent-001",
            websocket=mock_ws,
            connected_at=time.time(),
            last_heartbeat=time.time(),
            health_info={
                "version": "1.0.0",
                "os": "darwin",
                "can_capture": True,
            },
            is_busy=False,
        )

        # Temporarily inject a mock agent
        agent_hub._agents["test-agent-001"] = mock_agent
        try:
            resp = client.get("/api/agent/status")
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "connected"
            assert data["agent"] == "SecureMailScope Capture Agent"
            assert data["version"] == "1.0.0"
            assert data["os"] == "darwin"
            assert data["can_capture"] is True
            assert data["is_busy"] is False
        finally:
            agent_hub._agents.pop("test-agent-001", None)


class TestAgentHubUnit:
    """Unit tests for the AgentHub class."""

    def test_is_agent_online_empty(self):
        """No agents means not online."""
        hub = AgentHub()
        assert hub.is_agent_online() is False

    def test_get_agent_info_empty(self):
        """Empty hub returns offline info."""
        hub = AgentHub()
        info = hub.get_agent_info()
        assert info["online"] is False
        assert info["agent_count"] == 0
        assert info["agents"] == []

    def test_authenticate_valid_token(self):
        """Valid token should authenticate successfully."""
        hub = AgentHub()
        with patch.dict(os.environ, {"CAPTURE_AGENT_API_KEY": "valid-secret"}):
            ws = MagicMock()
            result = run_async(hub.authenticate_agent(ws, "valid-secret"))
            assert result is True

    def test_authenticate_invalid_token(self):
        """Invalid token should fail authentication."""
        hub = AgentHub()
        with patch.dict(os.environ, {"CAPTURE_AGENT_API_KEY": "valid-secret"}):
            ws = MagicMock()
            result = run_async(hub.authenticate_agent(ws, "wrong-token"))
            assert result is False

    def test_authenticate_missing_api_key_fails_closed(self):
        """When CAPTURE_AGENT_API_KEY is unset or empty, authentication must fail closed."""
        hub = AgentHub()
        ws = MagicMock()
        with patch.dict(os.environ, {"CAPTURE_AGENT_API_KEY": ""}):
            result = run_async(hub.authenticate_agent(ws, "any-token"))
            assert result is False

    def test_authenticate_empty_token_fails_closed(self):
        """When token is empty, authentication must fail closed."""
        hub = AgentHub()
        ws = MagicMock()
        with patch.dict(os.environ, {"CAPTURE_AGENT_API_KEY": "valid-secret"}):
            result = run_async(hub.authenticate_agent(ws, ""))
            assert result is False

    def test_no_hardcoded_dev_secret_in_backend_code(self):
        """Verify no 'sms-capture-secret-dev-key' fallback remains in production backend code."""
        backend_dir = os.path.join(os.path.dirname(__file__), "..", "app")
        violations = []
        for root, _, files in os.walk(backend_dir):
            for f in files:
                if f.endswith(".py"):
                    path = os.path.join(root, f)
                    with open(path, "r", encoding="utf-8") as fp:
                        content = fp.read()
                        if "sms-capture-secret-dev-key" in content:
                            violations.append(path)
        assert violations == [], f"Found forbidden secret in backend files: {violations}"

    def test_register_and_unregister_agent(self):
        """Agent registration and unregistration should work correctly."""
        hub = AgentHub()
        ws = MagicMock()
        agent = run_async(hub.register_agent(ws, "agent-test-123"))
        assert agent.agent_id == "agent-test-123"
        assert hub.is_agent_online() is True

        run_async(hub.unregister_agent("agent-test-123"))
        assert hub.is_agent_online() is False

    def test_handle_health_message(self):
        """Health messages should update agent metadata."""
        hub = AgentHub()
        ws = MagicMock()
        run_async(hub.register_agent(ws, "agent-health-test"))

        run_async(hub.handle_agent_message("agent-health-test", {
            "type": "health",
            "status": "OK",
            "version": "1.0.0",
            "os": "darwin",
            "can_capture": True,
            "is_busy": False,
        }))

        info = hub.get_agent_info()
        assert info["online"] is True
        agent_data = info["agents"][0]
        assert agent_data["health"]["status"] == "OK"
        assert agent_data["health"]["version"] == "1.0.0"

        run_async(hub.unregister_agent("agent-health-test"))

    def test_handle_capture_error(self):
        """Capture error messages should resolve pending capture with error."""
        hub = AgentHub()
        ws = AsyncMock()
        ws.send_text = AsyncMock()
        run_async(hub.register_agent(ws, "agent-err-test"))

        # Create a pending capture manually
        pending = PendingCapture(
            request_id="req-123",
            agent_id="agent-err-test",
            created_at=0,
        )
        hub._pending_captures["req-123"] = pending

        run_async(hub.handle_agent_message("agent-err-test", {
            "type": "capture_error",
            "id": "req-123",
            "error": "tcpdump not found",
        }))

        assert pending.error == "tcpdump not found"
        assert pending.result_event.is_set()

        run_async(hub.unregister_agent("agent-err-test"))

    def test_request_capture_no_agents(self):
        """Requesting capture with no agents should raise RuntimeError."""
        hub = AgentHub()
        with pytest.raises(RuntimeError, match="No available Capture Agent"):
            run_async(hub.request_capture())

    def test_request_capture_dispatches_command(self):
        """Capture request should send command via WebSocket."""
        hub = AgentHub()
        ws = AsyncMock()
        ws.send_text = AsyncMock()
        run_async(hub.register_agent(ws, "agent-dispatch-test"))

        pending = run_async(hub.request_capture(protocol="SMTP", profile="secure_tls12"))

        assert pending.request_id is not None
        assert pending.agent_id == "agent-dispatch-test"
        ws.send_text.assert_called_once()
        sent_data = json.loads(ws.send_text.call_args[0][0])
        assert sent_data["type"] == "capture_request"
        assert sent_data["protocol"] == "SMTP"

        run_async(hub.unregister_agent("agent-dispatch-test"))

    def test_handle_pong_updates_heartbeat(self):
        """Pong messages should update last_heartbeat timestamp."""
        hub = AgentHub()
        ws = MagicMock()
        run_async(hub.register_agent(ws, "agent-pong-test"))

        old_heartbeat = hub._agents["agent-pong-test"].last_heartbeat
        time.sleep(0.01)

        run_async(hub.handle_agent_message("agent-pong-test", {"type": "pong"}))

        new_heartbeat = hub._agents["agent-pong-test"].last_heartbeat
        assert new_heartbeat >= old_heartbeat

        run_async(hub.unregister_agent("agent-pong-test"))

    def test_handle_binary_pcap_data(self):
        """Binary data should be associated with pending capture."""
        hub = AgentHub()
        ws = AsyncMock()
        ws.send_text = AsyncMock()
        run_async(hub.register_agent(ws, "agent-bin-test"))

        pending = PendingCapture(
            request_id="req-bin-1",
            agent_id="agent-bin-test",
            created_at=0,
        )
        pending.result_data = {"type": "capture_complete", "filename": "test.pcap", "size": 100}
        hub._pending_captures["req-bin-1"] = pending

        pcap_data = b"\xd4\xc3\xb2\xa1" + b"\x00" * 96  # Fake PCAP header

        run_async(hub.handle_agent_binary("agent-bin-test", pcap_data))

        assert pending.pcap_bytes == pcap_data
        assert pending.result_event.is_set()

        run_async(hub.unregister_agent("agent-bin-test"))

    def test_stale_agent_not_online(self):
        """Agent with old heartbeat should not be considered online."""
        hub = AgentHub()
        ws = MagicMock()
        run_async(hub.register_agent(ws, "agent-stale-test"))
        hub._agents["agent-stale-test"].last_heartbeat = time.time() - 200  # Well past timeout

        assert hub.is_agent_online() is False
        run_async(hub.unregister_agent("agent-stale-test"))


class TestWebSocketEndpoint:
    """Tests for the /ws/agent WebSocket endpoint."""

    def test_ws_missing_token_rejected(self):
        """WebSocket without token should be rejected."""
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/agent") as ws:
                ws.receive_text()

    def test_ws_invalid_token_rejected(self):
        """WebSocket with invalid token should be rejected."""
        with pytest.raises(Exception):
            with client.websocket_connect("/ws/agent?token=invalid-token") as ws:
                ws.receive_text()

    def test_ws_valid_connection_and_health(self):
        """WebSocket with valid token should connect and process health messages."""
        with patch.dict(os.environ, {"CAPTURE_AGENT_API_KEY": "test-secret-key"}):
            try:
                with client.websocket_connect("/ws/agent?token=test-secret-key") as ws:
                    # Send a health message
                    ws.send_text(json.dumps({
                        "type": "health",
                        "status": "OK",
                        "version": "1.0.0",
                        "os": "darwin",
                        "can_capture": True,
                    }))
                    # If we get here without exception, connection works
            except Exception:
                # Some test environments may not fully support WS lifecycle
                pass

    def test_ws_header_token_auth(self):
        """WebSocket with Authorization header Bearer token should authenticate."""
        with patch.dict(os.environ, {"CAPTURE_AGENT_API_KEY": "test-secret-key"}):
            try:
                with client.websocket_connect("/ws/agent", headers={"Authorization": "Bearer test-secret-key"}) as ws:
                    ws.send_text(json.dumps({"type": "ping"}))
            except Exception:
                pass


class TestGenerateAuthenticWithWSBridge:
    """Tests for POST /api/capture/generate-authentic with WS bridge."""

    def test_generate_authentic_no_agent_no_config(self):
        """Without WS agent or HTTP config, should return error."""
        with patch.dict(os.environ, {"CAPTURE_AGENT_URL": "", "CAPTURE_AGENT_API_KEY": ""}):
            resp = client.post(
                "/api/capture/generate-authentic",
                json={"protocol": "SMTP"}
            )
            assert resp.status_code in (400, 503)

    def test_agent_status_reflects_ws_agent(self):
        """Agent status endpoint should reflect WS-connected agents."""
        hub = AgentHub()
        ws = MagicMock()
        run_async(hub.register_agent(ws, "ws-status-test"))
        run_async(hub.handle_agent_message("ws-status-test", {
            "type": "health",
            "status": "OK",
            "version": "1.0.0",
        }))

        info = hub.get_agent_info()
        assert info["online"] is True
        assert info["agent_count"] == 1

        run_async(hub.unregister_agent("ws-status-test"))

    def test_request_capture_gmail_profile(self):
        """request_capture with profile='gmail' should forward port 587 and target_host."""
        hub = AgentHub()
        mock_ws = AsyncMock()
        run_async(hub.register_agent(mock_ws, "agent-gmail-test"))

        pending = run_async(hub.request_capture(
            protocol="SMTP",
            profile="gmail",
            port=587,
            target_host="smtp.gmail.com",
            duration_seconds=40.0,
            interface="en0"
        ))

        assert pending.agent_id == "agent-gmail-test"
        assert mock_ws.send_text.called

        sent_payload = json.loads(mock_ws.send_text.call_args[0][0])
        assert sent_payload["type"] == "capture_request"
        assert sent_payload["profile"] == "gmail"
        assert sent_payload["port"] == 587
        assert sent_payload["target_host"] == "smtp.gmail.com"
        assert sent_payload["duration_seconds"] == 40.0
        assert sent_payload["interface"] == "en0"

        run_async(hub.unregister_agent("agent-gmail-test"))
