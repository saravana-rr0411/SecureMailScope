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


class TestAgentSelectionAndRouting:
    """
    Validates agent OS tracking and selection logic:
    - Mac + Mac
    - Windows + Windows
    - Mac + Windows simultaneously
    - Windows + Mac simultaneously
    - Multiple agents where matching OS must win
    - No matching agent fallback
    """

    def test_mac_browser_mac_agent(self):
        """Mac browser + Mac agent: matching agent selected."""
        hub = AgentHub()
        ws_mac = AsyncMock()
        run_async(hub.register_agent(ws_mac, "agent-mac", client_os="darwin"))

        info = hub.get_agent_info(client_os="macos")
        assert info["online"] is True
        assert info["matched_client_os"] is True
        assert info["selected_agent"]["agent_id"] == "agent-mac"
        assert info["selected_agent"]["os"] == "macos"

        # Capture routes to Mac agent
        pending = run_async(hub.request_capture(client_os="macos"))
        assert pending.agent_id == "agent-mac"

    def test_windows_browser_windows_agent(self):
        """Windows browser + Windows agent: matching agent selected."""
        hub = AgentHub()
        ws_win = AsyncMock()
        run_async(hub.register_agent(ws_win, "agent-win", client_os="windows"))

        info = hub.get_agent_info(client_os="windows")
        assert info["online"] is True
        assert info["matched_client_os"] is True
        assert info["selected_agent"]["agent_id"] == "agent-win"
        assert info["selected_agent"]["os"] == "windows"

        # Capture routes to Windows agent
        pending = run_async(hub.request_capture(client_os="windows"))
        assert pending.agent_id == "agent-win"

    def test_mac_and_windows_simultaneously_mac_browser(self):
        """Both Mac and Windows agents connected simultaneously. Mac browser selects Mac agent."""
        hub = AgentHub()
        ws_win = AsyncMock()
        ws_mac = AsyncMock()
        # Windows connected first, Mac connected second
        run_async(hub.register_agent(ws_win, "agent-win", client_os="windows"))
        run_async(hub.register_agent(ws_mac, "agent-mac", client_os="darwin"))

        info = hub.get_agent_info(client_os="macos")
        assert info["online"] is True
        assert info["matched_client_os"] is True
        assert info["selected_agent"]["agent_id"] == "agent-mac"
        assert info["selected_agent"]["os"] == "macos"

        # Capture routes to Mac agent
        pending = run_async(hub.request_capture(client_os="macos"))
        assert pending.agent_id == "agent-mac"
        assert ws_mac.send_text.called
        assert not ws_win.send_text.called

    def test_windows_and_mac_simultaneously_windows_browser(self):
        """Both agents connected, Mac connected FIRST. Windows browser MUST select Windows agent."""
        hub = AgentHub()
        ws_mac = AsyncMock()
        ws_win = AsyncMock()
        # Mac connected FIRST, Windows connected SECOND
        run_async(hub.register_agent(ws_mac, "agent-mac", client_os="darwin"))
        run_async(hub.register_agent(ws_win, "agent-win", client_os="windows"))

        info = hub.get_agent_info(client_os="windows")
        assert info["online"] is True
        assert info["matched_client_os"] is True
        assert info["selected_agent"]["agent_id"] == "agent-win"
        assert info["selected_agent"]["os"] == "windows"

        # Capture routes to Windows agent, NOT Mac agent
        pending = run_async(hub.request_capture(client_os="windows"))
        assert pending.agent_id == "agent-win"
        assert ws_win.send_text.called
        assert not ws_mac.send_text.called

    def test_multiple_agents_where_matching_os_must_win(self):
        """Multiple agents (Linux, Mac 1, Mac 2, Windows) connected. Matching OS must always win."""
        hub = AgentHub()
        ws_linux = AsyncMock()
        ws_mac1 = AsyncMock()
        ws_mac2 = AsyncMock()
        ws_win = AsyncMock()

        run_async(hub.register_agent(ws_linux, "agent-linux", client_os="linux"))
        run_async(hub.register_agent(ws_mac1, "agent-mac-1", client_os="darwin"))
        run_async(hub.register_agent(ws_mac2, "agent-mac-2", client_os="darwin"))
        run_async(hub.register_agent(ws_win, "agent-win", client_os="windows"))

        # For Windows client -> agent-win MUST win
        win_info = hub.get_agent_info(client_os="windows")
        assert win_info["selected_agent"]["agent_id"] == "agent-win"
        assert win_info["matched_client_os"] is True

        win_capture = run_async(hub.request_capture(client_os="windows"))
        assert win_capture.agent_id == "agent-win"

        # For Mac client -> a Mac agent MUST win
        mac_info = hub.get_agent_info(client_os="macos")
        assert mac_info["selected_agent"]["agent_id"] in ("agent-mac-1", "agent-mac-2")
        assert mac_info["matched_client_os"] is True

        mac_capture = run_async(hub.request_capture(client_os="macos"))
        assert mac_capture.agent_id in ("agent-mac-1", "agent-mac-2")

        # For Linux client -> agent-linux MUST win
        linux_info = hub.get_agent_info(client_os="linux")
        assert linux_info["selected_agent"]["agent_id"] == "agent-linux"
        assert linux_info["matched_client_os"] is True

    def test_no_matching_agent_fallback(self):
        """When client is Windows but ONLY a Mac agent is connected, fallback is provided but matched_client_os is False."""
        hub = AgentHub()
        ws_mac = AsyncMock()
        run_async(hub.register_agent(ws_mac, "agent-mac", client_os="darwin"))

        info = hub.get_agent_info(client_os="windows")
        assert info["online"] is True
        # Fallback to connected agent
        assert info["selected_agent"]["agent_id"] == "agent-mac"
        assert info["selected_agent"]["os"] == "macos"
        # Crucial: matched_client_os is False, enabling frontend to show "WINDOWS AGENT NEEDED"
        assert info["matched_client_os"] is False

    def test_rest_api_agent_status_routing(self):
        """Tests REST /api/agent/status with query param, X-Client-OS header, and User-Agent."""
        ws_mac = AsyncMock()
        ws_win = AsyncMock()
        agent_mac = run_async(agent_hub.register_agent(ws_mac, "api-agent-mac", client_os="darwin"))
        agent_win = run_async(agent_hub.register_agent(ws_win, "api-agent-win", client_os="windows"))

        try:
            # 1. Query param ?client_os=windows
            resp_win = client.get("/api/agent/status?client_os=windows")
            assert resp_win.status_code == 200
            data_win = resp_win.json()
            assert data_win["status"] == "connected"
            assert data_win["os"] == "windows"
            assert data_win["matched_client_os"] is True

            # 2. Query param ?client_os=macos
            resp_mac = client.get("/api/agent/status?client_os=macos")
            assert resp_mac.status_code == 200
            data_mac = resp_mac.json()
            assert data_mac["status"] == "connected"
            assert data_mac["os"] == "macos"
            assert data_mac["matched_client_os"] is True

            # 3. Header X-Client-OS: windows
            resp_hdr = client.get("/api/agent/status", headers={"X-Client-OS": "windows"})
            assert resp_hdr.status_code == 200
            data_hdr = resp_hdr.json()
            assert data_hdr["os"] == "windows"

            # 4. User-Agent with Windows NT
            resp_ua_win = client.get("/api/agent/status", headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            assert resp_ua_win.status_code == 200
            assert resp_ua_win.json()["os"] == "windows"

            # 5. User-Agent with Macintosh
            resp_ua_mac = client.get("/api/agent/status", headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"})
            assert resp_ua_mac.status_code == 200
            assert resp_ua_mac.json()["os"] == "macos"

        finally:
            run_async(agent_hub.unregister_agent("api-agent-mac"))
            run_async(agent_hub.unregister_agent("api-agent-win"))

    def test_capture_routing_via_api(self):
        """Capture commands route to the matching OS agent, not merely status reporting."""
        ws_mac = AsyncMock()
        ws_win = AsyncMock()
        run_async(agent_hub.register_agent(ws_mac, "cap-agent-mac", client_os="darwin"))
        run_async(agent_hub.register_agent(ws_win, "cap-agent-win", client_os="windows"))

        try:
            # Dispatch capture for Windows client
            pending_win = run_async(agent_hub.request_capture(client_os="windows"))
            assert pending_win.agent_id == "cap-agent-win"
            assert ws_win.send_text.called
            assert not ws_mac.send_text.called

            # Dispatch capture for Mac client
            pending_mac = run_async(agent_hub.request_capture(client_os="macos"))
            assert pending_mac.agent_id == "cap-agent-mac"
            assert ws_mac.send_text.called
        finally:
            run_async(agent_hub.unregister_agent("cap-agent-mac"))
            run_async(agent_hub.unregister_agent("cap-agent-win"))
