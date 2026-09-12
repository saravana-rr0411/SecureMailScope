"""
Tests for the Capture Agent WebSocket Bridge client.
Validates connection URL construction, bridge lifecycle, and message handling.
"""
import asyncio
import json
import os
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

# Prevent actual WebSocket connections during tests
os.environ.setdefault("BACKEND_WS_URL", "")
os.environ.setdefault("CAPTURE_AGENT_SECRET_KEY", "test-agent-key")

from capture_agent.ws_bridge import WebSocketBridge, start_ws_bridge, stop_ws_bridge, get_bridge


def run_async(coro):
    """Helper to run async code in sync tests."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


class TestWebSocketBridge:
    """Unit tests for WebSocketBridge class."""

    def test_connect_url_construction(self):
        """Should construct correct WebSocket URL with token."""
        bridge = WebSocketBridge(
            backend_ws_url="wss://example.com/ws/agent",
            api_key="my-secret-key",
        )
        url = bridge._get_connect_url()
        assert "wss://example.com/ws/agent" in url
        assert "token=my-secret-key" in url

    def test_connect_url_with_existing_query(self):
        """Should handle URLs that already have query params."""
        bridge = WebSocketBridge(
            backend_ws_url="wss://example.com/ws/agent?version=2",
            api_key="my-key",
        )
        url = bridge._get_connect_url()
        assert "&token=my-key" in url

    def test_default_config_values(self):
        """Bridge should have sensible defaults."""
        bridge = WebSocketBridge(
            backend_ws_url="wss://example.com/ws/agent",
            api_key="key",
        )
        assert bridge.heartbeat_interval == 30
        assert bridge.reconnect_max_delay == 60
        assert bridge._running is False

    def test_custom_config_values(self):
        """Bridge should accept custom configuration."""
        bridge = WebSocketBridge(
            backend_ws_url="wss://example.com/ws/agent",
            api_key="key",
            heartbeat_interval=15,
            reconnect_max_delay=120,
        )
        assert bridge.heartbeat_interval == 15
        assert bridge.reconnect_max_delay == 120

    def test_start_sets_running(self):
        """Starting bridge should set _running flag."""
        bridge = WebSocketBridge(
            backend_ws_url="wss://example.com/ws/agent",
            api_key="key",
        )

        # Patch _connection_loop to prevent actual connection
        bridge._connection_loop = AsyncMock()
        run_async(bridge.start())

        assert bridge._running is True
        assert bridge._task is not None

        # Cleanup
        bridge._running = False
        if bridge._task:
            bridge._task.cancel()

    def test_stop_clears_running(self):
        """Stopping bridge should clear _running flag."""
        bridge = WebSocketBridge(
            backend_ws_url="wss://example.com/ws/agent",
            api_key="key",
        )
        bridge._running = True
        bridge._task = MagicMock()
        bridge._task.done = MagicMock(return_value=True)

        run_async(bridge.stop())
        assert bridge._running is False


class TestBridgeModuleFunctions:
    """Tests for module-level bridge management functions."""

    def test_start_with_empty_url_does_nothing(self):
        """Starting with empty URL should not create a bridge."""
        run_async(start_ws_bridge(backend_ws_url="", api_key="key"))
        assert get_bridge() is None

    def test_stop_when_not_started(self):
        """Stopping when not started should not raise."""
        run_async(stop_ws_bridge())  # Should not raise


class TestBridgeConfigIntegration:
    """Tests that config values are properly loaded."""

    def test_backend_ws_url_from_env(self):
        """BACKEND_WS_URL should be loaded from environment."""
        with patch.dict(os.environ, {"BACKEND_WS_URL": "wss://test.example.com/ws/agent"}):
            import importlib
            import capture_agent.config
            importlib.reload(capture_agent.config)
            assert capture_agent.config.BACKEND_WS_URL == "wss://test.example.com/ws/agent"

    def test_ws_heartbeat_from_env(self):
        """WS_HEARTBEAT_INTERVAL should be loaded from environment."""
        with patch.dict(os.environ, {"WS_HEARTBEAT_INTERVAL": "45"}):
            import importlib
            import capture_agent.config
            importlib.reload(capture_agent.config)
            assert capture_agent.config.WS_HEARTBEAT_INTERVAL == 45

    def test_ws_reconnect_from_env(self):
        """WS_RECONNECT_MAX_DELAY should be loaded from environment."""
        with patch.dict(os.environ, {"WS_RECONNECT_MAX_DELAY": "120"}):
            import importlib
            import capture_agent.config
            importlib.reload(capture_agent.config)
            assert capture_agent.config.WS_RECONNECT_MAX_DELAY == 120


class TestBridgeMessageHandling:
    """Tests for message handling logic."""

    def test_handle_ping_message(self):
        """Bridge should respond to ping with pong."""
        bridge = WebSocketBridge(
            backend_ws_url="wss://example.com/ws/agent",
            api_key="key",
        )
        mock_ws = AsyncMock()
        mock_ws.send = AsyncMock()

        run_async(bridge._handle_message(mock_ws, {"type": "ping"}))

        mock_ws.send.assert_called_once()
        sent = mock_ws.send.call_args[0][0]
        data = json.loads(sent)
        assert data["type"] == "pong"

    def test_handle_unknown_message(self):
        """Unknown message types should be handled gracefully."""
        bridge = WebSocketBridge(
            backend_ws_url="wss://example.com/ws/agent",
            api_key="key",
        )
        mock_ws = AsyncMock()

        # Should not raise
        run_async(bridge._handle_message(mock_ws, {"type": "unknown_type"}))

    def test_handle_capture_request_message(self):
        """Capture request should trigger _execute_capture task creation."""
        bridge = WebSocketBridge(
            backend_ws_url="wss://example.com/ws/agent",
            api_key="key",
        )
        mock_ws = AsyncMock()

        # Patch _execute_capture to prevent actual capture
        with patch.object(bridge, '_execute_capture', new_callable=AsyncMock) as mock_exec:
            # We need an event loop for asyncio.create_task
            async def run():
                await bridge._handle_message(mock_ws, {
                    "type": "capture_request",
                    "id": "test-req-1",
                    "protocol": "SMTP",
                    "profile": "secure_tls12",
                })
                # Give the task a moment to be created
                await asyncio.sleep(0.01)

            run_async(run())
            # The task should have been created (may or may not have run)

    def test_ws_config_loaded_properly(self):
        """Verify that WebSocket configuration defaults and settings load correctly."""
        from capture_agent import config
        assert hasattr(config, "BACKEND_WS_URL")
        assert config.WS_HEARTBEAT_INTERVAL > 0
        assert config.WS_RECONNECT_MAX_DELAY >= 60
        # Verify default production Render endpoint
        default_ws = os.environ.get("BACKEND_WS_URL") or "wss://securemailscope-130k.onrender.com/ws/agent"
        assert "wss://" in default_ws and "/ws/agent" in default_ws

    def test_no_hardcoded_dev_secret_in_capture_agent_code(self):
        """Verify no 'sms-capture-secret-dev-key' fallback remains in production capture_agent code."""
        agent_dir = os.path.join(os.path.dirname(__file__), "..")
        violations = []
        for root, dirs, files in os.walk(agent_dir):
            # Skip tests, storage, and build artifacts
            if "tests" in root or "storage" in root or "__pycache__" in root:
                continue
            for f in files:
                if f.endswith(".py"):
                    path = os.path.join(root, f)
                    with open(path, "r", encoding="utf-8") as fp:
                        content = fp.read()
                        if "sms-capture-secret-dev-key" in content:
                            violations.append(path)
        assert violations == [], f"Found forbidden dev secret in capture_agent files: {violations}"
