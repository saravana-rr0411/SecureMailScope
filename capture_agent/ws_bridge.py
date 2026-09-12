"""
WebSocket Bridge Client — connects the local Capture Agent to the Render backend.

The agent opens an outbound WebSocket to the backend hub at:
  wss://securemailscope-130k.onrender.com/ws/agent?token=<API_KEY>

This allows the production HTTPS frontend to trigger captures via the backend,
bypassing the browser's Private Network Access (PNA) block on HTTPS→HTTP localhost.

Features:
- Auto-reconnect with exponential backoff
- Periodic heartbeat with health info
- Capture command handling (receives command → runs tcpdump → streams PCAP back)
- Graceful shutdown
"""

import asyncio
import json
import time
import logging
from typing import Optional

logger = logging.getLogger("capture_agent.ws_bridge")


class WebSocketBridge:
    """
    Persistent outbound WebSocket client that connects the local Capture Agent
    to the remote Render backend hub.
    """

    def __init__(
        self,
        backend_ws_url: str,
        api_key: str,
        heartbeat_interval: int = 30,
        reconnect_max_delay: int = 60,
    ):
        self.backend_ws_url = backend_ws_url
        self.api_key = api_key
        self.heartbeat_interval = heartbeat_interval
        self.reconnect_max_delay = reconnect_max_delay
        self._ws = None
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._heartbeat_task: Optional[asyncio.Task] = None

    def _get_connect_url(self) -> str:
        """Builds the WebSocket URL with authentication token and agent OS."""
        from capture_agent.config import get_current_os
        sep = "&" if "?" in self.backend_ws_url else "?"
        return f"{self.backend_ws_url}{sep}token={self.api_key}&os={get_current_os()}"

    async def start(self):
        """Start the WebSocket bridge as a background task."""
        if self._running:
            logger.warning("WebSocket bridge is already running.")
            return
        self._running = True
        self._task = asyncio.create_task(self._connection_loop())
        logger.info(f"WebSocket bridge started. Target: {self.backend_ws_url}")

    async def stop(self):
        """Gracefully stop the WebSocket bridge."""
        self._running = False
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("WebSocket bridge stopped.")

    async def _connection_loop(self):
        """Main loop: connect, handle messages, reconnect on disconnect."""
        backoff = 5  # Start with 5 second delay

        while self._running:
            try:
                await self._connect_and_listen()
                # If we get here, connection closed normally
                backoff = 5  # Reset backoff on clean disconnect
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"WebSocket connection error: {e}")

            if not self._running:
                break

            # Reconnect with exponential backoff
            logger.info(f"Reconnecting in {backoff}s...")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, self.reconnect_max_delay)

    async def _connect_and_listen(self):
        """Establishes a single WebSocket connection and processes messages."""
        try:
            import websockets
        except ImportError:
            logger.error(
                "websockets package not installed. "
                "Install with: pip install websockets>=13.0"
            )
            raise RuntimeError("websockets package required for WS bridge")

        url = self._get_connect_url()
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        logger.info(f"Connecting to backend WebSocket hub...")

        async with websockets.connect(
            url,
            additional_headers=headers,
            ping_interval=20,
            ping_timeout=10,
            close_timeout=5,
            max_size=50 * 1024 * 1024,  # 50MB max for PCAP transfers
        ) as ws:
            self._ws = ws
            logger.info("WebSocket bridge connected to backend hub.")

            # Start heartbeat sender
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(ws))

            # Send initial health report
            await self._send_health(ws)

            try:
                async for message in ws:
                    if isinstance(message, str):
                        try:
                            data = json.loads(message)
                            await self._handle_message(ws, data)
                        except json.JSONDecodeError:
                            logger.warning("Received invalid JSON from backend hub.")
                    elif isinstance(message, bytes):
                        logger.warning(f"Received unexpected binary from hub ({len(message)} bytes)")
            finally:
                if self._heartbeat_task and not self._heartbeat_task.done():
                    self._heartbeat_task.cancel()
                self._ws = None

    async def _handle_message(self, ws, data: dict):
        """Processes a JSON message from the backend hub."""
        msg_type = data.get("type")

        if msg_type == "ping":
            await ws.send(json.dumps({"type": "pong"}))

        elif msg_type == "capture_request":
            request_id = data.get("id")
            protocol = data.get("protocol", "SMTP")
            profile = data.get("profile", "secure_tls12")
            logger.info(f"Received capture request {request_id} (protocol={protocol}, profile={profile})")

            # Run capture in background to avoid blocking the WS listener
            asyncio.create_task(
                self._execute_capture(ws, request_id, protocol, profile, data)
            )

        else:
            logger.debug(f"Unhandled message type from hub: {msg_type}")

    async def _execute_capture(
        self,
        ws,
        request_id: str,
        protocol: str,
        profile: str,
        data: Optional[dict] = None
    ):
        """
        Executes the actual packet capture using the existing capture engine
        and streams the result back to the backend hub over WebSocket.
        """
        import datetime
        from pathlib import Path

        try:
            # Notify hub that capture has started
            await ws.send(json.dumps({
                "type": "capture_started",
                "id": request_id,
            }))

            # Import capture components (lazy to avoid circular imports)
            from capture_agent.config import (
                TEST_SMTP_HOST, TEST_SMTP_PORT, PCAP_STORAGE_DIR,
                check_capture_capabilities, get_capture_interface
            )
            from capture_agent.certs.cert_manager import generate_test_certificate
            from capture_agent.traffic.smtp_server import AuthenticSmtpServer
            from capture_agent.traffic.smtp_client import AuthenticSmtpClient
            from capture_agent.recorder.packet_capturer import PacketCapturer

            # Use the same capture_lock from main to prevent concurrent captures
            from capture_agent.main import capture_lock

            if capture_lock.locked():
                await ws.send(json.dumps({
                    "type": "capture_error",
                    "id": request_id,
                    "error": "Another capture is currently in progress.",
                }))
                return

            async with capture_lock:
                req_data = data or {}
                target_port = req_data.get("port")
                interface = req_data.get("interface")
                target_host = req_data.get("target_host")
                duration_seconds = req_data.get("duration_seconds")

                target_ports = req_data.get("ports")

                is_gmail_mode = (
                    target_port in (587, 465) or
                    (target_ports and any(p in (587, 465) for p in target_ports)) or
                    (profile and profile.lower() in ("gmail", "submission", "port_587", "port_465")) or
                    (protocol and protocol.upper() in ("GMAIL", "SUBMISSION"))
                )

                timestamp_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
                filename = (
                    f"authentic_gmail_smtp_submission_{timestamp_str}.pcap"
                    if is_gmail_mode
                    else f"authentic_{protocol.lower()}_tls_{timestamp_str}.pcap"
                )
                output_dir = PCAP_STORAGE_DIR
                output_dir.mkdir(parents=True, exist_ok=True)
                output_pcap_path = str(output_dir / filename)

                cert_material = None
                server = None
                capturer = None

                try:
                    if is_gmail_mode:
                        # Live external Gmail / mail submission capture mode (e.g. from desktop mail client)
                        gmail_ports = target_ports or ([target_port] if target_port in (587, 465) else [587, 465])
                        capturer = PacketCapturer(
                            output_pcap_path=output_pcap_path,
                            ports=gmail_ports,
                            interface=interface or get_capture_interface(gmail_ports),
                            host=target_host
                        )
                        duration = duration_seconds or 40.0
                        logger.info(f"WS Bridge: Capturing live Gmail SMTP submission traffic on {capturer.bpf_filter} ({capturer.interface}) for {duration}s...")
                        capturer.start(settle_delay=0.2)
                        await asyncio.sleep(duration)
                        capturer.stop()
                    else:
                        logger.info(f"WS Bridge: Starting authentic {protocol} capture...")

                        # 1. Generate real X.509 certificate
                        cert_material = generate_test_certificate(
                            common_name="mail.securemailscope.test",
                            validity_days=365,
                            key_size=2048
                        )

                        # 2. Start Real SMTP Server
                        server = AuthenticSmtpServer(
                            host=TEST_SMTP_HOST,
                            port=TEST_SMTP_PORT,
                            cert_path=cert_material.cert_path,
                            key_path=cert_material.key_path
                        )
                        server.start()

                        # 3. Start Packet Capturer
                        capturer = PacketCapturer(
                            output_pcap_path=output_pcap_path,
                            port=server.actual_port
                        )
                        capturer.start(settle_delay=0.2)

                        # 4. Execute Real SMTP Client
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

                        # Settle delay for TCP teardown
                        await asyncio.sleep(0.5)

                        # 5. Stop capturer and server
                        capturer.stop()
                        server.stop()
                        server = None

                finally:
                    if server:
                        try:
                            server.stop()
                        except Exception:
                            pass
                    if cert_material:
                        cert_material.cleanup()

                # Read the PCAP file
                pcap_path = Path(output_pcap_path)
                if not pcap_path.exists() or pcap_path.stat().st_size <= 24:
                    err_msg = (
                        "No Gmail SMTP submission traffic detected during the capture window. Send an email using your configured desktop mail client while capture is active."
                        if is_gmail_mode else
                        "Capture produced empty or invalid PCAP file."
                    )
                    await ws.send(json.dumps({
                        "type": "capture_error",
                        "id": request_id,
                        "error": err_msg,
                    }))
                    return

                pcap_bytes = pcap_path.read_bytes()
                pcap_size = len(pcap_bytes)

                # Send completion message
                await ws.send(json.dumps({
                    "type": "capture_complete",
                    "id": request_id,
                    "filename": filename,
                    "size": pcap_size,
                }))

                # Send PCAP binary
                await ws.send(pcap_bytes)

                logger.info(f"WS Bridge: Capture complete. Sent {pcap_size} bytes for {filename}")

                # Clean up temp PCAP file
                try:
                    pcap_path.unlink()
                except Exception:
                    pass

        except Exception as e:
            logger.error(f"WS Bridge capture error: {e}", exc_info=True)
            try:
                await ws.send(json.dumps({
                    "type": "capture_error",
                    "id": request_id,
                    "error": str(e),
                }))
            except Exception:
                pass

    async def _heartbeat_loop(self, ws):
        """Sends periodic health heartbeats to the backend hub."""
        while self._running:
            try:
                await asyncio.sleep(self.heartbeat_interval)
                await self._send_health(ws)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"Heartbeat send failed: {e}")
                break

    async def _send_health(self, ws):
        """Sends current health info as a heartbeat message."""
        try:
            from capture_agent.config import (
                check_capture_capabilities,
                detect_loopback_interface,
                get_tcpdump_binary,
                get_current_os,
            )
            from capture_agent.main import capture_lock

            can_cap, _, req_sudo = check_capture_capabilities()

            health = {
                "type": "health",
                "status": "OK",
                "version": "1.0.0",
                "os": get_current_os(),
                "interface": detect_loopback_interface(),
                "tcpdump_path": get_tcpdump_binary(),
                "can_capture": can_cap,
                "requires_sudo": req_sudo,
                "is_busy": capture_lock.locked(),
            }
            await ws.send(json.dumps(health))
        except Exception as e:
            logger.debug(f"Failed to send health heartbeat: {e}")


# Module-level bridge instance (initialized by main.py on startup)
_bridge_instance: Optional[WebSocketBridge] = None


def get_bridge() -> Optional[WebSocketBridge]:
    """Returns the active bridge instance, if any."""
    return _bridge_instance


async def start_ws_bridge(backend_ws_url: str, api_key: str, **kwargs):
    """Creates and starts the WebSocket bridge."""
    global _bridge_instance
    if not backend_ws_url:
        logger.info("WebSocket bridge disabled: BACKEND_WS_URL not configured.")
        return

    _bridge_instance = WebSocketBridge(
        backend_ws_url=backend_ws_url,
        api_key=api_key,
        **kwargs,
    )
    await _bridge_instance.start()


async def stop_ws_bridge():
    """Stops the WebSocket bridge if running."""
    global _bridge_instance
    if _bridge_instance:
        await _bridge_instance.stop()
        _bridge_instance = None
