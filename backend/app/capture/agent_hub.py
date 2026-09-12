"""
WebSocket Agent Hub — manages persistent WebSocket connections from Capture Agents.

Architecture:
  Capture Agent (user machine) --[outbound WSS]--> Render Backend (this hub)
  Frontend (Vercel HTTPS) --[REST API]--> Render Backend --[WS relay]--> Agent

This solves the browser PNA block: the frontend never fetches localhost directly.
"""

import os
import asyncio
import json
import time
import uuid
import hmac
import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field

from fastapi import WebSocket, WebSocketDisconnect, status

logger = logging.getLogger("securemailscope.agent_hub")

# How long before a silent agent is considered stale (seconds)
AGENT_HEARTBEAT_TIMEOUT = 90

# Maximum time to wait for a capture result (seconds)
CAPTURE_REQUEST_TIMEOUT = 60


def normalize_os(os_name: Optional[str]) -> str:
    """Normalizes OS string to 'windows', 'macos', 'linux', or 'unknown'."""
    if not os_name:
        return "unknown"
    val = str(os_name).lower().strip()
    if val in ("darwin", "mac", "macos", "osx", "apple", "ios") or "mac" in val or "darwin" in val:
        return "macos"
    if val in ("win", "windows", "win32", "win64", "windows_nt") or val.startswith("win") or "windows" in val:
        return "windows"
    if "linux" in val:
        return "linux"
    return val


@dataclass
class ConnectedAgent:
    """Represents a single authenticated Capture Agent WebSocket connection."""
    agent_id: str
    websocket: WebSocket
    connected_at: float
    last_heartbeat: float
    os: str = "unknown"
    health_info: Dict[str, Any] = field(default_factory=dict)
    is_busy: bool = False

    @property
    def normalized_os(self) -> str:
        if self.os and self.os != "unknown":
            return normalize_os(self.os)
        if self.health_info and "os" in self.health_info:
            return normalize_os(self.health_info["os"])
        return "unknown"


@dataclass
class PendingCapture:
    """Tracks a capture request that has been dispatched to an agent."""
    request_id: str
    agent_id: str
    created_at: float
    result_event: asyncio.Event = field(default_factory=asyncio.Event)
    result_data: Optional[Dict[str, Any]] = None
    pcap_bytes: Optional[bytes] = None
    error: Optional[str] = None


class AgentHub:
    """
    Singleton hub that manages WebSocket connections from Capture Agents.
    Thread-safe via asyncio locks.
    """

    def __init__(self):
        self._agents: Dict[str, ConnectedAgent] = {}
        self._pending_captures: Dict[str, PendingCapture] = {}
        self._lock = asyncio.Lock()

    async def authenticate_agent(self, websocket: WebSocket, token: str) -> bool:
        """
        Validates the agent's Bearer token against the configured secret.
        Uses constant-time comparison to prevent timing attacks.
        Fails closed if CAPTURE_AGENT_API_KEY is not configured or empty.
        """
        expected_key = os.environ.get("CAPTURE_AGENT_API_KEY", "").strip()
        if not expected_key:
            logger.warning("CAPTURE_AGENT_API_KEY is not configured; rejecting agent connection.")
            return False

        if not token:
            return False

        return hmac.compare_digest(token.encode("utf-8"), expected_key.encode("utf-8"))

    async def register_agent(
        self,
        websocket: WebSocket,
        agent_id: str,
        client_os: str = "unknown"
    ) -> ConnectedAgent:
        """Registers a newly authenticated agent connection."""
        now = time.time()
        agent = ConnectedAgent(
            agent_id=agent_id,
            websocket=websocket,
            connected_at=now,
            last_heartbeat=now,
            os=normalize_os(client_os),
        )
        async with self._lock:
            # If an agent with same ID is already connected, close the old one gracefully
            if agent_id in self._agents:
                old = self._agents[agent_id]
                try:
                    await old.websocket.close(code=1000, reason="Replaced by new connection")
                except Exception:
                    pass
            self._agents[agent_id] = agent

        logger.info(f"Agent registered: {agent_id} (os={agent.normalized_os}, total connected: {len(self._agents)})")
        return agent

    async def unregister_agent(self, agent_id: str):
        """Removes a disconnected agent from the registry."""
        async with self._lock:
            agent = self._agents.pop(agent_id, None)

            # Fail any pending captures for this agent
            failed_ids = []
            for req_id, pending in self._pending_captures.items():
                if pending.agent_id == agent_id and not pending.result_event.is_set():
                    pending.error = "Agent disconnected during capture."
                    pending.result_event.set()
                    failed_ids.append(req_id)

        if agent:
            logger.info(f"Agent unregistered: {agent_id} (total connected: {len(self._agents)})")

    def is_agent_online(self, client_os: Optional[str] = None) -> bool:
        """
        Returns True if at least one agent is connected and has recent heartbeat.
        If client_os is provided and an agent for that OS is online, returns True.
        """
        now = time.time()
        norm_client_os = normalize_os(client_os) if client_os else None

        if norm_client_os and norm_client_os != "unknown":
            for agent in self._agents.values():
                if (now - agent.last_heartbeat) < AGENT_HEARTBEAT_TIMEOUT and agent.normalized_os == norm_client_os:
                    return True

        for agent in self._agents.values():
            if (now - agent.last_heartbeat) < AGENT_HEARTBEAT_TIMEOUT:
                return True
        return False

    def get_agent_info(self, client_os: Optional[str] = None) -> Dict[str, Any]:
        """
        Returns status information about connected agents for the frontend.
        Selects the best agent matching client_os if provided.
        """
        now = time.time()
        online_agents = []
        for agent in self._agents.values():
            is_stale = (now - agent.last_heartbeat) > AGENT_HEARTBEAT_TIMEOUT
            if not is_stale:
                online_agents.append({
                    "agent_id": agent.agent_id,
                    "connected_at": agent.connected_at,
                    "last_heartbeat": agent.last_heartbeat,
                    "is_busy": agent.is_busy,
                    "os": agent.normalized_os,
                    "health": agent.health_info,
                })

        available_platforms = list({a["os"] for a in online_agents if a["os"] != "unknown"})

        selected_agent = None
        matched_client_os = False
        norm_client_os = normalize_os(client_os) if client_os else None

        if norm_client_os and norm_client_os != "unknown":
            # 1. Prefer matching OS non-busy agent
            for a in online_agents:
                if a["os"] == norm_client_os and not a["is_busy"]:
                    selected_agent = a
                    matched_client_os = True
                    break
            # 2. Prefer matching OS even if busy
            if not selected_agent:
                for a in online_agents:
                    if a["os"] == norm_client_os:
                        selected_agent = a
                        matched_client_os = True
                        break

        # 3. Fallback: first non-busy, then first agent
        if not selected_agent and online_agents:
            for a in online_agents:
                if not a["is_busy"]:
                    selected_agent = a
                    break
            if not selected_agent:
                selected_agent = online_agents[0]

        return {
            "online": len(online_agents) > 0,
            "agent_count": len(online_agents),
            "agents": online_agents,
            "selected_agent": selected_agent,
            "matched_client_os": matched_client_os,
            "available_platforms": available_platforms,
        }

    async def handle_agent_message(self, agent_id: str, message: Dict[str, Any]):
        """Processes an incoming JSON message from an agent."""
        msg_type = message.get("type")

        if msg_type == "pong":
            async with self._lock:
                if agent_id in self._agents:
                    self._agents[agent_id].last_heartbeat = time.time()

        elif msg_type == "health":
            async with self._lock:
                if agent_id in self._agents:
                    self._agents[agent_id].last_heartbeat = time.time()
                    self._agents[agent_id].health_info = {
                        k: v for k, v in message.items() if k != "type"
                    }
                    if "os" in message and message["os"]:
                        self._agents[agent_id].os = normalize_os(message["os"])
                    self._agents[agent_id].is_busy = message.get("is_busy", False)

        elif msg_type == "capture_started":
            req_id = message.get("id")
            logger.info(f"Agent {agent_id} started capture {req_id}")

        elif msg_type == "capture_complete":
            req_id = message.get("id")
            async with self._lock:
                if req_id in self._pending_captures:
                    self._pending_captures[req_id].result_data = message
                    if agent_id in self._agents:
                        self._agents[agent_id].is_busy = False
            logger.info(f"Agent {agent_id} completed capture {req_id} ({message.get('size', 0)} bytes)")

        elif msg_type == "capture_error":
            req_id = message.get("id")
            async with self._lock:
                if req_id in self._pending_captures:
                    self._pending_captures[req_id].error = message.get("error", "Unknown capture error")
                    self._pending_captures[req_id].result_event.set()
                    if agent_id in self._agents:
                        self._agents[agent_id].is_busy = False
            logger.error(f"Agent {agent_id} capture error for {req_id}: {message.get('error')}")

        else:
            logger.warning(f"Unknown message type from agent {agent_id}: {msg_type}")

    async def handle_agent_binary(self, agent_id: str, data: bytes):
        """Processes incoming binary data (PCAP bytes) from an agent."""
        async with self._lock:
            # Find the pending capture for this agent that has result_data but no pcap_bytes yet
            for req_id, pending in self._pending_captures.items():
                if pending.agent_id == agent_id and pending.result_data and not pending.pcap_bytes:
                    pending.pcap_bytes = data
                    pending.result_event.set()
                    logger.info(f"Received PCAP binary ({len(data)} bytes) for capture {req_id}")
                    return

        logger.warning(f"Received unexpected binary data from agent {agent_id} ({len(data)} bytes)")

    async def request_capture(
        self,
        protocol: str = "SMTP",
        profile: str = "secure_tls12",
        port: Optional[int] = None,
        ports: Optional[List[int]] = None,
        target_host: Optional[str] = None,
        duration_seconds: Optional[float] = None,
        interface: Optional[str] = None,
        client_os: Optional[str] = None,
    ) -> PendingCapture:
        """
        Dispatches a capture request to an available agent.
        Supports both local test captures (2525) and real external captures (e.g. Gmail 587/465).
        Routes to the agent matching client_os if available.
        Returns a PendingCapture whose result_event will be set when complete.
        """
        # Find an available (not busy, not stale) agent
        now = time.time()
        target_agent: Optional[ConnectedAgent] = None
        norm_client_os = normalize_os(client_os) if client_os else None

        async with self._lock:
            # 1. If client_os specified, find matching OS agent that is not busy and not stale
            if norm_client_os and norm_client_os != "unknown":
                for agent in self._agents.values():
                    is_stale = (now - agent.last_heartbeat) > AGENT_HEARTBEAT_TIMEOUT
                    if not is_stale and not agent.is_busy and agent.normalized_os == norm_client_os:
                        target_agent = agent
                        break

            # 2. Fallback: find any available non-busy agent
            if not target_agent:
                for agent in self._agents.values():
                    is_stale = (now - agent.last_heartbeat) > AGENT_HEARTBEAT_TIMEOUT
                    if not is_stale and not agent.is_busy:
                        target_agent = agent
                        break

        if not target_agent:
            if norm_client_os and norm_client_os != "unknown":
                raise RuntimeError(f"No available Capture Agent is currently connected for {norm_client_os}.")
            raise RuntimeError("No available Capture Agent is currently connected.")

        request_id = str(uuid.uuid4())
        pending = PendingCapture(
            request_id=request_id,
            agent_id=target_agent.agent_id,
            created_at=now,
        )

        async with self._lock:
            self._pending_captures[request_id] = pending
            target_agent.is_busy = True

        # Send capture command to agent
        msg_payload: Dict[str, Any] = {
            "type": "capture_request",
            "id": request_id,
            "protocol": protocol,
            "profile": profile,
        }
        if port is not None:
            msg_payload["port"] = port
        if ports is not None:
            msg_payload["ports"] = ports
        if target_host is not None:
            msg_payload["target_host"] = target_host
        if duration_seconds is not None:
            msg_payload["duration_seconds"] = duration_seconds
        if interface is not None:
            msg_payload["interface"] = interface

        command = json.dumps(msg_payload)

        try:
            await target_agent.websocket.send_text(command)
            logger.info(f"Dispatched capture request {request_id} (profile={profile}, port={port}) to agent {target_agent.agent_id}")
        except Exception as e:
            async with self._lock:
                self._pending_captures.pop(request_id, None)
                target_agent.is_busy = False
            raise RuntimeError(f"Failed to send capture command to agent: {e}")

        return pending

    async def await_capture_result(
        self,
        pending: PendingCapture,
        timeout: Optional[float] = None
    ) -> tuple:
        """
        Waits for the capture to complete and returns (pcap_bytes, filename).
        Raises RuntimeError on timeout or error.
        """
        wait_timeout = timeout or CAPTURE_REQUEST_TIMEOUT
        try:
            await asyncio.wait_for(
                pending.result_event.wait(),
                timeout=wait_timeout
            )
        except asyncio.TimeoutError:
            async with self._lock:
                self._pending_captures.pop(pending.request_id, None)
            raise RuntimeError(
                f"Capture request {pending.request_id} timed out after {wait_timeout}s."
            )

        # Clean up
        async with self._lock:
            self._pending_captures.pop(pending.request_id, None)

        if pending.error:
            raise RuntimeError(f"Capture Agent error: {pending.error}")

        if not pending.pcap_bytes:
            raise RuntimeError("Capture completed but no PCAP data was received.")

        filename = pending.result_data.get("filename", "authentic_capture.pcap") if pending.result_data else "authentic_capture.pcap"

        return pending.pcap_bytes, filename

    async def cleanup_stale(self):
        """Removes stale agent connections that have exceeded heartbeat timeout."""
        now = time.time()
        stale_ids = []
        async with self._lock:
            for agent_id, agent in self._agents.items():
                if (now - agent.last_heartbeat) > AGENT_HEARTBEAT_TIMEOUT:
                    stale_ids.append(agent_id)

        for agent_id in stale_ids:
            await self.unregister_agent(agent_id)
            logger.warning(f"Removed stale agent: {agent_id}")


# Singleton instance
agent_hub = AgentHub()
