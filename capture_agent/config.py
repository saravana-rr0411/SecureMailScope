import os
import sys
import platform
import shutil
import subprocess
import re
from pathlib import Path
from typing import Tuple, Optional

# Base directories
BASE_DIR = Path(__file__).resolve().parent
if platform.system().lower() == "windows" and os.environ.get("PROGRAMDATA"):
    DEFAULT_STORAGE_DIR = Path(os.environ["PROGRAMDATA"]) / "SecureMailScope" / "CaptureAgent" / "storage"
else:
    DEFAULT_STORAGE_DIR = BASE_DIR / "storage"

# Environment configuration
CAPTURE_AGENT_SECRET_KEY = os.environ.get("CAPTURE_AGENT_SECRET_KEY", "").strip()
AGENT_HOST = os.environ.get("AGENT_HOST", "127.0.0.1")
AGENT_PORT = int(os.environ.get("AGENT_PORT", "9000"))
LOCAL_ONLY = os.environ.get("CAPTURE_AGENT_LOCAL_ONLY", "true").lower() in ("1", "true", "yes")

# Ephemeral Handshake Token TTL (seconds)
HANDSHAKE_TOKEN_TTL_SECONDS = int(os.environ.get("HANDSHAKE_TOKEN_TTL_SECONDS", "60"))

# WebSocket Bridge Configuration (outbound connection to Render backend)
BACKEND_WS_URL = os.environ.get(
    "BACKEND_WS_URL",
    "wss://securemailscope-130k.onrender.com/ws/agent"
)
WS_HEARTBEAT_INTERVAL = int(os.environ.get("WS_HEARTBEAT_INTERVAL", "30"))
WS_RECONNECT_MAX_DELAY = int(os.environ.get("WS_RECONNECT_MAX_DELAY", "60"))

# Strict Allowed Origins for Web Frontend CORS & Handshake (NO WILDCARD)
DEFAULT_ALLOWED_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "https://secure-mail-scope-eight.vercel.app",
    "https://securemailscope-130k.onrender.com",
    "https://securemailscope.onrender.com",
]


def get_allowed_origins() -> list[str]:
    """Returns the strict list of allowed web origins, merging defaults with any custom environment override."""
    extra = os.environ.get("CAPTURE_AGENT_ALLOWED_ORIGINS", "")
    origins = list(DEFAULT_ALLOWED_ORIGINS)
    if extra:
        for o in extra.split(","):
            cleaned = o.strip()
            if cleaned and cleaned not in origins:
                origins.append(cleaned)
    return origins


def is_origin_allowed(origin: Optional[str]) -> bool:
    """Checks if an origin is authorized, allowing configured origins and official SecureMailScope vercel deployments."""
    if not origin:
        return False
    if origin in get_allowed_origins():
        return True
    if re.match(r"^https:\/\/secure-mail-scope(?:-[a-z0-9-]+)?\.vercel\.app$", origin):
        return True
    return False


TEST_SMTP_HOST = os.environ.get("TEST_SMTP_HOST", "127.0.0.1")
TEST_SMTP_PORT = int(os.environ.get("TEST_SMTP_PORT", "2525"))

PCAP_STORAGE_DIR = Path(os.environ.get("PCAP_STORAGE_DIR", str(DEFAULT_STORAGE_DIR)))


def get_current_os() -> str:
    """Returns normalized operating system name: 'darwin', 'linux', or 'windows'."""
    return platform.system().lower()


# Mail capture ports configuration
# 587 / 465: Standard submission SMTP used by Gmail (smtp.gmail.com) and desktop mail clients
DEFAULT_CAPTURE_PORTS = [2525, 587, 465]


def get_capture_ports() -> list[int]:
    """Returns list of authorized TCP capture ports from environment or defaults."""
    env_ports = os.environ.get("CAPTURE_PORTS", "")
    if env_ports:
        ports = [int(p.strip()) for p in env_ports.split(",") if p.strip().isdigit()]
        if ports:
            return ports
    return list(DEFAULT_CAPTURE_PORTS)


def is_npcap_installed() -> bool:
    """
    Checks if Npcap / WinPcap packet capture driver is installed on Windows.
    Checks standard Windows system directories for wpcap.dll or Packet.dll.
    """
    if get_current_os() != "windows":
        return False

    sys_root = os.environ.get("SystemRoot", r"C:\Windows")
    npcap_paths = [
        os.path.join(sys_root, "System32", "Npcap", "wpcap.dll"),
        os.path.join(sys_root, "System32", "wpcap.dll"),
        os.path.join(sys_root, "SysWOW64", "Npcap", "wpcap.dll"),
        os.path.join(sys_root, "SysWOW64", "wpcap.dll"),
    ]
    for p in npcap_paths:
        if os.path.exists(p):
            return True

    # Also check if npcap service exists
    try:
        out = subprocess.run(
            ["sc", "query", "npcap"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2
        )
        if out.returncode == 0 and "RUNNING" in out.stdout.upper():
            return True
    except Exception:
        pass

    return False


def is_windows_admin() -> bool:
    """Checks whether current process on Windows has elevated Administrator rights."""
    if get_current_os() != "windows":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def detect_loopback_interface() -> str:
    """
    Detects appropriate loopback interface for packet capture.
    - macOS: 'lo0'
    - Linux: 'lo'
    - Windows: Npcap Loopback adapter or \\Device\\NPF_Loopback
    Can be overridden via CAPTURE_INTERFACE environment variable.
    """
    explicit = os.environ.get("CAPTURE_INTERFACE")
    if explicit:
        return explicit

    current_os = get_current_os()
    if current_os == "darwin":
        return "lo0"
    elif current_os == "windows":
        # Check Scapy Windows ifaces for loopback
        try:
            from scapy.all import conf
            for iface_name, iface in conf.ifaces.items():
                desc = getattr(iface, "description", "") or ""
                name = getattr(iface, "name", "") or ""
                if "loopback" in desc.lower() or "loopback" in name.lower() or "npf_loopback" in str(iface_name).lower():
                    return str(iface_name)
        except Exception:
            pass
        return r"\Device\NPF_Loopback"
    return "lo"


def detect_active_interface() -> str:
    """
    Detects the primary active network interface on the system (e.g. en0 on macOS).
    Used when capturing external traffic like Gmail SMTP (smtp.gmail.com:587).
    """
    explicit = os.environ.get("CAPTURE_INTERFACE")
    if explicit:
        return explicit

    current_os = get_current_os()
    if current_os == "darwin":
        try:
            out = subprocess.check_output(
                ["route", "-n", "get", "default"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2
            )
            for line in out.splitlines():
                if "interface:" in line:
                    iface = line.split(":")[1].strip()
                    if iface:
                        return iface
        except Exception:
            pass
        return "en0"
    elif current_os == "linux":
        try:
            out = subprocess.check_output(
                ["ip", "route", "show", "default"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2
            )
            parts = out.split()
            if "dev" in parts:
                return parts[parts.index("dev") + 1]
        except Exception:
            pass
        return "eth0"
    elif current_os == "windows":
        # 1. Try PowerShell Get-NetRoute for default gateway interface alias (e.g. 'Wi-Fi' or 'Ethernet')
        try:
            cmd = [
                "powershell", "-NoProfile", "-Command",
                "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -First 1).InterfaceAlias"
            ]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=3).strip()
            if out:
                return out
        except Exception:
            pass
        # 2. Try Scapy's default route interface
        try:
            from scapy.all import conf
            if conf.iface:
                return str(conf.iface)
        except Exception:
            pass
        return "Ethernet"
    return detect_loopback_interface()


def get_capture_interface(ports: Optional[list[int]] = None) -> str:
    """
    Selects the appropriate capture interface:
    - If CAPTURE_INTERFACE is set in env, always respect it.
    - If ports contain external submission port (587) and no local test port (2525), select active interface (en0).
    - Otherwise default to loopback interface (lo0).
    """
    explicit = os.environ.get("CAPTURE_INTERFACE")
    if explicit:
        return explicit
    if ports and (587 in ports or 465 in ports) and 2525 not in ports:
        return detect_active_interface()
    return detect_loopback_interface()


def get_tcpdump_binary() -> Optional[str]:
    """Finds path to system tcpdump binary (macOS / Linux)."""
    return shutil.which("tcpdump") or ("/usr/sbin/tcpdump" if os.path.exists("/usr/sbin/tcpdump") else None)


def check_capture_capabilities(interface: Optional[str] = None) -> Tuple[bool, str, bool]:
    """
    Checks whether the current environment and process has capabilities to capture packets.
    Returns (can_capture, diagnostic_message, requires_sudo).
    """
    current_os = get_current_os()

    # Windows capability validation (Npcap + Admin rights)
    if current_os == "windows":
        has_npcap = is_npcap_installed()
        has_admin = is_windows_admin()
        if not has_npcap:
            diag = (
                "Npcap packet capture driver is not installed on this Windows system.\n"
                "Please download and install Npcap from: https://npcap.com/#download\n"
                "(Ensure 'Install Npcap in WinPcap API-compatible Mode' is enabled)."
            )
            return False, diag, False
        if not has_admin:
            diag = (
                "Capture Agent is running without Administrator privileges.\n"
                "Please start the agent as Administrator or run via the installed Windows Service."
            )
            return True, diag, True
        return True, "Full packet capture capability available via Npcap.", False

    tcpdump_path = get_tcpdump_binary()
    if not tcpdump_path:
        return False, "tcpdump binary not found in PATH or /usr/sbin/tcpdump.", False

    iface = interface or detect_loopback_interface()

    # 1. Check direct BPF device access on macOS
    if current_os == "darwin" and os.path.exists("/dev/bpf0"):
        if os.access("/dev/bpf0", os.R_OK | os.W_OK):
            return True, f"Direct /dev/bpf access granted on '{iface}'.", False

    # 2. Attempt unprivileged dry-run check with tcpdump (-L lists datalinks and exits immediately)
    try:
        proc = subprocess.run(
            [tcpdump_path, "-L", "-i", iface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2
        )
        if proc.returncode == 0:
            return True, f"Full packet capture capability available directly on '{iface}' via {tcpdump_path}.", False
    except Exception:
        pass

    # 3. Check if passwordless sudo is available (e.g. sudo -n)
    try:
        proc_sudo = subprocess.run(
            ["sudo", "-n", tcpdump_path, "-L", "-i", iface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2
        )
        if proc_sudo.returncode == 0:
            return True, f"Packet capture capability available via sudo on '{iface}'.", True
    except Exception:
        pass

    # 4. If neither worked, provide clear, safe diagnostic instructions
    if current_os == "darwin":
        diag = (
            f"Permission denied accessing /dev/bpf* on macOS for interface '{iface}'.\n"
            "Recommended fix: Install the local macOS LaunchDaemon background service:\n"
            "    cd capture_agent/macos && sudo ./install.sh\n"
            "Or run the agent with root privileges: sudo .venv/bin/python capture_agent/main.py\n"
            "(Do not modify system permissions on /dev/bpf*)."
        )
        return False, diag, False

    diag = (
        f"Permission denied for packet capture on Linux interface '{iface}'.\n"
        f"Grant capabilities using: sudo setcap cap_net_raw,cap_net_admin+eip {tcpdump_path}"
    )
    return False, diag, False
