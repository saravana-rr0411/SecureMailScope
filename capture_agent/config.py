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
        # 1. Fast native netsh query for connected network interface (fast Win32, no .NET overhead)
        try:
            out = subprocess.check_output(
                ["netsh", "interface", "show", "interface"],
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2
            ).strip()
            # If mock or command returned a single interface name directly:
            if "\n" not in out and out and "loopback" not in out.lower():
                return out
            for line in out.splitlines():
                if "Connected" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        iface_name = " ".join(parts[3:]).strip()
                        if iface_name and "loopback" not in iface_name.lower():
                            return iface_name
        except Exception:
            pass

        # 2. PowerShell query for default route interface alias (checking both IPv6 ::/0 and IPv4 0.0.0.0/0)
        try:
            cmd = [
                "powershell", "-NoProfile", "-Command",
                "@(Get-NetRoute -DestinationPrefix @('::/0', '0.0.0.0/0') -ErrorAction SilentlyContinue | Sort-Object RouteMetric | Select-Object -ExpandProperty InterfaceAlias -First 1; Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notmatch 'Loopback' } | Select-Object -ExpandProperty Name -First 1)[0]"
            ]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=3).strip()
            if out and "loopback" not in out.lower():
                return out
        except Exception:
            pass

        # 3. Scapy routing tables and interface inspection (active on real Windows hosts)
        if sys.platform == "win32":
            try:
                from scapy.all import conf
                # Check IPv6 route to Google (e.g. Gmail IPv6 endpoint)
                try:
                    iface6 = conf.route6.route("2607:f8b0:4004:800::206d")[0]
                    if iface6:
                        name_str = getattr(iface6, "name", "") or str(iface6)
                        desc_str = getattr(iface6, "description", "") or ""
                        net_str = getattr(iface6, "network_name", "") or ""
                        combined = f"{name_str} {desc_str} {net_str}".lower()
                        if not ("loopback" in combined or "npf_loopback" in combined):
                            return net_str or name_str
                except Exception:
                    pass

                # Check IPv4 route to Google/DNS
                try:
                    iface4 = conf.route.route("8.8.8.8")[0]
                    if iface4:
                        name_str = getattr(iface4, "name", "") or str(iface4)
                        desc_str = getattr(iface4, "description", "") or ""
                        net_str = getattr(iface4, "network_name", "") or ""
                        combined = f"{name_str} {desc_str} {net_str}".lower()
                        if not ("loopback" in combined or "npf_loopback" in combined):
                            return net_str or name_str
                except Exception:
                    pass

                # Inspect Scapy conf.ifaces for active external Wi-Fi / Ethernet adapter
                candidates = []
                for iface_key, iface_obj in conf.ifaces.items():
                    name_str = getattr(iface_obj, "name", "") or str(iface_key)
                    desc_str = getattr(iface_obj, "description", "") or ""
                    net_str = getattr(iface_obj, "network_name", "") or str(iface_key)
                    combined = f"{name_str} {desc_str} {net_str}".lower()

                    if "loopback" in combined or "npf_loopback" in combined:
                        continue

                    # Check IPs assigned to this adapter
                    ips_v4 = []
                    ips_v6 = []
                    if hasattr(iface_obj, "ips") and isinstance(iface_obj.ips, dict):
                        ips_v4 = iface_obj.ips.get(4, []) or []
                        ips_v6 = iface_obj.ips.get(6, []) or []

                    has_global_v6 = any(ip for ip in ips_v6 if not ip.startswith("fe80:") and ip != "::1")
                    has_routable_v4 = any(ip for ip in ips_v4 if not ip.startswith("127.") and not ip.startswith("169.254."))
                    has_any_v6 = any(ip for ip in ips_v6 if ip != "::1")

                    score = 0
                    if has_global_v6:
                        score += 10
                    if has_routable_v4:
                        score += 10
                    if has_any_v6:
                        score += 3
                    if "wi-fi" in combined or "wifi" in combined or "wireless" in combined or "802.11" in combined or "ax211" in combined:
                        score += 5
                    elif "ethernet" in combined:
                        score += 2

                    target_id = net_str or name_str
                    candidates.append((score, target_id))

                if candidates:
                    candidates.sort(key=lambda c: c[0], reverse=True)
                    if candidates[0][0] > 0:
                        return candidates[0][1]
            except Exception:
                pass

        # 4. Try conf.iface if not loopback
        try:
            from scapy.all import conf
            if conf.iface:
                ci_name = getattr(conf.iface, "name", "") or str(conf.iface)
                ci_desc = getattr(conf.iface, "description", "") or ""
                ci_net = getattr(conf.iface, "network_name", "") or ""
                ci_combined = f"{ci_name} {ci_desc} {ci_net}".lower()
                if not ("loopback" in ci_combined or "npf_loopback" in ci_combined):
                    return ci_net or ci_name
        except Exception:
            pass

        return "Wi-Fi"
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
