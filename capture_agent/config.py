import os
import sys
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Tuple, Optional

# Base directories
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_STORAGE_DIR = BASE_DIR / "storage"

# Environment configuration
CAPTURE_AGENT_SECRET_KEY = os.environ.get("CAPTURE_AGENT_SECRET_KEY", "sms-capture-secret-dev-key")
AGENT_HOST = os.environ.get("AGENT_HOST", "0.0.0.0")
AGENT_PORT = int(os.environ.get("AGENT_PORT", "9000"))

TEST_SMTP_HOST = os.environ.get("TEST_SMTP_HOST", "127.0.0.1")
TEST_SMTP_PORT = int(os.environ.get("TEST_SMTP_PORT", "2525"))

PCAP_STORAGE_DIR = Path(os.environ.get("PCAP_STORAGE_DIR", str(DEFAULT_STORAGE_DIR)))


def get_current_os() -> str:
    """Returns normalized operating system name: 'darwin', 'linux', or 'windows'."""
    return platform.system().lower()


def detect_loopback_interface() -> str:
    """
    Detects appropriate loopback interface for packet capture.
    macOS uses 'lo0', while Linux uses 'lo'.
    Can be overridden via CAPTURE_INTERFACE environment variable.
    """
    explicit = os.environ.get("CAPTURE_INTERFACE")
    if explicit:
        return explicit

    current_os = get_current_os()
    if current_os == "darwin":
        return "lo0"
    return "lo"


def get_tcpdump_binary() -> Optional[str]:
    """Finds path to system tcpdump binary."""
    return shutil.which("tcpdump") or ("/usr/sbin/tcpdump" if os.path.exists("/usr/sbin/tcpdump") else None)


def check_capture_capabilities(interface: Optional[str] = None) -> Tuple[bool, str, bool]:
    """
    Checks whether the current environment and process has capabilities to capture packets.
    Returns (can_capture, diagnostic_message, requires_sudo).
    """
    tcpdump_path = get_tcpdump_binary()
    if not tcpdump_path:
        return False, "tcpdump binary not found in PATH or /usr/sbin/tcpdump.", False

    iface = interface or detect_loopback_interface()
    current_os = get_current_os()

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

    # 3. If neither worked, provide clear, safe diagnostic instructions
    if current_os == "darwin":
        diag = (
            f"Permission denied accessing /dev/bpf* on macOS for interface '{iface}'.\n"
            "Safest & Simplest local fix: Run once in your terminal:\n"
            "    sudo chmod 666 /dev/bpf*\n"
            "(This grants unprivileged user access to BPF taps without running Python as root)."
        )
        return False, diag, False

    diag = (
        f"Permission denied for packet capture on Linux interface '{iface}'.\n"
        f"Grant capabilities using: sudo setcap cap_net_raw,cap_net_admin+eip {tcpdump_path}"
    )
    return False, diag, False
