import os
import plistlib
import subprocess
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DIST_DIR = PROJECT_ROOT / "dist"
PKG_PATH = DIST_DIR / "SecureMailScopeCaptureAgent-1.0.0.pkg"
LAUNCHD_PLIST = PROJECT_ROOT / "capture_agent" / "macos" / "com.securemailscope.captureagent.plist"
UNINSTALL_SH = PROJECT_ROOT / "capture_agent" / "macos" / "uninstall.sh"
PREINSTALL_SH = PROJECT_ROOT / "capture_agent" / "macos" / "scripts" / "preinstall"
POSTINSTALL_SH = PROJECT_ROOT / "capture_agent" / "macos" / "scripts" / "postinstall"


def test_pkg_file_generated_and_valid_size():
    """Verify that the .pkg installer file was generated and has realistic size (> 1MB)."""
    assert PKG_PATH.exists(), f"Expected package at {PKG_PATH} does not exist. Run build_pkg.sh first."
    size_mb = PKG_PATH.stat().st_size / (1024 * 1024)
    assert size_mb > 1.0, f"Package size is unexpectedly small: {size_mb:.2f} MB"


def test_pkg_payload_contains_critical_components():
    """Verify that the .pkg contains all required application, daemon, and uninstall files."""
    proc = subprocess.run(
        ["pkgutil", "--payload-files", str(PKG_PATH)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True
    )
    files = proc.stdout.splitlines()

    # Normalize file paths
    normalized = [f.lstrip("./") for f in files]

    assert any("com.securemailscope.captureagent.plist" in f for f in normalized), "Missing LaunchDaemon plist"
    assert any("bin/run_agent.sh" in f for f in normalized), "Missing run_agent.sh"
    assert any("bin/uninstall.sh" in f for f in normalized), "Missing uninstall.sh"
    assert any("capture_agent/main.py" in f for f in normalized), "Missing capture_agent/main.py"
    assert any("wheels" in f for f in normalized), "Missing bundled offline wheels"


def test_launchdaemon_plist_security_and_syntax():
    """Verify LaunchDaemon plist configuration adheres to security requirements."""
    # Find plist inside build payload or template
    payload_plist = PROJECT_ROOT / "build" / "pkg_build" / "payload" / "Library" / "LaunchDaemons" / "com.securemailscope.captureagent.plist"
    plist_to_test = payload_plist if payload_plist.exists() else LAUNCHD_PLIST

    assert plist_to_test.exists()
    with open(plist_to_test, "rb") as f:
        data = plistlib.load(f)

    assert data.get("Label") == "com.securemailscope.captureagent"
    assert data.get("RunAtLoad") is True
    assert data.get("KeepAlive") is True

    # Check environment variables
    env = data.get("EnvironmentVariables", {})
    assert env.get("AGENT_HOST") == "127.0.0.1"
    assert env.get("AGENT_PORT") in (9000, "9000")
    assert env.get("CAPTURE_AGENT_LOCAL_ONLY") in ("true", True)

    # Confirm not exposed on 0.0.0.0
    for val in data.get("ProgramArguments", []):
        assert "0.0.0.0" not in str(val), "Found 0.0.0.0 binding in ProgramArguments!"


def test_installer_lifecycle_scripts_syntax_and_safety():
    """Verify preinstall and postinstall scripts exist, are executable, and contain no dangerous commands."""
    for script_path in [PREINSTALL_SH, POSTINSTALL_SH, UNINSTALL_SH]:
        assert script_path.exists(), f"Missing script: {script_path}"
        assert os.access(script_path, os.X_OK), f"Script not executable: {script_path}"

        content = script_path.read_text(encoding="utf-8")
        # Ensure bash set -e or set -euo pipefail
        assert "set -e" in content or "set -euo pipefail" in content
        # Ensure chmod 666 /dev/bpf is NOT present in any installer script
        assert "chmod 666" not in content, f"Insecure chmod 666 found in {script_path}"
        assert "/dev/bpf" not in content or "chmod" not in content, f"BPF permissions manipulation found in {script_path}"


def test_uninstaller_script_path_safety():
    """Verify uninstall.sh targets strictly the SecureMailScope CaptureAgent directories."""
    content = UNINSTALL_SH.read_text(encoding="utf-8")
    assert "/Library/LaunchDaemons/com.securemailscope.captureagent.plist" in content
    assert "/Library/Application Support/SecureMailScope/CaptureAgent" in content
    # Ensure no dangerous generic deletions like "rm -rf /" or "rm -rf /Library"
    assert "rm -rf /" not in content.replace("/Library/Application Support/SecureMailScope/CaptureAgent", "")


def test_installer_packages_websockets_dependency():
    """Verify that websockets is packaged in requirements, build_pkg.sh, and postinstall."""
    req_path = PROJECT_ROOT / "capture_agent" / "requirements.txt"
    assert req_path.exists()
    assert "websockets" in req_path.read_text(encoding="utf-8")

    build_pkg_path = PROJECT_ROOT / "capture_agent" / "macos" / "build_pkg.sh"
    assert build_pkg_path.exists()
    assert "websockets" in build_pkg_path.read_text(encoding="utf-8")

    postinstall_path = POSTINSTALL_SH
    assert postinstall_path.exists()
    assert "websockets" in postinstall_path.read_text(encoding="utf-8")


def test_launchdaemon_receives_ws_configuration():
    """Verify LaunchDaemon template and installer configure BACKEND_WS_URL and local-only bindings."""
    with open(LAUNCHD_PLIST, "rb") as f:
        data = plistlib.load(f)

    env = data.get("EnvironmentVariables", {})
    assert env.get("BACKEND_WS_URL") == "wss://securemailscope-130k.onrender.com/ws/agent"
    assert env.get("AGENT_HOST") == "127.0.0.1"
    assert env.get("AGENT_PORT") in (9000, "9000")
    assert env.get("CAPTURE_AGENT_LOCAL_ONLY") in ("true", True)
    assert "__AGENT_SECRET_KEY__" in env.get("CAPTURE_AGENT_SECRET_KEY", "")

    # Check install.sh performs substitution
    install_sh = PROJECT_ROOT / "capture_agent" / "macos" / "install.sh"
    content = install_sh.read_text(encoding="utf-8")
    assert "__AGENT_SECRET_KEY__" in content
    assert "chmod 600" in content
