import os
import sys
import tempfile
import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from capture_agent.config import (
    get_current_os,
    is_npcap_installed,
    is_windows_admin,
    detect_loopback_interface,
    detect_active_interface,
    get_capture_interface,
    check_capture_capabilities
)
from capture_agent.recorder.packet_capturer import PacketCapturer, build_bpf_filter
from capture_agent.recorder.windows_sniffer import WindowsPacketSniffer


def test_windows_platform_detection():
    """Verify get_current_os returns normalized platform names including windows."""
    with patch("platform.system", return_value="Windows"):
        assert get_current_os() == "windows"


def test_is_npcap_installed_mocked():
    """Verify is_npcap_installed detects presence when wpcap.dll exists or sc returns RUNNING."""
    with patch("capture_agent.config.get_current_os", return_value="windows"):
        # When file exists
        with patch("os.path.exists", return_value=True):
            assert is_npcap_installed() is True

        # When file does not exist, sc query returns RUNNING
        with patch("os.path.exists", return_value=False):
            mock_proc = MagicMock(returncode=0, stdout="STATE : 4 RUNNING")
            with patch("subprocess.run", return_value=mock_proc):
                assert is_npcap_installed() is True

        # When neither exists
        with patch("os.path.exists", return_value=False):
            mock_proc = MagicMock(returncode=1, stdout="NOT FOUND")
            with patch("subprocess.run", return_value=mock_proc):
                assert is_npcap_installed() is False


def test_is_windows_admin_mocked():
    """Verify is_windows_admin checks ctypes.windll.shell32 on Windows."""
    with patch("capture_agent.config.get_current_os", return_value="windows"):
        mock_ctypes = MagicMock()
        mock_ctypes.windll.shell32.IsUserAnAdmin.return_value = 1
        with patch.dict("sys.modules", {"ctypes": mock_ctypes}):
            assert is_windows_admin() is True


def test_windows_loopback_interface_resolution():
    """Verify Windows loopback interface fallback and resolution."""
    with patch("capture_agent.config.get_current_os", return_value="windows"):
        # Without CAPTURE_INTERFACE env override
        with patch.dict(os.environ, {}, clear=True):
            iface = detect_loopback_interface()
            assert iface in (r"\Device\NPF_Loopback", "lo") or "loopback" in iface.lower()


def test_windows_active_interface_resolution():
    """Verify Windows active external interface resolution for port 587."""
    with patch("capture_agent.config.get_current_os", return_value="windows"):
        with patch("subprocess.check_output", return_value="Wi-Fi"):
            iface = detect_active_interface()
            assert iface == "Wi-Fi"


def test_windows_check_capture_capabilities_success():
    """Verify check_capture_capabilities on Windows when Npcap is present."""
    with patch("capture_agent.config.get_current_os", return_value="windows"):
        with patch("capture_agent.config.is_npcap_installed", return_value=True):
            with patch("capture_agent.config.is_windows_admin", return_value=True):
                can_cap, diag, req_admin = check_capture_capabilities()
                assert can_cap is True
                assert req_admin is False
                assert "Npcap" in diag


def test_windows_check_capture_capabilities_missing_npcap():
    """Verify check_capture_capabilities warns when Npcap is missing."""
    with patch("capture_agent.config.get_current_os", return_value="windows"):
        with patch("capture_agent.config.is_npcap_installed", return_value=False):
            can_cap, diag, _ = check_capture_capabilities()
            assert can_cap is False
            assert "npcap.com" in diag.lower()


def test_bpf_filter_generation_for_windows():
    """Verify strict BPF filters generate identical safe syntax on Windows."""
    assert build_bpf_filter(port=587) == "tcp and port 587"
    assert build_bpf_filter(port=2525) == "tcp and port 2525 and host 127.0.0.1"
    assert build_bpf_filter(port=587, host="smtp.gmail.com") == "tcp and port 587 and host smtp.gmail.com"


def test_packet_capturer_dispatches_to_windows_sniffer_on_windows():
    """Verify PacketCapturer dispatches to WindowsPacketSniffer when platform is Windows."""
    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
        pcap_path = tmp.name

    with patch("capture_agent.recorder.packet_capturer.get_current_os", return_value="windows"):
        with patch("capture_agent.recorder.packet_capturer.check_capture_capabilities", return_value=(True, "OK", False)):
            with patch("capture_agent.recorder.windows_sniffer.WindowsPacketSniffer") as mock_sniffer_cls:
                mock_instance = MagicMock()
                mock_instance.stop.return_value = pcap_path
                mock_sniffer_cls.return_value = mock_instance

                capturer = PacketCapturer(
                    output_pcap_path=pcap_path,
                    port=587
                )
                capturer.start()
                assert capturer._windows_sniffer is not None
                mock_instance.start.assert_called_once()

                capturer.stop()
                mock_instance.stop.assert_called_once()


def test_windows_sniffer_lifecycle_mocked():
    """Verify WindowsPacketSniffer start, stop, and clean termination."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        # Write valid 24-byte PCAP header
        tmp.write(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00")
        tmp_path = tmp.name

    try:
        sniffer = WindowsPacketSniffer(
            output_pcap_path=tmp_path,
            bpf_filter="tcp and port 587"
        )
        # Mock thread and internal state
        sniffer._is_capturing = True
        sniffer._thread = MagicMock()
        sniffer._thread.is_alive.return_value = False

        result_path = sniffer.stop(timeout=1.0)
        assert result_path == tmp_path
        assert sniffer._stop_event.is_set()
        assert sniffer._is_capturing is False
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_windows_service_configuration():
    """Verify Windows Service module configuration constants."""
    from capture_agent.windows.service import (
        SERVICE_NAME,
        SERVICE_DISPLAY_NAME,
        SERVICE_DESCRIPTION
    )
    assert SERVICE_NAME == "SecureMailScopeCaptureAgent"
    assert "Capture Agent" in SERVICE_DISPLAY_NAME
    assert "SecureMailScope" in SERVICE_DESCRIPTION


def test_inno_setup_script_configuration():
    """Verify Inno Setup script configuration parameters, paths, and prerequisite checks."""
    iss_path = Path(__file__).resolve().parent.parent / "windows" / "inno_setup.iss"
    assert iss_path.exists(), f"inno_setup.iss not found at {iss_path}"
    content = iss_path.read_text(encoding="utf-8")

    # Installer metadata and binary name
    assert "OutputBaseFilename=SecureMailScopeCaptureAgent-1.0.0-Setup" in content
    assert "PrivilegesRequired=admin" in content
    assert "ArchitecturesInstallIn64BitMode=x64compatible" in content

    # Standard installation paths
    assert "{autopf}\\SecureMailScope\\CaptureAgent" in content
    assert "{commonappdata}\\SecureMailScope\\CaptureAgent\\storage" in content
    assert "{commonappdata}\\SecureMailScope\\CaptureAgent\\logs" in content

    # Windows Service name and execution
    assert 'MyServiceName "SecureMailScopeCaptureAgent"' in content
    assert 'service.py"" --startup=auto install' in content
    assert 'sc.exe"; Parameters: "start {#MyServiceName}"' in content
    assert 'sc.exe"; Parameters: "stop {#MyServiceName}"' in content
    assert 'service.py"" remove' in content

    # Npcap prerequisite logic
    assert "function IsNpcapInstalled(): Boolean;" in content
    assert "wpcap.dll" in content
    assert "https://npcap.com/#download" in content
    assert "WinPcap API-compatible Mode" in content
    assert "Check: IsNpcapInstalled" in content


def test_build_installer_script_validation():
    """Verify build_installer.bat contains strict prerequisite validation and fail-closed logic."""
    bat_path = Path(__file__).resolve().parent.parent / "windows" / "build_installer.bat"
    assert bat_path.exists(), f"build_installer.bat not found at {bat_path}"
    content = bat_path.read_text(encoding="utf-8")

    # Inno Setup compiler detection
    assert "ISCC_PATH" in content
    assert "ISCC.exe" in content
    assert "https://jrsoftware.org/isdl.php" in content

    # Required SecureMailScope source files validation
    assert "REQUIRED_ASSETS=" in content
    assert "windows_sniffer.py" in content
    assert "packet_capturer.py" in content
    assert "service.py" in content

    # SHA-256 hash verification
    assert "certutil -hashfile" in content
    assert "SHA256" in content
    assert "official_npcap_hashes.txt" in content

    # Output verification and fail-closed handling
    assert "SecureMailScopeCaptureAgent-1.0.0-Setup.exe" in content
    assert "exit /b 1" in content


def test_official_npcap_hashes_file():
    """Verify official_npcap_hashes.txt exists and contains valid SHA-256 signatures."""
    hash_path = Path(__file__).resolve().parent.parent / "windows" / "official_npcap_hashes.txt"
    assert hash_path.exists(), f"official_npcap_hashes.txt not found at {hash_path}"
    lines = [line.strip() for line in hash_path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    assert len(lines) >= 3, "Expected at least 3 official Npcap release hashes"

    for entry in lines:
        parts = entry.split()
        sha256 = parts[0]
        filename = parts[1]
        assert len(sha256) == 64, f"Invalid SHA-256 length for {filename}: {sha256}"
        assert all(c in "0123456789abcdefABCDEF" for c in sha256), f"Invalid hex in {sha256}"
        assert "npcap" in filename.lower(), f"Unexpected filename {filename}"


def test_failed_or_cancelled_npcap_installation_simulation():
    """Verify behavior when Npcap is missing or an installation was aborted."""
    with patch("capture_agent.config.get_current_os", return_value="windows"):
        with patch("capture_agent.config.is_npcap_installed", return_value=False):
            can_cap, diag, _ = check_capture_capabilities()
            assert can_cap is False
            assert "npcap.com/#download" in diag
            assert "WinPcap API-compatible Mode" in diag


def test_windows_service_env_loading(tmp_path):
    """Verify service loads environment configuration from agent.env if present."""
    from capture_agent.windows.service import SecureMailScopeWindowsService, load_service_env
    env_dir = tmp_path / "SecureMailScope" / "CaptureAgent"
    env_dir.mkdir(parents=True)
    env_file = env_dir / "agent.env"
    env_file.write_text("TEST_VAR_FOR_SERVICE=active_value\n", encoding="utf-8")

    with patch.dict(os.environ, {"PROGRAMDATA": str(tmp_path)}):
        check_path = Path(os.environ["PROGRAMDATA"]) / "SecureMailScope" / "CaptureAgent" / "agent.env"
        assert check_path.exists()
        loaded = load_service_env()
        assert loaded is True
        assert os.environ.get("TEST_VAR_FOR_SERVICE") == "active_value"

    # Also test when file doesn't exist
    with patch.dict(os.environ, {"PROGRAMDATA": str(tmp_path / "nonexistent")}):
        assert load_service_env() is False
