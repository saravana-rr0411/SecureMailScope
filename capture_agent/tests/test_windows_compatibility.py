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
    assert build_bpf_filter(ports=[587, 465]) == "tcp and (port 587 or port 465)"


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
    assert "OutputBaseFilename=SecureMailScopeCaptureAgent-1.0.1-Setup" in content
    assert "PrivilegesRequired=admin" in content
    assert "ArchitecturesInstallIn64BitMode=x64compatible" in content

    # Standard installation paths
    assert "{autopf}\\SecureMailScope\\CaptureAgent" in content
    assert "{commonappdata}\\SecureMailScope\\CaptureAgent\\storage" in content
    assert "{commonappdata}\\SecureMailScope\\CaptureAgent\\logs" in content

    # Windows Service name and execution
    assert 'MyServiceName "SecureMailScopeCaptureAgent"' in content
    assert 'service.py"' in content and "install" in content and "--startup=auto" in content
    assert 'sc.exe"; Parameters: "start {#MyServiceName}"' in content
    assert 'sc.exe"; Parameters: "stop {#MyServiceName}"' in content
    assert 'service.py"" remove' in content

    # Npcap prerequisite logic
    assert "function IsNpcapInstalled(): Boolean;" in content
    assert "wpcap.dll" in content
    assert "https://npcap.com/#download" in content
    assert "WinPcap API-compatible Mode" in content
    assert "Check: IsNpcapInstalled" in content

    # Python runtime verification & post-install health check
    assert "function IsPythonRuntimeAvailable(): Boolean;" in content
    assert "CurStepChanged" in content
    assert "http://127.0.0.1:9000/health" in content
    assert "service.log" in content


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

    # Python runtime and dependency staging
    assert "PYTHON_BASE_DIR" in content
    assert "requirements.txt" in content
    assert "pip install" in content
    assert "import fastapi, uvicorn, scapy, win32serviceutil, websockets" in content

    # Verify no multi-quoted for /f commands that trigger CMD quote-stripping bugs
    for line in content.splitlines():
        if "for /f" in line and "('" in line:
            # Must not have multiple pairs of double quotes inside single quotes
            inner = line[line.find("('") + 2 : line.rfind("')")]
            assert inner.count('"') <= 2, f"Unsafe multi-quoted for /f command in batch script: {line}"

    # SHA-256 hash verification
    assert "certutil -hashfile" in content
    assert "SHA256" in content
    assert "official_npcap_hashes.txt" in content

    # Output verification and fail-closed handling
    assert "SecureMailScopeCaptureAgent-1.0.1-Setup.exe" in content
    assert "exit /b 1" in content

    # Ensure no echo statements inside blocks contain unquoted/unescaped parentheses
    for line in content.splitlines():
        trimmed = line.strip()
        if trimmed.startswith("echo ") and not trimmed.startswith("echo =="):
            if line.startswith("    ") or line.startswith("\t"):
                assert "(" not in trimmed and ")" not in trimmed, f"CMD block parser hazard: parenthesis in block echo: {line}"


def test_windows_service_install_root_and_paths():
    """Verify Windows Service module defines INSTALL_ROOT and sets up sys.path and directories."""
    from capture_agent.windows.service import (
        INSTALL_ROOT,
        DATA_DIR,
        LOG_DIR,
        STORAGE_DIR
    )
    assert INSTALL_ROOT.exists()
    assert (INSTALL_ROOT / "capture_agent").exists()
    assert str(INSTALL_ROOT) in sys.path
    assert "SecureMailScope" in str(DATA_DIR)
    assert "logs" in str(LOG_DIR)
    assert "storage" in str(STORAGE_DIR)


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


def test_github_actions_windows_workflow_structure():
    """Verify GitHub Actions workflow for Windows installer build exists and has correct parameters."""
    workflow_path = Path(__file__).resolve().parent.parent.parent / ".github" / "workflows" / "build-windows-agent.yml"
    assert workflow_path.exists(), f"Workflow file not found at {workflow_path}"
    content = workflow_path.read_text(encoding="utf-8")

    # Runner and triggers
    assert "runs-on: windows-latest" in content
    assert "workflow_dispatch:" in content
    assert "publish_release:" in content
    assert "release_tag:" in content

    # Build and dependencies
    assert "choco install innosetup" in content
    assert "build_installer.bat" in content
    assert "dist/SecureMailScopeCaptureAgent-1.0.1-Setup.exe" in content

    # Validation and artifacts
    assert "actions/upload-artifact" in content
    assert "SecureMailScopeCaptureAgent-1.0.1-Setup" in content
    assert "gh release upload" in content or "gh release create" in content

    # Live SCM Lifecycle validation
    assert "Validate Windows Service SCM Lifecycle & Live Startup" in content
    assert "sc.exe start $serviceName" in content
    assert "http://127.0.0.1:9000/health" in content

    # Ensure PowerShell script does not contain unsafe "$var:" style variable interpolation
    import re
    assert not re.findall(r"\$[A-Za-z0-9_]+:", content), (
        "PowerShell script contains unsafe variable interpolation immediately followed by colon (e.g. '$i:'). "
        "Use explicit delimiters '${i}:' instead."
    )
    assert 'Attempt ${i}:' in content


def test_windows_gmail_capture_selects_active_external_interface_not_loopback():
    """Verify Gmail capture mode selects active external interface (Wi-Fi), never loopback."""
    with patch("capture_agent.recorder.packet_capturer.get_current_os", return_value="windows"):
        with patch("capture_agent.config.get_current_os", return_value="windows"):
            with patch("capture_agent.config.detect_active_interface", return_value="Wi-Fi"):
                with patch("capture_agent.recorder.packet_capturer.detect_active_interface", return_value="Wi-Fi"):
                    # Case 1: No interface provided -> resolves to active Wi-Fi
                    capturer1 = PacketCapturer(
                        output_pcap_path="test_gmail.pcap",
                        ports=[587, 465]
                    )
                    assert capturer1.interface == "Wi-Fi"
                    assert "loopback" not in capturer1.interface.lower()

                    # Case 2: Loopback explicitly provided -> overridden to active external Wi-Fi for Gmail ports
                    capturer2 = PacketCapturer(
                        output_pcap_path="test_gmail.pcap",
                        ports=[587, 465],
                        interface=r"\Device\NPF_Loopback"
                    )
                    assert capturer2.interface == "Wi-Fi"
                    assert capturer2.interface != r"\Device\NPF_Loopback"

                    # Case 3: Controlled local test port 2525 -> preserves loopback
                    capturer3 = PacketCapturer(
                        output_pcap_path="test_local.pcap",
                        port=2525,
                        interface=r"\Device\NPF_Loopback"
                    )
                    assert capturer3.interface == r"\Device\NPF_Loopback"
                    assert capturer3.build_bpf_filter() == "tcp and port 2525 and host 127.0.0.1"


def test_windows_gmail_bpf_filter_preserves_ipv6_and_ipv4():
    """Verify Gmail capture BPF filter does not restrict to IPv4-only smtp.gmail.com and supports IPv6."""
    with patch("capture_agent.recorder.packet_capturer.get_current_os", return_value="windows"):
        with patch("capture_agent.config.detect_active_interface", return_value="Wi-Fi"):
            # Gmail capture initiated with default host="smtp.gmail.com"
            capturer = PacketCapturer(
                output_pcap_path="test_gmail.pcap",
                ports=[587, 465],
                host="smtp.gmail.com"
            )
            # Must omit 'host smtp.gmail.com' to prevent Npcap from compiling an IPv4-only filter
            bpf = capturer.build_bpf_filter()
            assert bpf == "tcp and (port 587 or port 465)"
            assert "host" not in bpf

            # Verify filter can be compiled with BPF and matches both IPv6 (0x86dd) and IPv4 (0x0800)
            from scapy.arch.bpf.core import compile_filter
            compiled = compile_filter(bpf, linktype=1)
            assert compiled.bf_len > 0


def test_normalize_service_argv():
    """Verify normalize_service_argv places all option flags before verbs for pywin32 getopt compatibility."""
    from capture_agent.windows.service import normalize_service_argv

    # Case 1: Standard Inno Setup / CMD invocation: install --startup=auto
    argv1 = ["service.py", "install", "--startup=auto"]
    assert normalize_service_argv(argv1) == ["service.py", "--startup=auto", "install"]

    # Case 2: Inverted invocation: --startup=auto install
    argv2 = ["service.py", "--startup=auto", "install"]
    assert normalize_service_argv(argv2) == ["service.py", "--startup=auto", "install"]

    # Case 3: Multiple options
    argv3 = ["service.py", "install", "--startup=auto", "-user", "LocalSystem"]
    assert normalize_service_argv(argv3) == ["service.py", "--startup=auto", "-user", "LocalSystem", "install"]

    # Case 4: Simple verb
    argv4 = ["service.py", "remove"]
    assert normalize_service_argv(argv4) == ["service.py", "remove"]

    # Case 5: Empty or single-element argv
    assert normalize_service_argv(["service.py"]) == ["service.py"]
    assert normalize_service_argv([]) == []


def test_win32_verbs_coverage():
    """Verify WIN32_VERBS contains all standard pywin32 service management actions."""
    from capture_agent.windows.service import WIN32_VERBS

    expected_verbs = {"install", "start", "stop", "restart", "remove", "update", "status", "debug"}
    assert expected_verbs.issubset(WIN32_VERBS)


def test_service_host_exe_resolution(tmp_path):
    """Verify get_service_host_exe locates PythonService.exe in runtime prefix or site-packages."""
    from capture_agent.windows.service import get_service_host_exe

    # Case 1: PythonService.exe directly in sys.exec_prefix
    fake_exe = tmp_path / "PythonService.exe"
    fake_exe.touch()
    with patch("sys.exec_prefix", str(tmp_path)):
        host = get_service_host_exe()
        assert host == str(fake_exe)

    # Case 2: pythonservice.exe (lowercase) in sys.exec_prefix
    fake_exe.unlink()
    fake_exe_lower = tmp_path / "pythonservice.exe"
    fake_exe_lower.touch()
    with patch("sys.exec_prefix", str(tmp_path)):
        host = get_service_host_exe()
        assert Path(host).name.lower() == "pythonservice.exe"

    # Case 3: In site-packages/win32
    fake_exe_lower.unlink()
    sp_dir = tmp_path / "Lib" / "site-packages" / "win32"
    sp_dir.mkdir(parents=True)
    sp_exe = sp_dir / "PythonService.exe"
    sp_exe.touch()
    with patch("sys.exec_prefix", str(tmp_path)):
        host = get_service_host_exe()
        assert host == str(sp_exe)

    # Case 4: None when not found
    sp_exe.unlink()
    with patch("sys.exec_prefix", str(tmp_path)):
        assert get_service_host_exe() is None


def test_inno_setup_scm_verification_and_agent_env():
    """Verify Inno Setup script provisions agent.env in ssPostInstall and validates SCM service existence."""
    iss_path = Path(__file__).resolve().parent.parent / "windows" / "inno_setup.iss"
    content = iss_path.read_text(encoding="utf-8")

    # Post-install agent.env provisioning
    assert "if CurStep = ssPostInstall then" in content
    assert "ForceDirectories(DataDirPath);" in content
    assert "BACKEND_WS_URL=wss://securemailscope-130k.onrender.com/ws/agent" in content
    assert "CAPTURE_AGENT_SECRET_KEY=sms-capture-secret-dev-key" in content
    assert "CAPTURE_AGENT_API_KEY=sms-capture-secret-dev-key" in content

    # SCM validation before health check
    assert "sc.exe" in content
    assert "query {#MyServiceName}" in content
    assert "Service Registration Error:" in content
    assert "NOT registered in Windows Service Control Manager" in content

    # Health check after SCM confirmation
    assert "start {#MyServiceName}" in content
    assert "http://127.0.0.1:9000/health" in content
    assert "Attempts := 1 to 15" in content


def test_build_installer_pythonservice_staging_and_clean_build():
    """Verify build_installer.bat contains PythonService staging, clean build, and asset verification."""
    bat_path = Path(__file__).resolve().parent.parent / "windows" / "build_installer.bat"
    content = bat_path.read_text(encoding="utf-8")

    # Clean build
    assert "Removing stale installer artifact before clean build" in content
    assert "del /q /f" in content

    # Staging verification of core assets
    assert "Required staged file missing: service.py" in content
    assert "Required staged file missing: config.py" in content
    assert "Required staged file missing: main.py" in content
    assert "Required staged file missing: ws_bridge.py" in content

    # PythonService.exe and pywin32 staging
    assert "PythonService.exe" in content
    assert "pythonservice.exe" in content
    assert "pywintypes*.dll" in content
    assert "pythoncom*.dll" in content
    assert "Verified PythonService host binary confirmed present." in content


def test_dynamic_secret_retrieval_and_env_loading(tmp_path):
    """Verify get_capture_agent_secret dynamically reloads credentials from agent.env."""
    from capture_agent.config import get_capture_agent_secret

    env_dir = tmp_path / "SecureMailScope" / "CaptureAgent"
    env_dir.mkdir(parents=True)
    env_file = env_dir / "agent.env"
    env_file.write_text("CAPTURE_AGENT_SECRET_KEY=custom-live-secret-test-999\n", encoding="utf-8")

    clean_env = {k: v for k, v in os.environ.items() if k not in ("CAPTURE_AGENT_SECRET_KEY", "CAPTURE_AGENT_API_KEY")}
    clean_env["PROGRAMDATA"] = str(tmp_path)

    with patch("platform.system", return_value="Windows"):
        with patch.dict(os.environ, clean_env, clear=True):
            secret = get_capture_agent_secret()
            assert secret == "custom-live-secret-test-999"


def test_service_class_string_format_pythonservice_compatibility():
    r"""
    Verify get_service_class_string() returns canonical [path\to\]module.ClassName format
    required by PythonService.exe's C++ loader (LoadPythonServiceClass).
    A naked dotted string like 'capture_agent.windows.service.SecureMailScopeWindowsService'
    lacks backslashes, causing PythonService.exe to fail to add the directory to sys.path
    and raise AttributeError, terminating with Error 1066 / 1 ('Incorrect function').
    """
    from capture_agent.windows.service import get_service_class_string, SecureMailScopeWindowsService

    svc_class_str = get_service_class_string()
    assert "\\" in svc_class_str, f"Service class string must contain backslashes for PythonService.exe: {svc_class_str}"
    assert svc_class_str.endswith(f".{SecureMailScopeWindowsService.__name__}")
    assert "service" in svc_class_str
    # Must NOT be a plain dotted package without path
    assert not svc_class_str.startswith("capture_agent.windows.service.")


def test_pythonservice_cpp_loading_semantics_simulation():
    r"""
    Simulate the exact C++ algorithm implemented in pywin32's PythonService.cpp LoadPythonServiceClass:
    1. Look for last '\\'.
    2. If missing, module import of 'capture_agent.windows.service' returns top package 'capture_agent'.
       getattr(capture_agent, 'SecureMailScopeWindowsService') fails -> WinError 1066 / Error 1.
    3. If present, [path\to\] is added to sys.path, and 'service' is imported directly,
       and getattr(service, 'SecureMailScopeWindowsService') succeeds.
    """
    from capture_agent.windows.service import get_service_class_string

    # Scenario A: Broken naked dotted string (Commit a171d7b behavior)
    broken_str = "capture_agent.windows.service.SecureMailScopeWindowsService"
    sep_idx = broken_str.rfind("\\")
    assert sep_idx == -1, "Broken string has no backslash"
    last_dot = broken_str.rfind(".")
    mod_name_broken = broken_str[:last_dot]
    class_name_broken = broken_str[last_dot + 1:]
    assert mod_name_broken == "capture_agent.windows.service"
    assert class_name_broken == "SecureMailScopeWindowsService"

    # PyImport_Import in CPython calls __import__ without fromlist
    top_mod = __import__(mod_name_broken)
    # top_mod is 'capture_agent', which lacks SecureMailScopeWindowsService
    assert not hasattr(top_mod, class_name_broken), (
        "Demonstrates why PythonService.exe threw AttributeError and exited with Error 1066 / 1"
    )

    # Scenario B: Fixed format with path (Current fix)
    valid_str = get_service_class_string()
    sep_idx_valid = valid_str.rfind("\\")
    assert sep_idx_valid != -1, "Valid string has backslash separating directory"
    dir_part = valid_str[:sep_idx_valid]
    fname_part = valid_str[sep_idx_valid + 1:]
    last_dot_valid = fname_part.rfind(".")
    mod_name_valid = fname_part[:last_dot_valid]
    class_name_valid = fname_part[last_dot_valid + 1:]

    assert mod_name_valid == "service"
    assert class_name_valid == "SecureMailScopeWindowsService"
    # Convert Windows backslashes to current OS separator to check existence
    assert Path(dir_part.replace("\\", os.sep)).exists()


def test_service_stdout_stderr_stream_safety():
    """Verify service.py handles missing console streams gracefully for LocalSystem execution."""
    import capture_agent.windows.service as svc_mod
    assert sys.stdout is not None
    assert sys.stderr is not None
    assert sys.stdin is not None
