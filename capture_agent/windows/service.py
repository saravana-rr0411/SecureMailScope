import os
import sys
import time
import socket
import logging
import threading
from pathlib import Path

# Ensure project install root is on sys.path so capture_agent package can always be imported
INSTALL_ROOT = Path(__file__).resolve().parent.parent.parent
if str(INSTALL_ROOT) not in sys.path:
    sys.path.insert(0, str(INSTALL_ROOT))

# Set up directories and logging early
DATA_DIR = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "SecureMailScope" / "CaptureAgent"
LOG_DIR = DATA_DIR / "logs"
STORAGE_DIR = DATA_DIR / "storage"
LOG_DIR.mkdir(parents=True, exist_ok=True)
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
log_file = LOG_DIR / "service.log"

logging.basicConfig(
    filename=str(log_file),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] (WindowsService) %(message)s"
)
logger = logging.getLogger("SecureMailScopeService")

SERVICE_NAME = "SecureMailScopeCaptureAgent"
SERVICE_DISPLAY_NAME = "SecureMailScope Local Capture Agent"
SERVICE_DESCRIPTION = "Provides authentic local and Gmail SMTP packet capture capabilities for SecureMailScope."

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


from typing import Optional

WIN32_VERBS = {"install", "start", "stop", "restart", "remove", "update", "status", "debug"}


def normalize_service_argv(argv: list) -> list:
    """
    Ensure all option flags and parameters appear before win32 verbs
    so that win32serviceutil's internal getopt.getopt parses them correctly without terminating early.
    """
    if len(argv) <= 1:
        return list(argv)
    script = argv[0]
    args = list(argv[1:])
    verbs = []
    options_and_params = []
    for a in args:
        if a.lower() in WIN32_VERBS:
            verbs.append(a)
        else:
            options_and_params.append(a)
    return [script] + options_and_params + verbs


def get_service_host_exe() -> Optional[str]:
    """Locate the PythonService.exe host binary in the Python runtime directory."""
    exec_prefix = Path(sys.exec_prefix)
    for name in ("PythonService.exe", "pythonservice.exe"):
        candidate = exec_prefix / name
        if candidate.is_file():
            return str(candidate)
    # Check site-packages/win32
    sp_win32 = exec_prefix / "Lib" / "site-packages" / "win32"
    for name in ("PythonService.exe", "pythonservice.exe"):
        candidate = sp_win32 / name
        if candidate.is_file():
            return str(candidate)
    return None


def run_agent_server(stop_event: threading.Event):
    """Runs Uvicorn server in worker thread."""
    try:
        load_service_env()
        import uvicorn
        from capture_agent.main import app

        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=9000,
            log_level="info",
            access_log=False
        )
        server = uvicorn.Server(config)

        # Monitor stop_event and shut down uvicorn when signaled
        def stop_monitor():
            while not stop_event.is_set():
                time.sleep(0.5)
            server.should_exit = True

        monitor_thread = threading.Thread(target=stop_monitor, daemon=True)
        monitor_thread.start()

        logger.info("Starting Capture Agent Uvicorn server on 127.0.0.1:9000...")
        server.run()
        logger.info("Capture Agent Uvicorn server stopped cleanly.")
    except Exception as e:
        logger.error(f"Error in Capture Agent worker thread: {e}", exc_info=True)


def load_service_env() -> bool:
    """Load environment configuration from agent.env if available."""
    env_file = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "SecureMailScope" / "CaptureAgent" / "agent.env"
    if env_file.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(dotenv_path=str(env_file), override=True)
            logger.info("Loaded credentials from agent.env")
            return True
        except Exception as env_err:
            logger.warning(f"Could not load agent.env: {env_err}")
    return False


if WIN32_AVAILABLE:
    BaseServiceFramework = win32serviceutil.ServiceFramework
else:
    class BaseServiceFramework:
        def __init__(self, *args, **kwargs):
            pass


class SecureMailScopeWindowsService(BaseServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = SERVICE_DESCRIPTION

    _host_exe = get_service_host_exe()
    if _host_exe:
        _exe_name_ = _host_exe

    def __init__(self, args):
        super().__init__(args)
        if WIN32_AVAILABLE:
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self._stop_event = threading.Event()
        self._worker_thread = None

    def SvcStop(self):
        if WIN32_AVAILABLE:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.hWaitStop)
        logger.info("Received service stop request from Service Control Manager.")
        self._stop_event.set()

    def SvcDoRun(self):
        if WIN32_AVAILABLE:
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, "")
            )
        logger.info("Service started successfully.")

        # Load environment configuration from agent.env if available
        load_service_env()

        self._worker_thread = threading.Thread(
            target=run_agent_server,
            args=(self._stop_event,),
            name="AgentServerWorker",
            daemon=True
        )
        self._worker_thread.start()

        # Wait until SCM sends stop signal
        if WIN32_AVAILABLE:
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
            logger.info("Service terminating.")
            self.ReportServiceStatus(win32service.SERVICE_STOPPED)


def standalone_main():
    """Fallback runner for CLI debugging or non-service execution on Windows."""
    logger.info("Running Capture Agent in standalone CLI mode...")
    load_service_env()
    stop_event = threading.Event()
    try:
        run_agent_server(stop_event)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received; stopping...")
        stop_event.set()


if __name__ == "__main__":
    load_service_env()

    # Case 1: Invoked by SCM with no command-line arguments
    if len(sys.argv) == 1:
        if WIN32_AVAILABLE:
            try:
                servicemanager.Initialize()
                servicemanager.PrepareToHostSingle(SecureMailScopeWindowsService)
                servicemanager.StartServiceCtrlDispatcher()
            except Exception as e:
                # If run interactively from console with no arguments, dispatcher connection fails (error 1063)
                logger.info(f"Interactive execution detected (SCM dispatcher not active: {e}); running in standalone mode.")
                standalone_main()
        else:
            standalone_main()

    # Case 2: Windows Service management verbs (install, start, stop, remove, etc.)
    elif WIN32_AVAILABLE and any(arg.lower() in WIN32_VERBS for arg in sys.argv[1:]):
        normalized_argv = normalize_service_argv(sys.argv)
        logger.info("Processing service command line: %s", normalized_argv)
        try:
            win32serviceutil.HandleCommandLine(
                SecureMailScopeWindowsService,
                serviceClassString="capture_agent.windows.service.SecureMailScopeWindowsService",
                argv=normalized_argv
            )
            logger.info("win32serviceutil.HandleCommandLine finished successfully.")
        except Exception as exc:
            logger.error("Error executing win32serviceutil.HandleCommandLine: %s", exc, exc_info=True)
            sys.exit(1)

    # Case 3: Explicit SCM service dispatcher flag
    elif WIN32_AVAILABLE and "--service" in sys.argv:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(SecureMailScopeWindowsService)
        servicemanager.StartServiceCtrlDispatcher()

    # Case 4: Standalone / debugging execution
    else:
        standalone_main()

