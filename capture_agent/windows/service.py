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

import platform
import tempfile

# Set up directories and logging early
if platform.system().lower() == "windows":
    DATA_DIR = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "SecureMailScope" / "CaptureAgent"
else:
    DATA_DIR = Path(os.environ.get("PROGRAMDATA", tempfile.gettempdir())) / "SecureMailScope" / "CaptureAgent"
LOG_DIR = DATA_DIR / "logs"
STORAGE_DIR = DATA_DIR / "storage"
try:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass
log_file = LOG_DIR / "service.log"

# In a Windows service (running under SCM/LocalSystem without an interactive console),
# sys.stdout, sys.stderr, and sys.stdin may be None.
# Redirect None streams to os.devnull to prevent AttributeError in libraries writing to stdout/stderr.
if sys.stdout is None:
    try:
        sys.stdout = open(os.devnull, "w", encoding="utf-8")
    except Exception:
        pass
if sys.stderr is None:
    try:
        sys.stderr = open(os.devnull, "w", encoding="utf-8")
    except Exception:
        pass
if sys.stdin is None:
    try:
        sys.stdin = open(os.devnull, "r", encoding="utf-8")
    except Exception:
        pass

# Configure root logger and dedicated service logger with explicit FileHandler
logger = logging.getLogger("SecureMailScopeService")
logger.setLevel(logging.INFO)

file_handler_present = any(isinstance(h, logging.FileHandler) for h in logger.handlers)
if not file_handler_present:
    try:
        fh = logging.FileHandler(str(log_file), encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] (WindowsService) %(message)s"))
        logger.addHandler(fh)
    except Exception:
        pass

try:
    logging.basicConfig(
        filename=str(log_file),
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] (WindowsService) %(message)s"
    )
except Exception:
    pass

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


def get_service_class_string() -> str:
    r"""
    Return the fully qualified service class string in the format expected by pywin32's PythonService.exe host:
    [path\to\]module.ClassName

    PythonService.exe's C++ loader (LoadPythonServiceClass) requires this format so it can locate
    the directory from the backslash, prepend it to sys.path, and import the module directly.
    Passing a dotted package name without a path causes LoadPythonServiceClass to fail with
    AttributeError and SCM to terminate the service with service-specific error 1066 / 1 ('Incorrect function').
    """
    script_path = Path(__file__).resolve()
    base_path = str(script_path.with_suffix("")).replace("/", "\\")
    return f"{base_path}.{SecureMailScopeWindowsService.__name__}"


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


def apply_windows_asyncio_protections():
    """
    Applies asyncio protections on Windows:
    1. Sets WindowsSelectorEventLoopPolicy as default event loop policy.
    2. Patches BaseProactorEventLoop._start_serving (if present) to prevent
       transient client connection resets (WinError 64 ERROR_NETNAME_DELETED,
       WSAECONNRESET 10054, WSAECONNABORTED 10053, ERROR_SEM_TIMEOUT 121)
       from destroying the listening server socket (CPython Issue #93758).
    """
    if platform.system().lower() != "windows":
        return

    import asyncio
    # 1. Enforce WindowsSelectorEventLoopPolicy for robust BSD-socket semantics
    try:
        if hasattr(asyncio, "WindowsSelectorEventLoopPolicy"):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            logger.info("Enforced WindowsSelectorEventLoopPolicy for Capture Agent service.")
    except Exception as e:
        logger.warning(f"Could not set WindowsSelectorEventLoopPolicy: {e}")

    # 2. Defense-in-depth monkeypatch for ProactorEventLoop (CPython #93758)
    try:
        import asyncio.proactor_events
        import asyncio.trsock
        base_proactor = getattr(asyncio.proactor_events, "BaseProactorEventLoop", None)
        if base_proactor and not getattr(base_proactor, "_sms_patched_winerror64", False):
            orig_start_serving = base_proactor._start_serving

            def patched_start_serving(self, protocol_factory, sock, sslcontext=None, server=None, backlog=100, ssl_handshake_timeout=None, ssl_shutdown_timeout=None):
                def loop(f=None):
                    try:
                        if f is not None:
                            conn, addr = f.result()
                            if self._debug:
                                logger.debug("%r got a new connection from %r: %r", server, addr, conn)
                            protocol = protocol_factory()
                            if sslcontext is not None:
                                self._make_ssl_transport(conn, protocol, sslcontext, server_side=True, extra={'peername': addr}, server=server, ssl_handshake_timeout=ssl_handshake_timeout, ssl_shutdown_timeout=ssl_shutdown_timeout)
                            else:
                                self._make_socket_transport(conn, protocol, extra={'peername': addr}, server=server)
                        if self.is_closed():
                            return
                        f = self._proactor.accept(sock)
                    except OSError as exc:
                        win_err = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
                        # WinError 64: ERROR_NETNAME_DELETED, WinError 121: ERROR_SEM_TIMEOUT, 10053: WSAECONNABORTED, 10054: WSAECONNRESET
                        if win_err in (64, 121, 10053, 10054) and not self.is_closed() and sock.fileno() != -1:
                            logger.warning(f"Ignored transient client accept error (WinError {win_err}: {exc}); keeping server listener alive.")
                            try:
                                f = self._proactor.accept(sock)
                                self._accept_futures[sock.fileno()] = f
                                f.add_done_callback(loop)
                                return
                            except Exception as rearm_err:
                                logger.error(f"Failed to re-arm accept on socket: {rearm_err}")
                        if sock.fileno() != -1:
                            self.call_exception_handler({
                                'message': 'Accept failed on a socket',
                                'exception': exc,
                                'socket': asyncio.trsock.TransportSocket(sock),
                            })
                            sock.close()
                        elif self._debug:
                            logger.debug("Accept failed on socket %r", sock, exc_info=True)
                    except asyncio.CancelledError:
                        sock.close()
                    else:
                        self._accept_futures[sock.fileno()] = f
                        f.add_done_callback(loop)

                self.call_soon(loop)

            base_proactor._start_serving = patched_start_serving
            base_proactor._sms_patched_winerror64 = True
            logger.info("Applied ProactorEventLoop WinError 64 resilience patch.")
    except Exception as e:
        logger.warning(f"Could not apply ProactorEventLoop patch: {e}")


def run_agent_server(stop_event: threading.Event, ready_event: Optional[threading.Event] = None):
    """Runs Uvicorn server in worker thread with single clear asyncio ownership."""
    try:
        load_service_env()
        apply_windows_asyncio_protections()

        import asyncio
        if platform.system().lower() == "windows":
            try:
                loop = asyncio.SelectorEventLoop()
            except Exception:
                loop = asyncio.new_event_loop()
        else:
            loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        import uvicorn
        from capture_agent.main import app

        loop_param = "asyncio:SelectorEventLoop" if platform.system().lower() == "windows" else "auto"

        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=9000,
            log_level="info",
            access_log=False,
            loop=loop_param
        )
        server = uvicorn.Server(config)

        async def serve_with_graceful_stop():
            server_task = asyncio.create_task(server.serve())

            # Wait for Uvicorn to bind and start listening
            while not server.started and not server_task.done() and not stop_event.is_set():
                await asyncio.sleep(0.05)

            if server.started:
                logger.info("Capture Agent Uvicorn server successfully bound and listening on 127.0.0.1:9000.")
                if ready_event:
                    ready_event.set()

            # Cooperative monitoring loop
            while not stop_event.is_set() and not server_task.done():
                await asyncio.sleep(0.5)

            if stop_event.is_set() and not server_task.done():
                logger.info("Service stop event signaled; requesting Uvicorn shutdown...")
                server.should_exit = True

            await server_task

        logger.info("Starting Capture Agent Uvicorn server on 127.0.0.1:9000...")
        try:
            loop.run_until_complete(serve_with_graceful_stop())
        finally:
            try:
                loop.close()
            except Exception:
                pass
        logger.info("Capture Agent Uvicorn server stopped cleanly.")
    except Exception as e:
        logger.error(f"Error in Capture Agent worker thread: {e}", exc_info=True)
        if ready_event:
            ready_event.set()


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
        logger.info("SecureMailScopeWindowsService.__init__ called with args: %s", args)
        super().__init__(args)
        if WIN32_AVAILABLE:
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self._stop_event = threading.Event()
        self._ready_event = threading.Event()
        self._worker_thread = None
        logger.info("SecureMailScopeWindowsService.__init__ completed successfully.")

    def SvcStop(self):
        logger.info("Received service stop request from Service Control Manager.")
        if WIN32_AVAILABLE:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.hWaitStop)
        self._stop_event.set()

    def SvcDoRun(self):
        try:
            logger.info("SecureMailScopeWindowsService SvcDoRun starting...")
            if WIN32_AVAILABLE:
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, "")
                )

            # Load environment configuration from agent.env if available
            load_service_env()

            self._worker_thread = threading.Thread(
                target=run_agent_server,
                args=(self._stop_event, self._ready_event),
                name="AgentServerWorker",
                daemon=True
            )
            self._worker_thread.start()
            logger.info("Worker thread started for Uvicorn.")

            # Wait briefly for HTTP server to confirm port 9000 is listening
            if self._ready_event.wait(timeout=10.0):
                logger.info("Uvicorn HTTP server confirmed listening on 127.0.0.1:9000.")
            else:
                logger.warning("Uvicorn HTTP server did not signal ready within 10s; reporting RUNNING to SCM and continuing.")

            if WIN32_AVAILABLE:
                self.ReportServiceStatus(win32service.SERVICE_RUNNING)
            logger.info("Service status reported as RUNNING to SCM.")

            # Monitor service stop event and worker thread liveness
            if WIN32_AVAILABLE:
                while True:
                    rc = win32event.WaitForSingleObject(self.hWaitStop, 1000)
                    if rc == win32event.WAIT_OBJECT_0:
                        logger.info("Service stop event received; exiting SvcDoRun.")
                        break
                    if self._worker_thread and not self._worker_thread.is_alive():
                        logger.error("AgentServerWorker thread exited unexpectedly.")
                        break
        except Exception as exc:
            logger.error("Fatal exception in SvcDoRun: %s", exc, exc_info=True)
            if WIN32_AVAILABLE:
                self.ReportServiceStatus(
                    win32service.SERVICE_STOPPED,
                    win32ExitCode=win32service.ERROR_SERVICE_SPECIFIC_ERROR,
                    svcExitCode=1
                )
            raise


def standalone_main():
    """Fallback runner for CLI debugging or non-service execution on Windows."""
    logger.info("Running Capture Agent in standalone CLI mode...")
    load_service_env()
    stop_event = threading.Event()
    ready_event = threading.Event()
    try:
        run_agent_server(stop_event, ready_event)
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
        service_class_str = get_service_class_string()
        logger.info("Processing service command line: %s (serviceClassString: %s)", normalized_argv, service_class_str)
        try:
            win32serviceutil.HandleCommandLine(
                SecureMailScopeWindowsService,
                serviceClassString=service_class_str,
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

