import os
import signal
import time
import subprocess
import logging
from pathlib import Path
from typing import Optional, List

from capture_agent.config import (
    get_tcpdump_binary,
    detect_loopback_interface,
    check_capture_capabilities,
    get_current_os
)

logger = logging.getLogger("capture_agent.packet_capturer")


class PacketCapturer:
    """
    Manages live tcpdump packet capture targeting ONLY the controlled mail test port.
    Never sniffs arbitrary interfaces or user traffic.
    """

    def __init__(
        self,
        output_pcap_path: str,
        port: int = 2525,
        interface: Optional[str] = None
    ):
        self.output_pcap_path = output_pcap_path
        self.port = port
        self.interface = interface or detect_loopback_interface()
        self._process: Optional[subprocess.Popen] = None
        self._is_capturing = False

    def start(self, settle_delay: float = 0.2):
        """
        Starts the tcpdump capture process with strict BPF filter.
        Raises PermissionError or RuntimeError if capture cannot be initiated.
        """
        tcpdump_bin = get_tcpdump_binary()
        if not tcpdump_bin:
            raise RuntimeError("tcpdump binary not found on the system.")

        # Ensure output directory exists
        out_dir = Path(self.output_pcap_path).parent
        out_dir.mkdir(parents=True, exist_ok=True)

        # Remove existing file if present
        if os.path.exists(self.output_pcap_path):
            try:
                os.remove(self.output_pcap_path)
            except Exception:
                pass

        # Strict BPF filter targeting only our local test port and host
        bpf_filter = f"tcp and port {self.port} and host 127.0.0.1"

        can_cap, cap_diag, requires_sudo = check_capture_capabilities(self.interface)
        use_sudo = requires_sudo or os.environ.get("CAPTURE_USE_SUDO", "0").lower() in ("1", "true", "yes")

        # Construct tcpdump argument list
        # --immediate-mode: delivers packets to userland immediately as they arrive (bypasses BPF buffering)
        # -i <interface>: capture on specific interface only
        # -s 0: full packet snapshot length (no truncation)
        # -U: packet-buffered output flush to file
        # -w <file>: write raw PCAP
        cmd: List[str] = []
        if use_sudo:
            cmd.extend(["sudo", "-n"])
        cmd.extend([
            tcpdump_bin,
            "--immediate-mode",
            "-i", self.interface,
            "-s", "0",
            "-U",
            "-w", self.output_pcap_path,
            bpf_filter
        ])

        logger.info(f"Starting tcpdump capture on interface '{self.interface}', filter: '{bpf_filter}', sudo: {use_sudo}")

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
        except PermissionError as pe:
            raise PermissionError(
                f"Insufficient system permissions to execute tcpdump on interface '{self.interface}': {pe}"
            )
        except Exception as e:
            raise RuntimeError(f"Failed to launch tcpdump: {e}")

        # Wait for tcpdump to initialize and confirm it is listening
        # tcpdump flushes its initial banner to stderr:
        # e.g., "tcpdump: listening on lo0, link-type NULL (BSD loopback), capture size 262144 bytes"
        startup_lines = []
        start_time = time.time()
        timeout = 5.0
        listening_confirmed = False

        while time.time() - start_time < timeout:
            poll = self._process.poll()
            if poll is not None:
                remaining_err = self._process.stderr.read() if self._process.stderr else ""
                all_err = "\n".join(startup_lines + [remaining_err]).strip()
                if "permission" in all_err.lower() or "bpf" in all_err.lower():
                    diag = (
                        f"Permission denied initializing packet capture on {self.interface} ({all_err}). "
                        "macOS requires root/sudo or access to /dev/bpf*. "
                        "Run: sudo chmod 666 /dev/bpf*"
                    )
                    raise PermissionError(diag)
                raise RuntimeError(f"tcpdump exited prematurely with code {poll}: {all_err}")

            import select
            if self._process.stderr:
                rlist, _, _ = select.select([self._process.stderr], [], [], 0.05)
                if rlist:
                    line = self._process.stderr.readline()
                    if line:
                        startup_lines.append(line.strip())
                        logger.info(f"tcpdump: {line.strip()}")
                        if "listening on" in line.lower():
                            listening_confirmed = True
                            break

        if not listening_confirmed and self._process.poll() is None:
            logger.warning("tcpdump process started but 'listening on' banner was not caught within timeout.")

        time.sleep(settle_delay)
        self._is_capturing = True
        logger.info(f"tcpdump successfully capturing on '{self.interface}' (PID: {self._process.pid})")

    def stop(self, timeout: float = 3.0) -> str:
        """
        Stops the tcpdump process using SIGINT (allowing libpcap to cleanly flush headers and packet records)
        and verifies the resulting PCAP file.
        """
        if not self._process or not self._is_capturing:
            logger.warning("PacketCapturer stop() called but capture was not running.")
            return self.output_pcap_path

        logger.info(f"Stopping tcpdump (PID: {self._process.pid})...")
        stderr_output = ""

        try:
            # SIGINT tells tcpdump to stop capturing and flush PCAP header & packet records cleanly
            self._process.send_signal(signal.SIGINT)
            try:
                stdout_data, stderr_data = self._process.communicate(timeout=timeout)
                stderr_output = stderr_data.strip() if stderr_data else ""
            except subprocess.TimeoutExpired:
                logger.warning("tcpdump did not exit on SIGINT within timeout; sending SIGTERM...")
                self._process.terminate()
                stdout_data, stderr_data = self._process.communicate(timeout=1.5)
                stderr_output = stderr_data.strip() if stderr_data else ""
        except Exception as e:
            logger.error(f"Error terminating tcpdump process: {e}")
            try:
                self._process.kill()
                self._process.communicate(timeout=1.0)
            except Exception:
                pass
        finally:
            self._is_capturing = False

        if stderr_output:
            logger.info(f"tcpdump exit statistics:\n{stderr_output}")

        # Small settle delay for filesystem buffer flush
        time.sleep(0.1)

        # Validate that the PCAP file was generated and is non-empty
        if not os.path.exists(self.output_pcap_path):
            raise RuntimeError(f"Capture finished but PCAP file '{self.output_pcap_path}' was not created.")

        file_size = os.path.getsize(self.output_pcap_path)
        logger.info(f"PCAP capture file successfully created: {self.output_pcap_path} ({file_size} bytes)")

        if file_size < 24:
            raise RuntimeError(
                f"PCAP file is too small ({file_size} bytes). Minimum valid libpcap header is 24 bytes."
            )

        return self.output_pcap_path

    @property
    def is_running(self) -> bool:
        return self._is_capturing and self._process is not None and self._process.poll() is None
