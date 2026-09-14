import os
import time
import logging
import threading
from pathlib import Path
from typing import Optional, List

logger = logging.getLogger("capture_agent.windows_sniffer")

# Guard scapy import so it loads gracefully and provides actionable error if missing
try:
    from scapy.all import sniff, PcapWriter, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class WindowsPacketSniffer:
    """
    Windows-native packet sniffer using Scapy and Npcap.
    Features:
    - Genuine packet sniffing only (no synthetic traffic).
    - Strict BPF filtering (e.g. 'tcp and port 587' or 'tcp and port 2525').
    - Standard libpcap binary output via PcapWriter.
    - Clean thread-based execution with threading.Event() stopping mechanism.
    - Avoids POSIX select.select() pipe issues and Windows signal.SIGINT limitations.
    - Flushes PCAP headers and packets cleanly upon stop().
    """

    def __init__(
        self,
        output_pcap_path: str,
        bpf_filter: str,
        interface: Optional[str] = None,
    ):
        self.output_pcap_path = output_pcap_path
        self.bpf_filter = bpf_filter
        self.interface = interface
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._pcap_writer: Optional[PcapWriter] = None
        self._packet_count = 0
        self._ipv4_count = 0
        self._ipv6_count = 0
        self._port_587_count = 0
        self._port_465_count = 0
        self._is_capturing = False
        self._error: Optional[Exception] = None

    def _packet_callback(self, packet):
        """Callback invoked by scapy.sniff() for each captured packet."""
        try:
            if self._pcap_writer:
                self._pcap_writer.write(packet)
                self._packet_count += 1

                # Safe non-sensitive metrics for diagnostic logging
                has_ip = packet.haslayer("IP")
                has_ipv6 = packet.haslayer("IPv6")
                if has_ip:
                    self._ipv4_count += 1
                elif has_ipv6:
                    self._ipv6_count += 1

                if packet.haslayer("TCP"):
                    tcp_layer = packet.getlayer("TCP")
                    sport = getattr(tcp_layer, "sport", 0)
                    dport = getattr(tcp_layer, "dport", 0)
                    if 587 in (sport, dport):
                        self._port_587_count += 1
                    elif 465 in (sport, dport):
                        self._port_465_count += 1
        except Exception as e:
            logger.warning(f"Error writing packet to PCAP on Windows: {e}")

    def _sniff_worker(self):
        """Worker thread executing continuous scapy.sniff with Npcap."""
        try:
            # Prepare directory and PCAP writer
            out_dir = Path(self.output_pcap_path).parent
            out_dir.mkdir(parents=True, exist_ok=True)
            self._pcap_writer = PcapWriter(
                self.output_pcap_path,
                append=True,
                sync=True
            )

            sniff_kwargs = {
                "filter": self.bpf_filter,
                "prn": self._packet_callback,
                "stop_filter": lambda _: self._stop_event.is_set(),
                "store": False,
            }

            if self.interface:
                try:
                    from scapy.interfaces import resolve_iface
                    resolved_iface = resolve_iface(self.interface)
                    sniff_kwargs["iface"] = resolved_iface
                except Exception:
                    sniff_kwargs["iface"] = self.interface

            logger.info(
                f"Windows sniffer active on iface '{self.interface}', "
                f"filter '{self.bpf_filter}', output '{self.output_pcap_path}'"
            )

            # Use AsyncSniffer to maintain persistent Npcap handle without packet drop,
            # and cleanly stop as soon as stop_event is signaled.
            from scapy.sendrecv import AsyncSniffer
            sniffer = AsyncSniffer(**sniff_kwargs)
            sniffer.start()

            while not self._stop_event.is_set():
                time.sleep(0.05)

            if sniffer.running:
                sniffer.stop()

            logger.info(
                f"Windows sniffer finished capture session. Stats: total={self._packet_count}, "
                f"ipv4={self._ipv4_count}, ipv6={self._ipv6_count}, "
                f"port587={self._port_587_count}, port465={self._port_465_count}"
            )

        except Exception as e:
            logger.error(f"Windows sniffer worker encountered exception: {e}", exc_info=True)
            self._error = e
        finally:
            if self._pcap_writer:
                try:
                    self._pcap_writer.flush()
                    self._pcap_writer.close()
                except Exception as close_err:
                    logger.warning(f"Error closing PCAP writer: {close_err}")
                self._pcap_writer = None

    def start(self, settle_delay: float = 0.2):
        """Starts the Windows sniffer thread."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError(
                "Scapy is required for packet capture on Windows. "
                "Install with: pip install scapy>=2.5.0"
            )

        if os.path.exists(self.output_pcap_path):
            try:
                os.remove(self.output_pcap_path)
            except Exception:
                pass

        self._stop_event.clear()
        self._packet_count = 0
        self._error = None

        self._thread = threading.Thread(
            target=self._sniff_worker,
            name="WindowsPacketSnifferThread",
            daemon=True
        )
        self._thread.start()
        self._is_capturing = True

        time.sleep(settle_delay)
        if self._error:
            self._is_capturing = False
            raise RuntimeError(f"Failed to start Windows packet sniffer: {self._error}")

        logger.info(f"Windows sniffer thread started successfully.")

    def stop(self, timeout: float = 3.0) -> str:
        """
        Signals the sniffer thread to stop, waits for thread termination,
        flushes the PCAP file, and validates output.
        """
        if not self._is_capturing and (not self._thread or not self._thread.is_alive()):
            logger.warning("WindowsPacketSniffer stop() called but capture was not active.")
            return self.output_pcap_path

        logger.info("Stopping Windows sniffer...")
        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                logger.warning("Windows sniffer thread did not exit within timeout.")

        self._is_capturing = False

        # Small settle delay for OS filesystem flush
        time.sleep(0.1)

        if not os.path.exists(self.output_pcap_path):
            raise RuntimeError(
                f"Capture finished but PCAP file '{self.output_pcap_path}' was not created."
            )

        file_size = os.path.getsize(self.output_pcap_path)
        logger.info(
            f"Windows PCAP capture complete: {self.output_pcap_path} "
            f"({file_size} bytes, {self._packet_count} packets)"
        )

        if file_size < 24:
            raise RuntimeError(
                f"PCAP file is too small ({file_size} bytes). Minimum valid libpcap header is 24 bytes."
            )

        return self.output_pcap_path

    @property
    def is_running(self) -> bool:
        return self._is_capturing and self._thread is not None and self._thread.is_alive()
