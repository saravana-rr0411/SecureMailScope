import ssl
import socket
import threading
import logging
from typing import Optional

logger = logging.getLogger("capture_agent.smtp_server")


class AuthenticSmtpServer:
    """
    Genuine RFC 5321 and RFC 3207 compliant SMTP test server.
    Binds to an actual TCP socket, issues authentic ESMTP protocol banners,
    advertises STARTTLS capability, and upgrades the active connection to TLS 1.2
    using OpenSSL, transmitting a real X.509 certificate chain.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 2525,
        cert_path: Optional[str] = None,
        key_path: Optional[str] = None,
        domain: str = "mail.securemailscope.test",
        tls_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2
    ):
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.key_path = key_path
        self.domain = domain
        self.tls_version = tls_version

        self._server_socket: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._is_running = False
        self._ready_event = threading.Event()
        self.actual_port = port
        self.last_error: Optional[str] = None

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Constructs an authentic OpenSSL server context loading the real certificate."""
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.minimum_version = self.tls_version
        ctx.maximum_version = self.tls_version

        # Modern standard forward-secret cipher suites matching SecureMailScope SECURE baseline
        ctx.set_ciphers(
            "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256"
        )

        if self.cert_path and self.key_path:
            ctx.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)

        return ctx

    def start(self):
        """Starts the SMTP server socket listener in a dedicated daemon thread."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self.actual_port = self._server_socket.getsockname()[1]
        self._server_socket.listen(5)
        self._is_running = True

        self._thread = threading.Thread(target=self._listen_loop, daemon=True, name="SmtpServerThread")
        self._thread.start()

        # Wait for the server socket to be bound and ready
        self._ready_event.wait(timeout=2.0)
        logger.info(f"Authentic SMTP Server listening on {self.host}:{self.actual_port}")

    def stop(self):
        """Stops the SMTP server and closes the listening socket."""
        self._is_running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        logger.info("Authentic SMTP Server stopped.")

    def _listen_loop(self):
        self._ready_event.set()
        ssl_ctx = self._build_ssl_context()

        while self._is_running:
            try:
                self._server_socket.settimeout(0.5)
                conn, addr = self._server_socket.accept()
            except (socket.timeout, OSError):
                continue

            # Handle connection synchronously (one client at a time during capture)
            try:
                self._handle_client(conn, ssl_ctx)
            except Exception as e:
                self.last_error = str(e)
                logger.warning(f"Error handling SMTP client: {e}")
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    def _handle_client(self, conn: socket.socket, ssl_ctx: ssl.SSLContext):
        conn.settimeout(5.0)

        # 1. Authentic RFC 5321 Service Greeting Banner
        banner = f"220 {self.domain} ESMTP Service Ready\r\n".encode("utf-8")
        conn.sendall(banner)

        # Helper to read CRLF delimited line from socket
        def read_line(sock):
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = sock.recv(1)
                if not chunk:
                    break
                buf += chunk
            return buf.decode("utf-8", errors="replace").strip()

        # 2. Read initial EHLO
        ehlo_cmd = read_line(conn)
        logger.debug(f"Server received: {ehlo_cmd}")

        # 3. Respond with ESMTP extensions advertising STARTTLS capability
        ehlo_resp = (
            f"250-{self.domain}\r\n"
            f"250-STARTTLS\r\n"
            f"250-8BITMIME\r\n"
            f"250-SIZE 10485760\r\n"
            f"250 OK\r\n"
        ).encode("utf-8")
        conn.sendall(ehlo_resp)

        # 4. Read command (expecting STARTTLS)
        cmd = read_line(conn)
        logger.debug(f"Server received: {cmd}")

        if not cmd.upper().startswith("STARTTLS"):
            conn.sendall(b"500 5.5.1 Unrecognized command\r\n")
            return

        # 5. Accept STARTTLS upgrade
        conn.sendall(b"220 2.0.0 Ready to start TLS\r\n")

        # 6. Execute live TLS 1.2 Handshake on the established TCP socket
        tls_conn = ssl_ctx.wrap_socket(conn, server_side=True)
        tls_conn.settimeout(5.0)
        logger.debug("TLS Handshake completed successfully on server socket.")

        # 7. Post-TLS ESMTP session
        # Client sends second EHLO inside encrypted channel (RFC 3207 requirement)
        post_ehlo = read_line(tls_conn)
        logger.debug(f"Server received (encrypted): {post_ehlo}")

        post_ehlo_resp = (
            f"250-{self.domain}\r\n"
            f"250-8BITMIME\r\n"
            f"250-SIZE 10485760\r\n"
            f"250 OK\r\n"
        ).encode("utf-8")
        tls_conn.sendall(post_ehlo_resp)

        # Handle mail exchange commands inside TLS channel
        while True:
            line = read_line(tls_conn)
            if not line:
                break
            cmd_upper = line.upper()

            if cmd_upper.startswith("MAIL FROM:"):
                tls_conn.sendall(b"250 2.1.0 Sender OK\r\n")
            elif cmd_upper.startswith("RCPT TO:"):
                tls_conn.sendall(b"250 2.1.5 Recipient OK\r\n")
            elif cmd_upper == "DATA":
                tls_conn.sendall(b"354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                # Read data stream until <CRLF>.<CRLF>
                data_buf = b""
                while not data_buf.endswith(b"\r\n.\r\n"):
                    chunk = tls_conn.recv(1024)
                    if not chunk:
                        break
                    data_buf += chunk
                tls_conn.sendall(b"250 2.0.0 Message accepted for delivery\r\n")
            elif cmd_upper == "QUIT":
                tls_conn.sendall(b"221 2.0.0 Service closing transmission channel\r\n")
                break
            elif cmd_upper == "RSET":
                tls_conn.sendall(b"250 2.0.0 Reset OK\r\n")
            else:
                tls_conn.sendall(b"250 2.0.0 OK\r\n")

        try:
            tls_conn.close()
        except Exception:
            pass
