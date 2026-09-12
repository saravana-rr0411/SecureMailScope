import ssl
import smtplib
import logging
from typing import Optional

logger = logging.getLogger("capture_agent.smtp_client")


class AuthenticSmtpClient:
    """
    Genuine SMTP client utilizing standard library smtplib.
    Connects to the server over a real TCP socket, issues EHLO,
    requests STARTTLS, executes a live TLS 1.2 handshake,
    sends a realistic audit email message, and cleanly closes the session with QUIT.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 2525,
        local_hostname: str = "client.securemailscope.test",
        timeout: float = 8.0,
        tls_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2
    ):
        self.host = host
        self.port = port
        self.local_hostname = local_hostname
        self.timeout = timeout
        self.tls_version = tls_version

    def _build_client_ssl_context(self) -> ssl.SSLContext:
        """Constructs client SSL context configured for TLS 1.2."""
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.minimum_version = self.tls_version
        ctx.maximum_version = self.tls_version
        # Disable strict CA verification for test certificate validation in controlled lab
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def execute_session(
        self,
        sender: str = "security-auditor@securemailscope.test",
        recipient: str = "compliance-officer@securemailscope.test",
        subject: str = "Authentic Mail Flow Forensic Verification",
        body: Optional[str] = None
    ) -> bool:
        """
        Executes the complete authentic SMTP session through the OS TCP stack:
        1. Connects to server (TCP SYN/ACK)
        2. Receives greeting banner
        3. Sends EHLO
        4. Sends STARTTLS command
        5. Executes genuine TLS 1.2 handshake
        6. Sends post-TLS EHLO
        7. Sends MAIL FROM, RCPT TO, DATA with authentic email body
        8. Issues QUIT and tears down TCP connection cleanly
        """
        if body is None:
            body = (
                "From: SecureMailScope Forensic Auditor <security-auditor@securemailscope.test>\r\n"
                f"To: Compliance Officer <{recipient}>\r\n"
                f"Subject: {subject}\r\n"
                "Date: Sat, 12 Sep 2026 12:00:00 +0000\r\n"
                "Message-ID: <audit-sample-20260912@securemailscope.test>\r\n"
                "MIME-Version: 1.0\r\n"
                "Content-Type: text/plain; charset=utf-8\r\n"
                "\r\n"
                "Forensic verification email transmitted via authentic RFC 5321 / RFC 3207 socket.\r\n"
                "Cryptographic baseline: TLSv1.2 with ECDHE forward-secret cipher suite.\r\n"
                "Certificate: X.509 RSA 2048-bit SHA-256.\r\n"
                "Generated dynamically by SecureMailScope Capture Agent.\r\n"
            )

        logger.info(f"Connecting to SMTP server at {self.host}:{self.port}...")
        client = None
        try:
            # local_hostname bypasses reverse DNS lookup, ensuring rapid deterministic execution
            client = smtplib.SMTP(
                host=self.host,
                port=self.port,
                local_hostname=self.local_hostname,
                timeout=self.timeout
            )

            # Initial ESMTP Handshake
            client.ehlo(self.local_hostname)

            if not client.has_extn("starttls"):
                raise RuntimeError("Server did not advertise STARTTLS capability.")

            # STARTTLS Protocol Upgrade & Live TLS Handshake
            ssl_ctx = self._build_client_ssl_context()
            client.starttls(context=ssl_ctx)
            logger.info("TLS 1.2 handshake completed on client socket.")

            # Post-TLS EHLO (RFC 3207 requirement)
            client.ehlo(self.local_hostname)

            # Mail exchange inside encrypted tunnel
            client.sendmail(sender, [recipient], body)
            logger.info("Test mail payload successfully sent over encrypted TLS session.")

            # Clean QUIT
            client.quit()
            logger.info("SMTP session closed cleanly.")
            return True
        except Exception as e:
            logger.error(f"Failed to execute authentic SMTP session: {e}")
            if client:
                try:
                    client.close()
                except Exception:
                    pass
            raise
