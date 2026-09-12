import os
import ssl
import ipaddress
import tempfile
import datetime
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass
class TestCertMaterial:
    cert_path: str
    key_path: str
    ca_cert_path: Optional[str] = None
    common_name: str = "mail.securemailscope.test"

    def cleanup(self):
        """Removes temporary certificate and key files from disk."""
        for p in [self.cert_path, self.key_path, self.ca_cert_path]:
            if p and os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass


def generate_test_certificate(
    common_name: str = "mail.securemailscope.test",
    validity_days: int = 365,
    key_size: int = 2048
) -> TestCertMaterial:
    """
    Generates a genuine, cryptographically valid X.509 certificate and private key.
    Configured with:
    - RSA 2048-bit key
    - SHA-256 signature
    - KeyUsage (digitalSignature, keyEncipherment)
    - ExtendedKeyUsage (serverAuth)
    - SubjectAlternativeName (DNS and IP)
    - Active validity window
    """
    # 1. Generate authentic RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

    # 2. Build Distinguished Name (DN)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope Network Forensic Lab"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Automated Capture Agent"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    valid_from = now_utc - datetime.timedelta(hours=1)
    valid_to = now_utc + datetime.timedelta(days=validity_days)

    # 3. Subject Alternative Names (DNS & 127.0.0.1 IP)
    san_entries = [
        x509.DNSName(common_name),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ]

    # 4. Construct X.509 certificate with RFC 5280 compliant extensions
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(valid_from)
        .not_valid_after(valid_to)
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
    )

    cert = builder.sign(private_key, hashes.SHA256())

    # 5. Write to temporary PEM files for loading by Python OpenSSL
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_file = tempfile.NamedTemporaryFile(delete=False, prefix="sms_cert_", suffix=".pem")
    cert_file.write(cert_pem)
    cert_file.close()

    key_file = tempfile.NamedTemporaryFile(delete=False, prefix="sms_key_", suffix=".pem")
    key_file.write(key_pem)
    key_file.close()

    return TestCertMaterial(
        cert_path=cert_file.name,
        key_path=key_file.name,
        common_name=common_name
    )
