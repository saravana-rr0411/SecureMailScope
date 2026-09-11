import os
import ssl
import time
import tempfile
import datetime
from pathlib import Path
from typing import List, Tuple

from scapy.all import Ether, IP, TCP, Raw, wrpcap, rdpcap

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_self_signed_certificate(cert_path: str, key_path: str, common_name: str = "mail.example.test"):
    """
    Generates a realistic self-signed X.509 certificate for local synthetic PCAP generation.
    Temporary key material is written to a designated local path and cleaned up after generation.
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope Testing CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now - datetime.timedelta(days=1)
    ).not_valid_after(
        now + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(common_name),
            x509.DNSName(f"smtp.{common_name.split('.', 1)[-1]}")
        ]),
        critical=False,
    ).sign(key, hashes.SHA256())

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def generate_ca_signed_certificate(cert_path: str, key_path: str, common_name: str = "mail.example.test"):
    """
    Generates a realistic CA-signed X.509 certificate for local synthetic PCAP generation.
    Presents a complete valid certificate chain with trusted root and valid leaf.
    """
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope Testing CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureMailScope Test Root CA"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = x509.CertificateBuilder().subject_name(
        ca_name
    ).issuer_name(
        ca_name
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now - datetime.timedelta(days=10)
    ).not_valid_after(
        now + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(ca_key, hashes.SHA256())

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureMailScope Testing CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    server_cert = x509.CertificateBuilder().subject_name(
        server_subject
    ).issuer_name(
        ca_name
    ).public_key(
        server_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now - datetime.timedelta(days=1)
    ).not_valid_after(
        now + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(common_name),
            x509.DNSName(f"smtp.{common_name.split('.', 1)[-1]}")
        ]),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).sign(ca_key, hashes.SHA256())

    with open(key_path, "wb") as f:
        f.write(server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(cert_path, "wb") as f:
        f.write(server_cert.public_bytes(serialization.Encoding.PEM))
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))


def generate_tls_pcap(output_path: str = None) -> str:
    """
    Generates a reproducible offline PCAP containing:
    1. TCP 3-way handshake
    2. Plaintext SMTP STARTTLS negotiation
    3. Genuine TLS 1.2 Handshake (ClientHello, ServerHello, Certificate, ServerKeyExchange, Finished)
       generated directly using standard OpenSSL / Python ssl MemoryBIO
    4. Genuine encrypted ApplicationData records
    5. Clean TCP teardown
    """
    if output_path is None:
        project_root = Path(__file__).resolve().parents[3]
        output_dir = project_root / "dataset"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = str(output_dir / "tls_test_email.pcap")
    else:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    client_ip = "192.168.1.100"
    server_ip = "192.168.1.25"
    client_port = 49152
    server_port = 587  # Submission port with STARTTLS

    client_mac = "02:00:00:00:00:01"
    server_mac = "02:00:00:00:00:02"

    packets = []
    current_time = time.time() - 30

    def add_pkt(src_mac, dst_mac, src_ip, dst_ip, sport, dport, flags, seq, ack, payload=b"", dt=0.02):
        nonlocal current_time
        current_time += dt
        ether = Ether(src=src_mac, dst=dst_mac)
        ip = IP(src=src_ip, dst=dst_ip)
        tcp = TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        pkt = (ether / ip / tcp / Raw(load=payload)) if payload else (ether / ip / tcp)
        pkt.time = current_time
        packets.append(pkt)

    c_seq = 10000
    s_seq = 50000

    # 1. TCP 3-Way Handshake
    add_pkt(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "S", c_seq, 0)
    c_seq += 1

    add_pkt(server_mac, client_mac, server_ip, client_ip, server_port, client_port, "SA", s_seq, c_seq)
    s_seq += 1

    add_pkt(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "A", c_seq, s_seq)

    # 2. SMTP STARTTLS Plaintext Handshake
    banner = b"220 mail.example.test ESMTP Postfix\r\n"
    add_pkt(server_mac, client_mac, server_ip, client_ip, server_port, client_port, "PA", s_seq, c_seq, banner)
    s_seq += len(banner)
    add_pkt(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "A", c_seq, s_seq)

    ehlo = b"EHLO client.example.test\r\n"
    add_pkt(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "PA", c_seq, s_seq, ehlo)
    c_seq += len(ehlo)

    ehlo_resp = b"250-mail.example.test\r\n250-STARTTLS\r\n250 8BITMIME\r\n250 OK\r\n"
    add_pkt(server_mac, client_mac, server_ip, client_ip, server_port, client_port, "PA", s_seq, c_seq, ehlo_resp)
    s_seq += len(ehlo_resp)
    add_pkt(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "A", c_seq, s_seq)

    starttls_cmd = b"STARTTLS\r\n"
    add_pkt(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "PA", c_seq, s_seq, starttls_cmd)
    c_seq += len(starttls_cmd)

    starttls_resp = b"220 2.0.0 Ready to start TLS\r\n"
    add_pkt(server_mac, client_mac, server_ip, client_ip, server_port, client_port, "PA", s_seq, c_seq, starttls_resp)
    s_seq += len(starttls_resp)
    add_pkt(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "A", c_seq, s_seq)

    # 3. Real TLS Handshake via Python MemoryBIO & OpenSSL
    with tempfile.TemporaryDirectory() as td:
        key_file = os.path.join(td, "temp_key.pem")
        cert_file = os.path.join(td, "temp_cert.pem")
        generate_ca_signed_certificate(cert_file, key_file, common_name="mail.example.test")

        # Setup SSL Contexts (configured for TLS 1.2 to present on-wire X.509 Certificate Handshake record)
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        server_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        server_ctx.load_cert_chain(cert_file, key_file)

        client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        client_ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE

        c_in, c_out = ssl.MemoryBIO(), ssl.MemoryBIO()
        s_in, s_out = ssl.MemoryBIO(), ssl.MemoryBIO()

        c_ssl = client_ctx.wrap_bio(c_in, c_out, server_hostname="mail.example.test")
        s_ssl = server_ctx.wrap_bio(s_in, s_out, server_side=True)

        # Step 3a: ClientHello
        try:
            c_ssl.do_handshake()
        except ssl.SSLWantReadError:
            pass
        client_hello_bytes = c_out.read()
        add_pkt(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "PA", c_seq, s_seq, client_hello_bytes)
        c_seq += len(client_hello_bytes)

        # Step 3b: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone
        s_in.write(client_hello_bytes)
        try:
            s_ssl.do_handshake()
        except ssl.SSLWantReadError:
            pass
        server_hello_bytes = s_out.read()
        add_pkt(server_mac, client_mac, server_ip, client_ip, server_port, client_port, "PA", s_seq, c_seq, server_hello_bytes)
        s_seq += len(server_hello_bytes)

        # Step 3c: ClientKeyExchange + ChangeCipherSpec + Finished
        c_in.write(server_hello_bytes)
        try:
            c_ssl.do_handshake()
        except ssl.SSLWantReadError:
            pass
        client_fin_bytes = c_out.read()
        add_pkt(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "PA", c_seq, s_seq, client_fin_bytes)
        c_seq += len(client_fin_bytes)

        # Step 3d: Server ChangeCipherSpec + Finished
        s_in.write(client_fin_bytes)
        try:
            s_ssl.do_handshake()
        except ssl.SSLWantReadError:
            pass
        server_fin_bytes = s_out.read()
        if server_fin_bytes:
            add_pkt(server_mac, client_mac, server_ip, client_ip, server_port, client_port, "PA", s_seq, c_seq, server_fin_bytes)
            s_seq += len(server_fin_bytes)

            c_in.write(server_fin_bytes)
            try:
                c_ssl.do_handshake()
            except ssl.SSLWantReadError:
                pass

        # Step 4: Real Encrypted Application Data
        c_ssl.write(b"EHLO client.example.test\r\n")
        c_app_data = c_out.read()
        add_pkt(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "PA", c_seq, s_seq, c_app_data)
        c_seq += len(c_app_data)

        s_ssl.write(b"250-mail.example.test\r\n250 8BITMIME\r\n250 OK\r\n")
        s_app_data = s_out.read()
        add_pkt(server_mac, client_mac, server_ip, client_ip, server_port, client_port, "PA", s_seq, c_seq, s_app_data)
        s_seq += len(s_app_data)

        # Step 5: TCP teardown
        add_pkt(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "FA", c_seq, s_seq)
        c_seq += 1
        add_pkt(server_mac, client_mac, server_ip, client_ip, server_port, client_port, "FA", s_seq, c_seq)
        s_seq += 1
        add_pkt(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "A", c_seq, s_seq)

    # Write PCAP to file
    wrpcap(output_path, packets)
    print(f"[+] Successfully generated genuine TLS PCAP with {len(packets)} packets at: {output_path}")
    return output_path


if __name__ == "__main__":
    generate_tls_pcap()
