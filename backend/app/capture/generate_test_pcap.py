import os
import time
from pathlib import Path
from scapy.all import Ether, IP, TCP, Raw, wrpcap

def generate_smtp_pcap(output_path: str = None) -> str:
    """
    Generates a synthetic offline PCAP file containing Ethernet/IP/TCP packets
    representing a standard SMTP session with STARTTLS advertisement and negotiation.
    
    Note: This is synthetic test traffic for PCAP ingestion and protocol detection testing.
    It does not contain real TLS negotiation or encrypted messages.
    """
    if output_path is None:
        # Default to dataset/test_email.pcap at project root
        project_root = Path(__file__).resolve().parents[3]
        output_dir = project_root / "dataset"
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = str(output_dir / "test_email.pcap")
    else:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    client_ip = "192.168.1.100"
    server_ip = "192.168.1.25"
    client_port = 49152
    server_port = 25  # Standard SMTP port

    client_mac = "02:00:00:00:00:01"
    server_mac = "02:00:00:00:00:02"

    packets = []
    current_time = time.time() - 60  # 1 minute ago

    def add_packet(src_mac, dst_mac, src_ip, dst_ip, sport, dport, flags, seq, ack, payload=b"", dt=0.05):
        nonlocal current_time
        current_time += dt
        ether = Ether(src=src_mac, dst=dst_mac)
        ip = IP(src=src_ip, dst=dst_ip)
        tcp = TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        
        if payload:
            pkt = ether / ip / tcp / Raw(load=payload)
        else:
            pkt = ether / ip / tcp
        
        pkt.time = current_time
        packets.append(pkt)

    c_seq = 10000
    s_seq = 50000

    # 1. TCP 3-Way Handshake
    # SYN (Client -> Server)
    add_packet(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "S", c_seq, 0)
    c_seq += 1

    # SYN-ACK (Server -> Client)
    add_packet(server_mac, client_mac, server_ip, client_ip, server_port, client_port, "SA", s_seq, c_seq)
    s_seq += 1

    # ACK (Client -> Server)
    add_packet(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "A", c_seq, s_seq)

    # 2. Server Greeting (Banner)
    banner_payload = b"220 mail.example.test ESMTP\r\n"
    add_packet(server_mac, client_mac, server_ip, client_ip, server_port, client_port, "PA", s_seq, c_seq, banner_payload)
    s_seq += len(banner_payload)

    # Client ACK
    add_packet(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "A", c_seq, s_seq)

    # 3. Client EHLO
    ehlo_payload = b"EHLO client.example.test\r\n"
    add_packet(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "PA", c_seq, s_seq, ehlo_payload)
    c_seq += len(ehlo_payload)

    # Server EHLO Response with STARTTLS
    ehlo_resp_payload = b"250-mail.example.test\r\n250-STARTTLS\r\n250 8BITMIME\r\n250 OK\r\n"
    add_packet(server_mac, client_mac, server_ip, client_ip, server_port, client_port, "PA", s_seq, c_seq, ehlo_resp_payload)
    s_seq += len(ehlo_resp_payload)

    # Client ACK
    add_packet(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "A", c_seq, s_seq)

    # 4. Client requests STARTTLS
    starttls_payload = b"STARTTLS\r\n"
    add_packet(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "PA", c_seq, s_seq, starttls_payload)
    c_seq += len(starttls_payload)

    # Server confirms STARTTLS
    starttls_resp_payload = b"220 Ready to start TLS\r\n"
    add_packet(server_mac, client_mac, server_ip, client_ip, server_port, client_port, "PA", s_seq, c_seq, starttls_resp_payload)
    s_seq += len(starttls_resp_payload)

    # Client ACK
    add_packet(client_mac, server_mac, client_ip, server_ip, client_port, server_port, "A", c_seq, s_seq)

    # Write packets to PCAP file
    wrpcap(output_path, packets)
    print(f"[+] Successfully generated synthetic SMTP PCAP with {len(packets)} packets at: {output_path}")
    return output_path

if __name__ == "__main__":
    generate_smtp_pcap()
