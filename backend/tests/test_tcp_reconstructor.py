import pytest
import time
from scapy.all import Ether, IP, TCP, Raw
from app.reconstruction.tcp_reconstructor import reconstruct_tcp_sessions

def create_tcp_packet(src_ip, dst_ip, sport, dport, flags, payload=b"", pkt_time=None):
    ether = Ether()
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=sport, dport=dport, flags=flags)
    pkt = (ether / ip / tcp / Raw(load=payload)) if payload else (ether / ip / tcp)
    pkt.time = pkt_time if pkt_time is not None else time.time()
    return pkt


def test_single_bidirectional_session():
    t0 = 1000.0
    pkts = [
        # SYN
        create_tcp_packet("192.168.1.50", "192.168.1.10", 40000, 25, "S", pkt_time=t0),
        # SYN-ACK
        create_tcp_packet("192.168.1.10", "192.168.1.50", 25, 40000, "SA", pkt_time=t0 + 0.01),
        # ACK
        create_tcp_packet("192.168.1.50", "192.168.1.10", 40000, 25, "A", pkt_time=t0 + 0.02),
        # Server Banner
        create_tcp_packet("192.168.1.10", "192.168.1.50", 25, 40000, "PA", payload=b"220 mail.test ESMTP\r\n", pkt_time=t0 + 0.03),
        # Client EHLO
        create_tcp_packet("192.168.1.50", "192.168.1.10", 40000, 25, "PA", payload=b"EHLO client.test\r\n", pkt_time=t0 + 0.04),
    ]

    sessions = reconstruct_tcp_sessions(pkts)
    assert len(sessions) == 1
    s = sessions[0]
    assert s["session_id"] == "TCP-001"
    assert s["protocol"] == "SMTP"
    assert s["source_ip"] == "192.168.1.50"
    assert s["destination_ip"] == "192.168.1.10"
    assert s["source_port"] == 40000
    assert s["destination_port"] == 25
    assert s["packet_count"] == 5
    assert s["client_to_server_packets"] == 3
    assert s["server_to_client_packets"] == 2
    assert s["client_to_server_bytes"] == len(b"EHLO client.test\r\n")
    assert s["server_to_client_bytes"] == len(b"220 mail.test ESMTP\r\n")
    assert "EHLO client.test" in s["client_payload"]
    assert "220 mail.test ESMTP" in s["server_payload"]
    assert s["start_time"] == t0
    assert s["end_time"] == t0 + 0.04
    assert s["duration_seconds"] == pytest.approx(0.04)


def test_multiple_sessions():
    t0 = 2000.0
    # Session 1: SMTP
    s1_pkts = [
        create_tcp_packet("10.0.0.2", "10.0.0.1", 50001, 25, "S", pkt_time=t0),
        create_tcp_packet("10.0.0.1", "10.0.0.2", 25, 50001, "SA", pkt_time=t0 + 0.01),
    ]
    # Session 2: IMAP
    s2_pkts = [
        create_tcp_packet("10.0.0.3", "10.0.0.1", 50002, 143, "S", pkt_time=t0 + 0.10),
        create_tcp_packet("10.0.0.1", "10.0.0.3", 143, 50002, "SA", pkt_time=t0 + 0.11),
    ]

    all_pkts = s1_pkts + s2_pkts
    sessions = reconstruct_tcp_sessions(all_pkts)
    assert len(sessions) == 2
    assert sessions[0]["session_id"] == "TCP-001"
    assert sessions[0]["source_port"] == 50001
    assert sessions[0]["destination_port"] == 25
    assert sessions[0]["protocol"] == "SMTP"

    assert sessions[1]["session_id"] == "TCP-002"
    assert sessions[1]["source_port"] == 50002
    assert sessions[1]["destination_port"] == 143
    assert sessions[1]["protocol"] == "IMAP"


def test_reverse_direction_packets_grouped_together():
    t0 = 3000.0
    # Packets arriving in mixed forward/reverse sequence
    pkts = [
        create_tcp_packet("192.168.1.200", "192.168.1.1", 45000, 110, "PA", payload=b"USER testuser\r\n", pkt_time=t0),
        create_tcp_packet("192.168.1.1", "192.168.1.200", 110, 45000, "PA", payload=b"+OK Password required\r\n", pkt_time=t0 + 0.02),
        create_tcp_packet("192.168.1.200", "192.168.1.1", 45000, 110, "PA", payload=b"PASS secret\r\n", pkt_time=t0 + 0.04),
        create_tcp_packet("192.168.1.1", "192.168.1.200", 110, 45000, "PA", payload=b"+OK Logged in\r\n", pkt_time=t0 + 0.06),
    ]

    sessions = reconstruct_tcp_sessions(pkts)
    assert len(sessions) == 1
    s = sessions[0]
    assert s["protocol"] == "POP3"
    assert s["source_ip"] == "192.168.1.200"
    assert s["destination_ip"] == "192.168.1.1"
    assert s["packet_count"] == 4
    assert s["client_to_server_packets"] == 2
    assert s["server_to_client_packets"] == 2


def test_incomplete_session_graceful_handling():
    # Only a single mid-stream packet without SYN or ACK handshake
    t0 = 4000.0
    pkt = create_tcp_packet("172.16.0.5", "172.16.0.10", 33333, 8080, "PA", payload=b"Random non-email data", pkt_time=t0)
    sessions = reconstruct_tcp_sessions([pkt])
    assert len(sessions) == 1
    s = sessions[0]
    assert s["session_id"] == "TCP-001"
    assert s["protocol"] == "UNKNOWN"
    assert s["packet_count"] == 1
    assert s["client_to_server_packets"] == 1
    assert s["server_to_client_packets"] == 0
    assert s["client_to_server_bytes"] == len(b"Random non-email data")
    assert s["server_to_client_bytes"] == 0
    assert s["duration_seconds"] == 0.0


def test_payload_extraction_and_retransmissions():
    t0 = 5000.0
    # Include repeated/retransmitted packet
    pkts = [
        create_tcp_packet("10.1.1.1", "10.2.2.2", 60000, 25, "PA", payload=b"STARTTLS\r\n", pkt_time=t0),
        create_tcp_packet("10.1.1.1", "10.2.2.2", 60000, 25, "PA", payload=b"STARTTLS\r\n", pkt_time=t0 + 0.05), # Retransmit
        create_tcp_packet("10.2.2.2", "10.1.1.1", 25, 60000, "PA", payload=b"220 Ready\r\n", pkt_time=t0 + 0.10),
    ]
    sessions = reconstruct_tcp_sessions(pkts)
    assert len(sessions) == 1
    s = sessions[0]
    assert s["packet_count"] == 3
    assert s["client_to_server_packets"] == 2
    assert s["server_to_client_packets"] == 1
    assert s["client_to_server_bytes"] == len(b"STARTTLS\r\n") * 2
    assert s["server_to_client_bytes"] == len(b"220 Ready\r\n")
    assert "STARTTLS" in s["client_payload"]
    assert "220 Ready" in s["server_payload"]


def test_ipv6_smtp_session_reconstruction():
    """Verify bidirectional IPv6 SMTP session reconstruction with STARTTLS."""
    from scapy.all import IPv6
    t0 = 6000.0
    client_ipv6 = "2001:db8:85a3::8a2e:370:7334"
    server_ipv6 = "2607:f8b0:4004:800::206d"

    def create_tcp6_packet(src_ip, dst_ip, sport, dport, flags, payload=b"", pkt_time=None):
        ether = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        ip6 = IPv6(src=src_ip, dst=dst_ip)
        tcp = TCP(sport=sport, dport=dport, flags=flags)
        pkt = (ether / ip6 / tcp / Raw(load=payload)) if payload else (ether / ip6 / tcp)
        pkt.time = pkt_time if pkt_time is not None else time.time()
        return pkt

    pkts = [
        # SYN from client to Gmail SMTP port 587
        create_tcp6_packet(client_ipv6, server_ipv6, 54321, 587, "S", pkt_time=t0),
        # SYN-ACK from Gmail SMTP
        create_tcp6_packet(server_ipv6, client_ipv6, 587, 54321, "SA", pkt_time=t0 + 0.01),
        # ACK from client
        create_tcp6_packet(client_ipv6, server_ipv6, 54321, 587, "A", pkt_time=t0 + 0.02),
        # Server banner: 220 smtp.gmail.com ESMTP
        create_tcp6_packet(server_ipv6, client_ipv6, 587, 54321, "PA", payload=b"220 smtp.gmail.com ESMTP ready\r\n", pkt_time=t0 + 0.03),
        # Client EHLO
        create_tcp6_packet(client_ipv6, server_ipv6, 54321, 587, "PA", payload=b"EHLO [2001:db8:85a3::8a2e:370:7334]\r\n", pkt_time=t0 + 0.04),
    ]

    sessions = reconstruct_tcp_sessions(pkts)
    assert len(sessions) == 1
    s = sessions[0]
    assert s["protocol"] == "SMTP"
    assert s["submission_type"] == "SMTP STARTTLS"
    assert s["source_ip"] == client_ipv6
    assert s["destination_ip"] == server_ipv6
    assert s["source_port"] == 54321
    assert s["destination_port"] == 587
    assert s["packet_count"] == 5
    assert "smtp.gmail.com" in s["server_payload"]
    assert "EHLO" in s["client_payload"]
