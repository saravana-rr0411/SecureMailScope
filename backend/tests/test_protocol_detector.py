import pytest
from scapy.all import Ether, IP, TCP, Raw
from app.capture.protocol_detector import detect_flow_protocol, detect_protocols_from_packets

def test_detect_smtp_with_payload():
    payloads = [
        b"220 mail.example.test ESMTP\r\n",
        b"EHLO client.example.test\r\n",
        b"250-mail.example.test\r\n250-STARTTLS\r\n250 OK\r\n",
        b"STARTTLS\r\n",
        b"220 Ready to start TLS\r\n"
    ]
    result = detect_flow_protocol(
        source_ip="192.168.1.100",
        source_port=49152,
        destination_ip="192.168.1.25",
        destination_port=25,
        payloads=payloads
    )
    assert result["protocol"] == "SMTP"
    assert result["confidence"] == "HIGH"
    assert result["source_ip"] == "192.168.1.100"
    assert result["destination_ip"] == "192.168.1.25"
    assert result["source_port"] == 49152
    assert result["destination_port"] == 25
    
    evidence_types = [e["type"] for e in result["evidence"]]
    assert "port" in evidence_types
    assert "banner" in evidence_types
    assert "payload" in evidence_types
    
    values = [e.get("value") for e in result["evidence"]]
    assert "STARTTLS" in values
    assert "EHLO client.example.test" in values


def test_detect_imap_with_payload():
    payloads = [
        b"* OK [CAPABILITY IMAP4rev1 STARTTLS] IMAP service ready\r\n",
        b"A001 CAPABILITY\r\n",
        b"* CAPABILITY IMAP4rev1 STARTTLS\r\n",
        b"A001 OK CAPABILITY completed\r\n",
        b"A002 STARTTLS\r\n",
        b"A002 OK Begin TLS negotiation now\r\n"
    ]
    result = detect_flow_protocol(
        source_ip="10.0.0.5",
        source_port=54321,
        destination_ip="10.0.0.1",
        destination_port=143,
        payloads=payloads
    )
    assert result["protocol"] == "IMAP"
    assert result["confidence"] == "HIGH"
    values = [e.get("value") for e in result["evidence"]]
    assert any("IMAP4rev1" in str(v) for v in values)
    assert any("A002 STARTTLS" in str(v) for v in values)


def test_detect_pop3_with_payload():
    payloads = [
        b"+OK POP3 server ready <1234@mail.test>\r\n",
        b"CAPA\r\n",
        b"+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n",
        b"STLS\r\n",
        b"+OK Begin TLS negotiation\r\n"
    ]
    result = detect_flow_protocol(
        source_ip="10.0.0.6",
        source_port=55555,
        destination_ip="10.0.0.1",
        destination_port=110,
        payloads=payloads
    )
    assert result["protocol"] == "POP3"
    assert result["confidence"] == "HIGH"
    values = [e.get("value") for e in result["evidence"]]
    assert any("+OK POP3 server ready" in str(v) for v in values)
    assert any("STLS" in str(v) for v in values)


def test_detect_unknown_protocol():
    payloads = [
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello"
    ]
    result = detect_flow_protocol(
        source_ip="192.168.1.50",
        source_port=51234,
        destination_ip="93.184.216.34",
        destination_port=80,
        payloads=payloads
    )
    assert result["protocol"] == "UNKNOWN"
    assert result["confidence"] == "LOW"


def test_port_only_vs_payload_evidence():
    # Flow on SMTP port 25 without any payload
    port_only_result = detect_flow_protocol(
        source_ip="192.168.1.100",
        source_port=49152,
        destination_ip="192.168.1.25",
        destination_port=25,
        payloads=[]
    )
    assert port_only_result["protocol"] == "SMTP"
    assert port_only_result["confidence"] == "MEDIUM"
    assert len(port_only_result["evidence"]) == 1
    assert port_only_result["evidence"][0]["type"] == "port"

    # Non-standard port with SMTP payload (e.g. port 8025)
    payload_on_nonstandard_port = detect_flow_protocol(
        source_ip="192.168.1.100",
        source_port=49152,
        destination_ip="192.168.1.25",
        destination_port=8025,
        payloads=[b"220 mail.custom.test ESMTP\r\n", b"EHLO test\r\n"]
    )
    assert payload_on_nonstandard_port["protocol"] == "SMTP"
    assert payload_on_nonstandard_port["confidence"] == "HIGH"


def test_detect_from_packets_grouping():
    ether = Ether()
    ip_client_to_server = IP(src="192.168.1.10", dst="192.168.1.20")
    ip_server_to_client = IP(src="192.168.1.20", dst="192.168.1.10")
    
    tcp_c2s = TCP(sport=50000, dport=25)
    tcp_s2c = TCP(sport=25, dport=50000)

    p1 = ether / ip_server_to_client / tcp_s2c / Raw(load=b"220 mail.test ESMTP\r\n")
    p2 = ether / ip_client_to_server / tcp_c2s / Raw(load=b"EHLO client\r\n")

    protocols = detect_protocols_from_packets([p1, p2])
    assert len(protocols) == 1
    assert protocols[0]["protocol"] == "SMTP"
    assert protocols[0]["confidence"] == "HIGH"
    assert protocols[0]["destination_port"] == 25
