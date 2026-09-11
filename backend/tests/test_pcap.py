import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.capture.generate_tls_test_pcap import generate_tls_pcap
import os

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "SecureMailScope"}

def test_analyze_pcap_unsupported_extension():
    response = client.post(
        "/api/pcap/analyze",
        files={"file": ("test.txt", b"some text content", "text/plain")}
    )
    assert response.status_code == 400
    assert "Unsupported file extension" in response.json()["detail"]

def test_analyze_pcap_empty_file(tmp_path):
    empty_pcap = tmp_path / "empty.pcap"
    empty_pcap.write_bytes(b"")
    
    with open(empty_pcap, "rb") as f:
        response = client.post(
            "/api/pcap/analyze",
            files={"file": ("empty.pcap", f, "application/vnd.tcpdump.pcap")}
        )
    
    assert response.status_code == 400
    assert "PCAP file is empty" in response.json()["detail"]

def test_analyze_pcap_invalid_file(tmp_path):
    invalid_pcap = tmp_path / "invalid.pcap"
    invalid_pcap.write_bytes(b"not a real pcap file content, just some random bytes")
    
    with open(invalid_pcap, "rb") as f:
        response = client.post(
            "/api/pcap/analyze",
            files={"file": ("invalid.pcap", f, "application/vnd.tcpdump.pcap")}
        )
    
    assert response.status_code == 400
    assert "Invalid PCAP file" in response.json()["detail"]

def test_analyze_pcap_valid_file(tmp_path):
    from scapy.all import wrpcap, Ether, IP, TCP, Raw
    
    valid_pcap = tmp_path / "valid.pcap"
    pkt = Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=1234, dport=25)/Raw(load=b"220 mail.test ESMTP\r\n")
    wrpcap(str(valid_pcap), [pkt])
    
    with open(valid_pcap, "rb") as f:
        response = client.post(
            "/api/pcap/analyze",
            files={"file": ("valid.pcap", f, "application/vnd.tcpdump.pcap")}
        )
    
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "valid.pcap"
    assert data["total_packets"] == 1
    assert data["tcp_packets"] == 1
    assert data["udp_packets"] == 0
    assert data["other_packets"] == 0
    assert "192.168.1.1" in data["source_ips"]
    assert "192.168.1.2" in data["destination_ips"]
    assert data["unique_source_ips"] == 1
    assert data["unique_destination_ips"] == 1
    assert "protocols" in data
    assert len(data["protocols"]) == 1
    assert data["protocols"][0]["protocol"] == "SMTP"
    assert data["protocols"][0]["confidence"] == "HIGH"
    assert "sessions" in data
    assert len(data["sessions"]) == 1
    assert data["sessions"][0]["session_id"] == "TCP-001"
    assert data["sessions"][0]["protocol"] == "SMTP"


def test_analyze_tls_pcap(tmp_path):
    tls_pcap_path = tmp_path / "tls_test.pcap"
    generate_tls_pcap(str(tls_pcap_path))

    with open(tls_pcap_path, "rb") as f:
        response = client.post(
            "/api/pcap/analyze",
            files={"file": ("tls_test.pcap", f, "application/vnd.tcpdump.pcap")}
        )

    assert response.status_code == 200
    data = response.json()
    assert data["total_packets"] == 20
    assert len(data["sessions"]) == 1
    session = data["sessions"][0]
    assert session["protocol"] == "SMTP"
    assert session["starttls"]["status"] == "SECURE_TRANSITION"
    assert session["starttls"]["tls_transition_observed"] is True


def test_demo_endpoint_secure_tls():
    """Verify POST /api/pcap/demo/secure_tls returns 200 and expected forensic results."""
    response = client.post("/api/pcap/demo/secure_tls")
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "tls_test_email.pcap"
    assert len(data["sessions"]) >= 1
    s0 = data["sessions"][0]
    assert s0["protocol"] == "SMTP"
    assert s0["tls"]["version"] == "TLSv1.2"
    assert "ECDHE" in s0["tls"]["key_exchange"]
    assert s0["posture"]["score"] == 100
    assert s0["posture"]["risk_level"] == "LOW_RISK"
    assert s0["ai_analysis"]["prediction"] == "NORMAL"


def test_demo_endpoint_incomplete_starttls():
    """Verify POST /api/pcap/demo/incomplete_starttls returns 200 and expected forensic risk results."""
    response = client.post("/api/pcap/demo/incomplete_starttls")
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "test_email.pcap"
    assert len(data["sessions"]) >= 1
    s0 = data["sessions"][0]
    assert s0["protocol"] == "SMTP"
    assert s0["starttls"]["status"] == "INCOMPLETE"
    assert s0["posture"]["score"] == 75
    assert s0["posture"]["risk_level"] == "MODERATE_RISK"
    assert s0["ai_analysis"]["prediction"] == "ANOMALOUS"


def test_demo_endpoint_invalid_name():
    """Verify POST /api/pcap/demo/invalid_demo returns 404 with a helpful error."""
    response = client.post("/api/pcap/demo/invalid_demo_name")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()
 