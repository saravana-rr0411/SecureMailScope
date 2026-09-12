import pytest
from app.tls.starttls_detector import assess_starttls

def test_smtp_starttls_advertised_accepted_and_transition_observed():
    messages = [
        ("s2c", b"220 mail.example.com ESMTP Postfix\r\n"),
        ("c2s", b"EHLO client.example.com\r\n"),
        ("s2c", b"250-mail.example.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n250 OK\r\n"),
        ("c2s", b"STARTTLS\r\n"),
        ("s2c", b"220 2.0.0 Ready to start TLS\r\n"),
        ("c2s", b"\x16\x03\x03\x00\x45\x01\x00\x00\x41\x03\x03")  # TLS ClientHello record
    ]
    res = assess_starttls("SMTP", messages)
    assert res["upgrade_supported"] is True
    assert res["upgrade_requested"] is True
    assert res["upgrade_accepted"] is True
    assert res["tls_transition_observed"] is True
    assert res["status"] == "SECURE_TRANSITION"
    evidence_types = [e["type"] for e in res["evidence"]]
    assert "capability" in evidence_types
    assert "command" in evidence_types
    assert "response" in evidence_types
    assert "tls_handshake" in evidence_types


def test_smtp_starttls_accepted_but_handshake_not_observable_incomplete():
    # Ends right after 220 Ready to start TLS without TLS handshake
    messages = [
        ("s2c", b"220 mail.example.com ESMTP\r\n"),
        ("c2s", b"EHLO client.example.com\r\n"),
        ("s2c", b"250-mail.example.com\r\n250-STARTTLS\r\n250 OK\r\n"),
        ("c2s", b"STARTTLS\r\n"),
        ("s2c", b"220 Ready to start TLS\r\n")
    ]
    res = assess_starttls("SMTP", messages)
    assert res["upgrade_supported"] is True
    assert res["upgrade_requested"] is True
    assert res["upgrade_accepted"] is True
    assert res["tls_transition_observed"] is False
    assert res["status"] == "INCOMPLETE"


def test_smtp_starttls_not_advertised():
    messages = [
        ("s2c", b"220 mail.example.com ESMTP\r\n"),
        ("c2s", b"EHLO client.example.com\r\n"),
        ("s2c", b"250-mail.example.com\r\n250-PIPELINING\r\n250 8BITMIME\r\n250 OK\r\n"),
        ("c2s", b"MAIL FROM:<sender@test.com>\r\n")
    ]
    res = assess_starttls("SMTP", messages)
    assert res["upgrade_supported"] is False or res["upgrade_supported"] is None
    assert res["upgrade_requested"] is False
    assert res["upgrade_accepted"] is None
    assert res["status"] in ("NOT_USED", "NOT_OBSERVABLE")


def test_smtp_starttls_advertised_but_never_requested():
    messages = [
        ("s2c", b"220 mail.example.com ESMTP\r\n"),
        ("c2s", b"EHLO client.example.com\r\n"),
        ("s2c", b"250-mail.example.com\r\n250-STARTTLS\r\n250 OK\r\n"),
        ("c2s", b"MAIL FROM:<plain@test.com>\r\n"),
        ("s2c", b"250 2.1.0 Ok\r\n")
    ]
    res = assess_starttls("SMTP", messages)
    assert res["upgrade_supported"] is True
    assert res["upgrade_requested"] is False
    assert res["upgrade_accepted"] is None
    assert res["status"] == "NOT_USED"


def test_smtp_starttls_requested_but_rejected():
    messages = [
        ("s2c", b"220 mail.example.com ESMTP\r\n"),
        ("c2s", b"EHLO client.example.com\r\n"),
        ("s2c", b"250-mail.example.com\r\n250-STARTTLS\r\n250 OK\r\n"),
        ("c2s", b"STARTTLS\r\n"),
        ("s2c", b"454 4.7.0 TLS not available due to local problem\r\n")
    ]
    res = assess_starttls("SMTP", messages)
    assert res["upgrade_supported"] is True
    assert res["upgrade_requested"] is True
    assert res["upgrade_accepted"] is False
    assert res["status"] == "NOT_USED"


def test_imap_starttls_advertised_and_accepted():
    messages = [
        ("s2c", b"* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] Dovecot ready.\r\n"),
        ("c2s", b"a001 STARTTLS\r\n"),
        ("s2c", b"a001 OK Begin TLS negotiation now.\r\n"),
        ("c2s", b"\x16\x03\x03\x00\x50\x01\x00\x00\x4c\x03\x03")
    ]
    res = assess_starttls("IMAP", messages)
    assert res["upgrade_supported"] is True
    assert res["upgrade_requested"] is True
    assert res["upgrade_accepted"] is True
    assert res["tls_transition_observed"] is True
    assert res["status"] == "SECURE_TRANSITION"


def test_pop3_stls_advertised_and_accepted():
    messages = [
        ("s2c", b"+OK POP3 server ready\r\n"),
        ("c2s", b"CAPA\r\n"),
        ("s2c", b"+OK Capability list follows\r\nSTLS\r\nUSER\r\n.\r\n"),
        ("c2s", b"STLS\r\n"),
        ("s2c", b"+OK Begin TLS negotiation\r\n"),
        ("c2s", b"\x16\x03\x03\x00\x50\x01\x00\x00\x4c\x03\x03")
    ]
    res = assess_starttls("POP3", messages)
    assert res["upgrade_supported"] is True
    assert res["upgrade_requested"] is True
    assert res["upgrade_accepted"] is True
    assert res["tls_transition_observed"] is True
    assert res["status"] == "SECURE_TRANSITION"


def test_unsupported_protocol_starttls():
    messages = [
        ("c2s", b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n")
    ]
    res = assess_starttls("UNKNOWN", messages)
    assert res["status"] == "NOT_OBSERVABLE"
    assert res["upgrade_supported"] is None


def test_assess_starttls_port_465_implicit_tls():
    """Verify assess_starttls identifies port 465 as implicit TLS."""
    messages = [
        ("c2s", b"\x16\x03\x03\x00\x50\x01\x00\x00\x4c\x03\x03"),
        ("s2c", b"\x16\x03\x03\x00\x50\x02\x00\x00\x4c\x03\x03")
    ]
    res = assess_starttls("SMTP", messages, port=465)
    assert res["status"] == "DIRECT_TLS"
    assert res["transport_mode"] == "IMPLICIT_TLS"
    assert res["submission_type"] == "implicit TLS SMTP"
    assert res["tls_transition_observed"] is True


def test_assess_starttls_port_587_starttls():
    """Verify assess_starttls identifies port 587 as explicit STARTTLS."""
    messages = [
        ("s2c", b"220 mail.example.com ESMTP\r\n"),
        ("c2s", b"EHLO client.example.com\r\n"),
        ("s2c", b"250-mail.example.com\r\n250-STARTTLS\r\n250 OK\r\n"),
        ("c2s", b"STARTTLS\r\n"),
        ("s2c", b"220 Ready to start TLS\r\n"),
        ("c2s", b"\x16\x03\x03\x00\x45\x01\x00\x00\x41\x03\x03")
    ]
    res = assess_starttls("SMTP", messages, port=587)
    assert res["status"] == "SECURE_TRANSITION"
    assert res["transport_mode"] == "STARTTLS"
    assert res["submission_type"] == "SMTP STARTTLS"
