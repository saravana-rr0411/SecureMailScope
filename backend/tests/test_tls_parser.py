import pytest
from app.tls.tls_parser import analyze_tls_session, lookup_cipher_suite

def test_cipher_suite_lookup():
    name, kx, fs = lookup_cipher_suite(0xC030)
    assert name == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    assert kx == "ECDHE"
    assert fs is True

    name_rsa, kx_rsa, fs_rsa = lookup_cipher_suite(0x0035)
    assert name_rsa == "TLS_RSA_WITH_AES_256_CBC_SHA"
    assert kx_rsa == "RSA"
    assert fs_rsa is False

    name_tls13, kx_tls13, fs_tls13 = lookup_cipher_suite(0x1302)
    assert name_tls13 == "TLS_AES_256_GCM_SHA384"
    assert fs_tls13 is True


def test_non_tls_traffic():
    messages = [
        ("c2s", b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        ("s2c", b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello")
    ]
    res = analyze_tls_session(messages)
    assert res["detected"] is False
    assert res["version"] is None
    assert res["cipher_suite"] is None
    assert res["key_exchange"] is None
    assert res["forward_secrecy"] is None
    assert res["certificate_present"] is False
    assert res["encrypted_application_data_observed"] is False


def test_incomplete_client_hello_only():
    # Construct a minimal valid TLS record with ClientHello
    # Record Header: Type 0x16, Ver 0x0301, Len 47
    # Handshake Header: Type 0x01 (ClientHello), Len 43
    # ClientHello: Ver 0x0303, Random (32B), SessionID Len 0, CipherSuites Len 2 (0xC030), Comp Len 1 (0x00), Ext Len 0
    client_hello_body = (
        b"\x03\x03" +  # client_version TLS 1.2
        b"\x01" * 32 +  # random
        b"\x00" +      # session_id_len
        b"\x00\x02\xC0\x30" +  # cipher_suites (len=2, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
        b"\x01\x00"    # compression methods (len=1, 0x00)
    )
    hs_header = b"\x01" + len(client_hello_body).to_bytes(3, "big")
    rec_payload = hs_header + client_hello_body
    rec_header = b"\x16\x03\x01" + len(rec_payload).to_bytes(2, "big")

    messages = [
        ("c2s", rec_header + rec_payload)
    ]
    res = analyze_tls_session(messages)
    assert res["detected"] is True
    assert "ClientHello" in res["handshake_messages"]
    assert res["client_hello"]["client_version"] == "TLSv1.2"
    assert res["client_hello"]["offered_cipher_suites_count"] == 1
    assert res["version"] is None  # Server hasn't selected a version yet
    assert res["cipher_suite"] is None
    assert res["certificate_present"] is False
    assert res["encrypted_application_data_observed"] is False


def test_full_tls_handshake_with_ecdhe_and_forward_secrecy():
    # 1. ClientHello
    ch_body = (
        b"\x03\x03" +
        b"\x01" * 32 +
        b"\x00" +
        b"\x00\x02\xC0\x30" +
        b"\x01\x00"
    )
    ch_rec = b"\x16\x03\x01" + (4 + len(ch_body)).to_bytes(2, "big") + b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body

    # 2. ServerHello (negotiating TLS 1.2, 0xC030)
    sh_body = (
        b"\x03\x03" +  # TLS 1.2
        b"\x02" * 32 +  # server random
        b"\x00" +      # session_id_len
        b"\xC0\x30" +  # selected cipher suite
        b"\x00"        # compression null
    )
    sh_hs = b"\x02" + len(sh_body).to_bytes(3, "big") + sh_body

    # 3. Certificate Handshake
    fake_cert = b"\x30\x82\x01\x00" + b"\xAA" * 256
    cert_body = (
        len(fake_cert + b"\x00\x01\x00").to_bytes(3, "big") +
        len(fake_cert).to_bytes(3, "big") + fake_cert
    )
    cert_hs = b"\x0B" + len(cert_body).to_bytes(3, "big") + cert_body

    # 4. ServerKeyExchange (named_curve secp256r1 = 0x0017)
    ske_body = b"\x03\x00\x17\x41" + b"\xBB" * 65 + b"\x04\x01\x00\x10" + b"\xCC" * 16
    ske_hs = b"\x0C" + len(ske_body).to_bytes(3, "big") + ske_body

    # 5. ServerHelloDone
    shd_hs = b"\x0E\x00\x00\x00"

    server_rec_payload = sh_hs + cert_hs + ske_hs + shd_hs
    server_rec = b"\x16\x03\x03" + len(server_rec_payload).to_bytes(2, "big") + server_rec_payload

    # 6. ChangeCipherSpec & Encrypted ApplicationData
    ccs_rec = b"\x14\x03\x03\x00\x01\x01"
    app_data_rec = b"\x17\x03\x03\x00\x20" + b"\xDD" * 32

    messages = [
        ("c2s", ch_rec),
        ("s2c", server_rec),
        ("s2c", ccs_rec),
        ("c2s", app_data_rec)
    ]

    res = analyze_tls_session(messages)
    assert res["detected"] is True
    assert res["version"] == "TLSv1.2"
    assert res["cipher_suite"] == "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    assert "ECDHE" in res["key_exchange"]
    assert res["forward_secrecy"] is True
    assert res["certificate_present"] is True
    assert res["certificate_der_hex"] is not None
    assert res["encrypted_application_data_observed"] is True
    assert "ClientHello" in res["handshake_messages"]
    assert "ServerHello" in res["handshake_messages"]
    assert "Certificate" in res["handshake_messages"]
    assert "ServerKeyExchange" in res["handshake_messages"]
    assert "ChangeCipherSpec" in res["handshake_messages"]
