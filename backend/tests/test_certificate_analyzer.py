import pytest
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.certificate.certificate_analyzer import analyze_x509_certificates


def generate_test_cert(
    key_size=2048,
    not_valid_before_offset=datetime.timedelta(days=-30),
    not_valid_after_offset=datetime.timedelta(days=365),
    hash_algo=hashes.SHA256(),
    common_name="mail.example.com",
    san_list=None,
    issuer_name=None
) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name)
    ])
    issuer = subject if issuer_name is None else x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now + not_valid_before_offset
    ).not_valid_after(
        now + not_valid_after_offset
    )

    if san_list:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san) for san in san_list]),
            critical=False
        )

    cert = builder.sign(key, hash_algo)
    return cert.public_bytes(serialization.Encoding.DER)


def test_missing_certificate():
    res = analyze_x509_certificates([], sni="mail.example.com")
    assert res["certificate_present"] is False
    assert res["expiration_status"] == "NOT_OBSERVABLE"
    assert res["days_until_expiry"] is None
    assert res["findings"] == []


def test_incomplete_or_invalid_cert_bytes():
    res = analyze_x509_certificates([b"random_invalid_bytes"], sni="mail.example.com")
    assert res["certificate_present"] is False
    assert len(res["findings"]) == 1
    assert res["findings"][0]["finding"] == "MALFORMED_CERTIFICATE_DATA"


def test_valid_certificate_with_hostname_match():
    der = generate_test_cert(
        key_size=2048,
        common_name="mail.example.com",
        san_list=["mail.example.com", "smtp.example.com"]
    )
    res = analyze_x509_certificates([der], sni="mail.example.com")
    assert res["certificate_present"] is True
    assert res["expiration_status"] == "VALID"
    assert res["days_until_expiry"] > 30
    assert res["public_key_algorithm"] == "RSA"
    assert res["public_key_length"] == 2048
    assert res["self_signed"] is True
    assert res["hostname_match"] is True
    assert "mail.example.com" in res["subject_alternative_names"]
    assert res["findings"] == []


def test_expired_certificate():
    der = generate_test_cert(
        not_valid_before_offset=datetime.timedelta(days=-60),
        not_valid_after_offset=datetime.timedelta(days=-1)
    )
    res = analyze_x509_certificates([der], sni="mail.example.com")
    assert res["expiration_status"] == "EXPIRED"
    assert res["days_until_expiry"] < 0
    assert any(f["finding"] == "EXPIRED_CERTIFICATE" for f in res["findings"])


def test_not_yet_valid_certificate():
    der = generate_test_cert(
        not_valid_before_offset=datetime.timedelta(days=10),
        not_valid_after_offset=datetime.timedelta(days=365)
    )
    res = analyze_x509_certificates([der], sni="mail.example.com")
    assert res["expiration_status"] == "NOT_YET_VALID"
    assert any(f["finding"] == "NOT_YET_VALID_CERTIFICATE" for f in res["findings"])


def test_expiring_soon_certificate():
    der = generate_test_cert(
        not_valid_before_offset=datetime.timedelta(days=-100),
        not_valid_after_offset=datetime.timedelta(days=15)
    )
    res = analyze_x509_certificates([der], sni="mail.example.com")
    assert res["expiration_status"] == "EXPIRING_SOON"
    assert 0 <= res["days_until_expiry"] <= 30
    assert any(f["finding"] == "CERTIFICATE_EXPIRING_SOON" for f in res["findings"])


def test_weak_rsa_key_length():
    der = generate_test_cert(key_size=1024)
    res = analyze_x509_certificates([der], sni="mail.example.com")
    assert res["public_key_length"] == 1024
    assert any(f["finding"] == "WEAK_RSA_KEY_LENGTH" for f in res["findings"])


def test_deprecated_signature_algorithm():
    from unittest.mock import PropertyMock, patch
    der = generate_test_cert()
    with patch.object(x509.Certificate, "signature_algorithm_oid", new_callable=PropertyMock) as mock_sig:
        fake_oid = type("FakeOID", (), {"_name": "sha1WithRSAEncryption"})()
        mock_sig.return_value = fake_oid
        res = analyze_x509_certificates([der], sni="mail.example.com")
        assert any(f["finding"] == "DEPRECATED_SIGNATURE_ALGORITHM" for f in res["findings"])


def test_hostname_mismatch():
    der = generate_test_cert(
        common_name="mail.legitimate.com",
        san_list=["mail.legitimate.com"]
    )
    res = analyze_x509_certificates([der], sni="mail.attacker.com")
    assert res["hostname_match"] is False
    assert any(f["finding"] == "HOSTNAME_MISMATCH" for f in res["findings"])


def test_wildcard_san_matching():
    der = generate_test_cert(
        common_name="*.example.com",
        san_list=["*.example.com"]
    )
    res = analyze_x509_certificates([der], sni="mail.example.com")
    assert res["hostname_match"] is True

    res_nomatch = analyze_x509_certificates([der], sni="sub.mail.example.com")
    assert res_nomatch["hostname_match"] is False


def build_test_certificate_chain(
    inter_ca: bool = True,
    inter_key_sign: bool = True,
    inter_expired: bool = False,
    leaf_bad_sig: bool = False
):
    """Helper to generate a realistic 3-tier X.509 PKI hierarchy for chain tests."""
    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. Self-Signed Root CA
    root_k = rsa.generate_private_key(65537, 2048)
    root_n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root CA")])
    root_c = x509.CertificateBuilder().subject_name(
        root_n
    ).issuer_name(
        root_n
    ).public_key(
        root_k.public_key()
    ).serial_number(
        1001
    ).not_valid_before(
        now - datetime.timedelta(days=10)
    ).not_valid_after(
        now + datetime.timedelta(days=3650)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).add_extension(
        x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True
    ).sign(root_k, hashes.SHA256())

    # 2. Intermediate CA
    inter_k = rsa.generate_private_key(65537, 2048)
    inter_n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Intermediate CA")])
    inter_b = x509.CertificateBuilder().subject_name(
        inter_n
    ).issuer_name(
        root_n
    ).public_key(
        inter_k.public_key()
    ).serial_number(
        1002
    )

    if inter_expired:
        inter_b = inter_b.not_valid_before(
            now - datetime.timedelta(days=100)
        ).not_valid_after(
            now - datetime.timedelta(days=1)
        )
    else:
        inter_b = inter_b.not_valid_before(
            now - datetime.timedelta(days=10)
        ).not_valid_after(
            now + datetime.timedelta(days=1825)
        )

    inter_b = inter_b.add_extension(
        x509.BasicConstraints(ca=inter_ca, path_length=0 if inter_ca else None),
        critical=True
    ).add_extension(
        x509.KeyUsage(True, False, False, False, False, inter_key_sign, True, False, False),
        critical=True
    )
    inter_c = inter_b.sign(root_k, hashes.SHA256())

    # 3. Leaf Certificate
    leaf_k = rsa.generate_private_key(65537, 2048)
    leaf_n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mail.example.test")])
    leaf_b = x509.CertificateBuilder().subject_name(
        leaf_n
    ).issuer_name(
        inter_n
    ).public_key(
        leaf_k.public_key()
    ).serial_number(
        1003
    ).not_valid_before(
        now - datetime.timedelta(days=10)
    ).not_valid_after(
        now + datetime.timedelta(days=365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName("mail.example.test")]), critical=False
    )

    signing_k = rsa.generate_private_key(65537, 2048) if leaf_bad_sig else inter_k
    leaf_c = leaf_b.sign(signing_k, hashes.SHA256())

    return (
        leaf_c.public_bytes(serialization.Encoding.DER),
        inter_c.public_bytes(serialization.Encoding.DER),
        root_c.public_bytes(serialization.Encoding.DER)
    )


def test_valid_three_tier_chain():
    """Verify complete leaf -> intermediate -> root CA chain passes validation."""
    leaf_der, inter_der, root_der = build_test_certificate_chain()
    res = analyze_x509_certificates([leaf_der, inter_der, root_der], sni="mail.example.test")

    chain = res["certificate_chain"]
    assert chain["certificate_count"] == 3
    assert chain["chain_observable"] is True
    assert chain["chain_status"] == "VALID"
    assert chain["chain_complete"] is True
    assert len(chain["issuer_relationships"]) == 3

    # Leaf -> Intermediate link
    r0 = chain["issuer_relationships"][0]
    assert r0["is_leaf"] is True
    assert r0["issuer_found"] is True
    assert r0["signature_valid"] is True
    assert r0["ca_constraints_valid"] is True

    # Intermediate -> Root link
    r1 = chain["issuer_relationships"][1]
    assert r1["is_leaf"] is False
    assert r1["is_root"] is False
    assert r1["issuer_found"] is True
    assert r1["signature_valid"] is True

    # Root -> Root self-anchor
    r2 = chain["issuer_relationships"][2]
    assert r2["is_root"] is True
    assert r2["is_self_signed"] is True
    assert r2["signature_valid"] is True

    assert len(res["findings"]) == 0


def test_incomplete_chain():
    """Verify missing intermediate CA marks chain as INCOMPLETE."""
    leaf_der, _, _ = build_test_certificate_chain()
    res = analyze_x509_certificates([leaf_der], sni="mail.example.test")

    chain = res["certificate_chain"]
    assert chain["certificate_count"] == 1
    assert chain["chain_status"] == "INCOMPLETE"
    assert chain["chain_complete"] is False
    assert any(f["finding"] == "INCOMPLETE_CERTIFICATE_CHAIN" for f in res["findings"])

    r0 = chain["issuer_relationships"][0]
    assert r0["issuer_found"] is False
    assert r0["signature_valid"] is None


def test_invalid_certificate_signature():
    """Verify cryptographic signature mismatch marks chain as INVALID."""
    leaf_bad, inter_der, root_der = build_test_certificate_chain(leaf_bad_sig=True)
    res = analyze_x509_certificates([leaf_bad, inter_der, root_der], sni="mail.example.test")

    chain = res["certificate_chain"]
    assert chain["chain_status"] == "INVALID"
    assert any(f["finding"] == "INVALID_CERTIFICATE_SIGNATURE" for f in res["findings"])

    r0 = chain["issuer_relationships"][0]
    assert r0["signature_valid"] is False


def test_non_ca_intermediate():
    """Verify intermediate lacking BasicConstraints CA=true marks chain as INVALID."""
    leaf_der, inter_noca, root_der = build_test_certificate_chain(inter_ca=False)
    res = analyze_x509_certificates([leaf_der, inter_noca, root_der], sni="mail.example.test")

    chain = res["certificate_chain"]
    assert chain["chain_status"] == "INVALID"
    assert any(f["finding"] == "INVALID_ISSUER_CONSTRAINTS" for f in res["findings"])

    r0 = chain["issuer_relationships"][0]
    assert r0["ca_constraints_valid"] is False


def test_expired_intermediate():
    """Verify expired intermediate certificate marks chain as INVALID."""
    leaf_der, inter_exp, root_der = build_test_certificate_chain(inter_expired=True)
    res = analyze_x509_certificates([leaf_der, inter_exp, root_der], sni="mail.example.test")

    chain = res["certificate_chain"]
    assert chain["chain_status"] == "INVALID"
    assert any(f["finding"] == "EXPIRED_INTERMEDIATE_CERTIFICATE" for f in res["findings"])


def test_self_signed_root():
    """Verify a standalone self-signed certificate evaluates as complete and VALID."""
    _, _, root_der = build_test_certificate_chain()
    res = analyze_x509_certificates([root_der])

    chain = res["certificate_chain"]
    assert chain["certificate_count"] == 1
    assert chain["chain_complete"] is True
    assert chain["chain_status"] == "VALID"
    assert not any(f["finding"] == "INCOMPLETE_CERTIFICATE_CHAIN" for f in res["findings"])


def test_existing_sample_tls_pcap():
    """Verify chain validation on existing dataset/tls_test_email.pcap."""
    import os
    from app.capture.pcap_reader import analyze_pcap

    pcap_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "dataset", "tls_test_email.pcap")
    if os.path.exists(pcap_path):
        result = analyze_pcap(pcap_path)
        assert len(result["sessions"]) >= 1
        s0 = result["sessions"][0]
        cert = s0["tls"]["certificate"]
        assert cert["certificate_present"] is True
        assert cert["certificate_chain"]["chain_observable"] is True
        assert cert["certificate_chain"]["chain_status"] == "VALID"
        assert cert["certificate_chain"]["chain_complete"] is True
        assert s0["posture"]["score"] == 100


def test_tls_13_certificate_structure_parsing():
    """Verify parsing of TLS 1.3 Certificate structure with context and entry extensions."""
    from app.tls.tls_parser import parse_certificates

    leaf_der, _, _ = build_test_certificate_chain()
    # Construct TLS 1.3 Certificate message body:
    # Context (len=0) + ListLen(3 bytes) + CertLen(3 bytes) + CertBytes + ExtLen(2 bytes = 0)
    entry = len(leaf_der).to_bytes(3, "big") + leaf_der + (0).to_bytes(2, "big")
    body = (0).to_bytes(1, "big") + len(entry).to_bytes(3, "big") + entry

    parsed = parse_certificates(body, is_tls13=True)
    assert len(parsed) == 1
    assert parsed[0] == leaf_der

