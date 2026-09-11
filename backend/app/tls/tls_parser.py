import struct
from typing import List, Dict, Any, Optional, Tuple
from app.certificate.certificate_analyzer import analyze_x509_certificates

# Standard TLS Record Content Types
CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14
CONTENT_TYPE_ALERT = 0x15
CONTENT_TYPE_HANDSHAKE = 0x16
CONTENT_TYPE_APPLICATION_DATA = 0x17

# Standard TLS Handshake Types
HANDSHAKE_TYPE_HELLO_REQUEST = 0x00
HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
HANDSHAKE_TYPE_SERVER_HELLO = 0x02
HANDSHAKE_TYPE_NEW_SESSION_TICKET = 0x04
HANDSHAKE_TYPE_CERTIFICATE = 0x0B
HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = 0x0C
HANDSHAKE_TYPE_CERTIFICATE_REQUEST = 0x0D
HANDSHAKE_TYPE_SERVER_HELLO_DONE = 0x0E
HANDSHAKE_TYPE_CERTIFICATE_VERIFY = 0x0F
HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 0x10
HANDSHAKE_TYPE_FINISHED = 0x14

HANDSHAKE_NAME_MAP = {
    0x00: "HelloRequest",
    0x01: "ClientHello",
    0x02: "ServerHello",
    0x04: "NewSessionTicket",
    0x0B: "Certificate",
    0x0C: "ServerKeyExchange",
    0x0D: "CertificateRequest",
    0x0E: "ServerHelloDone",
    0x0F: "CertificateVerify",
    0x10: "ClientKeyExchange",
    0x14: "Finished"
}

TLS_VERSION_MAP = {
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3"
}

# Known Named Curves for ECDHE
NAMED_CURVE_MAP = {
    0x0017: "secp256r1 (NIST P-256)",
    0x0018: "secp384r1 (NIST P-384)",
    0x0019: "secp521r1 (NIST P-521)",
    0x001D: "x25519",
    0x001E: "x448"
}

# IANA Cipher Suites Dictionary (Value -> (Name, KeyExchange, ForwardSecrecy))
CIPHER_SUITE_DB: Dict[int, Tuple[str, str, bool]] = {
    # TLS 1.3 Cipher Suites (Mandatory Ephemeral Key Exchange / Forward Secrecy)
    0x1301: ("TLS_AES_128_GCM_SHA256", "ECDHE/DHE (TLS 1.3)", True),
    0x1302: ("TLS_AES_256_GCM_SHA384", "ECDHE/DHE (TLS 1.3)", True),
    0x1303: ("TLS_CHACHA20_POLY1305_SHA256", "ECDHE/DHE (TLS 1.3)", True),
    0x1304: ("TLS_AES_128_CCM_SHA256", "ECDHE/DHE (TLS 1.3)", True),
    0x1305: ("TLS_AES_128_CCM_8_SHA256", "ECDHE/DHE (TLS 1.3)", True),

    # ECDHE + RSA / ECDSA (Forward Secrecy)
    0xC02F: ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", True),
    0xC030: ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", True),
    0xC02B: ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "ECDHE", True),
    0xC02C: ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "ECDHE", True),
    0xCCA8: ("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", True),
    0xCCA9: ("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "ECDHE", True),
    0xC013: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "ECDHE", True),
    0xC014: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "ECDHE", True),
    0xC027: ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "ECDHE", True),
    0xC028: ("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", "ECDHE", True),
    0xC009: ("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", "ECDHE", True),
    0xC00A: ("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", "ECDHE", True),

    # DHE + RSA / DSS (Forward Secrecy)
    0x009E: ("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", "DHE", True),
    0x009F: ("TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", "DHE", True),
    0xCCAA: ("TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "DHE", True),
    0x0033: ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "DHE", True),
    0x0039: ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA", "DHE", True),
    0x0067: ("TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", "DHE", True),
    0x006B: ("TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", "DHE", True),

    # Static RSA (No Forward Secrecy)
    0x009C: ("TLS_RSA_WITH_AES_128_GCM_SHA256", "RSA", False),
    0x009D: ("TLS_RSA_WITH_AES_256_GCM_SHA384", "RSA", False),
    0x002F: ("TLS_RSA_WITH_AES_128_CBC_SHA", "RSA", False),
    0x0035: ("TLS_RSA_WITH_AES_256_CBC_SHA", "RSA", False),
    0x003C: ("TLS_RSA_WITH_AES_128_CBC_SHA256", "RSA", False),
    0x003D: ("TLS_RSA_WITH_AES_256_CBC_SHA256", "RSA", False),
    0x000A: ("TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA", False),
    0x0005: ("TLS_RSA_WITH_RC4_128_SHA", "RSA", False),
    0x0004: ("TLS_RSA_WITH_RC4_128_MD5", "RSA", False),
}


def lookup_cipher_suite(val: int) -> Tuple[str, str, Optional[bool]]:
    """Returns (cipher_name, key_exchange, forward_secrecy) for given 16-bit cipher code."""
    if val in CIPHER_SUITE_DB:
        return CIPHER_SUITE_DB[val]
    hex_name = f"0x{val:04X}"
    return (f"TLS_UNKNOWN_CIPHER_{hex_name}", "UNKNOWN", None)


def parse_client_hello(body: bytes) -> Dict[str, Any]:
    """Parses ClientHello handshake body and extracts parameters, SNI, and supported versions."""
    res: Dict[str, Any] = {
        "client_version": None,
        "server_name": None,
        "offered_cipher_suites_count": 0,
        "offered_cipher_suites": [],
        "supported_versions": []
    }
    if len(body) < 34:
        return res

    version_raw = int.from_bytes(body[0:2], "big")
    res["client_version"] = TLS_VERSION_MAP.get(version_raw, f"Unknown(0x{version_raw:04X})")

    session_id_len = body[34]
    offset = 35 + session_id_len
    if offset + 2 > len(body):
        return res

    cipher_len = int.from_bytes(body[offset:offset+2], "big")
    offset += 2
    if offset + cipher_len > len(body):
        return res

    cipher_codes = []
    for i in range(0, cipher_len, 2):
        if offset + i + 2 <= len(body):
            code = int.from_bytes(body[offset+i:offset+i+2], "big")
            cipher_codes.append(code)

    res["offered_cipher_suites_count"] = len(cipher_codes)
    res["offered_cipher_suites"] = [lookup_cipher_suite(c)[0] for c in cipher_codes[:10]]
    offset += cipher_len

    if offset >= len(body):
        return res
    comp_len = body[offset]
    offset += 1 + comp_len

    if offset + 2 > len(body):
        return res

    ext_total_len = int.from_bytes(body[offset:offset+2], "big")
    offset += 2
    ext_end = min(offset + ext_total_len, len(body))

    while offset + 4 <= ext_end:
        ext_type = int.from_bytes(body[offset:offset+2], "big")
        ext_len = int.from_bytes(body[offset+2:offset+4], "big")
        ext_data = body[offset+4:offset+4+ext_len]
        offset += 4 + ext_len

        # SNI extension (0x0000)
        if ext_type == 0x0000 and len(ext_data) >= 5:
            list_len = int.from_bytes(ext_data[0:2], "big")
            name_type = ext_data[2]
            if name_type == 0:  # host_name
                name_len = int.from_bytes(ext_data[3:5], "big")
                if len(ext_data) >= 5 + name_len:
                    res["server_name"] = ext_data[5:5+name_len].decode("utf-8", errors="replace")

        # Supported Versions extension (0x002B)
        elif ext_type == 0x002B and len(ext_data) >= 1:
            ver_list_len = ext_data[0]
            for v_idx in range(1, min(1 + ver_list_len, len(ext_data)), 2):
                if v_idx + 2 <= len(ext_data):
                    v_val = int.from_bytes(ext_data[v_idx:v_idx+2], "big")
                    v_name = TLS_VERSION_MAP.get(v_val, f"0x{v_val:04X}")
                    if v_name not in res["supported_versions"]:
                        res["supported_versions"].append(v_name)

    return res


def parse_server_hello(body: bytes) -> Dict[str, Any]:
    """Parses ServerHello handshake body and extracts selected version, cipher suite, and random."""
    res: Dict[str, Any] = {
        "selected_version": None,
        "selected_cipher_suite": None,
        "cipher_suite_code": None,
        "server_random": None,
        "session_id": None
    }
    if len(body) < 38:
        return res

    version_raw = int.from_bytes(body[0:2], "big")
    res["selected_version"] = TLS_VERSION_MAP.get(version_raw, f"Unknown(0x{version_raw:04X})")
    res["server_random"] = body[2:34].hex()

    session_id_len = body[34]
    offset = 35 + session_id_len
    if session_id_len > 0:
        res["session_id"] = body[35:35+session_id_len].hex()

    if offset + 2 <= len(body):
        cipher_code = int.from_bytes(body[offset:offset+2], "big")
        res["cipher_suite_code"] = cipher_code
        c_name, _, _ = lookup_cipher_suite(cipher_code)
        res["selected_cipher_suite"] = c_name
        offset += 2

    # Check for TLS 1.3 supported_versions in extensions
    if offset < len(body):
        offset += 1  # compression method
        if offset + 2 <= len(body):
            ext_total_len = int.from_bytes(body[offset:offset+2], "big")
            offset += 2
            ext_end = min(offset + ext_total_len, len(body))
            while offset + 4 <= ext_end:
                ext_type = int.from_bytes(body[offset:offset+2], "big")
                ext_len = int.from_bytes(body[offset+2:offset+4], "big")
                ext_data = body[offset+4:offset+4+ext_len]
                offset += 4 + ext_len
                if ext_type == 0x002B and len(ext_data) >= 2:
                    v_val = int.from_bytes(ext_data[0:2], "big")
                    res["selected_version"] = TLS_VERSION_MAP.get(v_val, f"0x{v_val:04X}")

    return res


def parse_certificates(body: bytes, is_tls13: bool = False) -> List[bytes]:
    """
    Extracts raw DER encoded certificates from Certificate handshake message body.
    Supports both TLS 1.2 (RFC 5246) and TLS 1.3 (RFC 8446) Certificate message structures.
    """
    if len(body) < 3:
        return []

    def _parse_tls12(data: bytes) -> List[bytes]:
        res = []
        total_len = int.from_bytes(data[0:3], "big")
        offset = 3
        end = min(3 + total_len, len(data))
        while offset + 3 <= end:
            cert_len = int.from_bytes(data[offset:offset+3], "big")
            offset += 3
            if offset + cert_len <= len(data):
                res.append(data[offset:offset+cert_len])
                offset += cert_len
            else:
                break
        return res

    def _parse_tls13(data: bytes) -> List[bytes]:
        res = []
        if len(data) < 4:
            return res
        ctx_len = data[0]
        offset = 1 + ctx_len
        if offset + 3 > len(data):
            return res
        total_len = int.from_bytes(data[offset:offset+3], "big")
        offset += 3
        end = min(offset + total_len, len(data))
        while offset + 3 <= end:
            cert_len = int.from_bytes(data[offset:offset+3], "big")
            offset += 3
            if offset + cert_len > len(data):
                break
            res.append(data[offset:offset+cert_len])
            offset += cert_len
            if offset + 2 <= len(data):
                ext_len = int.from_bytes(data[offset:offset+2], "big")
                offset += 2 + ext_len
            else:
                break
        return res

    if is_tls13:
        certs = _parse_tls13(body)
        if certs:
            return certs
        return _parse_tls12(body)

    certs = _parse_tls12(body)
    if certs and len(certs[0]) > 0 and certs[0][0] == 0x30:
        return certs

    # Fallback to TLS 1.3 format if TLS 1.2 did not produce valid ASN.1 SEQUENCE
    certs_tls13 = _parse_tls13(body)
    if certs_tls13 and len(certs_tls13[0]) > 0 and certs_tls13[0][0] == 0x30:
        return certs_tls13

    return certs



def parse_server_key_exchange(body: bytes) -> Dict[str, Any]:
    """Parses ServerKeyExchange parameters for ECDHE / DHE named curve."""
    info: Dict[str, Any] = {
        "curve_type": None,
        "named_curve": None
    }
    if len(body) >= 3:
        curve_type = body[0]
        if curve_type == 3:  # named_curve
            info["curve_type"] = "named_curve"
            curve_id = int.from_bytes(body[1:3], "big")
            info["named_curve"] = NAMED_CURVE_MAP.get(curve_id, f"0x{curve_id:04X}")
    return info


def extract_tls_records(payload: bytes) -> List[Dict[str, Any]]:
    """
    Scans a payload byte stream and extracts all embedded TLS records.
    Handles multiple TLS records packed into a single TCP payload.
    """
    records = []
    offset = 0

    while offset + 5 <= len(payload):
        c_type = payload[offset]
        v_major = payload[offset+1]
        v_minor = payload[offset+2]

        if c_type in (CONTENT_TYPE_CHANGE_CIPHER_SPEC, CONTENT_TYPE_ALERT, CONTENT_TYPE_HANDSHAKE, CONTENT_TYPE_APPLICATION_DATA) and v_major == 0x03 and v_minor in (0, 1, 2, 3, 4):
            rec_len = int.from_bytes(payload[offset+3:offset+5], "big")
            rec_body = payload[offset+5:offset+5+rec_len]
            records.append({
                "content_type": c_type,
                "version_raw": (v_major << 8) | v_minor,
                "length": rec_len,
                "body": rec_body,
                "offset": offset
            })
            offset += 5 + rec_len
        else:
            next_idx = payload.find(b"\x16\x03", offset + 1)
            if next_idx == -1:
                next_app = payload.find(b"\x17\x03", offset + 1)
                next_ccs = payload.find(b"\x14\x03", offset + 1)
                candidates = [i for i in (next_app, next_ccs) if i != -1]
                if candidates:
                    offset = min(candidates)
                else:
                    break
            else:
                offset = next_idx

    return records


def analyze_tls_session(ordered_messages: List[Tuple[str, bytes]]) -> Dict[str, Any]:
    """
    Analyzes all directional payload chunks in a reconstructed session to parse the TLS handshake,
    extract cryptographic parameters, parse X.509 certificates, and collect forensic evidence.
    """
    tls_detected = False
    version: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None
    forward_secrecy: Optional[bool] = None

    client_hello_data: Optional[Dict[str, Any]] = None
    server_hello_data: Optional[Dict[str, Any]] = None
    handshake_messages: List[str] = []
    certificate_present = False
    certificate_der_hex: Optional[str] = None
    all_cert_der_bytes: List[bytes] = []
    encrypted_application_data_observed = False
    evidence: List[Dict[str, Any]] = []

    for msg_idx, (direction, raw_payload) in enumerate(ordered_messages):
        if not raw_payload:
            continue

        records = extract_tls_records(raw_payload)
        for rec in records:
            tls_detected = True
            c_type = rec["content_type"]

            if c_type == CONTENT_TYPE_CHANGE_CIPHER_SPEC:
                if "ChangeCipherSpec" not in handshake_messages:
                    handshake_messages.append("ChangeCipherSpec")
                evidence.append({
                    "type": "tls_record",
                    "value": "ChangeCipherSpec",
                    "direction": direction.upper(),
                    "description": f"Observed TLS ChangeCipherSpec record in {direction.upper()} stream"
                })

            elif c_type == CONTENT_TYPE_APPLICATION_DATA:
                encrypted_application_data_observed = True
                evidence.append({
                    "type": "tls_application_data",
                    "value": f"Encrypted ApplicationData (Length: {rec['length']} bytes)",
                    "direction": direction.upper(),
                    "description": f"Observed encrypted TLS application traffic from {direction.upper()}"
                })

            elif c_type == CONTENT_TYPE_HANDSHAKE:
                body = rec["body"]
                h_offset = 0

                while h_offset + 4 <= len(body):
                    h_type = body[h_offset]
                    h_len = int.from_bytes(body[h_offset+1:h_offset+4], "big")
                    h_body = body[h_offset+4:h_offset+4+h_len]
                    h_name = HANDSHAKE_NAME_MAP.get(h_type, f"Handshake_0x{h_type:02X}")

                    if h_name not in handshake_messages:
                        handshake_messages.append(h_name)

                    # 1. ClientHello
                    if h_type == HANDSHAKE_TYPE_CLIENT_HELLO:
                        client_hello_data = parse_client_hello(h_body)
                        evidence.append({
                            "type": "handshake_message",
                            "message": "ClientHello",
                            "direction": direction.upper(),
                            "sni": client_hello_data.get("server_name"),
                            "offered_ciphers": client_hello_data.get("offered_cipher_suites_count"),
                            "description": f"Observed TLS ClientHello with SNI: {client_hello_data.get('server_name') or 'None'}"
                        })

                    # 2. ServerHello
                    elif h_type == HANDSHAKE_TYPE_SERVER_HELLO:
                        server_hello_data = parse_server_hello(h_body)
                        version = server_hello_data.get("selected_version")
                        cipher_suite = server_hello_data.get("selected_cipher_suite")
                        c_code = server_hello_data.get("cipher_suite_code")

                        if c_code is not None:
                            _, kx, fs = lookup_cipher_suite(c_code)
                            key_exchange = kx
                            forward_secrecy = fs

                        evidence.append({
                            "type": "handshake_message",
                            "message": "ServerHello",
                            "direction": direction.upper(),
                            "selected_version": version,
                            "selected_cipher_suite": cipher_suite,
                            "description": f"Server negotiated version {version} and cipher {cipher_suite}"
                        })

                    # 3. Certificate
                    elif h_type == HANDSHAKE_TYPE_CERTIFICATE:
                        certificate_present = True
                        is_tls13 = (version == "TLSv1.3")
                        certs = parse_certificates(h_body, is_tls13=is_tls13)
                        if certs:
                            all_cert_der_bytes.extend(certs)
                            certificate_der_hex = certs[0].hex()
                        evidence.append({
                            "type": "handshake_message",
                            "message": "Certificate",
                            "direction": direction.upper(),
                            "certificates_count": len(certs),
                            "leaf_cert_len": len(certs[0]) if certs else 0,
                            "description": f"Observed X.509 Certificate chain ({len(certs)} certificate(s)) in Server Handshake"
                        })

                    # 4. ServerKeyExchange
                    elif h_type == HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE:
                        kx_info = parse_server_key_exchange(h_body)
                        curve = kx_info.get("named_curve")
                        if curve:
                            key_exchange = f"ECDHE ({curve})" if key_exchange == "ECDHE" or not key_exchange else key_exchange
                        evidence.append({
                            "type": "handshake_message",
                            "message": "ServerKeyExchange",
                            "direction": direction.upper(),
                            "named_curve": curve,
                            "description": f"Server provided KeyExchange parameters (Curve: {curve or 'Standard'})"
                        })

                    # 5. ClientKeyExchange
                    elif h_type == HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE:
                        evidence.append({
                            "type": "handshake_message",
                            "message": "ClientKeyExchange",
                            "direction": direction.upper(),
                            "description": "Client transmitted key exchange parameters"
                        })

                    # 6. Finished
                    elif h_type == HANDSHAKE_TYPE_FINISHED:
                        evidence.append({
                            "type": "handshake_message",
                            "message": "Finished",
                            "direction": direction.upper(),
                            "description": f"Handshake Finished message observed from {direction.upper()}"
                        })

                    h_offset += 4 + h_len

    # If ServerHello was seen but no ServerKeyExchange, evaluate ECDHE/FS from cipher suite
    if key_exchange is None and cipher_suite:
        if "ECDHE" in cipher_suite:
            key_exchange = "ECDHE"
            forward_secrecy = True
        elif "DHE" in cipher_suite:
            key_exchange = "DHE"
            forward_secrecy = True
        elif "RSA" in cipher_suite:
            key_exchange = "RSA"
            forward_secrecy = False

    # Determine TLS Handshake Completeness
    if not tls_detected:
        tls_handshake_status = "NOT_OBSERVED"
        handshake_complete = False
        ephemeral_key_exchange_verified = False
    else:
        is_tls13 = (version == "TLSv1.3" or version == "TLS 1.3")
        if encrypted_application_data_observed or "Finished" in handshake_messages:
            tls_handshake_status = "COMPLETE"
            handshake_complete = True
        elif not is_tls13 and "ClientKeyExchange" in handshake_messages and "ChangeCipherSpec" in handshake_messages:
            tls_handshake_status = "COMPLETE"
            handshake_complete = True
        elif server_hello_data is not None or client_hello_data is not None:
            tls_handshake_status = "INCOMPLETE"
            handshake_complete = False
        else:
            tls_handshake_status = "UNKNOWN"
            handshake_complete = False

        # Determine if ephemeral key exchange (PFS) was cryptographically completed vs merely indicated
        if forward_secrecy is True:
            if is_tls13:
                ephemeral_key_exchange_verified = handshake_complete
            else:
                # For TLS 1.0 - 1.2: ServerKeyExchange + ClientKeyExchange required
                has_server_kex = "ServerKeyExchange" in handshake_messages
                has_client_kex = "ClientKeyExchange" in handshake_messages
                ephemeral_key_exchange_verified = (has_server_kex and has_client_kex and handshake_complete)
        else:
            ephemeral_key_exchange_verified = False

        evidence.append({
            "type": "tls_handshake_status",
            "status": tls_handshake_status,
            "complete": handshake_complete,
            "description": f"TLS handshake status: {tls_handshake_status} (Messages: {', '.join(handshake_messages) or 'None'})"
        })

    # Perform full X.509 certificate analysis
    sni = client_hello_data.get("server_name") if client_hello_data else None
    cert_analysis = analyze_x509_certificates(all_cert_der_bytes, sni=sni)

    return {
        "detected": tls_detected,
        "version": version,
        "cipher_suite": cipher_suite,
        "key_exchange": key_exchange,
        "forward_secrecy": forward_secrecy,
        "client_hello": client_hello_data,
        "server_hello": server_hello_data,
        "handshake_messages": handshake_messages,
        "handshake_status": tls_handshake_status,
        "tls_handshake_status": tls_handshake_status,
        "handshake_complete": handshake_complete,
        "ephemeral_key_exchange_verified": ephemeral_key_exchange_verified,
        "certificate_present": certificate_present,
        "certificate_der_hex": certificate_der_hex,
        "certificate_chain_validation": cert_analysis.get("certificate_chain", {}),
        "encrypted_application_data_observed": encrypted_application_data_observed,
        "evidence": evidence,
        "certificate": cert_analysis
    }

