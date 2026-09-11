from typing import List, Dict, Any, Optional

def evaluate_tls_version_rule(tls_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluates negotiated TLS version for obsolescence and security risk."""
    findings = []
    if not tls_info.get("detected"):
        return findings

    version = tls_info.get("version")
    if not version:
        return findings

    if version == "SSLv3":
        findings.append({
            "category": "TLS_CONFIGURATION",
            "title": "Insecure Legacy SSL Protocol (SSLv3)",
            "severity": "CRITICAL",
            "reason": "The session negotiated SSLv3, which is fundamentally broken and vulnerable to POODLE and padding oracle attacks (RFC 7568).",
            "evidence": [{"type": "tls_version", "value": "SSLv3", "description": "Server negotiated SSLv3"}],
            "recommendation": "Immediately disable SSLv3 across mail transfer agents and clients, and mandate TLS 1.2 or TLS 1.3."
        })
    elif version in ("TLSv1.0", "TLSv1.1"):
        findings.append({
            "category": "TLS_CONFIGURATION",
            "title": f"Deprecated Protocol Version ({version})",
            "severity": "HIGH",
            "reason": f"The session negotiated {version}, which has been formally deprecated by IETF (RFC 8996) due to weak cryptographic algorithms and lack of modern AEAD cipher support.",
            "evidence": [{"type": "tls_version", "value": version, "description": f"Server negotiated {version}"}],
            "recommendation": f"Disable {version} and configure minimum supported protocol to TLS 1.2 or TLS 1.3."
        })

    return findings


def evaluate_cipher_suite_rule(tls_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluates negotiated cipher suite for cryptographic weaknesses."""
    findings = []
    if not tls_info.get("detected"):
        return findings

    cipher = tls_info.get("cipher_suite")
    if not cipher:
        return findings

    cipher_upper = cipher.upper()

    if "NULL" in cipher_upper:
        findings.append({
            "category": "CIPHER_SUITE",
            "title": "NULL Encryption Cipher Suite",
            "severity": "CRITICAL",
            "reason": f"The session negotiated {cipher}, which provides zero cryptographic confidentiality.",
            "evidence": [{"type": "cipher_suite", "value": cipher, "description": "Negotiated NULL encryption cipher"}],
            "recommendation": "Disable all NULL encryption ciphers immediately and enforce authenticated encryption (AES-GCM / ChaCha20-Poly1305)."
        })
    elif "EXPORT" in cipher_upper:
        findings.append({
            "category": "CIPHER_SUITE",
            "title": "Export-Grade Weak Cipher Suite",
            "severity": "CRITICAL",
            "reason": f"The session negotiated export-grade cipher {cipher}, vulnerable to FREAK and Logjam attacks.",
            "evidence": [{"type": "cipher_suite", "value": cipher, "description": "Negotiated legacy export cipher"}],
            "recommendation": "Disable all legacy 40-bit/56-bit export cipher suites."
        })
    elif any(anon in cipher_upper for anon in ("_ANON_", "_DH_ANON_", "_AECDH_")):
        findings.append({
            "category": "CIPHER_SUITE",
            "title": "Anonymous Authentication Cipher Suite",
            "severity": "CRITICAL",
            "reason": f"The session negotiated {cipher} without endpoint authentication, vulnerable to active Man-in-the-Middle attacks.",
            "evidence": [{"type": "cipher_suite", "value": cipher, "description": "Negotiated unauthenticated anonymous cipher"}],
            "recommendation": "Disable anonymous cipher suites and require authenticated endpoints."
        })
    elif "_RC4_" in cipher_upper or "RC4" in cipher_upper:
        findings.append({
            "category": "CIPHER_SUITE",
            "title": "Insecure RC4 Stream Cipher",
            "severity": "HIGH",
            "reason": f"The session negotiated {cipher} utilizing the RC4 stream cipher, prohibited by RFC 7465 due to statistical keystream biases.",
            "evidence": [{"type": "cipher_suite", "value": cipher, "description": "Negotiated RC4 stream cipher"}],
            "recommendation": "Remove RC4 cipher suites from server and client configurations."
        })
    elif any(b in cipher_upper for b in ("_3DES_", "3DES", "_DES_")):
        findings.append({
            "category": "CIPHER_SUITE",
            "title": "Weak 64-Bit Block Cipher (3DES/DES)",
            "severity": "MEDIUM",
            "reason": f"The session negotiated {cipher} using a 64-bit block cipher vulnerable to Sweet32 collision attacks (CVE-2016-2183).",
            "evidence": [{"type": "cipher_suite", "value": cipher, "description": "Negotiated 64-bit block cipher"}],
            "recommendation": "Disable 3DES and transition to AES-GCM (128 or 256 bits) or ChaCha20-Poly1305."
        })
    elif "_CBC_" in cipher_upper:
        findings.append({
            "category": "CIPHER_SUITE",
            "title": "Legacy CBC Mode Cipher Configuration",
            "severity": "LOW",
            "reason": f"The session negotiated {cipher} using CBC mode with HMAC. While acceptable in TLS 1.2 with proper mitigations, AEAD ciphers are strongly preferred.",
            "evidence": [{"type": "cipher_suite", "value": cipher, "description": "Negotiated CBC mode cipher"}],
            "recommendation": "Prioritize modern Authenticated Encryption with Associated Data (AEAD) ciphers like AES-GCM or ChaCha20-Poly1305."
        })

    return findings


def evaluate_forward_secrecy_rule(tls_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluates whether session provides Perfect Forward Secrecy."""
    findings = []
    if not tls_info.get("detected"):
        return findings

    fs = tls_info.get("forward_secrecy")
    kx = tls_info.get("key_exchange")

    if fs is False:
        findings.append({
            "category": "KEY_EXCHANGE",
            "title": "Lack of Forward Secrecy (Static Key Exchange)",
            "severity": "MEDIUM",
            "reason": f"The session negotiated {kx or 'Static RSA'} key exchange without Forward Secrecy. Compromise of the server private key allows retrospective decryption of recorded past traffic.",
            "evidence": [{"type": "key_exchange", "value": kx or "RSA", "forward_secrecy": False, "description": "Static key exchange without ephemeral keys"}],
            "recommendation": "Configure Ephemeral Elliptic Curve Diffie-Hellman (ECDHE) or Ephemeral Diffie-Hellman (DHE) key exchange."
        })

    return findings


def evaluate_starttls_negotiation_rule(
    starttls_info: Dict[str, Any],
    tls_info: Dict[str, Any],
    protocol: str
) -> List[Dict[str, Any]]:
    """Evaluates STARTTLS / STLS transition and security state."""
    findings = []
    if protocol not in ("SMTP", "IMAP", "POP3"):
        return findings

    status = starttls_info.get("status")
    up_supported = starttls_info.get("upgrade_supported")
    up_requested = starttls_info.get("upgrade_requested")
    up_accepted = starttls_info.get("upgrade_accepted")
    tls_observed = starttls_info.get("tls_transition_observed")

    if status == "INCOMPLETE" and not tls_info.get("detected"):
        findings.append({
            "category": "PROTOCOL_NEGOTIATION",
            "title": "Incomplete STARTTLS Transition",
            "severity": "HIGH",
            "reason": "The server accepted STARTTLS upgrade, but no TLS handshake was transmitted before capture completion. The session failed to establish cryptographic protection.",
            "evidence": starttls_info.get("evidence", []),
            "recommendation": "Verify network path and MTA/client timeout settings to ensure uninterrupted TLS handshake execution."
        })

    elif up_requested is True and up_accepted is False:
        findings.append({
            "category": "PROTOCOL_NEGOTIATION",
            "title": "STARTTLS Upgrade Rejected by Server",
            "severity": "HIGH",
            "reason": "The client requested STARTTLS encryption, but the mail server rejected the upgrade request.",
            "evidence": starttls_info.get("evidence", []),
            "recommendation": "Inspect server TLS service certificate, cipher configuration, and local SSL subsystem health."
        })

    elif up_supported is True and up_requested is False:
        findings.append({
            "category": "PROTOCOL_NEGOTIATION",
            "title": "STARTTLS Advertised but Not Utilized (Plaintext Email)",
            "severity": "MEDIUM",
            "reason": "The mail server advertised STARTTLS capability, but the client continued communicating in unencrypted plaintext without requesting encryption.",
            "evidence": starttls_info.get("evidence", []),
            "recommendation": "Configure the email client/MTA to enforce mandatory STARTTLS (upgraded to enforced TLS)."
        })

    return findings


def evaluate_certificate_security_rule(cert_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Evaluates X.509 certificate validity, key strength, and hostname matching."""
    findings = []
    if not cert_info or not cert_info.get("certificate_present"):
        return findings

    exp_status = cert_info.get("expiration_status")
    valid_to = cert_info.get("valid_to")
    valid_from = cert_info.get("valid_from")
    days_left = cert_info.get("days_until_expiry")

    # Expiration rules
    if exp_status == "EXPIRED":
        findings.append({
            "category": "CERTIFICATE",
            "title": "Expired X.509 Certificate",
            "severity": "HIGH",
            "reason": f"Certificate expired on {valid_to} ({abs(days_left) if days_left is not None else 'N/A'} days ago).",
            "evidence": [{"type": "validity", "valid_to": valid_to, "expiration_status": "EXPIRED"}],
            "recommendation": "Renew and replace the expired certificate with a currently-valid certificate immediately."
        })
    elif exp_status == "NOT_YET_VALID":
        findings.append({
            "category": "CERTIFICATE",
            "title": "Certificate Not Yet Valid",
            "severity": "HIGH",
            "reason": f"Certificate is not valid until {valid_from}.",
            "evidence": [{"type": "validity", "valid_from": valid_from, "expiration_status": "NOT_YET_VALID"}],
            "recommendation": "Verify server system clock synchronization and deploy a certificate with an active validity period."
        })
    elif exp_status == "EXPIRING_SOON":
        findings.append({
            "category": "CERTIFICATE",
            "title": "Certificate Expiring Soon",
            "severity": "MEDIUM",
            "reason": f"Certificate will expire in {days_left} day(s) on {valid_to}.",
            "evidence": [{"type": "validity", "valid_to": valid_to, "days_remaining": days_left}],
            "recommendation": "Initiate automated certificate renewal prior to expiration to prevent service interruption."
        })

    # Key Strength
    pk_algo = cert_info.get("public_key_algorithm")
    pk_len = cert_info.get("public_key_length")
    if pk_algo == "RSA" and pk_len is not None and pk_len < 2048:
        findings.append({
            "category": "CERTIFICATE",
            "title": "Weak RSA Key Length",
            "severity": "HIGH",
            "reason": f"Certificate uses an RSA modulus of {pk_len} bits, which is below the 2048-bit minimum security standard.",
            "evidence": [{"type": "public_key", "algorithm": "RSA", "key_length": pk_len}],
            "recommendation": "Reissue the certificate with an RSA key of at least 2048 bits or an ECDSA key (e.g., NIST P-256)."
        })

    # Signature Algorithm
    sig_algo = cert_info.get("signature_algorithm", "")
    sig_lower = sig_algo.lower()
    if any(weak in sig_lower for weak in ("md5", "md2", "sha1")):
        findings.append({
            "category": "CERTIFICATE",
            "title": "Deprecated Certificate Signature Algorithm",
            "severity": "HIGH",
            "reason": f"Certificate signature uses deprecated digest algorithm {sig_algo}, vulnerable to collision attacks.",
            "evidence": [{"type": "signature_algorithm", "value": sig_algo}],
            "recommendation": "Reissue certificate signed with SHA-256 or stronger digest algorithm."
        })

    # Hostname Validation (Only when observable)
    hostname_match = cert_info.get("hostname_match")
    if hostname_match is False:
        findings.append({
            "category": "CERTIFICATE",
            "title": "Certificate Hostname Mismatch",
            "severity": "MEDIUM",
            "reason": f"Requested SNI does not match certificate Subject Alternative Names ({cert_info.get('subject_alternative_names', [])}) or Common Name '{cert_info.get('common_name')}'.",
            "evidence": [{"type": "hostname_validation", "match": False, "sans": cert_info.get("subject_alternative_names", [])}],
            "recommendation": "Update the certificate Subject Alternative Name (SAN) list to cover all client-facing hostnames."
        })

    # Self-Signed Certificate
    if cert_info.get("self_signed") is True:
        findings.append({
            "category": "CERTIFICATE",
            "title": "Self-Signed Certificate",
            "severity": "HIGH",
            "reason": f"Certificate for '{cert_info.get('common_name') or cert_info.get('subject')}' is self-signed, lacking cryptographic trust anchor validation from a recognized Certificate Authority.",
            "evidence": [{"type": "self_signed", "subject": cert_info.get("subject"), "issuer": cert_info.get("issuer"), "self_signed": True}],
            "recommendation": "Deploy an X.509 certificate issued and signed by a trusted public or enterprise Certificate Authority (CA)."
        })

    return findings


def evaluate_certificate_chain_rule(cert_info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluates passive X.509 certificate chain validation findings.
    Checks cryptographic signatures, CA BasicConstraints, KeyUsage, validity windows,
    and chain completeness.
    """
    findings = []
    if not cert_info or not cert_info.get("certificate_present"):
        return findings

    chain_info = cert_info.get("certificate_chain", {})
    if not chain_info or not chain_info.get("chain_observable"):
        return findings

    relationships = chain_info.get("issuer_relationships", [])
    for rel in relationships:
        child_cn = rel.get("child_common_name") or rel.get("child_subject", "Unknown")
        issuer_cn = rel.get("issuer_common_name") or rel.get("issuer_subject", "Unknown")

        # 1. Invalid certificate signature
        if rel.get("signature_valid") is False:
            findings.append({
                "category": "CERTIFICATE_CHAIN",
                "title": "Invalid Certificate Signature",
                "severity": "CRITICAL",
                "reason": f"Cryptographic signature on certificate '{child_cn}' failed verification against issuer '{issuer_cn}'.",
                "evidence": [{"type": "certificate_signature", "child": rel.get("child_subject"), "issuer": rel.get("issuer_subject"), "valid": False}],
                "recommendation": "Investigate potential certificate tampering, transit corruption, or mismatched issuer certificates."
            })

        # 2. Invalid CA constraints
        if rel.get("ca_constraints_valid") is False:
            findings.append({
                "category": "CERTIFICATE_CHAIN",
                "title": "Invalid Issuer CA Constraints",
                "severity": "HIGH",
                "reason": f"Issuing certificate '{issuer_cn}' lacks valid CA BasicConstraints (CA=true) or keyCertSign KeyUsage permissions.",
                "evidence": [{"type": "ca_constraints", "issuer": rel.get("issuer_subject"), "errors": rel.get("errors", [])}],
                "recommendation": "Ensure all issuing intermediate and root authorities possess valid Basic Constraints CA flags and keyCertSign key usage."
            })

        # 3. Intermediate expiration / not yet valid
        if not rel.get("is_leaf"):
            val_status = rel.get("validity_status")
            if val_status == "EXPIRED":
                findings.append({
                    "category": "CERTIFICATE_CHAIN",
                    "title": "Expired Intermediate Certificate",
                    "severity": "HIGH",
                    "reason": f"Intermediate certificate '{child_cn}' in the chain expired on {rel.get('valid_to')}.",
                    "evidence": [{"type": "intermediate_validity", "subject": rel.get("child_subject"), "valid_to": rel.get("valid_to")}],
                    "recommendation": "Update server certificate bundle to include active, non-expired intermediate certificates."
                })
            elif val_status == "NOT_YET_VALID":
                findings.append({
                    "category": "CERTIFICATE_CHAIN",
                    "title": "Intermediate Certificate Not Yet Valid",
                    "severity": "HIGH",
                    "reason": f"Intermediate certificate '{child_cn}' in the chain is not valid until {rel.get('valid_from')}.",
                    "evidence": [{"type": "intermediate_validity", "subject": rel.get("child_subject"), "valid_from": rel.get("valid_from")}],
                    "recommendation": "Synchronize server time and deploy certificates within their active validity window."
                })

        # 4. Incomplete chain (missing issuer for a non-self-signed certificate)
        if rel.get("issuer_found") is False and not rel.get("is_self_signed"):
            findings.append({
                "category": "CERTIFICATE_CHAIN",
                "title": "Incomplete Certificate Chain",
                "severity": "MEDIUM",
                "reason": f"The certificate chain is incomplete. Issuer certificate '{issuer_cn}' was not observed in the captured TLS Certificate message.",
                "evidence": [{"type": "chain_completeness", "child": rel.get("child_subject"), "missing_issuer": rel.get("issuer_subject")}],
                "recommendation": "Configure the mail transfer agent or server to bundle all required intermediate CA certificates in the TLS handshake."
            })

    return findings

