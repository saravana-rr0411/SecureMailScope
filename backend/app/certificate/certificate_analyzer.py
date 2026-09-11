import datetime
import fnmatch
from typing import List, Dict, Any, Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448


def match_hostname(hostname: str, pattern: str) -> bool:
    """Matches a hostname against a certificate DNS SAN or CN pattern, supporting wildcards."""
    h = hostname.strip().lower()
    p = pattern.strip().lower()
    if p.startswith("*."):
        # Wildcard must match single level subdomain (RFC 6125)
        suffix = p[2:]
        if h.endswith("." + suffix):
            prefix = h[:-len(suffix)-1]
            return "." not in prefix
        return False
    return h == p


def extract_cert_metadata(cert: x509.Certificate, idx: int = 0) -> Dict[str, Any]:
    """Extracts cryptographic parameters, extensions, and validity window from an X.509 certificate."""
    subject_str = cert.subject.rfc4514_string()
    issuer_str = cert.issuer.rfc4514_string()
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name = cn_attrs[0].value if cn_attrs else None
    serial_number_hex = format(cert.serial_number, "x")

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    if hasattr(cert, "not_valid_before_utc"):
        valid_from_dt = cert.not_valid_before_utc
        valid_to_dt = cert.not_valid_after_utc
    else:
        valid_from_dt = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        valid_to_dt = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)

    valid_from_str = valid_from_dt.isoformat()
    valid_to_str = valid_to_dt.isoformat()
    days_left = (valid_to_dt - now_utc).days

    if now_utc > valid_to_dt:
        exp_status = "EXPIRED"
    elif now_utc < valid_from_dt:
        exp_status = "NOT_YET_VALID"
    elif 0 <= days_left <= 30:
        exp_status = "EXPIRING_SOON"
    else:
        exp_status = "VALID"

    pub_key = cert.public_key()
    pub_algo = "UNKNOWN"
    pub_len = None
    if isinstance(pub_key, rsa.RSAPublicKey):
        pub_algo = "RSA"
        pub_len = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        pub_algo = f"EC ({pub_key.curve.name})"
        pub_len = pub_key.key_size
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        pub_algo = "Ed25519"
        pub_len = 256
    elif isinstance(pub_key, ed448.Ed448PublicKey):
        pub_algo = "Ed448"
        pub_len = 448
    elif isinstance(pub_key, dsa.DSAPublicKey):
        pub_algo = "DSA"
        pub_len = pub_key.key_size

    sig_algo = getattr(cert.signature_algorithm_oid, "_name", "Unknown")

    has_basic_constraints = False
    is_ca = None
    path_length = None
    try:
        bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        has_basic_constraints = True
        is_ca = bc_ext.value.ca
        path_length = bc_ext.value.path_length
    except x509.ExtensionNotFound:
        pass

    has_key_usage = False
    key_cert_sign = None
    crl_sign = None
    try:
        ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        has_key_usage = True
        key_cert_sign = ku_ext.value.key_cert_sign
        crl_sign = ku_ext.value.crl_sign
    except x509.ExtensionNotFound:
        pass

    sans = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                sans.append(name.value)
            elif isinstance(name, x509.IPAddress):
                sans.append(str(name.value))
    except x509.ExtensionNotFound:
        pass

    is_self_signed = (cert.issuer == cert.subject)

    return {
        "index": idx,
        "subject": subject_str,
        "issuer": issuer_str,
        "common_name": common_name,
        "serial_number": serial_number_hex,
        "valid_from": valid_from_str,
        "valid_to": valid_to_str,
        "days_until_expiry": days_left,
        "expiration_status": exp_status,
        "public_key_algorithm": pub_algo,
        "public_key_length": pub_len,
        "signature_algorithm": sig_algo,
        "has_basic_constraints": has_basic_constraints,
        "is_ca": is_ca,
        "path_length": path_length,
        "has_key_usage": has_key_usage,
        "key_cert_sign": key_cert_sign,
        "crl_sign": crl_sign,
        "subject_alternative_names": sans,
        "is_self_signed": is_self_signed
    }


def validate_certificate_chain(
    parsed_chain: List[x509.Certificate]
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Performs passive cryptographic validation of an X.509 certificate chain.
    Evaluates:
    - Child -> Issuer relationship and resolution
    - Cryptographic signature verification (verify_directly_issued_by)
    - Basic Constraints CA=true on issuing certificates
    - Key Usage keyCertSign on issuing certificates
    - Validity windows (expiration / not-yet-valid) for all certificates
    - Chain completeness (terminates in self-signed root in PCAP)
    - Distinguishes observable vs complete vs cryptographically valid
    """
    if not parsed_chain:
        return {
            "certificate_count": 0,
            "chain_observable": False,
            "chain_status": "UNDETERMINED",
            "chain_complete": False,
            "chain_summary": [],
            "issuer_relationships": [],
            "validation_details": {
                "signatures_verified": False,
                "ca_constraints_verified": False,
                "validity_periods_verified": False,
                "trust_store_validation": "NOT_OBSERVABLE",
                "revocation_check": "NOT_OBSERVABLE",
                "revocation_note": "Passive network analysis cannot verify revocation without in-stream OCSP stapling or CRL records in the PCAP; external live queries are prohibited."
            }
        }, [], []

    cert_metas = [extract_cert_metadata(c, idx) for idx, c in enumerate(parsed_chain)]
    by_subject: Dict[str, List[Tuple[x509.Certificate, Dict[str, Any]]]] = {}
    for idx, c in enumerate(parsed_chain):
        s_str = cert_metas[idx]["subject"]
        if s_str not in by_subject:
            by_subject[s_str] = []
        by_subject[s_str].append((c, cert_metas[idx]))

    issuer_relationships: List[Dict[str, Any]] = []
    chain_findings: List[Dict[str, Any]] = []
    chain_evidence: List[Dict[str, Any]] = []

    chain_status = "VALID"
    chain_complete = False
    all_sigs_verified = True
    all_ca_verified = True
    all_validity_verified = True

    visited = set()
    current_cert = parsed_chain[0]
    current_meta = cert_metas[0]

    while current_cert is not None:
        if current_cert in visited:
            break
        visited.add(current_cert)

        c_subject = current_meta["subject"]
        c_issuer = current_meta["issuer"]
        c_cn = current_meta["common_name"] or c_subject
        is_leaf = (current_cert == parsed_chain[0])
        is_self_signed = current_meta["is_self_signed"]

        if is_self_signed:
            # Self-signed certificate (Root CA or self-signed leaf)
            sig_valid = False
            sig_err = None
            try:
                current_cert.verify_directly_issued_by(current_cert)
                sig_valid = True
            except Exception as e:
                sig_err = str(e) or "Self-signature verification failed"
                sig_valid = False
                all_sigs_verified = False
                chain_status = "INVALID"
                chain_findings.append({
                    "finding": "INVALID_CERTIFICATE_SIGNATURE",
                    "severity": "CRITICAL",
                    "reason": f"Self-signed certificate '{c_cn}' failed cryptographic signature verification: {sig_err}",
                    "evidence": f"Subject: {c_subject}, Signature Algorithm: {current_meta['signature_algorithm']}"
                })

            # Check validity of root if it's acting as CA in a chain
            if not is_leaf:
                if current_meta["expiration_status"] == "EXPIRED":
                    all_validity_verified = False
                    chain_status = "INVALID"
                    chain_findings.append({
                        "finding": "EXPIRED_INTERMEDIATE_CERTIFICATE",
                        "severity": "HIGH",
                        "reason": f"Root/Intermediate certificate '{c_cn}' in chain expired on {current_meta['valid_to']}.",
                        "evidence": f"Subject: {c_subject}, valid_to: {current_meta['valid_to']}"
                    })
                elif current_meta["expiration_status"] == "NOT_YET_VALID":
                    all_validity_verified = False
                    chain_status = "INVALID"
                    chain_findings.append({
                        "finding": "NOT_YET_VALID_INTERMEDIATE_CERTIFICATE",
                        "severity": "HIGH",
                        "reason": f"Root/Intermediate certificate '{c_cn}' in chain is not valid until {current_meta['valid_from']}.",
                        "evidence": f"Subject: {c_subject}, valid_from: {current_meta['valid_from']}"
                    })

            rel = {
                "child_subject": c_subject,
                "child_common_name": current_meta["common_name"],
                "child_role": "Leaf" if is_leaf else "Root CA",
                "issuer_subject": c_subject,
                "issuer_common_name": current_meta["common_name"],
                "issuer_found": True,
                "is_self_signed": True,
                "is_leaf": is_leaf,
                "is_root": True,
                "signature_valid": sig_valid,
                "signature_algorithm": current_meta["signature_algorithm"],
                "ca_constraints_valid": True,
                "validity_status": current_meta["expiration_status"],
                "valid_from": current_meta["valid_from"],
                "valid_to": current_meta["valid_to"],
                "days_until_expiry": current_meta["days_until_expiry"],
                "errors": [sig_err] if sig_err else []
            }
            issuer_relationships.append(rel)
            chain_evidence.append({
                "type": "certificate_chain_link",
                "child": c_cn,
                "issuer": c_cn,
                "relationship": "Self-Signed Root / Anchor",
                "signature_valid": sig_valid,
                "description": f"Verified self-signed certificate signature for {c_cn}"
            })
            chain_complete = True
            break

        else:
            # Child signed by an external issuer: resolve issuer in parsed_chain
            candidates = [pair for pair in by_subject.get(c_issuer, []) if pair[0] != current_cert]
            if candidates:
                issuer_cert, iss_meta = candidates[0]
                iss_subject = iss_meta["subject"]
                iss_cn = iss_meta["common_name"] or iss_subject

                # 1. Cryptographic Signature Verification
                sig_valid = False
                sig_err = None
                try:
                    current_cert.verify_directly_issued_by(issuer_cert)
                    sig_valid = True
                except Exception as e:
                    sig_err = str(e) or "Signature verification failed"
                    sig_valid = False
                    all_sigs_verified = False
                    chain_status = "INVALID"
                    chain_findings.append({
                        "finding": "INVALID_CERTIFICATE_SIGNATURE",
                        "severity": "CRITICAL",
                        "reason": f"Cryptographic signature on certificate '{c_cn}' failed verification against issuer '{iss_cn}': {sig_err}",
                        "evidence": f"Child: {c_subject}, Issuer: {c_issuer}"
                    })

                # 2. Issuer CA Constraints Verification
                ca_valid = True
                ca_errs = []
                if iss_meta["has_basic_constraints"]:
                    if iss_meta["is_ca"] is not True:
                        ca_valid = False
                        ca_errs.append("BasicConstraints CA flag is False")
                else:
                    ca_valid = False
                    ca_errs.append("Lacks BasicConstraints extension with CA=True")

                if iss_meta["has_key_usage"]:
                    if iss_meta["key_cert_sign"] is not True:
                        ca_valid = False
                        ca_errs.append("KeyUsage does not permit certificate signing (keyCertSign=False)")

                if not ca_valid:
                    all_ca_verified = False
                    chain_status = "INVALID"
                    chain_findings.append({
                        "finding": "INVALID_ISSUER_CONSTRAINTS",
                        "severity": "HIGH",
                        "reason": f"Issuing certificate '{iss_cn}' violates CA constraints: {', '.join(ca_errs)}",
                        "evidence": f"Subject: {iss_subject}, is_ca={iss_meta['is_ca']}, key_cert_sign={iss_meta['key_cert_sign']}"
                    })

                # 3. Intermediate Validity Window Check
                if iss_meta["expiration_status"] == "EXPIRED":
                    all_validity_verified = False
                    chain_status = "INVALID"
                    chain_findings.append({
                        "finding": "EXPIRED_INTERMEDIATE_CERTIFICATE",
                        "severity": "HIGH",
                        "reason": f"Intermediate certificate '{iss_cn}' in chain expired on {iss_meta['valid_to']}.",
                        "evidence": f"Subject: {iss_subject}, valid_to: {iss_meta['valid_to']}"
                    })
                elif iss_meta["expiration_status"] == "NOT_YET_VALID":
                    all_validity_verified = False
                    chain_status = "INVALID"
                    chain_findings.append({
                        "finding": "NOT_YET_VALID_INTERMEDIATE_CERTIFICATE",
                        "severity": "HIGH",
                        "reason": f"Intermediate certificate '{iss_cn}' in chain is not valid until {iss_meta['valid_from']}.",
                        "evidence": f"Subject: {iss_subject}, valid_from: {iss_meta['valid_from']}"
                    })

                errors = []
                if sig_err:
                    errors.append(sig_err)
                if ca_errs:
                    errors.extend(ca_errs)

                rel = {
                    "child_subject": c_subject,
                    "child_common_name": current_meta["common_name"],
                    "child_role": "Leaf" if is_leaf else "Intermediate",
                    "issuer_subject": c_issuer,
                    "issuer_common_name": iss_meta["common_name"],
                    "issuer_found": True,
                    "is_self_signed": False,
                    "is_leaf": is_leaf,
                    "is_root": False,
                    "signature_valid": sig_valid,
                    "signature_algorithm": current_meta["signature_algorithm"],
                    "ca_constraints_valid": ca_valid,
                    "validity_status": iss_meta["expiration_status"],
                    "valid_from": iss_meta["valid_from"],
                    "valid_to": iss_meta["valid_to"],
                    "days_until_expiry": iss_meta["days_until_expiry"],
                    "errors": errors
                }
                issuer_relationships.append(rel)
                chain_evidence.append({
                    "type": "certificate_chain_link",
                    "child": c_cn,
                    "issuer": iss_cn,
                    "relationship": "Child -> Issuer",
                    "signature_valid": sig_valid,
                    "ca_valid": ca_valid,
                    "description": f"Verified link from {c_cn} to issuer {iss_cn} (Signature: {'VALID' if sig_valid else 'INVALID'}, CA Constraints: {'VALID' if ca_valid else 'INVALID'})"
                })

                # Advance to next certificate up the chain
                current_cert = issuer_cert
                current_meta = iss_meta

            else:
                # Required issuer is missing from the captured TLS Certificate list
                rel = {
                    "child_subject": c_subject,
                    "child_common_name": current_meta["common_name"],
                    "child_role": "Leaf" if is_leaf else "Intermediate",
                    "issuer_subject": c_issuer,
                    "issuer_common_name": None,
                    "issuer_found": False,
                    "is_self_signed": False,
                    "is_leaf": is_leaf,
                    "is_root": False,
                    "signature_valid": None,
                    "signature_algorithm": current_meta["signature_algorithm"],
                    "ca_constraints_valid": None,
                    "validity_status": current_meta["expiration_status"],
                    "valid_from": current_meta["valid_from"],
                    "valid_to": current_meta["valid_to"],
                    "days_until_expiry": current_meta["days_until_expiry"],
                    "errors": [f"Issuer '{c_issuer}' was not observed in the captured TLS Certificate message"]
                }
                issuer_relationships.append(rel)
                chain_complete = False
                if chain_status != "INVALID":
                    chain_status = "INCOMPLETE"

                chain_findings.append({
                    "finding": "INCOMPLETE_CERTIFICATE_CHAIN",
                    "severity": "MEDIUM",
                    "reason": f"The certificate chain is incomplete. Issuer certificate '{c_issuer}' was not observed in the captured TLS Certificate message.",
                    "evidence": f"Missing issuer for: {c_subject}"
                })
                chain_evidence.append({
                    "type": "certificate_chain_link",
                    "child": c_cn,
                    "issuer": c_issuer,
                    "relationship": "Child -> Missing Issuer",
                    "signature_valid": None,
                    "ca_valid": None,
                    "description": f"Issuer '{c_issuer}' for certificate {c_cn} was not provided in the capture"
                })
                break

    # Build chain summary strings
    chain_summary = []
    for idx, c in enumerate(parsed_chain):
        m = cert_metas[idx]
        role = "Leaf" if idx == 0 else ("Root CA" if m["is_self_signed"] else "Intermediate CA")
        cn_label = m["common_name"] or m["subject"]
        chain_summary.append(f"Certificate #{idx+1}: CN={cn_label} [{role}] (Status: {m['expiration_status']})")

    chain_dict = {
        "certificate_count": len(parsed_chain),
        "chain_observable": len(parsed_chain) > 0,
        "chain_status": chain_status,
        "chain_complete": chain_complete,
        "chain_summary": chain_summary,
        "issuer_relationships": issuer_relationships,
        "validation_details": {
            "signatures_verified": all_sigs_verified and (len(issuer_relationships) > 0),
            "ca_constraints_verified": all_ca_verified,
            "validity_periods_verified": all_validity_verified,
            "trust_store_validation": "NOT_OBSERVABLE",
            "revocation_check": "NOT_OBSERVABLE",
            "revocation_note": "Passive network analysis cannot verify revocation without in-stream OCSP stapling or CRL records in the PCAP; external live queries are prohibited."
        }
    }

    return chain_dict, chain_findings, chain_evidence


def analyze_x509_certificates(
    cert_der_list: List[bytes],
    sni: Optional[str] = None
) -> Dict[str, Any]:
    """
    Parses and cryptographically analyzes X.509 certificate chains extracted from TLS handshakes.
    Validates expiration, key strength, signature algorithm, self-signed status, SNI hostname match,
    and full certificate chain integrity (signatures, CA basic constraints, completeness).
    """
    if not cert_der_list:
        return {
            "certificate_present": False,
            "subject": None,
            "issuer": None,
            "common_name": None,
            "serial_number": None,
            "valid_from": None,
            "valid_to": None,
            "days_until_expiry": None,
            "expiration_status": "NOT_OBSERVABLE",
            "public_key_algorithm": None,
            "public_key_length": None,
            "signature_algorithm": None,
            "subject_alternative_names": [],
            "self_signed": None,
            "hostname_match": None,
            "trust_validation": "NOT_OBSERVABLE",
            "certificate_chain": {
                "certificate_count": 0,
                "chain_observable": False,
                "chain_status": "UNDETERMINED",
                "chain_complete": False,
                "chain_summary": [],
                "issuer_relationships": [],
                "validation_details": {
                    "signatures_verified": False,
                    "ca_constraints_verified": False,
                    "validity_periods_verified": False,
                    "trust_store_validation": "NOT_OBSERVABLE",
                    "revocation_check": "NOT_OBSERVABLE",
                    "revocation_note": "Passive network analysis cannot verify revocation without in-stream OCSP stapling or CRL records in the PCAP; external live queries are prohibited."
                }
            },
            "findings": [],
            "evidence": []
        }

    findings: List[Dict[str, Any]] = []
    evidence: List[Dict[str, Any]] = []
    chain_summary: List[str] = []

    # Parse all certificates in the chain
    parsed_chain: List[x509.Certificate] = []
    for idx, c_bytes in enumerate(cert_der_list):
        try:
            c = x509.load_der_x509_certificate(c_bytes)
            parsed_chain.append(c)
            cn_attrs = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            cn_label = cn_attrs[0].value if cn_attrs else c.subject.rfc4514_string()
            chain_summary.append(f"Certificate #{idx+1}: CN={cn_label}")
        except Exception as e:
            chain_summary.append(f"Certificate #{idx+1}: [Unparseable DER bytes: {str(e)}]")

    if not parsed_chain:
        return {
            "certificate_present": False,
            "subject": None,
            "issuer": None,
            "common_name": None,
            "serial_number": None,
            "valid_from": None,
            "valid_to": None,
            "days_until_expiry": None,
            "expiration_status": "NOT_OBSERVABLE",
            "public_key_algorithm": None,
            "public_key_length": None,
            "signature_algorithm": None,
            "subject_alternative_names": [],
            "self_signed": None,
            "hostname_match": None,
            "trust_validation": "NOT_OBSERVABLE",
            "certificate_chain": {
                "certificate_count": len(cert_der_list),
                "chain_observable": False,
                "chain_status": "UNDETERMINED",
                "chain_complete": False,
                "chain_summary": chain_summary,
                "issuer_relationships": [],
                "validation_details": {
                    "signatures_verified": False,
                    "ca_constraints_verified": False,
                    "validity_periods_verified": False,
                    "trust_store_validation": "NOT_OBSERVABLE",
                    "revocation_check": "NOT_OBSERVABLE",
                    "revocation_note": "Passive network analysis cannot verify revocation without in-stream OCSP stapling or CRL records in the PCAP; external live queries are prohibited."
                }
            },
            "findings": [{
                "finding": "MALFORMED_CERTIFICATE_DATA",
                "severity": "HIGH",
                "reason": "Provided certificate DER bytes could not be decoded as standard X.509",
                "evidence": f"Total bytes: {sum(len(b) for b in cert_der_list)}"
            }],
            "evidence": []
        }

    # Primary leaf certificate is the first certificate in the TLS chain
    leaf_cert = parsed_chain[0]
    leaf_meta = extract_cert_metadata(leaf_cert, 0)

    # 1. Subject, Issuer, Common Name, Serial Number
    subject_str = leaf_meta["subject"]
    issuer_str = leaf_meta["issuer"]
    common_name = leaf_meta["common_name"]
    serial_number_hex = leaf_meta["serial_number"]

    # 2. Validity and Expiration Assessment
    valid_from_str = leaf_meta["valid_from"]
    valid_to_str = leaf_meta["valid_to"]
    days_until_expiry = leaf_meta["days_until_expiry"]
    expiration_status = leaf_meta["expiration_status"]

    if expiration_status == "EXPIRED":
        findings.append({
            "finding": "EXPIRED_CERTIFICATE",
            "severity": "HIGH",
            "reason": f"Certificate expired on {valid_to_str} ({abs(days_until_expiry)} days ago)",
            "evidence": f"not_valid_after: {valid_to_str}"
        })
    elif expiration_status == "NOT_YET_VALID":
        findings.append({
            "finding": "NOT_YET_VALID_CERTIFICATE",
            "severity": "HIGH",
            "reason": f"Certificate is not valid until {valid_from_str}",
            "evidence": f"not_valid_before: {valid_from_str}"
        })
    elif expiration_status == "EXPIRING_SOON":
        findings.append({
            "finding": "CERTIFICATE_EXPIRING_SOON",
            "severity": "MEDIUM",
            "reason": f"Certificate expires within {days_until_expiry} day(s) on {valid_to_str}",
            "evidence": f"Days remaining: {days_until_expiry}"
        })

    # 3. Public Key Algorithm and Key Length Assessment
    pub_key_algo = leaf_meta["public_key_algorithm"]
    pub_key_len = leaf_meta["public_key_length"]

    if pub_key_algo == "RSA" and pub_key_len is not None and pub_key_len < 2048:
        findings.append({
            "finding": "WEAK_RSA_KEY_LENGTH",
            "severity": "HIGH",
            "reason": f"RSA key length is {pub_key_len} bits, below the 2048-bit minimum cryptographic recommendation",
            "evidence": f"RSA modulus size: {pub_key_len} bits"
        })

    # 4. Signature Algorithm Assessment
    sig_algo_name = leaf_meta["signature_algorithm"]
    sig_algo_lower = sig_algo_name.lower()
    if any(weak_algo in sig_algo_lower for weak_algo in ("md5", "md2", "sha1")):
        findings.append({
            "finding": "DEPRECATED_SIGNATURE_ALGORITHM",
            "severity": "HIGH",
            "reason": f"Certificate signature uses weak/deprecated digest algorithm: {sig_algo_name}",
            "evidence": f"signature_algorithm: {sig_algo_name}"
        })

    # 5. Subject Alternative Names (SAN)
    sans = leaf_meta["subject_alternative_names"]

    # 6. Self-Signed Detection
    is_self_signed = leaf_meta["is_self_signed"]
    trust_validation = "NOT_OBSERVABLE"

    # 7. Hostname / SAN Verification against ClientHello SNI
    hostname_match: Optional[bool] = None
    if sni:
        candidate_names = list(sans)
        if common_name and common_name not in candidate_names:
            candidate_names.append(common_name)

        if candidate_names:
            hostname_match = any(match_hostname(sni, name) for name in candidate_names)
            if not hostname_match:
                findings.append({
                    "finding": "HOSTNAME_MISMATCH",
                    "severity": "MEDIUM",
                    "reason": f"ClientHello SNI '{sni}' does not match certificate SANs ({sans}) or Common Name '{common_name}'",
                    "evidence": f"SNI: '{sni}', Valid Subject Names: {candidate_names}"
                })
        else:
            hostname_match = False
            findings.append({
                "finding": "HOSTNAME_MISMATCH",
                "severity": "MEDIUM",
                "reason": f"Certificate contains no SANs or Common Name to match requested SNI '{sni}'",
                "evidence": f"SNI: '{sni}'"
            })

    # 8. Leaf Evidence
    evidence.append({
        "type": "x509_leaf_certificate",
        "subject": subject_str,
        "issuer": issuer_str,
        "valid_from": valid_from_str,
        "valid_to": valid_to_str,
        "public_key": f"{pub_key_algo} ({pub_key_len} bits)",
        "signature_algorithm": sig_algo_name,
        "sans": sans,
        "self_signed": is_self_signed,
        "description": f"X.509 certificate parsed for CN={common_name or 'Unknown'} with {pub_key_algo} key"
    })

    # 9. Full Certificate Chain Cryptographic Validation
    chain_dict, chain_findings, chain_evidence = validate_certificate_chain(parsed_chain)
    findings.extend(chain_findings)
    evidence.extend(chain_evidence)

    return {
        "certificate_present": True,
        "subject": subject_str,
        "issuer": issuer_str,
        "common_name": common_name,
        "serial_number": serial_number_hex,
        "valid_from": valid_from_str,
        "valid_to": valid_to_str,
        "days_until_expiry": days_until_expiry,
        "expiration_status": expiration_status,
        "expired": (expiration_status == "EXPIRED"),
        "not_yet_valid": (expiration_status == "NOT_YET_VALID"),
        "public_key_algorithm": pub_key_algo,
        "public_key_length": pub_key_len,
        "signature_algorithm": sig_algo_name,
        "subject_alternative_names": sans,
        "self_signed": is_self_signed,
        "hostname_match": hostname_match,
        "trust_validation": trust_validation,
        "certificate_chain": chain_dict,
        "findings": findings,
        "evidence": evidence
    }
