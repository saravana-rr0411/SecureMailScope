from typing import List, Dict, Any
from app.assessment.rules import (
    evaluate_tls_version_rule,
    evaluate_cipher_suite_rule,
    evaluate_forward_secrecy_rule,
    evaluate_starttls_negotiation_rule,
    evaluate_certificate_security_rule,
    evaluate_certificate_chain_rule
)


def assess_session_security(session: Dict[str, Any]) -> Dict[str, Any]:
    """
    Executes deterministic, explainable security rules against a reconstructed email session.
    Consumes protocol, STARTTLS, TLS parameters, and X.509 certificate metadata.
    """
    protocol = session.get("protocol", "UNKNOWN")
    starttls_info = session.get("starttls", {})
    tls_info = session.get("tls", {})
    cert_info = tls_info.get("certificate", {})

    raw_findings: List[Dict[str, Any]] = []

    # 1. TLS Version Evaluation
    raw_findings.extend(evaluate_tls_version_rule(tls_info))

    # 2. Cipher Suite Evaluation
    raw_findings.extend(evaluate_cipher_suite_rule(tls_info))

    # 3. Key Exchange & Forward Secrecy Evaluation
    raw_findings.extend(evaluate_forward_secrecy_rule(tls_info))

    # 4. STARTTLS Negotiation Evaluation
    raw_findings.extend(evaluate_starttls_negotiation_rule(starttls_info, tls_info, protocol))

    # 5. X.509 Certificate Evaluation
    raw_findings.extend(evaluate_certificate_security_rule(cert_info))

    # 6. X.509 Certificate Chain Evaluation
    raw_findings.extend(evaluate_certificate_chain_rule(cert_info))

    # Assign deterministic finding IDs
    findings: List[Dict[str, Any]] = []
    for idx, f in enumerate(raw_findings):
        finding_obj = {
            "finding_id": f"SEC-{idx + 1:03d}",
            "category": f.get("category", "CRYPTOGRAPHY"),
            "title": f.get("title", "Security Finding"),
            "severity": f.get("severity", "MEDIUM"),
            "reason": f.get("reason", ""),
            "description": f.get("description") or f.get("reason", ""),
            "evidence": f.get("evidence", []),
            "recommendation": f.get("recommendation", "")
        }
        findings.append(finding_obj)

    critical_count = sum(1 for f in findings if f["severity"] == "CRITICAL")
    high_count = sum(1 for f in findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in findings if f["severity"] == "MEDIUM")
    low_count = sum(1 for f in findings if f["severity"] == "LOW")

    # Determine deterministic security status
    if critical_count > 0 or high_count > 0 or medium_count > 0:
        security_status = "AT_RISK"
    elif starttls_info.get("status") == "INCOMPLETE" and not tls_info.get("detected"):
        security_status = "INCOMPLETE"
    elif tls_info.get("detected") is True:
        security_status = "SECURE"
    elif protocol in ("SMTP", "IMAP", "POP3") and not tls_info.get("detected"):
        security_status = "AT_RISK"
    else:
        security_status = "NOT_OBSERVABLE"

    return {
        "security_status": security_status,
        "finding_count": len(findings),
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "findings": findings
    }
