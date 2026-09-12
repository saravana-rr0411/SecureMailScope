import re
from typing import List, Dict, Any, Optional, Tuple

# TLS Record Header detection (0x16 = Handshake, 0x03 = SSL 3.0/TLS 1.x)
def has_tls_handshake_header(payload: bytes) -> bool:
    """Checks if payload begins with or contains a standard TLS Handshake record header."""
    if len(payload) >= 5 and payload[0] == 0x16 and payload[1] == 0x03 and payload[2] in (0x00, 0x01, 0x02, 0x03):
        return True
    # In case of small leading framing or fragmented packet
    idx = payload.find(b"\x16\x03")
    if idx != -1 and len(payload) >= idx + 5 and payload[idx + 2] in (0x00, 0x01, 0x02, 0x03):
        return True
    return False


def decode_lines(payload: bytes) -> List[str]:
    """Decodes payload to lines cleanly."""
    lines = []
    try:
        text = payload.decode("utf-8", errors="replace")
        for line in text.splitlines():
            s = line.strip()
            if s:
                lines.append(s)
    except Exception:
        pass
    return lines


def assess_starttls(
    protocol: str,
    ordered_messages: List[Tuple[str, bytes]],
    port: Optional[int] = None
) -> Dict[str, Any]:
    """
    Evaluates STARTTLS / STLS negotiation sequence across chronological session messages.
    ordered_messages is a list of tuples: ("c2s" | "s2c", raw_payload_bytes).
    """
    if protocol == "SMTP" and port == 465:
        has_tls = any(has_tls_handshake_header(raw_bytes) for _, raw_bytes in ordered_messages if raw_bytes)
        return {
            "upgrade_supported": None,
            "upgrade_requested": False,
            "upgrade_accepted": None,
            "tls_transition_observed": has_tls,
            "status": "DIRECT_TLS",
            "transport_mode": "IMPLICIT_TLS",
            "submission_type": "implicit TLS SMTP",
            "evidence": [{
                "type": "transport",
                "value": "port 465",
                "description": "SMTP over implicit TLS (port 465); direct TLS encryption without STARTTLS negotiation"
            }]
        }

    upgrade_supported: Optional[bool] = None
    upgrade_requested: bool = False
    upgrade_accepted: Optional[bool] = None
    tls_transition_observed: Optional[bool] = None
    status = "NOT_OBSERVABLE"
    evidence: List[Dict[str, Any]] = []

    if protocol not in ("SMTP", "IMAP", "POP3"):
        return {
            "upgrade_supported": None,
            "upgrade_requested": False,
            "upgrade_accepted": None,
            "tls_transition_observed": None,
            "status": "NOT_OBSERVABLE",
            "evidence": [{
                "type": "info",
                "description": f"STARTTLS assessment is not applicable for protocol: {protocol}"
            }]
        }

    # State tracking
    starttls_command_seen = False
    starttls_accepted_seen = False
    starttls_command_tag: Optional[str] = None

    for msg_idx, (direction, raw_bytes) in enumerate(ordered_messages):
        if not raw_bytes:
            continue

        # If upgrade was accepted in a previous step, check if TLS handshake begins
        if starttls_accepted_seen:
            if has_tls_handshake_header(raw_bytes):
                tls_transition_observed = True
                evidence.append({
                    "type": "tls_handshake",
                    "value": "TLS Handshake ClientHello (0x1603...)",
                    "description": f"Observed TLS record header in subsequent {direction.upper()} packet"
                })
                break
            else:
                # Received non-TLS payload after accepted STARTTLS
                continue

        lines = decode_lines(raw_bytes)

        # -------------------------------------------------------------
        # SMTP STARTTLS Evaluation
        # -------------------------------------------------------------
        if protocol == "SMTP":
            if direction == "s2c":
                # Check for capability advertisement
                for line in lines:
                    if re.search(r"^250[- ]STARTTLS\b", line, re.IGNORECASE):
                        upgrade_supported = True
                        evidence.append({
                            "type": "capability",
                            "value": line,
                            "description": "Server advertised STARTTLS capability in EHLO response"
                        })
                    elif line.startswith("250") and upgrade_supported is None:
                        # Server sent 250 response without STARTTLS
                        pass

                # If client already sent STARTTLS command, check server response
                if starttls_command_seen and upgrade_accepted is None:
                    for line in lines:
                        if line.startswith("220"):
                            upgrade_accepted = True
                            starttls_accepted_seen = True
                            evidence.append({
                                "type": "response",
                                "value": line,
                                "description": "Server accepted STARTTLS upgrade"
                            })
                            break
                        elif re.match(r"^(?:454|501|502|503|550)\b", line):
                            upgrade_accepted = False
                            evidence.append({
                                "type": "response",
                                "value": line,
                                "description": "Server rejected STARTTLS upgrade"
                            })
                            break

            elif direction == "c2s":
                for line in lines:
                    if re.match(r"^STARTTLS\b", line, re.IGNORECASE):
                        upgrade_requested = True
                        starttls_command_seen = True
                        evidence.append({
                            "type": "command",
                            "value": line,
                            "description": "Client requested STARTTLS upgrade"
                        })
                        break

        # -------------------------------------------------------------
        # IMAP STARTTLS Evaluation
        # -------------------------------------------------------------
        elif protocol == "IMAP":
            if direction == "s2c":
                for line in lines:
                    if re.search(r"\bSTARTTLS\b", line, re.IGNORECASE) and (line.startswith("*") or "CAPABILITY" in line.upper()):
                        upgrade_supported = True
                        evidence.append({
                            "type": "capability",
                            "value": line,
                            "description": "Server advertised STARTTLS in IMAP capabilities"
                        })

                if starttls_command_seen and upgrade_accepted is None:
                    for line in lines:
                        match_ok = re.match(r"^([A-Za-z0-9]+)\s+OK\b", line, re.IGNORECASE)
                        match_bad = re.match(r"^([A-Za-z0-9]+)\s+(?:NO|BAD)\b", line, re.IGNORECASE)
                        if match_ok:
                            tag = match_ok.group(1)
                            if starttls_command_tag is None or tag.upper() == starttls_command_tag.upper():
                                upgrade_accepted = True
                                starttls_accepted_seen = True
                                evidence.append({
                                    "type": "response",
                                    "value": line,
                                    "description": "Server accepted IMAP STARTTLS upgrade"
                                })
                                break
                        elif match_bad:
                            tag = match_bad.group(1)
                            if starttls_command_tag is None or tag.upper() == starttls_command_tag.upper():
                                upgrade_accepted = False
                                evidence.append({
                                    "type": "response",
                                    "value": line,
                                    "description": "Server rejected IMAP STARTTLS upgrade"
                                })
                                break

            elif direction == "c2s":
                for line in lines:
                    match_cmd = re.match(r"^([A-Za-z0-9]+)\s+STARTTLS\b", line, re.IGNORECASE)
                    if match_cmd:
                        upgrade_requested = True
                        starttls_command_seen = True
                        starttls_command_tag = match_cmd.group(1)
                        evidence.append({
                            "type": "command",
                            "value": line,
                            "description": "Client issued IMAP STARTTLS command"
                        })
                        break
                    elif re.match(r"^STARTTLS\b", line, re.IGNORECASE):
                        upgrade_requested = True
                        starttls_command_seen = True
                        evidence.append({
                            "type": "command",
                            "value": line,
                            "description": "Client issued IMAP STARTTLS command"
                        })
                        break

        # -------------------------------------------------------------
        # POP3 STLS Evaluation
        # -------------------------------------------------------------
        elif protocol == "POP3":
            if direction == "s2c":
                for line in lines:
                    if re.search(r"\bSTLS\b", line, re.IGNORECASE):
                        upgrade_supported = True
                        evidence.append({
                            "type": "capability",
                            "value": line,
                            "description": "Server advertised STLS capability in POP3 CAPA response"
                        })

                if starttls_command_seen and upgrade_accepted is None:
                    for line in lines:
                        if line.startswith("+OK"):
                            upgrade_accepted = True
                            starttls_accepted_seen = True
                            evidence.append({
                                "type": "response",
                                "value": line,
                                "description": "Server accepted POP3 STLS upgrade"
                            })
                            break
                        elif line.startswith("-ERR"):
                            upgrade_accepted = False
                            evidence.append({
                                "type": "response",
                                "value": line,
                                "description": "Server rejected POP3 STLS upgrade"
                            })
                            break

            elif direction == "c2s":
                for line in lines:
                    if re.match(r"^STLS\b", line, re.IGNORECASE):
                        upgrade_requested = True
                        starttls_command_seen = True
                        evidence.append({
                            "type": "command",
                            "value": line,
                            "description": "Client requested POP3 STLS upgrade"
                        })
                        break

    # Determine final TLS transition state if accepted
    if starttls_accepted_seen and tls_transition_observed is None:
        tls_transition_observed = False

    # Determine overall status
    if upgrade_accepted is True:
        if tls_transition_observed is True:
            status = "SECURE_TRANSITION"
        else:
            # PCAP ends or TLS handshake was not observable
            status = "INCOMPLETE"
    elif upgrade_requested is True and upgrade_accepted is False:
        status = "NOT_USED"
    elif upgrade_requested is False:
        if upgrade_supported is not None:
            status = "NOT_USED"
        else:
            status = "NOT_OBSERVABLE"
    else:
        status = "INCOMPLETE" if starttls_command_seen else "NOT_OBSERVABLE"

    # If upgrade_supported wasn't explicitly found but capability was given
    if upgrade_supported is None and protocol in ("SMTP", "IMAP", "POP3"):
        # Check if server presented capability banner that lacked STARTTLS
        if any("250" in e.get("value", "") for e in evidence if e["type"] == "capability"):
            upgrade_supported = False

    res = {
        "upgrade_supported": upgrade_supported,
        "upgrade_requested": upgrade_requested,
        "upgrade_accepted": upgrade_accepted,
        "tls_transition_observed": tls_transition_observed,
        "status": status,
        "evidence": evidence
    }
    if protocol == "SMTP":
        if port == 587:
            res["transport_mode"] = "STARTTLS"
            res["submission_type"] = "SMTP STARTTLS"
        elif port == 465:
            res["transport_mode"] = "IMPLICIT_TLS"
            res["submission_type"] = "implicit TLS SMTP"
    return res
