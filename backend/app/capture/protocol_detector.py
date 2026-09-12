import re
from typing import List, Dict, Any, Optional, Tuple
from scapy.all import IP, IPv6, TCP, Raw

# Well-known email ports
SMTP_PORTS = {25, 587, 465, 2525}
IMAP_PORTS = {143, 993}
POP3_PORTS = {110, 995}

# Regex patterns for SMTP
SMTP_BANNER_REGEX = re.compile(r"^220[ -](?:[^\r\n]*)", re.IGNORECASE)
SMTP_RESPONSE_REGEX = re.compile(r"^(?:250|354|221|421|550|500|502)[ -](?:[^\r\n]*)", re.IGNORECASE)
SMTP_CMD_REGEX = re.compile(r"^(?:EHLO|HELO|MAIL FROM:|RCPT TO:|STARTTLS|DATA|RSET|QUIT|AUTH\s+(?:PLAIN|LOGIN|CRAM-MD5)|VRFY|EXPN)\b", re.IGNORECASE)

# Regex patterns for IMAP
IMAP_UNTAGGED_REGEX = re.compile(r"^\*\s+(?:OK|PREAUTH|BYE|CAPABILITY|LIST|LSUB|FLAGS|SEARCH|\d+\s+EXISTS|\d+\s+RECENT)\b", re.IGNORECASE)
IMAP_TAGGED_CMD_REGEX = re.compile(r"^[A-Za-z0-9]+\s+(?:LOGIN|SELECT|EXAMINE|CREATE|DELETE|RENAME|SUBSCRIBE|UNSUBSCRIBE|LIST|LSUB|STATUS|APPEND|CHECK|CLOSE|EXPUNGE|SEARCH|FETCH|STORE|COPY|UID|CAPABILITY|NOOP|LOGOUT|STARTTLS|AUTHENTICATE|ID)\b", re.IGNORECASE)
IMAP_TAGGED_RESP_REGEX = re.compile(r"^[A-Za-z0-9]+\s+(?:OK|NO|BAD)\b", re.IGNORECASE)

# Regex patterns for POP3
POP3_RESP_REGEX = re.compile(r"^(?:\+OK|-ERR)\b", re.IGNORECASE)
POP3_CMD_REGEX = re.compile(r"^(?:USER|PASS|STAT|LIST|RETR|DELE|NOOP|RSET|QUIT|TOP|UIDL|APOP|STLS|CAPA|AUTH)\b", re.IGNORECASE)


def extract_lines(payload: bytes) -> List[str]:
    """Extract clean ASCII/UTF-8 decoded lines from raw payload bytes."""
    lines = []
    try:
        text = payload.decode("utf-8", errors="replace")
        for line in text.splitlines():
            line = line.strip()
            if line:
                lines.append(line)
    except Exception:
        pass
    return lines


def analyze_payload_indicators(lines: List[str]) -> Dict[str, List[Dict[str, str]]]:
    """
    Inspects payload lines to discover protocol-specific indicators.
    Returns categorized evidence for SMTP, IMAP, and POP3.
    """
    evidence = {
        "SMTP": [],
        "IMAP": [],
        "POP3": []
    }

    for line in lines:
        # Check SMTP
        if SMTP_BANNER_REGEX.match(line):
            evidence["SMTP"].append({"type": "banner", "value": line})
        elif SMTP_CMD_REGEX.match(line):
            evidence["SMTP"].append({"type": "payload", "value": line})
        elif SMTP_RESPONSE_REGEX.match(line):
            evidence["SMTP"].append({"type": "payload", "value": line})

        # Check IMAP
        if IMAP_UNTAGGED_REGEX.match(line):
            evidence["IMAP"].append({"type": "banner" if "* OK" in line.upper() else "payload", "value": line})
        elif IMAP_TAGGED_CMD_REGEX.match(line):
            evidence["IMAP"].append({"type": "payload", "value": line})
        elif IMAP_TAGGED_RESP_REGEX.match(line):
            evidence["IMAP"].append({"type": "payload", "value": line})

        # Check POP3
        if POP3_RESP_REGEX.match(line):
            evidence["POP3"].append({"type": "banner" if line.upper().startswith("+OK") else "payload", "value": line})
        elif POP3_CMD_REGEX.match(line):
            evidence["POP3"].append({"type": "payload", "value": line})

    return evidence


def detect_flow_protocol(
    source_ip: str,
    source_port: int,
    destination_ip: str,
    destination_port: int,
    payloads: List[bytes]
) -> Dict[str, Any]:
    """
    Determines application protocol for a specific TCP flow using both payload analysis and port context.
    """
    # Aggregate payload lines
    all_lines = []
    for p in payloads:
        all_lines.extend(extract_lines(p))

    evidence_by_proto = analyze_payload_indicators(all_lines)
    
    smtp_ev = evidence_by_proto["SMTP"]
    imap_ev = evidence_by_proto["IMAP"]
    pop3_ev = evidence_by_proto["POP3"]

    ports = {source_port, destination_port}
    matched_ports = {
        "SMTP": ports.intersection(SMTP_PORTS),
        "IMAP": ports.intersection(IMAP_PORTS),
        "POP3": ports.intersection(POP3_PORTS),
    }

    protocol = "UNKNOWN"
    confidence = "LOW"
    sub_type = "UNKNOWN"
    final_evidence: List[Dict[str, Any]] = []

    # Check payload evidence with priority
    if smtp_ev and len(smtp_ev) >= len(imap_ev) and len(smtp_ev) >= len(pop3_ev):
        protocol = "SMTP"
        confidence = "HIGH"
        if matched_ports["SMTP"]:
            port_val = list(matched_ports["SMTP"])[0]
            if port_val == 465:
                sub_type = "implicit TLS SMTP"
                port_desc = "Standard SMTP over implicit TLS submission port (465)"
            elif port_val == 587:
                sub_type = "SMTP STARTTLS"
                port_desc = "Standard SMTP submission port (587) with STARTTLS"
            else:
                sub_type = "SMTP"
                port_desc = f"Standard SMTP port ({port_val})"
            final_evidence.append({
                "type": "port",
                "value": port_val,
                "description": port_desc
            })
        else:
            sub_type = "SMTP"
        final_evidence.extend(smtp_ev)

    elif imap_ev and len(imap_ev) >= len(pop3_ev):
        protocol = "IMAP"
        sub_type = "IMAP"
        confidence = "HIGH"
        if matched_ports["IMAP"]:
            port_val = list(matched_ports["IMAP"])[0]
            final_evidence.append({
                "type": "port",
                "value": port_val,
                "description": f"Standard IMAP port ({port_val})"
            })
        final_evidence.extend(imap_ev)

    elif pop3_ev:
        protocol = "POP3"
        sub_type = "POP3"
        confidence = "HIGH"
        if matched_ports["POP3"]:
            port_val = list(matched_ports["POP3"])[0]
            final_evidence.append({
                "type": "port",
                "value": port_val,
                "description": f"Standard POP3 port ({port_val})"
            })
        final_evidence.extend(pop3_ev)

    # If no payload evidence, evaluate port context
    elif matched_ports["SMTP"]:
        protocol = "SMTP"
        confidence = "MEDIUM"
        port_val = list(matched_ports["SMTP"])[0]
        if port_val == 465:
            sub_type = "implicit TLS SMTP"
            port_desc = "Standard SMTP over implicit TLS submission port (465)"
        elif port_val == 587:
            sub_type = "SMTP STARTTLS"
            port_desc = "Standard SMTP submission port (587) with STARTTLS"
        else:
            sub_type = "SMTP"
            port_desc = f"Traffic detected on standard SMTP port ({port_val}) with no explicit protocol payload"
        final_evidence.append({
            "type": "port",
            "value": port_val,
            "description": port_desc
        })

    elif matched_ports["IMAP"]:
        protocol = "IMAP"
        sub_type = "IMAP"
        confidence = "MEDIUM"
        port_val = list(matched_ports["IMAP"])[0]
        final_evidence.append({
            "type": "port",
            "value": port_val,
            "description": f"Traffic detected on standard IMAP port ({port_val}) with no explicit protocol payload"
        })

    elif matched_ports["POP3"]:
        protocol = "POP3"
        sub_type = "POP3"
        confidence = "MEDIUM"
        port_val = list(matched_ports["POP3"])[0]
        final_evidence.append({
            "type": "port",
            "value": port_val,
            "description": f"Traffic detected on standard POP3 port ({port_val}) with no explicit protocol payload"
        })

    else:
        protocol = "UNKNOWN"
        sub_type = "UNKNOWN"
        confidence = "LOW"
        final_evidence.append({
            "type": "info",
            "description": "No recognized email protocol signatures or ports detected"
        })

    # Determine canonical client/server ordering for reporting
    # If destination port is standard service port, source is client, destination is server
    is_server_dst = destination_port in (SMTP_PORTS | IMAP_PORTS | POP3_PORTS)
    is_server_src = source_port in (SMTP_PORTS | IMAP_PORTS | POP3_PORTS)

    c_ip, c_port = source_ip, source_port
    s_ip, s_port = destination_ip, destination_port

    if is_server_src and not is_server_dst:
        c_ip, c_port = destination_ip, destination_port
        s_ip, s_port = source_ip, source_port

    return {
        "protocol": protocol,
        "submission_type": sub_type,
        "confidence": confidence,
        "detection_method": "APPLICATION_DATA" if confidence == "HIGH" else ("PORT_INFERRED" if confidence == "MEDIUM" else "UNKNOWN"),
        "source_ip": c_ip,
        "destination_ip": s_ip,
        "source_port": c_port,
        "destination_port": s_port,
        "evidence": final_evidence
    }


def detect_protocols_from_packets(packets: List[Any]) -> List[Dict[str, Any]]:
    """
    Groups TCP packets by bidirectional conversation flows and returns protocol analysis for each flow.
    """
    flows: Dict[Tuple[str, str, int, int], List[bytes]] = {}
    flow_endpoints: Dict[Tuple[str, str, int, int], Tuple[str, int, str, int]] = {}

    for packet in packets:
        if (IP in packet or IPv6 in packet) and TCP in packet:
            src_ip = packet[IP].src if IP in packet else packet[IPv6].src
            dst_ip = packet[IP].dst if IP in packet else packet[IPv6].dst
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            # Canonical flow key
            if (src_ip, sport) < (dst_ip, dport):
                flow_key = (src_ip, dst_ip, sport, dport)
            else:
                flow_key = (dst_ip, src_ip, dport, sport)

            if flow_key not in flows:
                flows[flow_key] = []
                flow_endpoints[flow_key] = (src_ip, sport, dst_ip, dport)

            if Raw in packet:
                payload = bytes(packet[Raw].load)
                flows[flow_key].append(payload)

    results = []
    for flow_key, payloads in flows.items():
        src_ip, sport, dst_ip, dport = flow_endpoints[flow_key]
        flow_analysis = detect_flow_protocol(
            source_ip=src_ip,
            source_port=sport,
            destination_ip=dst_ip,
            destination_port=dport,
            payloads=payloads
        )
        results.append(flow_analysis)

    return results
