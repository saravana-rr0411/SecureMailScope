from typing import List, Dict, Any, Tuple
from scapy.all import IP, TCP, Raw
from app.capture.protocol_detector import detect_flow_protocol, SMTP_PORTS, IMAP_PORTS, POP3_PORTS
from app.tls.starttls_detector import assess_starttls
from app.tls.tls_parser import analyze_tls_session
from app.assessment.assessor import assess_session_security
from app.posture.posture_engine import calculate_security_posture
from app.ml.feature_extractor import extract_session_features
from app.ml.anomaly_detector import detector_instance
from app.ml.crypto_risk_scorer import crypto_risk_scorer_instance

KNOWN_EMAIL_PORTS = SMTP_PORTS | IMAP_PORTS | POP3_PORTS


def reconstruct_tcp_sessions(packets: List[Any]) -> List[Dict[str, Any]]:
    """
    Reconstructs bidirectional TCP sessions from a list of captured packets.
    Groups packets by (IP, Port) pairs regardless of direction, establishes
    client/server roles, preserves chronological order, and extracts metrics, payloads, STARTTLS state,
    cryptographic TLS parameters, deterministic assessment, posture scoring, ML features, and AI anomaly analysis.
    """
    raw_sessions: Dict[Tuple[str, str, int, int], List[Any]] = {}

    # 1. Group packets into bidirectional conversations
    for packet in packets:
        if IP in packet and TCP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            sport = int(packet[TCP].sport)
            dport = int(packet[TCP].dport)

            # Canonical conversation key for bidirectional grouping
            if (src_ip, sport) < (dst_ip, dport):
                conv_key = (src_ip, dst_ip, sport, dport)
            else:
                conv_key = (dst_ip, src_ip, dport, sport)

            if conv_key not in raw_sessions:
                raw_sessions[conv_key] = []
            raw_sessions[conv_key].append(packet)

    if not raw_sessions:
        return []

    # 2. Sort packets within each session by timestamp
    session_list = []
    for conv_key, pkt_list in raw_sessions.items():
        sorted_pkts = sorted(pkt_list, key=lambda p: float(p.time))
        session_list.append(sorted_pkts)

    # 3. Sort sessions chronologically by their first packet time
    session_list.sort(key=lambda pkts: float(pkts[0].time))

    reconstructed_sessions: List[Dict[str, Any]] = []

    for idx, pkts in enumerate(session_list):
        session_id = f"TCP-{idx + 1:03d}"
        first_pkt = pkts[0]

        # Determine Client vs Server
        client_ip = None
        client_port = None
        server_ip = None
        server_port = None

        # Heuristic 1: Look for SYN packet without ACK
        for p in pkts:
            flags = p[TCP].flags
            # If SYN is set and ACK is not set (TCP SYN initiation)
            if flags & 0x02 and not (flags & 0x10):
                client_ip = p[IP].src
                client_port = int(p[TCP].sport)
                server_ip = p[IP].dst
                server_port = int(p[TCP].dport)
                break

        # Heuristic 2: Check known service ports if SYN wasn't found
        if client_ip is None:
            for p in pkts:
                src_p = int(p[TCP].sport)
                dst_p = int(p[TCP].dport)
                if dst_p in KNOWN_EMAIL_PORTS and src_p not in KNOWN_EMAIL_PORTS:
                    client_ip = p[IP].src
                    client_port = src_p
                    server_ip = p[IP].dst
                    server_port = dst_p
                    break
                elif src_p in KNOWN_EMAIL_PORTS and dst_p not in KNOWN_EMAIL_PORTS:
                    client_ip = p[IP].dst
                    client_port = dst_p
                    server_ip = p[IP].src
                    server_port = src_p
                    break

        # Heuristic 3: Default to first packet's source as client
        if client_ip is None:
            client_ip = first_pkt[IP].src
            client_port = int(first_pkt[TCP].sport)
            server_ip = first_pkt[IP].dst
            server_port = int(first_pkt[TCP].dport)

        # 4. Extract directional metrics and payload streams
        c2s_packets = 0
        s2c_packets = 0
        c2s_bytes = 0
        s2c_bytes = 0
        c2s_payload_chunks: List[bytes] = []
        s2c_payload_chunks: List[bytes] = []
        all_payloads: List[bytes] = []
        ordered_messages: List[Tuple[str, bytes]] = []

        for p in pkts:
            is_c2s = (p[IP].src == client_ip and int(p[TCP].sport) == client_port)
            payload = bytes(p[Raw].load) if Raw in p else b""
            direction = "c2s" if is_c2s else "s2c"

            if is_c2s:
                c2s_packets += 1
                if payload:
                    c2s_bytes += len(payload)
                    c2s_payload_chunks.append(payload)
                    all_payloads.append(payload)
                    ordered_messages.append((direction, payload))
            else:
                s2c_packets += 1
                if payload:
                    s2c_bytes += len(payload)
                    s2c_payload_chunks.append(payload)
                    all_payloads.append(payload)
                    ordered_messages.append((direction, payload))

        start_time = float(pkts[0].time)
        end_time = float(pkts[-1].time)
        duration_seconds = round(end_time - start_time, 6)

        # 5. Detect protocol using protocol_detector
        protocol_info = detect_flow_protocol(
            source_ip=client_ip,
            source_port=client_port,
            destination_ip=server_ip,
            destination_port=server_port,
            payloads=all_payloads
        )

        client_payload_str = b"".join(c2s_payload_chunks).decode("utf-8", errors="replace")
        server_payload_str = b"".join(s2c_payload_chunks).decode("utf-8", errors="replace")

        # 6. Evaluate STARTTLS negotiation and validation
        starttls_assessment = assess_starttls(
            protocol=protocol_info["protocol"],
            ordered_messages=ordered_messages
        )

        # 7. Parse TLS Handshake and extract cryptographic parameters
        tls_analysis = analyze_tls_session(
            ordered_messages=ordered_messages
        )

        session_dict = {
            "session_id": session_id,
            "protocol": protocol_info["protocol"],
            "protocol_confidence": protocol_info["confidence"],
            "protocol_detection_method": protocol_info.get("detection_method", "UNKNOWN"),
            "source_ip": client_ip,
            "destination_ip": server_ip,
            "source_port": client_port,
            "destination_port": server_port,
            "start_time": start_time,
            "end_time": end_time,
            "duration_seconds": duration_seconds,
            "packet_count": len(pkts),
            "client_to_server_packets": c2s_packets,
            "server_to_client_packets": s2c_packets,
            "client_to_server_bytes": c2s_bytes,
            "server_to_client_bytes": s2c_bytes,
            "client_payload": client_payload_str,
            "server_payload": server_payload_str,
            "evidence": protocol_info["evidence"],
            "starttls": starttls_assessment,
            "tls": tls_analysis
        }

        # 8. Deterministic Security Posture Assessment
        security_assessment = assess_session_security(session_dict)
        session_dict["assessment"] = security_assessment

        # 9. Cross-Layer Security Posture Scoring & Correlation
        posture_profile = calculate_security_posture(session_dict)
        session_dict["posture"] = posture_profile

        # 10. ML Feature Extraction
        ml_features = extract_session_features(session_dict)
        session_dict["ml_features"] = ml_features

        # 11. AI Anomaly Detection Analysis
        ai_analysis = detector_instance.predict(session_dict)
        session_dict["ai_analysis"] = ai_analysis

        # 12. AI Cryptographic Risk Scoring
        ai_risk = crypto_risk_scorer_instance.predict(session_dict)
        session_dict["ai_risk"] = ai_risk

        reconstructed_sessions.append(session_dict)

    return reconstructed_sessions
