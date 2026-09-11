import os
from scapy.all import PcapReader, IP, TCP, UDP
from app.capture.protocol_detector import detect_protocols_from_packets
from app.reconstruction.tcp_reconstructor import reconstruct_tcp_sessions

def analyze_pcap(file_path: str) -> dict:
    if not os.path.exists(file_path):
        raise ValueError("File does not exist")
    
    if not file_path.lower().endswith(('.pcap', '.pcapng')):
        raise ValueError("Unsupported file extension. Only .pcap and .pcapng are allowed.")
    
    if os.path.getsize(file_path) == 0:
        raise ValueError("PCAP file is empty")
    
    total_packets = 0
    tcp_packets = 0
    udp_packets = 0
    other_packets = 0
    
    source_ips = set()
    destination_ips = set()
    
    capture_start_time = None
    capture_end_time = None
    all_packets = []

    try:
        with PcapReader(file_path) as pcap_reader:
            for packet in pcap_reader:
                total_packets += 1
                all_packets.append(packet)
                
                packet_time = float(packet.time)
                if capture_start_time is None or packet_time < capture_start_time:
                    capture_start_time = packet_time
                if capture_end_time is None or packet_time > capture_end_time:
                    capture_end_time = packet_time

                if IP in packet:
                    source_ips.add(packet[IP].src)
                    destination_ips.add(packet[IP].dst)
                
                if TCP in packet:
                    tcp_packets += 1
                elif UDP in packet:
                    udp_packets += 1
                else:
                    other_packets += 1
    except Exception as e:
        raise ValueError(f"Invalid PCAP file: {str(e)}")

    if total_packets == 0:
        raise ValueError("PCAP file contains no packets")

    duration = None
    if capture_start_time is not None and capture_end_time is not None:
        duration = capture_end_time - capture_start_time

    # Detect email protocols from captured packets
    protocols = detect_protocols_from_packets(all_packets)

    # Reconstruct TCP sessions
    sessions = reconstruct_tcp_sessions(all_packets)

    # Establish canonical capture-level AI risk and security posture from representative primary session
    def select_primary_session(sessions_list: list) -> dict:
        if not sessions_list:
            return None
        if len(sessions_list) == 1:
            return sessions_list[0]

        # Prioritize sessions with confirmed security findings if any exist
        vulnerable_sessions = [
            s for s in sessions_list
            if (isinstance(s, dict) and (
                (s.get("assessment") or {}).get("critical_count", 0) > 0 or
                (s.get("assessment") or {}).get("high_count", 0) > 0 or
                (s.get("posture") or {}).get("security_posture") in ("AT_RISK", "COMPROMISED")
            ))
        ]
        if vulnerable_sessions:
            return max(vulnerable_sessions, key=lambda s: len((s.get("assessment") or {}).get("findings") or []))

        # Otherwise, rank sessions by completeness and application traffic volume
        def session_rank(s):
            if not isinstance(s, dict):
                return 0
            tls = s.get("tls") or {}
            tls_detected = bool(tls.get("detected"))
            hs_status = tls.get("handshake_status") or tls.get("tls_handshake_status")
            app_data = bool(tls.get("encrypted_application_data_observed"))
            total_bytes = s.get("client_to_server_bytes", 0) + s.get("server_to_client_bytes", 0)
            pkt_count = s.get("packet_count", 0)
            evidence = s.get("evidence") or []
            has_app_evidence = any(isinstance(e, dict) and e.get("type") in ("banner", "payload", "command", "response") for e in evidence)

            rank = 0
            if tls_detected:
                rank += 10000
            if hs_status == "COMPLETE":
                rank += 5000
            if app_data:
                rank += 2500
            if has_app_evidence:
                rank += 1000
            rank += min(total_bytes, 1000)
            rank += min(pkt_count, 100)
            return rank

        return max(sessions_list, key=session_rank)

    primary_session = select_primary_session(sessions)
    primary_ai_risk = primary_session.get("ai_risk") if primary_session else None
    primary_posture = primary_session.get("posture") if primary_session else None

    return {
        "filename": os.path.basename(file_path),
        "total_packets": total_packets,
        "tcp_packets": tcp_packets,
        "udp_packets": udp_packets,
        "other_packets": other_packets,
        "source_ips": list(source_ips),
        "destination_ips": list(destination_ips),
        "unique_source_ips": len(source_ips),
        "unique_destination_ips": len(destination_ips),
        "capture_start_time": capture_start_time,
        "capture_end_time": capture_end_time,
        "capture_duration_seconds": duration,
        "protocols": protocols,
        "sessions": sessions,
        "ai_risk": primary_ai_risk,
        "posture": primary_posture
    }
