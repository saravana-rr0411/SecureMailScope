#!/usr/bin/env python3
"""
Minimal Independent tcpdump Verification on macOS lo0
Tests that tcpdump with --immediate-mode on loopback lo0 captures real TCP traffic.
"""
import os
import sys
import time
import socket
import signal
import subprocess
import select
from pathlib import Path

def test_minimal_tcpdump():
    pcap_path = "/tmp/minimal_test_capture.pcap"
    if os.path.exists(pcap_path):
        os.remove(pcap_path)

    port = 2525
    host = "127.0.0.1"
    bpf_filter = f"tcp and port {port} and host {host}"

    print(f"[*] Minimal tcpdump Test on lo0:")
    print(f"    - Filter: {bpf_filter}")
    print(f"    - Output: {pcap_path}")

    # 1. Start a simple TCP listening socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((host, port))
    server_sock.listen(1)
    print(f"[+] TCP server listening on {host}:{port}")

    # 2. Launch tcpdump with --immediate-mode
    cmd = [
        "/usr/sbin/tcpdump",
        "--immediate-mode",
        "-i", "lo0",
        "-s", "0",
        "-U",
        "-w", pcap_path,
        bpf_filter
    ]

    print(f"[*] Starting tcpdump: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )

    # 3. Wait for tcpdump to report "listening on lo0"
    ready = False
    start_time = time.time()
    startup_lines = []
    while time.time() - start_time < 5.0:
        if proc.poll() is not None:
            err = proc.stderr.read()
            print(f"[-] tcpdump exited prematurely ({proc.returncode}): {err}")
            server_sock.close()
            return False

        rlist, _, _ = select.select([proc.stderr], [], [], 0.05)
        if rlist:
            line = proc.stderr.readline()
            if line:
                startup_lines.append(line.strip())
                print(f"    [tcpdump] {line.strip()}")
                if "listening on" in line.lower():
                    ready = True
                    break

    if not ready:
        print("[!] Warning: 'listening on' was not caught, but checking if process is running...")
        if proc.poll() is not None:
            server_sock.close()
            return False

    time.sleep(0.2)
    print(f"[+] tcpdump confirmed active (PID: {proc.pid})")

    # 4. Generate real TCP traffic
    print("[*] Generating real TCP socket traffic on 127.0.0.1:2525...")
    client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_sock.connect((host, port))
    conn, addr = server_sock.accept()

    for i in range(5):
        msg = f"TEST_MESSAGE_{i}\r\n".encode("utf-8")
        client_sock.sendall(msg)
        recv = conn.recv(1024)
        conn.sendall(b"OK\r\n")
        reply = client_sock.recv(1024)

    client_sock.close()
    conn.close()
    server_sock.close()
    print("[+] Sockets closed cleanly.")

    # 5. Settle delay for TCP teardown
    time.sleep(0.5)

    # 6. Stop tcpdump
    print("[*] Sending SIGINT to tcpdump...")
    proc.send_signal(signal.SIGINT)
    stdout_data, stderr_data = proc.communicate(timeout=3.0)
    print(f"    [tcpdump exit stats]\n{stderr_data.strip()}")

    # 7. Check file size
    if not os.path.exists(pcap_path):
        print("[-] PCAP file was not created!")
        return False

    size = os.path.getsize(pcap_path)
    print(f"[+] Captured PCAP File Size: {size:,} bytes")
    if size > 24:
        print(f"[SUCCESS] Real packets were successfully captured and written ({size} bytes > 24 bytes)!")
        return True
    else:
        print(f"[FAILURE] Only the 24-byte PCAP header was written.")
        return False

if __name__ == "__main__":
    test_minimal_tcpdump()
