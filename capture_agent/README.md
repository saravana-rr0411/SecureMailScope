# SecureMailScope Local Capture Agent

The **SecureMailScope Local Capture Agent** is a dedicated, user-local background service for macOS that enables the SecureMailScope web platform to capture genuine, non-synthetic network packets from real email protocols (SMTP, STARTTLS, TLS 1.2, POP3, IMAP).

---

## 1. Installation

### Option A: Standard macOS Installer (`.pkg`) — Recommended

1. Build the installer package (or download the release):
   ```bash
   bash capture_agent/macos/build_pkg.sh
   ```
2. Double-click `dist/SecureMailScopeCaptureAgent-1.0.0.pkg` to open the standard macOS Installer GUI, or run via terminal:
   ```bash
   sudo installer -pkg dist/SecureMailScopeCaptureAgent-1.0.0.pkg -target /
   ```
3. The installer automatically:
   - Installs the agent into `/Library/Application Support/SecureMailScope/CaptureAgent`.
   - Registers and launches the background daemon via `launchd` (`/Library/LaunchDaemons/com.securemailscope.captureagent.plist`).
   - Starts the HTTP service listening strictly on `http://127.0.0.1:9000`.
   - Verifies the agent is healthy and ready.

### Option B: Quick Shell Installer

For developers wishing to run the setup script directly:
```bash
cd capture_agent/macos && sudo ./install.sh
```

---

## 2. Uninstallation

To completely stop and remove the agent and all associated files from your Mac:

```bash
sudo "/Library/Application Support/SecureMailScope/CaptureAgent/bin/uninstall.sh"
```
Or from the project repository:
```bash
cd capture_agent/macos && sudo ./uninstall.sh
```

This will:
1. Unload the `com.securemailscope.captureagent` LaunchDaemon via `launchctl`.
2. Terminate any running agent processes.
3. Remove `/Library/LaunchDaemons/com.securemailscope.captureagent.plist`.
4. Delete `/Library/Application Support/SecureMailScope/CaptureAgent`.
5. Remove log files from `/var/log/securemailscope-capture-agent*.log`.

---

## 3. Required Permissions & System Security

- **Why does the agent require root/administrator privileges to install?**
  On macOS, raw packet capture via the Berkeley Packet Filter (`/dev/bpf*`) is restricted by the Darwin kernel to privileged processes. The agent runs as a system LaunchDaemon (`root:wheel 0644`), giving `tcpdump` the necessary native kernel capability to open BPF descriptors without weakening macOS system security.
- **No Insecure `/dev/bpf` Permission Changes**:
  The installer **never** runs `chmod 666 /dev/bpf*`. System device node permissions remain untouched at factory defaults (`crw------- root:wheel`).
- **Loopback Binding Only**:
  The HTTP server binds strictly to `127.0.0.1:9000`. It is never exposed on `0.0.0.0`, Wi-Fi, Ethernet, or the local network (LAN).
- **DNS Rebinding & CORS Protection**:
  The agent enforces a strict `Origin` whitelist (only authorized SecureMailScope web origins) and validates the `Host` header (`127.0.0.1:9000` / `localhost:9000`), rejecting unauthorized cross-site requests with `403 Forbidden`.
- **Ephemeral Handshake Authentication**:
  No long-lived API keys or passwords exist in the web browser bundle. When you click **Generate Authentic PCAP**, the website requests a single-use, 60-second ephemeral session token via `/api/v1/auth/handshake` which is immediately invalidated upon first use.

---

## 4. What Data Does the Agent Capture?

### Strict Privacy Guarantee
The agent **never** sniffs your personal web browsing, passwords, or arbitrary network traffic. 

Every packet capture is executed using a hardcoded, immutable Berkeley Packet Filter targeting **strictly** the controlled loopback mail test port:
```
tcp and port 2525 and host 127.0.0.1
```
- **Interface**: Loopback only (`lo0`).
- **Traffic**: Only synthetic test email sessions generated between the local test client and local test server.
- **Port**: Strictly port `2525`. All other traffic on your Mac is ignored and never inspected.

---

## 5. Troubleshooting & Diagnostics

1. **Verify Health Endpoint**:
   ```bash
   curl -s http://127.0.0.1:9000/health | json_pp
   ```
   Expected response:
   ```json
   {
      "status": "OK",
      "agent": "SecureMailScope Capture Agent",
      "version": "1.0.0",
      "os": "darwin",
      "interface": "lo0",
      "can_capture": true,
      "is_busy": false
   }
   ```

2. **Check LaunchDaemon Status**:
   ```bash
   sudo launchctl list | grep com.securemailscope.captureagent
   ```
   If status shows a non-zero exit code, inspect the logs.

3. **Inspect Service Logs**:
   - Standard output:
     ```bash
     tail -f /var/log/securemailscope-capture-agent.log
     ```
   - Error output:
     ```bash
     tail -f /var/log/securemailscope-capture-agent.error.log
     ```

4. **Port 9000 Conflict**:
   If another application is using port 9000:
   ```bash
   sudo lsof -i :9000
   ```
