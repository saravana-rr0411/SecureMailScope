#!/bin/bash
# ==============================================================================
# SecureMailScope Local Capture Agent - macOS Background Service Installer
# Installs the capture agent as an automated launchd daemon on macOS.
# ==============================================================================

set -euo pipefail

PLIST_NAME="com.securemailscope.captureagent.plist"
TARGET_PLIST="/Library/LaunchDaemons/${PLIST_NAME}"

# 1. Verify macOS environment
if [[ "$(uname)" != "Darwin" ]]; then
    echo "[-] Error: This installer is intended strictly for macOS (Darwin)."
    exit 1
fi

# 2. Check root/sudo privileges
if [[ $EUID -ne 0 ]]; then
    echo "[-] This installation requires root privileges to install the LaunchDaemon."
    echo "    Please run with sudo: sudo ./install.sh"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEMPLATE_PLIST="${SCRIPT_DIR}/${PLIST_NAME}"

# 3. Detect Python virtual environment
PYTHON_BIN=""
if [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
    PYTHON_BIN="${ROOT_DIR}/.venv/bin/python"
elif [[ -x "${ROOT_DIR}/capture_agent/.venv/bin/python" ]]; then
    PYTHON_BIN="${ROOT_DIR}/capture_agent/.venv/bin/python"
else
    PYTHON_BIN="$(which python3 || true)"
fi

if [[ -z "${PYTHON_BIN}" || ! -x "${PYTHON_BIN}" ]]; then
    echo "[-] Error: Could not locate Python executable. Please create a virtualenv first."
    exit 1
fi

echo "==========================================================================="
echo "  SecureMailScope Local Capture Agent - macOS Service Installer"
echo "==========================================================================="
echo "  Project Root  : ${ROOT_DIR}"
echo "  Python Binary : ${PYTHON_BIN}"
echo "  Target Daemon : ${TARGET_PLIST}"
echo "==========================================================================="

# 4. Stop existing service if running
if launchctl list | grep -q "com.securemailscope.captureagent"; then
    echo "[*] Unloading existing capture agent service..."
    launchctl unload "${TARGET_PLIST}" 2>/dev/null || true
fi

# 5. Generate LaunchDaemon plist with concrete paths
echo "[*] Generating system LaunchDaemon configuration..."
mkdir -p /var/log
touch /var/log/securemailscope-capture-agent.log /var/log/securemailscope-capture-agent.error.log
chmod 640 /var/log/securemailscope-capture-agent.log /var/log/securemailscope-capture-agent.error.log
chown root:wheel /var/log/securemailscope-capture-agent.log /var/log/securemailscope-capture-agent.error.log

sed -e "s|__APP_DIR__|${ROOT_DIR}|g" \
    -e "s|__PYTHON_BIN__|${PYTHON_BIN}|g" \
    "${TEMPLATE_PLIST}" > "${TARGET_PLIST}"

chown root:wheel "${TARGET_PLIST}"
chmod 644 "${TARGET_PLIST}"

# 6. Load and start the background daemon via launchd
echo "[*] Registering and launching background service with launchctl..."
launchctl load -w "${TARGET_PLIST}"

# 7. Wait and verify health
echo "[*] Waiting for Capture Agent to initialize on http://127.0.0.1:9000..."
HEALTH_URL="http://127.0.0.1:9000/health"
MAX_ATTEMPTS=15
ATTEMPT=0
SUCCESS=0

while [[ $ATTEMPT -lt $MAX_ATTEMPTS ]]; do
    sleep 1
    ATTEMPT=$((ATTEMPT + 1))
    if curl -s -f "${HEALTH_URL}" > /dev/null 2>&1; then
        SUCCESS=1
        break
    fi
done

if [[ $SUCCESS -eq 1 ]]; then
    echo ""
    echo "==========================================================================="
    echo "  [SUCCESS] SecureMailScope Capture Agent is ACTIVE and HEALTHY!"
    echo "==========================================================================="
    echo "  Daemon Label : com.securemailscope.captureagent"
    echo "  API Endpoint : http://127.0.0.1:9000"
    echo "  Logs         : /var/log/securemailscope-capture-agent.log"
    echo "  Status       : Running as a persistent background macOS service"
    echo "==========================================================================="
else
    echo ""
    echo "[-] Warning: Service was loaded but http://127.0.0.1:9000/health is not responding yet."
    echo "    Check logs: cat /var/log/securemailscope-capture-agent.error.log"
fi
