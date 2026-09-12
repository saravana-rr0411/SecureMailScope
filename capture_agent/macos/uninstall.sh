#!/bin/bash
# ==============================================================================
# SecureMailScope Local Capture Agent - macOS Background Service Uninstaller
# Unregisters the LaunchDaemon and removes installed files from the system.
# ==============================================================================

set -euo pipefail

PLIST_PATH="/Library/LaunchDaemons/com.securemailscope.captureagent.plist"
APP_DIR="/Library/Application Support/SecureMailScope/CaptureAgent"
PARENT_DIR="/Library/Application Support/SecureMailScope"
LOG_OUT="/var/log/securemailscope-capture-agent.log"
LOG_ERR="/var/log/securemailscope-capture-agent.error.log"

if [[ "$(uname)" != "Darwin" ]]; then
    echo "[-] Error: This script is intended strictly for macOS (Darwin)."
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "[-] Error: Uninstallation requires root privileges."
    echo "    Please run with sudo: sudo $0"
    exit 1
fi

echo "[*] Stopping and unloading SecureMailScope Capture Agent daemon..."
if launchctl list | grep -q "com.securemailscope.captureagent"; then
    launchctl unload -w "${PLIST_PATH}" 2>/dev/null || true
fi

# Ensure any lingering uvicorn process on port 9000 is terminated
pkill -f "uvicorn.*capture_agent.main:app" 2>/dev/null || true

if [[ -f "${PLIST_PATH}" ]]; then
    echo "[*] Removing LaunchDaemon descriptor: ${PLIST_PATH}..."
    rm -f "${PLIST_PATH}"
fi

if [[ -d "${APP_DIR}" ]]; then
    echo "[*] Removing installed Capture Agent files from: ${APP_DIR}..."
    rm -rf "${APP_DIR}"
fi

# Remove parent directory only if empty
if [[ -d "${PARENT_DIR}" && -z "$(ls -A "${PARENT_DIR}" 2>/dev/null)" ]]; then
    echo "[*] Cleaning up empty parent directory: ${PARENT_DIR}..."
    rmdir "${PARENT_DIR}" 2>/dev/null || true
fi

# Clean up daemon log files
rm -f "${LOG_OUT}" "${LOG_ERR}" 2>/dev/null || true

echo ""
echo "==========================================================================="
echo "  [SUCCESS] SecureMailScope Capture Agent successfully uninstalled."
echo "==========================================================================="
