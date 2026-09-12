#!/bin/bash
# ==============================================================================
# SecureMailScope Local Capture Agent - macOS .pkg Package Builder
# Builds a self-contained, user-installable .pkg installer for macOS.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

PKG_NAME="SecureMailScopeCaptureAgent"
PKG_VERSION="1.0.0"
PKG_ID="com.securemailscope.captureagent.pkg"
ARCH="$(uname -m)"

echo "==========================================================================="
echo "  Building macOS .pkg Installer: ${PKG_NAME} (v${PKG_VERSION}, ${ARCH})"
echo "==========================================================================="

# 1. Verify macOS and pkgbuild tool
if [[ "$(uname)" != "Darwin" ]]; then
    echo "[-] Error: This build script must be run on macOS (Darwin)." >&2
    exit 1
fi

if ! command -v pkgbuild >/dev/null 2>&1; then
    echo "[-] Error: pkgbuild command not found. Please install Xcode Command Line Tools." >&2
    exit 1
fi

# 2. Setup build and distribution directories
BUILD_DIR="${PROJECT_ROOT}/build/pkg_build"
PAYLOAD_ROOT="${BUILD_DIR}/payload"
SCRIPTS_DIR="${BUILD_DIR}/scripts"
DIST_DIR="${PROJECT_ROOT}/dist"

rm -rf "${BUILD_DIR}"
mkdir -p "${PAYLOAD_ROOT}" "${SCRIPTS_DIR}" "${DIST_DIR}"

APP_INSTALL_DIR="${PAYLOAD_ROOT}/Library/Application Support/SecureMailScope/CaptureAgent"
LAUNCHD_DIR="${PAYLOAD_ROOT}/Library/LaunchDaemons"

mkdir -p "${APP_INSTALL_DIR}/bin" "${APP_INSTALL_DIR}/wheels" "${LAUNCHD_DIR}"

# 3. Copy application package source files (excluding pycache, tests, macos build scripts, and systemd)
echo "[*] Packaging capture_agent source code..."
mkdir -p "${APP_INSTALL_DIR}/capture_agent"
rsync -av --exclude '__pycache__' --exclude '*.pyc' --exclude 'tests' --exclude 'storage' \
    --exclude 'macos' --exclude 'systemd' --exclude 'Dockerfile' \
    "${PROJECT_ROOT}/capture_agent/" "${APP_INSTALL_DIR}/capture_agent/"

echo "${PKG_VERSION}" > "${APP_INSTALL_DIR}/VERSION"
echo "${ARCH}" > "${APP_INSTALL_DIR}/ARCH"

# 4. Bundle offline dependency wheels
echo "[*] Bundling offline Python dependency wheels..."
PYTHON_BIN=""
if [[ -x "${PROJECT_ROOT}/.venv/bin/python" ]]; then
    PYTHON_BIN="${PROJECT_ROOT}/.venv/bin/python"
else
    PYTHON_BIN="$(which python3)"
fi

"${PYTHON_BIN}" -m pip download \
    --dest "${APP_INSTALL_DIR}/wheels" \
    fastapi uvicorn pydantic cryptography >/dev/null 2>&1 || {
        echo "[*] Downloading wheels with output..."
        "${PYTHON_BIN}" -m pip download \
            --dest "${APP_INSTALL_DIR}/wheels" \
            fastapi uvicorn pydantic cryptography
    }

# 5. Create the service launcher wrapper (bin/run_agent.sh)
echo "[*] Creating launcher wrapper..."
cat <<'EOF' > "${APP_INSTALL_DIR}/bin/run_agent.sh"
#!/bin/bash
set -e

APP_DIR="/Library/Application Support/SecureMailScope/CaptureAgent"
VENV_PYTHON="${APP_DIR}/venv/bin/python"

if [[ ! -x "${VENV_PYTHON}" ]]; then
    echo "[-] Error: Python executable not found at ${VENV_PYTHON}" >&2
    exit 1
fi

cd "${APP_DIR}"
export PYTHONPATH="${APP_DIR}"
export AGENT_HOST="127.0.0.1"
export AGENT_PORT="9000"
export CAPTURE_AGENT_LOCAL_ONLY="true"

exec "${VENV_PYTHON}" -m uvicorn capture_agent.main:app --host 127.0.0.1 --port 9000
EOF
chmod 755 "${APP_INSTALL_DIR}/bin/run_agent.sh"

# 6. Copy standalone uninstaller script (bin/uninstall.sh)
cp "${PROJECT_ROOT}/capture_agent/macos/uninstall.sh" "${APP_INSTALL_DIR}/bin/uninstall.sh"
chmod 755 "${APP_INSTALL_DIR}/bin/uninstall.sh"

# 7. Create LaunchDaemon plist
echo "[*] Generating LaunchDaemon property list..."
cat <<'EOF' > "${LAUNCHD_DIR}/com.securemailscope.captureagent.plist"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.securemailscope.captureagent</string>
    <key>WorkingDirectory</key>
    <string>/Library/Application Support/SecureMailScope/CaptureAgent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Library/Application Support/SecureMailScope/CaptureAgent/bin/run_agent.sh</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PYTHONPATH</key>
        <string>/Library/Application Support/SecureMailScope/CaptureAgent</string>
        <key>AGENT_HOST</key>
        <string>127.0.0.1</string>
        <key>AGENT_PORT</key>
        <string>9000</string>
        <key>CAPTURE_AGENT_LOCAL_ONLY</key>
        <string>true</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/securemailscope-capture-agent.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/securemailscope-capture-agent.error.log</string>
</dict>
</plist>
EOF
chmod 644 "${LAUNCHD_DIR}/com.securemailscope.captureagent.plist"

# 8. Copy installer lifecycle scripts
export COPYFILE_DISABLE=1
cp "${PROJECT_ROOT}/capture_agent/macos/scripts/preinstall" "${SCRIPTS_DIR}/preinstall"
cp "${PROJECT_ROOT}/capture_agent/macos/scripts/postinstall" "${SCRIPTS_DIR}/postinstall"
chmod +x "${SCRIPTS_DIR}/preinstall" "${SCRIPTS_DIR}/postinstall"

# Clean any macOS resource fork / AppleDouble artifacts from payload
xattr -rc "${PAYLOAD_ROOT}" "${SCRIPTS_DIR}" 2>/dev/null || true
dot_clean -m "${PAYLOAD_ROOT}" "${SCRIPTS_DIR}" 2>/dev/null || true
find "${PAYLOAD_ROOT}" "${SCRIPTS_DIR}" -name "._*" -delete 2>/dev/null || true
find "${PAYLOAD_ROOT}" "${SCRIPTS_DIR}" -name ".DS_Store" -delete 2>/dev/null || true

# 9. Build the flat component package with pkgbuild
OUTPUT_PKG="${DIST_DIR}/${PKG_NAME}-${PKG_VERSION}.pkg"
echo "[*] Executing pkgbuild..."
pkgbuild \
    --root "${PAYLOAD_ROOT}" \
    --scripts "${SCRIPTS_DIR}" \
    --identifier "${PKG_ID}" \
    --version "${PKG_VERSION}" \
    --ownership recommended \
    --install-location "/" \
    "${OUTPUT_PKG}"

echo ""
echo "==========================================================================="
echo "  [SUCCESS] macOS Installer Package Created Successfully!"
echo "==========================================================================="
echo "  Package Path : ${OUTPUT_PKG}"
echo "  Package Size : $(du -h "${OUTPUT_PKG}" | cut -f1)"
echo "  Architecture : ${ARCH}"
echo "  Identifier   : ${PKG_ID}"
echo "  Version      : ${PKG_VERSION}"
echo "==========================================================================="
