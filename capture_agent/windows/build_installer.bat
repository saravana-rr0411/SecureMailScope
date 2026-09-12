@echo off
rem ==============================================================================
rem SecureMailScope Local Capture Agent - Windows Installer Build Script
rem Builds SecureMailScopeCaptureAgent-1.0.0-Setup.exe using Inno Setup Compiler
rem ==============================================================================

setlocal enabledelayedexpansion

echo ===========================================================================
echo   Building Windows Installer: SecureMailScope Capture Agent (v1.0.0)
echo ===========================================================================

set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%..\.."
set "BUILD_DIR=%PROJECT_ROOT%\build\windows_payload"
set "DIST_DIR=%PROJECT_ROOT%\dist"
set "VENDOR_DIR=%SCRIPT_DIR%vendor"
set "NPCAP_EXE=%VENDOR_DIR%\npcap-setup.exe"
set "HASH_FILE=%SCRIPT_DIR%official_npcap_hashes.txt"

rem ---------------------------------------------------------------------------
rem 1. Check for ISCC.exe (Inno Setup Compiler)
rem ---------------------------------------------------------------------------
set "ISCC_PATH="
if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" (
    set "ISCC_PATH=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
)
if not defined ISCC_PATH if exist "C:\Program Files\Inno Setup 6\ISCC.exe" (
    set "ISCC_PATH=C:\Program Files\Inno Setup 6\ISCC.exe"
)
if not defined ISCC_PATH (
    for /f "delims=" %%i in ('where ISCC.exe 2^>nul') do set "ISCC_PATH=%%i"
)
if not defined ISCC_PATH (
    echo [-] Error: Inno Setup 6 ISCC.exe not found in standard paths or PATH.
    echo     Please install Inno Setup 6 from: https://jrsoftware.org/isdl.php
    exit /b 1
)
echo [+] Found Inno Setup Compiler: !ISCC_PATH!

rem ---------------------------------------------------------------------------
rem 2. Check for Python Runtime (Fail Closed)
rem ---------------------------------------------------------------------------
echo [*] Checking for Python 3.10+ build runtime...
set "PYTHON_EXE="
where python >nul 2>&1
if !errorlevel! equ 0 (
    for /f "delims=" %%i in ('where python') do (
        if not defined PYTHON_EXE set "PYTHON_EXE=%%i"
    )
)
if not defined PYTHON_EXE (
    echo [-] Error: Python executable not found in PATH.
    echo     Python 3.10+ is required to build the Windows Capture Agent installer.
    exit /b 1
)
echo [+] Found Python build tool: !PYTHON_EXE!
"!PYTHON_EXE!" --version
if !errorlevel! neq 0 (
    echo [-] Error: Failed to execute Python command.
    exit /b 1
)

rem ---------------------------------------------------------------------------
rem 3. Validate required SecureMailScope source files exist (Fail Closed)
rem ---------------------------------------------------------------------------
echo [*] Validating required SecureMailScope source assets...
set "REQUIRED_ASSETS=capture_agent\main.py capture_agent\config.py capture_agent\ws_bridge.py capture_agent\recorder\windows_sniffer.py capture_agent\recorder\packet_capturer.py capture_agent\windows\service.py capture_agent\requirements.txt"

for %%A in (%REQUIRED_ASSETS%) do (
    if not exist "%PROJECT_ROOT%\%%A" (
        echo [-] Error: Required SecureMailScope asset missing: %PROJECT_ROOT%\%%A
        echo     Cannot build installer with missing core components.
        exit /b 1
    )
)
echo [+] All required SecureMailScope source assets confirmed present.

rem ---------------------------------------------------------------------------
rem 4. Npcap Bundling Check & SHA-256 Hash Verification
rem ---------------------------------------------------------------------------
if exist "%NPCAP_EXE%" (
    echo [*] Detected Npcap installer for bundling: %NPCAP_EXE%
    echo [*] Verifying official SHA-256 checksum...

    set "CALC_HASH="
    for /f "skip=1 tokens=* delims=" %%H in ('certutil -hashfile "%NPCAP_EXE%" SHA256 2^>nul') do (
        if not defined CALC_HASH (
            set "RAW_HASH=%%H"
            set "CALC_HASH=!RAW_HASH: =!"
        )
    )

    if not defined CALC_HASH (
        echo [-] Error: Failed to calculate SHA-256 hash for %NPCAP_EXE%
        exit /b 1
    )
    echo [*] Calculated SHA-256: !CALC_HASH!

    set "HASH_MATCH=0"
    if defined NPCAP_EXPECTED_SHA256 (
        if /i "!CALC_HASH!"=="!NPCAP_EXPECTED_SHA256!" (
            set "HASH_MATCH=1"
        )
    )

    if exist "%HASH_FILE%" (
        findstr /i "!CALC_HASH!" "%HASH_FILE%" >nul 2>&1
        if !errorlevel! equ 0 (
            set "HASH_MATCH=1"
        )
    )

    if "!HASH_MATCH!"=="0" (
        echo [-] SECURITY ERROR: SHA-256 checksum verification failed for %NPCAP_EXE%!
        echo     The file hash !CALC_HASH! does not match any official Npcap release signature.
        echo     Refusing to bundle unverified third-party binary.
        exit /b 1
    )
    echo [+] Npcap installer verified against official signature.
) else (
    echo [*] Note: No bundled Npcap installer found in %VENDOR_DIR%\
    echo     Building standard installer with official Npcap prerequisite validation mode.
    echo     Per Npcap EULA Section 5, public redistribution requires an OEM license.
    echo     The installer will safely verify Npcap presence and direct users to official download.
)

rem ---------------------------------------------------------------------------
rem 5. Prepare build and dist directories
rem ---------------------------------------------------------------------------
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%"
if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"

rem ---------------------------------------------------------------------------
rem 6. Copy application package source files into build directory
rem ---------------------------------------------------------------------------
echo [*] Copying capture_agent package source files...
mkdir "%BUILD_DIR%\capture_agent"
robocopy "%PROJECT_ROOT%\capture_agent" "%BUILD_DIR%\capture_agent" /E /XD __pycache__ tests storage macos .pytest_cache vendor /XF *.pyc >nul

echo [*] Packaging python requirements...
copy "%PROJECT_ROOT%\capture_agent\requirements.txt" "%BUILD_DIR%\" >nul

rem ---------------------------------------------------------------------------
rem 7. Stage Self-Contained Python Runtime and Packages (Fail Closed)
rem ---------------------------------------------------------------------------
echo [*] Determining Python base runtime path...
set "PY_BASE="
for /f "delims=" %%P in ('"!PYTHON_EXE!" -c "import sys; print(sys.base_prefix)"') do set "PY_BASE=%%P"

if not defined PY_BASE (
    echo [-] Error: Failed to resolve Python base directory.
    exit /b 1
)
echo [+] Python Base Directory: !PY_BASE!

echo [*] Staging self-contained Python runtime into %BUILD_DIR%\python...
mkdir "%BUILD_DIR%\python"
robocopy "!PY_BASE!" "%BUILD_DIR%\python" python*.exe python*.dll vcruntime*.dll /NFL /NDL /NJH /NJS >nul

if exist "!PY_BASE!\DLLs" (
    robocopy "!PY_BASE!\DLLs" "%BUILD_DIR%\python\DLLs" /E /NFL /NDL /NJH /NJS >nul
)
if exist "!PY_BASE!\Lib" (
    robocopy "!PY_BASE!\Lib" "%BUILD_DIR%\python\Lib" /E /XD test idlelib tkinter turtledemo /NFL /NDL /NJH /NJS >nul
)

set "STAGED_PYTHON=%BUILD_DIR%\python\python.exe"
if not exist "!STAGED_PYTHON!" (
    echo [-] Error: Staged Python executable not found: !STAGED_PYTHON!
    exit /b 1
)

echo [*] Upgrading pip in staged runtime...
"!STAGED_PYTHON!" -m pip install --upgrade pip setuptools wheel --no-warn-script-location >nul 2>&1

echo [*] Installing required Capture Agent packages into staged runtime...
"!STAGED_PYTHON!" -m pip install -r "%PROJECT_ROOT%\capture_agent\requirements.txt" --no-warn-script-location
if !errorlevel! neq 0 (
    echo [-] Error: pip install of requirements.txt failed.
    exit /b 1
)

if exist "%BUILD_DIR%\python\Scripts\pywin32_postinstall.py" (
    echo [*] Executing pywin32 post-install registration...
    "!STAGED_PYTHON!" "%BUILD_DIR%\python\Scripts\pywin32_postinstall.py" -install -quiet >nul 2>&1
)
echo [+] Self-contained Python runtime prepared successfully.

rem Create virtualenv alias for backward compatibility with existing configs
echo [*] Creating runtime aliases at %BUILD_DIR%\venv...
mkdir "%BUILD_DIR%\venv\Scripts" >nul 2>&1
copy "!STAGED_PYTHON!" "%BUILD_DIR%\venv\Scripts\python.exe" >nul 2>&1

rem ---------------------------------------------------------------------------
rem 8. Compile with Inno Setup (Fail Closed)
rem ---------------------------------------------------------------------------
echo [*] Compiling installer with Inno Setup: !ISCC_PATH!...
"!ISCC_PATH!" "%SCRIPT_DIR%inno_setup.iss"
if !errorlevel! neq 0 (
    echo [-] Error: Inno Setup compilation failed with exit code !errorlevel!.
    exit /b 1
)

set "OUTPUT_INSTALLER=%DIST_DIR%\SecureMailScopeCaptureAgent-1.0.0-Setup.exe"
if not exist "!OUTPUT_INSTALLER!" (
    echo [-] Error: Expected installer output file not found: !OUTPUT_INSTALLER!
    exit /b 1
)

echo ===========================================================================
echo   [SUCCESS] Windows Installer Created Successfully!
echo ===========================================================================
echo   Package : !OUTPUT_INSTALLER!
echo ===========================================================================
endlocal
