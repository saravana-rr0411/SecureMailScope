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
set "ISCC_PATH=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if not exist "%ISCC_PATH%" (
    set "ISCC_PATH=C:\Program Files\Inno Setup 6\ISCC.exe"
)
if not exist "%ISCC_PATH%" (
    where ISCC.exe >nul 2>&1
    if !errorlevel! equ 0 (
        for /f "delims=" %%i in ('where ISCC.exe') do set "ISCC_PATH=%%i"
    ) else (
        echo [-] Error: Inno Setup 6 (ISCC.exe) not found.
        echo     Please install Inno Setup 6 from: https://jrsoftware.org/isdl.php
        exit /b 1
    )
)
echo [+] Found Inno Setup Compiler: %ISCC_PATH%

rem ---------------------------------------------------------------------------
rem 2. Validate required SecureMailScope source files exist (Fail Closed)
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
rem 3. Npcap Bundling Check & SHA-256 Hash Verification
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

    rem Verify against official hash list or environment override
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
    echo     (Per Npcap EULA Section 5, public redistribution requires an OEM license;
    echo      the installer will safely verify Npcap presence and direct users to the official download).
)

rem ---------------------------------------------------------------------------
rem 4. Prepare build and dist directories
rem ---------------------------------------------------------------------------
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%"
if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"

rem ---------------------------------------------------------------------------
rem 5. Copy application package source files into build directory
rem ---------------------------------------------------------------------------
echo [*] Copying capture_agent package source files...
mkdir "%BUILD_DIR%\capture_agent"
robocopy "%PROJECT_ROOT%\capture_agent" "%BUILD_DIR%\capture_agent" /E /XD __pycache__ tests storage macos .pytest_cache vendor /XF *.pyc >nul

echo [*] Packaging python requirements...
copy "%PROJECT_ROOT%\capture_agent\requirements.txt" "%BUILD_DIR%\" >nul

echo [*] Checking for Python environment to bundle dependencies...
where python >nul 2>&1
if !errorlevel! equ 0 (
    echo [*] Creating bundled Python virtual environment in %BUILD_DIR%\venv...
    python -m venv "%BUILD_DIR%\venv"
    if exist "%BUILD_DIR%\venv\Scripts\python.exe" (
        echo [*] Installing required packages into bundled venv...
        "%BUILD_DIR%\venv\Scripts\python.exe" -m pip install --upgrade pip >nul 2>&1
        "%BUILD_DIR%\venv\Scripts\python.exe" -m pip install -r "%PROJECT_ROOT%\capture_agent\requirements.txt"
    )
)

rem ---------------------------------------------------------------------------
rem 6. Compile with Inno Setup (Fail Closed)
rem ---------------------------------------------------------------------------
echo [*] Compiling installer with Inno Setup...
"%ISCC_PATH%" "%SCRIPT_DIR%inno_setup.iss"
if !errorlevel! neq 0 (
    echo [-] Error: Inno Setup compilation failed with exit code !errorlevel!.
    exit /b 1
)

set "OUTPUT_INSTALLER=%DIST_DIR%\SecureMailScopeCaptureAgent-1.0.0-Setup.exe"
if not exist "%OUTPUT_INSTALLER%" (
    echo [-] Error: Expected installer output file not found: %OUTPUT_INSTALLER%
    exit /b 1
)

echo ===========================================================================
echo   [SUCCESS] Windows Installer Created Successfully!
echo ===========================================================================
echo   Package : %OUTPUT_INSTALLER%
echo ===========================================================================
endlocal
