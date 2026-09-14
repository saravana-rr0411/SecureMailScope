@echo off
rem ==============================================================================
rem SecureMailScope Local Capture Agent - Windows Installer Build Script
rem Builds SecureMailScopeCaptureAgent-1.0.1-Setup.exe using Inno Setup Compiler
rem ==============================================================================

setlocal enabledelayedexpansion

echo ===========================================================================
echo   Building Windows Installer: SecureMailScope Capture Agent (v1.0.1)
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
rem 5. Prepare build and dist directories (Clean Build)
rem ---------------------------------------------------------------------------
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%"
if not exist "%DIST_DIR%" mkdir "%DIST_DIR%"
if exist "%DIST_DIR%\SecureMailScopeCaptureAgent-1.0.1-Setup.exe" (
    echo [*] Removing stale installer artifact before clean build...
    del /q /f "%DIST_DIR%\SecureMailScopeCaptureAgent-1.0.1-Setup.exe" >nul 2>&1
)

rem ---------------------------------------------------------------------------
rem 6. Copy application package source files into build directory
rem ---------------------------------------------------------------------------
echo [*] Copying capture_agent package source files...
mkdir "%BUILD_DIR%\capture_agent"
robocopy "%PROJECT_ROOT%\capture_agent" "%BUILD_DIR%\capture_agent" /E /XD __pycache__ tests storage macos .pytest_cache vendor /XF *.pyc >nul

rem Verify core staged source files exist (Fail Closed)
if not exist "%BUILD_DIR%\capture_agent\windows\service.py" (
    echo [-] Error: Required staged file missing: service.py
    exit /b 1
)
if not exist "%BUILD_DIR%\capture_agent\config.py" (
    echo [-] Error: Required staged file missing: config.py
    exit /b 1
)
if not exist "%BUILD_DIR%\capture_agent\main.py" (
    echo [-] Error: Required staged file missing: main.py
    exit /b 1
)
if not exist "%BUILD_DIR%\capture_agent\ws_bridge.py" (
    echo [-] Error: Required staged file missing: ws_bridge.py
    exit /b 1
)
echo [+] Verified fresh staged assets: service.py, config.py, main.py, ws_bridge.py.

echo [*] Packaging python requirements...
copy "%PROJECT_ROOT%\capture_agent\requirements.txt" "%BUILD_DIR%\" >nul

rem ---------------------------------------------------------------------------
rem 7. Stage Self-Contained Python Runtime and Packages (Fail Closed)
rem ---------------------------------------------------------------------------
echo [*] Determining Python base runtime path...
set "PYTHON_BASE_DIR="
set "PY_BASE_TMP=%BUILD_DIR%\_pybase.txt"
"!PYTHON_EXE!" -c "import sys; print(sys.base_prefix)" > "!PY_BASE_TMP!" 2>nul
if !errorlevel! equ 0 (
    if exist "!PY_BASE_TMP!" (
        for /f "usebackq delims=" %%P in ("!PY_BASE_TMP!") do (
            if not defined PYTHON_BASE_DIR set "PYTHON_BASE_DIR=%%P"
        )
        del "!PY_BASE_TMP!" >nul 2>&1
    )
)

if not defined PYTHON_BASE_DIR (
    echo [-] Error: Failed to resolve Python base directory.
    exit /b 1
)
if not exist "!PYTHON_BASE_DIR!" (
    echo [-] Error: Resolved Python base directory does not exist: !PYTHON_BASE_DIR!
    exit /b 1
)
set "PY_BASE=!PYTHON_BASE_DIR!"
echo [+] Python Base Directory: !PYTHON_BASE_DIR!

echo [*] Staging self-contained Python runtime into %BUILD_DIR%\python...
mkdir "%BUILD_DIR%\python"
robocopy "!PYTHON_BASE_DIR!" "%BUILD_DIR%\python" python*.exe python*.dll vcruntime*.dll msvcp*.dll /NFL /NDL /NJH /NJS >nul

if exist "!PYTHON_BASE_DIR!\DLLs" (
    robocopy "!PYTHON_BASE_DIR!\DLLs" "%BUILD_DIR%\python\DLLs" /E /NFL /NDL /NJH /NJS >nul
)
if exist "!PYTHON_BASE_DIR!\Lib" (
    robocopy "!PYTHON_BASE_DIR!\Lib" "%BUILD_DIR%\python\Lib" /E /XD test idlelib tkinter turtledemo /NFL /NDL /NJH /NJS >nul
)

rem Reset errorlevel from robocopy
ver >nul

set "STAGED_PYTHON=%BUILD_DIR%\python\python.exe"
if not exist "!STAGED_PYTHON!" (
    echo [-] Error: Staged Python executable not found: !STAGED_PYTHON!
    exit /b 1
)
if not exist "%BUILD_DIR%\python\Lib\os.py" (
    echo [-] Error: Staged Python standard library not found in %BUILD_DIR%\python\Lib
    exit /b 1
)

echo [*] Ensuring pip is initialized in staged runtime...
"!STAGED_PYTHON!" -m ensurepip --default-pip >nul 2>&1

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
if exist "%BUILD_DIR%\python\Lib\site-packages\pywin32_system32" (
    copy /y "%BUILD_DIR%\python\Lib\site-packages\pywin32_system32\*.dll" "%BUILD_DIR%\python\" >nul 2>&1
)

echo [*] Staging PythonService.exe and pywin32 service host binaries...
if exist "%BUILD_DIR%\python\Lib\site-packages\win32\PythonService.exe" (
    copy /y "%BUILD_DIR%\python\Lib\site-packages\win32\PythonService.exe" "%BUILD_DIR%\python\PythonService.exe" >nul 2>&1
    copy /y "%BUILD_DIR%\python\Lib\site-packages\win32\PythonService.exe" "%BUILD_DIR%\python\pythonservice.exe" >nul 2>&1
    echo [+] Staged PythonService.exe from site-packages\win32
)
if exist "%BUILD_DIR%\python\Scripts\PythonService.exe" (
    copy /y "%BUILD_DIR%\python\Scripts\PythonService.exe" "%BUILD_DIR%\python\PythonService.exe" >nul 2>&1
    copy /y "%BUILD_DIR%\python\Scripts\PythonService.exe" "%BUILD_DIR%\python\pythonservice.exe" >nul 2>&1
    echo [+] Staged PythonService.exe from Scripts
)
if exist "%BUILD_DIR%\python\Lib\site-packages\win32\pywintypes*.dll" (
    copy /y "%BUILD_DIR%\python\Lib\site-packages\win32\pywintypes*.dll" "%BUILD_DIR%\python\" >nul 2>&1
)
if exist "%BUILD_DIR%\python\Lib\site-packages\win32\pythoncom*.dll" (
    copy /y "%BUILD_DIR%\python\Lib\site-packages\win32\pythoncom*.dll" "%BUILD_DIR%\python\" >nul 2>&1
)

echo [*] Verifying staged Python runtime dependencies...
"!STAGED_PYTHON!" -c "import fastapi, uvicorn, scapy, win32serviceutil, websockets; print('[+] Staged runtime dependencies verified.')"
if !errorlevel! neq 0 (
    echo [-] Error: Staged Python environment failed dependency verification.
    exit /b 1
)

if not exist "%BUILD_DIR%\python\PythonService.exe" if not exist "%BUILD_DIR%\python\pythonservice.exe" (
    if not exist "%BUILD_DIR%\python\Lib\site-packages\win32\PythonService.exe" (
        echo [-] Error: pywin32 service host binary (PythonService.exe) missing from staged environment!
        exit /b 1
    )
)
echo [+] Verified PythonService host binary confirmed present.
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

set "OUTPUT_INSTALLER=%DIST_DIR%\SecureMailScopeCaptureAgent-1.0.1-Setup.exe"
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
