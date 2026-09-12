# SecureMailScope Capture Agent - Windows Deployment & Installer Guide

This directory contains the Windows packaging and installation resources for the **SecureMailScope Capture Agent**, producing the standalone installer:

```
dist/SecureMailScopeCaptureAgent-1.0.1-Setup.exe
```

---

## 1. System Requirements & Architecture

- **Operating System**: Windows 10 / 11 / Windows Server 2019+ (64-bit x64).
- **Permissions**: Administrator rights required (UAC elevated).
- **Service Name**: `SecureMailScopeCaptureAgent`
- **Installation Directory**: `C:\Program Files\SecureMailScope\CaptureAgent`
- **Application Data & Logs**: `C:\ProgramData\SecureMailScope\CaptureAgent`
  - Storage: `C:\ProgramData\SecureMailScope\CaptureAgent\storage`
  - Logs: `C:\ProgramData\SecureMailScope\CaptureAgent\logs\service.log`
- **Network Interfaces**:
  - Controlled 2525 Loopback: `\Device\NPF_Loopback` (Npcap Loopback Adapter)
  - Live Gmail SMTP 587: Active external interface (Wi-Fi / Ethernet default route)
- **Local API Endpoint**: `http://127.0.0.1:9000` (strictly bound to localhost, protected with DNS rebinding and origin whitelist).
- **Outbound WSS**: Secure WebSocket client to Render backend (`wss://securemailscope-130k.onrender.com/ws/agent`).

---

## 2. Npcap Prerequisite & Licensing Compliance

### Licensing Summary
- **Npcap** is developed by Insecure.Com LLC (The Nmap Project).
- **Section 5 of the Npcap License** explicitly prohibits redistributing or bundling the standard Npcap installer in public repositories, installers, or third-party mirrors without a commercial **Npcap OEM License**.
- To remain 100% compliant with Npcap's legal terms, SecureMailScope **does NOT** bundle unlicensed third-party Npcap binaries in public releases and **never** performs automatic arbitrary internet binary downloads.

### Installer Handling
The installer (`SecureMailScopeCaptureAgent-1.0.1-Setup.exe`) implements safe, dual-mode prerequisite handling:

1. **When Npcap is Already Installed (e.g. via Wireshark or prior setup)**:
   - The installer detects `wpcap.dll` in `System32` / `SysWOW64` or the running `npcap` driver service.
   - It proceeds completely automatically with zero extra clicks, installs the Capture Agent files, registers the Windows service, and starts it.

2. **When Npcap is Not Installed**:
   - The installer displays an official prerequisite notice informing the user that Npcap is required.
   - It provides a direct option to open the official download page:
     `https://npcap.com/#download`
   - It instructs the user to check **"Install Npcap in WinPcap API-compatible Mode"**.
   - It halts setup safely (fail-closed) so no broken services or corrupt files are left on disk.

3. **OEM / Enterprise Bundled Mode**:
   - Organizations with an Npcap OEM license can place `npcap-setup.exe` into `capture_agent/windows/vendor/`.
   - The build script (`build_installer.bat`) validates the file's SHA-256 checksum against official signatures before compiling.
   - The compiled Setup will automatically extract and launch the Npcap installer with `/winpcap_mode=yes`, verify its successful completion, and proceed to start the service.

---

## 3. Building the Windows Installer

### Prerequisites
1. [Inno Setup 6](https://jrsoftware.org/isdl.php) installed at default path (`C:\Program Files (x86)\Inno Setup 6\ISCC.exe`).
2. Python 3.10+ installed on the build machine.

### Build Command
Run from `capture_agent\windows\`:
```cmd
build_installer.bat
```

The script will:
1. Verify `ISCC.exe` is present.
2. Verify all core SecureMailScope source files exist.
3. Check for optional `vendor\npcap-setup.exe` and verify its SHA-256 hash.
4. Stage files into `build\windows_payload\`.
5. Compile `inno_setup.iss` into `dist\SecureMailScopeCaptureAgent-1.0.1-Setup.exe`.
6. Fail closed if any step fails.

---

## 4. Service Management & Operations

### Service Control via PowerShell / CMD (Run as Administrator)
- **Status**: `sc.exe query SecureMailScopeCaptureAgent`
- **Start**: `sc.exe start SecureMailScopeCaptureAgent`
- **Stop**: `sc.exe stop SecureMailScopeCaptureAgent`

### Health Check via Browser or Curl
```bash
curl http://127.0.0.1:9000/health
```

### Uninstallation
Run `C:\Program Files\SecureMailScope\CaptureAgent\unins000.exe` or use Windows **Add/Remove Programs**. The uninstaller:
1. Stops the `SecureMailScopeCaptureAgent` Windows Service.
2. Unregisters and removes the service from the Service Control Manager.
3. Removes installed binaries and cleans up program files.
