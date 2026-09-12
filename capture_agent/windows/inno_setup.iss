; ==============================================================================
; SecureMailScope Capture Agent - Inno Setup Script for Windows
; Target: SecureMailScopeCaptureAgent-1.0.0-Setup.exe
; ==============================================================================

#define MyAppName "SecureMailScope Capture Agent"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "SecureMailScope"
#define MyAppURL "https://github.com/saravana-rr0411/SecureMailScope"
#define MyAppExeName "service.exe"
#define MyServiceName "SecureMailScopeCaptureAgent"

[Setup]
AppId={{D1429B4F-2E0F-4B81-80C7-96EF7634C2B1}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\SecureMailScope\CaptureAgent
DefaultGroupName=SecureMailScope
DisableProgramGroupPage=yes
OutputBaseFilename=SecureMailScopeCaptureAgent-1.0.0-Setup
OutputDir=..\..\dist
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
ArchitecturesAllowed=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
; Python application payload
Source: "..\..\build\windows_payload\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; Optional bundled official Npcap installer (only packaged if present during build)
#if FileExists("vendor\npcap-setup.exe")
Source: "vendor\npcap-setup.exe"; DestDir: "{tmp}"; Flags: dontcopy
#endif

[Dirs]
Name: "{commonappdata}\SecureMailScope\CaptureAgent"; Permissions: users-modify
Name: "{commonappdata}\SecureMailScope\CaptureAgent\storage"; Permissions: users-modify
Name: "{commonappdata}\SecureMailScope\CaptureAgent\logs"; Permissions: users-modify

[Run]
; Check / register the Windows Service upon install
Filename: "{code:GetPythonExe}"; Parameters: """{app}\capture_agent\windows\service.py"" --startup=auto install"; Flags: runhidden waituntilterminated; Check: IsNpcapInstalled
Filename: "sc.exe"; Parameters: "start {#MyServiceName}"; Flags: runhidden waituntilterminated; Check: IsNpcapInstalled

[UninstallRun]
; Stop and remove the Windows Service cleanly
Filename: "sc.exe"; Parameters: "stop {#MyServiceName}"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{code:GetPythonExe}"; Parameters: """{app}\capture_agent\windows\service.py"" remove"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[Code]
// Helper function to resolve Python executable in {app}\venv, {app}\python.exe, or system PATH
function GetPythonExe(Param: String): String;
begin
  if FileExists(ExpandConstant('{app}\python\python.exe')) then
    Result := ExpandConstant('{app}\python\python.exe')
  else if FileExists(ExpandConstant('{app}\venv\Scripts\python.exe')) then
    Result := ExpandConstant('{app}\venv\Scripts\python.exe')
  else if FileExists(ExpandConstant('{app}\python.exe')) then
    Result := ExpandConstant('{app}\python.exe')
  else
    Result := 'python.exe';
end;

// Helper function to check if Npcap driver is installed on the target Windows system
function IsNpcapInstalled(): Boolean;
begin
  Result := FileExists(ExpandConstant('{sys}\Npcap\wpcap.dll')) or
            FileExists(ExpandConstant('{sys}\wpcap.dll')) or
            FileExists(ExpandConstant('{sys}\SysWOW64\Npcap\wpcap.dll')) or
            FileExists(ExpandConstant('{sys}\SysWOW64\wpcap.dll'));
end;

function HasBundledNpcap(): Boolean;
begin
  #if FileExists("vendor\npcap-setup.exe")
    Result := True;
  #else
    Result := False;
  #endif
end;

// Verify and handle Npcap prerequisite installation
function InstallNpcapPrerequisite(): Boolean;
var
  ErrorCode: Integer;
  NpcapExe: String;
begin
  Result := True;

  // 1. If Npcap is already present, proceed immediately (zero clicks needed)
  if IsNpcapInstalled() then
  begin
    Exit;
  end;

  // 2. If an official Npcap installer is bundled (OEM / internal build)
  if HasBundledNpcap() then
  begin
    ExtractTemporaryFile('npcap-setup.exe');
    NpcapExe := ExpandConstant('{tmp}\npcap-setup.exe');
    if FileExists(NpcapExe) then
    begin
      MsgBox('SecureMailScope Capture Agent requires Npcap for packet capture on Windows.' + #13#10 + #13#10 +
             'The official Npcap installer will now launch.' + #13#10 +
             'Please ensure "Install Npcap in WinPcap API-compatible Mode" remains checked.',
             mbInformation, MB_OK);

      // Launch official Npcap installer with WinPcap API compatibility flag and wait
      if not Exec(NpcapExe, '/winpcap_mode=yes', '', SW_SHOWNORMAL, ewWaitUntilTerminated, ErrorCode) then
      begin
        MsgBox('Failed to launch Npcap installer (Error: ' + IntToStr(ErrorCode) + ').' + #13#10 +
               'Setup cannot continue without Npcap.', mbCriticalError, MB_OK);
        Result := False;
        Exit;
      end;

      // Re-verify Npcap is now installed
      if not IsNpcapInstalled() then
      begin
        MsgBox('Npcap installation did not complete or was cancelled.' + #13#10 + #13#10 +
               'SecureMailScope Capture Agent cannot capture packets without Npcap.' + #13#10 +
               'Setup will now exit safely.', mbError, MB_OK);
        Result := False;
        Exit;
      end;
    end
    else
    begin
      MsgBox('Internal error: Bundled Npcap installer could not be extracted.' + #13#10 +
             'Setup will now exit.', mbCriticalError, MB_OK);
      Result := False;
      Exit;
    end;
  end
  else
  begin
    // 3. Unbundled / Open distribution mode (Npcap License Section 5 redistribution restriction)
    if MsgBox('SecureMailScope Capture Agent requires the Npcap packet capture driver on Windows.' + #13#10 + #13#10 +
              'Npcap was not detected on this system.' + #13#10 + #13#10 +
              'Under Npcap licensing terms, redistributing Npcap is restricted to OEM license holders.' + #13#10 + #13#10 +
              'Would you like to open the official Npcap download page now (https://npcap.com/#download)?' + #13#10 + #13#10 +
              'Please download and run the official installer, enable "Install Npcap in WinPcap API-compatible Mode", and then run this installer again.',
              mbConfirmation, MB_YESNO) = IDYES then
    begin
      ShellExec('open', 'https://npcap.com/#download', '', '', SW_SHOWNORMAL, ewNoWait, ErrorCode);
    end;
    Result := False;
  end;
end;

function IsPythonRuntimeAvailable(): Boolean;
var
  PyExe: String;
  ErrorCode: Integer;
begin
  PyExe := GetPythonExe('');
  if (PyExe <> 'python.exe') and FileExists(PyExe) then
  begin
    Result := True;
    Exit;
  end;
  Result := Exec('python.exe', '--version', '', SW_HIDE, ewWaitUntilTerminated, ErrorCode);
end;

function HasBundledPython(): Boolean;
begin
  #if FileExists("..\..\build\windows_payload\python\python.exe") || FileExists("..\..\build\windows_payload\venv\Scripts\python.exe")
    Result := True;
  #else
    Result := False;
  #endif
end;

// Pre-installation check
function InitializeSetup(): Boolean;
begin
  Result := InstallNpcapPrerequisite();
end;

// Secondary check before installation starts
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  if not IsNpcapInstalled() then
  begin
    Result := 'Npcap packet capture driver is required to install SecureMailScope Capture Agent.';
    Exit;
  end;
  if not HasBundledPython() and not IsPythonRuntimeAvailable() then
  begin
    Result := 'Python runtime was not detected. Please install Python 3.10+ from https://www.python.org/downloads/ (ensure "Add python.exe to PATH" is checked), then run Setup again.';
    Exit;
  end;
end;

// Post-installation verification: Verify service is healthy on port 9000
procedure CurStepChanged(CurStep: TSetupStep);
var
  Attempts: Integer;
  IsHealthy: Boolean;
  WinHttpReq: Variant;
begin
  if CurStep = ssDone then
  begin
    IsHealthy := False;
    for Attempts := 1 to 10 do
    begin
      try
        WinHttpReq := CreateOleObject('WinHttp.WinHttpRequest.5.1');
        WinHttpReq.SetTimeouts(1000, 1000, 1000, 1000);
        WinHttpReq.Open('GET', 'http://127.0.0.1:9000/health', False);
        WinHttpReq.Send();
        if WinHttpReq.Status = 200 then
        begin
          IsHealthy := True;
          Break;
        end;
      except
      end;
      Sleep(1000);
    end;

    if not IsHealthy then
    begin
      MsgBox('SecureMailScope Capture Agent service was registered, but the health check at http://127.0.0.1:9000/health did not respond within 10 seconds.' + #13#10 + #13#10 +
             'Please check the service log file at:' + #13#10 +
             ExpandConstant('{commonappdata}\SecureMailScope\CaptureAgent\logs\service.log') + #13#10 + #13#10 +
             'You can inspect or start the service using: sc.exe query SecureMailScopeCaptureAgent',
             mbError, MB_OK);
    end;
  end;
end;
