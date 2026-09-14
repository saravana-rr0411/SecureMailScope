; ==============================================================================
; SecureMailScope Capture Agent - Inno Setup Script for Windows
; Target: SecureMailScopeCaptureAgent-1.0.1-Setup.exe
; ==============================================================================

#define MyAppName "SecureMailScope Capture Agent"
#define MyAppVersion "1.0.1"
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
OutputBaseFilename=SecureMailScopeCaptureAgent-1.0.1-Setup
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
; 1. Allow inbound localhost communication through Windows Defender Firewall if needed
Filename: "netsh.exe"; Parameters: "advfirewall firewall add rule name=""SecureMailScope Capture Agent"" dir=in action=allow protocol=TCP localport=9000 profile=any"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated

; 2. Register the Windows Service upon install
Filename: "{code:GetPythonExe}"; Parameters: """{app}\capture_agent\windows\service.py"" --startup=auto install"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; Check: IsNpcapInstalled

; 3. Start the Windows Service
Filename: "sc.exe"; Parameters: "start {#MyServiceName}"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; Check: IsNpcapInstalled

[UninstallRun]
; Stop and remove the Windows Service cleanly
Filename: "sc.exe"; Parameters: "stop {#MyServiceName}"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; RunOnceId: "StopService"
Filename: "{code:GetPythonExe}"; Parameters: """{app}\capture_agent\windows\service.py"" remove"; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"
Filename: "netsh.exe"; Parameters: "advfirewall firewall delete rule name=""SecureMailScope Capture Agent"""; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveFirewallRule"


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

// Post-installation verification & environment configuration
procedure CurStepChanged(CurStep: TSetupStep);
var
  Attempts: Integer;
  IsHealthy: Boolean;
  ServiceExists: Boolean;
  WinHttpReq: Variant;
  EnvFilePath: String;
  EnvContent: TArrayOfString;
  DataDirPath: String;
  ResultCode: Integer;
  LogFilePath: String;
begin
  if CurStep = ssPostInstall then
  begin
    // 1. Ensure ProgramData directories exist before writing agent.env
    DataDirPath := ExpandConstant('{commonappdata}\SecureMailScope\CaptureAgent');
    ForceDirectories(DataDirPath);
    ForceDirectories(DataDirPath + '\logs');
    ForceDirectories(DataDirPath + '\storage');

    // 2. Provision agent.env if it doesn't already exist
    EnvFilePath := DataDirPath + '\agent.env';
    if not FileExists(EnvFilePath) then
    begin
      SetArrayLength(EnvContent, 4);
      EnvContent[0] := '# SecureMailScope Windows Capture Agent Configuration';
      EnvContent[1] := 'BACKEND_WS_URL=wss://securemailscope-130k.onrender.com/ws/agent';
      EnvContent[2] := 'CAPTURE_AGENT_SECRET_KEY=sms-capture-secret-dev-key';
      EnvContent[3] := 'CAPTURE_AGENT_API_KEY=sms-capture-secret-dev-key';
      SaveStringsToUTF8File(EnvFilePath, EnvContent, False);
    end;
  end;

  if CurStep = ssDone then
  begin
    LogFilePath := ExpandConstant('{commonappdata}\SecureMailScope\CaptureAgent\logs\service.log');

    // Check if Npcap is installed; if not, service registration was skipped by Check: IsNpcapInstalled
    if not IsNpcapInstalled() then
    begin
      Exit;
    end;

    // Verify service actually exists in Windows Service Control Manager (SCM)
    ResultCode := -1;
    ServiceExists := Exec(ExpandConstant('{sys}\sc.exe'), 'query {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);

    if not ServiceExists then
    begin
      MsgBox('Service Registration Error: SecureMailScope Capture Agent service was NOT registered in Windows Service Control Manager.' + #13#10 + #13#10 +
             'Exit code from sc.exe query: ' + IntToStr(ResultCode) + #13#10 + #13#10 +
             'Please inspect the service log file at:' + #13#10 +
             LogFilePath + #13#10 + #13#10 +
             'You can inspect registration errors by opening an Administrator Command Prompt and running:' + #13#10 +
             GetPythonExe('') + ' "' + ExpandConstant('{app}\capture_agent\windows\service.py') + '" --startup=auto install',
             mbCriticalError, MB_OK);
      Exit;
    end;

    // Service exists in SCM. Ensure it is triggered to start if not already running.
    Exec(ExpandConstant('{sys}\sc.exe'), 'start {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // Wait for the service to initialize and respond to health checks
    IsHealthy := False;
    for Attempts := 1 to 15 do
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
      MsgBox('SecureMailScope Capture Agent service is registered in Windows Service Manager, but the health check at http://127.0.0.1:9000/health did not respond within 15 seconds.' + #13#10 + #13#10 +
             'The service may still be starting or initializing dependencies.' + #13#10 + #13#10 +
             'Please check the service log file at:' + #13#10 +
             LogFilePath + #13#10 + #13#10 +
             'You can inspect the service state using: sc.exe query {#MyServiceName}',
             mbError, MB_OK);
    end;
  end;
end;

