; HostsGuard .NET installer (NET-051 / WFCP-000a).
; Installs the split-trust pair: HostsGuardSvc (LocalSystem, auto-start,
; depends on MpsSvc so firewall/audit APIs are up) + the unelevated WPF app
; and CLI. Uninstall stops the service, restores the firewall posture and
; removes HG_ rules via `HostsGuard.Cli uninstall-cleanup`, then deletes the
; service registration.
; Build x64:   build\publish.ps1, then `iscc installer-dotnet.iss`.
; Build ARM64: build\publish.ps1 -RuntimeIdentifier win-arm64, then
;              `iscc /DTargetRid=win-arm64 /DTargetArchitecturesAllowed=arm64 /DTargetInstallIn64BitMode=arm64 installer-dotnet.iss`.

#ifndef TargetRid
#define TargetRid "win-x64"
#endif
#ifndef TargetArchitecturesAllowed
#define TargetArchitecturesAllowed "x64compatible"
#endif
#ifndef TargetInstallIn64BitMode
#define TargetInstallIn64BitMode "x64compatible"
#endif

#define MyAppName "HostsGuard"
#define MyAppVersion "0.12.149"
#define MyAppVersionInfo "0.12.149.0"
#define MyServiceName "HostsGuardSvc"

[Setup]
AppId=HostsGuardNet
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher=SysAdminDoc
AppPublisherURL=https://github.com/SysAdminDoc/HostsGuard
DefaultDirName={autopf}\HostsGuard
DefaultGroupName=HostsGuard
UninstallDisplayIcon={app}\HostsGuard.App.exe
OutputDir=installer_output
OutputBaseFilename=HostsGuard-v{#MyAppVersion}-{#TargetRid}-dotnet-Setup
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern
SetupIconFile=icon.ico
ArchitecturesAllowed={#TargetArchitecturesAllowed}
ArchitecturesInstallIn64BitMode={#TargetInstallIn64BitMode}
LicenseFile=LICENSE
MinVersion=10.0
SetupLogging=yes
CloseApplications=yes
CloseApplicationsFilter=HostsGuard.App.exe
RestartApplications=no
VersionInfoVersion={#MyAppVersionInfo}
VersionInfoCompany=SysAdminDoc
VersionInfoDescription=HostsGuard installer
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}

[Files]
Source: "dist\dotnet\{#TargetRid}\service\*"; DestDir: "{app}\service"; Flags: ignoreversion recursesubdirs
; Extracted before file replacement so upgrades can stop/wait, snapshot, and
; later roll back without executing a helper from the tree being replaced.
Source: "dist\dotnet\{#TargetRid}\service\HostsGuard.Service.exe"; DestDir: "{tmp}"; DestName: "HostsGuard.UpdateHelper.exe"; Flags: dontcopy
Source: "dist\dotnet\{#TargetRid}\app\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs
Source: "dist\dotnet\{#TargetRid}\cli\*"; DestDir: "{app}\cli"; Flags: ignoreversion recursesubdirs
Source: "dist\dotnet\{#TargetRid}\migrator\*"; DestDir: "{app}\migrator"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\HostsGuard"; Filename: "{app}\HostsGuard.App.exe"
Name: "{group}\Uninstall HostsGuard"; Filename: "{uninstallexe}"
Name: "{autodesktop}\HostsGuard"; Filename: "{app}\HostsGuard.App.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\HostsGuard.App.exe"; Description: "Launch HostsGuard"; Flags: nowait postinstall skipifsilent; Check: CanLaunchApp

[UninstallDelete]
Type: dirifempty; Name: "{app}"

[Code]
var
  WasUpgrade: Boolean;
  UpdatePrepared: Boolean;
  UpdateFailed: Boolean;
  UpdateFailure: String;
  PurgeLocalData: Boolean;
  PurgeNeedsRestart: Boolean;
  UninstallActionsStarted: Boolean;

function RunAndCheck(const Filename, Parameters: String; var ResultCode: Integer): Boolean;
begin
  Result := Exec(Filename, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and
            (ResultCode = 0);
end;

function ServiceExists(): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'), 'query {#MyServiceName}', '',
    SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  Helper, Parameters: String;
begin
  Result := '';
  NeedsRestart := False;
  WasUpgrade := DirExists(ExpandConstant('{app}\service')) or ServiceExists();
  if not WasUpgrade then
    exit;

  ExtractTemporaryFile('HostsGuard.UpdateHelper.exe');
  Helper := ExpandConstant('{tmp}\HostsGuard.UpdateHelper.exe');
  Parameters := '--prepare-update "{#MyAppVersion}" "' + ExpandConstant('{app}') +
    '" "' + ExpandConstant('{commonappdata}\HostsGuard') + '"';
  if not RunAndCheck(Helper, Parameters, ResultCode) then
  begin
    Result := 'HostsGuard update preflight failed before any files were replaced ' +
      '(helper exit ' + IntToStr(ResultCode) + '). The existing installation was left in place.';
    exit;
  end;

  UpdatePrepared := True;
end;

function ConfigureAndStartService(var Failure: String): Boolean;
var
  ResultCode: Integer;
  Command: String;
begin
  Result := False;
  if not WasUpgrade then
  begin
    Command := 'create {#MyServiceName} binPath= ""' +
      ExpandConstant('{app}\service\HostsGuard.Service.exe') +
      '"" start= auto depend= MpsSvc obj= LocalSystem DisplayName= ""HostsGuard Service""';

    if not RunAndCheck(ExpandConstant('{sys}\sc.exe'), Command, ResultCode) then
    begin
      Failure := 'service registration failed (sc.exe exit ' + IntToStr(ResultCode) + ')';
      exit;
    end;

    if not RunAndCheck(ExpandConstant('{sys}\sc.exe'),
        'description {#MyServiceName} ""HostsGuard elevated engine: hosts file, firewall rules, DNS/connection monitors, consent prompts.""',
        ResultCode) then
    begin
      Failure := 'service description failed (sc.exe exit ' + IntToStr(ResultCode) + ')';
      exit;
    end;

    if not RunAndCheck(ExpandConstant('{sys}\sc.exe'),
        'failure {#MyServiceName} reset= 86400 actions= restart/5000/restart/10000/restart/30000',
        ResultCode) then
    begin
      Failure := 'service recovery configuration failed (sc.exe exit ' + IntToStr(ResultCode) + ')';
      exit;
    end;
  end
  else if not ServiceExists() then
  begin
    Failure := 'the existing service registration disappeared after update preflight';
    exit;
  end;

  if not RunAndCheck(ExpandConstant('{sys}\sc.exe'), 'start {#MyServiceName}', ResultCode) then
  begin
    Failure := 'service start failed (sc.exe exit ' + IntToStr(ResultCode) + ')';
    exit;
  end;

  Result := True;
end;

procedure RollBackOrFail(const Failure: String);
var
  ResultCode: Integer;
  Helper, Parameters: String;
begin
  if WasUpgrade and UpdatePrepared then
  begin
    Helper := ExpandConstant('{commonappdata}\HostsGuard\updates\rollback-helper\HostsGuard.Service.exe');
    Parameters := '--rollback-update "' + ExpandConstant('{commonappdata}\HostsGuard') + '"';
    if RunAndCheck(Helper, Parameters, ResultCode) then
    begin
      UpdateFailed := True;
      UpdateFailure := Failure;
      UpdatePrepared := False;
      Log('Update failed and the previous version was restored once: ' + Failure);
      exit;
    end;

    RaiseException(Failure + '; automatic rollback also failed (helper exit ' +
      IntToStr(ResultCode) + ').');
  end;

  RaiseException(Failure);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  Failure, Parameters: String;
begin
  if CurStep <> ssPostInstall then
    exit;

  if not ConfigureAndStartService(Failure) then
  begin
    RollBackOrFail(Failure);
    exit;
  end;

  if WasUpgrade then
  begin
    Parameters := 'update health --expected "{#MyAppVersion}" --timeout 30';
    if not RunAndCheck(ExpandConstant('{app}\cli\HostsGuard.Cli.exe'), Parameters, ResultCode) then
    begin
      RollBackOrFail('installed service failed exact-version/read-only posture health (CLI exit ' +
        IntToStr(ResultCode) + ')');
      exit;
    end;

    Parameters := '--complete-update "' + ExpandConstant('{commonappdata}\HostsGuard') +
      '" "{#MyAppVersion}"';
    if not RunAndCheck(ExpandConstant('{app}\service\HostsGuard.Service.exe'), Parameters, ResultCode) then
    begin
      RollBackOrFail('healthy update state could not be committed (helper exit ' +
        IntToStr(ResultCode) + ')');
      exit;
    end;

    UpdatePrepared := False;
  end
  else
  begin
    // A new install starts from safe defaults. Upgrades intentionally skip
    // these mutating commands and use the read-only health probe above.
    if not RunAndCheck(ExpandConstant('{app}\cli\HostsGuard.Cli.exe'), 'safe-posture', ResultCode) then
      RaiseException('fresh-install safe posture failed (CLI exit ' + IntToStr(ResultCode) + ')');
    if not RunAndCheck(ExpandConstant('{app}\cli\HostsGuard.Cli.exe'), 'safe-posture-smoke', ResultCode) then
      RaiseException('fresh-install posture verification failed (CLI exit ' + IntToStr(ResultCode) + ')');
  end;
end;

procedure DeinitializeSetup();
var
  ResultCode: Integer;
  Helper, Parameters: String;
begin
  // Cancellation/internal setup failure after preflight must not leave the old
  // service stopped. Claim the same one-shot rollback path used by health fail.
  if WasUpgrade and UpdatePrepared then
  begin
    Helper := ExpandConstant('{commonappdata}\HostsGuard\updates\rollback-helper\HostsGuard.Service.exe');
    Parameters := '--rollback-update "' + ExpandConstant('{commonappdata}\HostsGuard') + '"';
    RunAndCheck(Helper, Parameters, ResultCode);
    UpdatePrepared := False;
  end;
end;

function CanLaunchApp(): Boolean;
begin
  Result := not UpdateFailed;
end;

function GetCustomSetupExitCode(): Integer;
begin
  if UpdateFailed then
    Result := 10
  else
    Result := 0;
end;

function HasUninstallSwitch(const SwitchName: String): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
  begin
    if CompareText(ParamStr(I), SwitchName) = 0 then
    begin
      Result := True;
      exit;
    end;
  end;
end;

function InitializeUninstall(): Boolean;
var
  PurgeRequested, RetainRequested: Boolean;
  Choice: Integer;
  ProgramDataPath, AppDataPath: String;
begin
  Result := False;
  PurgeLocalData := False;
  PurgeNeedsRestart := False;
  UninstallActionsStarted := False;
  PurgeRequested := HasUninstallSwitch('/PURGELOCALDATA');
  RetainRequested := HasUninstallSwitch('/RETAINLOCALDATA');

  if PurgeRequested and RetainRequested then
  begin
    Log('Uninstall stopped: /PURGELOCALDATA and /RETAINLOCALDATA are mutually exclusive.');
    if not UninstallSilent then
      MsgBox('Choose only one data option: /PURGELOCALDATA or /RETAINLOCALDATA.',
        mbError, MB_OK);
    exit;
  end;

  if PurgeRequested then
  begin
    PurgeLocalData := True;
    Result := True;
    exit;
  end;

  // Silent uninstall defaults to retention unless the purge switch is explicit.
  if RetainRequested or UninstallSilent then
  begin
    Result := True;
    exit;
  end;

  ProgramDataPath := ExpandConstant('{commonappdata}\HostsGuard');
  AppDataPath := ExpandConstant('{userappdata}\HostsGuard');
  Choice := MsgBox(
    'Choose what to do with HostsGuard local data:' + #13#10 + #13#10 +
    'Yes - Retain for reinstall (default)' + #13#10 +
    'Keep ProgramData: ' + ProgramDataPath + #13#10 +
    'Keep AppData: ' + AppDataPath + #13#10 + #13#10 +
    'No - Purge all HostsGuard local data' + #13#10 +
    'Delete both ProgramData and AppData paths above.' + #13#10 + #13#10 +
    'Cancel - Keep HostsGuard installed.',
    mbConfirmation, MB_YESNOCANCEL or MB_DEFBUTTON1);

  if Choice = IDCANCEL then
    exit;

  PurgeLocalData := Choice = IDNO;
  Result := True;
end;

procedure ReportPurgeResult(ResultCode: Integer);
var
  MessageText: String;
begin
  if ResultCode = 0 then
  begin
    Log('HostsGuard ProgramData and AppData purge completed.');
    exit;
  end;

  if ResultCode = 3 then
  begin
    PurgeNeedsRestart := True;
    MessageText := 'HostsGuard local data purge is incomplete because one or more files were locked. ' +
      'Those entries are scheduled for deletion at the next Windows restart.';
  end
  else
    MessageText := 'HostsGuard could not purge all local data. Review the uninstall log; ' +
      'remaining ProgramData or AppData files can be removed after Windows restarts.';

  Log(MessageText + ' CLI exit ' + IntToStr(ResultCode) + '.');
  if not UninstallSilent then
    MsgBox(MessageText, mbInformation, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
  CliPath: String;
begin
  if (CurUninstallStep <> usUninstall) or UninstallActionsStarted then
    exit;

  UninstallActionsStarted := True;
  CliPath := ExpandConstant('{app}\cli\HostsGuard.Cli.exe');

  // Preserve the established cleanup order before any data directory is removed.
  if not Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#MyServiceName}', '',
      SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('Could not launch service stop command.');

  if not Exec(CliPath, 'uninstall-cleanup', '', SW_HIDE,
      ewWaitUntilTerminated, ResultCode) then
    Log('Could not launch firewall/posture cleanup command.')
  else if ResultCode <> 0 then
    Log('Firewall/posture cleanup reported exit ' + IntToStr(ResultCode) + '.');

  if PurgeLocalData then
  begin
    if not Exec(CliPath, 'purge-local-data', '', SW_HIDE,
        ewWaitUntilTerminated, ResultCode) then
      ReportPurgeResult(-1)
    else
      ReportPurgeResult(ResultCode);
  end
  else
    Log('Retaining HostsGuard ProgramData and AppData for reinstall.');

  if not Exec(ExpandConstant('{sys}\sc.exe'), 'delete {#MyServiceName}', '',
      SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('Could not launch service delete command.');
end;

function UninstallNeedRestart(): Boolean;
begin
  Result := PurgeNeedsRestart;
end;
