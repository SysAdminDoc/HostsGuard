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
#define MyAppVersion "0.12.121"
#define MyAppVersionInfo "0.12.121.0"
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

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop {#MyServiceName}"; Flags: runhidden; RunOnceId: "StopSvc"
; Restore default-outbound posture, delete HG_ firewall rules, drop the handshake.
Filename: "{app}\cli\HostsGuard.Cli.exe"; Parameters: "uninstall-cleanup"; Flags: runhidden; RunOnceId: "Cleanup"
Filename: "{sys}\sc.exe"; Parameters: "delete {#MyServiceName}"; Flags: runhidden; RunOnceId: "DeleteSvc"

[UninstallDelete]
Type: dirifempty; Name: "{app}"

[Code]
var
  WasUpgrade: Boolean;
  UpdatePrepared: Boolean;
  UpdateFailed: Boolean;
  UpdateFailure: String;

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
