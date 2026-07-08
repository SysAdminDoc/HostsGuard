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
#define MyAppVersion "0.12.34"
#define MyAppVersionInfo "0.12.34.0"
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
Source: "dist\dotnet\{#TargetRid}\app\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs
Source: "dist\dotnet\{#TargetRid}\cli\*"; DestDir: "{app}\cli"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\HostsGuard"; Filename: "{app}\HostsGuard.App.exe"
Name: "{group}\Uninstall HostsGuard"; Filename: "{uninstallexe}"
Name: "{autodesktop}\HostsGuard"; Filename: "{app}\HostsGuard.App.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
; Register the elevated engine: LocalSystem, auto-start, after the Windows
; Firewall service. Recovery: restart on failure (5s / 10s / 30s, daily reset).
Filename: "{sys}\sc.exe"; Parameters: "create {#MyServiceName} binPath= ""{app}\service\HostsGuard.Service.exe"" start= auto depend= MpsSvc obj= LocalSystem DisplayName= ""HostsGuard Service"""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "description {#MyServiceName} ""HostsGuard elevated engine: hosts file, firewall rules, DNS/connection monitors, consent prompts."""; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "failure {#MyServiceName} reset= 86400 actions= restart/5000/restart/10000/restart/30000"; Flags: runhidden
Filename: "{sys}\sc.exe"; Parameters: "start {#MyServiceName}"; Flags: runhidden
Filename: "{app}\HostsGuard.App.exe"; Description: "Launch HostsGuard"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{sys}\sc.exe"; Parameters: "stop {#MyServiceName}"; Flags: runhidden; RunOnceId: "StopSvc"
; Restore default-outbound posture, delete HG_ firewall rules, drop the handshake.
Filename: "{app}\cli\HostsGuard.Cli.exe"; Parameters: "uninstall-cleanup"; Flags: runhidden; RunOnceId: "Cleanup"
Filename: "{sys}\sc.exe"; Parameters: "delete {#MyServiceName}"; Flags: runhidden; RunOnceId: "DeleteSvc"

[UninstallDelete]
Type: dirifempty; Name: "{app}"

[Code]
// Re-install safety: stop and remove an existing service registration before
// files are replaced, so the binary is never locked and `sc create` succeeds.
procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssInstall then
  begin
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(1500);
    Exec(ExpandConstant('{sys}\sc.exe'), 'delete {#MyServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
