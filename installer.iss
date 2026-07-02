#define MyAppName "HostsGuard"
#define MyAppVersion "3.15.0"
#define MyAppVersionInfo "3.15.0.0"

[Setup]
AppId=HostsGuard
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher=SysAdminDoc
AppPublisherURL=https://github.com/SysAdminDoc/HostsGuard
DefaultDirName={autopf}\HostsGuard
DefaultGroupName=HostsGuard
UninstallDisplayIcon={app}\HostsGuard.exe
OutputDir=installer_output
OutputBaseFilename=HostsGuard-v{#MyAppVersion}-Setup
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern
SetupIconFile=icon.ico
ArchitecturesInstallIn64BitMode=x64compatible
LicenseFile=LICENSE
MinVersion=10.0
SetupLogging=yes
CloseApplications=yes
CloseApplicationsFilter=HostsGuard.exe
RestartApplications=no
VersionInfoVersion={#MyAppVersionInfo}
VersionInfoCompany=SysAdminDoc
VersionInfoDescription=HostsGuard installer
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}

[Files]
Source: "dist\HostsGuard\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{group}\HostsGuard"; Filename: "{app}\HostsGuard.exe"
Name: "{group}\Uninstall HostsGuard"; Filename: "{uninstallexe}"
Name: "{autodesktop}\HostsGuard"; Filename: "{app}\HostsGuard.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\HostsGuard.exe"; Description: "Launch HostsGuard"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: dirifempty; Name: "{app}"
