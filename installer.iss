[Setup]
AppName=HostsGuard
AppVersion=3.12.0
AppPublisher=SysAdminDoc
AppPublisherURL=https://github.com/SysAdminDoc/HostsGuard
DefaultDirName={autopf}\HostsGuard
DefaultGroupName=HostsGuard
UninstallDisplayIcon={app}\HostsGuard.exe
OutputDir=installer_output
OutputBaseFilename=HostsGuard_Setup
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern
SetupIconFile=icon.ico
ArchitecturesInstallIn64BitMode=x64compatible
LicenseFile=LICENSE
MinVersion=10.0

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
