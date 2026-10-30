; WireVeil Checker per-machine installer.
; CI supplies /DAppVersion=x.y.z for tagged releases.

#ifndef AppVersion
  #define AppVersion "1.8.1"
#endif

#define AppName "WireVeil Checker"
#define AppExeName "WireVeilChecker.exe"
#define AppPublisher "WireVeil"
#define RepositoryUrl "https://github.com/markKikhtenko/WireVeil"

[Setup]
AppId={{A4C81415-8612-49AB-9EC8-23D63FC1D134}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#RepositoryUrl}
AppSupportURL={#RepositoryUrl}/issues
AppUpdatesURL={#RepositoryUrl}/releases/latest
DefaultDirName={autopf}\WireVeil Checker
DefaultGroupName=WireVeil Checker
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\installer-output
OutputBaseFilename=WireVeilChecker-Setup-x64
SetupIconFile=..\assets\wireveil-icon.ico
UninstallDisplayIcon={app}\{#AppExeName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
CloseApplications=yes
RestartApplications=yes
CloseApplicationsFilter={#AppExeName},sing-box.exe,mihomo.exe,libcronet.dll
SetupLogging=yes
UsePreviousAppDir=no
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} installer
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Дополнительные ярлыки:"; Flags: unchecked

[InstallDelete]
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "..\dist\WireVeilChecker\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\WireVeil Checker"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\WireVeil Checker"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Запустить WireVeil Checker"; WorkingDir: "{app}"; Flags: nowait postinstall skipifsilent
Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Flags: nowait; Check: IsWireVeilUiUpdate

[Code]
function IsWireVeilUiUpdate: Boolean;
begin
  Result := ExpandConstant('{param:WIREVEILUPDATE|0}') = '1';
end;
