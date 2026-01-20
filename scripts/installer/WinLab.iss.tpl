; WinLab Inno Setup template
#define AppName "WinLab"
#define AppVersion "{{VERSION}}"
#define SourceDir "{{SOURCE_DIR}}"
#define OutputDir "{{OUTPUT_DIR}}"

[Setup]
AppId={{1F51B09B-0E6A-4B5B-9B7C-919DA0B3E97C}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=WinLab
DefaultDirName={pf}\WinLab
DefaultGroupName=WinLab
OutputDir={#OutputDir}
OutputBaseFilename=WinLab_Installer_{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
DisableProgramGroupPage=yes
SetupIconFile=

[Dirs]
Name: "C:\WinLab\logs"; Permissions: users-modify
Name: "C:\WinLab_Inbox"; Permissions: users-modify
Name: "C:\WinLab_Outbox"; Permissions: users-modify

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{group}\WinLab (Lanzador)"; Filename: "{app}\downloads\launcher\WinLab_Launcher.cmd"
Name: "{group}\WinLab (Doctor)"; Filename: "{app}\tools\cli\WinLab.cmd"; Parameters: "doctor"
Name: "{group}\Guia rapida"; Filename: "{app}\docs\guia_cliente.html"
Name: "{group}\Desinstalar WinLab"; Filename: "{uninstallexe}"
Name: "{commondesktop}\WinLab"; Filename: "{app}\downloads\launcher\WinLab_Launcher.cmd"

[UninstallDelete]
Type: filesandordirs; Name: "C:\WinLab\logs"
Type: filesandordirs; Name: "C:\WinLab_Inbox"
Type: filesandordirs; Name: "C:\WinLab_Outbox"
