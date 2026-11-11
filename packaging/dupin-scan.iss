; Script do Inno Setup 6 - gera Output\Dupin-Scan-Setup-<versao>.exe
#define MyAppName "Dupin-Scan"
#define MyAppVersion "1.0.0"
#define MyAppExe "Dupin-Scan.exe"

[Setup]
AppId={{B7E1B1F4-5A52-4C0E-9C5E-6A8D2B9F1C11}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
UninstallDisplayIcon={app}\{#MyAppExe}
SetupIconFile=..\assets\dupin-scan.ico
OutputDir=..\Output
OutputBaseFilename=Dupin-Scan-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "contextmenu"; Description: "Adicionar ""Varrer com o Dupin-Scan"" ao menu de contexto de arquivos e pastas"; GroupDescription: "Integração com o Windows:"
Name: "addtopath"; Description: "Adicionar a linha de comando (dupin-scan-cli) ao PATH"; GroupDescription: "Integração com o Windows:"; Flags: unchecked

[Files]
Source: "..\dist\Dupin-Scan\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion
Source: "..\dist\dupin-scan-cli\*"; DestDir: "{app}\cli"; Flags: recursesubdirs createallsubdirs ignoreversion

[Registry]
; Menu de contexto: "Varrer com o Dupin-Scan" abre a interface já apontada para o arquivo/pasta clicado. HKA = HKLM (instalação
; para todos) porque o instalador pede administrador; a desinstalação remove as chaves.
Root: HKA; Subkey: "Software\Classes\*\shell\DupinScan"; ValueType: string; ValueName: ""; ValueData: "Varrer com o Dupin-Scan"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\*\shell\DupinScan"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyAppExe}"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\*\shell\DupinScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExe}"" ""%1"""; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\DupinScan"; ValueType: string; ValueName: ""; ValueData: "Varrer com o Dupin-Scan"; Flags: uninsdeletekey; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\DupinScan"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#MyAppExe}"; Tasks: contextmenu
Root: HKA; Subkey: "Software\Classes\Directory\shell\DupinScan\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExe}"" ""%1"""; Tasks: contextmenu
; PATH do sistema (opcional). A remoção na desinstalação está em [Code].
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}\cli"; Tasks: addtopath; Check: NeedsPathEntry(ExpandConstant('{app}\cli'))

[Code]
function NeedsPathEntry(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', OrigPath) then
  begin
    Result := True;
    exit;
  end;
  Result := Pos(';' + Uppercase(Param) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  OrigPath, Entry: string;
  P: Integer;
begin
  if CurUninstallStep <> usPostUninstall then exit;
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', OrigPath) then exit;
  Entry := ';' + ExpandConstant('{app}\cli');
  P := Pos(Uppercase(Entry), Uppercase(OrigPath));
  if P > 0 then
  begin
    Delete(OrigPath, P, Length(Entry));
    RegWriteExpandStringValue(HKLM, 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', 'Path', OrigPath);
  end;
end;

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExe}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent
