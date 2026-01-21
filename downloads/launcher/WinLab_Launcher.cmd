@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul

title WinLab - Lanzador

set "LAUNCHER_DIR=%~dp0"
set "PACK_ROOT="
if exist "%LAUNCHER_DIR%version.txt" (
  set "PACK_ROOT=%LAUNCHER_DIR%"
) else if exist "%LAUNCHER_DIR%..\\..\\version.txt" (
  for %%I in ("%LAUNCHER_DIR%..\\..") do set "PACK_ROOT=%%~fI"
) else (
  for %%I in ("%LAUNCHER_DIR%..\\..") do set "PACK_ROOT=%%~fI"
)

if "%~1"=="" (
  powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%LAUNCHER_DIR%WinLab_Launcher_UI.ps1"
  exit /b 0
)

set "STAGING_ROOT=C:\WinLab_Pack"
set "INBOX=C:\WinLab_Inbox"
set "OUTBOX=C:\WinLab_Outbox"
set "LOG_ROOT=C:\WinLab\logs"

call :init_logs
call :log "WinLab Lanzador iniciado"

call :check_windows || exit /b 1
call :check_sandbox || exit /b 1
call :ensure_dir "%INBOX%" || exit /b 1
call :ensure_dir "%OUTBOX%" || exit /b 1
call :ensure_dir "%LOG_ROOT%" || exit /b 1
call :stage_pack || exit /b 1

call :parse_args %*
if not defined PRESET call :choose_preset
if not defined PRESET set "PRESET=Balanced"
if not defined INPUT_PATH if not defined URL call :interactive_inputs

call :resolve_preset "%PRESET%" || exit /b 1
call :prepare_input
call :write_presets || exit /b 1
call :build_run_wsb || exit /b 1
call :watch_report

call :log "Lanzando Windows Sandbox con perfil %PRESET_LABEL%"
start "" "%WSB_PATH%"
exit /b 0

:check_windows
set "EDITION="
for /f "tokens=2,*" %%A in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v EditionID 2^>nul ^| find /I "EditionID"') do set "EDITION=%%B"
if "%EDITION%"=="" set "EDITION=UNKNOWN"

echo %EDITION% | find /I "Core" >nul
if not errorlevel 1 (
  call :log "Windows Home detectado. Windows Sandbox no está disponible."
  call :log "Necesitas Windows 10/11 Pro, Enterprise o Education."
  call :log "Si querés, escribinos por WhatsApp y te guiamos."
  call :log "Guía local: %PACK_ROOT%\\docs\\guia.html"
  pause
  exit /b 2
)
exit /b 0

:check_sandbox
set "WSBEXE=%SystemRoot%\System32\WindowsSandbox.exe"
if not exist "%WSBEXE%" (
  call :log "Windows Sandbox no está disponible en este equipo."
  call :log "Paso rápido: habilítalo desde Características de Windows."
  call :log "O ejecuta como Admin: Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart"
  call :log "Guía local: %PACK_ROOT%\\docs\\guia.html"
  pause
  exit /b 3
)
set "SANDBOX_OK="
for /f "usebackq delims=" %%S in (`dism /online /Get-FeatureInfo /FeatureName:Containers-DisposableClientVM /English ^| findstr /I /C:"State : Enabled"`) do set "SANDBOX_OK=1"
if defined SANDBOX_OK exit /b 0
call :log "Windows Sandbox no está habilitado."
call :log "Paso rápido: ejecuta PowerShell como Admin y corré:"
call :log "Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart"
call :log "Después reiniciá Windows."
call :log "Guía local: %PACK_ROOT%\\docs\\guia.html"
pause
exit /b 3

:parse_args
set "ARG1=%~1"
set "ARG2=%~2"
set "ARG3=%~3"

call :maybe_preset "%ARG1%"
if not defined PRESET call :maybe_input "%ARG1%"

if not defined PRESET call :maybe_preset "%ARG2%"
if not defined INPUT_PATH if not defined URL call :maybe_input "%ARG2%"

if not defined INPUT_PATH if not defined URL call :maybe_input "%ARG3%"
exit /b 0

:maybe_preset
set "CAND=%~1"
if "%CAND%"=="" exit /b 0
if /I "%CAND%"=="Balanced" set "PRESET=Balanced"
if /I "%CAND%"=="Equilibrado" set "PRESET=Balanced"
if /I "%CAND%"=="UltraSecure" set "PRESET=UltraSecure"
if /I "%CAND%"=="UltraSeguro" set "PRESET=UltraSecure"
if /I "%CAND%"=="Networked" set "PRESET=Networked"
if /I "%CAND%"=="ConRed" set "PRESET=Networked"
exit /b 0

:maybe_input
set "CAND=%~1"
if "%CAND%"=="" exit /b 0
if /I "%CAND:~0,4%"=="http" (
  set "URL=%CAND%"
  exit /b 0
)
if exist "%CAND%" (
  set "INPUT_PATH=%CAND%"
  exit /b 0
)
exit /b 0

:interactive_inputs
call :log "Elegí cómo querés analizar:"
call :log "1) Archivo"
call :log "2) URL"
call :log "3) Archivo más reciente en Descargas"
set /p "MODE=Selección (1/2/3): "
if "%MODE%"=="2" (
  set /p "URL=Pegá la URL completa: "
  exit /b 0
)
if "%MODE%"=="1" (
  set /p "INPUT_PATH=Pegá la ruta del archivo (o arrastralo y soltalo): "
  exit /b 0
)
call :pick_latest_download
exit /b 0

:pick_latest_download
for /f "usebackq delims=" %%F in (`powershell -NoProfile -Command "$f = Get-ChildItem -Path $env:USERPROFILE\Downloads -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if($f){$f.FullName}"`) do set "INPUT_PATH=%%F"
if "%INPUT_PATH%"=="" (
  call :log "No se encontró un archivo en Descargas."
) else (
  call :log "Usando el archivo más reciente de Descargas."
)
exit /b 0

:choose_preset
call :log "Elegí el preset:"
call :log "1) Equilibrado (recomendado)"
call :log "2) Ultra seguro (sin red)"
call :log "3) Con red (más abierto)"
set /p "PRESEL=Selección (1/2/3): "
if "%PRESEL%"=="2" set "PRESET=UltraSecure"
if "%PRESEL%"=="3" set "PRESET=Networked"
if not defined PRESET set "PRESET=Balanced"
exit /b 0

:resolve_preset
set "PRESET_LABEL="
set "MINUTES=10"
set "NETWORKING=Enable"
set "FIREWALL=InternetOnly"
set "VGPU=Default"

if /I "%PRESET%"=="Balanced" (
  set "PRESET_LABEL=Equilibrado"
  set "MINUTES=10"
  set "NETWORKING=Enable"
  set "FIREWALL=InternetOnly"
  set "VGPU=Default"
)
if /I "%PRESET%"=="UltraSecure" (
  set "PRESET_LABEL=Ultra seguro"
  set "MINUTES=5"
  set "NETWORKING=Disable"
  set "FIREWALL=BlockAll"
  set "VGPU=Disable"
)
if /I "%PRESET%"=="Networked" (
  set "PRESET_LABEL=Con red"
  set "MINUTES=15"
  set "NETWORKING=Enable"
  set "FIREWALL=AllowMost"
  set "VGPU=Default"
)

if "%PRESET_LABEL%"=="" (
  call :log "Preset inválido. Usá Equilibrado, UltraSeguro o ConRed."
  exit /b 1
)
exit /b 0

:prepare_input
if not "%INPUT_PATH%"=="" (
  if not exist "%INPUT_PATH%" (
    call :log "El archivo no existe: %INPUT_PATH%"
    exit /b 1
  )
  for %%F in ("%INPUT_PATH%") do set "TARGET_NAME=%%~nxF"
  copy /y "%INPUT_PATH%" "%INBOX%\%TARGET_NAME%" >nul
  call :log "Archivo listo en la carpeta de entrada: %TARGET_NAME%"
)
exit /b 0

:stage_pack
if /I "%PACK_ROOT%"=="%STAGING_ROOT%" exit /b 0
call :log "Copiando el pack a %STAGING_ROOT%"
if not exist "%STAGING_ROOT%" mkdir "%STAGING_ROOT%" 2>nul
if not exist "%STAGING_ROOT%" (
  call :log "No pude crear %STAGING_ROOT%. Ejecuta como Administrador."
  pause
  exit /b 1
)
robocopy "%PACK_ROOT%" "%STAGING_ROOT%" /MIR /XD ".git" "dist" "tmp" >nul
set "RC=%ERRORLEVEL%"
if %RC% GEQ 8 (
  call :log "Falló la copia del pack (robocopy %RC%)."
  pause
  exit /b 1
)
exit /b 0

:write_presets
set "PRESET_DIR=%STAGING_ROOT%\downloads\presets"
if not exist "%PRESET_DIR%" mkdir "%PRESET_DIR%" 2>nul
call :write_preset "Balanced" "%PRESET_DIR%\Balanced_AUTO.wsb" "Enable" "Enable" "InternetOnly" "Default" 10
call :write_preset "UltraSecure" "%PRESET_DIR%\UltraSecure_AUTO.wsb" "Disable" "Disable" "BlockAll" "Disable" 5
call :write_preset "Networked" "%PRESET_DIR%\Networked_AUTO.wsb" "Enable" "Enable" "AllowMost" "Default" 15
exit /b 0

:write_preset
set "P_NAME=%~1"
set "P_FILE=%~2"
set "P_VGPU=%~3"
set "P_NET=%~4"
set "P_FIRE=%~5"
set "P_MIN=%~6"
> "%P_FILE%" (
  echo ^<Configuration^>
  echo   ^<ProtectedClient^>Enable^</ProtectedClient^>
  echo   ^<VGpu^>%P_VGPU%^</VGpu^>
  echo   ^<Networking^>%P_NET%^</Networking^>
  echo   ^<ClipboardRedirection^>Disable^</ClipboardRedirection^>
  echo   ^<PrinterRedirection^>Disable^</PrinterRedirection^>
  echo   ^<AudioInput^>Disable^</AudioInput^>
  echo   ^<VideoInput^>Disable^</VideoInput^>
  echo   ^<MappedFolders^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>%STAGING_ROOT%^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabPack^</SandboxFolder^>
  echo       ^<ReadOnly^>true^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>%INBOX%^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabInboxRO^</SandboxFolder^>
  echo       ^<ReadOnly^>true^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>%OUTBOX%^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabOutbox^</SandboxFolder^>
  echo       ^<ReadOnly^>false^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>%LOG_ROOT%^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabLogs^</SandboxFolder^>
  echo       ^<ReadOnly^>false^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo   ^</MappedFolders^>
  echo   ^<LogonCommand^>
  echo     ^<Command^>powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\WinLabPack\tools\cli\bin\InsideLab.ps1" -Preset %P_NAME% -InputFolder "C:\WinLabInboxRO" -OutFolder "C:\WinLabOutbox" -Minutes %P_MIN% -FirewallMode %P_FIRE% -EnableOutbox 1 -LogFolder "C:\WinLabLogs"^</Command^>
  echo   ^</LogonCommand^>
  echo ^</Configuration^>
)
exit /b 0

:build_run_wsb
for /f "usebackq delims=" %%T in (`powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"`) do set "STAMP=%%T"
set "WSB_PATH=%TEMP%\WinLab_Run_%STAMP%.wsb"
set "EXTRA_ARGS="
if not "%URL%"=="" set "EXTRA_ARGS=%EXTRA_ARGS% -Url \"%URL%\""
if not "%TARGET_NAME%"=="" set "EXTRA_ARGS=%EXTRA_ARGS% -TargetFileName \"%TARGET_NAME%\""

> "%WSB_PATH%" (
  echo ^<Configuration^>
  echo   ^<ProtectedClient^>Enable^</ProtectedClient^>
  echo   ^<VGpu^>%VGPU%^</VGpu^>
  echo   ^<Networking^>%NETWORKING%^</Networking^>
  echo   ^<ClipboardRedirection^>Disable^</ClipboardRedirection^>
  echo   ^<PrinterRedirection^>Disable^</PrinterRedirection^>
  echo   ^<AudioInput^>Disable^</AudioInput^>
  echo   ^<VideoInput^>Disable^</VideoInput^>
  echo   ^<MappedFolders^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>%STAGING_ROOT%^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabPack^</SandboxFolder^>
  echo       ^<ReadOnly^>true^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>%INBOX%^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabInboxRO^</SandboxFolder^>
  echo       ^<ReadOnly^>true^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>%OUTBOX%^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabOutbox^</SandboxFolder^>
  echo       ^<ReadOnly^>false^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>%LOG_ROOT%^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabLogs^</SandboxFolder^>
  echo       ^<ReadOnly^>false^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo   ^</MappedFolders^>
  echo   ^<LogonCommand^>
  echo     ^<Command^>powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\WinLabPack\tools\cli\bin\InsideLab.ps1" -Preset %PRESET% -InputFolder "C:\WinLabInboxRO" -OutFolder "C:\WinLabOutbox" -Minutes %MINUTES% -FirewallMode %FIREWALL% -EnableOutbox 1 -LogFolder "C:\WinLabLogs"%EXTRA_ARGS%^</Command^>
  echo   ^</LogonCommand^>
  echo ^</Configuration^>
)
exit /b 0

:watch_report
start "" powershell -NoProfile -WindowStyle Hidden -Command "`$out='%OUTBOX%'; `$start=Get-Date; while((Get-Date) -lt `$start.AddMinutes(30)){ `$f = Get-ChildItem -Path `$out -Filter report.html -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if(`$f -and `$f.LastWriteTime -ge `$start){ Start-Process `$f.FullName; break }; Start-Sleep -Seconds 4 }"
exit /b 0

:init_logs
for /f "usebackq delims=" %%T in (`powershell -NoProfile -Command "Get-Date -Format yyyyMMdd_HHmmss"`) do set "STAMP=%%T"
if not exist "%LOG_ROOT%" mkdir "%LOG_ROOT%" 2>nul
if not exist "%LOG_ROOT%" set "LOG_ROOT=%LOCALAPPDATA%\WinLab\logs"
if not exist "%LOG_ROOT%" mkdir "%LOG_ROOT%" 2>nul
set "LOG_FILE=%LOG_ROOT%\launcher_%STAMP%.log"
exit /b 0

:ensure_dir
set "TARGET_DIR=%~1"
if not exist "%TARGET_DIR%" mkdir "%TARGET_DIR%" 2>nul
if not exist "%TARGET_DIR%" (
  call :log "No pude crear %TARGET_DIR%. Ejecuta como Administrador."
  pause
  exit /b 1
)
exit /b 0

:log
if "%~1"=="" exit /b 0
set "TS=%date% %time%"
echo %~1
>>"%LOG_FILE%" echo [%TS%] %~1
exit /b 0
