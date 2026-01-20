@echo off
setlocal EnableExtensions

set "LAUNCHER_DIR=%~dp0"
for %%I in ("%LAUNCHER_DIR%..\..") do set "PACK_ROOT=%%~fI"
set "STAGING_ROOT=C:\WinLab_Pack"
set "PRESET_DIR=%STAGING_ROOT%\downloads\presets"

set "PRESET_NAME=%~1"
if "%PRESET_NAME%"=="" set "PRESET_NAME=Balanced"

call :check_sandbox || exit /b 1
call :ensure_dir "C:\WinLab_Inbox" || exit /b 1
call :ensure_dir "C:\WinLab_Outbox" || exit /b 1
call :stage_pack || exit /b 1
call :write_presets || exit /b 1
call :select_preset || exit /b 1

if not exist "%PRESET_PATH%" (
  echo [WinLab] Missing preset: "%PRESET_PATH%"
  pause
  exit /b 1
)

echo [WinLab] Launching preset: %PRESET_FILE%
start "" "%PRESET_PATH%"
exit /b 0

:check_sandbox
set "SANDBOX_OK="
for /f "usebackq delims=" %%S in (`dism /online /Get-FeatureInfo /FeatureName:Containers-DisposableClientVM /English ^| findstr /I /C:"State : Enabled"`) do set "SANDBOX_OK=1"
if defined SANDBOX_OK exit /b 0
echo.
echo [WinLab] Windows Sandbox is not enabled.
echo Run PowerShell as Admin and execute:
echo   Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart
echo Then reboot Windows.
echo.
pause
exit /b 1

:ensure_dir
set "TARGET_DIR=%~1"
if not exist "%TARGET_DIR%" (
  mkdir "%TARGET_DIR%" 2>nul
)
if not exist "%TARGET_DIR%" (
  echo [WinLab] Could not create "%TARGET_DIR%". Run as Administrator.
  pause
  exit /b 1
)
exit /b 0

:stage_pack
if /I "%PACK_ROOT%"=="%STAGING_ROOT%" exit /b 0
echo [WinLab] Staging pack to %STAGING_ROOT% ...
if not exist "%STAGING_ROOT%" mkdir "%STAGING_ROOT%" 2>nul
if not exist "%STAGING_ROOT%" (
  echo [WinLab] Could not create "%STAGING_ROOT%". Run as Administrator.
  pause
  exit /b 1
)
robocopy "%PACK_ROOT%" "%STAGING_ROOT%" /MIR /XD ".git" "dist" >nul
set "RC=%ERRORLEVEL%"
if %RC% GEQ 8 (
  echo [WinLab] Failed to stage the pack (robocopy error %RC%).
  pause
  exit /b 1
)
exit /b 0

:write_presets
if not exist "%PRESET_DIR%" mkdir "%PRESET_DIR%" 2>nul
call :write_preset_balanced || exit /b 1
call :write_preset_ultrasecure || exit /b 1
call :write_preset_networked || exit /b 1
exit /b 0

:select_preset
set "PRESET_FILE="
if /I "%PRESET_NAME%"=="Balanced" set "PRESET_FILE=Balanced_AUTO.wsb"
if /I "%PRESET_NAME%"=="UltraSecure" set "PRESET_FILE=UltraSecure_AUTO.wsb"
if /I "%PRESET_NAME%"=="Networked" set "PRESET_FILE=Networked_AUTO.wsb"
if not defined PRESET_FILE (
  echo [WinLab] Invalid preset: %PRESET_NAME%
  echo Usage: WinLab_Launcher.cmd [Balanced^|UltraSecure^|Networked]
  exit /b 1
)
set "PRESET_PATH=%PRESET_DIR%\%PRESET_FILE%"
exit /b 0

:write_preset_balanced
set "FILE=%PRESET_DIR%\Balanced_AUTO.wsb"
> "%FILE%" (
  echo ^<Configuration^>
  echo   ^<VGpu^>Enable^</VGpu^>
  echo   ^<Networking^>Enable^</Networking^>
  echo   ^<Clipboard^>Enable^</Clipboard^>
  echo   ^<AudioInput^>Disable^</AudioInput^>
  echo   ^<Printer^>Disable^</Printer^>
  echo   ^<MappedFolders^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>C:\WinLab_Pack^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabPack^</SandboxFolder^>
  echo       ^<ReadOnly^>true^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>C:\WinLab_Inbox^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabInboxRO^</SandboxFolder^>
  echo       ^<ReadOnly^>true^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>C:\WinLab_Outbox^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabOutbox^</SandboxFolder^>
  echo       ^<ReadOnly^>false^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo   ^</MappedFolders^>
  echo   ^<LogonCommand^>
  echo     ^<Command^>powershell -NoProfile -ExecutionPolicy Bypass -File "C:\WinLabPack\tools\cli\bin\InsideLab.ps1" -Preset Balanced -InputFolder "C:\WinLabInboxRO" -OutFolder "C:\WinLabOutbox" -Minutes 10 -FirewallMode InternetOnly -EnableOutbox 1 -AutoDecisionEnabled 1 -CollectDeltas 1^</Command^>
  echo   ^</LogonCommand^>
  echo ^</Configuration^>
)
exit /b 0

:write_preset_ultrasecure
set "FILE=%PRESET_DIR%\UltraSecure_AUTO.wsb"
> "%FILE%" (
  echo ^<Configuration^>
  echo   ^<VGpu^>Disable^</VGpu^>
  echo   ^<Networking^>Disable^</Networking^>
  echo   ^<Clipboard^>Disable^</Clipboard^>
  echo   ^<AudioInput^>Disable^</AudioInput^>
  echo   ^<VideoInput^>Disable^</VideoInput^>
  echo   ^<Printer^>Disable^</Printer^>
  echo   ^<MappedFolders^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>C:\WinLab_Pack^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabPack^</SandboxFolder^>
  echo       ^<ReadOnly^>true^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>C:\WinLab_Inbox^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabInboxRO^</SandboxFolder^>
  echo       ^<ReadOnly^>true^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>C:\WinLab_Outbox^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabOutbox^</SandboxFolder^>
  echo       ^<ReadOnly^>false^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo   ^</MappedFolders^>
  echo   ^<LogonCommand^>
  echo     ^<Command^>powershell -NoProfile -ExecutionPolicy Bypass -File "C:\WinLabPack\tools\cli\bin\InsideLab.ps1" -Preset UltraSecure -InputFolder "C:\WinLabInboxRO" -OutFolder "C:\WinLabOutbox" -Minutes 5 -FirewallMode BlockAll -EnableOutbox 1 -AutoDecisionEnabled 1 -CollectDeltas 1^</Command^>
  echo   ^</LogonCommand^>
  echo ^</Configuration^>
)
exit /b 0

:write_preset_networked
set "FILE=%PRESET_DIR%\Networked_AUTO.wsb"
> "%FILE%" (
  echo ^<Configuration^>
  echo   ^<VGpu^>Enable^</VGpu^>
  echo   ^<Networking^>Enable^</Networking^>
  echo   ^<Clipboard^>Enable^</Clipboard^>
  echo   ^<AudioInput^>Disable^</AudioInput^>
  echo   ^<Printer^>Disable^</Printer^>
  echo   ^<MappedFolders^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>C:\WinLab_Pack^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabPack^</SandboxFolder^>
  echo       ^<ReadOnly^>true^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>C:\WinLab_Inbox^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabInboxRO^</SandboxFolder^>
  echo       ^<ReadOnly^>true^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo     ^<MappedFolder^>
  echo       ^<HostFolder^>C:\WinLab_Outbox^</HostFolder^>
  echo       ^<SandboxFolder^>C:\WinLabOutbox^</SandboxFolder^>
  echo       ^<ReadOnly^>false^</ReadOnly^>
  echo     ^</MappedFolder^>
  echo   ^</MappedFolders^>
  echo   ^<LogonCommand^>
  echo     ^<Command^>powershell -NoProfile -ExecutionPolicy Bypass -File "C:\WinLabPack\tools\cli\bin\InsideLab.ps1" -Preset Networked -InputFolder "C:\WinLabInboxRO" -OutFolder "C:\WinLabOutbox" -Minutes 15 -FirewallMode AllowMost -EnableOutbox 1 -AutoDecisionEnabled 1 -CollectDeltas 1^</Command^>
  echo   ^</LogonCommand^>
  echo ^</Configuration^>
)
exit /b 0
