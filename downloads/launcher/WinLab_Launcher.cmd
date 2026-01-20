@echo off
setlocal EnableExtensions

set "LAUNCHER_DIR=%~dp0"
for %%I in ("%LAUNCHER_DIR%..\..") do set "PACK_ROOT=%%~fI"
set "PRESET_DIR=%PACK_ROOT%\downloads\presets"
set "PRESET=%PRESET_DIR%\Balanced_AUTO.wsb"

call :check_sandbox || exit /b 1
call :ensure_dir "C:\WinLab_Inbox" || exit /b 1
call :ensure_dir "C:\WinLab_Outbox" || exit /b 1
call :update_presets || exit /b 1

if not exist "%PRESET%" (
  echo [WinLab] No encuentro el preset: "%PRESET%"
  pause
  exit /b 1
)

echo [WinLab] Lanzando preset recomendado: Balanced_AUTO.wsb
start "" "%PRESET%"
exit /b 0

:check_sandbox
set "SANDBOX_OK="
for /f "usebackq delims=" %%S in (`dism /online /Get-FeatureInfo /FeatureName:Containers-DisposableClientVM ^| findstr /I /C:"State : Enabled"`) do set "SANDBOX_OK=1"
if defined SANDBOX_OK exit /b 0
echo.
echo [WinLab] Windows Sandbox no esta habilitado.
echo Ejecuta PowerShell como Admin y corre:
echo   Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart
echo Luego reinicia Windows.
echo.
pause
exit /b 1

:ensure_dir
set "TARGET_DIR=%~1"
if not exist "%TARGET_DIR%" (
  mkdir "%TARGET_DIR%" 2>nul
)
if not exist "%TARGET_DIR%" (
  echo [WinLab] No pude crear "%TARGET_DIR%". Ejecuta como Administrador.
  pause
  exit /b 1
)
exit /b 0

:update_presets
if not exist "%PRESET_DIR%" (
  echo [WinLab] Falta la carpeta de presets: "%PRESET_DIR%"
  pause
  exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$root=$env:PACK_ROOT; $presetDir=Join-Path $root 'downloads\\presets'; Get-ChildItem -Path $presetDir -Filter '*_AUTO.wsb' | ForEach-Object { $content = Get-Content -Raw $_.FullName; if($content -match '__PACK_ROOT__'){ $content = $content.Replace('__PACK_ROOT__', $root); Set-Content -Path $_.FullName -Value $content -Encoding UTF8 } }"
exit /b 0
