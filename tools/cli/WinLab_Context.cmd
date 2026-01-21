@echo off
setlocal EnableExtensions EnableDelayedExpansion
chcp 65001 >nul

set "ARG=%~1"
if "%ARG%"=="" exit /b 2

set "ROOT=%~dp0.."
for %%I in ("%ROOT%") do set "ROOT=%%~fI"
set "LAUNCHER=%ROOT%\downloads\launcher\WinLab_Launcher.cmd"

if not exist "%LAUNCHER%" (
  echo WinLab Launcher no encontrado: %LAUNCHER%
  exit /b 3
)

if /I "%ARG:~0,4%"=="http" (
  call "%LAUNCHER%" Networked "%ARG%"
  exit /b 0
)

if exist "%ARG%" (
  for %%F in ("%ARG%") do set "EXT=%%~xF"
  if /I "!EXT!"==".url" (
    for /f "usebackq tokens=1,* delims==" %%A in (`findstr /I "^URL=" "%ARG%"`) do set "URL=%%B"
    if defined URL (
      call "%LAUNCHER%" Networked "!URL!"
      exit /b 0
    )
  )
  call "%LAUNCHER%" Balanced "%ARG%"
  exit /b 0
)

echo Entrada no valida: %ARG%
exit /b 4
