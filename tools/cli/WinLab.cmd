@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0WinLab.ps1" %*
endlocal
