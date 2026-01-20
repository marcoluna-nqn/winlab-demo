@echo off
setlocal enabledelayedexpansion
color 0a
title Safe Mode Helper - WinLab

:: Check admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
  set "IS_ADMIN=0"
) else (
  set "IS_ADMIN=1"
)

:menu
cls
echo ==============================================
echo   Safe Mode Helper - WinLab (requiere admin)
echo ==============================================
if %IS_ADMIN%==0 (
  echo [!] No estas ejecutando como Administrador. Opciones que modifican arranque no funcionaran.
  echo     Cierra y vuelve a abrir como Administrador para aplicar cambios.
  echo.
)
echo 1^) Ver pasos manuales (no cambia nada)
echo 2^) Abrir msconfig (GUI)
echo 3^) Aplicar Modo Seguro (safeboot minimal)
echo 4^) Revertir Modo Seguro (volver a normal)
echo 0^) Salir
echo.
set /p opt=Seleccion: 
if "%opt%"=="1" goto manual
if "%opt%"=="2" goto msconfig
if "%opt%"=="3" goto apply
if "%opt%"=="4" goto revert
if "%opt%"=="0" goto end
goto menu

:manual
cls
echo Pasos manuales para Modo Seguro:
echo 1. Abre PowerShell o CMD como Administrador.
echo 2. Ejecuta: bcdedit /set {current} safeboot minimal
echo 3. Reinicia. Para salir de Modo Seguro, ejecuta: bcdedit /deletevalue {current} safeboot y reinicia.
echo.
pause
goto menu

:msconfig
start msconfig
pause
goto menu

:apply
if %IS_ADMIN%==0 (
  echo [!] Necesitas permisos de Administrador para aplicar Modo Seguro.
  pause
  goto menu
)
set /p confirm=Aplicar Modo Seguro (safeboot minimal) y reiniciar despues? (S/N): 
if /I not "%confirm%"=="S" (
  echo Cancelado.
  pause
  goto menu
)
bcdedit /set {current} safeboot minimal
if %errorlevel% neq 0 (
  echo [!] No se pudo aplicar safeboot. Revisa si tienes permisos.
  pause
  goto menu
)
echo [OK] Safeboot configurado. Reinicia para entrar en Modo Seguro.
pause
goto menu

:revert
if %IS_ADMIN%==0 (
  echo [!] Necesitas permisos de Administrador para revertir.
  pause
  goto menu
)
set /p confirm=Quitar Modo Seguro y volver al arranque normal? (S/N): 
if /I not "%confirm%"=="S" (
  echo Cancelado.
  pause
  goto menu
)
bcdedit /deletevalue {current} safeboot
if %errorlevel% neq 0 (
  echo [!] No se pudo revertir safeboot. Revisa si tienes permisos.
  pause
  goto menu
)
echo [OK] Safeboot removido. Reinicia para volver al modo normal.
pause
goto menu

:end
exit /b 0
