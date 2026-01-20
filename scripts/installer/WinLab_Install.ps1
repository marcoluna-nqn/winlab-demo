param(
  [switch]$Silent
)

$ErrorActionPreference = 'Stop'

function Test-IsAdmin {
  try{
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
  } catch {
    return $false
  }
}

if(-not (Test-IsAdmin)){
  $argsList = @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
  if($Silent){ $argsList += '-Silent' }
  Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argsList
  exit 0
}

$sourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$payload = Join-Path $sourceRoot 'payload'
$installDir = 'C:\Program Files\WinLab'
$startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\WinLab'
$desktop = Join-Path $env:PUBLIC 'Desktop'
$logRoot = 'C:\WinLab\logs'
$inbox = 'C:\WinLab_Inbox'
$outbox = 'C:\WinLab_Outbox'

if(-not (Test-Path $payload)){
  Write-Host 'No se encontro la carpeta payload. El instalador esta corrupto.' -ForegroundColor Red
  exit 2
}

function Write-Log([string]$m){
  try{
    New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -LiteralPath (Join-Path $logRoot 'install.txt') -Value ("[{0}] {1}" -f $ts,$m)
  } catch {}
  Write-Host $m
}

$version = 'unknown'
try{
  $verPath = Join-Path $payload 'VERSION.txt'
  if(Test-Path $verPath){ $version = (Get-Content -LiteralPath $verPath | Select-Object -First 1).Trim() }
} catch {}

Write-Log "Instalando WinLab $version"
Write-Log "Destino: $installDir"

# Crear carpetas de datos
foreach($d in @($logRoot,$inbox,$outbox)){
  try{ New-Item -ItemType Directory -Force -Path $d | Out-Null } catch {}
}

# Copiar archivos
try{
  if(Test-Path $installDir){ Remove-Item -Recurse -Force -Path $installDir }
} catch {}
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

$rc = & robocopy $payload $installDir /E /NFL /NDL /NJH /NJS /NP
if($LASTEXITCODE -ge 8){
  Write-Log "ERROR: fallo la copia de archivos (robocopy $LASTEXITCODE)."
  exit 3
}

# Dar permisos de escritura a Usuarios en carpetas de datos
foreach($d in @($logRoot,$inbox,$outbox)){
  try{ & icacls $d /grant 'Users:(OI)(CI)M' /T | Out-Null } catch {}
}

# Crear accesos directos
try{
  New-Item -ItemType Directory -Force -Path $startMenu | Out-Null
  $wsh = New-Object -ComObject WScript.Shell
  $launcher = Join-Path $installDir 'downloads\launcher\WinLab_Launcher.cmd'
  $doctor = Join-Path $installDir 'tools\cli\WinLab.cmd'
  $guide = Join-Path $installDir 'docs\guia_cliente.html'
  $uninstall = Join-Path $installDir 'Uninstall-WinLab.ps1'

  $lnk1 = $wsh.CreateShortcut((Join-Path $startMenu 'WinLab (Lanzador).lnk'))
  $lnk1.TargetPath = $launcher
  $lnk1.WorkingDirectory = Split-Path $launcher
  $lnk1.Save()

  $lnk2 = $wsh.CreateShortcut((Join-Path $startMenu 'WinLab (Doctor).lnk'))
  $lnk2.TargetPath = $doctor
  $lnk2.Arguments = 'doctor'
  $lnk2.WorkingDirectory = Split-Path $doctor
  $lnk2.Save()

  $lnk3 = $wsh.CreateShortcut((Join-Path $startMenu 'Guia rapida.lnk'))
  $lnk3.TargetPath = $guide
  $lnk3.WorkingDirectory = Split-Path $guide
  $lnk3.Save()

  $lnk4 = $wsh.CreateShortcut((Join-Path $startMenu 'Desinstalar WinLab.lnk'))
  $lnk4.TargetPath = 'powershell.exe'
  $lnk4.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$uninstall`""
  $lnk4.WorkingDirectory = Split-Path $uninstall
  $lnk4.Save()

  $desk = $wsh.CreateShortcut((Join-Path $desktop 'WinLab.lnk'))
  $desk.TargetPath = $launcher
  $desk.WorkingDirectory = Split-Path $launcher
  $desk.Save()
} catch {
  Write-Log "No pude crear accesos directos: $($_.Exception.Message)"
}

# Registrar desinstalacion en Windows
try{
  $reg = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\WinLab'
  New-Item -Path $reg -Force | Out-Null
  Set-ItemProperty -Path $reg -Name DisplayName -Value 'WinLab'
  Set-ItemProperty -Path $reg -Name DisplayVersion -Value $version
  Set-ItemProperty -Path $reg -Name Publisher -Value 'WinLab'
  Set-ItemProperty -Path $reg -Name InstallLocation -Value $installDir
  $uninstallCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$installDir\Uninstall-WinLab.ps1`""
  Set-ItemProperty -Path $reg -Name UninstallString -Value $uninstallCmd
  Set-ItemProperty -Path $reg -Name QuietUninstallString -Value ($uninstallCmd + ' -Silent')
  Set-ItemProperty -Path $reg -Name DisplayIcon -Value (Join-Path $installDir 'downloads\launcher\WinLab_Launcher.cmd')
} catch {
  Write-Log "No pude registrar la desinstalacion: $($_.Exception.Message)"
}

Write-Log 'Instalacion finalizada.'
if(-not $Silent){
  Write-Host 'Listo. Abri WinLab desde el acceso directo del Escritorio o el Menu Inicio.'
}
