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

$installDir = 'C:\Program Files\WinLab'
$startMenu = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\WinLab'
$desktop = Join-Path $env:PUBLIC 'Desktop'
$logRoot = 'C:\WinLab\logs'
$inbox = 'C:\WinLab_Inbox'
$outbox = 'C:\WinLab_Outbox'

$version = 'unknown'
try{
  $verPath = Join-Path $installDir 'VERSION.txt'
  if(Test-Path $verPath){ $version = (Get-Content -LiteralPath $verPath | Select-Object -First 1).Trim() }
} catch {}

function Write-Log([string]$m){
  try{
    New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -LiteralPath (Join-Path $logRoot 'uninstall.txt') -Value ("[{0}] {1}" -f $ts,$m)
  } catch {}
  Write-Host $m
}

Write-Log "Desinstalando WinLab $version"

# Eliminar accesos directos
try{
  if(Test-Path $startMenu){ Remove-Item -Recurse -Force -Path $startMenu }
  $desktopLinks = @(
    (Join-Path $desktop 'WinLab.lnk'),
    (Join-Path $desktop 'WinLab (Lanzador).lnk'),
    (Join-Path $desktop 'WinLab (Doctor).lnk'),
    (Join-Path $desktop 'Guia rapida.lnk')
  )
  foreach($lnk in $desktopLinks){ if(Test-Path $lnk){ Remove-Item -Force -Path $lnk } }
} catch {
  Write-Log "No pude eliminar accesos directos: $($_.Exception.Message)"
}

# Eliminar instalacion
try{
  if(Test-Path $installDir){ Remove-Item -Recurse -Force -Path $installDir }
} catch {
  Write-Log "No pude eliminar $installDir: $($_.Exception.Message)"
}

# Eliminar registro de desinstalacion
try{
  $reg = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\WinLab'
  if(Test-Path $reg){ Remove-Item -Recurse -Force -Path $reg }
} catch {
  Write-Log "No pude eliminar la clave de desinstalacion: $($_.Exception.Message)"
}

# Eliminar menu contextual
try{
  $classesRoot = 'HKLM:\\Software\\Classes'
  $keys = @(
    (Join-Path $classesRoot '*\\shell\\WinLabAnalyze'),
    (Join-Path $classesRoot 'InternetShortcut\\shell\\WinLabAnalyze'),
    (Join-Path $classesRoot 'http\\shell\\WinLabAnalyze'),
    (Join-Path $classesRoot 'https\\shell\\WinLabAnalyze')
  )
  foreach($k in $keys){
    if(Test-Path $k){ Remove-Item -Recurse -Force -Path $k }
  }
} catch {
  Write-Log "No pude eliminar el menu contextual: $($_.Exception.Message)"
}

# Eliminar carpetas de datos
try{ if(Test-Path $logRoot){ Remove-Item -Recurse -Force -Path $logRoot } } catch {}
try{ if(Test-Path $inbox){ Remove-Item -Recurse -Force -Path $inbox } } catch {}
try{ if(Test-Path $outbox){ Remove-Item -Recurse -Force -Path $outbox } } catch {}

Write-Log 'Desinstalacion finalizada.'
if(-not $Silent){
  Write-Host 'Listo. Podes borrar los reportes manualmente si quedaron copias.'
}
