param()

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
  Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"")
  exit 0
}

$source = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = 'C:\Program Files\WinLab\remote_host'
$configDir = Join-Path $env:ProgramData 'WinLab\remote_host'

New-Item -ItemType Directory -Force -Path $target | Out-Null
Copy-Item -Path (Join-Path $source '*.ps1') -Destination $target -Force
Copy-Item -Path (Join-Path $source '*.txt') -Destination $target -Force
Copy-Item -Path (Join-Path $source 'remote_host_config.json') -Destination $target -Force

New-Item -ItemType Directory -Force -Path $configDir | Out-Null
$configPath = Join-Path $configDir 'config.json'
if(-not (Test-Path $configPath)){
  Copy-Item -Path (Join-Path $source 'remote_host_config.json') -Destination $configPath -Force
}

$serviceName = 'WinLabRemoteHost'
$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$binPath = "`"$psExe`" -NoProfile -ExecutionPolicy Bypass -File `"$target\WinLab_RemoteHost.ps1`""

$exists = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if(-not $exists){
  sc.exe create $serviceName binPath= $binPath start= demand DisplayName= "WinLab Host Remoto" | Out-Null
  sc.exe description $serviceName "Servicio local de WinLab para analizar desde celular (solo local por defecto)." | Out-Null
}

Write-Host 'Instalacion completa. Usa Start_RemoteHost.ps1 para iniciar el servicio.'
