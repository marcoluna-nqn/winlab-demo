# WinLab CLI wrapper (compatibilidad)
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $root 'WinLab.ps1'

if(-not (Test-Path $target)){
  Write-Host "WinLab.ps1 no encontrado en $root" -ForegroundColor Red
  exit 1
}

& $target @args
