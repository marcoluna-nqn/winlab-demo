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

$serviceName = 'WinLabRemoteHost'
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if($svc){
  if($svc.Status -ne 'Stopped'){
    Stop-Service -Name $serviceName -Force
  }
  sc.exe delete $serviceName | Out-Null
}

$target = 'C:\Program Files\WinLab\remote_host'
if(Test-Path $target){ Remove-Item -Recurse -Force -Path $target }

Write-Host 'Servicio WinLab Host Remoto eliminado.'
